import os
import logging
from pathlib import Path
from typing import TextIO, Callable

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


LogWatcherCallback = Callable[[str], None]


class _LogEventHandler(FileSystemEventHandler):

    def __init__(self, log_watcher: "LogWatcher") -> None:
        super().__init__()
        self.log_watcher = log_watcher

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        event_path = Path(event.src_path).resolve()
        target_path = self.log_watcher.log_path.resolve()

        if event_path == target_path:
            self.log_watcher._handle_modification()

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        event_path = Path(event.src_path).resolve()
        target_path = self.log_watcher.log_path.resolve()

        if event_path == target_path:
            self.log_watcher._handle_file_created()

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        event_path = Path(event.src_path).resolve()
        target_path = self.log_watcher.log_path.resolve()

        if event_path == target_path:
            self.log_watcher._handle_file_deleted()

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        src_path = Path(event.src_path).resolve()
        target_path = self.log_watcher.log_path.resolve()

        if src_path == target_path:
            self.log_watcher._handle_file_moved()


class LogWatcher:

    def __init__(
        self,
        log_path: str,
        on_line_callback: LogWatcherCallback,
        logger: logging.Logger | None = None,
    ) -> None:
        self.log_path = Path(log_path)
        self.on_line_callback = on_line_callback
        self.logger = logger or logging.getLogger(__name__)

        self._file: TextIO | None = None
        self._position: int = 0
        self._observer: Observer | None = None
        self._inode: int | None = None
        self._running: bool = False

    def start(self) -> None:
        if self._running:
            return

        self._running = True

        self._open_file()

        self._observer = Observer()
        handler = _LogEventHandler(self)

        watch_dir = str(self.log_path.parent.resolve())
        self._observer.schedule(handler, watch_dir, recursive=False)
        self._observer.start()

        self.logger.info("Started watching %s", self.log_path)

    def stop(self) -> None:
        if not self._running:
            return

        self._running = False

        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=1.0)
            self._observer = None

        self._close_file()

        self.logger.info("Stopped watching %s", self.log_path)

    def _open_file(self, seek_to_end: bool = True) -> None:
        self._close_file()

        if not self.log_path.exists():
            self.logger.debug("Log file does not exist yet: %s", self.log_path)
            return

        try:
            self._file = open(self.log_path, "r", encoding="utf-8", errors="replace")

            if seek_to_end:
                self._file.seek(0, os.SEEK_END)
                self._position = self._file.tell()
            else:
                self._position = 0

            self._inode = self._get_inode()

            self.logger.debug(
                "Opened log file %s at position %d, inode %s",
                self.log_path,
                self._position,
                self._inode,
            )
        except OSError as e:
            self.logger.error("Failed to open log file %s: %s", self.log_path, e)
            self._file = None

    def _close_file(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None
            self._position = 0
            self._inode = None

    def _get_inode(self) -> int | None:
        try:
            stat_result = os.stat(self.log_path)
            return stat_result.st_ino
        except OSError:
            return None

    def _check_rotation(self) -> bool:
        if self._inode is None:
            return False

        current_inode = self._get_inode()
        if current_inode is None:
            return True

        return current_inode != self._inode

    def _read_new_lines(self) -> None:
        if self._file is None:
            return

        try:
            self._file.seek(self._position)

            for line in self._file:
                stripped = line.rstrip("\n\r")
                if stripped:
                    self.on_line_callback(stripped)

            self._position = self._file.tell()

        except OSError as e:
            self.logger.error("Error reading log file: %s", e)

    def _handle_modification(self) -> None:
        if self._check_rotation():
            self.logger.info("Log rotation detected (inode changed), reopening file")
            self._open_file(seek_to_end=False)
            self._read_new_lines()
        else:
            self._read_new_lines()

    def _handle_file_created(self) -> None:
        self.logger.info("Log file created, opening")
        self._open_file(seek_to_end=False)
        self._read_new_lines()

    def _handle_file_deleted(self) -> None:
        self.logger.info("Log file deleted, closing handle")
        self._close_file()

    def _handle_file_moved(self) -> None:
        self.logger.info("Log file moved (rotation), closing old handle")
        self._close_file()
