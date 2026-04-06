import logging
import signal
import sys
from typing import Callable

from .config import Config, load_config
from .detection import DetectionEngine, FailedAttempt
from .log_watcher import LogWatcher
from .threshold import ThresholdTracker, ThresholdExceeded
from .blocking import BlockingEngine
from .persistence import BlockedIPStore
from . import web

logger = logging.getLogger(__name__)


class SSHBlockDaemon:

    def __init__(
        self,
        config: Config | None = None,
        on_threshold_exceeded: Callable[[ThresholdExceeded], None] | None = None,
    ) -> None:
        self.config = config or load_config()
        self.on_threshold_exceeded = on_threshold_exceeded
        self._running = False

        self.threshold_tracker = ThresholdTracker(
            threshold=self.config.threshold,
            window_seconds=self.config.window_seconds,
            on_threshold_exceeded=self._handle_threshold_exceeded,
        )

        self.detection_engine = DetectionEngine(
            on_failure_callback=self._handle_failure,
        )

        self.log_watcher = LogWatcher(
            log_path=self.config.log_path,
            on_line_callback=self._handle_line,
        )

        self.blocking_engine = BlockingEngine(whitelist=self.config.whitelist)
        self.blocked_ip_store = BlockedIPStore()

    def start(self) -> None:
        logger.info(
            f"Starting SSHBlock daemon: threshold={self.config.threshold}, "
            f"window={self.config.window_seconds}s, log={self.config.log_path}"
        )

        logger.info("Setting up SSHGUARD iptables chain")
        self.blocking_engine.setup_chain()

        logger.info("Restoring blocked IPs from persistent storage")
        self.blocked_ip_store.load()

        logger.info("Flushing SSHGUARD chain and restoring blocks")
        self.blocking_engine.flush_chain()

        for blocked_ip in self.blocked_ip_store.get_all():
            try:
                self.blocking_engine.block(blocked_ip.ip)
                logger.info(f"Restored block for {blocked_ip.ip}")
            except Exception as e:
                logger.warning(f"Failed to restore block for {blocked_ip.ip}: {e}")

        self._running = True
        self.log_watcher.start()

    def stop(self) -> None:
        logger.info("Stopping SSHBlock daemon")
        self._running = False
        self.log_watcher.stop()

    def _handle_line(self, line: str) -> None:
        self.detection_engine.parse_line(line)

    def _handle_failure(self, attempt: FailedAttempt) -> None:
        if attempt.ip in self.config.whitelist:
            logger.debug(f"Ignoring whitelisted IP: {attempt.ip}")
            return

        try:
            web.broadcast_attack_event(attempt)
            logger.debug(f"Broadcasted attack event: {attempt.ip}")
        except Exception as e:
            logger.warning(f"Failed to broadcast attack event: {e}")

        logger.debug(f"SSH failure: {attempt.ip} ({attempt.pattern_type})")
        self.threshold_tracker.record_failure(attempt.ip, attempt.timestamp)

    def _handle_threshold_exceeded(self, event: ThresholdExceeded) -> None:
        logger.warning(
            f"Threshold exceeded for {event.ip}: "
            f"{event.failure_count} failures in {event.window_seconds}s"
        )

        try:
            self.blocking_engine.block(event.ip)
            logger.info(f"Blocked {event.ip} via iptables")
        except Exception as e:
            logger.error(f"Failed to block {event.ip}: {e}")

        try:
            self.blocked_ip_store.add(event.ip, event.failure_count)
            logger.info(f"Persisted block for {event.ip} to JSON")
        except Exception as e:
            logger.error(f"Failed to persist block for {event.ip}: {e}")

        if self.on_threshold_exceeded:
            self.on_threshold_exceeded(event)

    @property
    def is_running(self) -> bool:
        return self._running


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SSHBlock Dashboard Daemon")
    parser.add_argument("-c", "--config", help="Path to config file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    setup_logging(args.verbose)

    config = load_config(args.config) if args.config else load_config()
    daemon = SSHBlockDaemon(config=config)

    def signal_handler(signum, frame):
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    daemon.start()

    import time

    while daemon.is_running:
        time.sleep(1)


if __name__ == "__main__":
    main()
