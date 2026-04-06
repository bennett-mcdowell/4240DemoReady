from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
import tempfile
import os
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class BlockedIP:

    ip: str
    blocked_at: datetime
    failure_count: int

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "blocked_at": self.blocked_at.isoformat(),
            "failure_count": self.failure_count,
        }

    @staticmethod
    def from_dict(data: dict) -> "BlockedIP":
        return BlockedIP(
            ip=data["ip"],
            blocked_at=datetime.fromisoformat(data["blocked_at"]),
            failure_count=data["failure_count"],
        )


class BlockedIPStore:

    def __init__(
        self, storage_path: Path | str = "/var/lib/sshguard-dashboard/blocked_ips.json"
    ) -> None:
        self._storage_path = Path(storage_path)
        self._blocked_ips: list[BlockedIP] = []

    def add(self, ip: str, failure_count: int) -> None:
        blocked = BlockedIP(
            ip=ip, blocked_at=datetime.now(), failure_count=failure_count
        )
        self._blocked_ips.append(blocked)
        self._save()

    def remove(self, ip: str) -> bool:
        original_length = len(self._blocked_ips)
        self._blocked_ips = [b for b in self._blocked_ips if b.ip != ip]

        if len(self._blocked_ips) < original_length:
            self._save()
            return True
        return False

    def get_all(self) -> list[BlockedIP]:
        return self._blocked_ips

    def load(self) -> None:
        if not self._storage_path.exists():
            logger.info(
                f"No blocked IPs file found at {self._storage_path}, starting fresh"
            )
            self._blocked_ips = []
            return

        try:
            with open(self._storage_path, "r") as f:
                data = json.load(f)

            self._blocked_ips = [
                BlockedIP.from_dict(item) for item in data.get("blocked_ips", [])
            ]
            logger.info(
                f"Loaded {len(self._blocked_ips)} blocked IPs from {self._storage_path}"
            )

        except json.JSONDecodeError as e:
            logger.warning(
                f"Corrupt blocked IPs file at {self._storage_path}: {e}. Starting fresh."
            )
            self._blocked_ips = []
        except Exception as e:
            logger.error(
                f"Error loading blocked IPs from {self._storage_path}: {e}. Starting fresh."
            )
            self._blocked_ips = []

    def _save(self) -> None:
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)

            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self._storage_path.parent,
                delete=False,
                suffix=".tmp",
            ) as f:
                data = {"blocked_ips": [b.to_dict() for b in self._blocked_ips]}
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
                temp_path = f.name

            os.replace(temp_path, self._storage_path)

            logger.debug(
                f"Saved {len(self._blocked_ips)} blocked IPs to {self._storage_path}"
            )

        except Exception as e:
            logger.error(f"Error saving blocked IPs to {self._storage_path}: {e}")
            try:
                if "temp_path" in locals():
                    os.unlink(temp_path)
            except Exception:
                pass 
