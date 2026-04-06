from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Callable
from threading import Lock
import logging

logger = logging.getLogger(__name__)


@dataclass
class ThresholdExceeded:

    ip: str
    failure_count: int
    window_seconds: int
    first_failure: datetime
    last_failure: datetime


class ThresholdTracker:

    def __init__(
        self,
        threshold: int,
        window_seconds: int,
        on_threshold_exceeded: Callable[[ThresholdExceeded], None] | None = None,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.on_threshold_exceeded = on_threshold_exceeded

        self._failures: dict[str, list[datetime]] = defaultdict(list)

        self._triggered: set[str] = set()

        self._attack_history: list[tuple[datetime, str]] = []
        self._stats_lock = Lock()

    def record_failure(self, ip: str, timestamp: datetime | None = None) -> bool:
        ts = timestamp or datetime.now()
        self._failures[ip].append(ts)

        with self._stats_lock:
            self._attack_history.append((ts, ip))

            cutoff = datetime.now() - timedelta(hours=24)
            self._attack_history = [
                (t, i) for t, i in self._attack_history
                if t >= cutoff
            ]

        if ip not in self._triggered and self.is_threshold_exceeded(ip, ts):
            self._triggered.add(ip)
            self._emit_exceeded(ip, ts)
            return True
        return False

    def is_threshold_exceeded(self, ip: str, now: datetime | None = None) -> bool:
        now = now or datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        recent = [t for t in self._failures.get(ip, []) if t >= cutoff]
        return len(recent) >= self.threshold

    def get_failure_count(self, ip: str, now: datetime | None = None) -> int:
        now = now or datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        return len([t for t in self._failures.get(ip, []) if t >= cutoff])

    def cleanup(self, now: datetime | None = None) -> int:
        now = now or datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        cleaned = 0

        for ip in list(self._failures.keys()):
            self._failures[ip] = [t for t in self._failures[ip] if t >= cutoff]

            if not self._failures[ip]:
                del self._failures[ip]
                self._triggered.discard(ip)
                cleaned += 1

        return cleaned

    def reset_ip(self, ip: str) -> None:
        self._failures.pop(ip, None)
        self._triggered.discard(ip)

    def _emit_exceeded(self, ip: str, now: datetime) -> None:
        if not self.on_threshold_exceeded:
            return

        failures = self._failures[ip]
        event = ThresholdExceeded(
            ip=ip,
            failure_count=len(failures),
            window_seconds=self.window_seconds,
            first_failure=min(failures),
            last_failure=max(failures),
        )
        self.on_threshold_exceeded(event)

    def get_attack_stats(self, hours: int = 24) -> dict:
        with self._stats_lock:
            now = datetime.now()
            cutoff = now - timedelta(hours=hours)

            relevant_attacks = [
                (t, ip) for t, ip in self._attack_history
                if t >= cutoff
            ]

            hourly_data = defaultdict(lambda: {"count": 0, "ips": set()})

            for timestamp, ip in relevant_attacks:
                hour = timestamp.replace(minute=0, second=0, microsecond=0)
                hourly_data[hour]["count"] += 1
                hourly_data[hour]["ips"].add(ip)

            labels = []
            attacks = []
            unique_ips = []

            for i in range(hours):
                hour = (now - timedelta(hours=hours-i-1)).replace(minute=0, second=0, microsecond=0)
                labels.append(hour.isoformat())

                if hour in hourly_data:
                    attacks.append(hourly_data[hour]["count"])
                    unique_ips.append(len(hourly_data[hour]["ips"]))
                else:
                    attacks.append(0)
                    unique_ips.append(0)

            return {
                "labels": labels,
                "attacks": attacks,
                "unique_ips": unique_ips
            }
