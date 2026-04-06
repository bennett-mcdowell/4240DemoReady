import re
import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Callable


@dataclass
class FailedAttempt:

    timestamp: datetime
    ip: str
    username: str | None
    pattern_type: str


FailedAttemptCallback = Callable[[FailedAttempt], None]


PATTERNS: list[tuple[re.Pattern[str], str, int, int]] = [
    (
        re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port'),
        'failed_password',
        1,  # username group
        2,  # ip group
    ),
    (
        re.compile(r'Invalid user (\S+) from (\S+) port'),
        'invalid_user',
        1,  # username group
        2,  # ip group
    ),
    (
        re.compile(r'Connection closed by authenticating user (\S+) (\S+) port'),
        'connection_closed',
        1,  # username group
        2,  # ip group
    ),
    (
        re.compile(r'maximum authentication attempts exceeded for (\S+) from (\S+) port'),
        'max_attempts',
        1,  # username group
        2,  # ip group
    ),
]

TIMESTAMP_PATTERN = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')


class DetectionEngine:

    def __init__(
        self,
        on_failure_callback: FailedAttemptCallback | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.on_failure_callback = on_failure_callback
        self.logger = logger or logging.getLogger(__name__)

    def parse_line(self, line: str) -> FailedAttempt | None:
        if not line or not line.strip():
            return None

        for pattern, pattern_type, username_group, ip_group in PATTERNS:
            match = pattern.search(line)
            if match:
                username = match.group(username_group)
                ip_str = match.group(ip_group)

                if not self._validate_ip(ip_str):
                    self.logger.warning(
                        "Invalid IP address rejected: %s (possible log injection)",
                        ip_str[:50],
                    )
                    return None

                timestamp = self._parse_timestamp(line)

                attempt = FailedAttempt(
                    timestamp=timestamp,
                    ip=ip_str,
                    username=username,
                    pattern_type=pattern_type,
                )

                if self.on_failure_callback is not None:
                    self.on_failure_callback(attempt)

                return attempt

        return None

    def _validate_ip(self, ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def _parse_timestamp(self, line: str) -> datetime:
        match = TIMESTAMP_PATTERN.match(line)
        if match:
            timestamp_str = match.group(1)
            try:
                current_year = datetime.now().year
                parsed = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                return parsed
            except ValueError:
                pass

        return datetime.now()
