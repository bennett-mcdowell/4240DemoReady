import subprocess
import logging
import ipaddress
from typing import List

logger = logging.getLogger(__name__)


class BlockingError(Exception):

    pass


class BlockingEngine:

    HARDCODED_WHITELIST = ["127.0.0.1", "::1"]

    def __init__(self, whitelist: List[str] | None = None):
        configured_whitelist = whitelist or []
        self.whitelist = list(set(self.HARDCODED_WHITELIST + configured_whitelist))
        logger.info(f"BlockingEngine initialized with whitelist: {self.whitelist}")

    def setup_chain(self) -> None:
        result = subprocess.run(
            ['iptables', '-N', 'SSHGUARD'],
            capture_output=True
        )
        if result.returncode != 0:
            logger.warning(f"iptables -N SSHGUARD failed: {result.stderr.decode()}")

        result = subprocess.run(
            ['iptables', '-I', 'INPUT', '1', '-j', 'SSHGUARD'],
            capture_output=True
        )
        if result.returncode != 0:
            logger.warning(f"iptables jump rule failed: {result.stderr.decode()}")

        result = subprocess.run(
            ['ip6tables', '-N', 'SSHGUARD'],
            capture_output=True
        )
        if result.returncode != 0:
            logger.warning(f"ip6tables -N SSHGUARD failed: {result.stderr.decode()}")

        result = subprocess.run(
            ['ip6tables', '-I', 'INPUT', '1', '-j', 'SSHGUARD'],
            capture_output=True
        )
        if result.returncode != 0:
            logger.warning(f"ip6tables jump rule failed: {result.stderr.decode()}")

        logger.info("SSHGUARD chain setup complete for both IPv4 and IPv6")

    def block(self, ip: str) -> None:
        if ip in self.whitelist:
            raise BlockingError(f"IP {ip} is whitelisted and cannot be blocked")

        addr = ipaddress.ip_address(ip)

        if isinstance(addr, ipaddress.IPv4Address):
            tool = 'iptables'
        else:
            tool = 'ip6tables'

        result = subprocess.run(
            [tool, '-I', 'SSHGUARD', '1', '-s', ip, '-j', 'DROP'],
            capture_output=True
        )

        if result.returncode != 0:
            stderr = result.stderr.decode()
            logger.warning(f"{tool} block of {ip} failed (exit {result.returncode}): {stderr}")
        else:
            logger.info(f"Blocked {ip} on {tool}")

    def unblock(self, ip: str) -> None:
        addr = ipaddress.ip_address(ip)

        if isinstance(addr, ipaddress.IPv4Address):
            tool = 'iptables'
        else:
            tool = 'ip6tables'

        result = subprocess.run(
            [tool, '-D', 'SSHGUARD', '-s', ip, '-j', 'DROP'],
            capture_output=True
        )

        if result.returncode != 0:
            stderr = result.stderr.decode()
            logger.warning(f"{tool} unblock of {ip} failed (exit {result.returncode}): {stderr}")
        else:
            logger.info(f"Unblocked {ip}")

    def flush_chain(self) -> None:
        result = subprocess.run(
            ['iptables', '-F', 'SSHGUARD'],
            capture_output=True
        )
        if result.returncode != 0:
            logger.warning(f"iptables flush failed: {result.stderr.decode()}")

        result = subprocess.run(
            ['ip6tables', '-F', 'SSHGUARD'],
            capture_output=True
        )
        if result.returncode != 0:
            logger.warning(f"ip6tables flush failed: {result.stderr.decode()}")

        logger.info("Flushed SSHGUARD chain for both IPv4 and IPv6")

    def is_blocked(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)

        if isinstance(addr, ipaddress.IPv4Address):
            tool = 'iptables'
        else:
            tool = 'ip6tables'

        result = subprocess.run(
            [tool, '-L', 'SSHGUARD', '-n'],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.warning(f"{tool} list failed: {result.stderr}")
            return False

        return ip in result.stdout
