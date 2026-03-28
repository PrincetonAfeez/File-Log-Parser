"""Regex matching, validation, and noise classification for access log lines."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from models import LogEntry

# Apache-style combined log fragment: IP, bracketed time, METHOD path HTTP/x, status
_ACCESS_LOG_REGEX = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'.*?\[(?P<timestamp>.*?)\] '
    r'"(?P<method>\w+) (?P<path>.*?) HTTP.*?" '
    r'(?P<status>\d{3})'
)

TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S"


class AccessLogLineMatcher:
    """
    Identifies whether a raw line looks like a supported access log record.

    Exposes the compiled pattern as ``PATTERN`` for tests and tooling that
    need the same regex without instantiating the class.
    """

    PATTERN = _ACCESS_LOG_REGEX

    def search(self, line: str) -> re.Match[str] | None:
        """Return a match object if ``line`` fits the access log pattern, else ``None``."""
        return self.PATTERN.search(line)


class LogEntryBuilder:
    """
    Converts regex capture groups into a ``LogEntry`` after structural checks.

    :meth:`build` returns a ``(entry, error_tag)`` pair so callers can increment
    corruption metrics and choose log levels without using exceptions for flow control.
    """

    def build(self, groups: dict[str, str]) -> tuple[LogEntry | None, str | None]:
        """
        Validate ``groups`` (from :meth:`AccessLogLineMatcher.search`) and build a row.

        On success returns ``(LogEntry, None)``. On failure returns ``(None, tag)`` where
        ``tag`` is ``invalid_ip``, ``invalid_timestamp``, or ``invalid_status`` so the
        caller can log at the appropriate level.
        """
        ip_obj = self._parse_ip(groups.get("ip", ""))
        if ip_obj is None:
            return None, "invalid_ip"

        if not self._timestamp_valid(groups.get("timestamp", "")):
            return None, "invalid_timestamp"

        status = self._parse_status(groups.get("status", ""))
        if status is None:
            return None, "invalid_status"

        entry = LogEntry(
            ip=str(ip_obj),
            timestamp=groups["timestamp"],
            method=groups["method"],
            path=groups["path"],
            status=status,
        )
        return entry, None

    def _parse_ip(self, value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """Parse ``value`` as an IP address, or return ``None`` if invalid."""
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    def _timestamp_valid(self, value: str) -> bool:
        """Return True if ``value`` matches the expected Apache log datetime format."""
        try:
            datetime.strptime(value, TIMESTAMP_FMT)
        except ValueError:
            return False
        return True

    def _parse_status(self, value: str) -> int | None:
        """Parse HTTP status code string to int, or ``None`` if not digits."""
        try:
            return int(value)
        except ValueError:
            return None


class NoisePathFilter:
    """
    Treats requests whose path ends with configured extensions as non-analytical noise.

    Typical examples: static assets (``.css``, ``.js``, images) that inflate hit
    counts without adding security or traffic insight.
    """

    def __init__(self, extensions: tuple[str, ...]):
        self._extensions = extensions

    def is_noise(self, entry: LogEntry) -> bool:
        """Return True if ``entry.path`` should be excluded from aggregate metrics."""
        return any(entry.path.endswith(ext) for ext in self._extensions)
