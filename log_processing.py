# log_processing.py
"""Regex matching, validation, and noise classification for access log lines."""

# Enable postponed evaluation of annotations for modern type hinting support.
from __future__ import annotations

# Import standard libraries for networking, regular expressions, and date handling.
import ipaddress
import re
from datetime import datetime

# Import the LogEntry dataclass to ensure structured data across the pipeline.
from models import LogEntry

# Apache-style combined log fragment: Defines the extraction pattern for IP, time, method, path, and status.
# Uses 'Named Capturing Groups' (?P<name>) to make the resulting dictionary self-documenting.
_ACCESS_LOG_REGEX = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'       # Matches an IPv4 address pattern (e.g., 192.168.1.1).
    r'.*?\[(?P<timestamp>.*?)\] '             # Non-greedily captures the string inside square brackets.
    r'"(?P<method>\w+) (?P<path>.*?) HTTP.*?" ' # Captures the HTTP verb and the requested resource path.
    r'(?P<status>\d{3})'                     # Captures exactly three digits representing the HTTP status code.
)

# Standard Apache/Nginx timestamp format used for secondary validation of the log's date string.
TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S"


class AccessLogLineMatcher:
    """
    Identifies whether a raw line looks like a supported access log record.

    Exposes the compiled pattern as ``PATTERN`` for tests and tooling that
    need the same regex without instantiating the class.
    """

    # Assign the pre-compiled private regex to a public class attribute for accessibility.
    PATTERN = _ACCESS_LOG_REGEX

    def search(self, line: str) -> re.Match[str] | None:
        """Execute the RegEx search on a raw string to identify potential log entries."""
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
        ``tag`` is used to identify the specific validation failure type.
        """
        # Validate that the string in the 'ip' group is a mathematically valid IP address.
        ip_obj = self._parse_ip(groups.get("ip", ""))
        if ip_obj is None:
            return None, "invalid_ip"

        # Validate that the 'timestamp' matches the expected chronological format.
        if not self._timestamp_valid(groups.get("timestamp", "")):
            return None, "invalid_timestamp"

        # Ensure the 'status' code is a valid integer (e.g., '200' -> 200).
        status = self._parse_status(groups.get("status", ""))
        if status is None:
            return None, "invalid_status"

        # If all structural checks pass, instantiate the frozen LogEntry dataclass.
        entry = LogEntry(
            ip=str(ip_obj),
            timestamp=groups["timestamp"],
            method=groups["method"],
            path=groups["path"],
            status=status,
        )
        return entry, None

    def _parse_ip(self, value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """Attempt to cast a string into an IP object; returns None if the format is invalid."""
        try:
            # Uses the standard library's ipaddress module for rigorous validation logic.
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    def _timestamp_valid(self, value: str) -> bool:
        """Verifies if the date string can be successfully parsed into a datetime object."""
        try:
            # Ensures the data isn't just a string, but a valid date (e.g., rejects Feb 30th).
            datetime.strptime(value, TIMESTAMP_FMT)
        except ValueError:
            return False
        return True

    def _parse_status(self, value: str) -> int | None:
        """Safely converts the HTTP status string to an integer for numerical analysis."""
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
        """Initialize the filter with a tuple of forbidden or 'noisy' file extensions."""
        self._extensions = extensions

    def is_noise(self, entry: LogEntry) -> bool:
        """Checks if the request path ends with any of the configured noise extensions."""
        # Returns True if the path matches extensions like .png, .css, etc., from config.
        return any(entry.path.endswith(ext) for ext in self._extensions)