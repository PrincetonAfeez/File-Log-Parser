# models.py
"""Domain types shared by parsing and reporting."""

from dataclasses import dataclass


@dataclass(frozen=True)
class LogEntry:
    """
    One successful parse of an access log line after regex capture and validation.

    ``timestamp`` stays a string in the original log format; ``status`` is an int
    for comparisons (e.g. counting 404s) and sorting.
    """

    ip: str
    timestamp: str
    method: str
    path: str
    status: int