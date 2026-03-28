# exceptions.py
"""Typed errors for log parsing I/O and format failures (optional use by callers)."""


class LogParserError(Exception):
    """Base class for all parser exceptions."""
    pass

class InvalidLogFormatError(LogParserError):
    """Raised when a log line doesn't match the expected RegEx."""
    pass

class FileReadError(LogParserError):
    """Raised when the file cannot be accessed."""
    pass