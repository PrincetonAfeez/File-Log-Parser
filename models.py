# models.py
"""Domain types shared by parsing and reporting."""

# Import the dataclass decorator to create a clean, structured data container.
from dataclasses import dataclass


# Use the 'frozen=True' parameter to make the instances immutable (read-only).
# This prevents data from being accidentally changed once it has been validated.
@dataclass(frozen=True)
class LogEntry:
    """
    One successful parse of an access log line after regex capture and validation.

    ``timestamp`` stays a string in the original log format; ``status`` is an int
    for comparisons (e.g. counting 404s) and sorting.
    """

    # The validated IP address of the client (stored as a string for display/export).
    ip: str
    
    # The raw timestamp string extracted from the log (e.g., '28/Mar/2026:12:10:35').
    timestamp: str
    
    # The HTTP Verb used in the request (e.g., 'GET', 'POST', 'PUT').
    method: str
    
    # The specific URL or resource path requested from the server.
    path: str
    
    # The numerical HTTP response status code (e.g., 200, 404, 500) for logic checks.
    status: int