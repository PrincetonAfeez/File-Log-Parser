# models.py
from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
class LogEntry:
    ip: str
    timestamp: str
    method: str
    path: str
    status: int  # Notice we convert to int for easier math later