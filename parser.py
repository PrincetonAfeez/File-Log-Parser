# parser.py
import re
from collections import Counter
from typing import Dict, List, Any

class LogParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.status_counts = Counter()
        self.ip_counts = Counter()
        
    def run(self):
        """Execution flow for the parser."""
        print(f"--- Processing: {self.filepath} ---")
        # Logic will be added in next commits


#feat: implement safe file reading logic

#feat: add initial regex for IP and status code extraction

#feat: implement status code frequency counting

#feat: implement IP hit tracking