# parser.py
import re
from collections import Counter
from typing import Dict, List, Any

# Enterprise-grade regex with named groups
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'       # Matches IP
    r'.*?\[(?P<timestamp>.*?)\] '            # Matches Timestamp
    r'"(?P<method>\w+) (?P<path>.*?) HTTP.*?" ' # Matches Method & Path
    r'(?P<status>\d{3})'                     # Matches Status Code
)

class LogParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.status_counts = Counter()
        self.ip_counts = Counter()
        
    def run(self):
        """Execution flow for the parser."""
        print(f"--- Processing: {self.filepath} ---")
        # Logic will be added in next commits

    def run(self):
        try:
            with open(self.filepath, 'r') as file:
                for line in file:
                    self.parse_line(line.strip())
            self.print_summary()
        except FileNotFoundError:
            print(f"Error: File '{self.filepath}' not found.")

    def parse_line(self, line: str):
        """Placeholder for regex logic."""
        pass

    def print_summary(self):
        """Placeholder for reporting logic."""
        print("Processing complete.")


#feat: add initial regex for IP and status code extraction

#feat: implement status code frequency counting

#feat: implement IP hit tracking