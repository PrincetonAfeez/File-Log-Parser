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