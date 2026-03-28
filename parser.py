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
        try:
            with open(self.filepath, 'r') as file:
                for line in file:
                    self.parse_line(line.strip())
            self.print_summary()
        except FileNotFoundError:
            print(f"Error: File '{self.filepath}' not found.")

    def parse_line(self, line: str):
        match = LOG_PATTERN.search(line)
        if match:
            data = match.groupdict()
            self.status_counts[data['status']] += 1
            self.ip_counts[data['ip']] += 1
        else:
            # We will handle "Data Cleansing" for failed matches in Phase 2
            pass

    def print_summary(self):
        print("\n--- Log Analysis Report ---")
        print(f"HTTP 200: {self.status_counts['200']}")
        print(f"HTTP 404: {self.status_counts['404']}")
        print(f"HTTP 500: {self.status_counts['500']}")
        
        print("\nTop 3 IP Addresses:")
        for ip, count in self.ip_counts.most_common(3):
            print(f"{ip}: {count} hits")
            
        # Security Alert Logic
        for ip, count in self.ip_counts.items():
            # Basic check: if an IP has > 50 hits, check if many are 404s
            # (Refining this logic will be a Phase 2 commit)
            if count > 50:
                print(f"!!! SECURITY ALERT: Potential Bot detected from {ip} !!!")


#feat: add initial regex for IP and status code extraction

#feat: implement status code frequency counting

#feat: implement IP hit tracking