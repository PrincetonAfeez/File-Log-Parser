# parser.py
import re
from collections import Counter
from typing import Dict, List, Any
from exceptions import InvalidLogFormatError
import ipaddress
from models import LogEntry

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
        self.corrupted_lines = 0
        self.ip_404_counts = Counter()
        self.ignored_lines = 0

    def run(self):
        try:
            with open(self.filepath, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    try:
                        self.parse_line(line.strip())
                    except Exception as e:
                        print(f"Unexpected error on line {line_num}: {e}")
                        self.corrupted_lines += 1
            self.print_summary()
        except FileNotFoundError:
            print(f"Error: {self.filepath} does not exist.")
            

    def is_noise(self, entry: LogEntry) -> bool:
        """Filter out static assets or health checks."""
        return entry.path.endswith(('.css', '.js', '.png', '.ico'))

    def parse_line(self, line: str):
        match = LOG_PATTERN.search(line)
        if match:
            group = match.groupdict()
            try:
                # Validate IP first
                ip_obj = ipaddress.ip_address(group['ip'])
                
                # Create structured entry
                entry = LogEntry(
                    ip=str(ip_obj),
                    timestamp=group['timestamp'],
                    method=group['method'],
                    path=group['path'],
                    status=int(group['status'])
                )
                
                if self.is_noise(entry):
                    self.ignored_lines += 1
                    return
                # Update counters using entry attributes
                self.status_counts[str(entry.status)] += 1
                self.ip_counts[entry.ip] += 1
                if entry.status == 404:
                    self.ip_404_counts[entry.ip] += 1
                    
            except (ValueError, KeyError):
                self.corrupted_lines += 1
        
        data = match.groupdict()
        self.status_counts[data['status']] += 1
        self.ip_counts[data['ip']] += 1
        if data['status'] == '404':
            self.ip_404_counts[data['ip']] += 1
        try:
            ip_obj = ipaddress.ip_address(data['ip'])
            self.ip_counts[str(ip_obj)] += 1
            self.status_counts[data['status']] += 1
        except ValueError:
            self.corrupted_lines += 1

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

        print("\n--- Integrity Report ---")
        print(f"Lines Processed: {sum(self.status_counts.values()) + self.corrupted_lines}")
        print(f"Malformed/Corrupted Lines: {self.corrupted_lines}")
        
        print("\n--- Security Alerts ---")
        for ip, count in self.ip_404_counts.items():
            if count > 50:
                print(f"[ALERT] {ip} flagged for suspicious activity ({count} 404s)")
    


    