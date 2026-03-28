# parser.py
import re
from collections import Counter
from typing import Dict, List, Any
from exceptions import InvalidLogFormatError
import ipaddress
from models import LogEntry
from rich.console import Console
from rich.theme import Theme
from rich.table import Table
import os
from rich.progress import track
import csv
import yaml


# Enterprise-grade regex with named groups
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'       # Matches IP
    r'.*?\[(?P<timestamp>.*?)\] '            # Matches Timestamp
    r'"(?P<method>\w+) (?P<path>.*?) HTTP.*?" ' # Matches Method & Path
    r'(?P<status>\d{3})'                     # Matches Status Code
)

# Custom theme for enterprise branding
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "bold green"
})

class LogParser:
    def __init__(self, filepath: str):
        self.console = Console(theme=custom_theme)
        self.filepath = filepath
        self.status_counts = Counter()
        self.ip_counts = Counter()
        self.corrupted_lines = 0
        self.ip_404_counts = Counter()
        self.ignored_lines = 0
        with open("config.yaml", "r") as f:
            self.config = yaml.safe_load(f)

   def run(self, threshold: int = 50):
        self.console.print(f"[info]Starting Analysis on {self.filepath}...[/info]")
        
        # Open file once to get line count for the progress bar
        with open(self.filepath, 'r') as f:
            lines = f.readlines()

        for line in track(lines, description="Processing logs..."):
            self.parse_line(line.strip())
            
        self.print_summary()
        self.check_security(threshold)


    def is_noise(self, entry: LogEntry) -> bool:
        return any(entry.path.endswith(ext) for ext in self.config['parser']['ignore_extensions'])

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

    def check_security(self, threshold: int):
        self.console.print("\n[bold]-- Security Audit --[/bold]")
        found_threats = False
        for ip, count in self.ip_404_counts.items():
            if count > threshold:
                self.console.print(f"[danger]ALERT:[/danger] {ip} exceeded 404 threshold with {count} errors!")
                found_threats = True
        
        if not found_threats:
            self.console.print("[success]No suspicious activity detected.[/success]")

    def export_data(self, format_type: str):
        report = {
            "summary": dict(self.status_counts),
            "top_ips": dict(self.ip_counts.most_common(5)),
            "security_alerts": [ip for ip, count in self.ip_404_counts.items() if count > 50],
            "integrity_metrics": {
                "corrupted": self.corrupted_lines,
                "ignored": self.ignored_lines
            }
        }
        
        if format_type == 'json':
            with open("report.json", "w") as f:
                json.dump(report, f, indent=4)
            self.console.print("[success]Report exported to report.json[/success]")
        
        if format_type == 'csv':
            with open("ip_report.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "Total Hits", "404 Errors"])
                for ip, hits in self.ip_counts.items():
                    writer.writerow([ip, hits, self.ip_404_counts.get(ip, 0)])
            self.console.print("[success]Report exported to ip_report.csv[/success]")
            filename = f"{output_name}.{format_type}"

    def print_summary(self):
        table = Table(title="HTTP Status Distribution", show_header=True, header_style="bold magenta")
        table.add_column("Status Code", style="dim")
        table.add_column("Occurrences", justify="right")

        for code, count in self.status_counts.items():
            table.add_row(code, str(count))

        self.console.print(table)
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
        
    


    