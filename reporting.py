# reporting.py
"""Terminal summaries and file exports built from aggregated log metrics."""

# Enable postponed evaluation of annotations for modern type hinting support.
from __future__ import annotations

# Import standard libraries for data persistence (CSV/JSON) and type management.
import csv
import json
from collections import Counter
from typing import Any

# Import Rich library components to create professional, high-fidelity terminal interfaces.
from rich.console import Console
from rich.table import Table
from rich.theme import Theme

# Define a centralized color palette to ensure consistent UI branding across the CLI tool.
_CUSTOM_THEME = Theme({
    "info": "cyan",        # Used for general status updates.
    "warning": "yellow",   # Used for non-critical integrity issues.
    "danger": "bold red",  # Used for high-priority security alerts.
    "success": "bold green", # Used for completed operations and clean audits.
})


def make_console() -> Console:
    """Factory function to initialize a Rich console with the project's custom theme."""
    return Console(theme=_CUSTOM_THEME)


class SecurityAuditor:
    """
    Prints a short security section focused on IPs with many HTTP 404 responses.

    This is a heuristic (scanning or broken clients), not proof of malice.
    """

    def print_audit(self, console: Console, ip_404_counts: Counter[str], threshold: int) -> None:
        """Analyze 404 frequency and emit high-visibility Rich-styled terminal alerts."""
        console.print("\n[bold]-- Security Audit --[/bold]")
        found = False  # Track if any threats were detected to handle the 'clean' state.
        
        # Iterate through the counter to identify IPs exceeding the security threshold.
        for ip, count in ip_404_counts.items():
            if count > threshold:
                # Trigger a 'danger' styled alert for IPs flagged by the heuristic.
                console.print(
                    f"[danger]ALERT:[/danger] {ip} exceeded 404 threshold with {count} errors!"
                )
                found = True
        
        # If no IPs hit the threshold, provide positive reinforcement to the operator.
        if not found:
            console.print("[success]No suspicious activity detected.[/success]")


class SummaryReporter:
    """
    Renders status distribution (Rich table) and plain-text breakdowns to stdout.

    Separates table rendering from free-form lines so each piece stays easy to test
    or replace (e.g. JSON-only output later).
    """

    def print_full_summary(
        self,
        console: Console,
        *,
        status_counts: Counter[str],
        ip_counts: Counter[str],
        ip_404_counts: Counter[str],
        corrupted_lines: int,
        ignored_lines: int,
        threshold: int,
    ) -> None:
        """Orchestrate the sequential printing of all summary sections after a run."""
        self._print_status_table(console, status_counts)        # Render the visual histogram.
        self._print_http_highlights(status_counts)             # Print specific code counts.
        self._print_top_ips(ip_counts)                         # Identify the most active clients.
        self._print_bot_heuristics(ip_counts, threshold)       # Flag high-volume traffic.
        self._print_integrity(status_counts, corrupted_lines, ignored_lines) # Show data quality.
        self._print_404_alerts(ip_404_counts, threshold)       # Output text-based security logs.

    def _print_status_table(self, console: Console, status_counts: Counter[str]) -> None:
        """Construct and render a formatted Rich table showing the HTTP status distribution."""
        table = Table(
            title="HTTP Status Distribution",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Status Code", style="dim")  # Column for the 3-digit HTTP code.
        table.add_column("Occurrences", justify="right") # Column for the hit frequency.
        
        # Sort status codes numerically for a clean, logical display.
        for code, count in sorted(status_counts.items(), key=lambda x: int(x[0])):
            table.add_row(code, str(count))
        
        console.print(table)

    def _print_http_highlights(self, status_counts: Counter[str]) -> None:
        """Extract and print high-level metrics for the most critical HTTP codes."""
        print("\n--- Log Analysis Report ---")
        print(f"HTTP 200: {status_counts.get('200', 0)}") # Successes.
        print(f"HTTP 404: {status_counts.get('404', 0)}") # Client Errors/Missing.
        print(f"HTTP 500: {status_counts.get('500', 0)}") # Server Errors.

    def _print_top_ips(self, ip_counts: Counter[str], limit: int = 3) -> None:
        """Identify and list the IPs responsible for the highest volume of traffic."""
        print(f"\nTop {limit} IP Addresses:")
        for ip, count in ip_counts.most_common(limit):
            print(f"{ip}: {count} hits")

    def _print_bot_heuristics(self, ip_counts: Counter[str], threshold: int) -> None:
        """Evaluate raw hit volume per IP to identify potential non-human traffic."""
        for ip, count in ip_counts.items():
            if count > threshold:
                print(f"!!! SECURITY ALERT: Potential Bot detected from {ip} !!!")

    def _print_integrity(
        self,
        status_counts: Counter[str],
        corrupted_lines: int,
        ignored_lines: int,
    ) -> None:
        """Calculate and display data quality metrics to ensure the audit is reliable."""
        matched = sum(status_counts.values()) # Total lines that passed all guards.
        print("\n--- Integrity Report ---")
        # Sum all categories to show the true total line count of the source file.
        print(f"Lines Processed: {matched + corrupted_lines + ignored_lines}")
        print(f"Malformed/Corrupted Lines: {corrupted_lines}") # Lines failing RegEx/Validation.
        print(f"Ignored (noise): {ignored_lines}") # Static assets filtered out.

    def _print_404_alerts(self, ip_404_counts: Counter[str], threshold: int) -> None:
        """Provide a plain-text section for security alerts, ideal for CLI pipe redirection."""
        print("\n--- Security Alerts ---")
        for ip, count in ip_404_counts.items():
            if count > threshold:
                print(f"[ALERT] {ip} flagged for suspicious activity ({count} 404s)")


class ReportExporter:
    """
    Serializes the same aggregates shown in the console to JSON or CSV files.

    JSON is structured for dashboards; CSV is flat per-IP for spreadsheets.
    """

    def __init__(self, console: Console):
        """Initialize the exporter with a reference to the active Rich console."""
        self._console = console

    def build_payload(
        self,
        *,
        status_counts: Counter[str],
        ip_counts: Counter[str],
        ip_404_counts: Counter[str],
        corrupted_lines: int,
        ignored_lines: int,
        alert_threshold: int,
    ) -> dict[str, Any]:
        """Convert Counter objects into a standard Python dictionary for serialization."""
        return {
            "summary": dict(status_counts), # Map of status codes to frequencies.
            "top_ips": dict(ip_counts.most_common(5)), # Limit IP breakdown to top 5.
            "security_alerts": [
                # Build a list of IPs that triggered the security heuristic.
                ip for ip, count in ip_404_counts.items() if count > alert_threshold
            ],
            "integrity_metrics": {
                "corrupted": corrupted_lines,
                "ignored": ignored_lines,
            },
        }

    def export(
        self,
        format_type: str,
        output_name: str,
        *,
        payload: dict[str, Any],
        ip_counts: Counter[str],
        ip_404_counts: Counter[str],
    ) -> None:
        """Determine the export format and trigger the appropriate file-writing method."""
        if format_type == "json":
            self._write_json(output_name, payload)
        elif format_type == "csv":
            self._write_csv(output_name, ip_counts, ip_404_counts)
        else:
            # Raise an error if the user provides an unsupported CLI flag.
            raise ValueError(f"Unsupported export format: {format_type!r}")

    def _write_json(self, output_name: str, payload: dict[str, Any]) -> None:
        """Serialize the processed data into a formatted JSON file on disk."""
        path = f"{output_name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4) # Use 4-space indentation for human readability.
        self._console.print(f"[success]Report exported to {path}[/success]")

    def _write_csv(
        self,
        output_name: str,
        ip_counts: Counter[str],
        ip_404_counts: Counter[str],
    ) -> None:
        """Serialize IP-specific metrics into a CSV file for spreadsheet analysis."""
        path = f"{output_name}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Define header row for clarity in Excel/Google Sheets.
            writer.writerow(["IP Address", "Total Hits", "404 Errors"])
            # Iterate through all observed IPs to provide a comprehensive hit list.
            for ip, hits in ip_counts.items():
                writer.writerow([ip, hits, ip_404_counts.get(ip, 0)])
        self._console.print(f"[success]Report exported to {path}[/success]")