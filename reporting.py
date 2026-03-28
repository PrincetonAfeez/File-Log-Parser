"""Terminal summaries and file exports built from aggregated log metrics."""

from __future__ import annotations

import csv
import json
from collections import Counter
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.theme import Theme

_CUSTOM_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "bold green",
})


def make_console() -> Console:
    """Create a Rich console using the project's standard color theme."""
    return Console(theme=_CUSTOM_THEME)


class SecurityAuditor:
    """
    Prints a short security section focused on IPs with many HTTP 404 responses.

    This is a heuristic (scanning or broken clients), not proof of malice.
    """

    def print_audit(self, console: Console, ip_404_counts: Counter[str], threshold: int) -> None:
        """Emit Rich-styled alerts for any IP above ``threshold`` 404 count."""
        console.print("\n[bold]-- Security Audit --[/bold]")
        found = False
        for ip, count in ip_404_counts.items():
            if count > threshold:
                console.print(
                    f"[danger]ALERT:[/danger] {ip} exceeded 404 threshold with {count} errors!"
                )
                found = True
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
        """Print the full post-run summary: table, highlights, integrity, alerts."""
        self._print_status_table(console, status_counts)
        self._print_http_highlights(status_counts)
        self._print_top_ips(ip_counts)
        self._print_bot_heuristics(ip_counts, threshold)
        self._print_integrity(status_counts, corrupted_lines, ignored_lines)
        self._print_404_alerts(ip_404_counts, threshold)

    def _print_status_table(self, console: Console, status_counts: Counter[str]) -> None:
        """Draw the HTTP status code histogram using Rich."""
        table = Table(
            title="HTTP Status Distribution",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Status Code", style="dim")
        table.add_column("Occurrences", justify="right")
        for code, count in sorted(status_counts.items(), key=lambda x: int(x[0])):
            table.add_row(code, str(count))
        console.print(table)

    def _print_http_highlights(self, status_counts: Counter[str]) -> None:
        """Print fixed code lines (200/404/500) for quick scanning."""
        print("\n--- Log Analysis Report ---")
        print(f"HTTP 200: {status_counts.get('200', 0)}")
        print(f"HTTP 404: {status_counts.get('404', 0)}")
        print(f"HTTP 500: {status_counts.get('500', 0)}")

    def _print_top_ips(self, ip_counts: Counter[str], limit: int = 3) -> None:
        """List the busiest IPs by total request count (``limit`` rows)."""
        print(f"\nTop {limit} IP Addresses:")
        for ip, count in ip_counts.most_common(limit):
            print(f"{ip}: {count} hits")

    def _print_bot_heuristics(self, ip_counts: Counter[str], threshold: int) -> None:
        """Flag IPs with very high total hit counts (coarse bot/scanner hint)."""
        for ip, count in ip_counts.items():
            if count > threshold:
                print(f"!!! SECURITY ALERT: Potential Bot detected from {ip} !!!")

    def _print_integrity(
        self,
        status_counts: Counter[str],
        corrupted_lines: int,
        ignored_lines: int,
    ) -> None:
        """Show how many lines matched, failed parsing, or were ignored as noise."""
        matched = sum(status_counts.values())
        print("\n--- Integrity Report ---")
        print(f"Lines Processed: {matched + corrupted_lines + ignored_lines}")
        print(f"Malformed/Corrupted Lines: {corrupted_lines}")
        print(f"Ignored (noise): {ignored_lines}")

    def _print_404_alerts(self, ip_404_counts: Counter[str], threshold: int) -> None:
        """Repeat 404-focused alerts in plain text for log capture / piping."""
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
        """Assemble the dictionary shared by JSON export (and future formats)."""
        return {
            "summary": dict(status_counts),
            "top_ips": dict(ip_counts.most_common(5)),
            "security_alerts": [
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
        """
        Write aggregates to disk.

        JSON uses ``payload`` only. CSV needs full ``ip_counts`` / ``ip_404_counts``
        so every IP appears, not just the ``top_ips`` slice in the payload.
        """
        if format_type == "json":
            self._write_json(output_name, payload)
        elif format_type == "csv":
            self._write_csv(output_name, ip_counts, ip_404_counts)
        else:
            raise ValueError(f"Unsupported export format: {format_type!r}")

    def _write_json(self, output_name: str, payload: dict[str, Any]) -> None:
        """Serialize ``payload`` to indented UTF-8 JSON next to the working directory."""
        path = f"{output_name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)
        self._console.print(f"[success]Report exported to {path}[/success]")

    def _write_csv(
        self,
        output_name: str,
        ip_counts: Counter[str],
        ip_404_counts: Counter[str],
    ) -> None:
        """Write UTF-8 CSV with columns IP / total hits / 404 count for every known IP."""
        path = f"{output_name}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Total Hits", "404 Errors"])
            for ip, hits in ip_counts.items():
                writer.writerow([ip, hits, ip_404_counts.get(ip, 0)])
        self._console.print(f"[success]Report exported to {path}[/success]")
