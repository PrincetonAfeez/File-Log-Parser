# parser.py
"""High-level orchestration: stream a log file and coordinate analysis + reporting."""

# Enable postponed evaluation of annotations for forward compatibility with Python type hints.
from __future__ import annotations

# Standard library imports for logging, high-performance counting, and type safety.
import logging
from collections import Counter
from typing import Any

# Third-party library for non-blocking asynchronous file I/O operations.
import aiofiles

# Internal module imports for specialized log matching, building, and filtering logic.
from log_processing import AccessLogLineMatcher, LogEntryBuilder, NoisePathFilter
from models import LogEntry
from reporting import ReportExporter, SecurityAuditor, SummaryReporter, make_console
from settings import ParserSettings

# Configure the system logger to record internal events, errors, and warnings to 'parser.log'.
logging.basicConfig(
    filename="parser.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Re-export the primary RegEx pattern from the Matcher for external validation or testing use.
LOG_PATTERN = AccessLogLineMatcher.PATTERN


class LogParser:
    """
    End-to-end access log analysis for a single file path.

    Wires together line matching, validation, noise filtering, in-memory counters,
    and pluggable reporting. Intended to be driven once per file from the CLI.
    """

    def __init__(self, filepath: str, config_path: str = "config.yaml"):
        """Initialize the parser with the target file path and external YAML configurations."""
        self.filepath = filepath  # The path to the server log file to be analyzed.
        self.settings = ParserSettings.load(config_path)  # Load thresholds and ignore rules from YAML.
        self.console = make_console()  # Initialize the Rich console for beautiful terminal output.

        # Initialize helper components for the processing pipeline.
        self._matcher = AccessLogLineMatcher()  # The RegEx engine for line extraction.
        self._entry_builder = LogEntryBuilder()  # Logic for transforming raw strings into LogEntry objects.
        self._noise = NoisePathFilter(self.settings.ignore_extensions)  # Filter for static assets (.css, .js).
        self._summary = SummaryReporter()  # Component responsible for generating terminal tables.
        self._auditor = SecurityAuditor()  # Component for detecting bot behavior/404 floods.
        self._exporter = ReportExporter(self.console)  # Component for generating JSON/CSV files.

        # In-memory data stores for statistical analysis.
        self.status_counts: Counter[str] = Counter()  # Tracks frequency of HTTP codes (200, 404, etc.).
        self.ip_counts: Counter[str] = Counter()  # Tracks total hits per unique IP address.
        self.corrupted_lines = 0  # Counter for lines failing RegEx or validation.
        self.ip_404_counts: Counter[str] = Counter()  # Tracks specific 404 error frequency per IP.
        self.ignored_lines = 0  # Counter for valid lines filtered out as noise.

    @property
    def config(self) -> dict[str, Any]:
        """Provides a dictionary representation of the settings for backward compatibility."""
        return self.settings.as_dict()

    def _security_threshold(self) -> int:
        """Helper to retrieve the 404 alert limit from the loaded settings."""
        return self.settings.security_threshold

    async def run(self, threshold: int = 50) -> None:
        """
        Main execution flow: streams the file asynchronously and triggers final reports.
        
        Args:
            threshold: The manual override for security alerts (defaults to 50).
        """
        self.console.print("[info]Initiating Async Stream Analysis...[/info]")
        await self._ingest_file()  # Perform the non-blocking file read.
        self.print_summary(threshold=threshold)  # Display the visual tables in the terminal.
        self.check_security(threshold)  # Display security warnings if any IPs exceed limits.

    async def _ingest_file(self) -> None:
        """Asynchronously opens the log file and iterates through it line by line."""
        async with aiofiles.open(self.filepath, mode="r", encoding="utf-8") as f:
            async for line in f:
                self.parse_line(line.strip())  # Process each line while stripping surrounding whitespace.

    def parse_line(self, line: str) -> None:
        """
        The central logic for processing a single string into an analytical data point.
        
        Evaluates the line against RegEx, transforms it into a model, and updates counters.
        """
        if not line:  # Skip empty lines to prevent unnecessary processing.
            return

        # Attempt to extract fields (IP, Timestamp, Path, Status) via RegEx.
        match = self._matcher.search(line)
        if not match:
            # If the RegEx fails, record it as corrupted and log the event.
            self._record_corrupted(line, "Line did not match log pattern")
            return

        # Pass captured groups to the builder to create a structured LogEntry object.
        groups = match.groupdict()
        entry, build_error = self._entry_builder.build(groups)
        
        if entry is None:
            # Handle cases where RegEx matched but data failed validation (e.g., invalid IP range).
            self._log_build_failure(line, groups, build_error)
            self.corrupted_lines += 1
            return

        # Check if the requested path is a static asset or noise (e.g., favicon.ico).
        if self._noise.is_noise(entry):
            self.ignored_lines += 1
            return

        # If all checks pass, apply the data to our statistical counters.
        self._apply_entry(entry)

    def _record_corrupted(self, line: str, reason: str) -> None:
        """Log a warning and increment the corrupted counter for audit purposes."""
        self.corrupted_lines += 1
        logging.warning("%s: %r", reason, line[:80])  # Log a preview of the problematic line.

    def _log_build_failure(
        self, line: str, groups: dict[str, str], build_error: str | None
    ) -> None:
        """Specific logging logic for different types of validation failures."""
        if build_error == "invalid_ip":
            logging.warning("Invalid IP in line: %s...", line[:50])
        elif build_error == "invalid_timestamp":
            logging.error("Invalid timestamp format: %r", groups.get("timestamp", ""))
        # Failures for status codes are counted but don't require verbose logs.

    def _apply_entry(self, entry: LogEntry) -> None:
        """Update the internal counters with data from a validated LogEntry."""
        self.status_counts[str(entry.status)] += 1  # Increment frequency for this HTTP status code.
        self.ip_counts[entry.ip] += 1  # Increment total hit count for this IP.
        if entry.status == 404:
            self.ip_404_counts[entry.ip] += 1  # Specifically track 404 errors for security auditing.

    def check_security(self, threshold: int) -> None:
        """Delegate to the SecurityAuditor to print alerts for suspicious IP activity."""
        self._auditor.print_audit(self.console, self.ip_404_counts, threshold)

    def export_data(self, format_type: str, output_name: str = "report") -> None:
        """
        Coordinates the compilation and export of analysis data to external files.
        """
        alert_threshold = self._security_threshold()  # Get the default alert limit.
        
        # Construct the data structure (payload) for the export.
        payload = self._exporter.build_payload(
            status_counts=self.status_counts,
            ip_counts=self.ip_counts,
            ip_404_counts=self.ip_404_counts,
            corrupted_lines=self.corrupted_lines,
            ignored_lines=self.ignored_lines,
            alert_threshold=alert_threshold,
        )
        
        # Trigger the actual file write (JSON or CSV).
        self._exporter.export(
            format_type,
            output_name,
            payload=payload,
            ip_counts=self.ip_counts,
            ip_404_counts=self.ip_404_counts,
        )

    def print_summary(self, threshold: int | None = None) -> None:
        """Generates the visual summary report in the console using the SummaryReporter."""
        if threshold is None:
            threshold = self._security_threshold()  # Fallback to config threshold if none provided.
            
        self._summary.print_full_summary(
            self.console,
            status_counts=self.status_counts,
            ip_counts=self.ip_counts,
            ip_404_counts=self.ip_404_counts,
            corrupted_lines=self.corrupted_lines,
            ignored_lines=self.ignored_lines,
            threshold=threshold,
        )