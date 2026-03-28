# parser.py
"""High-level orchestration: stream a log file and coordinate analysis + reporting."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

import aiofiles

from log_processing import AccessLogLineMatcher, LogEntryBuilder, NoisePathFilter
from models import LogEntry
from reporting import ReportExporter, SecurityAuditor, SummaryReporter, make_console
from settings import ParserSettings

logging.basicConfig(
    filename="parser.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Re-export for tests and callers that need the raw pattern.
LOG_PATTERN = AccessLogLineMatcher.PATTERN


class LogParser:
    """
    End-to-end access log analysis for a single file path.

    Wires together line matching, validation, noise filtering, in-memory counters,
    and pluggable reporting. Intended to be driven once per file from the CLI.
    """

    def __init__(self, filepath: str, config_path: str = "config.yaml"):
        self.filepath = filepath
        self.settings = ParserSettings.load(config_path)
        self.console = make_console()

        self._matcher = AccessLogLineMatcher()
        self._entry_builder = LogEntryBuilder()
        self._noise = NoisePathFilter(self.settings.ignore_extensions)
        self._summary = SummaryReporter()
        self._auditor = SecurityAuditor()
        self._exporter = ReportExporter(self.console)

        self.status_counts: Counter[str] = Counter()
        self.ip_counts: Counter[str] = Counter()
        self.corrupted_lines = 0
        self.ip_404_counts: Counter[str] = Counter()
        self.ignored_lines = 0

    @property
    def config(self) -> dict[str, Any]:
        """Shallow copy of YAML root; same shape older code expected on ``parser.config``."""
        return self.settings.as_dict()

    def _security_threshold(self) -> int:
        """404 count above which an IP is treated as noteworthy in exports."""
        return self.settings.security_threshold

    async def run(self, threshold: int = 50) -> None:
        """
        Read the log file asynchronously, parse each non-empty line, then print results.

        ``threshold`` is forwarded to the summary and security audit sections for
        404- and hit-based heuristics.
        """
        self.console.print("[info]Initiating Async Stream Analysis...[/info]")
        await self._ingest_file()
        self.print_summary(threshold=threshold)
        self.check_security(threshold)

    async def _ingest_file(self) -> None:
        """Stream ``self.filepath`` line by line and feed each line to :meth:`parse_line`."""
        async with aiofiles.open(self.filepath, mode="r", encoding="utf-8") as f:
            async for line in f:
                self.parse_line(line.strip())

    def parse_line(self, line: str) -> None:
        """
        Parse one log line: update counters or increment corruption / ignore tallies.

        Empty lines are skipped. Lines that fail regex, validation, or are classified
        as noise update the appropriate metric and return without raising.
        """
        if not line:
            return

        match = self._matcher.search(line)
        if not match:
            self._record_corrupted(line, "Line did not match log pattern")
            return

        groups = match.groupdict()
        entry, build_error = self._entry_builder.build(groups)
        if entry is None:
            self._log_build_failure(line, groups, build_error)
            self.corrupted_lines += 1
            return

        if self._noise.is_noise(entry):
            self.ignored_lines += 1
            return

        self._apply_entry(entry)

    def _record_corrupted(self, line: str, reason: str) -> None:
        """Increment the corrupted counter and log a short preview for debugging."""
        self.corrupted_lines += 1
        logging.warning("%s: %r", reason, line[:80])

    def _log_build_failure(
        self, line: str, groups: dict[str, str], build_error: str | None
    ) -> None:
        """Emit the same log levels as legacy parsing for each validation failure."""
        if build_error == "invalid_ip":
            logging.warning("Invalid IP in line: %s...", line[:50])
        elif build_error == "invalid_timestamp":
            logging.error("Invalid timestamp format: %r", groups.get("timestamp", ""))
        # invalid_status: match prior behavior (count corrupted, no extra log)

    def _apply_entry(self, entry: LogEntry) -> None:
        """Merge a validated, non-noise entry into status and IP counters."""
        self.status_counts[str(entry.status)] += 1
        self.ip_counts[entry.ip] += 1
        if entry.status == 404:
            self.ip_404_counts[entry.ip] += 1

    def check_security(self, threshold: int) -> None:
        """Print Rich-formatted alerts for IPs exceeding ``threshold`` 404 responses."""
        self._auditor.print_audit(self.console, self.ip_404_counts, threshold)

    def export_data(self, format_type: str, output_name: str = "report") -> None:
        """
        Write JSON or CSV under ``{output_name}.(json|csv)`` using current counters.

        Security alert lists inside JSON use the configured default threshold from YAML.
        """
        alert_threshold = self._security_threshold()
        payload = self._exporter.build_payload(
            status_counts=self.status_counts,
            ip_counts=self.ip_counts,
            ip_404_counts=self.ip_404_counts,
            corrupted_lines=self.corrupted_lines,
            ignored_lines=self.ignored_lines,
            alert_threshold=alert_threshold,
        )
        self._exporter.export(
            format_type,
            output_name,
            payload=payload,
            ip_counts=self.ip_counts,
            ip_404_counts=self.ip_404_counts,
        )

    def print_summary(self, threshold: int | None = None) -> None:
        """Print tables and text sections; ``threshold`` defaults to config when omitted."""
        if threshold is None:
            threshold = self._security_threshold()
        self._summary.print_full_summary(
            self.console,
            status_counts=self.status_counts,
            ip_counts=self.ip_counts,
            ip_404_counts=self.ip_404_counts,
            corrupted_lines=self.corrupted_lines,
            ignored_lines=self.ignored_lines,
            threshold=threshold,
        )
