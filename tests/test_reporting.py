"""Unit tests for report payload construction and file export."""

import json
from collections import Counter
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from reporting import ReportExporter


@pytest.fixture
def quiet_console() -> Console:
    return Console(file=StringIO(), width=120, force_terminal=True)


@pytest.fixture
def exporter(quiet_console: Console) -> ReportExporter:
    return ReportExporter(quiet_console)


def test_build_payload_shape_and_security_alerts(exporter: ReportExporter):
    status = Counter({"200": 10, "404": 3})
    ips = Counter({"1.1.1.1": 8, "2.2.2.2": 5})
    ip_404 = Counter({"1.1.1.1": 60, "2.2.2.2": 1})
    payload = exporter.build_payload(
        status_counts=status,
        ip_counts=ips,
        ip_404_counts=ip_404,
        corrupted_lines=2,
        ignored_lines=1,
        alert_threshold=50,
    )
    assert payload["summary"] == {"200": 10, "404": 3}
    assert payload["integrity_metrics"] == {"corrupted": 2, "ignored": 1}
    assert payload["security_alerts"] == ["1.1.1.1"]
    assert len(payload["top_ips"]) <= 5
    assert "1.1.1.1" in payload["top_ips"]


def test_export_json_writes_file(exporter: ReportExporter, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = {
        "summary": {"200": 1},
        "top_ips": {"9.9.9.9": 1},
        "security_alerts": [],
        "integrity_metrics": {"corrupted": 0, "ignored": 0},
    }
    exporter.export(
        "json",
        "out",
        payload=payload,
        ip_counts=Counter({"9.9.9.9": 1}),
        ip_404_counts=Counter(),
    )
    path = tmp_path / "out.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["summary"]["200"] == 1


def test_export_csv_all_ips(exporter: ReportExporter, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = exporter.build_payload(
        status_counts=Counter({"200": 2}),
        ip_counts=Counter({"10.0.0.1": 2, "10.0.0.2": 1}),
        ip_404_counts=Counter({"10.0.0.1": 5}),
        corrupted_lines=0,
        ignored_lines=0,
        alert_threshold=50,
    )
    exporter.export(
        "csv",
        "ips",
        payload=payload,
        ip_counts=Counter({"10.0.0.1": 2, "10.0.0.2": 1}),
        ip_404_counts=Counter({"10.0.0.1": 5}),
    )
    text = (tmp_path / "ips.csv").read_text(encoding="utf-8")
    assert "10.0.0.1" in text and "10.0.0.2" in text
    assert "404 Errors" in text


def test_export_unknown_format_raises(exporter: ReportExporter):
    with pytest.raises(ValueError, match="Unsupported export format"):
        exporter.export(
            "xml",
            "nope",
            payload={},
            ip_counts=Counter(),
            ip_404_counts=Counter(),
        )
