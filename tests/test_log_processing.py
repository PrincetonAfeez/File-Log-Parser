"""Unit tests for line matching, entry building, and noise filtering."""

import pytest

from log_processing import AccessLogLineMatcher, LogEntryBuilder, NoisePathFilter
from models import LogEntry


@pytest.fixture
def builder() -> LogEntryBuilder:
    return LogEntryBuilder()


@pytest.fixture
def valid_groups() -> dict[str, str]:
    return {
        "ip": "192.168.1.1",
        "timestamp": "28/Mar/2024:10:01:05",
        "method": "GET",
        "path": "/home",
        "status": "200",
    }


def test_log_entry_builder_success(builder: LogEntryBuilder, valid_groups: dict[str, str]):
    entry, err = builder.build(valid_groups)
    assert err is None
    assert entry == LogEntry(
        ip="192.168.1.1",
        timestamp="28/Mar/2024:10:01:05",
        method="GET",
        path="/home",
        status=200,
    )


def test_log_entry_builder_invalid_ip(builder: LogEntryBuilder, valid_groups: dict[str, str]):
    valid_groups["ip"] = "999.999.999.999"
    entry, err = builder.build(valid_groups)
    assert entry is None
    assert err == "invalid_ip"


def test_log_entry_builder_invalid_timestamp(
    builder: LogEntryBuilder, valid_groups: dict[str, str]
):
    valid_groups["timestamp"] = "not-a-date"
    entry, err = builder.build(valid_groups)
    assert entry is None
    assert err == "invalid_timestamp"


def test_log_entry_builder_invalid_status(builder: LogEntryBuilder, valid_groups: dict[str, str]):
    valid_groups["status"] = "2xx"
    entry, err = builder.build(valid_groups)
    assert entry is None
    assert err == "invalid_status"


def test_access_log_line_matcher_search():
    matcher = AccessLogLineMatcher()
    line = (
        '192.168.1.1 - - [28/Mar/2024:10:01:05] "GET /home HTTP/1.1" 200 512'
    )
    m = matcher.search(line)
    assert m is not None
    assert m.group("ip") == "192.168.1.1"
    assert m.group("status") == "200"


def test_noise_path_filter_matches_suffix():
    flt = NoisePathFilter((".css", ".js"))
    entry = LogEntry(
        ip="10.0.0.1",
        timestamp="28/Mar/2024:10:01:05",
        method="GET",
        path="/static/app.css",
        status=200,
    )
    assert flt.is_noise(entry) is True
    assert flt.is_noise(
        LogEntry(
            ip="10.0.0.1",
            timestamp="28/Mar/2024:10:01:05",
            method="GET",
            path="/api/data",
            status=200,
        )
    ) is False
