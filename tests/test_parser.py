import pytest
from parser import LogParser, LOG_PATTERN

def test_regex_valid_line():
    line = '192.168.1.1 - - [28/Mar/2024:10:01:05] "GET /home HTTP/1.1" 200 512'
    match = LOG_PATTERN.search(line)
    assert match is not None
    assert match.group('ip') == '192.168.1.1'
    assert match.group('status') == '200'

def test_regex_invalid_line():
    line = 'INVALID_LOG_DATA_12345'
    match = LOG_PATTERN.search(line)
    assert match is None

def test_ip_validation(tmp_path):
    # Create a temporary log file with a fake IP
    d = tmp_path / "subdir"
    d.mkdir()
    p = d / "test.log"
    p.write_text('999.999.999.999 - - [28/Mar/2024:10:01:05] "GET / HTTP/1.1" 200 512')
    
    parser = LogParser(str(p))
    parser.parse_line(p.read_text())
    assert parser.corrupted_lines == 1