from parser import LOG_PATTERN

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