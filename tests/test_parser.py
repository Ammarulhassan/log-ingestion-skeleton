from app.parser import format_line, parse_line

GOOD = "2026-09-23T10:15:02Z event_id=E0001 user_id=U1001 action=repay amount=250.00 status=success ip=10.0.0.5"


def test_extracts_core_fields():
    e = parse_line(GOOD)
    assert e["timestamp"] == "2026-09-23T10:15:02Z"
    assert e["user_id"] == "U1001"
    assert e["amount"] == 250.0
    assert e["status"] == "SUCCESS"  # normalised to upper-case
    assert e["ip"] == "10.0.0.5"


def test_quoted_value_with_spaces_and_quotes():
    e = parse_line("2026-09-23T10:00:00Z user_id=a status=FAILED payload=\"' OR '1'='1' --\"")
    assert e["payload"] == "' OR '1'='1' --"
    assert e["amount"] == 0.0  # default when missing


def test_blank_and_malformed_lines_return_none():
    assert parse_line("") is None
    assert parse_line(None) is None
    assert parse_line("garbage with no timestamp") is None
    assert parse_line("2026-09-23T10:00:00Z user_id=a") is None  # status missing
    assert parse_line("2026-09-23T10:00:00Z user_id=a status=OK amount=abc") is None


def test_format_line_round_trip():
    e = {"timestamp": "2026-09-23T10:00:00Z", "user_id": "x", "status": "FAILED", "amount": "0.00",
         "payload": 'a "b" \\ c'}
    parsed = parse_line(format_line(e))
    assert parsed["payload"] == 'a "b" \\ c'
    assert parsed["user_id"] == "x"
