"""Log parser: turns one raw log line into a dict (or None if malformed).

Line format (key=value pairs after an ISO-8601 UTC timestamp):

    2026-09-23T10:15:02Z event_id=E0001 user_id=U1001 action=repay amount=250.00 status=SUCCESS ip=10.0.0.5
    2026-09-23T10:16:11Z event_id=A0003 user_id=admin action=login status=FAILED ip=203.0.113.66 payload="' OR '1'='1' --"
"""
import re

LINE_RE = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(?P<rest>.+)$")
KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
REQUIRED = ("user_id", "status")


def _unquote(value: str) -> str:
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


def parse_line(line: str):
    """Return a parsed event dict, or None if the line is blank/malformed."""
    line = (line or "").strip()
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        return None
    event = {"timestamp": m.group("timestamp")}
    for key, value in KV_RE.findall(m.group("rest")):
        event[key] = _unquote(value)
    if any(k not in event for k in REQUIRED):
        return None
    try:
        event["amount"] = float(event.get("amount", 0))
    except ValueError:
        return None
    event["status"] = event["status"].upper()
    return event


def format_line(event: dict) -> str:
    """Inverse of parse_line - used by the vulnerable lab app and log generator."""
    parts = [event["timestamp"]]
    for key, value in event.items():
        if key == "timestamp":
            continue
        value = str(value)
        if not value or re.search(r'[\s"\\]', value):
            value = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        parts.append(f"{key}={value}")
    return " ".join(parts)
