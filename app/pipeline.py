"""Glue: read a log file, parse every line, run the rule engine."""
from .parser import parse_line
from .rules import RuleEngine


def process_lines(lines, engine: RuleEngine):
    events, alerts = [], []
    for line in lines:
        event = parse_line(line)
        if event is None:
            continue
        events.append(event)
        alerts.extend(engine.evaluate(event))
    return events, alerts


def process_file(path, rules_path):
    """Fresh engine per file so rate-rule state never leaks between files."""
    engine = RuleEngine.from_file(rules_path)
    with open(path, encoding="utf-8") as fh:
        return process_lines(fh, engine)
