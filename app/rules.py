"""Detection rule engine. Rules live in JSON (see rules/rules.json and README)."""
import json
import re
from collections import defaultdict, deque
from datetime import datetime

OPS = {
    "gt": lambda a, b: float(a) > float(b),
    "gte": lambda a, b: float(a) >= float(b),
    "lt": lambda a, b: float(a) < float(b),
    "eq": lambda a, b: str(a) == str(b),
    "ne": lambda a, b: str(a) != str(b),
    "contains": lambda a, b: str(b).lower() in str(a).lower(),
    "regex": lambda a, b: re.search(b, str(a)) is not None,
}
RULE_TYPES = ("threshold", "rate")


class RuleError(ValueError):
    pass


def _ts(event):
    return datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%SZ")


class Rule:
    def __init__(self, spec: dict):
        for key in ("id", "name", "severity", "type"):
            if key not in spec:
                raise RuleError(f"rule missing '{key}': {spec}")
        if spec["type"] not in RULE_TYPES:
            raise RuleError(f"unknown rule type '{spec['type']}'")
        self.id = spec["id"]
        self.name = spec["name"]
        self.severity = spec["severity"]
        self.type = spec["type"]
        self.where = spec.get("where", {})  # equality pre-filter, e.g. {"status": "FAILED"}
        if self.type == "threshold":
            for key in ("field", "op", "value"):
                if key not in spec:
                    raise RuleError(f"threshold rule '{self.id}' missing '{key}'")
            if spec["op"] not in OPS:
                raise RuleError(f"unknown op '{spec['op']}'")
            self.field, self.op, self.value = spec["field"], spec["op"], spec["value"]
        else:  # rate: N matching events from the same group within a time window
            for key in ("count", "window_seconds", "group_by"):
                if key not in spec:
                    raise RuleError(f"rate rule '{self.id}' missing '{key}'")
            self.count = int(spec["count"])
            self.window = int(spec["window_seconds"])
            self.group_by = spec["group_by"]

    def _prefilter(self, event):
        return all(str(event.get(k)) == str(v) for k, v in self.where.items())


class RuleEngine:
    def __init__(self, rules):
        self.rules = rules
        self._windows = defaultdict(deque)  # (rule_id, group) -> timestamps

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as fh:
            specs = json.load(fh)
        if isinstance(specs, dict):
            specs = specs.get("rules", [])
        return cls([Rule(s) for s in specs])

    def evaluate(self, event: dict):
        alerts = []
        for rule in self.rules:
            if not rule._prefilter(event):
                continue
            hit, detail = False, ""
            if rule.type == "threshold":
                if rule.field in event and OPS[rule.op](event[rule.field], rule.value):
                    hit = True
                    detail = f"{rule.field} {rule.op} {rule.value} (got {event[rule.field]})"
            else:
                group = event.get(rule.group_by)
                if group is not None:
                    key = (rule.id, group)
                    window = self._windows[key]
                    now = _ts(event)
                    window.append(now)
                    while (now - window[0]).total_seconds() > rule.window:
                        window.popleft()
                    if len(window) >= rule.count:
                        hit = True
                        detail = f"{len(window)} events from {rule.group_by}={group} within {rule.window}s"
                        window.clear()  # avoid re-alerting on every following event
            if hit:
                alerts.append({
                    "rule_id": rule.id, "rule_name": rule.name, "severity": rule.severity,
                    "event_id": event.get("event_id", ""), "user_id": event.get("user_id", ""),
                    "ip": event.get("ip", ""), "timestamp": event["timestamp"], "detail": detail,
                })
        return alerts
