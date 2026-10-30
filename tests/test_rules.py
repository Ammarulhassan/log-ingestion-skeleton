import json
import os
import tempfile

from app.rules import Rule, RuleEngine, RuleError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules", "rules.json")


def ev(ts="2026-09-23T10:00:00Z", **kw):
    base = {"timestamp": ts, "user_id": "U1", "status": "SUCCESS", "amount": 0.0, "ip": "1.1.1.1", "event_id": "E1"}
    base.update(kw)
    return base


def test_amount_over_10000_is_flagged():
    engine = RuleEngine.from_file(RULES)
    alerts = engine.evaluate(ev(amount=10000.01))
    assert [a["rule_id"] for a in alerts] == ["R001"]


def test_amount_at_or_below_10000_not_flagged():
    engine = RuleEngine.from_file(RULES)
    assert engine.evaluate(ev(amount=10000.0)) == []
    assert engine.evaluate(ev(amount=250.0)) == []


def test_sql_injection_payload_flagged_and_clean_payload_not():
    engine = RuleEngine.from_file(RULES)
    for p in ["' OR '1'='1' --", "x' UNION SELECT 1", "a'; DROP TABLE users; --"]:
        assert any(a["rule_id"] == "R002" for a in engine.evaluate(ev(payload=p))), p
    assert engine.evaluate(ev(payload="hello world")) == []


def test_failed_login_burst_fires_once_after_threshold():
    engine = RuleEngine.from_file(RULES)
    fired = []
    for i in range(7):
        t = f"2026-09-23T10:00:{i * 5:02d}Z"
        fired += engine.evaluate(ev(ts=t, action="login", status="FAILED", ip="9.9.9.9"))
    assert len(fired) == 1 and fired[0]["rule_id"] == "R003"


def test_slow_failures_outside_window_do_not_fire():
    engine = RuleEngine.from_file(RULES)
    fired = []
    for i in range(7):
        t = f"2026-09-23T10:{i * 5:02d}:00Z"  # 5 minutes apart
        fired += engine.evaluate(ev(ts=t, action="login", status="FAILED"))
    assert fired == []


def test_failures_from_different_ips_are_not_combined():
    engine = RuleEngine.from_file(RULES)
    fired = []
    for i in range(6):
        fired += engine.evaluate(ev(ts=f"2026-09-23T10:00:{i:02d}Z", action="login", status="FAILED", ip=f"1.1.1.{i}"))
    assert fired == []


def test_invalid_rules_raise():
    for bad in [{"id": "x"}, {"id": "x", "name": "n", "severity": "low", "type": "magic"},
                {"id": "x", "name": "n", "severity": "low", "type": "threshold", "field": "a", "op": "zzz", "value": 1},
                {"id": "x", "name": "n", "severity": "low", "type": "threshold", "field": "a"},
                {"id": "x", "name": "n", "severity": "low", "type": "rate", "count": 3}]:
        try:
            Rule(bad)
        except RuleError:
            continue
        raise AssertionError(f"expected RuleError for {bad}")


def test_from_file_accepts_dict_wrapper_and_where_filter():
    spec = {"rules": [{"id": "T", "name": "t", "severity": "low", "type": "threshold", "field": "amount",
                       "op": "gte", "value": 5, "where": {"status": "FAILED"}}]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(spec, fh)
    engine = RuleEngine.from_file(fh.name)
    assert engine.evaluate(ev(amount=9, status="SUCCESS")) == []
    assert len(engine.evaluate(ev(amount=9, status="FAILED"))) == 1
    os.unlink(fh.name)
