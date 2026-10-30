import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

from app import alerts as alerts_mod
from app.ingest import main as ingest_main
from app.pipeline import process_file, process_lines
from app.rules import RuleEngine

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules", "rules.json")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import tune  # noqa: E402


def test_sample_log_has_only_true_fraud_flagged():
    events, alerts = process_file(os.path.join(ROOT, "logs", "sample.log"), RULES)
    assert len(events) > 200
    assert {a["rule_id"] for a in alerts} == {"R001"}
    assert len(alerts) == 3


def test_attack_log_triggers_sqli_and_bruteforce():
    _, alerts = process_file(os.path.join(ROOT, "logs", "attack.log"), RULES)
    ids = {a["rule_id"] for a in alerts}
    assert {"R002", "R003"} <= ids


def test_process_lines_skips_garbage():
    engine = RuleEngine.from_file(RULES)
    events, alerts = process_lines(["junk", "", "2026-09-23T10:00:00Z user_id=a status=OK amount=99999"], engine)
    assert len(events) == 1 and len(alerts) == 1


def test_tuning_reduces_false_positives_by_at_least_30_percent():
    base, _ = tune.evaluate(os.path.join(ROOT, "rules", "rules_baseline.json"))
    tuned, _ = tune.evaluate(RULES)
    assert base["false_positives"] > 0
    reduction = 100 * (base["false_positives"] - tuned["false_positives"]) / base["false_positives"]
    assert reduction >= 30
    assert tuned["true_positives"] >= 9  # still catches every attack/fraud *incident*
    assert tune.main() >= 30


def test_ingest_prints_json_lines_and_alerts():
    out = io.StringIO()
    with redirect_stdout(out):
        code = ingest_main([os.path.join(ROOT, "logs", "attack.log"), "--rules", RULES])
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert code == 0
    assert any("ALERT" in x for x in lines) and any("user_id" in x for x in lines)


def test_notify_stores_alert_and_survives_bad_webhook():
    path = os.path.join(tempfile.mkdtemp(), "alerts.jsonl")
    os.environ["ALERT_STORE"] = path
    os.environ["WEBHOOK_URL"] = "http://127.0.0.1:1/unreachable"
    try:
        res = alerts_mod.notify({"severity": "high", "rule_name": "x", "user_id": "u"})
    finally:
        del os.environ["WEBHOOK_URL"]
    assert res["stored"] is True and res["webhook"] is False and res["email"] is False
    assert json.loads(open(path).read())["user_id"] == "u"


def test_email_sent_via_smtp_when_configured():
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port): sent["host"] = host
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): sent["tls"] = True
        def ehlo(self): pass
        def login(self, u, p): sent["login"] = u
        def send_message(self, m): sent["subject"] = m["Subject"]

    real = alerts_mod.smtplib.SMTP
    alerts_mod.smtplib.SMTP = FakeSMTP
    os.environ.update(SMTP_HOST="smtp.test", SMTP_USER="u", SMTP_PASS="p",
                      ALERT_STORE=os.path.join(tempfile.mkdtemp(), "a.jsonl"))
    try:
        res = alerts_mod.notify({"severity": "critical", "rule_name": "SQLi", "user_id": "bob"})
    finally:
        alerts_mod.smtplib.SMTP = real
        for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS"):
            del os.environ[k]
    assert res["email"] is True and sent["tls"] and "CRITICAL" in sent["subject"]


def test_follow_yields_existing_lines_then_stops():
    from app.ingest import follow
    path = os.path.join(ROOT, "logs", "attack.log")
    seen = []
    gen = follow(path, delay=0.01, stop=lambda: len(seen) >= 3)
    for line in gen:
        seen.append(line)
    assert len(seen) == 3 and "A0001" in seen[0]
    # from_start=False skips existing content and waits; stop immediately
    assert list(follow(path, delay=0.01, from_start=False, stop=lambda: True)) == []
