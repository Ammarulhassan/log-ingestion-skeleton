import os
import tempfile

os.environ["ALERT_STORE"] = os.path.join(tempfile.mkdtemp(), "alerts.jsonl")
from app.dashboard import app  # noqa: E402


def test_dashboard_pages():
    c = app.test_client()
    page = c.get("/")
    assert page.status_code == 200 and b"Log Monitor" in page.data and b"High-value" in page.data
    assert c.get("/healthz").get_json() == {"status": "ok"}
    alerts = c.get("/api/alerts").get_json()
    assert len(alerts) == 9  # 3 fraud + 1 brute-force + 5 SQLi (tuned rules)
    rb = c.get("/runbook")
    assert rb.status_code == 200 and rb.data[:4] == b"%PDF"
