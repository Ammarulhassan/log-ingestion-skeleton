"""Alert delivery: JSONL file always; email (SMTP, e.g. Mailtrap) and webhook if configured via env vars."""
import json
import os
import smtplib
import urllib.request
from email.message import EmailMessage


def _store(alert):
    path = os.environ.get("ALERT_STORE", "data/alerts.jsonl")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(alert) + "\n")


def _email(alert):
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    msg = EmailMessage()
    msg["Subject"] = f"[{alert['severity'].upper()}] {alert['rule_name']} - {alert['user_id']}"
    msg["From"] = os.environ.get("ALERT_FROM", "alerts@roshan-monitor.local")
    msg["To"] = os.environ.get("ALERT_TO", "security@roshan.example")
    msg.set_content(json.dumps(alert, indent=2))
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "2525"))) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        if os.environ.get("SMTP_USER"):
            smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
        smtp.send_message(msg)
    return True


def _webhook(alert):
    url = os.environ.get("WEBHOOK_URL")
    if not url:
        return False
    req = urllib.request.Request(url, data=json.dumps(alert).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5).close()
    return True


def notify(alert):
    """Deliver one alert. Channel failures are reported but never crash the pipeline."""
    result = {"stored": False, "email": False, "webhook": False}
    _store(alert)
    result["stored"] = True
    for name, fn in (("email", _email), ("webhook", _webhook)):
        try:
            result[name] = fn(alert)
        except Exception as exc:  # noqa: BLE001 - delivery must not break ingestion
            print(f"[alerts] {name} delivery failed: {exc}")
    return result
