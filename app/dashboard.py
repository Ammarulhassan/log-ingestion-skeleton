"""Web dashboard: log viewer + alert list + runbook link. Served by gunicorn on Render/Fly.io."""
import glob
import os
import threading

from jinja2 import Environment
from flask import Flask, jsonify, send_file, Response

from .alerts import notify
from .pipeline import process_file

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.environ.get("LOG_DIR", os.path.join(ROOT, "logs"))
RULES = os.environ.get("RULES_FILE", os.path.join(ROOT, "rules", "rules.json"))
RUNBOOK = os.path.join(ROOT, "docs", "runbook.pdf")

app = Flask(__name__)
_lock = threading.Lock()
_state = {"sig": None, "events": [], "alerts": []}
_sent = set()

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Roshan Log Monitor</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1f2b}h1{margin-bottom:0}
table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.85rem}th,td{border-bottom:1px solid #ddd;padding:.35rem .5rem;text-align:left}
th{background:#0d1320;color:#fff}.critical{color:#b00020;font-weight:700}.high{color:#c25100;font-weight:700}
.box{max-height:320px;overflow:auto;border:1px solid #ddd}a{color:#1a5fd0}</style></head><body>
<h1>Roshan Microfinance - Log Monitor</h1>
<p>{{ n_events }} events processed &middot; <b>{{ alerts|length }}</b> alerts &middot; <a href="/runbook">Incident runbook (PDF)</a> &middot; <a href="/api/alerts">alerts JSON</a></p>
<h2>Alerts</h2><div class="box"><table><tr><th>Time</th><th>Severity</th><th>Rule</th><th>User</th><th>IP</th><th>Detail</th></tr>
{% for a in alerts %}<tr><td>{{ a.timestamp }}</td><td class="{{ a.severity }}">{{ a.severity }}</td><td>{{ a.rule_id }} {{ a.rule_name }}</td><td>{{ a.user_id }}</td><td>{{ a.ip }}</td><td>{{ a.detail }}</td></tr>
{% else %}<tr><td colspan="6">No alerts.</td></tr>{% endfor %}</table></div>
<h2>Latest log events</h2><div class="box"><table><tr><th>Time</th><th>ID</th><th>User</th><th>Action</th><th>Amount</th><th>Status</th><th>IP</th></tr>
{% for e in events %}<tr><td>{{ e.timestamp }}</td><td>{{ e.event_id }}</td><td>{{ e.user_id }}</td><td>{{ e.action }}</td><td>{{ '%.2f'|format(e.amount) }}</td><td>{{ e.status }}</td><td>{{ e.ip }}</td></tr>{% endfor %}</table></div>
</body></html>"""


def _signature():
    return tuple((p, os.path.getmtime(p)) for p in sorted(glob.glob(os.path.join(LOG_DIR, "*.log"))))


def refresh():
    """Re-process log files only when they changed; send each new alert once."""
    with _lock:
        sig = _signature()
        if sig != _state["sig"]:
            events, alerts = [], []
            for path, _ in sig:
                ev, al = process_file(path, RULES)
                events += ev
                alerts += al
            alerts.sort(key=lambda a: a["timestamp"], reverse=True)
            for a in alerts:
                key = (a["rule_id"], a["event_id"], a["timestamp"])
                if key not in _sent:
                    _sent.add(key)
                    notify(a)
            _state.update(sig=sig, events=events, alerts=alerts)
        return _state


_jinja = Environment(autoescape=True)
_template = _jinja.from_string(PAGE)


@app.get("/")
def index():
    s = refresh()
    html = _template.render(alerts=s["alerts"], events=s["events"][-100:][::-1], n_events=len(s["events"]))
    return Response(html, mimetype="text/html")


@app.get("/api/alerts")
def api_alerts():
    return jsonify(refresh()["alerts"])


@app.get("/runbook")
def runbook():
    return send_file(RUNBOOK, mimetype="application/pdf")


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")
