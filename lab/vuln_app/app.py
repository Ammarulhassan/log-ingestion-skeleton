"""INTENTIONALLY VULNERABLE demo app (SQL injection in /login).
For the local Docker Compose lab ONLY. Never deploy this to a public host.
"""
import os
import sqlite3
import sys
from datetime import datetime, timezone

from flask import Flask, jsonify, request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from app.parser import format_line  # noqa: E402  (shared log format)

app = Flask(__name__)
LOG_FILE = os.environ.get("LOG_FILE", "/logs/app.log")
_counter = {"n": 0}


def db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 's3cret-admin-pw'), ('officer1', 'loanpass')")
    return conn


CONN = db()


def log_event(user, status, payload):
    _counter["n"] += 1
    event = {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "event_id": f"L{_counter['n']:05d}", "user_id": user or "unknown", "action": "login",
             "amount": "0.00", "status": status, "ip": request.remote_addr or "0.0.0.0", "payload": payload}
    os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(format_line(event) + "\n")


@app.get("/")
def home():
    return "Roshan lab app (intentionally vulnerable) - OK", 200


@app.post("/login")
def login():
    data = request.get_json(silent=True) or request.form
    username, password = data.get("username", ""), data.get("password", "")
    # VULNERABLE ON PURPOSE: raw string concatenation instead of a parameterised query
    query = f"SELECT id FROM users WHERE username='{username}' AND password='{password}'"
    try:
        row = CONN.execute(query).fetchone()
    except sqlite3.Error:
        row = None
    ok = row is not None
    log_event(username, "SUCCESS" if ok else "FAILED", f"{username}|{password}" if (
        "'" in username + password or "--" in username + password) else "")
    return jsonify(ok=ok), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
