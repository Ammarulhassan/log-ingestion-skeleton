# Roshan Microfinance - Log Monitoring & Incident Detection

Lightweight, automated system that reads transaction logs, applies JSON detection rules, raises alerts
(dashboard + email/webhook) and ships with an incident runbook.

- **Live demo:** `https://<your-service>.onrender.com`  (fill in after deploy)
- **Runbook (PDF):** [docs/runbook.pdf](docs/runbook.pdf) - also served at `/runbook` on the live site
- **Demo video:** `<YouTube link>`

## Quick start

```bash
pip install -r requirements.txt -r requirements-dev.txt
python scripts/gen_logs.py                         # regenerate sample + attack logs (optional)
python -m app.ingest logs/sample.log               # prints parsed lines as JSON
python -m app.ingest logs/attack.log --rules rules/rules.json   # JSON lines + ALERT lines
pytest --cov=app                                   # tests + coverage
python scripts/tune.py                             # baseline vs tuned false positives
flask --app app.dashboard run                      # dashboard at http://127.0.0.1:5000
```

Docker:

```bash
docker build -t roshan-log-monitor .
docker run --rm roshan-log-monitor                         # tails logs/sample.log, prints JSON (Task 1)
docker run --rm -e MODE=web -p 8000:8000 roshan-log-monitor   # dashboard on :8000
```

## Log format

```
2026-09-23T10:15:02Z event_id=E0001 user_id=U1001 action=repay amount=250.00 status=SUCCESS ip=10.0.0.5
2026-09-23T14:05:00Z event_id=A0009 user_id=attacker action=login status=FAILED ip=203.0.113.66 payload="' OR '1'='1' --"
```

The parser extracts `timestamp`, `user_id`, `amount`, `status` (required: timestamp, user_id, status) plus any other `key=value` pairs.
Malformed lines are skipped.

## Rule format (`rules/rules.json`)

A JSON list of rules. Common keys: `id`, `name`, `severity` (`low|medium|high|critical`), `type`, optional `where`
(equality pre-filter, e.g. `{"status": "FAILED"}`).

**`threshold`** - one event matches a condition: `field`, `op`, `value`.
`op` is one of `gt, gte, lt, eq, ne, contains, regex`.

```json
{"id": "R001", "name": "High-value transaction", "severity": "high",
 "type": "threshold", "field": "amount", "op": "gt", "value": 10000}
```

**`rate`** - N matching events from the same group within a time window: `group_by`, `count`, `window_seconds`.

```json
{"id": "R003", "name": "Failed-login burst from one IP", "severity": "high", "type": "rate",
 "where": {"action": "login", "status": "FAILED"}, "group_by": "ip", "count": 5, "window_seconds": 60}
```

| Rule | What it catches |
|------|-----------------|
| R001 | Transaction amount > 10,000 |
| R002 | SQL-injection syntax in `payload` |
| R003 | 5+ failed logins from one IP in 60 s |

## Attack lab (local only)

`docker compose up --build` starts an **intentionally vulnerable** Flask app (`/login` builds raw SQL), an attacker
container (brute-force burst + SQLi payloads) and the ingestion service, which prints alerts live.
The vulnerable app writes `logs/lab/app.log` in the same log format. **Never deploy `lab/` to a public host**; the
attacker script refuses any target except the lab app, and the app port is bound to 127.0.0.1.

## Alert tuning (Task 4)

`python scripts/tune.py` compares `rules/rules_baseline.json` (amount > 2,000, 2 failed logins / 5 min) with
`rules/rules.json` (amount > 10,000, 5 failed logins / 60 s) against ground truth in `logs/truth.json`:

```
baseline: 31 alerts, 17 false positives
tuned   :  9 alerts,  0 false positives     (false-positive reduction: 100%)
```

Legitimate loan disbursements (2,500-9,000) and "forgot password" retries caused the false positives; all real attack and
fraud incidents are still detected. The logs are synthetic, so results on real data will differ - re-run the script
after every rule change.

## Alert delivery

Every alert is appended to `data/alerts.jsonl`. Set environment variables to also send them:

| Variable | Purpose |
|----------|---------|
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` | email (e.g. Mailtrap sandbox: `sandbox.smtp.mailtrap.io`, port 2525) |
| `ALERT_TO`, `ALERT_FROM` | recipient / sender |
| `WEBHOOK_URL` | JSON POST (Slack/Discord/webhook.site) |

Test: set the variables, run `python -m app.ingest logs/attack.log --rules rules/rules.json`, check the inbox.

## Deploy on Render (free tier)

1. Push this repo to GitHub.
2. Render dashboard -> **New** -> **Blueprint** -> select the repo (uses `render.yaml`), or **New Web Service** -> Docker, plan *Free*, env `MODE=web`.
3. Add secrets (`SMTP_USER`, `SMTP_PASS`, `SMTP_HOST`) under *Environment*.
4. Open `https://<service>.onrender.com` - you should see alerts, the log viewer and the runbook link. `/healthz` returns `{"status":"ok"}`.
5. CI/CD: Render auto-deploys on every push to `main`. Optionally add the service's *Deploy Hook* URL as GitHub secret
   `RENDER_DEPLOY_HOOK` so the workflow triggers the deploy only after tests pass.

Free instances sleep after inactivity; the first request may take ~30-60 s.

## Project layout

```
app/        parser, rule engine, pipeline, ingest CLI, alerts, dashboard
rules/      rules.json (tuned), rules_baseline.json
logs/       sample.log, attack.log, truth.json
lab/        vulnerable app + attacker (local only)
docs/       runbook.pdf (+ build_runbook.py)
tests/      pytest suite
```
