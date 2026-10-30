# Short notes to paste into the portal (edit in your own words - understand each one!)

## Task 1 - Repo and ingestion skeleton
Created the repo with README, MIT license, Dockerfile and `app/ingest.py`, which reads `logs/sample.log` (or tails it with
`--follow`) and prints each line as JSON. A GitHub Actions workflow builds the Docker image and smoke-tests the ingest command.
I used key=value logs so parsing stays simple and extensible.

## Task 2 - Parser and rule engine
`app/parser.py` extracts timestamp, user_id, amount, status (plus extra fields) with regex and skips malformed lines.
`app/rules.py` loads JSON rules; `threshold` rules (e.g. amount > 10000) and `rate` rules (N events per IP in a window).
Pytest covers parser, rules, ingestion, alerts and dashboard; CI fails if coverage is below 80%. Rule format is documented in the README.

## Task 3 - Vulnerable app and attack lab
`lab/vuln_app` is a Flask app whose `/login` concatenates user input into SQL (deliberately vulnerable). `lab/attacker` sends a
brute-force burst and SQLi payloads. Docker Compose runs the app, attacker and our ingestion service, which reads the app's log
and prints alerts. The lab is local-only: port bound to 127.0.0.1 and the attacker refuses non-lab targets.

## Task 4 - Tuning and runbook
`scripts/tune.py` scores rules against ground truth. Raising the amount threshold from 2,000 to 10,000 and the failed-login rule from
2 in 5 min to 5 in 60 s cut false positives from 17 to 0 (100%) while still catching all attacks and fraud. The runbook PDF has
triage steps, escalation matrix, evidence collection. Alerts go to a JSONL file, and to email/webhook (Mailtrap) when configured.

## Task 5 - Deployment
Dockerfile runs the dashboard with gunicorn when `MODE=web`. `render.yaml` defines the free Render service; the CI workflow
triggers a Render deploy hook after tests pass. README has step-by-step deployment instructions and the demo video link.
