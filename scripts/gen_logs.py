"""Generate reproducible sample + simulated-attack logs and the ground-truth file.

    python scripts/gen_logs.py
Writes logs/sample.log, logs/attack.log, logs/truth.json
"""
import json
import os
import random
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.parser import format_line  # noqa: E402

random.seed(42)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START = datetime(2026, 9, 23, 8, 0, 0)


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    users = [f"U{1000 + i}" for i in range(1, 31)]
    ips = {u: f"10.0.{random.randint(1, 9)}.{random.randint(10, 250)}" for u in users}
    events, truth = [], []

    # Normal activity: repayments, small transfers, successful logins
    for i in range(240):
        u = random.choice(users)
        action = random.choice(["repay", "repay", "transfer", "login"])
        amount = 0 if action == "login" else round(random.uniform(50, 1500), 2)
        events.append(dict(timestamp=START + timedelta(seconds=i * 90 + random.randint(0, 40)), user_id=u,
                           action=action, amount=f"{amount:.2f}", status="SUCCESS", ip=ips[u]))
    # Legit loan disbursements (2,500-9,000): normal for a microfinance, noisy for a naive threshold
    for _ in range(12):
        u = random.choice(users)
        events.append(dict(timestamp=START + timedelta(seconds=random.randint(0, 21000)), user_id=u,
                           action="disburse", amount=f"{random.uniform(2500, 9000):.2f}", status="SUCCESS", ip=ips[u]))
    # Legit "forgot my password" - two failures then success
    for _ in range(5):
        u = random.choice(users)
        t = START + timedelta(seconds=random.randint(0, 21000))
        for k, st in enumerate(("FAILED", "FAILED", "SUCCESS")):
            events.append(dict(timestamp=t + timedelta(seconds=k * 20), user_id=u, action="login",
                               amount="0.00", status=st, ip=ips[u]))
    # Genuinely suspicious high-value transfers (ground truth = fraud)
    fraud = []
    for amt in (12500, 18200, 25000):
        u = random.choice(users)
        e = dict(timestamp=START + timedelta(seconds=random.randint(0, 21000)), user_id=u, action="transfer",
                 amount=f"{amt:.2f}", status="SUCCESS", ip=ips[u])
        events.append(e)
        fraud.append(e)

    events.sort(key=lambda e: e["timestamp"])
    lines = []
    for n, e in enumerate(events, 1):
        e = {"timestamp": ts(e["timestamp"]), "event_id": f"E{n:04d}", **{k: v for k, v in e.items() if k != "timestamp"}}
        lines.append(format_line(e))
        if float(e["amount"]) in (12500.0, 18200.0, 25000.0):
            truth.append(e["event_id"])
    with open(os.path.join(ROOT, "logs", "sample.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    # Simulated attacks (same shape the lab app produces)
    attack, base = [], datetime(2026, 9, 23, 14, 0, 0)
    n = 0
    for i in range(8):  # brute force: 8 bad passwords in ~16 seconds
        n += 1
        attack.append({"timestamp": ts(base + timedelta(seconds=i * 2)), "event_id": f"A{n:04d}", "user_id": "admin",
                       "action": "login", "amount": "0.00", "status": "FAILED", "ip": "203.0.113.50"})
    payloads = ["' OR '1'='1' --", "admin'--", "' UNION SELECT 1,2 --", "x'; DROP TABLE users; --", "' OR 1=1 --"]
    for i, p in enumerate(payloads):
        n += 1
        attack.append({"timestamp": ts(base + timedelta(minutes=5, seconds=i * 7)), "event_id": f"A{n:04d}",
                       "user_id": "attacker", "action": "login", "amount": "0.00",
                       "status": "SUCCESS" if i == 0 else "FAILED", "ip": "203.0.113.66", "payload": p})
    with open(os.path.join(ROOT, "logs", "attack.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(format_line(a) for a in attack) + "\n")
    truth.extend(a["event_id"] for a in attack)
    with open(os.path.join(ROOT, "logs", "truth.json"), "w", encoding="utf-8") as fh:
        json.dump({"malicious_event_ids": sorted(truth)}, fh, indent=2)
    print(f"sample.log: {len(lines)} lines | attack.log: {len(attack)} lines | truth: {len(truth)} malicious")


if __name__ == "__main__":
    main()
