"""Measure alert quality of baseline vs tuned rules against ground truth.

    python scripts/tune.py
An alert is a FALSE POSITIVE if its event_id is not listed in logs/truth.json.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from app.pipeline import process_file  # noqa: E402


def evaluate(rules_path, log_dir=None):
    log_dir = log_dir or os.path.join(ROOT, "logs")
    with open(os.path.join(log_dir, "truth.json"), encoding="utf-8") as fh:
        truth = set(json.load(fh)["malicious_event_ids"])
    alerts = []
    for name in ("sample.log", "attack.log"):
        alerts += process_file(os.path.join(log_dir, name), rules_path)[1]
    fp = [a for a in alerts if a["event_id"] not in truth]
    tp = [a for a in alerts if a["event_id"] in truth]
    return {"alerts": len(alerts), "true_positives": len(tp), "false_positives": len(fp),
            "caught_event_ids": sorted({a["event_id"] for a in tp})}, truth


def main():
    base, truth = evaluate(os.path.join(ROOT, "rules", "rules_baseline.json"))
    tuned, _ = evaluate(os.path.join(ROOT, "rules", "rules.json"))
    reduction = 100 * (base["false_positives"] - tuned["false_positives"]) / max(base["false_positives"], 1)
    print(f"baseline: {base['alerts']} alerts, {base['false_positives']} false positives")
    print(f"tuned   : {tuned['alerts']} alerts, {tuned['false_positives']} false positives")
    print(f"false-positive reduction: {reduction:.1f}%")
    print(f"real incidents detected: baseline {base['true_positives']} | tuned {tuned['true_positives']}")
    return reduction


if __name__ == "__main__":
    main()
