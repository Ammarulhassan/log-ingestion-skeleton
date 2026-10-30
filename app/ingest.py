"""Task 1 ingestion script: tails a log file and prints parsed lines as JSON.

    python -m app.ingest logs/sample.log                  # read once
    python -m app.ingest logs/sample.log --follow         # keep tailing (like tail -f)
    python -m app.ingest logs/sample.log --rules rules/rules.json   # also print alerts
"""
import argparse
import json
import sys
import time

from .alerts import notify
from .parser import parse_line
from .rules import RuleEngine


def follow(path, delay=0.5, from_start=True, stop=lambda: False):
    with open(path, encoding="utf-8") as fh:
        if not from_start:
            fh.seek(0, 2)
        while not stop():
            line = fh.readline()
            if line:
                yield line
            else:
                time.sleep(delay)


def read_once(path):
    with open(path, encoding="utf-8") as fh:
        yield from fh


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("logfile")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--rules", help="rules JSON; if given, alerts are evaluated and sent")
    args = ap.parse_args(argv)
    engine = RuleEngine.from_file(args.rules) if args.rules else None
    source = follow(args.logfile, args.delay) if args.follow else read_once(args.logfile)
    for line in source:
        event = parse_line(line)
        if event is None:
            continue
        print(json.dumps(event), flush=True)
        if engine:
            for alert in engine.evaluate(event):
                print(json.dumps({"ALERT": alert}), flush=True)
                notify(alert)
    return 0


if __name__ == "__main__":
    sys.exit(main())
