import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("ALERT_STORE", os.path.join(tempfile.gettempdir(), "roshan_test_alerts.jsonl"))
