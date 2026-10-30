import importlib.util
import os
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGFILE = os.path.join(tempfile.mkdtemp(), "lab.log")
os.environ["LOG_FILE"] = LOGFILE


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vuln = _load("vuln", "lab/vuln_app/app.py")
attacker = _load("attacker", "lab/attacker/attacker.py")


def test_home_returns_200_and_normal_login_works():
    c = vuln.app.test_client()
    assert c.get("/").status_code == 200
    assert c.post("/login", json={"username": "admin", "password": "wrong"}).get_json()["ok"] is False
    assert c.post("/login", json={"username": "officer1", "password": "loanpass"}).get_json()["ok"] is True


def test_sql_injection_bypasses_login_and_is_logged():
    c = vuln.app.test_client()
    r = c.post("/login", json={"username": "admin' --", "password": "anything"})
    assert r.status_code == 200 and r.get_json()["ok"] is True  # the vulnerability
    from app.pipeline import process_file
    events, alerts = process_file(LOGFILE, os.path.join(ROOT, "rules", "rules.json"))
    assert any("SELECT" not in e.get("payload", "") and "--" in e.get("payload", "") for e in events)
    assert any(a["rule_id"] == "R002" for a in alerts)


def test_attacker_refuses_non_lab_targets():
    try:
        attacker.run(target="http://example.com")
    except SystemExit as exc:
        assert "Refusing" in str(exc)
    else:
        raise AssertionError("attacker should refuse external targets")
