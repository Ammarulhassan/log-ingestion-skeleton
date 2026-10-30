"""Builds docs/runbook.pdf  (python docs/build_runbook.py). Requires reportlab."""
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runbook.pdf")
ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=ss["Heading1"], textColor=colors.HexColor("#0d1320"))
H2 = ParagraphStyle("H2", parent=ss["Heading2"], textColor=colors.HexColor("#1a5fd0"))
B = ParagraphStyle("B", parent=ss["BodyText"], leading=14)
CELL = ParagraphStyle("C", parent=B, fontSize=9, leading=11)


def table(rows, widths):
    data = [[Paragraph(str(c), CELL) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1320")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    for i in range(len(data[0])):
        data[0][i] = Paragraph(f"<font color='white'><b>{rows[0][i]}</b></font>", CELL)
    return t


def bullets(items):
    return [Paragraph(f"{i}. {t}", B) for i, t in enumerate(items, 1)]


s = []
s += [Paragraph("Incident Runbook - Roshan Microfinance Log Monitoring", H1),
      Paragraph("Audience: Roshan security / operations staff. Version 1.0. Review every 6 months.", B), Spacer(1, 10),
      Paragraph("1. Purpose", H2),
      Paragraph("This runbook explains what to do when the log-monitoring system raises an alert. Every alert "
                "appears on the dashboard, is stored in the alert log and is sent by email/webhook. "
                "Work the alert in the order: <b>Triage, Contain, Collect evidence, Escalate, Recover, Review</b>.", B),
      Paragraph("2. Alert catalogue", H2),
      table([["Rule", "Meaning", "Severity", "First response time"],
             ["R001 High-value transaction", "Single transaction above 10,000", "High", "30 minutes"],
             ["R002 SQL injection pattern", "Request contains SQL injection syntax (OR 1=1, UNION SELECT, --, DROP)", "Critical", "15 minutes"],
             ["R003 Failed-login burst", "5 or more failed logins from one IP within 60 seconds", "High", "30 minutes"]],
            [4.3 * cm, 6.2 * cm, 2.2 * cm, 3.3 * cm]),
      Paragraph("3. Triage steps", H2)]
s += bullets([
    "Open the dashboard and find the alert; note rule ID, user, IP, time and the detail text.",
    "Search the log viewer for the same user_id and ip within +/- 30 minutes to see surrounding activity.",
    "R001: call the field officer / customer on a known phone number (not one given in the request) and confirm the transaction is genuine.",
    "R002: check whether the same IP has other requests; a SUCCESS status after an injection payload means possible unauthorised access - treat as confirmed incident.",
    "R003: check whether the targeted account later logged in successfully from that IP. If yes, treat as account takeover.",
    "Classify: <b>False positive</b> (note reason, close), <b>Suspected</b> (continue below) or <b>Confirmed</b> (escalate immediately).",
])
s += [Paragraph("4. Containment actions", H2)]
s += bullets([
    "Block the source IP at the firewall / hosting provider.",
    "Lock or force a password reset on the affected user account(s).",
    "R001 confirmed fraud: hold or reverse the transaction through the finance team before settlement.",
    "R002 confirmed: take the affected application offline or put it in maintenance mode, and rotate database credentials.",
])
s += [PageBreak(), Paragraph("5. Escalation matrix", H2),
      table([["Level", "Who (fill in names/phones)", "When", "Deadline"],
             ["L1", "Security analyst on duty", "Any alert", "Start triage within the response time above"],
             ["L2", "IT / Security Lead", "Suspected incident, or any Critical alert", "Within 30 minutes of triage"],
             ["L3", "Operations Manager + Finance Head", "Confirmed fraud or data access", "Within 1 hour"],
             ["L4", "CEO + Legal / Regulator liaison", "Customer data exposed or financial loss confirmed", "Same business day"]],
            [1.5 * cm, 5.5 * cm, 5.5 * cm, 3.5 * cm]),
      Paragraph("6. Evidence collection", H2)]
s += bullets([
    "Do not delete or edit logs. Copy the original log files (logs/*.log) and the alert file (data/alerts.jsonl) to a read-only folder.",
    "Record SHA-256 hashes of the copied files (sha256sum) and the time/person who copied them.",
    "Save a screenshot of the dashboard alert and the surrounding log events.",
    "Note: who was contacted, what was confirmed, which actions were taken and when (incident timeline).",
    "Keep evidence for at least 12 months or as required by the regulator.",
])
s += [Paragraph("7. Recovery and review", H2)]
s += bullets([
    "Restore normal service only after the cause is understood and credentials are rotated.",
    "Within 5 working days hold a review: what happened, how it was detected, what to improve.",
    "If an alert was a false positive, record the pattern and propose a rule change (edit rules/rules.json, run python scripts/tune.py and the test-suite before deploying).",
])
s += [Paragraph("8. Alert delivery check", H2),
      Paragraph("Send a test alert monthly: run the lab or sample logs and confirm an email/webhook message arrives. "
                "If it does not, check SMTP_HOST / SMTP_USER / SMTP_PASS / WEBHOOK_URL environment settings on the host.", B)]

SimpleDocTemplate(OUT, pagesize=A4, title="Incident Runbook - Roshan Microfinance",
                  leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm).build(s)
print("wrote", OUT)
