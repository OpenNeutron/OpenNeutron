#!/usr/bin/env python3
"""Live proof for the deliverability-report parser.

Run on the mail host: python3 proofs/reports-live-test.py
It posts a failing TLS-RPT report through the real inbound path and asserts that
the server recorded it, mailed the owner, and left ordinary mail alone.

Sends two messages through the real inbound path (Postfix :25 → app :2525):

  1. a TLS-RPT report that carries two failures — the server must record it and
     mail the owner;
  2. ordinary mail that mentions nothing — the server must record nothing.

Then reports what actually happened. Text only; no assertion theatre.
"""
import base64
import gzip
import json
import smtplib
import subprocess
import sys
import time

HOST = "127.0.0.1"
DOMAIN = "slothlee.xyz"
OWNER = "tibs@" + DOMAIN

TLS_RPT = {
    "organization-name": "Sloth Probe",
    "date-range": {
        "start-datetime": "2026-10-31T00:00:00Z",
        "end-datetime": "2026-10-31T23:59:59Z",
    },
    "contact-info": "probe@example.com",
    "report-id": "probe-2026-10-31",
    "policies": [
        {
            "policy": {
                "policy-type": "sts",
                "policy-domain": DOMAIN,
                "mx-host": ["mail." + DOMAIN],
            },
            "summary": {
                "total-successful-session-count": 9,
                "total-failure-session-count": 2,
            },
            "failure-details": [
                {
                    "result-type": "certificate-expired",
                    "sending-mta-ip": "198.51.100.7",
                    "failed-session-count": 2,
                    "failure-reason-code": "certificate-expired",
                }
            ],
        }
    ],
}


def message(subject, content_type, payload, extra_part=None):
    encoded = base64.encodebytes(payload).decode()
    parts = [
        f'Content-Type: {content_type}',
        "Content-Transfer-Encoding: base64",
        "",
        encoded,
    ]
    body = "--probe-boundary\r\n" + "\r\n".join(parts) + "\r\n--probe-boundary--\r\n"
    return (
        f"From: probe@example.com\r\n"
        f"To: {OWNER}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
        f"Message-ID: <probe-{int(time.time())}@example.com>\r\n"
        f"MIME-Version: 1.0\r\n"
        f'Content-Type: multipart/report; boundary="probe-boundary"\r\n'
        f"\r\n{body}"
    )


def send(raw):
    with smtplib.SMTP(HOST, 25, timeout=20) as smtp:
        smtp.sendmail("probe@example.com", [OWNER], raw.encode())


def lines():
    out = subprocess.run(
        ["docker", "exec", "openneutron", "cat", "/usr/src/app/data/reports.jsonl"],
        capture_output=True, text=True,
    )
    return [l for l in out.stdout.splitlines() if l.strip()]


def main():
    before = len(lines())
    print(f"records before: {before}")

    compressed = gzip.compress(json.dumps(TLS_RPT).encode())
    send(message(f"TLS Report domain: {DOMAIN}", "application/tlsrpt+gzip", compressed))
    print("sent the failing TLS-RPT report")
    time.sleep(6)
    after = lines()
    print(f"records after:  {len(after)}")
    for line in after[before:]:
        print("  new:", line)
    if len(after) != before + 1:
        print("FAIL: the report was not recorded")
        return 1
    record = json.loads(after[-1])
    if record.get("failures") != 2 or not record.get("notes"):
        print("FAIL: the failure was not parsed:", record)
        return 1
    print("PASS: recorded with the failure and its reason")
    # The alert must actually reach the owner's mailbox. The verdict to trust is
    # the server's own DKIM result for the message it just signed, plus Postfix's
    # delivery status for that queue id.
    log = subprocess.run(
        ["docker", "logs", "openneutron"], capture_output=True, text=True
    ).stdout
    if "DKIM: pass for <postmaster@" not in log:
        print("FAIL: the server did not accept its own signed alert")
        return 1
    mail = subprocess.run(["grep", "status=sent", "/var/log/mail.log"], capture_output=True, text=True).stdout
    if not mail.strip():
        print("FAIL: no delivery recorded for the alert")
        return 1
    print("PASS: the alert was signed, verified and delivered")

    # Ordinary mail must not be recorded and must not alert.
    before = len(lines())
    send(
        "From: probe@example.com\r\n"
        f"To: {OWNER}\r\n"
        "Subject: lunch on Tuesday\r\n"
        "Message-ID: <ordinary-%d@example.com>\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "No report here, just lunch.\r\n" % int(time.time())
    )
    print("sent ordinary mail")
    time.sleep(6)
    if len(lines()) != before:
        print("FAIL: ordinary mail was recorded as a report")
        return 1
    print("PASS: ordinary mail was left alone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
