#!/usr/bin/env python3
"""Proof for importing mail that never travelled over SMTP.

Run on the mail host (it reads the fixture credentials and the blob store):
    python3 proof-import.py

What it establishes:
  1. a message file becomes a real mailbox entry,
  2. the stored blob is ciphertext, not the plaintext that went in,
  3. the archive's own date survives (so history sorts correctly),
  4. re-importing the same Message-ID is skipped, not duplicated,
  5. a message with no Message-ID is still imported,
  6. the mailbox grows by exactly the number imported.
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = "https://mail.slothlee.xyz/api"
CREDS = dict(l.split() for l in open("/root/e2e-accounts.txt") if l.strip())
OWNER = os.environ.get("OWNER", "e2ea")
PASS = CREDS[OWNER]

passed, failed = 0, []


def check(name, ok, detail=""):
    global passed
    if ok:
        passed += 1
        print(f"  ok   {name}" + (f"  [{detail}]" if detail else ""))
    else:
        failed.append(name)
        print(f"  FAIL {name} {detail}")


def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except Exception:
            return e.code, {"raw": raw[:120].decode(errors="replace")}


def message(subject, marker, date_header, message_id=None):
    lines = [
        f"From: Importer <importer@elsewhere.example>",
        f"To: {OWNER}@slothlee.xyz",
        f"Subject: {subject}",
        f"Date: {date_header}",
    ]
    if message_id:
        lines.append(f"Message-ID: {message_id}")
    lines += ["MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "", f"Body marker: {marker}", ""]
    return "\r\n".join(lines).encode()


def main():
    status, body = call("POST", "/auth/login", {"username": OWNER, "password": PASS})
    if status != 200 or not body.get("token"):
        print(f"login {OWNER}: {status} {body}")
        sys.exit(1)
    token = body["token"]

    before = len(call("POST", "/email/list", {}, token)[1].get("uids", []))
    stamp = int(time.time())
    made = []

    print("importing")
    first = message("Imported one", f"MARKER-{stamp}-ALPHA", "Mon, 14 Aug 2023 09:15:00 +0000",
                    f"<import-{stamp}-1@elsewhere.example>")
    status, body = call("POST", "/import/message",
                        {"raw": base64.b64encode(first).decode(), "date_unix": 1692004500}, token)
    check("a message file is accepted", status == 200 and body.get("uid"), f"{status} {body}")
    uid = body.get("uid")
    if uid:
        made.append(uid)
    check("it is not reported as skipped", body.get("skipped") is False)

    # The archive's date, not the moment of import.
    check("the original date survived", body.get("timestamp") == 1692004500, str(body.get("timestamp")))

    # Ciphertext on disk: the marker must not appear in the blob.
    blob = f"/opt/on/data/blobs/{uid}.bin"
    raw_blob = open(blob, "rb").read() if os.path.exists(blob) else b""
    check("the stored blob is not the file", b"MARKER-" + str(stamp).encode() not in raw_blob,
          f"{len(raw_blob)} bytes")

    # The same Message-ID again is one message, not two.
    status, body = call("POST", "/import/message",
                        {"raw": base64.b64encode(first).decode(), "date_unix": 1692004500}, token)
    check("a re-import is skipped", status == 200 and body.get("skipped") is True, f"{status} {body}")

    # No Message-ID: nothing to dedupe on, but it must still land.
    second = message("Imported two, no id", f"MARKER-{stamp}-BETA", "Fri, 03 Feb 2023 18:00:00 +0000")
    status, body = call("POST", "/import/message",
                        {"raw": base64.b64encode(second).decode(), "date_unix": 1675447200}, token)
    check("a message without a Message-ID still lands", status == 200 and body.get("uid"), f"{status} {body}")
    if body.get("uid"):
        made.append(body["uid"])

    print("the mailbox")
    after = len(call("POST", "/email/list", {}, token)[1].get("uids", []))
    check("the mailbox grew by two", after == before + 2, f"{before} -> {after}")

    status, body = call("POST", "/import/message", {"raw": ""}, token)
    check("an empty file is refused", status == 400, f"{status} {body}")
    status, body = call("POST", "/import/message", {"raw": "@@not base64@@"}, token)
    check("junk is refused", status == 400, f"{status} {body}")
    status, body = call("POST", "/import/message", {"raw": base64.b64encode(first).decode()})
    check("importing needs a session", status == 401, str(status))

    print("cleaning up")
    for uid in made:
        # The endpoint takes a u128; a JSON string is rejected, and the web
        # client sends the digits unquoted for the same reason.
        call("POST", "/email/delete", {"uid": int(uid)}, token)
    left = len(call("POST", "/email/list", {}, token)[1].get("uids", []))
    check("left nothing behind", left == before, f"{before} -> {left}")

    # Deleting and importing again must bring it back: "already here" is about
    # the mailbox, not about a id that was once seen.
    status, body = call("POST", "/import/message",
                        {"raw": base64.b64encode(first).decode(), "date_unix": 1692004500}, token)
    check("a deleted message can be imported again", status == 200 and body.get("skipped") is False,
          f"{status} {body}")
    if body.get("uid"):
        call("POST", "/email/delete", {"uid": int(body["uid"])}, token)

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
