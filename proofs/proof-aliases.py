#!/usr/bin/env python3
"""Prove aliases on the live service.

Checks the whole path, not just the endpoint: creating an address, that Postfix
accepts it because the server says it is valid, that mail delivered to it lands
in the owner's mailbox, that switching it off makes the sender bounce, and that
deleting it removes it from the recipient map.

Run on the mail host:  python3 proof-aliases.py
"""
import json
import os
import smtplib
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

BASE = "https://mail.slothlee.xyz/api"
MAP = "/etc/postfix/recipients"
CREDS = dict(l.split() for l in open("/root/e2e-accounts.txt") if l.strip())
# The mailbox that owns the aliases under test. It must have a public key, or
# mail is held rather than delivered and "landed in the mailbox" cannot pass.
OWNER = os.environ.get("OWNER", "e2ea")
OWNER_PASS = os.environ.get("OWNER_PASS") or CREDS[OWNER]
STRANGER = os.environ.get("STRANGER", "e2eb")

passed = 0
failed = []


def check(name, ok, detail=""):
    global passed
    if ok:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed.append(name)
        print(f"  FAIL {name} {detail}")


def call(method, path, body=None, tok=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def deliver(to, subject, body="Hello through the alias."):
    msg = EmailMessage()
    msg["From"] = "someone@example.com"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP("127.0.0.1", 25, timeout=30) as smtp:
        smtp.ehlo("example.com")
        smtp.send_message(msg)


def refused(to):
    try:
        deliver(to, "should bounce")
        return False
    except smtplib.SMTPRecipientsRefused:
        return True


def aliases(tok):
    return {a["local"]: a for a in call("GET", "/aliases", None, tok)[1]["aliases"]}


def in_map(local):
    try:
        with open(MAP) as handle:
            return any(line.split()[0].lower() == f"{local}@slothlee.xyz" for line in handle if line.strip())
    except FileNotFoundError:
        return False


def wait_for(predicate, seconds=20):
    for _ in range(seconds):
        if predicate():
            return True
        time.sleep(1)
    return False


def main():
    tok = call("POST", "/auth/login", {"username": OWNER, "password": OWNER_PASS})[1]["token"]
    other = call("POST", "/auth/login", {"username": STRANGER, "password": CREDS[STRANGER]})[1]["token"]
    uids_before = len(call("POST", "/email/list", {}, tok)[1]["uids"])

    print("create")
    name = f"proof-{int(time.time()) % 100000}"
    status, made = call("POST", "/aliases", {"local": name, "label": "proof"}, tok)
    check("created", status == 200 and made.get("address") == f"{name}@slothlee.xyz", str(made))
    address = made["address"]

    check("rejects a bad name", call("POST", "/aliases", {"local": "Bad Name!"}, tok)[0] == 400)
    check("refuses another account's name", call("POST", "/aliases", {"local": STRANGER}, tok)[0] == 409)
    check("shows in the owner's list", name in aliases(tok))
    check("not in a stranger's list", name not in aliases(other))

    print("delivery")
    check("postfix accepts it", wait_for(lambda: in_map(name)))
    deliver(address, f"alias proof {name}")
    check("counted", wait_for(lambda: aliases(tok)[name]["received"] == 1))
    uids_after = len(call("POST", "/email/list", {}, tok)[1]["uids"])
    check("landed in the mailbox", uids_after == uids_before + 1, f"{uids_before} -> {uids_after}")

    print("switch off")
    check("disabled", call("POST", "/aliases/disable", {"local": name, "disabled": True}, tok)[0] == 200)
    check("dropped from the map", wait_for(lambda: not in_map(name)))
    check("sender bounces", refused(address))
    check("count unchanged", aliases(tok)[name]["received"] == 1)
    check("stranger cannot switch it off",
          call("POST", "/aliases/disable", {"local": name, "disabled": False}, other)[0] == 404)

    print("switch back on")
    check("enabled", call("POST", "/aliases/disable", {"local": name, "disabled": False}, tok)[0] == 200)
    check("back in the map", wait_for(lambda: in_map(name)))
    deliver(address, f"alias proof again {name}")
    check("counted again", wait_for(lambda: aliases(tok)[name]["received"] == 2))

    print("delete")
    check("deleted", call("POST", "/aliases/delete", {"local": name}, tok)[0] == 200)
    check("gone from the list", name not in aliases(tok))
    check("gone from the map", wait_for(lambda: not in_map(name)))
    check("bounces after delete", refused(address))

    print("limits")
    # Fill up to the cap, then expect the next one to be refused, then let go of
    # every address this run made so the test leaves nothing behind.
    made_rows = []
    limit = call("GET", "/aliases", None, tok)[1]["limit"]
    start = len(aliases(tok))
    while len(aliases(tok)) < limit:
        stamp = int(time.time()) % 100000
        status, body = call("POST", "/aliases", {"local": f"limit-{stamp}-{len(made_rows)}"}, tok)
        if status != 200:
            break
        made_rows.append(body["local"])
    before = len(aliases(tok))
    status, _ = call("POST", "/aliases", {"local": f"over-{int(time.time()) % 100000}"}, tok)
    check(f"stops at {limit}", before == limit and status == 409, f"before={before} status={status}")
    for local in made_rows:
        call("POST", "/aliases/delete", {"local": local}, tok)
    check("left nothing behind", len(aliases(tok)) == start, f"{len(aliases(tok))} vs {start}")

    print(f"\n{passed} passed, {len(failed)} failed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
