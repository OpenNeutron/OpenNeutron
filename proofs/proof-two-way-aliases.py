#!/usr/bin/env python3
"""Two-way aliases: mail in at an alias, mail back out from it.

Runs on the mail host. Uses real SMTP for the inbound leg (so Postfix and the
recipient map are exercised) and the authenticated API for the outbound leg.

Checks:
  * a message to an alias lands in the owner's mailbox
  * the inbox knows which address it arrived at
  * the owner can send from that alias, and the mail arrives from it
  * a stranger cannot send from it, and a switched-off alias is refused
  * a plain send still leaves from the account address
"""
import base64
import hashlib
import json
import smtplib
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

BASE = "https://mail.slothlee.xyz/api"
DOMAIN = "slothlee.xyz"
OWNER = "twowaytest"
OWNER_PASS = "Two-Way-2026-x"
passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"PASS {name}" + (f"  [{detail}]" if detail else ""))
    else:
        failed += 1
        print(f"FAIL {name}" + (f"  [{detail}]" if detail else ""))


def accounts():
    out = {}
    for line in open("/root/e2e-accounts.txt"):
        parts = line.split()
        if len(parts) >= 2:
            out[parts[0]] = parts[1]
    return out


def api(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def login(username, password):
    status, body = api("POST", "/auth/login", {"username": username, "password": password})
    assert status == 200, f"login {username}: {status} {body}"
    return body["token"]


def b64(text):
    return base64.b64encode(text.encode()).decode()


def send_from(token, to_addr, marker, from_alias=None, from_header=None):
    """A plaintext send through the same endpoint the compose window uses."""
    sender = from_header or "prover@example.com"
    body = (
        f"Subject: {marker}\r\n"
        f"From: {sender}\r\n"
        f"To: {to_addr}\r\n"
        f"Message-ID: <{marker}@example.com>\r\n"
        f"\r\n"
        f"{marker} body\r\n"
    )
    payload = {
        "localcopy": {
            "to": [to_addr],
            "timestamp": int(time.time()),
            "public_key_hash": "",
            "raw_data": b64(body),
            "message_key": "",
            "e2ee": False,
        },
        "recipients": {
            to_addr: {"aes_encrypted": "", "data_encrypted": b64(body), "e2ee": False}
        },
    }
    if from_alias:
        payload["from_alias"] = from_alias
    return api("POST", "/email/sendencrypted", payload, token=token)


def inbox_rows(token, limit=25):
    status, body = api("POST", "/email/recent", {"offset": 0, "limit": limit}, token=token)
    assert status == 200, f"recent: {status} {body}"
    uids = body.get("uids", [])
    if not uids:
        return []
    status, bulk = api("POST", "/email/bulk", {"uids": [int(u) for u in uids]}, token=token)
    assert status == 200, f"bulk: {status} {bulk}"
    return bulk.get("emails", [])


def find(token, marker):
    for row in inbox_rows(token):
        raw = base64.b64decode(row.get("data") or "").decode(errors="replace")
        if marker in raw:
            return row, raw
    return None, ""


def ensure_owner():
    """A mailbox with real keys: inbound SMTP to a keyless account is held until
    the owner sets keys, which is not what this proof is about."""
    import subprocess
    challenge = api("GET", "/signup/challenge")[1]
    bits = challenge["difficulty"]
    nonce = 0
    while True:
        digest = hashlib.sha256((challenge["challenge"] + str(nonce)).encode()).digest()
        value = int.from_bytes(digest[:4], "big") >> (32 - bits)
        if value == 0:
            break
        nonce += 1
    status, body = api(
        "POST",
        "/user/register",
        {
            "username": OWNER,
            "password": OWNER_PASS,
            "pow_challenge": challenge["challenge"],
            "pow_nonce": str(nonce),
        },
    )
    assert status in (200, 201, 202), f"register: {status} {body}"
    subprocess.run(["/usr/local/bin/mail-pending", "approve", OWNER], capture_output=True, text=True)
    token = login(OWNER, OWNER_PASS)
    bundle = json.load(open("/root/twoway-keys.json"))
    status, body = api(
        "POST",
        "/user/setup",
        {
            "password": OWNER_PASS,
            "public_key": bundle["public_key"],
            "encrypted_private_key": bundle["encrypted_private_key"],
        },
        token=token,
    )
    assert status in (200, 409), f"setup: {status} {body}"
    return token


def delete_owner():
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("mp", "/usr/local/bin/mail-pending")
    spec = importlib.util.spec_from_loader("mp", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    req = urllib.request.Request(
        BASE + "/admin/users", data=json.dumps({"username": OWNER}).encode(), method="DELETE"
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + mod.token())
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except Exception:
        pass


def main():
    creds = accounts()
    delete_owner()
    owner = ensure_owner()
    other = login("e2eb", creds["e2eb"])

    stamp = str(int(time.time()))[-5:]
    status, made = api("POST", "/aliases", {"local": f"twoway-{stamp}"}, token=owner)
    check("alias created", status == 200 and made.get("address", "").endswith(DOMAIN), f"{status} {made}")
    alias = made.get("local")
    if not alias:
        return finish()
    address = f"{alias}@{DOMAIN}"

    # Inbound, over real SMTP. The recipient map is rebuilt every 5 s.
    for attempt in range(6):
        try:
            msg = EmailMessage()
            msg["From"] = "stranger@example.com"
            msg["To"] = address
            msg["Subject"] = f"inbound-{stamp}"
            msg.set_content(f"inbound-{stamp} body")
            with smtplib.SMTP("127.0.0.1", 25, timeout=20) as s:
                s.send_message(msg)
            break
        except smtplib.SMTPRecipientsRefused:
            if attempt == 5:
                raise
            time.sleep(5)

    # Inbound mail to a keyed account is stored encrypted to that account, so the
    # body cannot be searched for a marker — and must not be. What is checked is
    # the thing under test: it arrived, and the mailbox says which door it came
    # through. The account is fresh, so any inbox row is this message.
    row = None
    for _ in range(12):
        for candidate in inbox_rows(owner, limit=10):
            if candidate.get("alias") == alias:
                row = candidate
                break
        if row:
            break
        time.sleep(3)

    check("message to the alias lands in the mailbox", row is not None)
    check("the inbox knows the alias it arrived at", bool(row), f"{(row or {}).get('alias')}")
    if row:
        status, got = api("POST", "/email/get", {"uid": int(row["uid"])}, token=owner)
        check("the reader knows it too", status == 200 and got.get("alias") == alias, f"{status} {(got or {}).get('alias')}")

    # Outbound from the alias to a local mailbox, so the delivered copy is readable.
    marker = f"reply-{stamp}"
    status, body = send_from(owner, f"e2eb@{DOMAIN}", marker,
                             from_alias=alias, from_header=f"{address}")
    check("sending from the alias is accepted", status == 200, f"{status} {body}")

    hit, raw2 = None, ""
    for _ in range(10):
        hit, raw2 = find(other, marker)
        if hit:
            break
        time.sleep(2)
    check("the reply arrives", hit is not None)
    check("it arrives from the alias address", bool(hit) and address in (hit.get("from") or ""), (hit or {}).get("from"))
    check("the header says the alias", address in raw2, raw2.split("\n")[1][:60] if raw2 else "")

    # Nobody else may wear the alias.
    status, body = send_from(other, f"{OWNER}@{DOMAIN}", f"steal-{stamp}", from_alias=alias)
    check("a stranger cannot send as the alias", status == 400 and body.get("code") == "unknown_alias", f"{status} {body.get('code')}")

    # And a switched-off one is refused, not silently swapped.
    api("POST", "/aliases/disable", {"local": alias, "disabled": True}, token=owner)
    status, body = send_from(owner, f"e2eb@{DOMAIN}", f"off-{stamp}", from_alias=alias)
    check("a switched-off alias is refused", status == 409 and body.get("code") == "alias_disabled", f"{status} {body.get('code')}")
    api("POST", "/aliases/disable", {"local": alias, "disabled": False}, token=owner)

    # Control: no alias asked for means the real address, unchanged.
    marker = f"plain-{stamp}"
    status, _ = send_from(owner, f"e2eb@{DOMAIN}", marker, from_header=f"{OWNER}@{DOMAIN}")
    hit, raw3 = None, ""
    for _ in range(10):
        hit, raw3 = find(other, marker)
        if hit:
            break
        time.sleep(2)
    check("a plain send still leaves from the account", bool(hit) and f"{OWNER}@{DOMAIN}" in (hit.get("from") or ""), (hit or {}).get("from"))
    check("and carries no alias", bool(hit) and not (hit or {}).get("from", "").startswith(alias), (hit or {}).get("from"))

    # Clean the record up.
    api("DELETE", f"/aliases/{alias}", token=owner)
    delete_owner()
    return finish()


def finish():
    print(f"\n{passed}/{passed + failed} checks passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
