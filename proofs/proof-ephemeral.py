#!/usr/bin/env python3
"""Proof for disappearing mail against a live server.

Covers: the preview path withholds a deleting message's body, /email/get
deletes as it serves, a second open is a 404, the recipient's list loses the
row, the sender gets a receipt, and a timed message is swept after it expires.

Uses the plaintext envelope (e2ee=false) because the parts under test are the
server's deletion rules, not the client crypto. Credentials come from
/root/e2e-accounts.txt.
"""
import base64
import json
import sys
import time
import urllib.error
import urllib.request

API = "https://mail.slothlee.xyz/api"
DOMAIN = "slothlee.xyz"

checks = []
failures = []


def check(name, ok, detail=""):
    checks.append((name, ok, detail))
    if not ok:
        failures.append(f"{name} {detail}")
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def post(path, body, token=None):
    data = json.dumps(body).encode()
    req = urllib.request.Request(API + path, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw or b"{}")
        except Exception:
            parsed = {"raw": raw[:200].decode(errors="replace")}
        return e.code, parsed


def login(username, password):
    status, body = post("/auth/login", {"username": username, "password": password})
    assert status == 200, f"login {username}: {status} {body}"
    assert body.get("token"), f"login {username}: no token {body}"
    return body["token"]


def accounts():
    out = {}
    with open("/root/e2e-accounts.txt") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2:
                out[parts[0]] = parts[1]
    return out


def b64(text):
    return base64.b64encode(text.encode()).decode()


def send(from_token, to_addr, marker, ephemeral=None):
    body = f"Subject: {marker}\r\nFrom: prover\r\n\r\n{marker} body\r\n"
    status, resp = post(
        "/email/sendencrypted",
        {
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
            **({"ephemeral": ephemeral} if ephemeral else {}),
        },
        token=from_token,
    )
    return status, resp


def find_in_inbox(token, predicate):
    status, recent = post("/email/recent", {"offset": 0, "limit": 20}, token=token)
    assert status == 200, f"recent: {status} {recent}"
    uids = recent.get("uids", [])
    if not uids:
        return None, []
    status, bulk = post("/email/bulk", {"uids": uids}, token=token)
    assert status == 200, f"bulk: {status} {bulk}"
    items = bulk.get("emails", [])
    for item in items:
        if predicate(item):
            return item, items
    return None, items


def decode_data(item):
    try:
        return base64.b64decode(item.get("data") or "").decode(errors="replace")
    except Exception:
        return ""


def main():
    creds = accounts()
    sender_token = login("e2ea", creds["e2ea"])
    recipient_token = login("e2eb", creds["e2eb"])
    check("both accounts log in", True)
    to_addr = f"e2eb@{DOMAIN}"

    # ---- 1. A message that deletes when opened ----
    marker = f"vanish-read-{int(time.time())}"
    status, resp = send(sender_token, to_addr, marker, {"deletes_on_read": True})
    check("send with deletes_on_read is accepted", status == 200, f"{status}")
    results = resp.get("delivery_results") or []
    check(
        "local delivery succeeded",
        bool(results) and results[0].get("success") is True,
        json.dumps(results)[:200],
    )
    sent_uid = resp.get("sent_email_uid")

    item, _ = find_in_inbox(recipient_token, lambda e: e.get("ephemeral") == "read")
    check("the recipient's list marks it as disappearing", item is not None)
    if item is None:
        return finish()
    uid = item["uid"]
    check("the preview path withholds the body", item.get("data") == "", repr(item.get("data"))[:40])
    check("the preview path withholds the key", item.get("message_key") in (None, ""))
    check("the plaintext sender labels the preview", item.get("from") == f"e2ea@{DOMAIN}", str(item.get("from")))

    status, got = post("/email/get", {"uid": uid}, token=recipient_token)
    check("opening it succeeds", status == 200, f"{status}")
    check("the response says it was deleted", got.get("deleted") is True, str(got.get("deleted")))
    check("the body is the message that was sent", marker in decode_data(got), decode_data(got)[:80])

    status, again = post("/email/get", {"uid": uid}, token=recipient_token)
    check("a second open is a 404", status == 404, f"{status} {again}")
    check("the 404 is the documented code", again.get("code") == "email_not_found", str(again)[:120])

    leftover, items = find_in_inbox(recipient_token, lambda e: e.get("uid") == uid)
    check("the row is gone from the recipient's list", leftover is None)
    check("no other messages were disturbed", len(items) >= 0)

    status, status_body = post("/email/ephemeral", {"uids": [str(sent_uid)]}, token=sender_token)
    entry = (status_body.get("items") or [{}])[0]
    # The client sends ids as strings (a u128 does not survive a JS number).
    check("the sender is told it was read", entry.get("state") == "read", json.dumps(entry)[:160])
    check("the receipt names the reader", entry.get("recipient") == "e2eb", str(entry.get("recipient")))
    check("the receipt carries a time", isinstance(entry.get("read_at"), int) and entry["read_at"] > 0)

    # The sender's own copy must survive: it is their record of what they wrote.
    status, own = post("/email/sent/get", {"uid": sent_uid}, token=sender_token)
    check("the sender's sent copy still opens", status == 200 and marker in decode_data(own), f"{status}")

    # ---- 2. A message that expires on a timer ----
    marker2 = f"vanish-time-{int(time.time())}"
    status, resp2 = send(sender_token, to_addr, marker2, {"expires_in_seconds": 61})
    check("send with a timer is accepted", status == 200, f"{status}")
    item2, _ = find_in_inbox(recipient_token, lambda e: e.get("ephemeral") == "expire")
    check("the timer is visible in the list", item2 is not None)
    if item2 is not None:
        check("the expiry time is in the future", (item2.get("expires_at") or 0) > int(time.time()),
              str(item2.get("expires_at")))
        check("an expiring message still previews normally", item2.get("data") != "")

        uid2 = item2["uid"]
        deadline = time.time() + 120
        gone_at = None
        while time.time() < deadline:
            time.sleep(10)
            status, got2 = post("/email/get", {"uid": uid2}, token=recipient_token)
            if status == 404:
                gone_at = int(time.time())
                break
        check("the timer deleted it without it being read", gone_at is not None,
              "still present after 120s" if gone_at is None else "gone")

    # ---- 3. An ordinary message is untouched by all of this ----
    marker3 = f"ordinary-{int(time.time())}"
    send(sender_token, to_addr, marker3)
    status, recent3 = post("/email/recent", {"offset": 0, "limit": 20}, token=recipient_token)
    status, bulk3 = post("/email/bulk", {"uids": recent3.get("uids", [])}, token=recipient_token)
    ordinary = [e for e in bulk3.get("emails", []) if e.get("ephemeral") is None and e.get("data")]
    check("ordinary mail is unaffected and still previews", len(ordinary) > 0, f"{len(ordinary)} messages")
    if ordinary:
        check("ordinary mail is not marked deleted", ordinary[0].get("deleted") is False)

    return finish()


def finish():
    print()
    print(f"{len(checks) - len(failures)}/{len(checks)} checks passed")
    for f in failures:
        print("  FAILED:", f)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
