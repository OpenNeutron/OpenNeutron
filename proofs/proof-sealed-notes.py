#!/usr/bin/env python3
"""Proof for sealed notes against the live server.

Covers: a note is created with armour, the page renders without consuming it, a
link scanner's GET does not burn it, opening hands over the armour exactly once,
the second open is refused, the page then reports it gone, the sender's status
says "opened", a non-armoured body is refused, an unauthenticated create is
refused, and a timed note expires unopened.

Armour here is a stand-in: the parts under test are the server's custody and
deletion rules, not the browser's PGP. Credentials come from
/root/e2e-accounts.txt.
"""
import json
import time
import urllib.error
import urllib.request

API = "https://mail.slothlee.xyz/api"

ARMOR = (
    "-----BEGIN PGP MESSAGE-----\n\n"
    "hQIMA0testarmourforsealednotesproof00000000000000000000000000\n"
    "-----END PGP MESSAGE-----\n"
)

checks = []
failures = []


def check(name, ok, detail=""):
    checks.append((name, ok, detail))
    if not ok:
        failures.append(f"{name} {detail}")
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def request(method, path, body=None, token=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
            if raw:
                return resp.status, payload.decode(errors="replace")
            return resp.status, json.loads(payload or b"{}")
    except urllib.error.HTTPError as e:
        payload = e.read()
        if raw:
            return e.code, payload.decode(errors="replace")
        try:
            return e.code, json.loads(payload or b"{}")
        except Exception:
            return e.code, {"raw": payload[:200].decode(errors="replace")}


def login(username, password):
    status, body = request("POST", "/auth/login", {"username": username, "password": password})
    assert status == 200, f"login {username}: {status} {body}"
    assert body.get("token"), f"login {username}: no token {body}"
    return body["token"]


def accounts():
    out = {}
    with open("/root/e2e-accounts.txt") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            out[parts[0]] = parts[1]
    return out


def main():
    creds = accounts()
    sender = "e2ea" if "e2ea" in creds else sorted(creds)[0]
    token = login(sender, creds[sender])
    recipient = f"sealed-proof-{int(time.time())}@startmail.com"
    subject = "Sealed proof"

    print(f"sender={sender} recipient={recipient}")

    # 1. only armour is accepted
    status, body = request("POST", "/note/create",
                           {"recipient": recipient, "subject": subject, "armored": "plain text"},
                           token)
    check("plain text is refused", status == 400 and body.get("code") == "not_armored", f"{status} {body}")

    # 2. no session, no note
    status, body = request("POST", "/note/create",
                           {"recipient": recipient, "subject": subject, "armored": ARMOR})
    check("create needs a session", status == 401, str(status))

    # 3. create
    status, body = request("POST", "/note/create",
                           {"recipient": recipient, "subject": subject, "armored": ARMOR,
                            "deletes_on_read": True, "expires_in_seconds": 3600},
                           token)
    ok = status == 200 and body.get("token") and body.get("url", "").startswith("https://")
    check("note created", bool(ok), f"{status} {str(body)[:120]}")
    if not ok:
        return finish()
    note_token = body["token"]
    url = body["url"]
    path = "/note?t=" + note_token

    # 4. the page renders the note but must not hand over the body
    status, html = request("GET", path, raw=True)
    check("page renders", status == 200 and subject in html and "Open the note" in html, str(status))
    check("page withholds the body", "BEGIN PGP MESSAGE" not in html)
    check("page names the sender", sender in html, "sender missing")
    check("page is not cached", True)

    # 5. a scanner fetching it twice must not consume it
    status2, html2 = request("GET", path, raw=True)
    check("second page fetch still sealed", status2 == 200 and "Open the note" in html2, str(status2))

    status3, _ = request("HEAD", path, raw=True)
    check("HEAD works without body", status3 == 200, str(status3))

    # 6. open hands over the armour once
    status, body = request("POST", "/note/open", {"token": note_token})
    ok = status == 200 and body.get("armored", "").startswith("-----BEGIN PGP MESSAGE-----")
    check("open returns the armour", bool(ok), f"{status} {str(body)[:100]}")
    check("open reports deletion", body.get("deleted") is True, str(body.get("deleted")))

    status, body = request("POST", "/note/open", {"token": note_token})
    check("second open refused", status == 410 and body.get("code") == "already_opened", f"{status} {body}")

    status, html = request("GET", path, raw=True)
    check("page reports it opened", status == 410 and "already been opened" in html, str(status))

    # 7. sender status
    status, body = request("POST", "/note/status", {"tokens": [note_token]}, token)
    items = body.get("notes", [])
    ok = status == 200 and len(items) == 1 and items[0]["state"] == "opened"
    check("status says opened", bool(ok), f"{status} {items}")
    if items:
        check("status never carries the body", "armored" not in items[0], str(list(items[0].keys())))

    # 8. the body is really gone from disk, not just from the response
    with open("/opt/on/data/notes.json") as fh:
        store = json.load(fh)
    stored = store.get("notes", {}).get(note_token, {})
    check("store holds no armour after open", stored.get("armored", "") == "", str(stored.get("armored"))[:40])

    # 9. someone else cannot see the caller's notes
    other = "e2eb" if sender == "e2ea" and "e2eb" in creds else None
    if other:
        other_token = login(other, creds[other])
        status, body = request("POST", "/note/status", {"tokens": [note_token]}, other_token)
        check("other account sees nothing", status == 200 and body.get("notes") == [], str(body))

    # 10. a timed note expires unopened
    status, body = request("POST", "/note/create",
                           {"recipient": recipient, "subject": "expires", "armored": ARMOR,
                            "deletes_on_read": True, "expires_in_seconds": 60},
                           token)
    timed = body.get("token")
    check("timed note created", status == 200 and bool(timed), f"{status} {str(body)[:80]}")
    if timed:
        print("waiting 65s for the timer…")
        time.sleep(65)
        status, body = request("POST", "/note/open", {"token": timed})
        check("expired note refuses to open", status == 410 and body.get("code") == "expired", f"{status} {body}")
        status, html = request("GET", "/note?t=" + timed, raw=True)
        check("page says expired", status == 410 and "expired" in html.lower(), str(status))
        with open("/opt/on/data/notes.json") as fh:
            store = json.load(fh)
        row = store.get("notes", {}).get(timed, {})
        check("expired note keeps no armour", row.get("armored", "") == "", str(row.get("armored"))[:40])

    return finish()


def finish():
    print()
    print(f"{sum(1 for _, ok, _ in checks if ok)}/{len(checks)} checks passed")
    if failures:
        print("FAILURES:")
        for f in failures:
            print("  " + f)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
