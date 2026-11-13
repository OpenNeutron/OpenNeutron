#!/usr/bin/env python3
"""Prove scheduled send on the live service.

The claim under test is narrow and checkable: a message queued for later does not
go out now, goes out by itself when its time comes, and can be taken back before
then. Both send paths are covered — the plain one and the encrypted one the app
actually uses.

Run on the mail host:  python3 proof-scheduled.py
"""
import base64
import json
import smtplib
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

BASE = "https://mail.slothlee.xyz/api"

# This proof used to borrow the shared e2e accounts, which carry a 200-a-day sending
# limit earned by every other proof on the box. Once spent, ten checks failed for a
# reason that had nothing to do with scheduled send. It now makes its own two
# accounts, with real 4096-bit keys, and deletes them afterwards.
PW = "$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
ADMIN_JWT = (
    sys.argv[1]
    if len(sys.argv) > 1
    else open("/root/.admin.jwt").read().strip()
)
OWNER = ""
OWNER_PASS = PW
STRANGER = ""

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
        with urllib.request.urlopen(req, timeout=40) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def raw_message(subject, to):
    msg = EmailMessage()
    msg["From"] = f"{OWNER}@slothlee.xyz"
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = "Wed, 28 Oct 2026 12:00:00 +0000"
    msg.set_content("This body was written at queue time.")
    return msg.as_bytes()


def mailbox_size(tok, folder="inbox"):
    key = "uids" if folder == "inbox" else "uids"
    path = "/email/list" if folder == "inbox" else "/email/list_sent"
    if folder != "inbox":
        return len(call("POST", path, {}, tok)[1].get(key, []))
    return len(call("POST", "/email/list", {}, tok)[1].get("uids", []))


def scheduled_rows(tok):
    return call("GET", "/scheduled", None, tok)[1].get("items", [])


def wait_until(fn, seconds):
    for _ in range(seconds):
        if fn():
            return True
        time.sleep(1)
    return False


def make_account(admin_jwt, label):
    """A throwaway account that can send: registered, approved, and keyed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    name = f"{label}{int(time.time()) % 1000000}"

    # Idempotent: a killed run can leave one behind, and a duplicate name would make
    # every later call fail for a reason that is not about scheduled send.
    call("DELETE", "/admin/users", {"username": name}, admin_jwt)
    status, body = call("POST", "/admin/users", {"username": name}, admin_jwt)
    if status not in (200, 201):
        raise SystemExit(f"create {name} -> {status} {body}")
    status, body = call(
        "POST", "/admin/users/credentials", {"username": name, "password": PW}, admin_jwt
    )
    if status != 200:
        raise SystemExit(f"credentials {name} -> {status} {body}")

    status, body = call("POST", "/auth/login", {"username": name, "password": PW})
    if status != 200:
        raise SystemExit(f"login {name} -> {status} {body}")
    token = body["token"]
    salt = body.get("salt") or body.get("server_salt") or ""

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    # The private half is never used by this proof (nothing here decrypts), so it is
    # stored as plain PKCS#8 rather than pretending to be a passphrase-wrapped blob.
    private_blob = base64.b64encode(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    ).decode()

    status, body = call("POST", "/user/setup", {
        "password": PW,
        "public_key": public_key,
        "encrypted_private_key": private_blob,
    }, token)
    if status != 200:
        raise SystemExit(f"setup {name} -> {status} {body}")
    return name, token


def main():
    global OWNER, STRANGER
    OWNER, tok = make_account(ADMIN_JWT, "scheda")
    STRANGER, other = make_account(ADMIN_JWT, "schedb")
    to = f"{OWNER}@slothlee.xyz"

    print("plain path")
    now = int(time.time())
    before = len(scheduled_rows(tok))
    body = {
        "to": [to],
        "data": __import__("base64").b64encode(raw_message(f"sched-plain-{now}", to)).decode(),
        "send_at": now + 75,
        "subject": f"sched-plain-{now}",
    }
    status, res = call("POST", "/email/send", body, tok)
    check("queued", status == 200 and res.get("scheduled") is True, str(res))
    item_id = res.get("id")
    check("listed as pending", any(r["id"] == item_id and r["status"] == "pending" for r in scheduled_rows(tok)))
    check("nothing sent yet", len(scheduled_rows(tok)) == before + 1)

    check("refuses a time in the past",
          call("POST", "/email/send", {**body, "send_at": now - 60}, tok)[0] == 400)
    check("refuses an absurd time",
          call("POST", "/email/send", {**body, "send_at": now + 400 * 24 * 3600}, tok)[0] == 400)

    print("take it back")
    check("stranger cannot cancel", call("POST", "/scheduled/cancel", {"id": item_id}, other)[0] == 409)
    check("owner can cancel", call("POST", "/scheduled/cancel", {"id": item_id}, tok)[0] == 200)
    check("cancelling twice is refused", call("POST", "/scheduled/cancel", {"id": item_id}, tok)[0] == 409)

    print("plain path releases by itself")
    raw_subject = f"sched-raw-{now}"
    status, res = call("POST", "/email/send", {
        "to": [to],
        "data": __import__("base64").b64encode(raw_message(raw_subject, to)).decode(),
        "send_at": now + 70,
        "subject": raw_subject,
    }, tok)
    raw_id = res.get("id")
    check("raw message held", status == 200 and res.get("scheduled") is True, str(res))

    print("editing a held message")
    edit_subject = f"sched-edit-{now}"
    def held_request(subject, at):
        return {
            "localcopy": {
                "to": [to],
                "timestamp": now,
                "public_key_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "raw_data": __import__("base64").b64encode(raw_message(subject, to)).decode(),
                "message_key": "",
                "e2ee": False,
            },
            "recipients": {
                to: {
                    "aes_encrypted": "",
                    "data_encrypted": __import__("base64").b64encode(raw_message(subject, to)).decode(),
                    "e2ee": False,
                }
            },
            "send_at": at,
            "subject": subject,
        }

    status, res = call("POST", "/email/sendencrypted", held_request(edit_subject, now + 90), tok)
    edit_id = res.get("id")
    check("edit target is held", status == 200 and res.get("scheduled") is True, str(res))

    new_subject = f"sched-edited-{now}"
    edited = held_request(new_subject, now + 100)
    edited["replace_id"] = edit_id
    rows_before = len([r for r in scheduled_rows(tok) if r["status"] == "pending"])
    status, res = call("POST", "/email/sendencrypted", edited, tok)
    check("edit accepted", status == 200 and res.get("replaced") is True, str(res))
    check("edit keeps the id", res.get("id") == edit_id, str(res))

    rows = {r["id"]: r for r in scheduled_rows(tok)}
    check("the subject changed", rows.get(edit_id, {}).get("subject") == new_subject, str(rows.get(edit_id)))
    check("the time changed", rows.get(edit_id, {}).get("send_at") == now + 100, str(rows.get(edit_id)))
    check("no second message was queued",
          len([r for r in scheduled_rows(tok) if r["status"] == "pending"]) == rows_before,
          f"{rows_before} before, {len([r for r in scheduled_rows(tok) if r['status'] == 'pending'])} after")

    # Someone else naming the id must not touch it.
    status, res = call("POST", "/email/sendencrypted", edited, other)
    check("a stranger cannot edit it",
          status == 409 and res.get("code") == "not_editable", f"{status} {res}")

    # The dangerous case: an edit with no time would fall through to the normal send
    # path and deliver a second copy while the first stayed queued.
    no_time = {k: v for k, v in edited.items() if k != "send_at"}
    status, res = call("POST", "/email/sendencrypted", no_time, tok)
    check("an edit without a time is refused",
          status == 400 and res.get("code") == "replace_needs_time", f"{status} {res}")
    check("and nothing extra was queued",
          len([r for r in scheduled_rows(tok) if r["status"] == "pending"]) == rows_before,
          "pending count moved")
    check("and the held message is untouched",
          {r["id"]: r for r in scheduled_rows(tok)}.get(edit_id, {}).get("subject") == new_subject)

    check("a time in the past is still refused when editing",
          call("POST", "/email/sendencrypted", {**held_request(new_subject, now - 60), "replace_id": edit_id}, tok)[0] == 400)

    check("the message is still there after the refusals",
          any(r["id"] == edit_id and r["status"] == "pending" for r in scheduled_rows(tok)))
    check("an edit can be cancelled", call("POST", "/scheduled/cancel", {"id": edit_id}, tok)[0] == 200)

    print("encrypted path (what the compose window uses)")
    inbox_before = mailbox_size(tok)
    subject = f"sched-enc-{now}"
    request = {
        "localcopy": {
            "to": [to],
            "timestamp": now,
            "public_key_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "raw_data": __import__("base64").b64encode(raw_message(subject, to)).decode(),
            "message_key": "",
            "e2ee": False,
        },
        "recipients": {
            to: {
                "aes_encrypted": "",
                "data_encrypted": __import__("base64").b64encode(raw_message(subject, to)).decode(),
                "e2ee": False,
            }
        },
        "send_at": now + 70,
        "subject": subject,
    }
    status, res = call("POST", "/email/sendencrypted", request, tok)
    check("encrypted message held", status == 200 and res.get("scheduled") is True, str(res))
    held_id = res.get("id")
    check("held message is not in the inbox yet", mailbox_size(tok) == inbox_before)

    print("release (waits for the sweeper)")
    released = wait_until(lambda: mailbox_size(tok) > inbox_before, 210)
    check("delivered by itself", released, f"inbox stayed at {inbox_before}")
    check("marked sent", wait_until(
        lambda: any(r["id"] == held_id and r["status"] == "sent" for r in scheduled_rows(tok)), 60))
    sent_copy = len(call("POST", "/email/sent/list", {}, tok)[1].get("uids", []))
    check("a sent copy exists now", sent_copy >= 1, str(sent_copy))
    check("raw message marked sent", wait_until(
        lambda: any(r["id"] == raw_id and r["status"] == "sent" for r in scheduled_rows(tok)), 60))
    status, res = call("POST", "/email/sendencrypted",
                       {**held_request(f"too-late-{now}", now + 120), "replace_id": held_id}, tok)
    check("a message that has gone cannot be edited",
          status == 409 and res.get("code") == "not_editable", f"{status} {res}")

    # Cleanup: the proof owns these accounts, so it removes them.
    for name in (OWNER, STRANGER):
        try:
            call("DELETE", "/admin/users", {"username": name}, ADMIN_JWT)
        except Exception:
            pass

    print(f"\n{passed} passed, {len(failed)} failed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
