#!/usr/bin/env python3
"""End-to-end proof for code-free signup with approval.

Runs against a throwaway instance; asserts the four-step bar:
signup without a code -> login refused as pending (not bad password) ->
approve -> login succeeds. Also proves deny, invite-code compatibility,
replay refusal and that a pending account is not locked out by retries.
"""

import hashlib
import json
import sys
import time
import urllib.error
import urllib.request

API = "http://127.0.0.1:8080"
ADMIN_SETUP_TOKEN = sys.argv[1] if len(sys.argv) > 1 else ""

EDGE = "https://mail.slothlee.xyz"

PW = "$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"

results = []


def call(method, path, body=None, token=None, expect=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, raw = resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode()
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        payload = {"_raw": raw[:200]}
    if expect is not None and status != expect:
        fail(f"{method} {path} expected {expect}, got {status}: {str(payload)[:300]}")
    return status, payload


def admin_usernames():
    status, body = call("GET", "/api/admin/users", None, admin_token)
    return [u.get("username", "") for u in body.get("users", [])] if status == 200 else []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    print(("PASS  " if condition else "FAIL  ") + name + (f"   [{detail}]" if detail else ""))


def fail(message):
    print("FAIL  " + message)
    sys.exit(1)


def solve(challenge, bits):
    nonce = 0
    while True:
        digest = hashlib.sha256((challenge + str(nonce)).encode()).digest()
        value = int.from_bytes(digest, "big")
        if value >> (256 - bits) == 0:
            return str(nonce)
        nonce += 1


def challenge():
    _, body = call("GET", "/api/signup/challenge", expect=200)
    return body["challenge"], body["difficulty"]


def register(username, invite=None):
    chal, diff = challenge()
    nonce = solve(chal, diff)
    body = {
        "username": username,
        "password": PW,
        "pow_challenge": chal,
        "pow_nonce": nonce,
    }
    if invite:
        body["invite_code"] = invite
    return call("POST", "/api/user/register", body)


def login(username, password=PW):
    return call("POST", "/api/auth/login", {"username": username, "password": password})


stamp = str(int(time.time()))[-6:]

# ── A. signup with no code is queued ───────────────────────────────────────
acct_a = f"phase1a{stamp}"
status, body = register(acct_a)
check("A1 signup without an invite code returns 202", status == 202, str(body))
check("A2 the 202 body says pending and carries no token",
      body.get("pending") is True and "token" not in body, str(body))

# ── B. login is refused as pending, not as a wrong password ────────────────
status, body = login(acct_a)
check("B1 pending login returns 403", status == 403, str(status))
check("B2 the code is account_pending, not invalid_credentials",
      body.get("code") == "account_pending", str(body.get("code")))
check("B3 no session token is issued", "token" not in body, str(list(body)))
check("B4 the message names approval, not a bad password",
      "approval" in (body.get("error") or "").lower(), str(body.get("error")))

# Retries must not lock the account out: the 403 is not a failed password.
# A handful of retries, spaced out. Blasting the endpoint would only trip the
# edge rate limit (10/min, burst 5) and prove nginx's limiter rather than this
# question, which is whether retries turn into a credential failure or a lock.
pairs = []
for _ in range(3):
    time.sleep(1.5)
    status, body = login(acct_a)
    pairs.append((status, body.get("code")))
check("B5 repeated attempts stay account_pending (no lockout, no bad password)",
      all(code == "account_pending" for status, code in pairs), str(pairs))

# ── C. operator session ────────────────────────────────────────────────────
# There is no seeded 'admin' password any more; an operator session is a JWT minted
# for an administrator, passed in as the first argument.
admin_token = ADMIN_SETUP_TOKEN or fail("pass an administrator JWT as the first argument")
status, body = call("GET", "/api/user/me", token=admin_token, expect=200)
check("C1 the operator session is an administrator", body.get("is_admin") is True, str(body.get("is_admin")))

# ── D. the queue is visible ────────────────────────────────────────────────
status, body = call("GET", "/api/admin/pending", token=admin_token, expect=200)
names = [e.get("username") for e in body.get("entries", [])]
check("D1 the pending account is listed", acct_a in names, str(names))
entry = next((e for e in body.get("entries", []) if e.get("username") == acct_a), {})
check("D2 the entry records when it was asked for", (entry.get("requested_at") or 0) > 0,
      str(entry.get("requested_at")))

# A non-admin must not see the queue.
status, _ = call("GET", "/api/admin/pending")
check("D3 the queue is closed without a session", status == 401, str(status))

# ── E. approve, then the account works ─────────────────────────────────────
status, body = call("POST", "/api/admin/pending/approve", {"username": acct_a}, token=admin_token, expect=200)
check("E1 approve returns approved=true", body.get("approved") is True, str(body))
status, body = login(acct_a)
check("E2 the approved account can sign in", status == 200, str(status))
check("E3 and gets a real session token", bool(body.get("token")), str(bool(body.get("token"))))
status, body = call("GET", "/api/admin/pending", token=admin_token, expect=200)
check("E4 the approved account has left the queue",
      acct_a not in [e.get("username") for e in body.get("entries", [])], str(body))
status, _ = call("POST", "/api/admin/pending/approve", {"username": acct_a}, token=admin_token)
check("E5 approving twice is refused with not_pending",
      status == 404, str(status))

# ── F. deny deletes the account and its request ────────────────────────────
acct_b = f"phase1b{stamp}"
status, _ = register(acct_b)
check("F1 a second signup is queued", status == 202, str(status))
status, _ = call("POST", "/api/admin/pending/deny", {"username": acct_b}, token=admin_token, expect=200)
check("F2 deny returns 200", status == 200)
status, body = login(acct_b)
check("F3 a denied account cannot sign in at all (401, not pending)",
      status == 401 and body.get("code") == "invalid_credentials", f"{status} {body.get('code')}")
status, body = call("GET", "/api/admin/users", token=admin_token, expect=200)
check("F4 the denied account is gone from the account store",
      acct_b not in [u.get("username") for u in body.get("users", [])], "")
status, body = call("GET", "/api/admin/pending", token=admin_token, expect=200)
check("F5 and gone from the queue",
      acct_b not in [e.get("username") for e in body.get("entries", [])], "")

# ── G. invite codes still admit immediately ────────────────────────────────
invite_email = f"invitee{stamp}@example.invalid"
call("POST", "/api/waitlist/request", {"email": invite_email, "note": "proof run"}, expect=200)
status, body = call("POST", "/api/admin/waitlist/approve", {"email": invite_email}, token=admin_token, expect=200)
code = body.get("code") or fail("no invite code minted")
acct_c = f"phase1c{stamp}"
status, body = register(acct_c, invite=code)
check("G1 a signup with an invite code is admitted at once (201)", status == 201, f"{status} {body}")
status, body = login(acct_c)
check("G2 and can sign in without approval", status == 200, str(status))

# ── H. a spent code is refused, not queued ────────────────────────────────
status, body = register(f"phase1e{stamp}", invite=code)
check("H1 reusing a spent invite code is refused with invite_required",
      status == 403 and body.get("code") == "invite_required", f"{status} {body.get('code')}")
status, body = call("GET", "/api/admin/pending", token=admin_token, expect=200)
check("H2 the refused signup did not create a queue entry",
      not any(e.get("username") == f"phase1e{stamp}" for e in body.get("entries", [])), "")

# ── I. duplicate names ────────────────────────────────────────────────────
status, body = register(acct_c)
check("I1 an approved name cannot be registered again", status == 409 and body.get("code") == "username_taken",
      f"{status} {body.get('code')}")

# ── J. replaying a solved challenge ───────────────────────────────────────
chal, diff = challenge()
nonce = solve(chal, diff)
first = call("POST", "/api/user/register", {"username": f"phase1f{stamp}", "password": PW,
                                            "pow_challenge": chal, "pow_nonce": nonce})
replay = call("POST", "/api/user/register", {"username": f"phase1g{stamp}", "password": PW,
                                             "pow_challenge": chal, "pow_nonce": nonce})
check("J1 a solved challenge is single-use", replay[0] == 400 and replay[1].get("code") == "pow_invalid",
      f"first={first[0]} replay={replay[0]} {replay[1].get('code')}")

# ── K. the edge throttles, and says so ─────────────────────────────────────
# Unauthenticated POSTs to the sign-in endpoint, straight at nginx. Somebody
# guessing passwords must be told to slow down (429), not told the server is broken.
codes = []
for _ in range(9):
    req = urllib.request.Request(EDGE + "/api/auth/login", data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            codes.append(resp.status)
    except urllib.error.HTTPError as exc:
        codes.append(exc.code)
check("K1 the sign-in endpoint throttles with 429, not 503",
      429 in codes and 503 not in codes, str(sorted(set(codes))))
check("K2 and refuses the extra attempts", codes.count(429) >= 1, str(codes))

# ── Cleanup ────────────────────────────────────────────────────────────────
# This proof registers accounts on purpose, so it has to remove them or every run
# leaves the admin list littered with phase1* names that look like a leak.
for suffix in ("a", "b", "c", "e", "f", "g"):
    name = f"phase1{suffix}{stamp}"
    try:
        # Requests that were never approved sit in the queue, not in the user table,
        # so deleting the account alone leaves the queue dirty for the next run.
        call("POST", "/api/admin/pending/deny", {"username": name}, token=admin_token)
    except Exception:
        pass
    try:
        call("DELETE", "/api/admin/users", {"username": name}, admin_token)
    except Exception:
        pass

# Anything a previous run left behind is not this run's failure to report, but it is
# litter: clear it so the queue describes the present, not the history of the suite.
_litter = {e.get("username", "") for e in call("GET", "/api/admin/pending", token=admin_token)[1].get("entries", [])}
_litter |= {u for u in admin_usernames() if u.startswith("phase1")}
for name in sorted(_litter):
    if name.startswith("phase1"):
        try:
            call("POST", "/api/admin/pending/deny", {"username": name}, token=admin_token)
        except Exception:
            pass
        try:
            call("DELETE", "/api/admin/users", {"username": name}, admin_token)
        except Exception:
            pass
left = [u for u in admin_usernames() if u.startswith("phase1")]
check("cleanup left no phase1 accounts behind", not left, str(left))

print()
passed = sum(1 for _, ok, _ in results if ok)
print(f"{passed}/{len(results)} checks passed")
sys.exit(0 if passed == len(results) else 1)
