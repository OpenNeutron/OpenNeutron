#!/usr/bin/env python3
"""Ask the running server which of tibs' messages are not in the hybrid envelope.

Read-only: mints a short-lived token with the same secret the app uses, calls the
status endpoint, and for each unsealed uid prints the metadata the server holds
(received time and the length of the wrapped key). Message content is never touched —
the server cannot read it either.
"""
import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request

CONFIG = "/opt/on/config.yml"
BASE = "http://127.0.0.1:8080"


def jwt_secret():
    lines = open(CONFIG).read().splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == "jwt:")
    for line in lines[start + 1:]:
        s = line.strip()
        if s and not line.startswith((" ", "\t")):
            break
        if s.startswith("secret:"):
            return s.split(":", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("no jwt secret in config")


def token(user):
    raw = jwt_secret()
    # The server signs with the secret's literal bytes (jwt.rs: secret.as_bytes()),
    # not with a base64-decoded form. Getting this wrong yields a clean 401.
    key = raw.encode()
    enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
    header = enc(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    now = int(time.time())
    payload = enc(json.dumps(
        {"sub": user, "iat": now, "exp": now + 1800, "scope": None, "sid": None},
        separators=(",", ":")).encode())
    sig = enc(hmac.new(key, header + b"." + payload, hashlib.sha256).digest())
    return (header + b"." + payload + b"." + sig).decode()


def call(tok, path, body=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path,
        method=method or ("POST" if data else "GET"),
        data=data,
        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


user = "tibs"
tok = token(user)
status, body = call(tok, "/api/pq/migration")
print("pq/status", status, body[:300])
try:
    parsed = json.loads(body)
except Exception:
    raise SystemExit(0)

print(f"total={parsed.get('total')} sealed={parsed.get('sealed')} pending={parsed.get('pending')}")
for uid in parsed.get("uids", [])[:8]:
    st, raw = call(tok, "/api/email/get", {"uid": uid})
    if st != 200:
        print("uid", uid, "->", st, raw[:120])
        continue
    msg = json.loads(raw)
    key = msg.get("message_key") or ""
    print("uid", uid,
          "| received_at", msg.get("received_at"),
          "| key_len", len(key),
          "| key_prefix", key[:24])
