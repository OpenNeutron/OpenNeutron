"""Prove the WKD publish endpoint accepts what the fixed client now sends.

Old payload: hash=".well-known" (index 3 of the advanced WKD URL) -> 400 bad_hash.
New payload: hash=zbase32(sha1(local part)) -> 200.
"""
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request

CONFIG = "/opt/on/config.yml"
API = "http://127.0.0.1:8080/api"
USER = "tibs"
ADDRESS = "tibs@slothlee.xyz"
HASH = "7w37z6jcfzygr7pb1hwsy9g5np711afe"


def jwt_secret():
    lines = open(CONFIG).read().splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == "jwt:")
    for line in lines[start + 1:]:
        if line.strip() and not line.startswith((" ", "\t")):
            break
        if line.strip().startswith("#"):
            continue
        if "secret" in line:
            return line.split(":", 1)[1].strip().strip("\"'")
    raise SystemExit("no jwt secret in config")


def enc(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def mint(user):
    key = jwt_secret().encode()
    now = int(time.time())
    header = enc(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = enc(json.dumps(
        {"sub": user, "iat": now, "exp": now + 900, "scope": None, "sid": None},
        separators=(",", ":")).encode())
    sig = enc(hmac.new(key, header + b"." + payload, hashlib.sha256).digest())
    return (header + b"." + payload + b"." + sig).decode()


def post(body):
    req = urllib.request.Request(
        API + "/pgp/wkd/publish",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + mint(USER)},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()[:160]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:160]


key_b64 = base64.b64encode(open(f"/opt/on/data/wkd/{HASH}.pub", "rb").read()).decode()

old = {"hash": ".well-known", "key_b64": key_b64, "email": ADDRESS,
       "fingerprint": "603470B1BAFACC5C"}
new = {"hash": HASH, "key_b64": key_b64, "email": ADDRESS,
       "fingerprint": "603470B1BAFACC5C"}

for label, body in (("old payload (before the fix)", old), ("new payload (after the fix)", new)):
    status, text = post(body)
    print(f"{label}: {status} {text}")
