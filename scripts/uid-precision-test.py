"""Does a u128 uid survive the trip through JavaScript?

Fetches the mailbox list as a real account, compares the uid JavaScript would
hold (a double) against the exact integer in the raw body, then asks for the
message twice: once with the double, once with the exact digits.
"""
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.request

CONFIG = "/opt/on/config.yml"
API = "http://127.0.0.1:8080/api"
USER = "e2ea"


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
    raise SystemExit("no jwt secret")


def enc(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def token():
    key = jwt_secret().encode()
    now = int(time.time())
    header = enc(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = enc(json.dumps({"sub": USER, "iat": now, "exp": now + 900,
                             "scope": None, "sid": None}, separators=(",", ":")).encode())
    sig = enc(hmac.new(key, header + b"." + payload, hashlib.sha256).digest())
    return (header + b"." + payload + b"." + sig).decode()


def call(path, body=None):
    if body is None:
        body = {}
    data = json.dumps(body).encode()
    req = urllib.request.Request(API + path, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + token()})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


status, raw = call("/email/recent", {"offset": 0, "limit": 5})
print("recent:", status, "bytes", len(raw))
exact = re.findall(r'(\d{20,})', raw)
if not exact:
    print("no uids in body:", raw[:200])
    raise SystemExit(1)

uid_text = exact[0]
# JavaScript runs every JSON number through a 64-bit float. Python's json keeps
# arbitrary precision, so model the browser with float() instead of json.loads.
as_double = float(uid_text)
print("exact uid      :", uid_text)
print("what JS keeps  :", repr(as_double))
print("survives       :", int(as_double) == int(uid_text),
      "(off by %d)" % (int(as_double) - int(uid_text)))

s1, b1 = call("/email/get", {"uid": int(as_double)})
print("get with rounded uid :", s1, b1[:90])
exact_json = '{"uid":%s}' % uid_text
req = urllib.request.Request(API + "/email/get", data=exact_json.encode(), method="POST",
                             headers={"Content-Type": "application/json",
                                      "Authorization": "Bearer " + token()})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        print("get with exact uid   :", r.status, r.read()[:60])
except urllib.error.HTTPError as e:
    print("get with exact uid   :", e.code, e.read()[:90])
