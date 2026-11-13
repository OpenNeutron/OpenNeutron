#!/usr/bin/env python3
"""New-mail notifications: the rules the server enforces.

Runs on the mail host. The delivered-push path is proven in a browser (a real
service worker shows the notification); this checks what the API accepts, who can
see a subscription, and that an endpoint cannot be pointed at an arbitrary host.
"""
import json
import sys
import urllib.error
import urllib.request

BASE = "https://mail.slothlee.xyz/api"
passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"PASS {name}" + (f"  [{detail}]" if detail else ""))
    else:
        failed += 1
        print(f"FAIL {name}" + (f"  [{detail}]" if detail else ""))


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def login(username, password):
    status, body = call("POST", "/auth/login", {"username": username, "password": password})
    assert status == 200, f"login {username}: {status} {body}"
    return body["token"]


def main():
    creds = dict(l.split() for l in open("/root/e2e-accounts.txt") if l.strip())
    owner = login("e2ea", creds["e2ea"])
    other = login("e2eb", creds["e2eb"])

    status, key = call("GET", "/push/key")
    raw = key.get("key", "")
    decoded_len = 0
    if raw:
        import base64
        decoded_len = len(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    check("a public key is offered", status == 200 and raw, f"{status}")
    check("it is an uncompressed P-256 point", decoded_len == 65, f"{decoded_len} bytes")
    status2, again = call("GET", "/push/key")
    check("the same key every time", again.get("key") == raw, "stable")

    check("status needs a session", call("GET", "/push/status")[0] == 401)
    check("subscribing needs a session", call("POST", "/push/subscribe", {"endpoint": "x", "keys": {"p256dh": "a", "auth": "b"}})[0] == 401)

    # A real P-256 subscription key. The server validates the shape of these
    # now, and sealing a payload to a stub fails at send time -- so the fixture
    # generates a genuine keypair and lets the fake endpoint be the only lie.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    import base64, os
    _priv = ec.generate_private_key(ec.SECP256R1())
    _point = _priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    _b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    bogus = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/proof-" + str(int(__import__("time").time())),
        "keys": {"p256dh": _b64(_point), "auth": _b64(os.urandom(16))},
        "ua": "proof-script",
    }
    check("refuses a host that is not a push service",
          call("POST", "/push/subscribe", {**bogus, "endpoint": "https://example.com/push"}, owner)[0] == 400)
    check("refuses plain http",
          call("POST", "/push/subscribe", {**bogus, "endpoint": "http://fcm.googleapis.com/x"}, owner)[0] == 400)
    check("refuses a subscription with no keys",
          call("POST", "/push/subscribe", {**bogus, "keys": {"p256dh": "", "auth": ""}}, owner)[0] == 400)
    # Stub keys used to be accepted and then failed on every send with
    # "bad p256dh: Invalid input length", which nobody saw. They are refused
    # here now, where the subscriber is looking.
    check("refuses a stub public key",
          call("POST", "/push/subscribe", {**bogus, "keys": {"p256dh": _b64(b"\x04short"), "auth": _b64(b"0"*16)}}, owner)[0] == 400)
    check("refuses a stub auth secret",
          call("POST", "/push/subscribe", {**bogus, "keys": {"p256dh": _b64(_point), "auth": _b64(b"short")}}, owner)[0] == 400)

    before = call("GET", "/push/status", token=owner)[1].get("count", 0)
    status, body = call("POST", "/push/subscribe", bogus, token=owner)
    check("registers a browser", status == 200, f"{status} {body}")
    after = call("GET", "/push/status", token=owner)[1].get("count", 0)
    check("status counts it", after == before + 1, f"{before} -> {after}")
    check("another account does not see it",
          call("GET", "/push/status", token=other)[1].get("count", 0) == 0)

    # A subscription registered twice is one browser, not two.
    call("POST", "/push/subscribe", bogus, token=owner)
    check("re-registering does not stack",
          call("GET", "/push/status", token=owner)[1].get("count", 0) == after)

    status, body = call("POST", "/push/test", token=owner)
    check("a test push is attempted", status == 200 and "delivered" in body, f"{status} {body}")

    check("unsubscribing works", call("POST", "/push/unsubscribe", {"endpoint": bogus["endpoint"]}, token=owner)[0] == 200)
    check("the count drops back",
          call("GET", "/push/status", token=owner)[1].get("count", 0) == before)
    check("testing with nothing registered is refused",
          call("POST", "/push/test", token=owner)[0] == 409)

    print(f"\n{passed}/{passed + failed} checks passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
