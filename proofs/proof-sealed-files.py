#!/usr/bin/env python3
"""Sealed attachments: API side. Writes the served armour to /tmp/opened-file.asc
so it can be decrypted elsewhere and compared with the original bytes."""
import json
import urllib.error
import urllib.request

BASE = "https://mail.slothlee.xyz/api"
CREDS = dict(l.split() for l in open("/root/e2e-accounts.txt") if l.strip())

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
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main():
    d = json.load(open("/tmp/sealed-files.json"))
    tok = call("POST", "/auth/login", {"username": "e2ea", "password": CREDS["e2ea"]})[1]["token"]

    status, body = call("POST", "/note/create", {
        "recipient": "x@startmail.com", "subject": "nofiles", "armored": d["armor"], "mode": "pgp",
        "files": [{"name": "a.bin", "armored": d["fileArmor"], "size": d["fileSize"]}],
    }, tok)
    check("key-locked note refuses files", status == 400 and body.get("code") == "files_need_passphrase", str(body))

    status, body = call("POST", "/note/create", {
        "recipient": "x@startmail.com", "subject": "toomany", "armored": d["armor"], "mode": "passphrase",
        "files": [{"name": f"f{i}", "armored": "x", "size": 1} for i in range(6)],
    }, tok)
    check("refuses more than five files", status == 400 and body.get("code") == "too_many_files", str(body))

    status, body = call("POST", "/note/create", {
        "recipient": "x@startmail.com", "subject": "toobig", "armored": d["armor"], "mode": "passphrase",
        "files": [{"name": "big", "armored": "x" * 6_100_000, "size": 1}],
    }, tok)
    check("refuses oversized attachments", status == 413, str(body))

    status, made = call("POST", "/note/create", {
        "recipient": "x@startmail.com", "subject": "with-file", "armored": d["armor"], "mode": "passphrase",
        "files": [{"name": "../evil/attach-test.bin", "armored": d["fileArmor"], "size": d["fileSize"]}],
    }, tok)
    check("created with a file", status == 200 and "t=" in made.get("url", ""), str(made))
    token = made["url"].split("t=")[1]

    # The page must render without consuming anything.
    with urllib.request.urlopen(f"https://mail.slothlee.xyz/api/note?t={token}", timeout=30) as resp:
        page = resp.read().decode()
    check("page renders", resp.status == 200 and "Download" not in page.split("<script")[0])

    status, opened = call("POST", "/note/open", {"token": token})
    files = opened.get("files", [])
    check("open returns the file", status == 200 and len(files) == 1, str(status))
    check("name is stripped of paths", files and files[0]["name"] == "attach-test.bin", files[0]["name"] if files else "none")
    check("armour is intact", files and files[0]["armored"] == d["fileArmor"])
    if files:
        open("/tmp/opened-file.asc", "w").write(files[0]["armored"])

    # A passphrase note survives a wrong phrase, so its body and files stay until
    # the page burns it after a successful decrypt — which is what this calls.
    status, burned = call("POST", "/note/burn", {"token": token})
    check("burn clears it", status == 200, str(burned))

    status, again = call("POST", "/note/open", {"token": token})
    check("after burning, open is refused", status == 410, str(status))

    store = json.load(open("/opt/on/data/notes.json"))["notes"]
    row = store[token]
    check("body and file are gone from the store", row["armored"] == "" and len(row["files"]) == 0,
          f"armour={len(row['armored'])} files={len(row['files'])}")

    print(f"\n{passed} passed, {len(failed)} failed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
