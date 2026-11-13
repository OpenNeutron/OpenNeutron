#!/usr/bin/env python3
"""Fetch the newest off-site snapshot and unpack it into a scratch directory.

Reads the same token and passphrase the nightly job uses, so the drill exercises
the real artefact rather than a locally re-made one. Nothing is written outside
/root/restore-drill.
"""
import base64
import json
import os
import subprocess
import sys
import urllib.request

REPO = "SirTibbles666one/sloth-mail-backups"   # keep in step with mail-offsite-backup.sh
TOKEN = open("/root/.gh-backup-token").read().strip()
PASS = "/root/.mail-backup-pass"
WORK = "/root/restore-drill"
ENC = os.path.join(WORK, "snapshot.tgz.gpg")
DIR = os.path.join(WORK, "restored")


def api(path: str) -> dict:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}{path}",
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def main() -> int:
    os.makedirs(WORK, exist_ok=True)
    listing = api("/contents/backups")
    snapshots = sorted(i["name"] for i in listing if i["name"].endswith(".tgz.gpg"))
    if not snapshots:
        print("no snapshots in the repository")
        return 1
    newest = snapshots[-1]
    print("newest snapshot:", newest)

    entry = api(f"/contents/backups/{newest}")
    # The contents API returns content:"" for anything over 1 MB — silently, with
    # encoding "none". 21 MB of archive came back as zero bytes and the failure
    # surfaced later as a GPG error. The blob endpoint has a 100 MB ceiling.
    blob = api(f"/git/blobs/{entry['sha']}")
    with open(ENC, "wb") as handle:
        handle.write(base64.b64decode(blob["content"]))
    print("downloaded:", os.path.getsize(ENC), "bytes, sha", entry["sha"][:12])
    if os.path.getsize(ENC) < 1_000_000:
        print("archive is suspiciously small for a full snapshot")
        return 1

    subprocess.run(["rm", "-rf", DIR, DIR + ".tgz"], check=True)
    decrypt = subprocess.run(
        ["gpg", "--batch", "--yes", "--quiet", "--decrypt", "--passphrase-file", PASS, "-o", DIR + ".tgz", ENC],
        capture_output=True,
    )
    if decrypt.returncode != 0:
        print("decrypt failed:", decrypt.stderr.decode()[:300])
        return 1
    print("decrypted:", os.path.getsize(DIR + ".tgz"), "bytes")

    listing_out = subprocess.run(["tar", "tzf", DIR + ".tgz"], capture_output=True, text=True, check=True)
    names = listing_out.stdout.splitlines()
    print("members:", len(names))

    os.makedirs(DIR, exist_ok=True)
    subprocess.run(["tar", "xzf", DIR + ".tgz", "-C", DIR], check=True)

    # Members are stored relative to their tar root (the archive uses -C /opt/on
    # and -C /opt), so there is no "on/" prefix. Naming paths that cannot exist
    # made a healthy archive print MISSING three times.
    wanted = ["data/users.bin", "config.yml", "sloth-bot/.env", "etc/postfix/main.cf", "data/static/index.html"]
    for path in wanted:
        full = os.path.join(DIR, path)
        print(f"  {'ok ' if os.path.exists(full) else 'MISSING'} {path} {os.path.getsize(full) if os.path.exists(full) else ''}")

    groups = {}
    for name in names:
        top = name.split("/")[0]
        groups[top] = groups.get(top, 0) + 1
    print("top-level:", dict(sorted(groups.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
