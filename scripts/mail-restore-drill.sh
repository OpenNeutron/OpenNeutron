#!/usr/bin/env bash
# Restore drill: prove the off-site backup is a working mail server, not just a file.
#
# The nightly backup already decrypts its own archive and lists it, which proves the
# file is not truncated. It proves nothing about whether the *copy off the box* comes
# back, and that is the only question that matters on the day the box is gone.
#
# This downloads the newest archive from the private repo, checks it against the
# sha256 written when it was uploaded, decrypts it, and boots a second server from the
# restored data on port 8099 (production stays on 8080, untouched). It then asks the
# restored server who it has, and fails loudly if the answer is nobody.
#
# What a restore also needs and this does not supply: the TLS certificate (mount real
# certs, or re-issue once DNS points at the new host) and the /usr/src/app layout the
# image expects. Both are in /root/HARDENING.md and the runbook.
#
#   /usr/local/bin/mail-restore-drill.sh            newest archive
#   /usr/local/bin/mail-restore-drill.sh <name>     a specific archive
#
# Leaves nothing running: the drill container and its data are removed at the end.
set -uo pipefail

REPO="SirTibbles666one/sloth-mail-backups"
TOKEN_FILE="/root/.gh-backup-token"
PASS_FILE="/root/.mail-backup-pass"
IMAGE="openneutron:local"
WORK="$(mktemp -d)"
NAME="${1:-}"
FAILED=0

say() { printf '%s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILED=1; }
pass() { printf '  ok    %s\n' "$*"; }

cleanup() {
  docker rm -f restore-drill >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -r "$TOKEN_FILE" ] || { say "no backup token at $TOKEN_FILE"; exit 1; }
[ -r "$PASS_FILE" ]  || { say "no archive passphrase at $PASS_FILE"; exit 1; }
TOKEN="$(cat "$TOKEN_FILE")"

if [ -z "$NAME" ]; then
  NAME="$(curl -s -H "Authorization: token $TOKEN" \
    "https://api.github.com/repos/$REPO/contents/backups" \
    | python3 -c 'import sys,json; rows=[x["name"] for x in json.load(sys.stdin) if x["name"].endswith(".gpg")]; rows.sort(); print(rows[-1] if rows else "")')"
fi
[ -n "$NAME" ] || { say "could not find an archive in $REPO"; exit 1; }
say "drill: $NAME"

curl -sL -H "Authorization: token $TOKEN" -H "Accept: application/vnd.github.raw" \
  -o "$WORK/archive.gpg" \
  "https://api.github.com/repos/$REPO/contents/backups/$NAME"
[ -s "$WORK/archive.gpg" ] && pass "downloaded $(stat -c %s "$WORK/archive.gpg") bytes" \
  || { fail "download produced nothing"; exit 1; }

# The upload log records the sha256; a mismatch means the copy off the box differs
# from the one that was verified locally.
GOT="$(sha256sum "$WORK/archive.gpg" | cut -d' ' -f1)"
WANT="$(grep -F "$NAME" /var/log/mail-offsite.log | tail -1 | sed -n 's/.*sha256=\([0-9a-f]*\).*/\1/p')"
if [ -n "$WANT" ] && [ "$GOT" = "$WANT" ]; then pass "sha256 matches the upload log"
elif [ -n "$WANT" ]; then fail "sha256 $GOT does not match the recorded $WANT"
else say "  note  no sha256 in the log for this archive"; fi

gpg --batch --quiet --decrypt --passphrase-file "$PASS_FILE" \
    -o "$WORK/state.tgz" "$WORK/archive.gpg" 2>/dev/null \
  && pass "decrypts with the passphrase on this host" || { fail "will not decrypt"; exit 1; }

mkdir -p "$WORK/app"
tar xzf "$WORK/state.tgz" -C "$WORK/app" || { fail "archive does not extract"; exit 1; }
pass "extracts ($(tar tzf "$WORK/state.tgz" | wc -l) members)"

for want in data/users.bin data/blobs dkim config.yml; do
  [ -e "$WORK/app/$want" ] && pass "contains $want" || fail "missing $want"
done

# The archive is state, not a program: it deliberately holds no binary, because a
# backup that pinned a build would restore last month's server with this month's data.
# A real restore rebuilds from git; here the current build is already on the host.
BIN="/opt/on/target/x86_64-unknown-linux-musl/release/OpenNeutron"
if [ -x "$BIN" ]; then
  cp "$BIN" "$WORK/app/OpenNeutron" && chmod +x "$WORK/app/OpenNeutron"
  pass "paired the restored state with the current build"
else
  fail "no built binary at $BIN (build it: docker exec openneutron cargo build --release --target x86_64-unknown-linux-musl)"
fi

# Boot it. Ports inside the container stay standard; only 8099 is published, so this
# cannot collide with production. The certs are mounted read-only because the server
# refuses to start without a TLS certificate.
docker rm -f restore-drill >/dev/null 2>&1
docker run -d --name restore-drill -p 8099:8080 \
  -v "$WORK/app:/usr/src/app" -v /etc/letsencrypt:/etc/letsencrypt:ro \
  -w /usr/src/app --entrypoint ./OpenNeutron "$IMAGE" >/dev/null 2>&1 \
  || { fail "container would not start"; exit 1; }

for _ in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8099/api/user/me)
  [ "$code" = "401" ] && break
  sleep 1
done
if [ "$code" = "401" ]; then pass "restored server answers its API on 8099"
else fail "restored server did not answer (last: ${code:-none})"; docker logs restore-drill 2>&1 | tail -5; exit 1; fi

# Captured, not piped: `docker logs | grep -q` looks successful but with pipefail the
# killed `docker logs` (SIGPIPE once grep exits) makes the pipeline return 141, so a
# passing check reports failure. Read the log once and search the text.
LOGS="$(docker logs restore-drill 2>&1)"
case "$LOGS" in
  *"Loaded "*" users"*) pass "loaded its user table: $(printf '%s' "$LOGS" | grep -o 'Loaded [0-9]* users' | tail -1)" ;;
  *) fail "did not load a user table" ;;
esac
case "$LOGS" in
  *"DKIM] Loaded signing key"*) pass "DKIM key recovered from the archive" ;;
  *) fail "DKIM key missing — restored mail would go out unsigned" ;;
esac

# Who does the restored copy think exists? Zero users would still answer 401 above.
#
# This check used to read /root/.admin.jwt — a 24-hour token left on the host by a
# human. It expired on 31 October, and from then on every drill reported "the
# restored copy holds no accounts" while the same archive loaded its user table two
# checks earlier: the drill was measuring the age of a file, not the backup. Mint a
# token from the RESTORED config instead, so the check tests what was restored.
T="$(python3 - "$WORK/app/config.yml" <<'MINT'
import base64, hashlib, hmac, json, sys, time
try:
    import yaml
    secret = yaml.safe_load(open(sys.argv[1]))['jwt']['secret']
except Exception:
    raise SystemExit(0)
if not secret:
    raise SystemExit(0)
now = int(time.time())


def enc(value):
    raw = json.dumps(value, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


signing = f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'sub': 'tibs', 'iat': now, 'exp': now + 120})}"
sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
print(f"{signing}.{sig}")
MINT
)"
if [ -n "$T" ]; then
  COUNT=$(curl -s -H "Authorization: Bearer $T" http://127.0.0.1:8099/api/admin/users \
    | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("users",[])))' 2>/dev/null || echo 0)
  LOGGED_N=$(printf '%s' "$LOGS" | grep -o 'Loaded [0-9]* users' | tail -1 | grep -o '[0-9]*')
  if [ "${COUNT:-0}" -gt 0 ] && [ -n "$LOGGED_N" ] && [ "${COUNT:-0}" = "$LOGGED_N" ]; then
    pass "the restored copy holds $COUNT accounts, the same number it loaded"
  elif [ "${COUNT:-0}" -gt 0 ]; then
    fail "the API lists $COUNT accounts but the restored table loaded ${LOGGED_N:-?} — two sources disagree"
  else
    fail "the API listed no accounts on a restored copy that loaded ${LOGGED_N:-?} users"
  fi
else
  fail "could not mint an admin token from the restored config — the account count went unchecked"
fi

say ""
if [ "$FAILED" -eq 0 ]; then say "restore drill passed"; else say "restore drill FAILED"; fi
exit "$FAILED"
