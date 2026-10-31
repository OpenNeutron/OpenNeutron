#!/usr/bin/env bash
# Encrypted off-site snapshot of the mail state, pushed to a private GitHub repo.
#
# Why GitHub: it is a different provider, so a dead server does not take the
# backups with it, and it costs nothing. The archive is AES-256 encrypted with a
# passphrase that exists only on this host, so the repository contents are
# useless to anyone who can read the repo.
set -euo pipefail

REPO="SirTibbles666one/sloth-mail-backups"
TOKEN_FILE="/root/.gh-backup-token"
PASS_FILE="/root/.mail-backup-pass"
LOG="/var/log/mail-offsite.log"
KEEP=10
STAMP="$(date -u +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$LOG"; }

for f in "$TOKEN_FILE" "$PASS_FILE"; do
  [ -r "$f" ] || { log "ERROR missing $f"; exit 1; }
done

TOKEN="$(cat "$TOKEN_FILE")"

# State that matters: accounts, blobs, invites, recovery metadata, DKIM key and
# config. Everything in here is either secret or personal, hence the encryption.
# The approval queue must exist before tar runs, or a missing member makes tar
# exit non-zero under set -e and the whole backup is skipped.
[ -f /opt/on/data/webauthn.json ] || printf %s "{}" > /opt/on/data/webauthn.json
[ -f /opt/on/data/pgpkeys.json ] || printf %s "{}" > /opt/on/data/pgpkeys.json
[ -f /opt/on/data/pending_users.json ] || printf %s "{}\n" > /opt/on/data/pending_users.json
[ -f /opt/on/data/ephemeral.json ] || printf %s '{"entries":{},"receipts":{}}' > /opt/on/data/ephemeral.json
[ -f /opt/on/data/notes.json ] || printf %s '{"notes":{}}' > /opt/on/data/notes.json
[ -f /opt/on/data/aliases.json ] || printf %s '{"aliases":{}}' > /opt/on/data/aliases.json
[ -f /opt/on/data/scheduled.json ] || printf %s '{"items":{}}' > /opt/on/data/scheduled.json
[ -f /opt/on/data/arrival.json ] || printf %s '{"arrivals":{}}' > /opt/on/data/arrival.json
[ -f /opt/on/data/push.json ] || printf %s '{"subs":{}}' > /opt/on/data/push.json
# Losing this file invalidates every browser already subscribed, so it is kept.
# The bot's database is the half of the bot that cannot be re-created: its tokens live in
# .env, but guild settings, AI memory and history live here. Dump it beside the env file so
# one archive carries both, and refuse to continue on an empty dump rather than ship a
# backup that looks fine and restores nothing.
docker exec sloth-pg pg_dump -U sloth -d sloth --clean --if-exists | gzip > /opt/sloth-bot/backup/sloth.sql.gz
DUMP_BYTES=$(stat -c %s /opt/sloth-bot/backup/sloth.sql.gz)
[ "$DUMP_BYTES" -gt 2048 ] || { log "ERROR bot database dump is only ${DUMP_BYTES} bytes"; exit 1; }
chown 1000:1000 /opt/sloth-bot/backup/sloth.sql.gz

# The mail server's source lives in a git repository on this disk and nowhere else:
# OpenNeutron/OpenNeutron on GitHub refuses this PAT, and the fork's main has drifted
# away from the tree that is actually deployed. A bundle is the whole history in one
# file, so the archive can rebuild the code — not just the data it serves.
rm -rf /opt/backup-repo/mail-repo.bundle
mkdir -p /opt/backup-repo
git -C /opt/on bundle create /opt/backup-repo/mail-repo.bundle main 2>>"$LOG" \
  || { log "ERROR could not bundle the mail repository"; exit 1; }
BUNDLE_BYTES=$(stat -c %s /opt/backup-repo/mail-repo.bundle)
[ "$BUNDLE_BYTES" -gt 65536 ] || { log "ERROR mail repository bundle is only ${BUNDLE_BYTES} bytes"; exit 1; }
log "mail repository bundled (${BUNDLE_BYTES} bytes, $(git -C /opt/on rev-list --count main) commits)"

# The site is built from /opt/sloth-site and lives in no repository: without it
# the public pages survive only as a running container. Exclude the 1.3 GB of
# node_modules and .next — 808 KB of source is the part that cannot be rebuilt.
tar czf "$WORK/state.tgz" --exclude=node_modules --exclude=.next -C /opt/on \
  data/users.bin data/waitlist.json data/pending_users.json data/recovery.json \
  data/twofactor.json data/sessions.json data/ephemeral.json data/notes.json \
  data/aliases.json data/scheduled.json data/arrival.json data/push.json data/vapid.json data/imported.json data/pqkeys.json data/mailboxlog.json data/logkey.json data/webauthn.json data/pgpkeys.json data/reports.jsonl data/geoip.mmdb data/blobs data/static dkim config.yml \
  -C /opt sloth-bot/.env sloth-bot/docker-compose.yml sloth-bot/backup sloth-bot/bugreports sloth-bot/secrets.json sloth-bot/owner backup-repo \
  -C / etc/nginx/sites-available etc/nginx/sites-enabled etc/nginx/conf.d \
  etc/postfix/main.cf etc/postfix/master.cf etc/postfix/recipients.pcre \
  etc/systemd/resolved.conf.d etc/unbound/unbound.conf.d \
  var/spool/cron/crontabs etc/letsencrypt/live etc/letsencrypt/archive etc/letsencrypt/renewal \
  -C / usr/local/bin/mail-health.sh usr/local/bin/mail-alert.sh usr/local/bin/mail-dns-watch.sh \
  usr/local/bin/mail-offsite-backup.sh usr/local/bin/mail-recipients-sync.sh usr/local/bin/sloth-stack-watch.sh \
  -C /opt sloth-site

gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
    --passphrase-file "$PASS_FILE" \
    -o "$WORK/slothmail-$STAMP.tgz.gpg" "$WORK/state.tgz"

SIZE=$(stat -c %s "$WORK/slothmail-$STAMP.tgz.gpg")
SHA=$(sha256sum "$WORK/slothmail-$STAMP.tgz.gpg" | cut -d' ' -f1)

# Refuse to upload a truncated archive: an unopenable backup is worse than none.
gpg --batch --yes --quiet --decrypt --passphrase-file "$PASS_FILE" \
    -o "$WORK/verify.tgz" "$WORK/slothmail-$STAMP.tgz.gpg" 2>/dev/null
tar tzf "$WORK/verify.tgz" > /dev/null || { log "ERROR archive does not round-trip"; exit 1; }
tar tzf "$WORK/verify.tgz" sloth-bot/docker-compose.yml > /dev/null 2>&1 || { log "ERROR the archive carries no stack definition (sloth-bot/docker-compose.yml)"; exit 1; }
tar tzf "$WORK/verify.tgz" sloth-site/app/page.jsx > /dev/null 2>&1 || { log "ERROR the archive carries no site source (sloth-site/app)"; exit 1; }

B64="$WORK/payload.b64"
base64 -w0 "$WORK/slothmail-$STAMP.tgz.gpg" > "$B64"

PAYLOAD="$WORK/upload.json"
python3 - "$B64" "$STAMP" "$PAYLOAD" <<'PY'
import json, sys
b64_path, stamp, out = sys.argv[1], sys.argv[2], sys.argv[3]
with open(b64_path) as f:
    content = f.read()
json.dump({
    "message": f"snapshot {stamp}",
    "content": content,
    "branch": "main",
}, open(out, "w"))
PY

UPLOAD=$(curl -sS -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$REPO/contents/backups/slothmail-$STAMP.tgz.gpg" \
  --data-binary "@$PAYLOAD")

if ! echo "$UPLOAD" | grep -q '"commit"'; then
  # ${UPLOAD:0:200}, not a pipe to head: head exits early, and pipefail turns
  # that into SIGPIPE — the error would never reach the log.
  log "ERROR upload failed: ${UPLOAD:0:200}"
  exit 1
fi

# Prune old snapshots, keeping the newest $KEEP.
LIST=$(curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://api.github.com/repos/$REPO/contents/backups")

# The listing goes through a file, not a pipe: a pipe and a heredoc cannot both
# be stdin, and with `set -o pipefail` the unread pipe kills the script with
# SIGPIPE (141) before it can log the upload it just made.
printf '%s' "$LIST" > "$WORK/listing.json"
python3 - "$WORK/listing.json" "$KEEP" > "$WORK/prune.txt" <<'PY'
import json, sys
path, keep = sys.argv[1], int(sys.argv[2])
try:
    items = json.load(open(path))
except Exception:
    sys.exit(0)
if not isinstance(items, list):
    sys.exit(0)
files = sorted(
    [i for i in items if i.get("name", "").endswith(".tgz.gpg")],
    key=lambda i: i["name"],
)
for item in files[:-keep] if len(files) > keep else []:
    print(item["name"], item["sha"])
PY

while read -r name sha; do
  [ -z "${name:-}" ] && continue
  curl -sS -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/contents/backups/$name" \
    -d "{\"message\":\"prune $name\",\"sha\":\"$sha\",\"branch\":\"main\"}" > /dev/null || true
  log "pruned $name"
done < "$WORK/prune.txt"

log "OK uploaded backups/slothmail-$STAMP.tgz.gpg size=$SIZE sha256=$SHA"
