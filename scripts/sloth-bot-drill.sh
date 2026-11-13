#!/usr/bin/env bash
# Can the archive rebuild the bot, not just the mail?
#
# The monthly drill boots a second mail server from the newest archive and proves the mail
# half. The bot half has never been exercised that way: its database was proven once from a
# fresh dump, and its sealed credentials were proven from the live files. Neither is the same
# as proving the archive carries a working pair.
#
# This extracts only sloth-bot/*, restores the database into a scratch database, and opens the
# sealed credentials with the key that arrived in the same archive. It deliberately does not
# start the bot: Discord allows one gateway per token, so a "full" boot would mean stopping
# production. What is checked here is everything up to that line.
set -uo pipefail

REPO="SirTibbles666one/sloth-mail-backups"
TOKEN_FILE="/root/.gh-backup-token"
PASS_FILE="/root/.mail-backup-pass"
WORK="$(mktemp -d)"
FAILED=0

say() { printf '%s\n' "$*"; }
pass() { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILED=1; }

db() { docker exec sloth-pg psql -U sloth -d "$1" -tAc "$2" 2>/dev/null | tr -d '[:space:]'; }

cleanup() { docker exec sloth-pg psql -U sloth -d postgres -tAc 'DROP DATABASE IF EXISTS sloth_drill' >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

[ -r "$TOKEN_FILE" ] || { say "no backup token at $TOKEN_FILE"; exit 1; }
[ -r "$PASS_FILE" ] || { say "no archive passphrase at $PASS_FILE"; exit 1; }
TOKEN="$(cat "$TOKEN_FILE")"

NAME="$(curl -s -H "Authorization: token $TOKEN" \
  "https://api.github.com/repos/$REPO/contents/backups" \
  | python3 -c 'import sys,json; r=[x["name"] for x in json.load(sys.stdin) if x["name"].endswith(".gpg")]; r.sort(); print(r[-1] if r else "")')"
[ -n "$NAME" ] || { say "no archive found in $REPO"; exit 1; }
say "bot drill: $NAME"

curl -sL -H "Authorization: token $TOKEN" -H "Accept: application/vnd.github.raw" \
  -o "$WORK/archive.gpg" "https://api.github.com/repos/$REPO/contents/backups/$NAME"
[ -s "$WORK/archive.gpg" ] && pass "downloaded $(stat -c %s "$WORK/archive.gpg") bytes" \
  || { fail "download produced nothing"; exit 1; }

# The archive is encrypted with the passphrase that until recently existed only on this host.
gpg --batch --quiet --decrypt --passphrase-file "$PASS_FILE" -o "$WORK/state.tgz" "$WORK/archive.gpg" 2>/dev/null \
  && pass "decrypted with the recorded passphrase" || { fail "decryption failed"; exit 1; }

mkdir -p "$WORK/bot" && tar xzf "$WORK/state.tgz" -C "$WORK/bot" sloth-bot 2>/dev/null
# The bot runs as uid 1000 and these files come out of tar owned by root at 0600: without
# this the drill fails on a permission denied and blames the encryption.
chmod -R a+rX "$WORK/bot" 2>/dev/null; chmod a+rx "$WORK" "$WORK/bot" 2>/dev/null
for f in sloth-bot/.env sloth-bot/secrets.json sloth-bot/owner/key sloth-bot/backup/sloth.sql.gz; do
  [ -s "$WORK/bot/$f" ] && pass "archive carries $f" || fail "archive is missing $f"
done
[ "$FAILED" = 0 ] || { say "drill failed: the archive cannot rebuild the bot"; exit 1; }

# The database, restored into a scratch database and compared with production. Equal counts are
# the difference between "it restored" and "it restored the right thing".
docker exec sloth-pg psql -U sloth -d postgres -tAc 'DROP DATABASE IF EXISTS sloth_drill' >/dev/null 2>&1
docker exec sloth-pg psql -U sloth -d postgres -tAc 'CREATE DATABASE sloth_drill' >/dev/null 2>&1 || { fail "could not create scratch database"; exit 1; }
if gunzip -c "$WORK/bot/sloth-bot/backup/sloth.sql.gz" | docker exec -i sloth-pg psql -U sloth -d sloth_drill >/dev/null 2>&1; then
  pass "database restored into a scratch database"
else
  fail "database would not restore"
fi

for t in guild_settings ai_messages _prisma_migrations; do
  live=$(db sloth "select count(*) from $t")
  drill=$(db sloth_drill "select count(*) from $t")
  if [ -n "$live" ] && [ "$live" = "$drill" ]; then pass "$t: $drill rows, same as production"; else fail "$t: production $live vs archive ${drill:-0}"; fi
done

# The key from the archive must open the credentials from the archive, in a container that has
# nothing else mounted.
if docker run --rm -v "$WORK/bot/sloth-bot:/sealed:ro" sloth-bot:local node -e '
  process.env.SLOTH_SEALED_FILE = "/sealed/secrets.json";
  process.env.SLOTH_SEALED_KEY = "/sealed/owner/key";
  const m = await import("/app/src/services/sealed-env.js");
  const r = m.mergeSealedEnv({});
  // No error is how success looks here: the loader leaves `error` undefined, it does not
  // set it to a string. Requiring a value made a healthy archive look broken.
  const ok = !r.error && r.source === "sealed" && String(r.env.DISCORD_TOKEN || "").length > 40;
  console.log(ok ? "sealed-ok" : `sealed-bad source=${r.source} error=${r.error}`);
' > "$WORK/sealed.out" 2>&1; then
  :
fi
if grep -q sealed-ok "$WORK/sealed.out"; then
  pass "sealed credentials open with the archived key"
else
  fail "sealed credentials would not open with the archived key: $(tail -2 "$WORK/sealed.out" | tr '\n' ' ' | cut -c1-160)"
fi

say ""
if [ "$FAILED" = 0 ]; then say "drill PASSED: the archive rebuilds the bot"; else say "drill FAILED"; fi
exit "$FAILED"
