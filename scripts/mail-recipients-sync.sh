#!/usr/bin/env bash
# Keep Postfix's recipient map equal to the mailbox list the app considers real.
#
# Why: Postfix can refuse an unknown recipient at RCPT, which stops a bounce
# message before any data is transferred. It can only do that from a map that is
# actually maintained — a stale map is worse than no map, because it rejects
# real people. The app is the source of truth; this script copies its answer.
#
# The map is pcre, not hash, so the lookup is case-insensitive: addresses here
# are lowercase and our mailboxes are case-insensitive, so a sender writing
# Admin@slothlee.xyz must not be refused for a mailbox called admin.
#
# The role addresses are added by this script rather than read from the API.
# They are not accounts and cannot be aliases (the app reserves the names), but
# RFC 5321 requires postmaster@ to be deliverable, abuse@ is where complaints
# are expected, and root@ is where the MTA addresses its own failure notices.
# are expected; the app routes both to staff.
set -uo pipefail

API="http://127.0.0.1:8080/api/admin/recipients"
CONFIG="/opt/on/config.yml"
MAP="/etc/postfix/recipients.pcre"
STAGE="$(mktemp)"
trap 'rm -f "$STAGE"' EXIT

# The staff token is minted on every run from the same signing secret the app
# uses. A saved token expires, and a silent expiry here would freeze the map —
# nobody would notice until mail started bouncing.
TOKEN="$(python3 - "$CONFIG" <<'PY'
import base64, hashlib, hmac, json, sys, time

secret = None
try:
    for line in open(sys.argv[1]):
        text = line.strip()
        if text.startswith("secret:") and "jwt" not in text:
            candidate = text.split(":", 1)[1].strip().strip('"').strip("'")
            if candidate and len(candidate) >= 16:
                secret = candidate
                break
except OSError:
    raise SystemExit("")
if not secret:
    raise SystemExit("")

def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

now = int(time.time())
head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
body = b64(json.dumps({"sub": "tibs", "iat": now, "exp": now + 300}, separators=(",", ":")).encode())
sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
print(f"{head}.{body}.{b64(sig)}")
PY
)"

if [ -z "${TOKEN:-}" ]; then
    echo "recipients-sync: could not mint a staff token from $CONFIG" >&2
    exit 1
fi

BODY="$(curl -fsS --max-time 10 -H "Authorization: Bearer $TOKEN" "$API")" || {
    # Never fall through to writing an empty map: that would refuse every
    # recipient on the server because one API call timed out.
    echo "recipients-sync: API unreachable, leaving $MAP alone" >&2
    exit 1
}

DOMAIN="$(postconf -h relay_domains | awk '{print $1}')"
[ -n "$DOMAIN" ] || { echo "recipients-sync: no relay_domains" >&2; exit 1; }

printf '%s' "$BODY" | python3 -c '
import json, sys, re
domain = sys.argv[1]
data = json.load(sys.stdin)
names = {n.strip().lower() for n in data.get("recipients", []) if n.strip()}
names.update({"postmaster", "abuse", "hostmaster", "root"})
for name in sorted(names):
    # Escape regex metacharacters in the local part; match without case.
    print("/(?i)^" + re.escape(name) + "@" + re.escape(domain) + "$/ OK")
' "$DOMAIN" > "$STAGE" || { echo "recipients-sync: could not build map" >&2; exit 1; }

COUNT="$(wc -l < "$STAGE")"
if [ "$COUNT" -lt 1 ]; then
    echo "recipients-sync: refusing to install an empty map" >&2
    exit 1
fi
for required in postmaster abuse root; do
    grep -qi "${required}@" "$STAGE" || {
        echo "recipients-sync: map would omit ${required}@ — refusing to install" >&2
        exit 1
    }
done

if [ -f "$MAP" ] && cmp -s "$STAGE" "$MAP"; then
    exit 0
fi

install -m 0644 -o root -g root "$STAGE" "$MAP.new" && mv "$MAP.new" "$MAP"
echo "recipients-sync: installed $COUNT recipients for $DOMAIN"
