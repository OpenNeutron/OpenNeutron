#!/usr/bin/env bash
# Refresh the local country database used to label signed-in sessions.
#
# DB-IP Lite (CC BY 4.0, attribution: https://db-ip.com) — free, no account, and
# downloaded as a whole file, so no address ever leaves the machine to be looked up.
#
# Monthly: the file is dated by month, and an old month still answers correctly for
# addresses that have not been reassigned. A failed download leaves the previous file
# in place rather than deleting the feature.
set -euo pipefail

DEST=/opt/on/data/geoip.mmdb
TMP=$(mktemp /tmp/geoip.XXXXXX.mmdb)
MONTH=$(date -u +%Y-%m)

cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

url="https://download.db-ip.com/free/dbip-country-lite-${MONTH}.mmdb.gz"
if ! curl -fsSL --max-time 120 "$url" -o "$TMP.gz"; then
  # The new month's file is published a few days in; fall back to last month's.
  prev=$(date -u -d 'last month' +%Y-%m)
  url="https://download.db-ip.com/free/dbip-country-lite-${prev}.mmdb.gz"
  curl -fsSL --max-time 120 "$url" -o "$TMP.gz"
fi

gunzip -c "$TMP.gz" > "$TMP"
rm -f "$TMP.gz"

# A truncated database would answer every lookup with nothing, silently.
size=$(stat -c%s "$TMP")
if [ "$size" -lt 1000000 ]; then
  echo "FAIL  downloaded database is ${size} bytes — refusing to install it" >&2
  exit 1
fi

install -m 644 "$TMP" "$DEST"
echo "geoip: installed $(basename "$url") (${size} bytes) as $DEST"
