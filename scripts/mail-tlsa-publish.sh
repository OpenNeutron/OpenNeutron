#!/usr/bin/env bash
# Publish the DANE pin (TLSA) for the mail host from the certificate that is actually
# installed. Run by the certbot deploy hook after every renewal, and safe to run by hand.
#
# Why this exists: a DANE pin is a promise about the *current* certificate. If the cert
# renews and the pin does not, every sender that validates DANE refuses to deliver. So the
# pin must follow the certificate automatically, within seconds of the renewal.
set -uo pipefail

CERT=/etc/letsencrypt/live/mail.slothlee.xyz/cert.pem
TOKEN_FILE=/etc/cloudflare/dane.token
ZONE_ID=8708c31126d6177e328f489041aeb16d
RECORD_NAME=_25._tcp.mail.slothlee.xyz
LOG=/var/log/mail-tlsa.log

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG"; }

[ -r "$CERT" ] || { log "FAIL certificate missing: $CERT"; exit 1; }

# SPKI SHA-256 of the leaf key = TLSA 3 1 1
SPKI=$(openssl x509 -in "$CERT" -pubkey -noout 2>/dev/null \
       | openssl pkey -pubin -outform DER 2>/dev/null \
       | openssl dgst -sha256 -r 2>/dev/null | cut -d' ' -f1)
[ -n "${SPKI:-}" ] || { log "FAIL could not compute SPKI from $CERT"; exit 1; }
SERIAL=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2)

if [ ! -r "$TOKEN_FILE" ]; then
    log "SKIP no API token at $TOKEN_FILE — TLSA still points at ${SPKI:0:16}…; run this script once the token exists"
    exit 0
fi

API_TOKEN=$(tr -d '\r\n' <"$TOKEN_FILE")
API="https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records"

# Find the existing record id (there should be exactly one)
EXISTING=$(curl -sS -H "Authorization: Bearer $API_TOKEN" \
           "$API?type=TLSA&name=$RECORD_NAME" \
           | python3 -c 'import sys,json; d=json.load(sys.stdin); r=d.get("result") or []; print(r[0]["id"] if r else "")' 2>/dev/null)

BODY=$(python3 - "$SPKI" <<'PY'
import json,sys
print(json.dumps({"type":"TLSA","name":"_25._tcp.mail.slothlee.xyz","ttl":300,
                  "data":{"usage":3,"selector":1,"matching_type":1,"certificate":sys.argv[1]}}))
PY
)

if [ -n "$EXISTING" ]; then
    RESP=$(curl -sS -X PUT -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
           --data "$BODY" "$API/$EXISTING")
else
    RESP=$(curl -sS -X POST -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
           --data "$BODY" "$API")
fi

if printf '%s' "$RESP" | grep -q '"success":true'; then
    log "OK serial=$SERIAL pin=${SPKI:0:16}… published"
    exit 0
else
    log "FAIL API rejected the update: $(printf '%s' "$RESP" | head -c 300)"
    exit 1
fi
