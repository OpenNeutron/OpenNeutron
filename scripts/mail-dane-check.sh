#!/usr/bin/env bash
# Does the published DANE pin still match the certificate the mail server presents?
#
# This is the guard rail for an automatic pin: if a renewal updates the cert but the
# deploy hook failed, inbound mail from DANE-validating senders stops. This check answers
# that question from the outside, the way a sending server would.
set -uo pipefail

HOST=mail.slothlee.xyz
PORT=25
# Ask the authoritative nameserver, not a resolver: a resolver may still be serving a
# cached delegation, and the question here is "what does the zone say", not "has it
# propagated yet".
# dig wraps a 64-char hex into two lines, and the hex may come back upper case; normalise
# both or the comparison fails on formatting rather than on fact.
PINNED=$(dig +short +time=5 +tries=2 @memphis.ns.cloudflare.com TLSA _25._tcp.mail.slothlee.xyz 2>/dev/null \
         | awk '{for(i=4;i<=NF;i++) printf "%s", $i}' | tr 'A-Z' 'a-z' | sort -u | head -1)

if [ -z "$PINNED" ]; then
    echo "NO PIN: no TLSA record is published for $HOST"
    exit 2
fi

LIVE=$(openssl s_client -connect "$HOST:$PORT" -starttls smtp -showcerts </dev/null 2>/dev/null \
       | openssl x509 -pubkey -noout 2>/dev/null \
       | openssl pkey -pubin -outform DER 2>/dev/null \
       | openssl dgst -sha256 -r 2>/dev/null | cut -d' ' -f1)

if [ -z "$LIVE" ]; then
    echo "NO CERT: could not read the certificate from $HOST:$PORT"
    exit 3
fi

if printf '%s' "$PINNED" | grep -qi "$LIVE"; then
    echo "OK pin matches the served certificate (${LIVE:0:16}…)"
    exit 0
fi

echo "MISMATCH pin does not cover the served certificate"
echo "  served : $LIVE"
echo "  pinned : $PINNED"
exit 1
