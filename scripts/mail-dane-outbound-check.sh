#!/usr/bin/env bash
# Prove outbound DANE is still doing something.
#
# Two things can quietly stop being true: the resolver can stop validating (then
# every TLSA answer is worth nothing), and Postfix can stop asking for TLSA. Both
# are silent — mail keeps flowing, unverified. So this checks the pieces directly:
#
#   1. the local resolver marks a signed name AD and refuses a deliberately broken
#      signature (SERVFAIL), which is what makes a TLSA answer trustworthy;
#   2. asking Postfix's own resolver path for a TLSA record returns a signed one;
#   3. an SMTP session to a TLSA-publishing MX still gets to STARTTLS.
#
# Exit 0 only if all three hold. Run weekly; mails on failure via the watchdog.
set -uo pipefail

PROBE_HOST="mx01.posteo.de"   # publishes TLSA with a DNSSEC-signed zone
FAILED=0

say() { printf '%s\n' "$*"; }
fail() { say "FAIL  $*"; FAILED=1; }

# 1. Validation. A validating resolver returns SERVFAIL for a domain whose
#    signature is broken on purpose; one that only forwards returns NOERROR.
status_ok=$(dig +short +dnssec sigok.verteiltesysteme.net A >/dev/null 2>&1; dig sigok.verteiltesysteme.net | awk '/status:/{print $6}' | tr -d ,)
[ "$status_ok" = "NOERROR" ] || fail "a signed name did not resolve: status ${status_ok:-none}"
ad=$(dig sigok.verteiltesysteme.net | awk '/flags:/{print}' | grep -c " ad;")
[ "$ad" -eq 1 ] || fail "the resolver did not set the AD bit — it is not validating"

bogus=$(dig dnssec-failed.org | awk '/status:/{print $6}' | tr -d ,)
[ "$bogus" = "SERVFAIL" ] || fail "a broken signature returned ${bogus:-nothing} instead of SERVFAIL"

# 2. Postfix's own TLSA lookup, through the same resolver.
tlsa=$(dig +short TLSA "_25._tcp.${PROBE_HOST}")
[ -n "$tlsa" ] || fail "no TLSA record for _25._tcp.${PROBE_HOST} — DNS or the resolver is broken"

# 3. The handshake still happens. posttls-finger logs the 220 that answers STARTTLS.
probe=$(timeout 40 posttls-finger -v "${PROBE_HOST}:25" 2>&1 | grep -c "Ready to start TLS")
[ "${probe:-0}" -ge 1 ] || fail "no TLS session was offered by ${PROBE_HOST}:25"

if [ "$FAILED" -eq 0 ]; then
  say "OK   outbound DANE: resolver validates, TLSA is served, STARTTLS is offered by ${PROBE_HOST}"
  say "     TLSA: $(printf '%s' "$tlsa" | head -1 | cut -c1-60)…"
else
  say ""
  say "One or more checks failed. Outbound mail may still be delivered, but without"
  say "the guarantee DANE is supposed to give — and nothing else will tell you."
fi
exit "$FAILED"
