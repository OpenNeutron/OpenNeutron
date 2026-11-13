#!/usr/bin/env bash
# Does slothlee.xyz still say what we told it to say?
#
# A domain does not stay secured. Records can be edited by a tired click, a renewal can
# leave a stale pin, a DS can vanish on a plan change. This asks the authoritative
# nameservers directly (not a cache) so an answer is about the zone, not about timing.
#
# Silent when everything is right. Mails tibs@slothlee.xyz and writes a log line when
# something has drifted, because a check nobody reads is not a check.
set -uo pipefail

NS=memphis.ns.cloudflare.com
STATE=/var/lib/mail-dns-watch.state
LOG=/var/log/mail-dns-watch.log
ALERT_TO=tibs@slothlee.xyz

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG"; }

q() { dig +short +time=5 +tries=2 @"$NS" "$1" "$2" 2>/dev/null | sort; }

problems=()

check() { # name expected actual
    local name=$1 expected=$2 actual=$3
    if [ "$expected" != "$actual" ]; then
        problems+=("$name changed: expected [$expected] got [$actual]")
    fi
}

# --- the things that must not move ---
check "nameservers" "memphis.ns.cloudflare.com.
tori.ns.cloudflare.com." "$(q slothlee.xyz NS | sed 's/\.$//;s/$/./' | sort -u)"

# The apex is proxied through Cloudflare, so its A record is an edge address that
# changes by design. Check that it resolves, and that the origin behind it still
# answers when asked directly.
apex_ips="$(q slothlee.xyz A | tr '\n' ' ' | sed 's/ $//')"
[ -n "$apex_ips" ] || problems+=("apex does not resolve at all")
# Ask the origin that actually serves the site, over loopback. The previous version pinned
# 34.147.215.88, which is neither our box nor a current Cloudflare edge address (the apex resolves to
# 104.21.20.244 / 172.67.194.227): it is a stray host that answers 503, so this check reported drift on
# every run. A monitor pointed at the wrong machine is worse than no monitor.
origin_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
    -H "Host: slothlee.xyz" http://127.0.0.1:3100/ 2>/dev/null || echo 000)
# A deploy restarts the site container, so a single 503 is not drift — it is a rebuild. Retry before
# calling it a problem, or the watchdog reports every release as an outage.
if [ "$origin_code" != "200" ]; then
  for _ in 1 2 3; do
    sleep 5
    origin_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
      -H "Host: slothlee.xyz" http://127.0.0.1:3100/ 2>/dev/null || echo 000)
    [ "$origin_code" = "200" ] && break
  done
fi
[ "$origin_code" = "200" ] || problems+=("origin http://127.0.0.1:3100/ (Host: slothlee.xyz) answered $origin_code, not 200 — checked because apex A is $apex_ips")
check "mail A" "46.62.155.175" "$(q mail.slothlee.xyz A)"
check "mail AAAA" "2a01:4f9:c013:dab1::1" "$(q mail.slothlee.xyz AAAA)"
check "MX" "10 mail.slothlee.xyz." "$(q slothlee.xyz MX)"
check "MTA-STS id" '"v=STSv1; id=2026102701"' "$(q _mta-sts.slothlee.xyz TXT)"
check "TLS-RPT" '"v=TLSRPTv1; rua=mailto:tibs@slothlee.xyz"' "$(q _smtp._tls.slothlee.xyz TXT)"
check "SPF" '"v=spf1 mx -all"' "$(q slothlee.xyz TXT | grep spf1)"

# DMARC must stay at p=reject with strict alignment — a silent downgrade is the exact
# attack this guards against.
if ! q _dmarc.slothlee.xyz TXT | grep -q 'p=reject'; then
    problems+=("DMARC is no longer p=reject: $(q _dmarc.slothlee.xyz TXT)")
fi

# DNSSEC: the zone must be signed and the DS published at the registry must match the KSK.
if ! dig +dnssec +short @"$NS" slothlee.xyz DNSKEY 2>/dev/null | grep -q .; then
    problems+=("zone is no longer signed (no DNSKEY from $NS)")
fi
# The DS lives in the parent zone, so it is asked of the .xyz registry servers directly.
XYZ_NS=$(dig +short NS xyz. @1.1.1.1 2>/dev/null | head -2 | sed 's/\.$//')
PUBLISHED_DS=""
for parent in $XYZ_NS; do
    PUBLISHED_DS=$(dig +short DS slothlee.xyz @"$parent" 2>/dev/null | awk '{print $4}' | head -1)
    [ -n "$PUBLISHED_DS" ] && break
done
if [ -z "$PUBLISHED_DS" ]; then
    # The registry's database and the registry's served zone are updated separately: after
    # an NS or DS change, WHOIS/RDAP can say "signed" for a while before the parent zone
    # actually publishes it. That is a transition, not a fault, so say so instead of
    # mailing an alarm that will clear itself.
    if command -v whois >/dev/null && whois slothlee.xyz 2>/dev/null | grep -qi "signedDelegation"; then
        log "pending: registry database says signed, parent zone has not published the DS yet"
    else
        problems+=("no DS record at the registry — DNSSEC is not delegated")
    fi
fi

# DANE: the published pin must cover the certificate that is actually served.
if ! /usr/local/bin/mail-dane-check.sh >/tmp/dane.$$ 2>&1; then
    problems+=("$(cat /tmp/dane.$$ | tr '\n' ' ')")
fi
rm -f /tmp/dane.$$

# --- Web Key Directory ---
# openpgpkey.<domain> is its own hostname. It was once missing from DNS, which made every
# client's key lookup fail with a bare network error and looked like a crypto bug.
wkd_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
    https://openpgpkey.slothlee.xyz/health 2>/dev/null || echo 000)
[ "$wkd_code" = "200" ] || problems+=("Web Key Directory host answered $wkd_code, not 200 - clients cannot fetch keys")

# --- this host must be able to resolve names at all ---
# The systemd-resolved stub failed silently once: unbound answered correctly, every
# getaddrinfo() on the box did not, and nothing here noticed because every other leg
# speaks DNS directly instead of using the OS.
for name in mail.slothlee.xyz app.slothlee.xyz; do
    getent hosts "$name" >/dev/null 2>&1 || problems+=("this host cannot resolve $name")
done

# --- the bot site answer ---
code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 15 https://app.slothlee.xyz/ 2>/dev/null || echo 000)
# / redirects to /app by design; a 302 here is the correct answer, not a fault.
case "$code" in 200|302) ;; *) problems+=("https://app.slothlee.xyz/ answered $code (expected 200 or the 302 to /app)") ;; esac

# --- report ---
if [ ${#problems[@]} -eq 0 ]; then
    log "ok"
    rm -f "$STATE"
    exit 0
fi

printf '%s\n' "${problems[@]}" >"$STATE"
log "ALERT ${#problems[@]} problem(s)"
{
    echo "Subject: [slothlee.xyz] DNS or DANE has drifted"
    echo "From: dns-watch@slothlee.xyz"
    echo "To: $ALERT_TO"
    echo
    echo "Checked $(date -u +%FT%TZ) against $NS"
    echo
    printf '  - %s\n' "${problems[@]}"
    echo
    echo "Nothing has been changed automatically. Log: $LOG"
} | sendmail -t
exit 1
