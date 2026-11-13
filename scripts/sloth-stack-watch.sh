#!/usr/bin/env bash
# Is the Sloth Lee stack still standing?
#
# The mail watchdog covers mail, the homepage and the dashboard's DNS name. It says nothing
# about the bot: a container can be up and gateway-disconnected, a database can be running
# and refusing connections, and the only person who finds out is a server member.
#
# Silent when everything is right. Mails an alert and writes a log line when something breaks,
# because a check nobody reads is not a check.
#
# --test forces every check to fail so the alert path itself can be proven. It never touches
# a service: it lies to the script, not to the stack.
set -uo pipefail

LOG=/var/log/sloth-stack-watch.log
STATE=/var/lib/sloth-stack-watch.state
ALERT_TO=tibs@slothlee.xyz
ALERT=/usr/local/bin/mail-alert.sh
TEST=0
[ "${1:-}" = "--test" ] && TEST=1

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG"; }

problems=()

check() { # name, then the command that must succeed
  local name="$1"; shift
  if [ "$TEST" = 1 ]; then problems+=("$name (forced)"); return; fi
  if ! "$@" >/dev/null 2>&1; then problems+=("$name"); fi
}

# Container up and not crash-looping. RestartCount climbing means it is dying and coming back,
# which from the outside looks identical to "running".
container_ok() {
  local name="$1"
  local status restarts
  status=$(docker inspect "$name" --format '{{.State.Status}}|{{.RestartCount}}' 2>/dev/null) || return 1
  [ "${status%%|*}" = "running" ] || return 1
  restarts="${status##*|}"
  [ "${restarts:-0}" -lt 5 ]
}

bot_answers() {
  curl -fsS -m 8 http://127.0.0.1:3200/healthz 2>/dev/null | grep -q '"ok":true'
}

db_answers() {
  docker exec sloth-pg pg_isready -U sloth -q 2>/dev/null
}

db_has_data() {
  local n
  n=$(docker exec sloth-pg psql -U sloth -d sloth -tAc 'select count(*) from guild_settings' 2>/dev/null | tr -d '[:space:]')
  [ "${n:-0}" -ge 1 ]
}

# Name resolution is a dependency nothing else here names. When the host resolver
# died, every container looked broken at once and the cause was invisible: the
# bot crash-looped on `getaddrinfo EAI_AGAIN` while unbound itself answered fine.
# Checking it directly turns "the bot is down" into "DNS is down".
dns_resolves() { # hostname
  getent hosts "$1" 2>/dev/null | head -1 | grep -q .
}

host_answers() { # url, expected status
  local code
  code=$(curl -sS -m 12 -o /dev/null -w '%{http_code}' -A 'sloth-watch/1.0' "$1" 2>/dev/null)
  [ "$code" = "$2" ]
}

# DNS is the failure that makes every other check lie. Twice now the host resolver
# has degraded against unbound (DO, then EDNS0, then UDP, then TCP — the journal
# says so) and returned SERVFAIL for everything: containers healthy, bot in a
# restart loop, mail unable to resolve a single MX. Restarting systemd-resolved
# restores it, so do that once here rather than mailing a symptom nobody can act
# on from a phone. Only ever runs when resolution is already broken, so it cannot
# turn a healthy resolver into a broken one.
if [ "$TEST" = 0 ] && ! dns_resolves discord.com; then
  # Point the link at this box own resolver first: when eth0 carries a plain
  # upstream, resolved answers SERVFAIL for signed zones (2026-10-31, twice) and
  # a bare restart only works until the next bad answer. Then restart, which is
  # what clears the cached validation failure.
  if resolvectl status 2>/dev/null | grep -q "Current DNS Server: 127.0.0.1"      && resolvectl query discord.com >/dev/null 2>&1; then
    log "DNS failing but resolved already uses 127.0.0.1; leaving the link alone"
  else
    resolvectl dns eth0 127.0.0.1 >/dev/null 2>&1 || true
    log "link DNS pointed at 127.0.0.1"
  fi
  log "DNS resolution failed; restarting systemd-resolved once"
  systemctl restart systemd-resolved
  sleep 3
  if dns_resolves discord.com; then
    log "DNS recovered after restarting systemd-resolved"
  else
    log "DNS still failing after the restart"
  fi
fi

check "host can resolve DNS"      dns_resolves discord.com
check "bot container"            container_ok sloth-bot
check "postgres container"       container_ok sloth-pg
check "database accepts queries" db_answers
check "database still has guilds" db_has_data
check "bot health endpoint"      bot_answers
check "dashboard login door"     host_answers "https://app.slothlee.xyz/login" 200
check "owner console"            host_answers "https://owner.slothlee.xyz/" 200
check "homepage"                 host_answers "https://slothlee.xyz/" 200

if [ "${#problems[@]}" -eq 0 ]; then
  # Only speak when the state changes, or an alert every ten minutes becomes noise and
  # noise becomes ignored.
  if [ -f "$STATE" ]; then
    log "recovered: all checks passing again"
    rm -f "$STATE"
  fi
  exit 0
fi

summary=$(printf '%s; ' "${problems[@]}")
summary=${summary%; }

if [ -f "$STATE" ] && [ "$(cat "$STATE")" = "$summary" ]; then
  log "still failing (no repeat alert): $summary"
  exit 1
fi

printf '%s\n' "$summary" >"$STATE"
log "ALERT: $summary"

if [ -x "$ALERT" ]; then
  printf '%s\n\nHost: %s\nTime: %s\n' "$summary" "$(hostname)" "$(date -u +%FT%TZ)" \
    | "$ALERT" "[Sloth Lee] stack check failed" 2>/dev/null \
    || log "alert script failed to send"
else
  log "alert script missing at $ALERT"
fi

exit 1
