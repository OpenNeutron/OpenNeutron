#!/usr/bin/env bash
# Daily disk guard.
#
# The box sat at 95% (3.8 GB free) with nothing watching. The cause was not mail data:
# every `docker build` leaves the previous image untagged, and 73 of them had accumulated
# in containerd's snapshotter — 59 GB of layers nobody referenced. `docker system df`
# under-reports this badly (it said 646 MB reclaimable), so the number to trust is
# `du /var/lib/containerd` and `df`.
#
# Runs after the nightly backup. Prunes only what nothing uses:
#   * dangling images older than a day (today's rebuild stays available)
#   * build cache older than a week
#   * stopped containers older than a day
#
# Never touches tagged images, running containers, volumes or anything under /opt.
# Screams by mail when the disk is still tight after pruning.
set -euo pipefail

LOG=/var/log/sloth-disk-guard.log
ALERT=/usr/local/bin/mail-alert.sh
THRESHOLD=${DISK_THRESHOLD:-85}

avail_gb() { df --output=avail -BG / | tail -1 | tr -dc '0-9'; }
used_pct() { df --output=pcent / | tail -1 | tr -dc '0-9'; }

before=$(avail_gb)

{
  echo "--- $(date -u +%FT%TZ)"
  docker image prune -f --filter "until=24h" 2>&1
  docker builder prune -f --filter "until=168h" 2>&1
  docker container prune -f --filter "until=24h" 2>&1
} >>"$LOG" 2>&1

after=$(avail_gb)
pct=$(used_pct)
containerd=$(du -sh /var/lib/containerd 2>/dev/null | cut -f1)

echo "$(date -u +%FT%TZ) avail ${before}G -> ${after}G, usage ${pct}%, containerd ${containerd}" >>"$LOG"

if [ "$pct" -ge "$THRESHOLD" ]; then
  printf 'Disk on the mail host is at %s%% with %s GB free after pruning.\n\ncontainerd: %s\n\nLargest trees:\n' \
    "$pct" "$after" "$containerd" \
  | "$ALERT" "[Sloth Lee] disk at ${pct}% (${after} GB free)"
fi
