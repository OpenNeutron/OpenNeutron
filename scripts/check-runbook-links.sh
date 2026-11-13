#!/usr/bin/env bash
# N4.4 — every alert names the page that answers it, in both directions.
#
# 1. Every kind the watchdog can send has a page in OPERATIONS.md with exactly that heading.
# 2. Every `### Alert:` page in OPERATIONS.md is reachable from at least one kind — an orphan page
#    is a page nobody will ever be sent to.
#
# Run from a checkout that has both the bot repo (for the script) and OPERATIONS.md beside this file:
#   ops/repo/scripts/check-runbook-links.sh /opt/data/workspace/sloth-lee/ops/sloth-health-watch.py
set -euo pipefail

SCRIPT="${1:-/opt/data/workspace/sloth-lee/ops/sloth-health-watch.py}"
DOC="$(dirname "$0")/../../OPERATIONS.md"
[ -f "$DOC" ] || DOC="$(pwd)/OPERATIONS.md"

fail=0

# The kinds and their pages, read out of the script itself so the two cannot drift.
python3 - "$SCRIPT" <<'PY' > /tmp/runbook-kinds.txt
import importlib.util, sys
spec = importlib.util.spec_from_file_location("w", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
for kind, page in m.RUNBOOK.items():
    print(f"{kind}\t{page['page']}")
PY

while IFS=$'\t' read -r kind page; do
  if ! grep -qxF "### $page" "$DOC"; then
    echo "MISSING PAGE: kind '$kind' names '$page', which OPERATIONS.md does not contain"
    fail=1
  else
    echo "ok: $kind → $page"
  fi
done < /tmp/runbook-kinds.txt

# Every alert page must be reachable.
while IFS= read -r heading; do
  page="${heading#\#\#\# }"
  case "$page" in
    Alert:*|Alerting:*)
      if ! cut -f2 /tmp/runbook-kinds.txt | grep -qxF "$page"; then
        echo "ORPHAN PAGE: '$page' is in OPERATIONS.md, but no alert kind sends anyone to it"
        fail=1
      fi
      ;;
  esac
done < <(grep '^### ' "$DOC")

rm -f /tmp/runbook-kinds.txt
exit "$fail"
