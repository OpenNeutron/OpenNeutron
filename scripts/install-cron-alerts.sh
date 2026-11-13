#!/usr/bin/env bash
# Install alerting on every scheduled job that matters.
#
# Rewrites the crontab in place: keeps any line it does not recognise, and only
# touches the four jobs listed below. Every one of them ends in `|| … | mail-alert.sh`
# so a failure produces a mail instead of a line in a log.
set -euo pipefail

ALERT=/usr/local/bin/mail-alert.sh
[ -x "$ALERT" ] || { echo "missing $ALERT" >&2; exit 1; }

crontab -l 2>/dev/null | grep -v -E 'mail-offsite-backup.sh|mail-restore-drill.sh|mail-geoip-update.sh|mail-dns-watch.sh' > /tmp/cron.new || true

cat >> /tmp/cron.new <<'CRON'
# Nightly encrypted backup to a different provider. Silence here is the whole point of
# the job, so the only time this speaks is when it fails.
10 4 * * * /usr/local/bin/mail-offsite-backup.sh >>/var/log/mail-offsite.log 2>&1 || tail -25 /var/log/mail-offsite.log | /usr/local/bin/mail-alert.sh "Mail off-site backup FAILED"
# Monthly restore drill: downloads the archive, boots a second server from it.
0 6 1 * * /usr/local/bin/mail-restore-drill.sh >>/var/log/mail-restore-drill.log 2>&1 || tail -25 /var/log/mail-restore-drill.log | /usr/local/bin/mail-alert.sh "Restore drill FAILED — the backup may not come back"
# Monthly GeoIP refresh: without it, signed-in-device countries go stale, not blank.
17 4 3 * * /usr/local/bin/mail-geoip-update.sh >/var/log/mail-geoip.log 2>&1 || tail -10 /var/log/mail-geoip.log | /usr/local/bin/mail-alert.sh "GeoIP update FAILED"
# Domain records, every half hour. This script mails on its own when something drifts.
*/30 * * * * /usr/local/bin/mail-dns-watch.sh >/var/log/mail-dns-watch.log 2>&1
# Outbound DANE, weekly: validation, TLSA lookup and STARTTLS all still hold.
23 5 * * 1 /usr/local/bin/mail-dane-outbound-check.sh >/var/log/mail-dane-outbound.log 2>&1 || tail -10 /var/log/mail-dane-outbound.log | /usr/local/bin/mail-alert.sh "DANE (outbound) check FAILED"
CRON

crontab /tmp/cron.new
echo "installed:"
crontab -l | grep -vE '^#' | grep -v '^$'
