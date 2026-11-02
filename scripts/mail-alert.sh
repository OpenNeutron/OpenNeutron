#!/usr/bin/env bash
# Send one alert mail. Body on stdin, subject as the argument.
#
# Written because scheduled jobs that fail quietly are worse than jobs that do not
# run: a backup that stopped in August looks identical to one that ran last night
# until the day it is needed. Every cron line that matters ends in
# `|| <job output> | mail-alert.sh "subject"`.
#
# Deliberately uses /usr/sbin/sendmail — there is no `mail` binary on this host, and
# an alert path that silently fails is not an alert path.
set -uo pipefail

SUBJECT="${1:-alert from $(hostname)}"
BODY="$(cat)"
# Headers must be US-ASCII, or the MTA refuses the message outright:
#   5.6.7 SMTPUTF8 is required, but was not offered by host 127.0.0.1
# A subject as ordinary as "Test alert — this is what a real one looks like" bounced exactly like
# that on 2 November, so the subject is encoded per RFC 2047 and the body declares its charset.
SUBJECT_ENCODED="$(printf '%s' "$SUBJECT" | python3 -c '
import sys
subject = sys.stdin.read()
try:
    subject.encode("ascii")
    sys.stdout.write(subject)
except UnicodeEncodeError:
    from email.header import Header
    sys.stdout.write(Header(subject, "utf-8").encode())
')"

{
    printf 'Subject: %s\n' "$SUBJECT_ENCODED"
    printf 'From: root@slothlee.xyz\n'
    printf 'To: tibs@slothlee.xyz\n'
    printf 'Date: %s\n' "$(date -R)"
    printf 'MIME-Version: 1.0\n'
    printf 'Content-Type: text/plain; charset=utf-8\n'
    printf 'Content-Transfer-Encoding: 8bit\n'
    printf '\n'
    printf 'Host: %s\n\n' "$(hostname)"
    printf '%s\n' "${BODY:-(no output captured)}"
} | /usr/sbin/sendmail -t
rc=$?
[ "$rc" -eq 0 ] && echo "alert sent: $SUBJECT" || echo "ALERT COULD NOT BE SENT: $SUBJECT (sendmail rc=$rc)" >&2
exit "$rc"
