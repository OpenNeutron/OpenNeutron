# What protects the five hostnames (audited 2 November 2026)

Measured, not assumed. Every number here came from a request made against production.

## The chain that exists

Two hosts sit behind Cloudflare:

| Host | Proxied | Who terminates |
| --- | --- | --- |
| `slothlee.xyz`, `www` | yes | Cloudflare → nginx → `sloth-site` |
| `app.slothlee.xyz` | yes | Cloudflare → nginx → `sloth-bot` |
| `mail.slothlee.xyz` | **no** | nginx → `openneutron` |
| `owner.slothlee.xyz` | **no** | nginx → `owner-console` |

`mail` and `owner` are DNS-only on purpose (MX, MTA-STS, WKD and DANE want the
origin address), so **everything a stranger can reach on them is answered by nginx
and nothing else**.

At the edge, the free plan already does two things worth having: known scanner
user agents are refused (`curl -A sqlmap/1.7 https://app.slothlee.xyz/app` →
`403 error code: 1010` from Cloudflare), and the proxied hosts are DDoS-protected
by default.

Below the edge, nginx throttles the endpoints that cost something:

| Zone | Rate | Where |
| --- | --- | --- |
| `login` | 10 r/m, burst 5 | `mail` `/api/auth/login`, 2FA, webauthn |
| `account_recovery` | 10 r/m, burst 5 | password reset, recovery key |
| `register` | 5 r/m, burst 5 | signup |
| `waitlist` | 3 r/m, burst 3 | waitlist |
| `appeal` | 10 r/m, burst 5 | `app` `/appeal/submit` (the only 30 MB body) |
| `owner_login` | 5 r/m, burst 2 | `owner` `/unlock` (scrypt per attempt) |

Every one of those answers `429`, and fail2ban's `nginx-limit-req` jail
(`maxretry 3`, `findtime 600`, `bantime 3600`) turns three of those into a firewall
ban — on every port for that address. Verified end to end: a burst of wrong
passwords from one address produced `401 401 401 429 429 …`, then
`fail2ban-client status nginx-limit-req` showed the address banned until +3601 s,
then the unban restored `200`s everywhere.

## The bug the audit found: no real-IP handling on the proxied hosts

`$binary_remote_addr` on `app.slothlee.xyz` was **Cloudflare's edge address**, not
the visitor's. Any per-IP limit there would have been one bucket shared by every
visitor at once — a limit that fires on a busy minute instead of on an attacker —
and the access log could not have told you two clients apart.

Fixed with `/etc/nginx/conf.d/cloudflare-realip.conf`: `real_ip_header
CF-Connecting-IP` trusted **only** from Cloudflare's published ranges (15 IPv4,
7 IPv6), `real_ip_recursive on`. A stranger sending the header is ignored because
the connection did not come from an edge. Proved: the access log for a request
through Cloudflare now records `159.195.130.94` (the client) where it previously
recorded `162.158.202.90` (an edge).

## Two endpoints that had no throttle at all, now added

- **`app` `/appeal/submit`** — unauthenticated apart from a member cookie, accepts
  a **30 MB** body, and writes rows. It had no limit of any kind. `burst=5`
  deliberately: a person retrying a failed upload is not abuse, and only a script
  reaches the 429 that fail2ban turns into a ban.
- **`owner` `/unlock`** — every attempt runs **scrypt**, so an unthrottled
  endpoint is a CPU amplifier. The code is 12 characters (~72 bits) and not
  guessable; the hashing should still not be free.

## What is still missing, and why it is not fixed here

- **No Cloudflare WAF custom rules, no Bot Fight Mode setting, no Turnstile.**
  All three need a Cloudflare credential. The stored OAuth token from the `cf` CLI
  **expired 2026-10-31T16:38Z**, `/etc/cloudflare/dane.token` does not exist, and
  the account has no API token on this host. Unblocking needs one of: an API token
  with `Zone:WAF Edit`, `Zone Settings Edit`, `Zone:Bot Management Edit`, or an
  interactive `cf` re-auth.
- **`mail` and `owner` have no edge at all** by construction; nginx + fail2ban is the
  network shield there. That is per address, so it says nothing about a distributed
  attempt on one mailbox — but the mail server covers that case itself, which makes the
  gap narrower than it first looked:

  | Key | Budget | Window | What it stops |
  | --- | --- | --- | --- |
  | `user:<name>` | 10 failures | 15 min | grinding **one** mailbox from anywhere |
  | `ip:<addr>` | 100 failures | 15 min | one host spraying many mailboxes |

  A success clears the key. The table prunes expired entries and is capped, so it is not
  itself a memory-exhaustion vector. **What it is not**: persistent — a restart forgets
  the counters, and the lockout is a 15-minute pause, not a lock. Turnstile on
  `/api/auth/login` would still be the better first line, and it is the one thing here
  that needs the dashboard.
- **HSTS: four hosts were saying four different things, and one said nothing.** As
  found: `app` sent `preload`, `mail` and the apex did not, and **`owner` sent no HSTS
  header at all**. The apex's header was not even its own — it came from Cloudflare,
  which was overwriting the origin's. Now fixed at origin: the shared snippet carries
  `preload`, `owner` gained HSTS for the first time, and every host that answered port
  80 with a **404** now answers with **301 → https** while keeping the ACME challenge
  path reachable so renewals still work. Verified: `http://` on all four hosts → `301`,
  `https://` on `app`, `owner`, `mail` → `max-age=31536000; includeSubDomains; preload`.

  **The one thing still untrue is the apex.** Its origin now sends `preload`, but
  Cloudflare *replaces* the header on the way out (`curl --resolve` direct to origin
  shows `preload`; through the edge it is gone), so `slothlee.xyz` cannot be submitted
  to the preload list until the zone's HSTS setting has preload enabled. That is one
  toggle on the dashboard, or one API call.

## Transport: the HTTPS leg was post-quantum, the mail leg was not (fixed 2 November 2026)

Measured with `openssl s_client` and `posttls-finger` before changing anything:

- `mail.slothlee.xyz:443` negotiated **X25519MLKEM768** — already hybrid, courtesy of OpenSSL 3.5.
- `mail.slothlee.xyz:25` offered only the hybrid group → **handshake failure, alert 40**.
- Outbound to `gmail-smtp-in.l.google.com:25` → `key-exchange **x25519**`, classical.

Cause: Postfix ships `tls_eecdh_auto_curves = X25519 X448 prime256v1 secp384r1 secp521r1`, which
contains no ML-KEM group, so the server offered hybrid to nobody and declined it from everyone.

Fixed by putting the hybrid group first:

```
tls_eecdh_auto_curves = X25519MLKEM768 X25519 X448 prime256v1 secp384r1 secp521r1
```

Verified after the reload, from both directions:

- inbound `:25`, offering only the hybrid group → `Negotiated TLS1.3 group: X25519MLKEM768`
- inbound `:25`, classical group → still `TLS1.3 / TLS_AES_256_GCM_SHA384`
- outbound to Google with no overrides → `key-exchange X25519MLKEM768`
- a real message sent after the change: `mailq` empty, delivered, newest inbox entry present

Classical clients are unaffected: the group list is a preference order, and the old groups are
still offered. DANE pinning is untouched — it pins the certificate, not the key exchange.

**This is the leg that matters most for harvest-now-decrypt-later.** OpenPGP only protects mail
where both ends opted in; a hybrid key exchange protects every message the server relays, including
the overwhelming majority that never uses message-layer encryption at all.

**Also fixed here:** `/etc/aliases` did not exist while `alias_maps = hash:/etc/aliases`, so every
`smtpd` logged `error: open database /etc/aliases.db: No such file or directory` (first seen
1 November, so it predated this work). A minimal aliases file plus `newaliases` silenced it.

## Disk: 95% full, and nothing was watching (fixed 2 November 2026)

The host reached **68 GB of 75 GB used, 3.8 GB free**, and no alert fired — the watchdog watched
the bot, not the disk it lives on.

**The cause was not mail data.** `/opt/on/data` was 27 MB and `/opt/on/target` 2.3 GB, while
`/var/lib/containerd` held **59 GB**: every `docker build` leaves the previous image untagged, and 73
of them had accumulated. `docker system df` reported only 646 MB as reclaimable, which is why this
looked like something else for long enough for the disk to fill.

**What was done**

- `docker image prune -f` (dangling only — nothing a container uses): **17.24 GB reclaimed**,
  containerd 59 GB → 8 GB, disk 95% → 25%.
- `/usr/local/bin/sloth-disk-guard.sh`, cron `40 4 * * *`: prunes dangling images older than a day,
  build cache older than a week, stopped containers older than a day; alerts by mail above 85%.
- The watchdog now checks the disk **first**, before the bot, because a full disk explains every
  other symptom. Dedupe is the existing one-per-kind-per-hour.
- Both thresholds are overridable (`DISK_THRESHOLD`, `SLOTH_DISK_THRESHOLD`) so the alert path can be
  proved by lowering one instead of filling a disk. Proved: guard `alert sent: [Sloth Lee] disk at
  23% (56 GB free)`; watchdog `ALERT disk: disk at 26%`, mail rc=0, **DM delivered**
  (`message_id=1566695709363798127`).
- `/etc/docker/daemon.json` now caps container logs at 20 MB × 3 (`dockerd --validate` clean, docker
  restarted, all five containers back `unless-stopped`). **Applies to containers created from now
  on**, not the running ones.

**Numbers after:** 17 GB used, **56 GB free**, containerd 6.7 GB, mail/app/owner all answering, queue
empty, and a real message sent through the browser afterwards to prove the stack, not just the ports.

**Left alone deliberately:** `/opt/on/target` (2.3 GB) is what makes a mail rebuild 26 seconds instead
of ten minutes. Pruning it to save 2.3 GB would cost far more than it saves.

## The backup was quietly missing two sidecars (fixed 2 November 2026)

`mail-offsite-backup.sh` carried a hand-written list of `data/*.json`. Two had drifted out of it:
`sendcount.json` (per-sender rate counters) and `signup_ips.json` (signup abuse tracking). A restore
would have quietly reset both — an abuser's quota would come back clean, and a restore is exactly the
moment nobody is looking at rate limits.

**The fix is structural, not a longer list:** the script now builds its member list from
`ls data/*.json` at run time, logs how many it took, and after round-tripping the archive it checks
**every** sidecar on disk is a member — refusing to upload if one is missing.

Proved by re-injecting the bug: a test copy excluding one sidecar exited `rc=1` with
`ERROR archive is missing sidecars: data/zz-gate-test.json` and uploaded nothing.

A fresh archive followed: **22 sidecars, 29,437,706 bytes**, uploaded, and the restore drill passes
against it — 944 members, `Loaded 14 users`, DKIM key recovered, restored copy answers its API.

**Trap found while proving the gate:** GNU tar applies `--exclude` positionally — placed after the
file arguments it prints *"--exclude has no effect"* and keeps the file. The first injection test
therefore did nothing and "passed". Exclusions belong before the first member argument.

## Key transparency: a bigger tree is not proof of anything (2 November 2026)

A pinned head caught a log that shrank or changed at the same size. It could not catch the
interesting attack: rewrite an old key, grow past it, and every client sees a bigger tree that looks
exactly like normal operation.

**Added** `POST /api/kt/consistency` and RFC 6962 consistency proofs over the key log. The send path
now asks, on every send where this browser has a pinned head, whether the current tree still contains
the one it pinned — and refuses when the answer does not check out.

Two things worth recording:

- **The RFC defines the proof, not the check.** The parity walk that looks obvious from §2.1.2 rejects
  valid proofs at odd sizes and for every power-of-two prefix. The verifier here is a port of the
  reference implementation (`transparency-dev/merkle`, `proof/verify.go`), validated against the three
  worked proofs in §2.1.3 and then over **every size pair 1..24** in Rust and against live proofs in
  JavaScript.
- **The endpoint returns its own `first_root` for diagnostics.** A client must verify against the root
  it pinned; a root the server hands over now proves nothing.

**Proved live**, in a real browser with a planted pin at size 3:

- honest root → proof fetched and verified → the message **was delivered** (`10:29:32Z`).
- same size, one byte changed → refused: *"The key directory could not show that it still contains the
  history this browser saw (proof_does_not_fit). Nothing was sent."* — and **no delivery** appeared in
  the log.

131 Rust tests (was 128), 203 web tests, sw `v86`, bundle stamped `346fc69`, mail commit `6745ccd`.

## Monitoring the app itself, not just its sockets (2 November 2026)

Containers running, `/healthz` green, mail flowing, ports answering 200 — and the app can still serve
a blank screen, because none of those checks render it. That is exactly the failure that once took
the signed-in screens down for six minutes and was caught by a person rather than a monitor.

`sloth-app-probe` (Hermes cron, every 30 minutes, `no_agent`, quiet on success) loads `/login`,
requires a real form, signs in as a QA account, requires the mailbox shell to render with **no page
errors**, then signs out. On failure it mails with a runbook path and one first command; every run
writes one line to `/opt/data/logs/sloth-app-probe.log`.

Proved both directions: silent success, and a forced wrong password producing
`APP PROBE FAILED: sign-in did not reach the mailbox` plus a delivered alert at 10:51:37Z.

**Caveat, stated plainly:** the probe runs on the Hermes host, so if *that* host dies the probe stops
silently. Its absence is not itself monitored; the on-box stack watch and the mail watchdog still run
on the mail server.

## Sessions expire

`data/sessions.json` used to grow forever: nothing removed a record except the owner signing
out, so 452 sessions had accumulated and a cookie copied off a phone stayed valid for as long
as the account avoided signing out. Two limits now apply (`src/core/sessions.rs`):

- **absolute**: 30 days from `created_at`, regardless of use;
- **idle**: 14 days since `last_seen_at`.

Both are checked in `validate()` — an aged session is refused *and* its record dropped — and the
registry is swept by the same minute-ticker that clears ephemeral notes and held mail, so the
file shrinks without waiting for the account to return.

**Proved in production, not just in tests:** three records were planted (40 days old, 20 days
idle, and a fresh control), the message was restarted, and the log read
`sessions: dropped 2 aged-out session(s)`, with the two stale records gone, the control intact,
and the count falling 455 → 453. A real sign-in afterwards still rendered the mailbox
(app probe, 01:29:36Z). Five unit tests cover the boundaries — a session one second inside each
limit is still allowed.

**Known limit:** a record with no timestamps (`created_at == 0`, written before those fields
existed) is treated as aged out rather than immortal. In practice the sweep reaches a session
before a request does, so the `validate()` refusal is the backstop rather than the everyday path.

## The probe is monitored from outside itself

The app probe is the only check that renders the app like a person, and it runs on the Hermes
host on a 30-minute cron — which means its own death is silent. "The probe has not run for six
hours" and "the probe ran and everything was fine" look identical from the mail host, and a
probe that dies takes its only witness with it.

So the probe now stamps `/opt/sloth-bot/status/app-probe.heartbeat` on the mail host after
every run (`<epoch> <exit code>`), on failure as well as success — the heartbeat answers *did
it run*, not *was the app well*; a failed run has its own alert. The mail host's watchdog reads
it and mails when it is older than **90 minutes** (three missed runs,
`SLOTH_PROBE_STALE_MINUTES` to override), with a runbook page and one first command that runs
on the host: `cat /opt/sloth-bot/status/app-probe.heartbeat; date -u +%s`.

**Both branches proved by lowering the threshold, not by breaking the probe:**

- stale — `SLOTH_PROBE_STALE_MINUTES=0` → `ALERT app-probe: the app probe has been silent for
  0 minutes`, mail `rc=0`, DM `message_id=1566988175895699517`;
- never reported — heartbeat moved aside → `ALERT app-probe: the app probe has never reported`,
  mail `rc=0`, DM `message_id=1566988248826249218`.

With the real threshold and a fresh heartbeat the watchdog stays quiet, which is the third
thing worth checking: an alert that fires when it should not trains people to ignore it.

The alerting scripts now live in this repository (`scripts/sloth-health-watch.py`,
`scripts/sloth-disk-guard.sh`) as well as in `/usr/local/bin`, because logic that only exists on
one machine cannot be reviewed or restored.

