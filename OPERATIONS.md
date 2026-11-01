# Sloth Lee Mail — operations

Everything here was run on the live server (`mail.slothlee.xyz`, 46.62.155.175, Hetzner
CPX22, Ubuntu). Anything that stops being true should be corrected the moment it is
noticed: a runbook that describes a machine you do not have is worse than no runbook,
because it is trusted at 3am.

No secrets in this file. Passwords, tokens and keys live on the server, at 0600, in the
paths named below.

## What is running

| Piece | Where it runs | What it does | Check |
|---|---|---|---|
| `openneutron` container | Docker | Mailbox store, HTTP API **:8080**, SMTP **:2525** | `docker ps` |
| Postfix | host, **:25** (public MX) | Receives mail, TLS, rspamd milter, recipient map | `systemctl status postfix` |
| rspamd + redis | **host** (not containers) | Spam scoring, greylisting, ratelimits | `systemctl status rspamd redis-server` |
| nginx | host, **:443** | Web client, `mta-sts` and `wkd` vhosts | `systemctl status nginx` |
| fail2ban | host | `sshd` + `nginx-limit-req` jails | `fail2ban-client status` |
| certbot | host, timer | Let's Encrypt renewal | `systemctl list-timers \| grep certbot` |
| `data/geoip.mmdb` | file, read by the container | Country for each signed-in session (DB-IP Lite, CC BY 4.0) | `ls -l /opt/on/data/geoip.mmdb` |

**Every scheduled job that matters now says when it fails.** Five run: the nightly
off-site backup, the monthly restore drill, the monthly GeoIP refresh, the half-hourly DNS
watchdog (which mails on its own) and the weekly outbound DANE check. Each failure path
ends in `| /usr/local/bin/mail-alert.sh "<subject>"`, which uses `/usr/sbin/sendmail` —
there is no `mail` binary on this host, and an alert that silently fails is not an alert.
Before this, only the DANE check could tell anyone anything: a backup that stopped in
August looked exactly like one that ran last night.

**The restore drill has been proved, not just scheduled.** It downloaded the newest
archive (sha256 matched the upload log), decrypted it, extracted 397 members, booted a
second server on port 8099 from the restored state and read its user table back — 8
accounts, DKIM key recovered. A bogus archive name makes it exit 1 and mail the failure,
so the drill can fail rather than always passing.

**Outbound DANE is on, and it depends on one service staying up.** `unbound` runs as a
validating resolver on `127.0.0.1:53`; `systemd-resolved` points at it
(`/etc/systemd/resolved.conf.d/dane.conf`), so Postfix sees the AD bit without
`/etc/resolv.conf` changing — Docker reads that file when it builds a container's
resolver, and `127.0.0.1` there would point at the container itself. Postfix runs
`smtp_dns_support_level = dnssec`, `smtp_tls_security_level = dane`, so a domain that
publishes TLSA must present a matching certificate or delivery is deferred. If unbound
stops, every lookup loses the AD bit and DANE silently degrades to ordinary opportunistic
TLS — mail still flows, so nothing looks wrong. `mail-dane-outbound-check.sh` (cron
Mondays 05:23) is what notices, and it is proven to fail: stopping unbound turns it red.

**The apex is proxied, the mail records are not.** `slothlee.xyz` and `www` are proxied so
Cloudflare can add HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and
Permissions-Policy that the Northflank origin does not send; SSL mode is Full (strict) so
the origin certificate is still verified. No CSP is injected there on purpose — the origin
is a Next.js app and a wrong policy breaks it silently. SMTP, MTA-STS and the mail host
stay DNS-only: proxying them breaks mail.

**DANE pins the mail certificate, and renewal must keep the key.** `reuse_key = True` is set
in `/etc/letsencrypt/renewal/mail.slothlee.xyz.conf`, so the SPKI pin published in DNS stays
correct across renewals without the deploy hook needing a token. Two traps: `reuse_key` must
sit inside `[renewalparams]` — appending it to the end of the file puts it in `[[webroot_map]]`
and certbot reads the value as a webroot path (`True/.well-known`), which fails the renewal
silently until someone runs a dry run. And a dry run is the only way to know: it passed only
after the setting was moved, and a failed renewal in January would have taken TLS down with it.

**Security keys live in `data/webauthn.json`.** Public keys and signature counters only —
no shared secrets, unlike `twofactor.json`, so a copy of the file cannot sign anyone in.
It is in the off-site backup tar list; a restore without it makes every enrolled key
unusable (TOTP and recovery codes still work). Login challenges are held in memory for
five minutes and deleted when redeemed, so a restart mid-login means starting again —
that is intentional: an assertion over an old challenge is still a valid signature.
WebAuthn requires the site to be a secure context, so it works on
`https://mail.slothlee.xyz` and not through a frame or a preview URL.

**Outbound mail must be DKIM-signed at the MTA, not only by the app.** The app signs what
it sends itself, but anything submitted locally — cron output, scripts, the DNS watchdog —
goes through Postfix and rspamd. `rspamd` was logging
`cannot load dkim key /var/lib/rspamd/dkim/slothlee.xyz.dkim.key` and signing nothing, so
those messages left unsigned while DMARC said `p=reject`. Fixed by
`/etc/rspamd/local.d/dkim_signing.conf` pointing at `/opt/on/dkim/slothlee.xyz.pem`,
selector `mail`, group-readable by `_rspamd`.

**The recipient map follows the mailboxes, and is case-insensitive on purpose.**
Postfix refuses an unknown recipient at RCPT — before the DATA that would otherwise be
accepted and then bounced — but only from a map that is maintained. `mail-recipients-sync.sh`
(cron `*/2`) asks the app's `/api/admin/recipients` (the truth: accounts plus live aliases,
minus pending signups) and writes `/etc/postfix/recipients.pcre`; it refuses to install an
empty map, refuses a map that omits `postmaster@` or `abuse@`, and leaves the old file alone
when the API does not answer.

Three things it depends on:

  - **`postfix-pcre` is installed.** Without it every lookup fails with
    `unsupported dictionary type: pcre` and `reject_unlisted_recipient` would refuse everything.
    The map is pcre rather than hash because mailbox names are case-insensitive
    (`Admin@` must reach `admin@`), and a hash lookup is not.
  - **The sync mints its own staff token each run** from the `jwt.secret` in `config.yml`.
    Do not point it back at a saved token: `/root/.admin.jwt` expires, and an expired token
    leaves the map frozen rather than failing loudly. Minting per run is the same authority
    as root on this box, scoped to a five-minute token.
  - **Role addresses are added by the script, not by the API**, because they are not accounts
    and cannot be aliases — `postmaster`, `abuse`, `hostmaster` and the like are reserved so a
    customer cannot claim them. The app routes them to staff.

**`roles.owner` decides who reads postmaster@ and abuse@.** Without it the choice is
alphabetical, which put role mail in a test account. Set in `config.yml`:

    roles:
      owner: tibs

An owner that does not exist, or is not an administrator, logs a warning and falls back to the
first administrator — a configuration mistake must not swallow complaints.

**The front door is postscreen, and the client's own DKIM decides own-domain mail.**
Port 25 is answered by `postscreen`, which runs the tests that need no conversation
(pregreet, DNSBL) and only then hands the connection to `smtpd`; the real listener
carries anvil limits (20 connections, 30/min per client, 60 messages/min, 120
recipients/min). DNSBL scoring: `sbl`/`xbl` weighted 3 (spam source, exploited host),
`bl.spamcop.net` 2, `zen` 1, threshold 3 — so a listing has to mean something before a
sender is refused, and residential/dynamic listings alone only cost latency.

Two settings that must stay as they are:

  - `postscreen_greet_action = ignore`. `drop` refuses any client that answers the
    preliminary banner promptly, which is most legitimate MTAs — the first version of
    this config would have silently discarded ordinary mail.
  - `dnsblog` must exist in `master.cf`. Without it postscreen logs
    `psc_dnsbl_request: connect to private/dnsblog service` and silently performs **no**
    DNSBL lookup at all, so every client passes and the config looks correct.

**Proving the drop path without a listed IP.** The blocking half of postscreen cannot be
tested from a machine that is not on a blocklist. It can be proved honestly with a zone that
exists only on this host:

    # /etc/unbound/unbound.conf.d/zz-dnsbl-selftest.conf
    server:
        local-zone: "selftest.dnsbl.slothlee.xyz." static
        local-data: "175.155.62.46.selftest.dnsbl.slothlee.xyz. 60 IN A 127.0.0.2"

then `postconf -e "postscreen_dnsbl_sites = selftest.dnsbl.slothlee.xyz*3"`, reload, and connect
from the public address. The answer is immediate and unambiguous:
`521 5.7.1 Service unavailable; client [...] blocked using selftest.dnsbl.slothlee.xyz`, with
`DNSBL rank 3` in the log. Revert both files afterwards — the zone must not survive the test.
Use a name under the real domain, not `.invalid`: systemd-resolved refuses to forward `.invalid`
by design, so the query never reaches unbound and the test silently "passes" by not blocking.

`postscreen_access_list = permit_mynetworks` is the whole list: `cidr:127.0.0.0/8` is not
valid there (`table lookup error -- ignoring the remainder of this access list`), and
mynetworks already covers loopback.

The app refuses own-domain senders that fail DKIM, which is what makes
`p=reject` true of us as well as of everyone we tell. Two consequences worth knowing:

  - Mail the box generates for itself — cron's daemon output, `mail-alert.sh`, certbot —
    is injected by the local MTA and sometimes arrives unsigned. It is accepted when
    **Postfix's own first `Received:` header** contains `(Postfix, from userid`, because
    Postfix prepends that line and a remote sender cannot place anything above it. The
    log says `own-domain mail accepted from local injection (unsigned)` when this fires.
    Before this exception existed, the 00:00 certbot report bounced and nobody knew.
  - Everything else from our domain must verify. A forgery from outside is refused at
    DATA with `550 5.7.1` and the sender gets the bounce.

Cost: a first-contact client waits about four seconds in postscreen (cached for an hour
after that). Rollback is two files — `/root/main.cf.<stamp>` and `/root/master.cf.<stamp>`
— then `postfix check && systemctl reload postfix`.

**A `local.d` file must not repeat its section name.** Writing
`dkim_signing { ... }` inside `local.d/dkim_signing.conf` nests it as
`dkim_signing.dkim_signing`, which rspamd accepts with `syntax OK` and then ignores
entirely — the log keeps showing the old behaviour. Check with
`rspamadm configdump dkim_signing` before believing a config took effect.

**Country lookup is local.** The session list labels each signed-in device with the
country its address is registered in. The lookup reads `data/geoip.mmdb` in-process: no
address is sent to a third party to answer "where is this signed in from". Refresh the
file monthly with `mail-geoip-update.sh` (cron `17 4 3 * *`, source in `scripts/`); it
installs atomically and refuses a download under 1 MB. **A missing database is not an
error** — the rows simply carry no country, because that is the truth.

**One health command:** `mail-health.sh` — silent and exit 0 when everything is fine,
prints only what is wrong and exits 1 otherwise. `mail-health.sh -v` shows every check.
It checks the container, the API, all five units, https, certificate expiry, SMTP
listeners, the postfix queue, the recipient map, the age of the last off-site backup and
disk space.

## Deploying

The two halves are separate repositories (`Webinterface` = client, `OpenNeutron` =
server). Both are worked on locally and pushed to the box; nothing is edited in place on
the server except configuration.

**Web client**
```bash
cd <web-repo> && ./scripts/deploy.sh
```
That script builds, refuses to upload if the entry point or the build stamp is missing,
uploads, and then checks the served asset is byte-identical to the build (sha256). Use it
rather than the three-line pipeline: `npm run build | tail -2 && tar czf - ... | ssh ...`
takes its exit status from `tail`, so a failed build uploads the *previous* dist and the
result is indistinguishable from a browser cache problem.

Bump the service-worker version in `public/sw.js` before building, or browsers keep the
old shell and a fix looks like it did nothing. The sidebar footer shows the running build
(`<sha>[+] · <innerWidth>x<innerHeight>`), which answers "is my phone on the new build?"
without a devtools session.

**Server**
```bash
tar czf - src Cargo.toml Cargo.lock | ssh -i <key> root@46.62.155.175 \
  'tar xzf - -C /opt/on && docker exec -w /usr/src/app openneutron \
   bash -lc "PATH=/usr/local/cargo/bin:\$PATH cargo build --release --locked \
     --target x86_64-unknown-linux-musl" && docker restart openneutron'
```
The binary is `OpenNeutron`, not `neutron`. A restart reloads sessions; users stay
signed in.

**`cargo` is not on the default PATH inside the container** — `bash -lc` alone answers
`cargo: command not found`. Worse, piping the build through `tail` reports `tail`'s exit
status, so a build that never ran printed "done" and the old binary kept serving. Always
build without a pipe after the command, or with `set -o pipefail`, and confirm the
binary's mtime changed before restarting.

**`--locked` matters.** A new dependency means the lockfile changes, and the container
cannot write `/usr/src/app/Cargo.lock` (the bind mount's ownership). Resolve the lock on
the workstation (`cargo metadata`) and ship it; `--locked` then refuses to build if the
two disagree, which is the failure you want instead of a silent half-build.

**Prove it after deploying**
```bash
./scripts/run-all-proofs.sh              # everything
./scripts/run-all-proofs.sh --only scheduled
```
The suite is the Rust tests, the browser-crypto proofs (Node), and the Python proofs
that run against the box over SSH. Each line of output is one proof; the runner exits
non-zero if any fails, **judged by the proof's exit status**, never by matching its
output — that mistake once let a 29/30 run report `ok`. No count is written here on
purpose: it changed twice this week, and a number in prose is a claim that rots.

## Backups and restore

**Nightly, 04:10** (`/usr/local/bin/mail-offsite-backup.sh`): tar of the state, encrypted
with GPG AES-256 using a passphrase that exists only on this host, uploaded to the private
repository `SirTibbles666one/sloth-mail-backups`, ten kept, each logged with a sha256 in
`/var/log/mail-offsite.log`. The script refuses to upload an archive it cannot decrypt and
list itself.

**The state it carries:** `users.bin`, the sidecar JSONs (waitlist, pending accounts,
recovery, two-factor, sessions, ephemeral rules, notes, aliases, scheduled, arrival, push,
VAPID, imported, PQ keys, deletion log + its signing key), `data/blobs`, `dkim`,
`config.yml`.

**A new `data/*.json` sidecar must be added to the tar list in the same commit** that
creates it, or it is not backed up.

**Monthly, 1st at 06:00:** `mail-restore-drill.sh` — downloads the newest archive,
compares its sha256 with the upload log, decrypts it, and boots a second server from the
restored state on port 8099 while production keeps running, then asserts the API answers,
the user table loaded, the DKIM key returned and the account count is non-zero. Logs to
`/var/log/mail-restore-drill.log`.

**A real disaster restore also needs**, and the archive deliberately does not carry: the
built binary (rebuild it — but note the *source* is now in the archive as
`backup-repo/mail-repo.bundle`, because upstream refused the push and the fork had
drifted), TLS certificates (re-issue once DNS points at the new host), and the
`/usr/src/app` layout the image expects.

## Monitoring

A watchdog runs **every 30 minutes from the Hermes host**, not from this server —
deliberately, because a machine cannot report its own absence. `mail-watchdog.sh`
(script-only, no model invoked) SSHes in, runs `mail-health.sh`, and **prints nothing
when the check passes**. Silence means healthy; the only messages are the failures:

- **not answering over SSH** — the host is down, unreachable, or refusing the key
- **health check failed** — with the lines `mail-health.sh` printed

Alerts arrive in Telegram. They cover the container, the API, nginx, postfix, rspamd,
redis, fail2ban, https, certificate expiry under 14 days, the SMTP listeners, the
postfix queue, the age of the last off-site backup (over 26 h) and disk over 85%.

This is a backstop, not a substitute for `mail-health.sh -v` when something feels wrong.

## Where the secrets are

| Secret | Path |
|---|---|
| Backup GPG passphrase | `/root/.mail-backup-pass` |
| Backup repository token | `/root/.gh-backup-token` |
| Administrator JWT (cached) | `/root/.admin.jwt` |
| JWT signing secret, DKIM key, config | `/opt/on/config.yml`, `/opt/on/dkim/` |
| Deletion-log signing key | `/opt/on/data/logkey.json` (also in every backup) |

All 0600. `/opt/on/data` itself stays **755** — dropping it to 700 broke static serving
(`signup` 404, `sw.js` 403) because the container reads the directory as its own user.

## Everyday operations

- **Approve someone who asked for access** — Panel → Admin → the approval queue. Self
  signup at `/signup` creates the account but holds it; login answers "waiting for
  approval", not "wrong password". CLI: `mail-pending` lists the queue,
  `mail-pending approve <username>` and `mail-pending deny <username>` act on it.
- **Invite codes** — still work, still single-use (`mail-waitlist`).
- **Create an account by hand** — Panel → Admin → New account, then hand over the one-time
  setup token it shows. The account has no keys until setup completes.
- **Recovery** — users create a recovery key in Settings; it is single-use and replaces the
  old one when used. A server-side password reset costs the mailbox's old mail, because the
  private key is wrapped with the password. Say so before doing it.
- **A message that will not send** — the compose window shows the SMTP error the server
  returned (`502 smtp_error`). A scheduled message that fails appears in the Sent panel as
  "couldn't send — <reason>" and stays listed.

## Things that will bite

- **Never add a field to the `User` or `Email` structs.** Both stores are bincode and
  positional; a new field makes every existing record unreadable (`get_user` → `None` →
  every request 401) and the next save overwrites the store. New state goes in a
  `data/*.json` sidecar.
- **The CSP must keep `'wasm-unsafe-eval'`.** Argon2 runs as WebAssembly; without it,
  sign-in fails inside the browser while the server logs no request at all — and the app
  used to report that as "Login failed". The `headers` proof asserts it. Violations are
  readable at `/var/log/nginx/csp-reports.jsonl`.
- **`limit_req_status 429` on every rate-limited location.** Without it, throttling reads
  as "server broken" (it answered 503).
- **The postfix milter fails open.** `milter_default_action = accept` means that if rspamd
  is down, mail is still delivered — unscored. Check `systemctl status rspamd`, not the
  docker list.
- **`docker logs X | grep -q` lies under `set -o pipefail`**: grep exits early, docker logs
  dies of SIGPIPE, the pipeline returns 141 and a passing check reads as failure.
- **Run the mail server from `/usr/src/app`** (the image's workdir): the DKIM path in
  `config.yml` is absolute.
- **Editing a held message is device-local.** The server holds the sealed request and
  cannot return the plaintext; the pencil only appears on the device that composed it.
  `replace_id` without `send_at` is refused with `400 replace_needs_time` — otherwise an
  edit would deliver a second copy while the first stayed queued.

## Posture

Security details, the reasoning behind the headers, the fail2ban jails and what is still
open: `/root/HARDENING.md`. Mail authentication state (SPF, DKIM alignment, DMARC
`p=reject`, MTA-STS, TLS-RPT) is verified end-to-end through an outside receiver, not by
reading the DNS zone.

## Reading Google's TLS-RPT reports

`_smtp._tls.slothlee.xyz` is `v=TLSRPTv1; rua=mailto:tibs@slothlee.xyz`, so every sender
that reports sends a daily aggregate JSON into the `tibs` inbox (gzipped, named
`google_com-slothlee_xyz-<start>-<end>-001.json.gz`). It arrives as ordinary mail, which
is the point: one less dashboard to keep.

**How to read one.** Ignore the headers, read `policies[]`: one entry per policy the sender
applied. `policy.policy-type: sts` with `mode: enforce` and the `mx` list means **that
sender enforced MTA-STS** — `total-failure-session-count` must be 0. A second entry with
`policy-type: no-policy-found` and successes is *normal*: a sender that had not yet fetched
or cached the policy delivered over verified TLS anyway. Any `failure-session-count` > 0,
or a `result-type` naming a certificate/name mismatch, is the signal worth acting on.

**Reading of 2026-10-30** (the first one collected): 5 successful sessions under the
enforced policy, 1 under `no-policy-found`, **0 failures anywhere** — and the served
policy, the `_mta-sts` TXT id, MX and the DANE TLSA record all matched what the report
said was enforced.

**Changed after it:** `max_age` 604800 (7 days) → **1209600 (14 days)**, which is the
post-enforcement figure — senders keep enforcing through a policy-fetch outage instead of
falling back. Order matters and is not interchangeable:

1. write `/var/www/mta-sts/.well-known/mta-sts.txt` (vhost serves it from disk,
   `Cache-Control: max-age=300`, DNS-only — no CDN copy to purge) and confirm it over
   HTTPS;
2. **then** bump the id in `_mta-sts.slothlee.xyz` (`2026102701` → `2026103101`).

Bumping the id first would tell senders "the policy changed, go fetch it" a minute before
the new text exists, and they would cache the *old* policy under the *new* id for the whole
`max_age`. **The id must change whenever the policy changes** — an unchanged id means
senders never re-fetch.

Verified after the change: served policy `max_age: 1209600` (ETag moved `6ae0bba8-43` →
`6ae60b7a-44`), `_mta-sts` TXT `v=STSv1; id=2026103101` from `dns.google`, MX
`10 mail.slothlee.xyz.` and TLSA `3 1 1 d931…2c50b` unchanged. A `cf` update needs
`--body` (the sub-command has no per-field flags): `cf dns records update <id> --zone
slothlee.xyz --body '{"type":"TXT","name":"_mta-sts.slothlee.xyz","content":"v=STSv1;
id=…","ttl":300}'`.

## Dashboard headers (app.slothlee.xyz)

The staff dashboard is served by nginx at `/etc/nginx/sites-available/app-dashboard`,
which is where its security headers live (the Node process sets none of them).
Backups of that file: `/root/app-dashboard.pre-csp.<epoch>`.

CSP, enforced:

```
default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' data: https://cdn.discordapp.com https://media.discordapp.net;
font-src 'self' data:; connect-src 'self' wss://app.slothlee.xyz ws://app.slothlee.xyz;
media-src 'self'; worker-src 'self' blob:; manifest-src 'self';
frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none';
upgrade-insecure-requests
```

How it was proven, and how to prove it again:

1. Serve it as `Content-Security-Policy-Report-Only` first. Load the dashboard
   with a staff session and a `securitypolicyviolation` listener installed via
   CDP `Page.addScriptToEvaluateOnNewDocument` (installing it in the page is too
   late — the bootstrap has already run). Tour the screens; expect zero.
2. **Prove the listener itself fires** by requesting an image from a host the
   policy does not allow. Without this step a zero is indistinguishable from a
   broken collector.
3. Flip to enforced, then confirm nothing was blocked (`disposition: 'enforce'`
   in the violation events) and that the live feed still says "connected" — a
   websocket is the one thing `'self'` does not cover in every browser, hence the
   explicit `wss://`.

What it buys even with `'unsafe-inline'` in `script-src`: an injected script
cannot phone home. `fetch()` to another origin throws, and `<img>` beacons never
load — verified live, not assumed.

The report-only policy served alongside it drops `'unsafe-inline'` from
`script-src`. Its violations on a page load are the cost of a nonce migration:
8 inline scripts, which is Next.js's own bootstrap. Until that migration the
enforced policy stays as measured.

## The money gate, and the two ways it was not doing its job

Entitlement ("may this guild write, judged on money alone") has to sit where the
writes actually happen. It lived in the tool dispatcher, which covers every
tool-backed write — but three dashboard and Discord writes never pass through
it: closing a ticket, releasing a hold, deciding an appeal. Each calls its
service directly, so a lapsed subscription could still do all three.

Two defects, both now fixed:

1. **The gate was missing on those paths.** The check now lives in
   `writeBlocked()` (`src/services/security/killswitch.js`) and
   `appealWriteBlocked()`, which are the last checkpoints those services call.
2. **The read-only exemption was a dead letter on those same paths.** Both
   services called their gate without a guild id, so `readOnlyForGuild(null)`
   refused *every* guild — including the ones named in
   `SLOTH_LEE_READONLY_EXCEPT`. On a box with `READONLY=1` a ticket close was
   refused for the wrong reason, and the exemption it advertises did nothing.

The lesson generalises: **a write gate that forgets the guild id silently
disables the exception the gate exists to provide.** When a gate takes an
optional guild id, check every call site passes it.

### Proving it (do this after any change to the gate)

`scripts/money-drill.mjs` in the bot repo drives the real endpoint with a staff
session and a signed Paddle webhook. On a test guild:

1. set `trial_ends_at` in the past, `paid_until` null → `read` returns 200 and
   `entitlement.state` is `expired`; a `ticket_close` returns **403 with the
   billing line**.
2. `webhook-pay` (signed with the configured secret) → `paidUntil` extends; the
   same close now gets past the gate (it fails later, on the drill ticket having
   no real Discord thread — that is the proof it passed).
3. `webhook-cancel` with a period that already ended → the close is refused with
   the billing line again, and reads stay 200 throughout.
4. Restore the row to `null/null` (legacy) and delete the drill tickets.

A single refusal is not proof of the right refusal: read the message. A CSRF
refusal and a read-only refusal both say 403, and the drill once "passed" on a
wrong `csrf` field name before the field was corrected to `csrfToken`.

## Public site headers (slothlee.xyz, www)

The marketing site is `sloth-site` on `:3100`, proxied by
`/etc/nginx/sites-available/app.slothlee.xyz` (the file name predates the split;
it serves the apex and www, not the dashboard). Backups:
`/root/site.pre-csp.<epoch>`.

Until now it answered with **no** CSP, nosniff, referrer policy or permissions
policy — while the dashboard next door had all four. The public site is the one
anyone can load, so that was the wrong way round.

Enforced CSP (measured, not guessed):

```
default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' data: https:; font-src 'self' data:;
connect-src 'self' https://app.slothlee.xyz; media-src 'self' https:;
frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none';
upgrade-insecure-requests
```

The one cross-origin call the site makes is the **status page's health poll** to
`https://app.slothlee.xyz/healthz`. That host is named explicitly; nothing else
is. Verified live: that fetch returns 200 while a fetch to any other origin
throws.

The report-only policy alongside it drops `'unsafe-inline'` from `script-src`.
It reports **4 inline scripts per page** — the site's share of the nonce work
(the dashboard's is 8).

A trap worth remembering: the very first report-only tour showed 27 violations
on `/mail` that never reproduced. They were stale documents/chunk references
from before the header existed. **Re-tour on a clean load before believing a
violation count**, otherwise you widen a policy to satisfy a cache.

## The hash-based CSP attempt, and why it is not shipped

`script-src 'unsafe-inline'` is the one thing the dashboard's enforced policy
still gives away. The obvious fix — a nonce — is impossible here: the dashboard
is `output: 'export'`, a static document served from disk, so a per-request
nonce would be a constant. The next best option is build-time hashes: hash each
inline script in `dashboard/build/index.html` and name the hashes in `script-src`.

That was implemented, tested (6 unit tests) and deployed. **It broke the live
dashboard**: `Checking staff…` forever, `window.__shellReady` never true, 8
inline scripts refused under `script-src-elem` — while the response carried the
8 computed hashes and the browser's own `crypto.subtle` digest of those same
scripts matched them byte for byte.

It was rolled back in minutes. The lever is worth knowing: **nginx can strip an
upstream header without a rebuild** —

```
location / {
    proxy_hide_header Content-Security-Policy;
}
```

The application's policy is computed in `src/http` from the build, so it only
exists while that code is deployed; stripping it at nginx returns the site to the
measured policy immediately. The code was then reverted and the container
rebuilt, so nothing rests on the nginx line for safety.

Open question for the next attempt (do not guess at it): the hashes provably
matched the document's own inline scripts, yet the browser refused them. Worth
checking before rewriting anything:

1. whether the violations belong to a **different document** (a child frame or a
   client-rendered region), whose inline scripts are not the ones in
   `index.html`;
2. whether Cloudflare **merges the two response CSP headers** into one value,
   changing how the source list is parsed.

A controlled experiment — one page, one known inline script, hash in the header
— answers both in minutes and avoids another live failure.

Until that is understood, the dashboard keeps: `default-src 'none'`,
`connect-src 'self'`, CDN-allowlisted images, `frame-ancestors 'none'`, and
`script-src 'self' 'unsafe-inline'`. An injected script cannot reach the
network; it can still run.

## The DKIM branch nobody had tested: a *pass*

Every earlier probe proved the refusal side — own-domain mail without a signature
gets `550 5.7.1`. The acceptance side was never exercised, so "we verify DKIM"
was an assertion. It is not any more.

**What is verified.** `/opt/on/src/utils/dkim.rs` verifies the signature itself:
DNS TXT at `<selector>._domainkey.<d>`, body hash, RSA-SHA256 over the
canonicalised headers. It does not read rspamd's verdict. So the message has to
carry a signature that the domain's published key actually validates.

**How to reproduce.** Sign `relaxed/relaxed` with the real key
(`/opt/on/dkim/slothlee.xyz.pem`, selector `mail`), send from an external
vantage point, and read the app's own log line — not the SMTP reply:

```
signed    250 queued  →  [SMTP] DKIM: pass for <tibs@slothlee.xyz>   →  queued for user 'e2ea'
tampered  550 5.7.1 Mail from this domain did not pass DKIM: body hash mismatch
unsigned  550 5.7.1 Mail from this domain must carry a valid DKIM signature
```

**Two traps that cost this window an hour.**

1. *The SMTP reply is not the verdict.* Postfix accepts at DATA (`250 Ok:
   queued`) and relays to the app on `:2525`; the refusal comes back as a bounce
   (`dsn=5.7.1, status=bounced`). A probe that asserts on the SMTP reply reports
   `250 UNEXPECTED` for a message that was correctly refused. Read
   `/var/log/mail.log` for the `status=bounced` line and the container log for
   the DKIM verdict.
2. *Loopback mail is signed by rspamd before the app sees it.* Inject from
   `127.0.0.1` and all three cases come back "pass" — the app is verifying
   rspamd's signature, not the sender's. Negative cases only mean anything from
   outside the box.

**Fixed while testing:** the refusal text was the same string for both failures,
so a tampered message reported "must carry a valid DKIM signature" while the
header sat in plain sight. The refusal now carries the verdict
(`did not pass DKIM: body hash mismatch`) and a WARN names it in the log.
`8972919`, mail tests 102/102.

## Why hash-based CSP cannot work on this dashboard: Cloudflare rewrites the HTML

Two identical requests to `https://app.slothlee.xyz/app`, same byte length, same
first eight inline scripts — and the ninth differs:

```
request 1  …e036d478072e
request 2  …04328c56bf88
```

The diff is Cloudflare's own injection:

```js
window.__CF$cv$params={r:'a532f5079ccd367f',t:'MTc5MzQ1MjgyNg=='}
```

Ray id and timestamp change on every response. The edge also makes that script
create *another* inline script at runtime, which no static hash list can allow.

Fetched from the app itself on port 3200, the same document has **8** inline
scripts and no `__CF$cv$params`; through Cloudflare it has **9**. So the hash-CSP
attempt was not defeated by Next.js, by header merging, or by a bug in the
verifier — it was defeated by a script we do not serve and cannot hash.

**Conclusion.** `script-src 'unsafe-inline'` stays on any Cloudflare-proxied
document here. The honest bound is: injected script can *execute*, but it cannot
reach the network (`connect-src 'self'`, and `fetch('https://example.com/leak')`
throws). Removing the injection means turning off Cloudflare's JS detections —
a bot-protection trade for a header, not a free win.

### What did come free: `script-src-attr 'none'`

Inline `<script>` blocks still need `'unsafe-inline'`; inline *event handler
attributes* do not. Added to the enforced policy on `app.slothlee.xyz`:

```
script-src 'self' 'unsafe-inline'; script-src-attr 'none';
```

Proven on the live dashboard — same-origin image that 404s, `onerror` attribute
attached, and:

```
probe:     ran: 0  complete: true  naturalWidth: 0     ← the error event fired
violations: script-src-attr | inline  ×2
```

The handler was blocked and named as such, not silently skipped. Tour of seven
screens (status, tickets, settings, server, actions, appeals, logs): all
`shellReady: true`, `overflow 0`, **zero violations**. Nothing here uses inline
handlers, which is what makes this safe to enforce.

## When the resolver dies, everything else lies

Two outages in fourteen hours, both the same shape: containers healthy, mail web
200, bot crash-looping on `getaddrinfo EAI_AGAIN discord.com`. The cause was not
the bot. `systemd-resolved` had degraded its feature set against unbound and
eventually answered nothing:

```
00:00:56 Using degraded feature set UDP+EDNS0 instead of UDP+EDNS0+DO for DNS server 127.0.0.1
00:01:12 Using degraded feature set UDP instead of UDP+EDNS0 for DNS server 127.0.0.1
00:01:27 Using degraded feature set TCP instead of UDP for DNS server 127.0.0.1
13:33:35 DNSSEC validation failed for question discord.com IN A: no-signature
```

Losing the DO bit is what turns into `no-signature`: with no DNSSEC records the
validator refuses every answer, and every name on the box becomes SERVFAIL.
`dig @127.0.0.1 discord.com` answered fine the whole time — unbound was never the
problem, only the front door was.

**Diagnosis order that actually works.** `getent hosts <name>` on the host, then
`dig +short @127.0.0.1`, then `dig +short @127.0.0.53`, then
`journalctl -u systemd-resolved`. The middle two separating is the whole tell.

**Self-heal, proven by breaking it.** `sloth-stack-watch.sh` now restarts
`systemd-resolved` once when resolution is already failing — never when it is
working, so it cannot create this outage. Tested deliberately:

```
$ systemctl stop systemd-resolved      → DNS is down, as intended
$ sloth-stack-watch.sh                 → exit 0
  13:40:19Z DNS resolution failed; restarting systemd-resolved once
  13:40:22Z DNS recovered after restarting systemd-resolved
```

The bot no longer restarts when this happens: `loginWithRetry` backs off
(2s → 4s → … cap 30s, six attempts) on transport failures and still refuses to
retry `TokenInvalid`/`DisallowedIntents`, because a wrong token is not a blip.
Five unit tests pin that; it has not yet been exercised by a real outage.

**Not changed, deliberately.** Setting `DNSSEC=no` on resolved would remove the
failure mode, but resolved is what Postfix's DANE lookups resolve through — a
stray DO bit costs mail TLS authentication. That change needs its own controlled
experiment (verify DANE still validates before and after), not a paragraph here.

## The backup carried the data and not the machine

The nightly archive had every message, every key and the bot's database — and
none of the decisions that make this box behave the way it does. Restoring it
onto a fresh server would have produced healthy data behind the wrong headers:
no recipient map, no postscreen, no cron schedule, no CSP, and a reissued
certificate that silently breaks the DANE record other mail servers check.

Added to the same encrypted archive (44 KB compressed, everything resolves):

```
etc/nginx/sites-{available,enabled}  etc/nginx/conf.d
etc/postfix/{main.cf,master.cf,recipients.pcre}
etc/systemd/resolved.conf.d  etc/unbound/unbound.conf.d
var/spool/cron/crontabs      etc/letsencrypt/{live,archive,renewal}
usr/local/bin/{mail-*,sloth-stack-watch}.sh
```

`etc/letsencrypt` is in there **for the DANE pin**, not for convenience: the TLSA
record points at the current key, so a restore that reissues a certificate
without carrying the key order takes mail down until DNS is updated by hand.
The archive is already GPG-symmetric and already holds the DKIM keys and the bot
token, so this is the same trust boundary, not a new one.

Verified: `slothmail-20261031-134228.tgz.gpg`, 21,816,557 bytes, round-trip
checked by the script, members spot-checked against the live filesystem.

## The mail server's source existed on one disk only

`/opt/on` is a git clone with `origin = OpenNeutron/OpenNeutron`, and that upstream
refuses this PAT (`403 Resource not accessible by personal access token`), so the ten
commits this server actually runs were **not pushed anywhere**. The fork
(`SirTibbles666one/OpenNeutron`) has drifted 65 commits the other way, so a merge is not
a five-minute job. Losing this disk would have meant rebuilding the mail server from a
tree nobody has a copy of.

The archive now carries `backup-repo/mail-repo.bundle` — `git -C /opt/on bundle create`
before `tar`, refused under 64 KB, proved by cloning out of the uploaded snapshot.

**The trap: a shallow clone makes a bundle that is not a backup.** `git -C /opt/on
rev-parse --is-shallow-repository` said `true` (boundary commit `2c80a48`), so the first
bundle referenced a parent it did not carry. `git bundle verify` was happy; the clone
failed with `Could not read 2fb696a…` / `remote did not send all necessary objects`. Fix:
`git fetch --unshallow origin` (anonymous fetch, the repo is public) → 20 commits →
bundle verified as "complete history" and cloned cleanly.

**Two smaller traps in that proof, both worth keeping:**

- `git bundle verify` needs to run **inside a repository** — run from a bare temp dir it
  says `need a repository to verify a bundle` and proves nothing.
- a bundle whose only ref is `refs/heads/main` leaves a plain `git clone` with an unborn
  HEAD (`remote HEAD refers to nonexistent ref`); clone with `-b main` and assert the
  commit count.

The first version of the proof script printed `PROOF OK` after that failed clone, because
each step was unchecked and `set -e` was missing. It now exits non-zero on every step —
a drill that reports success without cloning is worse than no drill.

## The structure reads answered 404 in production

`/api/structure/snapshots` and `/api/structure/preview` sat on `GUILD_SCOPED_ENDPOINTS`
but never on `READ_ENDPOINTS`, and `handleApi` 404s any path outside it. Both answered
`{"ok":false,"error":"Not found."}` to every caller, while `dashboard/REBUILD.md` listed
them as live API. Measured with a minted staff cookie before the fix (404 on both, 200 on
`/api/stats/queues`) and after it (`200 {ok:true,snapshots:[]}` and `400 "That snapshot id
is not valid."` for a missing `?snapshot=` — the route answering rather than the door
refusing).

No screen consumes them yet (F6 draft), so nothing user-visible broke: what broke was the
contract — a documented capability the server refused, which the next screen would have
debugged from the wrong end.

What hid it: the contract generator's path class was `[a-z-]`, which stops at the second
segment, so nested paths (`/api/stats/*`, `/api/structure/*`) never entered the generated
surface even when registered — the pin could not disagree with reality. Both extractors
now use `[a-z_/-]`.

## The restore drill, and the three things it caught

A backup that round-trips as a *file* proves nothing about a restore. Downloaded
the newest snapshot from `SirTibbles666one/sloth-mail-backups`, decrypted it,
and booted both halves against the extracted copy — nothing touching production
except reading `openneutron:local`'s binary.

**What a restore actually needs.** The drill container is the production binary
with the restored data mounted over it:

```
docker run -d --name restore-mail -p 127.0.0.1:18080:8080 -p 127.0.0.1:12525:2525 \
  -v /opt/on/target:/usr/src/app/target:ro \
  -v …/restored/data:/usr/src/app/data -v …/restored/config.yml:/usr/src/app/config.yml:ro \
  -v …/restored/dkim:/usr/src/app/dkim:ro \
  --entrypoint /usr/src/app/target/x86_64-unknown-linux-musl/release/OpenNeutron \
  openneutron:local /usr/src/app/config.yml
```

The image's own entrypoint compiles from source on start — minutes of `cargo
build` before it listens. Point `--entrypoint` at the musl binary instead.

**Results.**

```
[Storage] Loaded 12 users from 'data/users.bin'
[Storage] Email index consistent (74 orphaned blob(s) ignored)
[DKIM] Loaded signing key … (selector='mail')
SMTP server listening on 0.0.0.0:2525
SMTP: queued for user 'e2ea' (total emails: 102)     ← 101 restored, 1 new
web: / 200   /web 200   /login 200
postgres: 73 tables, 72 identical, 0 restore errors
          guild_settings md5 a7388d41a4bc7f7fbbc6825402be600a — identical
          scheduled_jobs prod 23355 / restored 23354 (snapshot lag, not a defect)
```

**Three failures found, one of them serious.**

1. **`data/static` was not in the archive.** The restored server booted, loaded
   every user, accepted mail and answered **404 on every web route** — a mail
   server nobody can log into. The archive had round-tripped perfectly and would
   have restored that. Added to the tar list, backup re-run, drill repeated:
   `/`, `/web`, `/login` all 200.
2. **The contents API returns `content: ""` above 1 MB** — silently, with
   `encoding: "none"`. A 21 MB snapshot downloaded as zero bytes and surfaced
   later as `gpg: decrypt_message failed`. Use `/git/blobs/{sha}` (100 MB cap)
   and assert the size before decrypting.
3. **The drill's own path check lied**: members are stored relative to their tar
   root, so `on/data/users.bin` can never exist. Three `MISSING` lines on a
   healthy archive. Report paths that can exist, or the drill teaches the wrong
   lesson.

## Restoring from a snapshot, and the key that went away

The dashboard's Server → Restore screen shows the diff before it offers the
press, and the press carries a digest of that diff. Three things about the live
box are worth writing down, because two of them were only found by using it.

**1. The press is bound to the diff you were shown.** `POST /api/action` with
`kind=structure_restore`, `id=<snapshot uuid>` and `confirm=<the preview's
digest>`. The server rebuilds the diff at press time and refuses unless it
still hashes to the same 32 hex — `409 stale_preview`, "The server changed
since that preview — look again before restoring." Two presses from two tabs
cannot both land, and a tab left open over lunch cannot restore yesterday's
picture. No `confirm` at all is `400 confirm_required`; a bad uuid is
`400 bad_snapshot`; a closed imaging module, a kill switch, read-only mode or a
lapsed subscription is `403 blocked`. All of those are refused **before** the
safety snapshot is taken, so a refusal writes nothing.

**2. A successful restore takes a safety snapshot first.** The response carries
`preRestoreId`, and that row appears at the top of the list the screen reloads.
If the safety snapshot cannot be written, the restore stops and says so — the
"nothing was changed" promise rests on that ordering.

**3. The finding that mattered: 82 of 83 snapshots could not be opened at all.**
Snapshot payloads are AES-GCM sealed with `SECRETS_KEY`. That key was re-sealed
between 20 and 30 October, and every payload written under the old one became
unreadable — while the list kept offering them, because the row's metadata
(label, counts, size) is plaintext. The preview refused with "I could not read
that snapshot", which reads like a corrupt row and is actually a rotated secret.
Now:

```sql
ALTER TABLE guild_snapshots ADD COLUMN key_fingerprint TEXT;   -- migration 20261031171000
```

- every new snapshot stores `sha256(SECRETS_KEY)[0..16]`;
- `/api/structure/snapshots` returns `readable: true | false | null` per row,
  and the screen greys out the false ones with "sealed with a key this server no
  longer holds — cannot be restored" and does not make them pickable;
- preview/apply refuse a mismatched fingerprint with `code: "retired_key"`
  before any decrypt;
- `scripts/backfill-snapshot-keys.mjs` (runs inside the container, `--dry`
  available) fingerprints the pre-existing rows: it tries to open each payload
  and writes today's fingerprint or the literal `retired`.

Run it once after any `SECRETS_KEY` rotation. Live result on this box: 83 rows
→ 1 readable, 82 retired. **A rotated key silently orphans every snapshot
taken before it**, so rotate deliberately and re-take a snapshot afterwards.

### Proven on the box (2026-10-31)

```
list (Anti Ban Front): 25 rows, 1 readable, 24 retired
retired preview:       {"ok":false,"code":"retired_key","error":"That snapshot was sealed with a key this server no longer holds…"}
wrong digest:          http=409 {"code":"stale_preview"}          safety snapshots: 0
no digest:             http=400 {"code":"confirm_required"}        safety snapshots: 0
correct digest:        http=200 {"status":"applied","preRestoreId":"6569bf74-…"}
                                                                   safety snapshots: 1
audit_events:          restore.apply {"created":0,"updated":0,"settings":false}
```

`created: 0, updated: 0` is the point of choosing a snapshot of the live state:
the whole path ran — gate, digest, safety snapshot, apply, audit — and the
server's structure did not move.

### Reading the screen

At 390×700 the list renders one row per snapshot with counts, age and size, a
`2 of 25 can be restored · 23 sealed with a retired key` line above the diff
panel, 65 px pick targets, and no horizontal overflow. The four counts are kept
apart — create / update / left in place / blocked — because a single "12
changes" number hides the difference between adding a channel and being unable
to read one.

## The appeal plan

`docs/PLAN-ban-appeal.md` in the bot repo (rendered by `scripts/render-plan.py`)
is the standing plan for this feature: measured facts, the eight defects in order
of cost, six phases each ending in a number that can fail, and the four questions
left to the owner. Re-render it after changing the code it describes:

```
python3 scripts/render-plan.py docs/PLAN-ban-appeal.md /tmp/plan.pdf
```

Its first finding is a privacy defect, not a nicety: the read gate
(`guildContext`, `staffInGuild`) is weaker than the decide gate (`moderator` +
Moderate Members), so the lowest staff rank can read a banned person's complaint
and download their pictures while being unable to decide anything.

## The appeal page, for the person who cannot type in the server

Every appeal route before this one lived inside Discord: a quarantined member
gets a modal. That works while you are still in the server. A member who was
**banned** has no channel to open a modal in, so the one person with the most
reason to appeal had no door at all.

`https://app.slothlee.xyz/appeal` is that door, and it is the only page on this
box a non-staff person can sign in to.

**Identity is a Discord sign-in, not a token.** The page reuses the same OAuth
app as the staff door, but the destination decides which session is minted: a
state blob whose `next` is exactly `/appeal` gets `sloth_member`, and everything
else keeps the existing staff path. The member cookie is a different shape
(`m.<userId>.<issuedAt>.<hmac>`, 2 hours) so it cannot be replayed as
`sloth_staff`, and every staff endpoint reads only `sloth_staff`. `safeNext`
still allowlists paths — `/appeal/anything` is not an entry, only the exact
path.

**It is server-rendered on purpose.** No bundle, no JavaScript, no CSP
exception: the whole interaction is a form post. The page is
`GET /appeal`, with `POST /appeal/submit`, `POST /appeal/withdraw`,
`/appeal/login` and `/appeal/logout`. A cross-origin post is refused by an
origin check before the cookie is even looked at, and the cookie itself is
`SameSite=Lax`, so a cross-site form post arrives unauthenticated and is
redirected to sign-in rather than acted on.

**It shows only servers where you have a standing.** Signing in must not
enumerate the bot's guild list to a stranger: the page filters to guilds where
the member is banned or quarantined, plus any guild they already have an appeal
in. A member with nothing outstanding sees an empty page — not a list of this
bot's customers.

**The gates are the ones the Discord flow already uses** — `submitPortalAppeal`
goes through `appealWriteBlocked` (read-only mode with its per-guild exception,
kill switch, lapsed subscription), one pending appeal per guild, two per six
hours, 8 to 2000 characters. Nothing about the portal is a bypass; the only
difference is that it does not need a channel to post in.

**The drill that proved it** (`/root/appeal-drill.sh`, re-runnable):

```
quarantine 900000000000009001 in 1565572253624827965   -> 1 row
mint a member cookie (`staff-session.mjs <id> --member`) -> 109 bytes, 2h
GET /appeal                                             -> the server, "in quarantine", the form
POST /appeal/submit                                     -> ?flash=sent, row `pending`
POST /appeal/submit again                               -> ?flash=waiting (refused)
POST /appeal/withdraw                                   -> ?flash=withdrawn, row `withdrawn`
cleanup                                                 -> 0 appeal rows, 0 quarantine rows
```

**Deciding it exposed two bugs that had been there all along.** Both lived in
`settleAppeal`, which is the *only* way a decision is written — the Discord
button and the dashboard press both call it, so neither bug was specific to the
new page.

1. **Accepting only knew how to release a quarantine.** It fetched the member and
   refused with "I cannot see that member, so I have not closed the appeal" when
   they were not in the server. A banned member is never in the server — so the
   one person the page exists for was the one person whose appeal could not be
   accepted. `settleAppeal` now reads the ban state first (`banState`: banned,
   not banned, or *unknown*), lifts a ban with `guild.bans.remove(id, reason)`,
   releases a quarantine as before, and refuses by name in the third case. An
   unknown state (a Discord failure) refuses and writes nothing — the same rule
   as everywhere else here: "Discord did not answer" is never read as "clear".
2. **The read-only exception never reached the decision.** `appealWriteBlocked`
   takes a guild id so an exempted guild can still decide appeals while the
   process is read-only — and `settleAppeal` called it with no guild at all, so
   the exception silently did not exist and the refusal blamed read-only mode
   instead of the call site. The row is now loaded first and its `guildId`
   passed to the gate.

Both are the "a write gate that forgets the guild id" class this file already
warns about, and neither showed up in tests because **no test had ever accepted
an appeal** — the existing coverage decided one appeal and decided it *denied*.

**Proven live, twice:**

```
# a member who is neither banned nor present
accept  -> {"ok":false,"error":"That member is neither banned nor in the server,
            so there is nothing for me to lift — deny the appeal instead."}  http=400
status  -> still pending (a refusal writes nothing)
deny    -> 200 {"status":"denied"}; decided_at set; audit appeal.denied {lift:null}
page    -> "not accepted"

# a really banned member (our own dummy bot user, banned over REST, no gateway)
start   -> 200 BANNED
page    -> chip "banned", the form
submit  -> ?flash=sent, row pending
accept  -> 200 {"status":"accepted"}
after   -> 404 not banned          <-- the ban was actually lifted
audit   -> appeal.accepted {lift:"ban"}
page    -> "accepted on today"
```

The ban was driven with REST only (`PUT /guilds/{id}/bans/{user}` from the
sealed token inside the container) so no second gateway session ever touched the
production bot, and the subject was our own dummy bot user, never a person.

**What the drill does not prove: the OAuth exchange itself.** A real member
sign-in needs a Discord account, and logging one in from this box is what the
standing rule forbids. What is covered by tests: the cookie's signing, its
expiry, its refusal to be read as a staff session, the state allowlist, every
gate, ownership on withdraw, and the page's escaping. What Discord owns: whether
a given member's consent screen goes through — the callback branch for a member
is a redirect to `/appeal` and a cookie, and nothing else.

**Found while drilling:** the guild row for `1565572253624827965` stored its name
as `፧D፧፧r፧. ፧W፧፧i፧፧z፧፧a፧'s server` — a stray U+1367 interleaved into every
other character, from an earlier escaped write. The page rendered it faithfully,
which is how it was noticed. Repaired in place (`replace(name, chr(4967), '')`);
the row is now `Dr. Wiza's server`, 17 characters.

## What the nightly archive carries of the stack itself

The archive held the application's data but not the two things that define how it
runs: `/opt/sloth-bot/docker-compose.yml` (all five containers, their volumes and
env files) and `/opt/sloth-site` (the site's source, which lives in no repository
and exists only as files on the box). A restored box would have had the data and
no recipe for the stack.

Both are in the archive now. The site member is `-C /opt sloth-site` with
`node_modules` and `.next` excluded: 808 KB of source, not the 1.3 GB build tree.
Two guards were added beside the round-trip check, because a backup that quietly
loses the stack definition is the failure that only shows up on the worst day —
`sloth-bot/docker-compose.yml` and `sloth-site/app/page.jsx` must both be listed
in the decrypted archive or the run exits before uploading anything.

A `-C` in tar applies to the names that follow it, so `-C / sloth-site` asks for
`/sloth-site` and fails loudly; the first version of this edit did exactly that and
the run refused to upload rather than shipping a snapshot missing the site.

## Reviewing what was decided

`/api/appeals` is two lists on one route:

```
/api/appeals                   the queue — status pending, newest first
/api/appeals?status=decided    the history — accepted/denied, newest decision first
```

The history carries `decidedBy` and `memberTold` per row, read from the audit
rows (matched on `payload.appealId`, one query over a 90-day window). So the
dashboard can answer "who denied this, and did the person hear about it" without a
SQL session — and a row whose `memberTold` is `blocked`/`unavailable` is a member
whose answer exists only on their own page.

## Filing must not wait for the notices

`POST /appeal/submit` stores the row, stores the evidence, decides the flash —
and then announces **detached**: `void announceAppeal(...).then(log).catch(log)`.
Nothing about the member's response depends on a DM landing, and a slow fan-out
cannot hold a phone.

Two costs are kept off that path:

* the admin list is cached per guild for **two minutes** (`adminCache`,
  `resetAdminCache()` to clear). discord.js v14 cannot fetch members by role —
  `GuildMemberManager.fetch` takes `user`/`users`/`limit`/`query`/`withPresences`
  and nothing else — so finding admins means walking the member list, which is
  not something to do on every filing.
* DMs go **five at a time**, so a large staff does not serialise behind one send
  each, and Discord's DM limits are not what decides who hears.

Measured on the test guild: submit returns `302 → ?flash=sent` in **0.26 s**, and
`portal appeal announced` with its `sent/blocked/total` counts arrives in the log
just after.

## The appeal's audit trail

Five rows, all in `audit_events`, all guild-scoped:

```
appeal.submit     actor = the member        {appealId, surface: portal|discord}
appeal.withdraw   actor = the member        {appealId, surface: portal}
evidence.view     actor = staff             {appealId, evidenceId, bytes}
appeal.accepted   actor = the decider       {appealId, userId, lift: ban|quarantine}
appeal.denied     actor = the decider       {appealId, userId, lift: null}
```

`/api/appeals?id=` reads the decision back **out of that trail** rather than from
a column on the appeal, so the screen cannot claim a decider the trail does not
have: a settled appeal with no row reads `decidedBy: null` and the detail says
*"decided — no audit row found for this decision"* instead of a blank.

`/api/audit` is a different trail (`action_audit`, the Action Center's). An
appeal decision made in the dashboard appears in both; a decision made from the
Discord buttons appears only in `audit_events`, which is why the detail reads
from there — the embed trail is a notification, the audit row is the record.

Two things to remember when driving this by hand: `/api/action` takes the CSRF
field **`csrf`** (not `csrfToken`), and every staff read needs `?guild=` unless
the viewer is staff in exactly one server.

## The DM a banned member gets, and why it goes first

`src/services/security/ban-notice.js` sends one message when the bot bans
someone: the server, the reason as written, `https://app.slothlee.xyz/appeal?s=<guild>`,
who can read it, what they may attach, and that replying does nothing.

**It is sent before `members.ban`, always.** After the ban lands the member
shares no server with the bot and Discord refuses the DM (`50007 Cannot send
messages to this user`) — so a notice sent afterwards would fail for exactly the
people it is for. The ordering is asserted in `test/ban-notice.test.js` against
the real moderation path (`['dm', 'ban']`), not against a mock of the notice.

**A refused DM never stops a ban.** `dmBanNotice` returns `sent` / `blocked` /
`unavailable` and never throws; `performModeration` carries it back as `notice`
so a moderator can see the person was never told. Closed DMs are the common case
and get a single info log line, no stack trace.

**Softban is silent on purpose**: the member is unbanned immediately, so "you
were banned from X" would be a false statement posted at the moment it is false.

**The link focuses the page.** `/appeal?s=<guild>` shows only that server, and
the id is checked against the standing the member actually has — an id for a
server they have nothing in falls back to the full list, so a crafted link can
neither invent a server nor hide the others. Signing in would otherwise drop
which server the link was for, so the id is held in a 15-minute
`sloth_appeal_focus` cookie scoped to `Path=/appeal` (HttpOnly, Secure,
SameSite=Lax) instead of widening the OAuth `next` allowlist beyond `/appeal`.

**What cannot be proven on this box**: delivery to a human inbox. Bots cannot DM
bots, so the live proof covers the text, the link, the cookie and the focused
page; delivery needs a human recipient to say they received it.

## Who is told about an appeal, and who may decide it

The queues on the dashboard are per server: `/api/appeals` is scoped to the
tenant the staff session resolves to, the decision route 404s an appeal id from
any other server, and the evidence download re-checks `staffInGuild`. What was
missing was the part that makes any of that useful — somebody being told.

**An appeal is DM'd to that server's admins, and posted in no channel at all.**
`src/services/security/appeal-notice.js` resolves who "the admin" is with the same
rank logic the dashboard uses — the guild owner plus everyone at or above admin
rank (`staffRoles`, falling back to Discord permissions) — and sends each of them
their own DM. There is no channel post, and no channel setting to get wrong. A
channel is a room anyone who can see it can read; a banned member's written
appeal is a private complaint about that server's own staff, and it belongs in an
inbox addressed to the people who must answer it.

The DM carries the member (name and id), the statement (mentions defused,
backticks escaped, 800 characters), the attachment count, what Accept actually
does for that kind of appeal, and a link opening **that server's** queue. It
carries no buttons: a DM interaction has no guild, and `settleAppeal` is written
against a guild — so the decision is made where decisions are audited, in the
dashboard.

**Filed and DM'd are separate outcomes.** A DM Discord refuses (closed inbox,
`50007`, rate limit, deleted account) must not undo an appeal the member already
sent. Every send is attempted independently, `dmAppealAdmins` counts
`sent`/`blocked`/`total`, `announceAppeal` returns
`{ status: sent | none | failed | noserver, … }` and never throws, and the
portal's flash still says the appeal was sent. When no DM lands the run logs
`Appeal reached no admin — the queue still holds it` with the counts, so a silent
queue is never mistaken for a quiet server. The portal logs
`portal appeal announced` with the same counts on every filing.

The list is capped at 20 admins per appeal so one filing cannot fan out without
limit, and the owner is always included even when the role mapping would give
them nothing — they can always open the dashboard.

**`appealChannelId` no longer routes appeals.** It now means one thing only:
where `/security appeal-panel` posts the Appeal button for quarantined members.
`/setup` labels it *Appeal panel*, and the readiness line says appeals need no
channel at all.

**Who may decide is unchanged.** The dashboard route is tenant-scoped, the
decision 404s an appeal id from any other server, evidence download re-checks
`staffInGuild`, and `settleAppeal` refuses outright when the guild it was handed
is not the appeal's guild — the lift acts on the guild object it is given.

**Proven live** in the test guild: ban the dummy bot user, file from the member
page (`302 → ?flash=sent`), and the bot log answers
`{"notice":{"status":"sent","sent":1,"blocked":0,"total":1}}` — that server has
exactly one admin-ranked member — while `#general` is unchanged at 6 messages
before and after, which is the part that proves the channel path is gone. Then
the appeal rows are deleted, the ban lifted, `0` rows left.


## Telling the member what was decided

`src/services/security/appeal-outcome.js`, called from `settleAppeal` — so both
decision paths (dashboard and the Discord buttons) tell the member exactly once,
after the lift:

```
accepted + ban         "the ban in <server> has been lifted"  + how to rejoin
accepted + quarantine  "you have been released from quarantine"
denied                 "the decision stands", and that asking again is allowed
                       (one at a time, two in six hours, never held against them)
```

Every message names `https://app.slothlee.xyz/appeal`, because a DM is not
guaranteed and the page is.

**The delivery outcome is recorded, not assumed.** `sendDecisionDm` returns
`sent` / `blocked` / `unavailable`; `announceDecision` contains a throw as
`unavailable`; `settleAppeal` writes it into the `appeal.<decision>` audit row as
`memberTold` and returns it as `told`. `/api/action` carries it on the decision
response and `/api/appeals?id=` reads it back, so the detail screen can say:

* *the member was told by DM* — `sent`
* *the member could not be messaged — the answer is on their appeal page* — `blocked` / `unavailable`
* *no record of the member being told* — `null`, i.e. an appeal decided before this existed

**The limit that cannot be engineered away:** a banned member is not in the
server, Discord only lets a bot DM a user it shares a guild with, so an accepted
*ban* appeal's DM usually lands as `blocked` (`50007`) — the ban is lifted and
they are free to rejoin, but nobody has told them in their inbox. A quarantine
*release* always delivers, because that member is still in the server. The page is
the channel that cannot bounce; the dashboard line tells staff which case they are
in instead of letting them assume the person was reached.

## When the decision cannot be DM'd: the rejoin

An accepted ban appeal's DM usually bounces (`blocked`, `50007`): at decision time
the person is not in the server, and Discord only opens a DM with a shared guild.
The rejoin is the one moment that changes, so the closure lives there too.

`tellOnReturn()` runs in the join chain, after the blacklist and screen gates and
before the welcome. It sends one DM — "welcome back, your appeal in <server> was
accepted on <date>, that is why you can rejoin" — when all of these hold:

* the appeal is **accepted** (a denial is not a welcome — a denied member cannot rejoin anyway)
* it was decided in the last **30 days**
* the decision's audit row says `memberTold` was **not** `sent` (someone who already read it is not told twice)

A successful notice writes `appeal.member-told {appealId, userId, via: 'rejoin'}`
with the bot as actor. No bot id, no row: an unattributable audit entry is worse
than none.

This path is **unit-tested only** — nothing in the test fleet can be made to join
a server, so live proof would need a real person being unbanned and invited back.

## Evidence attached to an appeal

A banned member can attach pictures and a clip to their appeal. The feature is
small; the shape is the point, because "a public page that accepts uploads" is a
file host with extra steps.

**Where the bytes live.** `/opt/sloth-bot/evidence` on the host, mounted into the
container at `/var/lib/sloth-evidence`, `root 1000:1000`, mode `700`. Outside
every served path: there is no URL that maps to the directory, and the app never
writes there under a name the web layer knows. One directory per appeal, one file
per attachment, named by the attachment's own uuid.

**What is accepted.** Three pictures (PNG, JPEG, WebP, 5 MB each) and one clip
(MP4, WebM, 25 MB), 29 MB in total. The type comes from the **first bytes**, never
from the upload's declared `Content-Type` and never from the filename — an appeal
page is available to anyone with a Discord account, so both of those are the
client's claims. SVG and GIF are refused by construction (they are not in the
signature table, and an SVG is a script host).

**Who can read it.** Only a staff session, in the guild the appeal belongs to,
through `GET /dashboard/evidence?id=<uuid>`: staff cookie, then `staffInGuild` on
the row's own `guildId`, then the file. The response is
`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`,
`Cache-Control: private, no-store`, and a `sandbox` CSP, so even a file that got
past the sniffer cannot execute on this origin. Every read is audited
(`evidence.view`). The member's own page names the attachments and never links
them; the dashboard's appeal detail lists them with sizes and download links.

**How long it lives.** Withdrawing an appeal deletes the files immediately — the
member ended the conversation. A decision starts a 30-day clock, and a six-hourly
prune (`pruneExpired`, `unref`ed so it can never hold the process open) removes
the bytes and the rows. The nightly archive does **not** carry this directory on
purpose: it is third-party media with no archival obligation, and copying it every
night would multiply the uploads by the retention window.

**nginx.** Everything on `app.slothlee.xyz` keeps the 8 MB body cap. One exact
location — `location = /appeal/submit` — gets 30 MB, because a 25 MB clip plus
three pictures plus multipart framing does not fit in 8. A larger body anywhere
else is still refused by nginx before it reaches Node.

**What the tests caught, and what the drill caught.** The first version named the
file with one id and let Postgres generate another for the row, so every
attachment would have been a row pointing at nothing; the storage test compares
the row against the filesystem and failed it. The drill caught the other one: a
successful submission *with files* redirected to `flash=unknown`, because the
flash started as `unknown` for the failure paths and nothing overwrote it on
success — the appeal was filed, the page said it had not been.

**Proven live, through nginx** (`--resolve app.slothlee.xyz:443:127.0.0.1`, so
the real vhost and the real body cap were in the path):

```
submit 2 files -> 302 ?flash=sent        rows 2, both real files on disk
download (staff) -> 200, attachment, sha256 matches the row, both files
download (no cookie) -> 302 /login
download (member cookie) -> 302 /login
submit an .html dressed as .png -> 302 ?flash=badevidence, no second appeal row
cleanup -> 0 rows, 0 files
```

## DNS: why the box stopped resolving twice in one day

`systemd-resolved` answered `SERVFAIL` (rcode 2) to **every** query while
`unbound` on `127.0.0.1` answered correctly. The journal names the cause:

```
systemd-resolved: DNSSEC validation failed for question com IN DS: no-signature
systemd-resolved: DNSSEC validation failed for question discord.com IN A: no-signature
```

`com` is a signed zone. A resolver that answers its DS query without a signature
is either broken or stripping DNSSEC — and a validating resolver must then fail
closed, which takes the whole box with it: containers up, bot in a restart loop,
mail unable to resolve an MX.

The resolver was validating against **Hetzner's plain resolvers**, because
`/etc/netplan/50-cloud-init.yaml` listed them for `eth0`
(`2a01:4ff:ff00::add:2`, `2a01:4ff:ff00::add:1`). Link DNS outranks the global
setting, so `DNS=127.0.0.1` in `resolved.conf` was never being used.

Fixed at the source: `eth0` now names only `127.0.0.1`. Applied at runtime with
`resolvectl dns eth0 127.0.0.1` (never `netplan apply` on a live mail host over
SSH — it can bounce the interface) and written into the netplan file for the
next boot; the backup is `/root/netplan.pre-dnsfix.<epoch>`.

Verified after the change:

```
getent hosts discord.com        → 162.159.135.232 …
getent hosts mail.slothlee.xyz  → 2a01:4f9:c013:dab1::1
resolvectl query dnssec-failed.org → DNSSEC validation failed: missing-key   (still validating)
resolvectl query --type=TLSA _25._tcp.mail.slothlee.xyz
  → 3 1 1 d931…2c50b   (DANE material intact, via DNS, 14.7 ms)
```

`dnssec-failed.org` still failing is the point: the fix did not turn validation
off, it pointed it at a resolver that actually returns signatures.

The watchdog now repairs the class rather than the symptom: when resolution
fails it first points the link at `127.0.0.1` (skipping that if it already does)
and then restarts `systemd-resolved` to clear the cached validation failure.
A restart alone works only until the next signature-stripped answer.

### Capturing a snapshot from the dashboard

`POST /api/action` `kind=structure_snapshot` — one press, no card needed on the
server side (the screen still shows one, because retention can prune older
on-demand snapshots and that deserves a sentence). It runs the same
`createGuildSnapshot` as `/backup create`, so the module gate, kill switch,
read-only mode and the money gate all apply, and the audit row is `snapshot.on_demand`
plus `dashboard.action`.

Live check on a guild with no snapshots:

```
before:   rows 0
press:    http=200 {"outcome":{"status":"saved","counts":{"roles":2,"categories":2,"channels":2}}}
after:    rows 1 readable 1
on disk:  on_demand | user:1411142904604528673 | first from the dashboard | 7b7a949208d8ff79
```

The last column is the point: a dashboard capture stores its key fingerprint, so
it is visible to the restore straight away — the 82 retired rows are history, not
the new normal.
### Reading the deliverability reports, instead of just asking for them

`_dmarc.slothlee.xyz` and `_smtp._tls.slothlee.xyz` both name an address to send
reports to (`rua=mailto:tibs@slothlee.xyz`), and until 2026-10-31 nothing read
them. The first evidence that a provider could not deliver was an audit months
later, or a user asking why mail from a client never arrived.

A cron cannot fix this by polling: this server has no IMAP — only SMTP in on
2525 and the web app on 8080 — so nothing outside the process can see a report
without a human's browser session. The report is therefore parsed where the
bytes already are: `src/core/reports.rs`, called from the delivery path in
`main.rs` right after a message is stored.

How it behaves:

* **Sniff** — the first 16 KB of the message only. A report arrives as
  `multipart/report` and only the *inner* part says `application/tlsrpt+gzip`, so
  looking at the outer headers alone finds nothing (that was the first version,
  and it silently matched zero reports).
* **Parse** — SMTP TLS-RPT as JSON (Google's format), DMARC aggregate as XML,
  both gzip- or zip-wrapped or bare. Bounded at 8 MB per message and 4 MB per
  decompressed payload; a report that cannot be parsed is logged at `info` and
  dropped. A wrong alarm is worse than a missing one.
* **Record** — one JSON line per report in `data/reports.jsonl`, which is in the
  nightly archive. This is the historical record; the alert is the interruption.
* **Alert** — only when `failures > 0`, mailed from `postmaster@slothlee.xyz` to
  `roles.owner` (config.yml), because a bounce needs somewhere real to go. The
  parse and the alert run on their own thread so the SMTP transaction never waits.

Live proof, on this box, with a synthetic failing TLS-RPT report posted through
the real inbound path:

```
before:   records 0
send:     TLS-RPT, sts policy, 9 ok / 2 failed (certificate-expired)
after:    records 1
  {"kind":"tls-rpt","domain":"slothlee.xyz","total":11,"failures":2,
   "notes":["sts: 2 failed (certificate-expired)"],"reporter":"Sloth Probe"}
app log:  [SMTP] DKIM: pass for <postmaster@slothlee.xyz>
          [SMTP] Email … queued for user 'tibs'
ordinary mail sent afterwards: no new record
```

One caveat when checking by hand: a `curl` **from this box** to
`https://app.slothlee.xyz` or `https://slothlee.xyz` returns 403 with
`cf-mitigated: challenge` — Cloudflare challenges the mail host's own traffic to
its proxied hostnames. That is not an outage. Check the origin instead
(`http://127.0.0.1:3100/`, `http://127.0.0.1:3200/login`) or check from another
machine.

Check it by hand:

```
docker exec openneutron tail -5 /usr/src/app/data/reports.jsonl
docker logs openneutron 2>&1 | grep '\[reports\]' | tail
```

#### The two defects the first real report exposed

Both were worse than the missing feature, and neither was visible until a
message had to be signed *and* verified by this server.

**Relaxed body canonicalization deleted indentation.** `canonicalize_body_relaxed`
split each line on whitespace and rejoined it with single spaces, so `"  - item"`
became `"- item"`. Signing and verifying shared the mistake, so our own mail
verified here and failed everywhere else — a message signed by this server was
unverifiable at every other receiver. Now RFC 6376 §3.4.4 is implemented as
written: a run of spaces/tabs inside a line collapses to one space (a run at the
start of the line becomes one space, it is not removed), trailing whitespace goes,
trailing empty lines go, one final CRLF. The RFC's own example is a test:
`" C \r\nD \t E\r\n\r\n\r\n"` → `" C\r\nD E\r\n"`.

**Verification read only the first DKIM-Signature header.** A message can carry
several — this server's, rspamd's, a forwarder's. Judging it on whichever came
first meant a valid signature sitting next to an unverifiable one was ignored,
and own-domain mail was refused with `body hash mismatch` while holding a
perfectly good signature. RFC 6376 §6.1 evaluates all of them and passes if any
passes; that is what `verify()` does now.

Two smaller protocol faults surfaced with them:

* `MAIL FROM:<>` was refused as an invalid address. That is the null return path
  (RFC 5321 §4.5.5) and it is how every bounce arrives, so no DSN ever reached a
  user — mail that failed at the far end simply vanished — and each Postfix
  notification became a second bounce. Empty return path is now accepted, and
  only that: `MAIL FROM:<a@b>` is still validated.
* The receiving side truncated the last CRLF of every message ("the terminator
  is `\r\n.\r\n`" — but the leading `\r\n` belongs to the last line of the
  message, not to the terminator). Harmless to relaxed canonicalization, fatal
  to any `c=simple` signature sent to us.

**What that first reading of the signatures got wrong.** An earlier version of
this page said rspamd's second signature carried a body hash matching no
canonicalization of the message, and left it as an open question. It was the
checker that was wrong, not rspamd. Once our own canonicalization was fixed, the
same message signed here verifies under an independent RFC 6376 implementation
written from scratch (`proofs/dkim-independent-check.py`: public key from DNS,
RSA check by `cryptography`, no code shared with the server):

```
signature 1: d=slothlee.xyz s=mail c=relaxed/relaxed
  body hash signed   cGf1X4dtw5sBL96llGe4PtoFq9NcCwqTrxciSbHr35k=
            computed cGf1X4dtw5sBL96llGe4PtoFq9NcCwqTrxciSbHr35k=  MATCH
  rsa-sha256 PASS — an independent implementation agrees with the server
```

That value is exactly the hash rspamd was computing all along; our signer was
the only party in the building producing a different one, which is also why
rspamd stopped adding a second signature once ours became valid — the message now
carries one signature, and it is the server's own.

To re-run it, capture what the server transmits (an SMTP sink on `127.0.0.1:25`
inside the container) or any message it sent, and:

```
python3 proofs/dkim-independent-check.py /path/to/message.eml
```

### root@ is where the MTA complains

Postfix addresses its own failure notices to `root@$myorigin`, and until now that
address was not a recipient here: every queue problem, undeliverable bounce and
watchdog complaint was refused with `550` and became a second bounce, so operator
mail reached nobody. `root` now routes like `postmaster@`, `abuse@` and
`hostmaster@` — to `roles.owner` — and the recipient map (which is generated from
the same list) carries it, so the front door accepts it before any data is
transferred.

```
printf "Subject: operator probe\nFrom: postmaster@slothlee.xyz\nTo: root@slothlee.xyz\n\nprobe\n" \
  | sendmail -f postmaster@slothlee.xyz root@slothlee.xyz
→ postfix/smtp: to=<root@slothlee.xyz> … status=sent (250 2.0.0 OK)
→ app: Email received for: ["root@slothlee.xyz"] … queued for user 'tibs'
```

The null return path fix above is what makes this work end to end: a notification
carries `MAIL FROM:<>`, which used to be refused at `MAIL FROM` before the
recipient was even considered.

## The money ledger

Two tables carry what someone bought: `subscriptions` (one row per server or mailbox) and
`billing_deliveries` (every webhook delivery, unique on provider + delivery id). Everything
that moves entitlement goes through `src/services/billing/ledger.js` — it writes the row and
the `guild_settings` dates in one transaction, so the gate (`entitlementFor`, which reads
`paid_until` / `trial_ends_at`) and the ledger cannot disagree.

**Where the truth is.** `subscriptions`, not the settings columns. The settings dates are the
derived copy the hot path reads; if the two ever disagree, the row is right and a re-apply is
safe (it is idempotent per delivery id).

**What the states mean.** `trial`, `active`, `past_due` (the next charge failed — access
continues), `cancelled` (keeps the period already paid for, then expires), `expired`. A guild
with no row at all predates billing and is never gated on money.

**Record a payment by hand** while the merchant account is blocked — mark it `manual` so
nobody later mistakes it for a provider charge:

```
docker exec -w /app sloth-bot node -e "
const { applySubscription } = await import('/app/src/services/billing/ledger.js');
console.log(await applySubscription({
  scope: 'guild', guildId: '<guild id>', plan: 'bot',
  state: 'active', periodStart: new Date(), periodEnd: new Date(Date.now() + 30*864e5),
  provider: 'manual', amountMinor: 700, currency: 'GBP',
}));
"
```

**Prove it still works**, on production, in one command — it signs three deliveries with the
real secret inside the container, checks applied / duplicate / stale, and deletes what it
created:

```
docker cp /root/ledger-drill.mjs sloth-bot:/app/ && docker exec -w /app sloth-bot node /app/ledger-drill.mjs
```

**Do not quote a "collected" figure from this table.** It holds one period per subscription, so
a long-lived subscription's later charges are not in it. `billingSnapshot` therefore reports
`currentPeriodValueMinor` — the value of the periods in force. A real revenue figure needs a
payments record, which comes with the merchant account.
