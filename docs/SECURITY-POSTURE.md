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
- **`mail` and `owner` have no edge at all** by construction. Their whole shield is
  nginx + fail2ban, which is effective per address and useless against a distributed
  attempt — 1 000 addresses × 5 tries each is 5 000 guesses with no ban. For
  `mail` that is the login form, so **Turnstile on `/api/auth/login`** is the fix
  worth having, and it is the one thing here that needs the dashboard.
- **HSTS preload is declared but never submitted**; `preload` in the header does
  nothing until the domain is on the list.
