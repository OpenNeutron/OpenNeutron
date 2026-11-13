# OpenNeutron API Documentation

This document outlines the API endpoints, request/response DTOs, and JSON formats for the OpenNeutron application.
*ALL api andpoints have a /api/ prefix*

## Authentication

Every endpoint falls into one of three access levels, enforced centrally by the router:

| Level | Requirement |
|---|---|
| **Open** | No credentials. Only 'POST /auth/login' and 'POST /user/register'. |
| **Authenticated** | A valid, unexpired JWT in the 'Authorization: Bearer <token>' header, belonging to an existing account. |
| **Admin** | An authenticated session whose account currently has 'is_admin: true'. Every '/admin/*' route. |

A valid session by itself grants **no** administrative access: an authenticated
non-admin calling any '/admin/*' route receives '403 forbidden'. Privilege is read
from the stored account on every request, so revoking 'is_admin' takes effect
immediately rather than at the next login.

Tokens expire one hour after issue. A token is also rejected if it was issued
before an administrator last reset that account's credentials, so an admin
password reset immediately terminates the account's existing sessions.

## DTOs Overview

- **Base64 Usage**: Fields containing binary data (e.g., 'public_key', 'encrypted_private_key', 'data' in email DTOs) are base64-encoded strings.
- **Password handling**: All password operations are performed client-side. The client sends a password token (e.g. a client-side hash); the server stores and compares this token **directly** - no server-side re-hashing is applied.
- **Error Responses**: All endpoints can return 'ErrorResponse' on failure.

### Common DTOs

#### ErrorResponse
```json
{
  "error": "string",
  "code": "string"
}
```

Codes shared by many endpoints:

| Status | Code | Meaning |
|---|---|---|
| 401 | 'unauthorized' | Missing, invalid, expired, or administratively revoked token. |
| 403 | 'forbidden' | Authenticated, but the route requires administrator privileges. |
| 413 | 'body_too_large' | Request body exceeds 'server.max_request_body_bytes' (25 MiB by default). |
| 422 | 'invalid_json' | Body is not valid JSON for this endpoint. |

#### MessageResponse
```json
{
  "message": "string"
}
```

## Endpoints

### Open Routes (No Auth Required)

#### POST /auth/login
**Request**: 'LoginRequest'
```json
{
  "username": "string",
  "password": "string"
}
```
**Response**: 'LoginResponse'
```json
{
  "token": "string",
  "force_reset": false,
  "is_admin": false,
  "username": "string",
  "public_key": "base64-string|null",
  "unread_emails": 0,
  "salt": "hex-string",
  "encrypted_private_key": "base64-string|null"
}
```

> **'force_reset'**: When 'true', the account has no password yet and the presented credential was its one-time **setup token**. The session is intended solely for completing 'POST /user/setup'. This is always 'true' for a freshly provisioned account.
>
> **Failures**: every rejected login returns '401' with code 'invalid_credentials' and the same message, whether the account exists or not - the endpoint deliberately does not reveal which mailboxes exist. After 10 failed attempts against one account, or 100 from one source address, within 15 minutes, further attempts return '429 too_many_attempts' until the window elapses.
>
> **Pending accounts**: a self-registered account that is still waiting for
> approval returns '403' with code 'account_pending' and no token. The check runs
> *after* the password is verified - a correct password on a queued account is
> told it is queued, not that it is wrong - and *before* any token is minted, so
> approval cannot be bypassed by logging in. This failure is not counted against
> the rate limiter.
>
> **'salt'**: A per-user random hex string (32 hex chars / 16 bytes of entropy) generated at account creation time. The client uses this together with the user's password to derive the AES key that encrypts the private key. Always returned on successful login regardless of 'force_reset'.
>
> **'encrypted_private_key'**: The user's RSA private key, AES-256 encrypted client-side. 'null' for admin-created accounts that have not yet completed setup.

#### POST /user/register
Self-service account creation. **Disabled by default**: unless
'server.allow_open_registration' is 'true' in 'config.yml', this endpoint returns
'403' with code 'registration_disabled' and accounts must be created by an
administrator instead. Usernames are restricted to lowercase letters, digits,
'.', '_' and '-', must start and end with a letter or digit, and are at most 64
characters. 'public_key' must be a base64 SPKI RSA key that actually parses;
anything else is rejected with '400 invalid_public_key'.

**Request**: 'CreateUserRequest'
```json
{
  "username": "string",
  "password": "string",
  "public_key": "base64-string",
  "encrypted_private_key": "base64-string"
}
```
> 'password' is the client-side password token (e.g. a hash computed in the browser). The server stores and compares it as-is.
> 'encrypted_private_key' is the RSA private key encrypted client-side with AES-256 using a key derived from the password and the salt (returned on login).
>
> When 'server.registration_requires_approval' is on, an 'invite_code' admits the
> account immediately and a signup **without** one is created in a *pending*
> state: it exists, it cannot sign in, and an administrator has to approve it.
> A code that is presented but does not claim is rejected with
> '403 invite_required' rather than queued, so a typo is not mistaken for a
> request.

**Response** (201, admitted): 'MessageResponse'
```json
{
  "message": "User created"
}
```

**Response** (202, queued for approval)
```json
{
  "pending": true,
  "message": "Your account is waiting for approval"
}
```
> A 202 carries no session token: the account cannot sign in until it is
> approved. Do not treat it as an error.

### Secure Routes (JWT Required)

#### GET /user/me
#### GET /me
**Request**: None
**Response**: 'UserDto'
```json
{
  "uid": "string",
  "username": "string",
  "email": "string",  # user email (username@domain)
  "user_created": 1234567890,
  "last_login": 1234567890,
  "email_count": 0,
  "is_admin": false
}
```

#### POST /user/setup
Used to finish an account. Two states reach this endpoint:

1. **No password yet** — the account was provisioned by an administrator. The caller defines the password and public key ('force_reset: true' in the login response).
2. **Password but no keys yet** — a self-registered account. Its password was chosen at registration, so the 'password' field is accepted but **ignored**: this endpoint is not a password reset, and letting it write one would turn a session token into a credential change.

An account that already has keys is configured; re-keying it here returns '409'. All cryptographic operations are performed client-side - 'password' is a hash string and 'public_key' is base64-encoded.

**Request**: 'SetupPasswordRequest'
```json
{
  "password": "string",
  "public_key": "base64-string",
  "encrypted_private_key": "base64-string"
}
```
> 'password' is the client-side password token, stored as-is when the account had none. 'encrypted_private_key' is the RSA private key encrypted client-side with AES-256.
**Response**: 'MessageResponse'
```json
{
  "message": "Password set"
}
```

> **Flow**:
> 1. Admin creates the user via 'POST /admin/users'. The response carries a one-time 'setup_token', which the admin passes to the new user out of band. It is shown only in that response.
> 2. The user logs in with their username and **the setup token as the password** -> receives a token + 'force_reset: true'. No other password is accepted.
> 3. Client calls 'POST /user/setup' with the Bearer token, chosen password hash, and public key.
> 4. The server stores the credentials and invalidates the setup token; subsequent logins use the real password and return 'force_reset: false'.

### Admin Routes (JWT + 'is_admin' Required)

Every route below requires an administrator session. A valid non-admin token
receives '403' with code 'forbidden'.

#### GET /admin/users
**Request**: None
**Response**: 'AdminUsersResponse'
```json
{
  "users": [
    {
      "uid": "string",
      "username": "string",
      "user_created": 1234567890,
      "last_login": 1234567890,
      "email_count": 0,
      "is_admin": false
    }
  ],
  "total": 1
}
```

#### POST /admin/users
Creates a new user account with no password but with a one-time setup token. The user presents that token as their password on their first (and only that) login, then defines a real password via 'POST /user/setup'.

**Request**: 'AdminCreateUserRequest'
```json
{
  "username": "string",
  "is_admin": false
}
```
> **'is_admin'** is optional and defaults to 'false'. Pass 'true' only to create another administrator.

**Response**: 'AdminCreateUserResponse'
```json
{
  "message": "User created",
  "force_reset": true,
  "setup_token": "64-hex-chars"
}
```

> **'setup_token'** is a password-equivalent secret returned **only here** - it cannot be read back later. Deliver it to the new user over a channel you trust. If it is lost, reset the account with 'POST /admin/users/credentials'.
>
> **'force_reset'** is always 'true' here - it confirms that the created account has no password and the user will be required to define one on first login.

#### DELETE /admin/users
Deleting your own account ('409 cannot_delete_self') or the last remaining administrator ('409 last_admin') is refused, so the server cannot be locked out of administration.

**Request**: 'AdminDeleteUserRequest'
```json
{
  "username": "string"
}
```
**Response**: 'MessageResponse'
```json
{
  "message": "User deleted"
}
```

#### POST /admin/users/credentials
Overwrite a user's password, public key, or both. Omit either field to leave it unchanged. At least one field must be provided.

**Request**: 'AdminSetCredentialsRequest'
```json
{
  "username": "string",
  "password": "string",
  "public_key": "base64-string",
  "encrypted_private_key": "base64-string"
}
```
> All three credential fields are optional, but at least one must be present. 'password' is the client-side password token stored as-is. 'encrypted_private_key' is the RSA private key encrypted client-side with AES-256.
>
> Passing an **empty** 'password' clears the password and returns the account to the setup state with a fresh 'setup_token' - use this to re-provision a user who lost theirs. Passing any password change also revokes every session token already issued for that account.

**Response**: 'AdminResetResponse'
```json
{
  "message": "Credentials updated",
  "setup_token": "64-hex-chars"
}
```
> **'setup_token'** appears only when an empty password put the account back into the setup state; it is omitted otherwise.

#### POST /admin/users/admin
Grant or revoke admin privileges for a user.

**Request**: 'AdminSetAdminRequest'
```json
{
  "username": "string",
  "is_admin": true
}
```
> Set 'is_admin' to 'false' to demote an admin back to a regular user. Demoting the last remaining administrator is refused with '409 last_admin'.

**Response**: 'MessageResponse'
```json
{
  "message": "Admin status updated"
}
```

#### GET /admin/disk-usage
**Request**: None
**Response**: 'AdminDiskUsageResponse'
```json
{
  "users": [
    {
      "username": "string",
      "email_count": 0,
      "disk_usage_bytes": 0
    }
  ]
}
```

#### GET /admin/pending
Accounts created by signup that are waiting for approval (`data/pending_users.json`).

**Request**: None
**Response**
```json
{
  "entries": [
    {
      "username": "string",
      "requested_at": 1234567890,
      "ip": "203.0.113.9",
      "user_agent": "string"
    }
  ],
  "total": 1
}
```

#### POST /admin/pending/approve
Let a queued account sign in. Removing the queue entry *is* the activation;
nothing else about the account changes, so the person signs in with the password
they chose at signup.

**Request**
```json
{
  "username": "string"
}
```
**Response**
```json
{
  "username": "string",
  "approved": true
}
```
> '404 not_pending' if the account is not queued, '404 user_not_found' if it was
> deleted while queued (the stale entry is dropped in that case).

#### POST /admin/pending/deny
Delete a queued account and its request. Same refusals as 'DELETE /admin/users'
('cannot_delete_self', 'last_admin'). Denying is the safe default for an
unapproved signup: the account already occupies its username and, until the
recipient sync runs, would be a valid recipient.

**Request**
```json
{
  "username": "string"
}
```
**Response**: 'MessageResponse'

#### POST /email/get
**Request**: 'GetEmailRequest'
```json
{
  "uid": 12345678901234567890
}
```
**Response**: 'EmailBytesResponse'
```json
{
  "uid": 12345678901234567890,
  "data": "base64-encoded-email-bytes"
}
```

#### POST /email/bulk
**Request**: 'GetEmailsBulkRequest'
```json
{
  "uids": [12345678901234567890, 12345678901234567891]
}
```
**Response**: 'EmailsBulkResponse'
```json
{
  "emails": [
    {
      "uid": 12345678901234567890,
      "data": "base64-encoded-email-bytes"
    }
  ]
}
```

#### POST /email/list
**Request**: None
**Response**: 'EmailUidsResponse'
```json
{
  "uids": [12345678901234567890, 12345678901234567891]
}
```

#### POST /email/delete
**Request**: 'DeleteEmailRequest'
```json
{
  "uid": 12345678901234567890
}
```
**Response**: 'MessageResponse'
```json
{
  "message": "Email deleted"
}
```

#### POST /email/sent/delete
Deletes one of the caller's own sent copies (a uid from `/email/sent/list`). The recipient's copy is
a separate message and is not touched. Recorded in the deletion log like an inbox delete.

**Request**: 'DeleteEmailRequest'
```json
{
  "uid": 12345678901234567890
}
```
**Response**: 'MessageResponse' (`404 email_not_found` when the uid is not one of the caller's sent copies)
```json
{
  "message": "Email deleted"
}
```

#### POST /email/trash
Moves one of the caller's messages (received or sent) to the trash. It leaves its folder's list
endpoints but stays readable through `/email/get`, `/email/bulk` and the sent equivalents.
Deleted for good after 30 days. Not recorded in the deletion log until it is deleted for good.

**Request**: `{ "uid": "..." }` · **Response**: `{ "message": "Moved to trash", "uid": ..., "kind": "inbox" | "sent" }`
(`404 email_not_found` when the uid is not the caller's)

#### POST /email/restore
Takes a message out of the trash, back to the folder it came from.

**Request**: `{ "uid": "..." }` · **Response**: `MessageResponse` (`404 not_in_trash` when it is not there)

#### POST /email/trash/list
The caller's trash, newest first. Records whose message is already gone are left out.

**Response**: `{ "items": [{ "uid": ..., "kind": "inbox", "trashed_at": 1793..., "deletes_at": 1796... }], "retention_days": 30 }`

#### POST /email/trash/empty
Deletes everything in the caller's trash for good (blob, lists, groups, then a `deleted` entry in the
deletion log for each).

**Response**: `{ "deleted": 3, "failed": 0 }`

Permanent deletes (`/email/delete`, `/email/sent/delete`) also clear a message's trash record.

#### POST /email/set
**Request**: 'SetEmailBytesRequest'
```json
{
  "uid": 12345678901234567890,
  "data": "base64-encoded-email-bytes"
}
```
**Response**: 'MessageResponse'
```json
{
  "message": "Email updated"
}
```

#### POST /email/recent
Returns the most recent email UIDs for the authenticated user, newest first, with offset-based pagination. All email IDs are returned in arrival order (oldest-first internally); this endpoint reverses that and applies 'offset'/'limit'.

**Request**: 'GetRecentEmailsRequest'
```json
{
  "offset": 0,
  "limit": 20
}
```
**Response**: 'EmailUidsResponse'
```json
{
  "uids": [12345678901234567891, 12345678901234567890]
}
```

#### POST /email/send
Sends a raw email to each recipient's mail server. The server performs STARTTLS opportunistically if advertised. No encryption is applied server-side; the bytes are forwarded as-is.

**Request**: 'SendEmailRequest'
```json
{
  "to": ["bob@remote.com"],
  "data": "base64-encoded-raw-email-bytes"
}
```
> **'from', 'smtp_host' and 'smtp_port' are accepted but ignored.** The envelope
> sender is always '<your-username>@<server-domain>', so no account can send mail
> as another user or as a third-party domain, and delivery targets are resolved
> from each recipient's own MX record rather than from the request - a
> caller-supplied host would let any user aim the server's SMTP client at
> arbitrary internal addresses.
>
> At most 100 recipients per request ('400 invalid_recipients' beyond that).

**Response**: 'MessageResponse'
```json
{
  "message": "Email sent"
}
```
> Returns '502 smtp_error' if no recipient could be delivered to; a partial
> success reports how many recipients were reached.

#### POST /email/read
Mark a single email as read.

**Request**: 'MarkEmailReadRequest'
```json
{
  "uid": 12345678901234567890
}
```
**Response**: 'MessageResponse'
```json
{
  "message": "Email marked as read"
}
```

#### POST /email/unread
Mark a single email as unread (reverse of '/email/read').

**Request**: 'MarkEmailReadRequest'
```json
{
  "uid": 12345678901234567890
}
```
**Response**: 'MessageResponse'
```json
{
  "message": "Email marked as unread"
}
```

#### POST /email/star
Set or clear the starred flag on an email.

**Request**: 'SetEmailStarredRequest'
```json
{
  "uid": 12345678901234567890,
  "starred": true
}
```
> Set 'starred' to 'false' to unstar.

**Response**: 'MessageResponse'
```json
{
  "message": "Email starred"
}
```

---

### Email response shape (updated)

All endpoints that return email data ('/email/get', '/email/bulk') now include a 'received_at' field:

**'EmailBytesResponse'**
```json
{
  "uid": 12345678901234567890,
  "data": "base64-encoded-aes-ciphertext",
  "message_key": "base64-encoded-rsa-encrypted-aes-key",
  "received_at": "2026-03-27T14:05:00Z",
  "e2ee": true
}
```

> **'data'**: AES-256-GCM ciphertext of the email body, base64-encoded. Format: 'nonce (12 bytes) || ciphertext || GCM tag (16 bytes)'. When 'secure == false' (no public key was registered for this user), this is the raw plaintext bytes.
>
> **'message_key'**: RSA-OAEP encrypted AES-256 key, base64-encoded. Decrypt this with the user's RSA private key to obtain the AES key, then use the AES key to decrypt 'data'. 'null' when 'secure == false'.
>
> **'e2ee'**: 'true' when the blob was client-side encrypted (stored as-is via 'OPNTRN E2EE' or via the sender's 'e2ee: true' flag). 'false' when the server applied its own at-rest encryption. The client uses this flag to determine the source of the key material: for E2EE emails the keys were generated client-side by the sender; for server-encrypted emails the server generated the keys using the recipient's stored public key.
>
> Emails also carry a 'starred' boolean flag (set via 'POST /email/star'). The flag is **not** included in 'EmailBytesResponse' - it is a server-side metadata flag only. To star or unstar an email, use 'POST /email/star'.

#### Disappearing messages

A message can be told to delete itself. Two rules exist, independently or together:

- **on read** - the stored copy is deleted the moment its body is served.
- **on a timer** - the stored copy is deleted after N seconds, read or not (60 s to 90 days).

'EmailBytesResponse' carries four fields for them:

```json
{
  "ephemeral": "read | expire",
  "expires_at": 1793152758,
  "deleted": true,
  "from": "alice@example.com"
}
```

- **'ephemeral'** - omitted for ordinary mail. '"read"' means the message deletes itself when opened, '"expire"' means it has a deadline.
- **'expires_at'** - unix seconds, only for the timer rule.
- **'deleted'** - **true only when serving this very response deleted the message.** A failed delete reports 'false' and leaves the message in place; a client must not show "deleted" for any other reason.
- **'from'** - the plaintext sender, so a preview whose body is withheld can still be labelled.

Enforcement is deliberately server-side:

- **'/email/bulk' never returns the body of a message that deletes on read.** 'data' is empty and 'message_key' is 'null' for those uids; the row can still be listed (labelled "Disappearing message") but the only door to the content is '/email/get', which deletes as it hands it over. A preview fetch therefore cannot consume or retain the message.
- **'/email/get' deletes before answering.** The blob, the user's index entry and any group membership are removed first; if the blob cannot be removed the response says 'deleted: false' instead of claiming the copy is gone.
- **A second open is '404' 'email_not_found'.**
- **Timers are swept in the background** (every 60 s), including for messages nobody opened.
- **Only local mailboxes are covered.** A copy at another provider is that provider's to keep: 'ephemeral' is applied to recipients on this server and ignored for anyone else.

Deletion scope: the **recipient's** copy is deleted. The sender's own copy in 'sent_emails' stays, and the sender gets a read receipt instead, via 'POST /email/ephemeral' (below).

#### 'POST /email/ephemeral'

Reports the state of disappearing messages from either side. Authenticated; answers only for messages the caller owns.

```json
// request - ids as strings or numbers; a u128 does not survive a JS number,
// so the web client sends strings.
{ "uids": ["60349880548505824788395930780103824333"] }
```

```json
// response
{
  "items": [
    { "uid": "60349880548505824788395930780103824333",
      "state": "armed",              // or "read"
      "expires_at": 1793152756,      // timer, when it has one
      "read_at": 1793151895,         // set once the recipient opened it
      "recipient": "bob" }           // named once it has been read
  ]
}
```

- '"armed"' - still waiting: the recipient has not opened it (or the timer is running).
- '"read"' - the recipient's copy is gone; the record is a 30-day receipt kept for the sender.
- A uid the caller does not own is simply absent from 'items'.

---

### Sealed notes (recipients on other providers)

A message delivered by SMTP belongs to the recipient's provider, so 'ephemeral'
cannot delete it. For those recipients the body is not delivered at all: it is
PGP-encrypted on the client, stored here, and announced by a link. Opening the
link hands the armour over and deletes it in the same write.

The server cannot read a note. It stores ciphertext and a token, nothing else.

#### 'POST /note/create'  (JWT)

```json
{
  "recipient": "someone@startmail.com",
  "subject": "Re: Lol",
  "armored": "-----BEGIN PGP MESSAGE-----...",
  "deletes_on_read": true,
  "expires_in_seconds": 604800,
  "mode": "pgp"          // or "passphrase"
}
```

```json
{
  "token": "hK3…32 chars…",
  "url": "https://mail.example.com/api/note?t=hK3…",
  "expires_at": 1793753956,
  "deletes_on_read": true
}
```

- 'armored' must be PGP armour; anything else is refused ('400 not_armored')
  rather than stored as if it were sealed.
- Body only: 512 KB cap, no attachments ('413 note_too_large').
- 'expires_in_seconds' is clamped to 60 … 90 days. Every note gets a deadline
  even when the sender picked "delete when read", so a note whose notification
  never arrives cannot sit on disk forever — the client supplies 7 days.
- At most 50 unopened notes per account ('429 too_many_notes').
- 'mode': '"pgp"' (default) — armour locked to the recipient's key, cleared the
  moment it is served. '"passphrase"' — symmetric armour the page decrypts in
  the browser; a wrong phrase must not burn the note, so a fetch does not clear
  it: 'POST /note/burn' does, after a successful decrypt, or the timer. The link
  stops working after 5 fetches ('410 already_opened').

#### 'GET /note?t=<token>'  (open)

Returns an HTML page: who sent it, when it closes, and a button. It deliberately
does **not** consume the note — mail providers and security scanners fetch links,
and a fetched link must not burn the message before the recipient sees it.
Answered with '404' (unknown token) or '410' (already opened or expired).
'HEAD' returns the status without a body.

#### 'POST /note/open'  (open)

```json
{ "token": "hK3…" }
```

```json
{ "armored": "-----BEGIN PGP MESSAGE-----...", "from": "tibs",
  "subject": "Re: Lol", "recipient": "someone@startmail.com",
  "created_at": 1793149956, "deleted": true }
```

- The ciphertext is cleared and served under one lock: two simultaneous opens
  cannot both receive the body.
- '410 already_opened' on the second call, '410 expired' after the deadline,
  '404 no_such_note' for a token that never existed.
- The record (without the body) is kept so the sender can be told what happened.

#### 'POST /note/burn'  (open)

```json
{ "token": "hK3…" }
```

Clears a passphrase note once its text is on screen. Harmless if called twice,
and returns '200 {"burned": true}' either way; the note then reports
'"opened"' and a second fetch is '410'.

#### 'POST /note/revoke'  (JWT)

```json
{ "token": "hK3…" }
```

Withdraws a note before it is read: the armour is cleared and the link stops
working (its page reports "withdrawn", 'open' is '404'). '200 {"revoked": true}'
on success; '409 not_revocable' when the note is already read, already withdrawn,
or not the caller's — one answer for all three, so this cannot be used to probe
which tokens exist.

#### 'POST /note/status'  (JWT)

```json
{ "tokens": ["hK3…", "Zq9…"] }
```

```json
{ "notes": [ { "token": "hK3…", "state": "sealed",
               "subject": "Re: Lol", "recipient": "someone@startmail.com",
               "mode": "passphrase", "created_at": 1793149956,
               "opened_at": null, "expires_at": 1793753956 } ] }
```

- '"sealed"' - waiting; '"opened"' - link used, body gone; '"expired"' - timer
  won; '"revoked"' - withdrawn by the sender before it was read.
- Only the owner's notes are returned; someone else's token is absent, not
  refused, so a caller cannot probe which tokens exist.

Status is kept for 30 days after a note settles, then the record is dropped.

---

### Groups

Each user can have any number of named groups. A group stores references to emails by UID and a list of **filter addresses** - when an email arrives via SMTP whose 'MAIL FROM' address matches a filter address, the email UID is automatically added to that group. Groups are stored inside the user record and flushed to disk on every mutation.

#### GroupDto
```json
{
  "uid": "string",
  "title": "string",
  "email_uids": [12345678901234567890],
  "filter_addresses": ["alice@example.com"]
}
```

#### GET /group/list
List all groups for the authenticated user.

**Request**: None  
**Response**: 'GroupsListResponse'
```json
{
  "groups": [
    {
      "uid": "string",
      "title": "Work",
      "email_uids": [12345678901234567890],
      "filter_addresses": ["boss@work.com"]
    }
  ]
}
```

#### POST /group/create
Create a new group. Returns the created 'GroupDto'.

**Request**: 'CreateGroupRequest'
```json
{
  "title": "Work",
  "filter_addresses": ["boss@work.com", "hr@work.com"]
}
```
> 'filter_addresses' is optional. Omit it (or pass an empty array) to create a group with no auto-routing rules.

**Response** ('201'): 'GroupDto'

#### POST /group/get
Retrieve a single group by UID.

**Request**: 'GetGroupRequest'
```json
{
  "uid": 12345678901234567890
}
```
**Response**: 'GroupDto'

#### POST /group/update
Update a group's title and/or filter addresses. Omit a field to leave it unchanged. The returned 'GroupDto' reflects the new state.

**Request**: 'UpdateGroupRequest'
```json
{
  "uid": 12345678901234567890,
  "title": "New Title",
  "filter_addresses": ["new@example.com"]
}
```
**Response**: 'GroupDto'

#### POST /group/delete
Delete a group. The emails referenced by the group are **not** deleted - only the group record itself is removed.

**Request**: 'DeleteGroupRequest'
```json
{
  "uid": 12345678901234567890
}
```
**Response**: 'MessageResponse'
```json
{
  "message": "Group deleted"
}
```

#### POST /group/add-email
Manually add an email UID to a group. The email must belong to the authenticated user.

**Request**: 'GroupEmailRequest'
```json
{
  "group_uid": 12345678901234567890,
  "email_uid": 12345678901234567891
}
```
**Response**: 'MessageResponse'
```json
{
  "message": "Email added to group"
}
```

#### POST /group/remove-email
Manually remove an email UID from a group. The email blob is **not** deleted.

**Request**: 'GroupEmailRequest'
```json
{
  "group_uid": 12345678901234567890,
  "email_uid": 12345678901234567891
}
```
**Response**: 'MessageResponse'
```json
{
  "message": "Email removed from group"
}
```

---

### Encrypted Sending Flow

The encrypted sending flow is a two-step process that allows clients to send end-to-end encrypted email while keeping a sender-side copy and individually delivering to each recipient. Full protocol details are in [e2ee_spec.md](e2ee_spec.md).

#### Overview

1. **Resolve keys** - The client sends a list of recipient email addresses. The server returns the public key for each address. For local users the key is read from the user record. For external addresses the server connects to the recipient domain's MX server using SMTP and queries the key via the 'OPNTRN GETKEY' extension command inside a TLS session. If the remote server does not support OPNTRN, the key is returned as 'null'.

2. **Encrypt** - The client encrypts the email separately for each recipient using that recipient's public key (see *Encryption Scheme* below). Recipients with no key receive unencrypted bytes or are excluded - this is a client decision.

3. **Send** - The client calls 'POST /email/sendencrypted'. Each recipient entry carries its own 'e2ee' flag. The server stores the sender's local copy and delivers each recipient's payload individually:
   - For recipients with 'e2ee: true', the server sends 'OPNTRN E2EE' before 'MAIL FROM' to OPNTRN-capable receiving servers, signalling them to store the payload without re-encrypting it.
   - For recipients with 'e2ee: false', the payload is delivered as a normal SMTP message (no 'OPNTRN E2EE' is sent).
   - This allows mixed-mode sending in a single API call: some recipients get E2EE delivery, others get plaintext.

#### Encryption Scheme ('openneutron-1')

Keys returned with 'key_type: "openneutron-1"' require a hybrid RSA-OAEP + AES-256-GCM scheme. RSA alone cannot encrypt arbitrarily large payloads (the plaintext must be shorter than the key modulus minus OAEP overhead, typically <= 190 bytes for a 2048-bit key). The hybrid approach solves this: a random AES-256 key encrypts the payload, and RSA-OAEP encrypts only that short AES key. This is the industry-standard construction (analogous to PGP session keys and TLS key encapsulation).

**To encrypt plaintext bytes 'M' for a recipient's public key:**

1. Generate a random 32-byte AES key 'K' and a random 12-byte nonce 'N'.
2. Encrypt 'M' with AES-256-GCM (key 'K', nonce 'N'). Output: 'C || T' (ciphertext + 16-byte GCM tag).
3. Encrypt 'K' with RSA-OAEP SHA-256 using the recipient's public key. Output: 'E_K'.
4. The client API fields carry the two encrypted parts **separately**:
   - 'aes_encrypted' = Base64('E_K')
   - 'data_encrypted' = Base64('N || C || T')

The server stores these two fields separately in the 'Email' record ('message_key' and 'raw_data'). When the email is delivered over SMTP the server packs them into the wire format: '[ 4 bytes big-endian: len(E_K) ][ E_K ][ N || C || T ]'. The receiving server unpacks them on arrival.

**Public key format:** Base64-encoded DER 'SubjectPublicKeyInfo' (PKCS#8 public format). This is compatible with 'window.crypto.subtle.exportKey("spki", key)' in the Web Crypto API and 'openssl rsa -pubout -outform DER'.

**To decrypt an email** (received via '/email/get' or '/email/bulk'):
1. Base64-decode 'message_key' -> 'E_K'.
2. Decrypt 'E_K' with the user's RSA private key (RSA-OAEP SHA-256) -> 'K'.
3. Base64-decode 'data' -> 'N || C || T' where 'N' is the first 12 bytes, 'C || T' is the remainder.
4. Decrypt 'C || T' using AES-256-GCM with key 'K' and nonce 'N' -> 'M'. The GCM tag is verified implicitly.

#### Key Types

| 'key_type'         | Meaning |
|--------------------|---------|
| '"openneutron-1"'  | RSA public key (DER SPKI), hybrid RSA-OAEP + AES-256-GCM. Use the scheme above. |
| '"none"'           | No key available. The remote server does not support OPNTRN, or the user has no registered key. E2EE is not possible for this recipient. |

#### Technical Details

- **OPNTRN GETKEY**: For external addresses, the server connects to the recipient's MX on port 25, performs STARTTLS, re-sends EHLO, and checks for '250-OPNTRN' in the capability list. If present, it sends 'OPNTRN GETKEY user@domain' for each address on that domain. Responses are '250 OPNTRN KEY openneutron-1 <base64-pubkey>' or '250 OPNTRN NOKEY'. After all queries the server sends 'QUIT'.
- **OPNTRN E2EE**: When delivering an encrypted email to an OPNTRN-capable server, the sending FSM issues 'OPNTRN E2EE' immediately after EHLO (before 'MAIL FROM'). The receiving server sets an internal flag so the incoming payload is stored as-is (skipping server-side encryption) and marked 'secure = true'.
- **DKIM signing**: Each outgoing email is individually signed with 'rsa-sha256' / 'relaxed/relaxed' canonicalization before SMTP delivery.
- **MX resolution**: DNS MX lookup on the recipient's domain; falls back to the domain itself (implicit MX per RFC 5321) if no MX record exists.
- **EHLO domain**: The configured server domain is used in the EHLO greeting.
- **Sent email tracking**: The sender's local copy is stored in 'sentEmailIds' (separate from 'emailIds'). The client encrypts the local copy for its own public key so the server never holds the plaintext.

#### POST /email/publickeys
Resolve public keys for a list of email addresses. Local users are looked up directly. External addresses trigger an OPNTRN key exchange with the recipient's MX server.

**Request**: 'GetPublicKeysRequest'
```json
{
  "addresses": ["alice@remote.example.com", "bob@local.example.com", "carol@gmail.com"]
}
```
**Response**: 'GetPublicKeysResponse'
```json
{
  "keys": [
    {
      "address": "alice@remote.example.com",
      "public_key": "MIIBIjANBgkq...",
      "key_type": "openneutron-1"
    },
    {
      "address": "bob@local.example.com",
      "public_key": "MIIBIjANBgkq...",
      "key_type": "openneutron-1"
    },
    {
      "address": "carol@gmail.com",
      "public_key": null,
      "key_type": "none"
    }
  ]
}
```

> **'public_key'**: Base64-encoded DER 'SubjectPublicKeyInfo' bytes of the recipient's RSA public key, or 'null' if unavailable. The order of 'keys' matches the order of 'addresses' in the request.
>
> **'key_type'**: '"openneutron-1"' when a key was obtained (use the hybrid RSA-OAEP + AES-256-GCM scheme). '"none"' when no key is available (E2EE not possible for this recipient).

#### POST /email/sendencrypted
Send an email to one or more recipients. The server stores a local copy for the sender and delivers each recipient's payload individually.
At most 100 recipients per request. The stored local copy is timestamped by the server, not by 'localcopy.timestamp'.


**Request**: 'SendEncryptedRequest'
```json
{
  "localcopy": {
    "to": ["alice@remote.example.com", "bob@local.example.com"],
    "timestamp": 1711540000,
    "public_key_hash": "base64-sha256-of-sender-public-key",
    "raw_data": "base64-aes-ciphertext-encrypted-for-sender",
    "message_key": "base64-rsa-encrypted-aes-key-for-sender",
    "e2ee": true
  },
  "recipients": {
    "alice@remote.example.com": { "aes_encrypted": "base64-rsa-encrypted-aes-key-for-alice", "data_encrypted": "base64-aes-ciphertext-for-alice", "e2ee": true },
    "bob@local.example.com":    { "aes_encrypted": "base64-rsa-encrypted-aes-key-for-bob",   "data_encrypted": "base64-aes-ciphertext-for-bob",   "e2ee": true },
    "carol@gmail.com":          { "aes_encrypted": "",                                       "data_encrypted": "base64-raw-email-bytes",           "e2ee": false }
  }
}
```

> **'localcopy.from'** is auto-filled by the server as '<username>@<domain>'. Do not include it in the request.
>
> **'localcopy.raw_data'**: AES-256-GCM ciphertext of the email encrypted for the **sender's own** public key, base64-encoded ('nonce || ciphertext || tag'). Stored in 'sent_emails' as-is. The server never decrypts this.
>
> **'localcopy.message_key'**: RSA-OAEP encrypted AES-256 key for the local copy, base64-encoded. Encrypted under the sender's own public key. Required when 'localcopy.e2ee == true'.
>
> **'localcopy.public_key_hash'**: Base64-encoded SHA-256 hash of the sender's public key DER bytes ('SHA-256(DER_bytes)'). Stored alongside the email for client-side key-change detection.
>
> **'localcopy.timestamp'**: Unix timestamp (seconds) to use as the email's creation time.
>
> **'localcopy.e2ee'**: Whether the local copy was encrypted with the sender's own public key. Stored alongside the email so the client knows whether to decrypt it.
>
> **'recipients'**: Map of 'address -> { aes_encrypted, data_encrypted, e2ee }'. Each entry carries the two encrypted parts for that recipient individually.
>
> **'recipients[].aes_encrypted'**: Base64-encoded RSA-OAEP encrypted AES-256 key ('E_K'), encrypted under this specific recipient's public key. Pass an empty string '""' when 'e2ee == false'.
>
> **'recipients[].data_encrypted'**: Base64-encoded AES-256-GCM ciphertext ('nonce || ciphertext || tag') when 'e2ee == true', or raw RFC 5322 email bytes when 'e2ee == false'.
>
> **'recipients[].e2ee'**: Per-recipient flag. When 'true', the server packs 'aes_encrypted' and 'data_encrypted' into the SMTP wire blob and sends 'OPNTRN E2EE' to OPNTRN-capable receiving servers. When 'false', 'data_encrypted' is sent as a normal SMTP message. This allows mixed-mode sending: some recipients get E2EE delivery while others (on legacy servers with no key) get plaintext delivery - all in a single API call.
>
> Recipients with no OPNTRN key (returned as 'key_type: "none"' from '/email/publickeys') should be sent with 'e2ee: false'.
>
> **'ephemeral'** (optional): makes the message delete itself. Applied to recipients whose mailbox is on this server; other providers keep their own copy.
> ```json
> { "ephemeral": { "deletes_on_read": true } }
> { "ephemeral": { "expires_in_seconds": 3600 } }
> ```
> 'expires_in_seconds' is clamped to 60 s - 90 days. If the rule cannot be recorded for a local recipient the delivery is rolled back and reported as 'success: false' — a message is never delivered under a promise the server cannot keep. See *Disappearing messages* above.

**Response**: 'SendEncryptedResponse'
```json
{
  "message": "Send completed",
  "sent_email_uid": 12345678901234567890,
  "delivery_results": [
    {
      "address": "alice@remote.example.com",
      "success": true,
      "error": null
    },
    {
      "address": "bob@local.example.com",
      "success": true,
      "error": null
    }
  ]
}
```

> **'sent_email_uid'**: UID of the stored local copy. Use '/email/sent/get' to retrieve it.
>
> **'delivery_results'**: Per-recipient delivery outcome. 'success: true' means the remote SMTP server accepted the message with a 250 response. On partial failure the response still returns HTTP 200 - check each entry's 'success' field.

---

### Sent Emails

All four endpoints are **authenticated** (Bearer token required). A sent email is the same 'Email' blob stored in 'EmailStorage'; its UID lives in the sender's 'sent_emails' array rather than 'emailIds'.

#### POST /email/sent/list
Return every sent-email UID for the authenticated user (unordered, insertion order).

**Request**: empty body '{}' or no body required.

**Response**: 'EmailUidsResponse'
```json
{ "uids": [123456, 789012] }
```

---

#### POST /email/sent/recent
Return a paginated slice of sent-email UIDs, newest first.

**Request**:
```json
{ "offset": 0, "limit": 20 }
```

**Response**: 'EmailUidsResponse'
```json
{ "uids": [789012, 123456] }
```

---

#### POST /email/sent/get
Retrieve a single sent email by UID.

**Request**:
```json
{ "uid": 789012 }
```

**Response**: 'EmailBytesResponse'
```json
{
  "uid": 789012,
  "data": "<base64-encoded raw email bytes>",
  "received_at": "2024-01-15T10:30:00Z"
}
```

Returns **404** if the UID is not in the caller's 'sent_emails'.

---

#### POST /email/sent/bulk
Retrieve multiple sent emails in one request. UIDs not owned by the caller are silently ignored.

**Request**:
```json
{ "uids": [123456, 789012] }
```

**Response**: 'EmailsBulkResponse'
```json
{
  "emails": [
    { "uid": 123456, "data": "<base64>", "received_at": "2024-01-15T10:00:00Z" },
    { "uid": 789012, "data": "<base64>", "received_at": "2024-01-15T10:30:00Z" }
  ]
}
```

---

### DKIM Configuration (config.yml)

To enable DKIM signing for outgoing emails, configure the 'dkim' section:

```yaml
dkim:
  enabled: true
  private_key_path: "dkim_private.pem"   # Path to RSA private key in PKCS#8 PEM format
  selector: "default"                     # DKIM selector (used in DNS: <selector>._domainkey.<domain>)
```

On startup, if 'private_key_path' is set and the file exists, the server loads the key and uses it to sign all outbound SMTP messages. If the key cannot be loaded, a warning is logged and outgoing mail is sent unsigned.

### Disposable addresses (aliases)

An alias is another address that delivers to one account: `shop-8f2k@<domain>`
lands in the owner's mailbox, and switching it off makes senders bounce. Ten per
account. The local part is 3–32 characters of lower-case letters, digits and
hyphens.

Mail is only accepted for an address Postfix has been told about, and Postfix
asks `GET /admin/recipients` every few seconds — so a new alias starts working
within about five seconds, and a switched-off one stops being accepted rather
than being silently dropped.

#### GET /aliases  (JWT)
```json
{
  "aliases": [
    { "local": "shop-8f2k", "address": "shop-8f2k@slothlee.xyz", "label": "Shopping",
      "created_at": 1793158000, "disabled_at": null, "received": 4 }
  ],
  "limit": 10,
  "domain": "slothlee.xyz"
}
```
`received` counts messages delivered through the address.

#### POST /aliases  (JWT)
```json
{ "local": "", "label": "Shopping" }
```
`local` empty generates a readable name (`quiet-otter-418`). A name is lower-cased
before validation, so the response is the address actually created — always show
that. `200 {"local": "...", "address": "..."}`; `400 invalid` for a name that
cannot be used; `409 taken` when an account or another alias already answers to
it; `409 too_many` at the limit.

#### POST /aliases/disable  (JWT)
```json
{ "local": "shop-8f2k", "disabled": true }
```
`200 {"disabled": true}`. Switched off, the address is removed from the Postfix
recipient map, so senders get a normal 550 rather than having their mail vanish.
`404` when it is not the caller's.

#### POST /aliases/delete  (JWT)
```json
{ "local": "shop-8f2k" }
```
`200 {"deleted": true}`, `404` when it is not the caller's. Mail already
delivered stays in the mailbox.

#### GET /admin/recipients  (admin JWT)
```json
{ "recipients": ["tibs", "shop-8f2k", "..."] }
```
Every local part that may receive mail: real accounts (pending signups excluded)
plus switched-on aliases. Postfix's recipient map is built from this answer.

### Scheduled send

`POST /email/send` and `POST /email/sendencrypted` both accept `send_at` (unix
seconds) and `subject` (a label for the sender's own list, never used for
delivery). With `send_at` set to a time more than a minute and less than a year
away, the message is held and the answer is:

```json
{ "scheduled": true, "id": "s18f…", "send_at": 1793161200, "to": ["a@b.c"] }
```

Nothing is delivered, and no sent copy is created, until it goes out. Sending
limits are still counted at queue time, so a queue cannot exceed them. A plain
message is stored as the finished MIME blob; an encrypted one is stored as the
whole request and replayed through `/email/sendencrypted` when its time comes.

Failures: `400 send_at_too_soon`, `400 send_at_too_far`, `409 too_many_scheduled`
(fifty waiting per account).

#### GET /scheduled  (JWT)
```json
{
  "items": [
    { "id": "s18f…", "to": ["a@b.c"], "subject": "Later", "created_at": 1793159000,
      "send_at": 1793161200, "status": "pending", "kind": "encrypted",
      "sent_at": null, "error": "" }
  ],
  "now": 1793159100,
  "limit": 50
}
```
`status` is `pending`, `sent`, `failed` or `cancelled`. Bodies are never
returned. Finished rows are pruned after a day.

#### POST /scheduled/cancel  (JWT)
```json
{ "id": "s18f…" }
```
`200 {"cancelled": true}`. `409 not_cancellable` once it has gone out, once it is
already cancelled, or when it is not the caller's — one answer for all three.

#### Sealed-note attachments

`POST /note/create` accepts `files: [{ "name": "...", "armored": "...", "size": 4000 }]`
— each entry is a PGP message the client sealed to the **same passphrase** as the
body. Five files and 6,000,000 characters of armour per note.

- `400 files_need_passphrase` when `mode` is `pgp`: a key-locked note is decrypted
  by the recipient's own client, so its page cannot open files for them.
- `400 too_many_files`, `413 files_too_large` on the caps.
- Names are reduced to the last path segment, stripped of `/`, `\\`, `:` and
  control characters, trimmed of leading dots and cut to 80 characters.

`POST /note/open` returns the same `files` array alongside the body, and the page
decrypts them locally. Files are cleared with the body: on open (key mode), on
`/note/burn` (passphrase mode), on withdrawal and on expiry.

#### Sending as an alias

`POST /email/send` and `POST /email/sendencrypted` accept `from_alias` — a local
part or a full address belonging to the caller.

- `400 unknown_alias` when it is not the caller's.
- `409 alias_disabled` when it is theirs but switched off.
- Absent or empty: the account address, exactly as before.

The server sets the envelope sender; the client sets the `From:` header inside the
MIME text, because on the encrypted path the server cannot read the headers. On
local delivery the stored sender is the alias, so the recipient sees only that.

#### Which address a message arrived at

`POST /email/bulk` and `POST /email/get` return `alias` when the message was
addressed to one of the caller's aliases — the local part, without the domain.
Recorded in `data/arrival.json` (`{"arrivals": {"<uid>": {"alias": "...", "at": 0}}}`)
and pruned after 180 days. It exists so a reply can leave from the address the
sender actually wrote to.

#### New-mail notifications (Web Push)

- `GET /api/push/key` — the VAPID public key (uncompressed P-256 point,
  base64url). Open by design; the browser needs it before it can subscribe.
- `POST /api/push/subscribe` — `{endpoint, keys: {p256dh, auth}, ua?}`. The
  endpoint must be a browser push service (`*.google.com/fcm/send/*`,
  `*push.services.mozilla.com/wpush/*`, `web.push.apple.com`,
  `*.notify.windows.com`), else `400 invalid_endpoint`. One row per endpoint.
- `POST /api/push/unsubscribe` — `{endpoint}`.
- `GET /api/push/status` — `{subscribed, count}` for the caller.
- `POST /api/push/test` — sends one now; `409 not_subscribed` when nothing is
  registered.

Payloads are sealed per RFC 8291 (ECDH P-256 → AES-128-GCM) and carry only a
title and a sender. Endpoints answering 404/410 are deleted automatically.
