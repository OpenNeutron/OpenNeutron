# OpenNeutron API Documentation

This document outlines the API endpoints, request/response DTOs, and JSON formats for the OpenNeutron application.

## Authentication

All secure endpoints require a JWT token in the 'Authorization' header: 'Bearer <token>'.

## DTOs Overview

- **Base64 Usage**: Fields containing binary data (e.g., 'public_key', 'encrypted_private_key', 'data' in email DTOs) are base64-encoded strings.
- **Password handling**: All password operations are performed client-side. The client sends a password token (e.g. a client-side hash); the server stores and compares this token **directly** - no server-side re-hashing is applied.
- **Error Responses**: All endpoints can return 'ErrorResponse' on failure.

### Common DTOs

#### ErrorResponse
```json
{
  "error": "string"
}
```

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
  "username": "string",
  "public_key": "base64-string|null",
  "unread_emails": 0,
  "salt": "hex-string",
  "encrypted_private_key": "base64-string|null"
}
```

> **'force_reset'**: When 'true', the user has no password set and must set one before normal use. This is always 'true' for accounts provisioned by an admin. The client should redirect to a password-setup flow and call the appropriate endpoint to set the password.
>
> **'salt'**: A per-user random hex string (32 hex chars / 16 bytes of entropy) generated at account creation time. The client uses this together with the user's password to derive the AES key that encrypts the private key. Always returned on successful login regardless of 'force_reset'.
>
> **'encrypted_private_key'**: The user's RSA private key, AES-256 encrypted client-side. 'null' for admin-created accounts that have not yet completed setup.

#### POST /user/register
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
**Response**: 'MessageResponse'
```json
{
  "message": "User created"
}
```

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
Used during the initial account setup flow. When a user receives 'force_reset: true' after login (i.e. the account was provisioned by an admin and has no password yet), they must call this endpoint to define their password and public key before normal use. All cryptographic operations are performed client-side - 'password' is a hash string and 'public_key' is base64-encoded. Only works while the account is in the 'force_reset' state; returns '409' if a password is already set.

**Request**: 'SetupPasswordRequest'
```json
{
  "password": "string",
  "public_key": "base64-string",
  "encrypted_private_key": "base64-string"
}
```
> 'password' is the client-side password token stored as-is. 'encrypted_private_key' is the RSA private key encrypted client-side with AES-256.
**Response**: 'MessageResponse'
```json
{
  "message": "Password set"
}
```

> **Flow**:
> 1. Admin creates user via 'POST /admin/users' -> 'force_reset: true'
> 2. User logs in with any password -> receives token + 'force_reset: true'
> 3. Client calls 'POST /user/setup' with the Bearer token, chosen password hash, and public key
> 4. Server stores the credentials; subsequent logins return 'force_reset: false'

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
Creates a new user account with no password. The user must set their own password on first login (indicated by 'force_reset: true' in the login response and in this response).

**Request**: 'AdminCreateUserRequest'
```json
{
  "username": "string"
}
```
**Response**: 'AdminCreateUserResponse'
```json
{
  "message": "User created",
  "force_reset": true
}
```

> **'force_reset'** is always 'true' here - it confirms that the created account has no password and the user will be required to define one on first login.

#### DELETE /admin/users
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

**Response**: 'MessageResponse'
```json
{
  "message": "Credentials updated"
}
```

#### POST /admin/users/admin
Grant or revoke admin privileges for a user.

**Request**: 'AdminSetAdminRequest'
```json
{
  "username": "string",
  "is_admin": true
}
```
> Set 'is_admin' to 'false' to demote an admin back to a regular user.

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
Sends a raw email via an external SMTP server. The server performs STARTTLS opportunistically if advertised. No encryption is applied server-side; the bytes are forwarded as-is.

**Request**: 'SendEmailRequest'
```json
{
  "from": "alice@example.com",
  "to": ["bob@remote.com"],
  "data": "base64-encoded-raw-email-bytes",
  "smtp_host": "mail.remote.com",
  "smtp_port": 587
}
```
> 'smtp_port' is optional; defaults to '25'.

**Response**: 'MessageResponse'
```json
{
  "message": "Email sent"
}
```

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
