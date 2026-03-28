# OpenNeutron - OPNTRN E2EE Protocol Reference

This document describes the 'OPNTRN' SMTP extension and every other mechanism OpenNeutron
uses to deliver end-to-end encrypted email.  For every step, the exact bytes on the wire,
the algorithm used, and what each party stores are shown.

---

## Table of Contents

1. [Overview and Threat Model](#1-overview-and-threat-model)
2. [OPNTRN SMTP Extension](#2-opntrn-smtp-extension)
3. [Hybrid Encryption Primitives](#3-hybrid-encryption-primitives)
4. [Wire Blob Format (SMTP body)](#4-wire-blob-format-smtp-body)
5. [Server-to-Server E2EE Send Flow](#5-server-to-server-e2ee-send-flow)
6. [Client-to-Server E2EE Send Flow (API)](#6-client-to-server-e2ee-send-flow-api)
7. [Receiving Side - Storage Layout](#7-receiving-side--storage-layout)
8. [API Retrieval and Client Decryption](#8-api-retrieval-and-client-decryption)
9. [Server-Side At-Rest Encryption (non-E2EE SMTP)](#9-server-side-at-rest-encryption-non-e2ee-smtp)
10. [DKIM Interaction](#10-dkim-interaction)
11. [TLS Transport Layer](#11-tls-transport-layer)
12. [Complete Annotated SMTP Session Examples](#12-complete-annotated-smtp-session-examples)

---

## 1. Overview and Threat Model

OpenNeutron supports two distinct encryption modes for incoming email:

| Mode | Who encrypts? | Key source | 'e2ee' flag | Protects against |
|------|--------------|-----------|-------------|-----------------|
| **Server-side at-rest** | Receiving server | Recipient's stored public key | 'false' | Disk theft, DB leak |
| **E2EE (OPNTRN)** | Sending server | Recipient's public key fetched live | 'true' | Sending server reading content |

In both modes the encrypted blob is stored identically on disk and served identically
through the API; only the 'e2ee' flag and the provenance differ.

The server **always** holds:
- 'message_key' - the RSA-OAEP-encrypted 32-byte AES key (only the recipient's private key
  can decrypt this).
- 'raw_data' - the AES-256-GCM ciphertext (nonce prepended).

The server **never** holds the plaintxt body of an encrypted email, nor the AES key in
the clear.

---

## 2. OPNTRN SMTP Extension

### Capability advertisement

When the receiving server responds to 'EHLO', it includes 'OPNTRN' in the capability list:

```
250-mail.example.com
250-PIPELINING
250-SIZE 104857600
250-STARTTLS
250-AUTH PLAIN LOGIN
250-8BITMIME
250-ENHANCEDSTATUSCODES
250-OPNTRN
250 CHUNKING
```

If the connection has already been upgraded to TLS, 'STARTTLS' is omitted from subsequent
EHLO responses (RFC 3207 compliance), but 'OPNTRN' remains.

### Command: OPNTRN GETKEY

Queries the public key of a local user.

**Client sends:**
```
OPNTRN GETKEY alice@mail.example.com\r\n
```

**Server responds (key found):**
```
250 OPNTRN KEY openneutron-2 <base64(SPKI DER)>\r\n
```

- 'openneutron-2' is the key-type identifier string (currently the only defined type).
- The base64 value is the recipient's SPKI DER public key, byte-for-byte identical to
  'user.publicKey' stored in the user record.

**Server responds (no key / user not found / wrong domain):**
```
250 OPNTRN NOKEY\r\n
```

The server always responds 250 even on NOKEY so that the sending side can distinguish
"command understood, no key" from "command not understood".

**Validation rules (receiver side):**

```rust
// src/smtp/email_receiving_fsm.rs  (OPNTRN GETKEY handler)
let addr_domain = &addr[at_pos + 1..];
if addr_domain.eq_ignore_ascii_case(&self.server_name) {
    // look up username in user_storage
    if let Some(user) = self.user_storage.get_user(username) {
        if let Some(pk) = &user.publicKey {
            let encoded = base64::encode(&pk.0);
            // -> 250 OPNTRN KEY openneutron-2 <encoded>
        } else {
            // -> 250 OPNTRN NOKEY
        }
    } else {
        // -> 250 OPNTRN NOKEY
    }
} else {
    // -> 250 OPNTRN NOKEY  (wrong domain)
}
```

### Command: OPNTRN E2EE

Signals that the email body in the subsequent DATA command is a packed encrypted blob
rather than a plain RFC 5322 message.

**Client sends:**
```
OPNTRN E2EE\r\n
```

**Server responds:**
```
250 OPNTRN OK\r\n
```

The FSM sets 'is_e2ee = true'; this flag is propagated to 'Email::new_e2ee()' instead of
'Email::new()' during storage.

### Unknown OPNTRN sub-command

```
500 5.5.1 Unknown OPNTRN command\r\n
```

---

## 3. Hybrid Encryption Primitives

All email content is encrypted using hybrid RSA-OAEP + AES-256-GCM.

### AES-256-GCM (symmetric layer)

| Parameter   | Value                   |
|-------------|-------------------------|
| Algorithm   | AES-256-GCM             |
| Key size    | 256 bits (32 bytes)     |
| Nonce size  | 96 bits (12 bytes)      |
| Tag size    | 128 bits (16 bytes)     |
| Key source  | CSPRNG (fresh per email) |
| Nonce source| CSPRNG (fresh per email) |

Output layout:
```
[ 12 bytes nonce ][ N bytes ciphertext ][ 16 bytes GCM auth tag ]
```
The tag is appended by the AES-GCM implementation; it is not stored separately.

### RSA-OAEP (asymmetric key wrap)

| Parameter       | Value           |
|-----------------|-----------------|
| Algorithm       | RSA-OAEP        |
| Modulus length  | 4096 bits       |
| Public exponent | 65537           |
| OAEP hash       | SHA-256         |
| Plaintext input | 32-byte AES key |
| Ciphertext size | 512 bytes       |

The 32-byte AES key is wrapped with the recipient's 4096-bit RSA public key using
'RSA-OAEP-SHA256'.  The output is always exactly 512 bytes ('4096 / 8').

### Server-side implementation

```rust
// src/utils/cryptography.rs  ->  encrypt_split()
let mut aes_key_bytes = [0u8; 32];
let mut nonce_bytes   = [0u8; 12];
rng.fill_bytes(&mut aes_key_bytes);
rng.fill_bytes(&mut nonce_bytes);

// AES-256-GCM encrypt
let ciphertext = Aes256Gcm::new(Key::from_slice(&aes_key_bytes))
    .encrypt(Nonce::from_slice(&nonce_bytes), data)?;

// RSA-OAEP wrap the AES key
let enc_aes_key = rsa_pub.encrypt(&mut rng, Oaep::new::<Sha256>(), &aes_key_bytes)?;

// aes_ciphertext = nonce || ciphertext (with appended GCM tag)
let mut aes_ciphertext = Vec::new();
aes_ciphertext.extend_from_slice(&nonce_bytes);
aes_ciphertext.extend_from_slice(&ciphertext);
```

### Client-side implementation

```js
// crypto_frontend.js  ->  encryptEmail()
const iv     = crypto.getRandomValues(new Uint8Array(12))   // 12-byte nonce
const aesRaw = crypto.getRandomValues(new Uint8Array(32))   // 32-byte AES key
const aesKey = await crypto.subtle.importKey('raw', aesRaw,
    { name: 'AES-GCM' }, false, ['encrypt'])
const aesCipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, aesKey, enc.encode(plaintext))
const rsaCipher = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' }, publicKey, aesRaw)

// Packed into a single buffer for the data_encrypted field:
// [ 12-byte iv ][ aesCipher (ciphertext + 16-byte tag) ]
const dataOut = new Uint8Array(12 + aesCipher.byteLength)
dataOut.set(iv, 0)
dataOut.set(new Uint8Array(aesCipher), 12)
```

---

## 4. Wire Blob Format (SMTP body)

When an E2EE email is delivered over SMTP, the DATA body is a **binary packed blob**,
not an RFC 5322 text message.  The format is:

```
┌─────────────────────────────────────────────────────────────────┐
│  4 bytes  │  key_len bytes  │  12 bytes  │  N bytes  │ 16 bytes │
│  BE u32   │  encrypted AES  │   nonce    │ciphertext │ GCM tag  │
│  key_len  │      key        │            │           │          │
└─────────────────────────────────────────────────────────────────└
          ^                  ^─────────────────────────────────────^
     pack header              aes_ciphertext field
```

Specific sizes for a 4096-bit RSA key:

| Field            | Offset     | Size    | Value                                      |
|------------------|------------|---------|--------------------------------------------|
| 'key_len' prefix | 0          | 4 bytes | '0x00 0x00 0x02 0x00' = 512 (big-endian)  |
| 'enc_aes_key'    | 4          | 512 bytes | RSA-OAEP-SHA256(32-byte AES key)         |
| 'nonce'          | 516        | 12 bytes | random AES-GCM nonce                      |
| 'ciphertext'     | 528        | N bytes  | AES-256-GCM encrypted body                |
| 'GCM tag'        | 528+N      | 16 bytes | AES-GCM authentication tag (appended)     |

Total size: '4 + 512 + 12 + N + 16' bytes where N is the plaintext body length.

### Packing (sender)

```rust
// src/utils/cryptography.rs  ->  pack_encrypted_email()
let key_len = message_key.len() as u32;          // 512 for 4096-bit RSA
packed.extend_from_slice(&key_len.to_be_bytes()); // 4 bytes big-endian length prefix
packed.extend_from_slice(message_key);            // 512 bytes
packed.extend_from_slice(aes_ciphertext);         // 12 + N + 16 bytes
```

### Unpacking (receiver)

```rust
// src/utils/cryptography.rs  ->  unpack_encrypted_email()
let key_len    = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
let message_key    = data[4 .. 4 + key_len].to_vec();
let aes_ciphertext = data[4 + key_len ..].to_vec();
```

### SMTP dot-stuffing

The binary blob is passed through standard RFC 5321 dot-stuffing before transmission:
any byte sequence '\n.' (line starting with '.') gets an extra '.' prepended.  The
receiver performs dot-un-stuffing after the '\r\n.\r\n' terminator is detected.

```rust
// email_sending_fsm.rs  ->  smtp_dot_stuff()
if at_line_start && b == b'.' { out.push(b'.'); }   // insert extra dot

// email_receiving_fsm.rs  ->  smtp_dot_unstuff()
if at_line_start && b == b'.' { continue; }          // drop the extra dot
```

---

## 5. Server-to-Server E2EE Send Flow

This flow is used when a client calls 'POST /email/sendencrypted' and the receiving
server also supports OPNTRN.

```
Sending Server                                    Receiving Server
─────────────────────────────────────────────────────────────────
TCP connect to MX host on port 25
                          <-  220 mail.remote.example ESMTP ready\r\n
EHLO sending.example\r\n  ->
                          <-  250-mail.remote.example\r\n
                          <-  250-STARTTLS\r\n
                          <-  250-OPNTRN\r\n
                          <-  250 CHUNKING\r\n
STARTTLS\r\n              ->                        (if offered)
                          <-  220 2.0.0 Ready to start TLS\r\n
    [TLS handshake - certificate NOT verified, NoCertVerification]
EHLO sending.example\r\n  ->                        (re-issue after TLS)
                          <-  250-mail.remote.example\r\n
                          <-  250-OPNTRN\r\n         (STARTTLS no longer listed)
                          <-  250 CHUNKING\r\n

OPNTRN E2EE\r\n           ->
                          <-  250 OPNTRN OK\r\n

MAIL FROM:<sender@sending.example>\r\n  ->
                          <-  250 2.1.0 OK\r\n
RCPT TO:<alice@remote.example>\r\n      ->
                          <-  250 2.1.5 OK\r\n
DATA\r\n                  ->
                          <-  354 End data with <CR><LF>.<CR><LF>\r\n
[packed blob - 65536-byte chunks, dot-stuffed]     ->
\r\n.\r\n                 ->
                          <-  250 2.0.0 OK\r\n
QUIT\r\n                  ->
                          <-  221 Bye\r\n
```

### Key query (separate connection, before the send session)

The sending API handler calls 'POST /email/publickeys' which in turn opens a separate
SMTP connection to the recipient's MX host *only* to query the key, not to deliver mail:

```
TCP connect to MX host on port 25
                          <-  220 ...
EHLO sending.example\r\n  ->
                          <-  250-...OPNTRN...
[STARTTLS if offered - same as above]
OPNTRN GETKEY alice@remote.example\r\n  ->
                          <-  250 OPNTRN KEY openneutron-2 <base64>\r\n
QUIT\r\n                  ->
                          <-  221 Bye\r\n
```

The base64 public key value is returned to the client in the 'POST /email/publickeys'
response so the client can perform the encryption.

---

## 6. Client-to-Server E2EE Send Flow (API)

```
Browser Client                         OpenNeutron Server
──────────────────────────────────────────────────────────

POST /email/publickeys
{ "addresses": ["alice@remote.example", "bob@local.example"] }
Authorization: Bearer <JWT>
                                <-  200
                                   { "keys": [
                                       { "address": "alice@remote.example",
                                         "public_key": "<base64 SPKI>",
                                         "key_type": "openneutron-2" },
                                       { "address": "bob@local.example",
                                         "public_key": "<base64 SPKI>",
                                         "key_type": "openneutron-1" }
                                     ] }

[Client encrypts email body for each recipient independently]

For each recipient R with public key PK_R:
  aes_key       = random 32 bytes
  nonce         = random 12 bytes
  ciphertext    = AES-256-GCM(email_bytes, key=aes_key, nonce=nonce)
  aes_encrypted = RSA-OAEP-SHA256(aes_key, PK_R)       -> base64
  data_encrypted = Base64(nonce || ciphertext || tag)   -> base64

[Client also encrypts a copy to its own public key for sent-mail storage]

POST /email/sendencrypted
Authorization: Bearer <JWT>
{
  "localcopy": {
    "raw_data":       "<base64(nonce || ct || tag) encrypted to sender's own pubkey>",
    "message_key":    "<base64 RSA-OAEP(aes_key, sender_pubkey)>",
    "to":             ["alice@remote.example", "bob@local.example"],
    "timestamp":      1711584000,
    "public_key_hash": "<base64 SHA-256(sender SPKI DER)>",
    "e2ee":           true
  },
  "recipients": {
    "alice@remote.example": {
      "aes_encrypted":  "<base64 RSA(aes_key, alice_pubkey)>",
      "data_encrypted": "<base64(nonce || ct || tag)>",
      "e2ee": true
    },
    "bob@local.example": {
      "aes_encrypted":  "<base64 RSA(aes_key, bob_pubkey)>",
      "data_encrypted": "<base64(nonce || ct || tag)>",
      "e2ee": true
    }
  }
}
```

### What the server does with each recipient payload

```rust
// For e2ee=true recipients:
let enc_key = base64::decode(&payload.aes_encrypted)?;     // 512 bytes
let aes_ct  = base64::decode(&payload.data_encrypted)?;    // 12+N+16 bytes
let wire_bytes = pack_encrypted_email(&enc_key, &aes_ct);
// wire_bytes = [4-byte BE len=512][512 bytes enc_key][12 bytes nonce][N bytes ct][16 bytes tag]

// For e2ee=false recipients (plaintext payload):
let wire_bytes = base64::decode(&payload.data_encrypted)?;  // raw RFC 5322 bytes
```

The server then opens an SMTP connection to the recipient's MX host and delivers
'wire_bytes' as the DATA body with 'OPNTRN E2EE' pre-announced (for E2EE payloads).

### Local copy storage

The 'localcopy' object is saved as an 'Email' struct in 'email_storage' with:
- 'e2ee = true' (or false if the local copy is not E2EE)
- 'uid' = freshly generated UID
- The UID is appended to 'user.sent_emails'

---

## 7. Receiving Side - Storage Layout

When an SMTP connection completes delivery and the FSM finishes receiving the DATA body,
the main loop processes the email for each recipient listed in 'RCPT TO'.

### E2EE email ('is_e2ee = true')

```rust
// src/core/email.rs  ->  Email::new_e2ee()
let raw_bytes = received_email.raw_data;   // = the full DATA body after dot-unstuffing

let (message_key, aes_ciphertext) = unpack_encrypted_email(&raw_bytes)?;
// binary split:
//   message_key   = raw_bytes[4 .. 4+512]          (RSA-encrypted AES key, 512 bytes)
//   aes_ciphertext = raw_bytes[516 ..]             (nonce || ciphertext || tag)

Email {
    uid:           generate_email_uid(user),         // u128, random
    secure:        true,
    e2ee:          true,
    message_key:   Some(message_key),                // 512 bytes
    raw_data:      aes_ciphertext,                   // 12 + N + 16 bytes
    publicKeyHash: SHA256(user.publicKey.0),         // 32 bytes
    ...
}
```

### Non-E2EE email (ordinary SMTP, 'is_e2ee = false')

```rust
// src/core/email.rs  ->  Email::new()
// Server encrypts with a fresh AES key using the user's stored public key.
let (message_key, encrypted_data) = encrypt_split(&user.publicKey, &raw_bytes)?;
// same structure as above; e2ee=false, secure=true

// If user has no public key:
// message_key = None, encrypted_data = raw_bytes, secure = false
```

### Disk storage format

Each email is serialized with 'bincode' and written to '{blobs_dir}/{uid}.bin'.

The on-disk 'Email' struct:

| Field            | Type              | Content                                             |
|------------------|-------------------|-----------------------------------------------------|
| 'uid'            | 'u128'            | Unique random identifier                            |
| 'secure'         | 'bool'            | 'true' if encrypted                                 |
| 'e2ee'           | 'bool'            | 'true' if encrypted by sender (OPNTRN E2EE)         |
| 'read'           | 'bool'            | Whether the user has read this email                |
| 'starred'        | 'bool'            | User star/flag                                      |
| 'userid'         | 'u128'            | Recipient's user UID                                |
| 'from'           | 'String'          | SMTP MAIL FROM address                              |
| 'to'             | 'Vec<String>'     | SMTP RCPT TO addresses                              |
| 'timestamp'      | 'u64'             | Unix epoch seconds at delivery                      |
| 'publicKeyHash'  | '[u8; 32]'        | SHA-256(recipient SPKI DER) at time of encryption   |
| 'raw_data'       | 'Vec<u8>'         | 'nonce(12) \|\| ciphertext \|\| tag(16)' or plaintext |
| 'message_key'    | 'Option<Vec<u8>>' | RSA-OAEP wrapped AES key (512 bytes for 4096-bit)   |

---

## 8. API Retrieval and Client Decryption

### Fetch a single email

```
POST /email/get
Authorization: Bearer <JWT>
{ "uid": 123456789 }
```

Response:

```json
{
  "uid": 123456789,
  "data": "<base64(nonce || ciphertext || GCM tag)>",
  "message_key": "<base64(RSA-OAEP encrypted AES key)>",
  "received_at": "2026-03-28T12:00:00Z",
  "e2ee": true
}
```

'message_key' is 'null' when 'secure = false' (unencrypted email stored in plaintext).

### Client decryption

```js
// crypto_frontend.js  ->  decryptEmail(data, messageKey, privateKey)
const aesRaw = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' }, privateKey, fromB64(messageKey))
// aesRaw = 32-byte AES key

const aesKey = await crypto.subtle.importKey('raw', aesRaw,
    { name: 'AES-GCM' }, false, ['decrypt'])

const dataBuf    = new Uint8Array(fromB64(data))
const iv         = dataBuf.slice(0, 12)    // first 12 bytes = nonce
const ciphertext = dataBuf.slice(12)       // remainder = ciphertext || tag

const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext)
return new TextDecoder().decode(plain)
```

When 'messageKey' is absent (unencrypted), the function skips decryption and decodes
'data' as raw UTF-8 bytes.

### Bulk fetch

```
POST /email/bulk
Authorization: Bearer <JWT>
{ "uids": [123, 456, 789] }
```

Returns an array of the same 'EmailBytesResponse' objects.  UIDs not belonging to the
authenticated user are silently filtered out.

---

## 9. Server-Side At-Rest Encryption (non-E2EE SMTP)

When an ordinary SMTP email (no 'OPNTRN E2EE') arrives for a local user who has a
registered public key, the server re-encrypts the raw message body immediately on arrival:

```rust
// src/core/email.rs  ->  Email::new()
if let Some(pk) = &user.publicKey {
    let (enc_key, aes_ct) = encrypt_split(pk, &raw_bytes)?;
    // enc_key  = RSA-OAEP(random 32-byte AES key, user public key)
    // aes_ct   = random 12-byte nonce || AES-GCM(body) || 16-byte tag
    message_key   = Some(enc_key);
    raw_data      = aes_ct;
    secure        = true;
    e2ee          = false;
} else {
    // No public key registered - store plaintext.
    message_key   = None;
    raw_data      = raw_bytes;
    secure        = false;
    e2ee          = false;
}
```

The final 'Email' struct layout and API response format are identical to E2EE emails;
only 'e2ee' differs.  The client decrypts both with the same 'decryptEmail()' function.

---

## 10. DKIM Interaction

DKIM signing is applied **only to non-E2EE payloads**.

E2EE payloads are binary blobs, not RFC 5322 text.  Prepending a DKIM-Signature header
would corrupt the packed binary format (the 4-byte length prefix would no longer align),
so E2EE payloads are always sent unsigned.

```rust
// src/api/endpoints/email.rs  ->  send_encrypted()
let signed_bytes = if payload.e2ee {
    wire_bytes          // skip DKIM - binary blob
} else {
    match dkim_signer {
        Some(signer) => signer.sign(&wire_bytes).unwrap_or(wire_bytes),
        None => wire_bytes,
    }
};
```

---

## 11. TLS Transport Layer

### Incoming SMTP (receiving server)

The server advertises 'STARTTLS' while in plaintext state and does **not** re-advertise it
after TLS is established (RFC 3207).  The TLS certificate is loaded from disk (or a
self-signed certificate is generated at startup).

The 'is_tls' flag in 'EmailReceivingFSM' tracks upgrade state:

```rust
if line_lower.starts_with("starttls") {
    if self.is_tls {
        stream.write_all(b"503 5.5.1 Already in TLS\r\n")?;
        continue;
    }
    stream.write_all(b"220 2.0.0 Ready to start TLS\r\n")?;
    return Ok(CommandResult::UpgradeToTls);   // signals main loop to wrap stream
}
```

After the TLS handshake, the FSM's 'notify_tls_upgraded()' is called and the next EHLO
response omits STARTTLS.

### Outgoing SMTP (sending side)

The sending side ('EmailSendingFSM') opportunistically upgrades to TLS if the remote
server advertises 'STARTTLS'.  The TLS client uses a **permissive certificate verifier**
('NoCertVerification') that accepts any server certificate - this allows delivery to
servers with self-signed certificates.

```rust
// email_sending_fsm.rs
impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(&self, ...) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())   // always accept
    }
}
```

> **Security note:** The permissive verifier means TLS protects the content from passive
> eavesdroppers but does not authenticate the remote server's identity.  For E2EE emails
> this is acceptable because the content is already encrypted to the recipient's public key
> and cannot be read by an MitM even if TLS is stripped entirely.

---

## 12. Complete Annotated SMTP Session Examples

### Example A - Querying a public key (OPNTRN GETKEY)

```
C: [TCP connect to mail.remote.example:25]
S: 220 mail.remote.example ESMTP ready\r\n
C: EHLO mail.sender.example\r\n
S: 250-mail.remote.example\r\n
S: 250-PIPELINING\r\n
S: 250-SIZE 104857600\r\n
S: 250-STARTTLS\r\n
S: 250-AUTH PLAIN LOGIN\r\n
S: 250-8BITMIME\r\n
S: 250-ENHANCEDSTATUSCODES\r\n
S: 250-OPNTRN\r\n
S: 250 CHUNKING\r\n
C: STARTTLS\r\n
S: 220 2.0.0 Ready to start TLS\r\n
[TLS handshake]
C: EHLO mail.sender.example\r\n
S: 250-mail.remote.example\r\n
S: 250-OPNTRN\r\n
S: 250 CHUNKING\r\n
C: OPNTRN GETKEY alice@mail.remote.example\r\n
S: 250 OPNTRN KEY openneutron-2 MIICIjANBgkqhkiG9w0BAQEFAAOCAI8A...(base64 SPKI)...\r\n
C: QUIT\r\n
S: 221 Bye\r\n
```

### Example B - E2EE delivery

```
C: [TCP connect to mail.remote.example:25]
S: 220 mail.remote.example ESMTP ready\r\n
C: EHLO mail.sender.example\r\n
S: 250-mail.remote.example\r\n
S: 250-STARTTLS\r\n
S: 250-OPNTRN\r\n
S: 250 CHUNKING\r\n
C: STARTTLS\r\n
S: 220 2.0.0 Ready to start TLS\r\n
[TLS handshake]
C: EHLO mail.sender.example\r\n
S: 250-mail.remote.example\r\n
S: 250-OPNTRN\r\n
S: 250 CHUNKING\r\n
C: OPNTRN E2EE\r\n
S: 250 OPNTRN OK\r\n
C: MAIL FROM:<bob@mail.sender.example>\r\n
S: 250 2.1.0 OK\r\n
C: RCPT TO:<alice@mail.remote.example>\r\n
S: 250 2.1.5 OK\r\n
C: DATA\r\n
S: 354 End data with <CR><LF>.<CR><LF>\r\n
C: \x00\x00\x02\x00<512 bytes RSA-OAEP key><12 bytes nonce><N bytes ciphertext><16 bytes GCM tag>\r\n
C: .\r\n
S: 250 2.0.0 OK\r\n
C: QUIT\r\n
S: 221 Bye\r\n
```

> The DATA body is the raw packed binary blob.  It is not base64-encoded on the wire;
> only the SMTP dot-stuffing transparency encoding is applied.

### Example C - Receiving server handling after DATA

```
1. EmailReceivingFSM accumulates raw_data bytes until "\r\n.\r\n" is detected.
2. smtp_dot_unstuff() removes any leading dots from dot-stuffed lines.
3. is_e2ee = true (set by OPNTRN E2EE handler earlier in session).
4. main.rs calls Email::new_e2ee(received, &user):
      unpack_encrypted_email(&raw_data)
        -> message_key   = raw_data[4..516]   (512 bytes)
        -> aes_ciphertext = raw_data[516..]   (12+N+16 bytes)
5. Email struct is bincode-serialized and written to {blobs_dir}/{uid}.bin
6. uid appended to user.emailIds
7. user_storage.save_to_file() persists the updated user record.
```
