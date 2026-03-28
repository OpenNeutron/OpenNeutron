# OpenNeutron - Key Derivation & Key Storage Reference

This document describes every key, salt, hash, and credential in OpenNeutron: exactly how
each one is produced, what algorithm and parameters are used, what bytes flow in and out,
and where the result is stored or compared.

---

## Table of Contents

1. [RSA Key Pair - Generation](#1-rsa-key-pair--generation)
2. [Public Key Storage](#2-public-key-storage)
3. [Password Auth Token](#3-password-auth-token)
4. [Per-User Server Salt](#4-per-user-server-salt)
5. [Private Key Encryption (client-side, at-rest)](#5-private-key-encryption-client-side-at-rest)
6. [Private Key Decryption (on login)](#6-private-key-decryption-on-login)
7. [Login Flow - Credential Comparison](#7-login-flow--credential-comparison)
8. [Session Tokens (JWT)](#8-session-tokens-jwt)
9. [Registration Flows](#9-registration-flows)
10. [Password / Credential Change](#10-password--credential-change)
11. [Public Key Fingerprint (per-email)](#11-public-key-fingerprint-per-email)

---

## 1. RSA Key Pair - Generation

Every user has exactly one RSA key pair, generated entirely in the browser.

| Parameter        | Value                  |
|------------------|------------------------|
| Algorithm        | RSA-OAEP               |
| Modulus length   | 4096 bits              |
| Public exponent  | 65537 ('0x010001')     |
| OAEP hash        | SHA-256                |
| Key usages       | '["encrypt", "decrypt"]' |
| Extractable      | 'true'                 |

**Code location:** 'crypto_frontend.js -> generateKeyPair()'

```js
const kp = await crypto.subtle.generateKey(
  { name: 'RSA-OAEP', modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['encrypt', 'decrypt'],
)
```

The server **never sees the plaintext private key** at any point.

---

## 2. Public Key Storage

### Client export

The public key is exported as SPKI DER bytes, then base64-encoded:

```js
const spki = await crypto.subtle.exportKey('spki', publicKey)  // ArrayBuffer (DER)
const b64  = toB64(spki)                                        // standard base64 string
```

### Server storage

The server holds the raw DER bytes inside a 'PublicKey(Vec<u8>)' newtype wrapper.

```rust
pub struct PublicKey(pub Vec<u8>);
```

Serialization (JSON / bincode) encodes the inner bytes as base64.  The field is
'user.publicKey: Option<PublicKey>'.  A 'None' value means the user has not yet set
a key (cannot receive encrypted mail).

Fields that reference the public key:

| Location            | Field             | Type             | Content                           |
|---------------------|-------------------|------------------|-----------------------------------|
| 'User' struct       | 'publicKey'       | 'Option<PublicKey>' | Raw SPKI DER bytes              |
| Login response JSON | 'public_key'      | 'string \| null' | base64(SPKI DER)                  |
| 'Email' struct      | 'publicKeyHash'   | 'Sha256Hash'     | SHA-256(SPKI DER bytes) - 32 bytes |

---

## 3. Password Auth Token

The password is never sent in plaintext.  Before every login or registration the client
derives a deterministic bcrypt token from the plaintext password and a **fixed, hard-coded
salt**.

### Fixed auth salt

```
ASCII: "OpenNeutronAuth1"   (16 bytes)
Hex:   4f 70 65 6e 4e 65 75 74 72 6f 6e 41 75 74 68 31
```

This salt is **not a secret** and is **not random**.  Security comes entirely from bcrypt's
work factor (10 rounds).

### Derivation

```
auth_token = bcrypt(
    password   = UTF-8(plaintext_password),   // arbitrary length
    salt       = AUTH_SALT,                   // fixed 16 bytes above
    costFactor = 10,
    outputType = "encoded",                   // full bcrypt string, e.g. "$2b$10$..."
)
```

The 'hash-wasm' library is used.  'outputType: "encoded"' returns the full 60-character
Modular Crypt Format string (algo identifier + cost + 22-char salt + 31-char hash).

**Code location:** 'crypto_frontend.js -> hashPassword(password)'

### Server-side comparison

The server stores the full encoded bcrypt string verbatim in 'user.passwordHash: Option<String>'
and compares it with a plain string equality check:

```rust
fn verify_password(&self, passwordHash: String) -> bool {
    match &self.passwordHash {
        Some(stored) => stored == &passwordHash,
        None => true,   // no password set yet (force_reset state) - all tokens accepted
    }
}
```

No additional server-side hashing is applied.  The bcrypt work factor is the sole cost
barrier.

---

## 4. Per-User Server Salt

Each user has a random 16-byte (32 hex-char) salt stored on the server.

### Generation

```rust
fn gen_salt() -> String {
    let mut rng = rand::thread_rng();
    let a: u64 = rng.gen();
    let b: u64 = rng.gen();
    format!("{:016x}{:016x}", a, b)   // 32 lowercase hex characters
}
```

Two independent 64-bit random values are concatenated, giving 128 bits of entropy.

### Storage

'user.salt: String' - always present (defaulted via '#[serde(default = "gen_salt")]'
so older serialized records without the field get a fresh salt on first deserialize).

### When issued to the client

The salt is returned in **every successful login response**:

```json
{
  "token": "...",
  "salt": "a3f8b2e4c1d70912...",
  "encrypted_private_key": "...",
  ...
}
```

The client never possesses the salt before the first login.

---

## 5. Private Key Encryption (client-side, at-rest)

The private key is encrypted in the browser before it is ever sent to the server.  Both
the AES key and the IV are deterministically derived from the plaintext password and the
per-user server salt.  This means:

- The server cannot decrypt the private key (it never holds the plaintext password).
- Losing the password means losing the private key permanently.
- The encrypted blob has no nonce prepended to it; the nonce is re-derived each time.

**Code location:** 'crypto_frontend.js -> encryptPrivateKey()' /
'deriveKeyMaterial()'

### Step 1 - Convert server salt

```
salt_bytes = hexToBytes(server_salt)   // 32 hex chars -> 16 bytes
```

### Step 2 - First KDF layer (bcrypt)

```
bcrypt_out = bcrypt(
    password   = UTF-8(plaintext_password),
    salt       = salt_bytes,               // 16 bytes, user-specific
    costFactor = 10,
    outputType = "binary",                 // 24 bytes (raw blowfish output)
)
```

Note: 'outputType: "binary"' from hash-wasm returns the raw 24-byte blowfish output,
not the encoded string.

### Step 3 - Second KDF layer (Argon2id)

```
material = Argon2id(
    password    = bcrypt_out,   // 24 bytes from step 2
    salt        = salt_bytes,   // same 16 bytes as step 2
    iterations  = 3,
    memorySize  = 65536,        // 64 MiB
    hashLength  = 44,           // 44 bytes output
    parallelism = 1,
    outputType  = "binary",
)
```

### Step 4 - Split material

```
aes_key = material[0 .. 32]    // 32 bytes  ->  AES-256-GCM key
iv      = material[32 .. 44]   // 12 bytes  ->  AES-GCM nonce (deterministic!)
```

### Step 5 - Encrypt

```
pkcs8_bytes         = exportKey('pkcs8', privateKey)         // raw PKCS#8 DER bytes
encrypted_raw       = AES-256-GCM-Encrypt(pkcs8_bytes, key=aes_key, iv=iv)
                      // output: ciphertext || 16-byte GCM authentication tag
                      // NO nonce is prepended - the nonce is derived, not stored
encrypted_private_key = Base64(encrypted_raw)                // standard base64 string
```

### What is uploaded to the server

'user.encrypted_private_key: Option<String>' - the base64 blob above.

---

## 6. Private Key Decryption (on login)

The reverse of section 5.  Performed in the browser after receiving the login response.

**Code location:** 'crypto_frontend.js -> decryptPrivateKey()'

```
Inputs:
  encryptedKey  = user.encrypted_private_key from login response (base64)
  password      = plaintext password (typed by user)
  serverSalt    = user.salt from login response (32 hex chars)

1. material = deriveKeyMaterial(password, serverSalt)   // same as s.5 steps 1-3
2. aes_key  = material[0:32]
3. iv       = material[32:44]
4. pkcs8    = AES-256-GCM-Decrypt(fromB64(encryptedKey), key=aes_key, iv=iv)
5. privateKey = importKey('pkcs8', pkcs8, { name:'RSA-OAEP', hash:'SHA-256' }, true, ['decrypt'])
```

If the password is wrong, step 4 fails with an AES-GCM authentication error (the GCM tag
does not verify).

---

## 7. Login Flow - Credential Comparison

```
POST /auth/login
Content-Type: application/json

{ "username": "alice", "password": "<bcrypt encoded auth token>" }
```

Server logic:

1. Look up user by 'username'.
2. Call 'user.verify_password(submitted_token)' -> plain string equality against 'user.passwordHash'.
3. If 'passwordHash = null' (admin-created, force_reset), **any token is accepted** (the user
   is forced to set credentials after login via 'POST /user/setup').
4. On success: issue JWT, count unread emails, return:

```json
{
  "token": "<JWT>",
  "force_reset": false,
  "username": "alice",
  "public_key": "<base64 SPKI DER | null>",
  "unread_emails": 3,
  "salt": "<32 hex chars>",
  "encrypted_private_key": "<base64 AES-GCM blob | null>"
}
```

---

## 8. Session Tokens (JWT)

| Field       | Value                                               |
|-------------|-----------------------------------------------------|
| Algorithm   | HS256                                               |
| Secret      | 'openneutron_jwt_secret_change_in_production'       |
| Expiry      | 3600 seconds (1 hour)                               |
| Subject     | 'username' (plaintext string)                       |

All API routes registered with 'auth=true' validate the 'Authorization: Bearer <token>' header
by verifying the HS256 signature and checking the 'exp' claim before dispatching.

---

## 9. Registration Flows

### Self-registration ('POST /user/register')

1. Browser generates RSA-OAEP 4096-bit key pair.
2. Browser computes 'auth_token = hashPassword(password)' (bcrypt, fixed salt, cost=10).
3. Browser exports public key as base64 SPKI ('exportPublicKeyBase64').
4. Browser calls 'encryptPrivateKey(privateKey, password, placeholder_salt)' - at this
   point the real server salt is not yet known.  The placeholder may be anything; the
   blob is replaced immediately after.
5. Client sends:

```json
POST /user/register
{
  "username": "alice",
  "password": "<auth_token>",
  "public_key": "<base64 SPKI>",
  "encrypted_private_key": "<base64 blob>"
}
```

6. Server creates a new user record with a **freshly generated 'gen_salt()' salt**.
7. Client immediately logs in ('POST /auth/login') to receive the real 'user.salt'.
8. Client re-derives 'encryptPrivateKey(privateKey, password, real_salt)' and calls
   'POST /user/credentials' with the corrected blob.

### Admin-created users ('POST /admin/users' -> 'POST /user/setup')

1. Admin calls:

```json
POST /admin/users
Authorization: Bearer <admin JWT>
{ "username": "bob" }
```

Server creates user with 'passwordHash = null', 'force_reset = true', no public key.

2. User logs in with any token:

```json
POST /auth/login
{ "username": "bob", "password": "<anything>" }
```

Response includes 'force_reset: true', 'salt: "<server salt>"'.

3. User generates key pair, derives auth token and encrypted private key using the real salt,
   then calls:

```json
POST /user/setup
Authorization: Bearer <JWT>
{
  "password": "<auth_token>",
  "public_key": "<base64 SPKI>",
  "encrypted_private_key": "<base64 blob>"
}
```

This endpoint only works while 'force_reset = true' (i.e., 'passwordHash = null').

---

## 10. Password / Credential Change

```json
POST /user/credentials
Authorization: Bearer <JWT>
{
  "password": "<new_auth_token | omit>",
  "public_key": "<new base64 SPKI | omit>",
  "encrypted_private_key": "<new base64 blob | omit>"
}
```

All three fields are optional; only the supplied ones are updated.  When changing the
password, the client must also re-encrypt the private key with the new password + existing
server salt and include both 'password' and 'encrypted_private_key' in the same request.

Admins can update any user's credentials via:

```json
POST /admin/users/credentials
Authorization: Bearer <admin JWT>
{
  "username": "alice",
  "password": "...",
  "public_key": "...",
  "encrypted_private_key": "..."
}
```

---

## 11. Public Key Fingerprint (per-email)

> **SHA-256 usage note:** SHA-256 is used here **only as an identification and comparison
> fingerprint for non-secret public data**.  It carries no security function.  SHA-256 is
> not used anywhere in OpenNeutron for password hashing, key derivation, or any
> secret-sensitive operation - those exclusively use bcrypt (cost=10) and Argon2id (see
> s.3 and s.5).  Public keys are by definition public; hashing them with SHA-256 is safe
> and standard practice for generating short, fixed-size identifiers.

Each 'Email' record stores a 'publicKeyHash: Sha256Hash([u8; 32])' computed at
delivery time:

```rust
publicKeyHash = SHA-256(user.publicKey.0)   // SHA-256 of the raw SPKI DER bytes
```

On the client side the same hash is computed via:

```js
const spki = fromB64(publicKeyBase64)
const hash  = await crypto.subtle.digest('SHA-256', spki)   // 32 bytes
return toB64(hash)                                           // base64 string
```

This value is used **only for two non-security-critical purposes**:

1. **Key-change detection** - the client can compare the stored hash against the hash of
   the current public key to determine whether the key was rotated after the email was
   encrypted.  If they differ, the 'message_key' blob was encrypted for a different RSA
   key and decryption will fail.
2. **Informational display** - a short fingerprint that a client UI can display to the
   user for manual verification ("this email was encrypted for key fingerprint 'abc123...'").

Neither purpose involves protecting a secret.  A collision in this hash would at worst
cause the client to skip a key-mismatch warning - it would not expose any private key or
plaintext.  SHA-256 is more than sufficient for both uses.
