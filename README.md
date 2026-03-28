<img width="2500" height="500" alt="openneutronlogolargewhite" src="https://github.com/user-attachments/assets/8cbd6bc5-8d48-48e9-96c8-8875f66ae6b8" />

Uncompromising Email.
Your Keys. Your Server.

A self-hostable, true end-to-end encrypted email stack. We ditched IMAP and POP to guarantee zero-trust. Keys never leave your device, and node-to-node routing is strictly client-side E2EE.

> *Because your emails are nobody's business but yours.*

OpenNeutron is an open-source email server built around a simple idea: **the server should never be able to read your mail**. Every email that touches OpenNeutron's storage is encrypted - either by the sending server using the recipient's public key, or end-to-end by the client - so even a fully compromised server leaks nothing but ciphertext.

It speaks standard SMTP on the wire, extends it with a custom 'OPNTRN' capability for peer-to-peer E2EE negotiation, and exposes a clean JSON REST API for client apps to register, authenticate, send, and receive mail.

---

## Features at a Glance

| What | How |
|---|---|
| **At-rest encryption** | Every incoming email is encrypted with the recipient's RSA-4096 public key before it is written to disk (AES-256-GCM + RSA-OAEP) |
| **End-to-end encryption** | The 'OPNTRN' SMTP extension lets two OpenNeutron servers negotiate E2EE delivery; the sending server encrypts for the recipient and the receiving server stores the blob as-is - it never sees the plaintext |
| **Client-side key custody** | RSA key pairs are generated in the browser; the private key is encrypted with a password-derived AES key (bcrypt + Argon2id) before it ever leaves the client. The server holds only the encrypted blob |
| **DKIM** | Verification on inbound mail, signing on outbound (optional) |
| **STARTTLS** | Opportunistic TLS upgrade on SMTP connections, with auto-generated self-signed cert support for development |
| **JWT auth** | HS256 tokens for the REST API, configurable secret (randomised per-startup if you leave it blank) |
| **Groups / folders** | Server-side email grouping so clients can build folder views without seeing plaintext |
| **Blob storage** | Emails live as 'bincode'-serialised blobs under 'data/blobs/' - flat-file, no database required |

---

## Building

You need a working [Rust toolchain](https://rustup.rs) (edition 2024, stable).

```bash
# clone and build (debug)
git clone https://github.com/your-org/openneutron
cd openneutron
cargo build

# or a release binary
cargo build --release
```

The binary lands at 'target/release/OpenNeutron'.

For a fully static musl build (great for containers):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Runtime dependencies

None. All crypto (AES-GCM, RSA-OAEP, DKIM, TLS) is pure-Rust via 'aws-lc-rs' / 'ring' / 'rsa'. No OpenSSL needed.

---

## Running

```bash
./target/release/OpenNeutron
```

OpenNeutron looks for 'config.yml' in the current working directory. If it isn't found, safe defaults kick in and a warning is printed.

On first start with 'tls.self_signed: true' a fresh TLS certificate is auto-generated in memory (nothing is written to disk). Point your SMTP client at the configured port and you're ready to go.

---

## Configuration ('config.yml')

```yml
server:
  domain: "mail.example.com"   # Your mail domain - appears in EHLO and RCPT validation
  smtp_port: 2525              # Port to accept SMTP connections on
  api_port: 8080               # Port for the REST API

storage:
  users_file: "data/users.bin" # Where user records are persisted (bincode)
  blobs_dir: "data/blobs"      # Directory for encrypted email blobs

tls:
  # true  -> generate a self-signed cert on startup (perfect for local dev)
  # false -> load cert_path / key_path (PEM); required for production
  self_signed: true
  cert_path: "certs/cert.pem"
  key_path:  "certs/key.pem"

dkim:
  enabled: true                          # Verify DKIM signatures on inbound mail
  # private_key_path: "dkim_private.pem" # Uncomment to sign outbound mail
  # selector: "default"

logging:
  level: "info"   # trace | debug | info | warn | error

jwt:
  # Omit (or comment out) for a random secret generated on each startup.
  # Set a real value in production so tokens survive restarts.
  # secret: "change_me_to_a_long_random_string"
```

The 'data/' and 'data/blobs/' directories are created automatically if they don't exist.

---

## How the Encryption Works (the short version)

1. **Key generation** - the client generates an RSA-4096 key pair in the browser. The private key is encrypted with AES-256-GCM using a key derived from the user's password via bcrypt -> Argon2id before ever leaving the device. The server stores only the encrypted blob and the public key.

2. **Incoming SMTP mail** - the receiving server fetches the recipient's stored public key and wraps a fresh random AES-256 key with RSA-OAEP-SHA256. The email body is encrypted with that AES key, the AES key is discarded, and '[encrypted_key || nonce || ciphertext]' hits the disk.

3. **OPNTRN E2EE** - if the sending server also runs OpenNeutron, it sends 'OPNTRN GETKEY recipient@domain' to fetch the public key before the session, encrypts the body itself, announces 'OPNTRN E2EE', and transmits the blob over DATA. The receiving server stores it without touching the plaintext. The server is cryptographically excluded from the conversation.

4. **Client send** - clients can also call 'POST /email/sendencrypted' directly: the browser encrypts the body for each recipient independently (using public keys fetched from 'POST /email/publickeys'), and the server relays the pre-encrypted blobs over SMTP without ever seeing the content.

For the full gory detail - wire formats, byte offsets, KDF parameters, SMTP session transcripts - see [E2EE_PROTOCOL.md](E2EE_PROTOCOL.md) and [KEY_DERIVATION.md](KEY_DERIVATION.md).

---

## REST API (quick reference)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| 'POST' | '/auth/login' | No | Get a JWT |
| 'POST' | '/user/register' | No | Self-register with public key |
| 'POST' | '/user/setup' | Yes | Set credentials after admin provisioning |
| 'POST' | '/user/credentials' | Yes | Update password / keys |
| 'GET'  | '/user/me' | Yes | Fetch your own profile |
| 'GET'  | '/admin/users' | Yes (admin) | List all users |
| 'POST' | '/admin/users' | Yes (admin) | Create a user |
| 'DELETE' | '/admin/users' | Yes (admin) | Delete a user |
| 'POST' | '/email/list' | Yes | List email UIDs |
| 'POST' | '/email/get' | Yes | Fetch a single email blob |
| 'POST' | '/email/bulk' | Yes | Fetch multiple blobs at once |
| 'POST' | '/email/send' | Yes | Send an email (server encrypts) |
| 'POST' | '/email/sendencrypted' | Yes | Send a pre-encrypted E2EE email |
| 'POST' | '/email/publickeys' | Yes | Look up public keys for a list of addresses |
| 'GET'  | '/group/list' | Yes | List email groups/folders |
| 'POST' | '/group/create' | Yes | Create a group |

Full request/response schemas are documented in [api.md](api.md).

---

## License

See [LICENSE](LICENSE).

