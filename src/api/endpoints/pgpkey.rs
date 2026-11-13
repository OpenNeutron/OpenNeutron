//! The account's OpenPGP key, kept on the account.
//!
//! Until now the OpenPGP identity lived in one browser's localStorage and nowhere
//! else: clearing site data lost it, and signing in on a phone showed no identity at
//! all. This stores it on the account instead — but *only ever wrapped*: the browser
//! encrypts the private key with a key derived from the account password (PBKDF2 →
//! AES-GCM) and this endpoint sees ciphertext. The server cannot read it, which is the
//! whole point of the service and must stay true here.
//!
//! Storage is a sidecar (`data/pgpkeys.json`) keyed by username. Deliberately not a
//! field on `User`: `data/users.bin` is bincode and positional, so a new field makes
//! every existing record unreadable.
//!
//! Shape:
//!
//! ```json
//! { "tibs": { "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----…",
//!             "encrypted_private_key": "<base64 AES-GCM>",
//!             "fingerprint": "ABCD…",
//!             "kdf": "pbkdf2-sha256:310000:aes-256-gcm",
//!             "updated_at": "2026-10-29T23:10:00Z" } }
//! ```

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex, OnceLock};
use tiny_http::{Request, Response};

use crate::api::dto::{json_header, ErrorResponse, MessageResponse};
use crate::api::request::read_json_body;
use crate::core::{EmailStorage, User, UserStorage};

const STORE_PATH: &str = "data/pgpkeys.json";
/// An armoured secret key of a 4096-bit RSA identity is ~6 KB; wrapped and base64'd it
/// is comfortably under this. Ed25519 identities are far smaller. Anything larger is
/// not a key we generated.
const MAX_FIELD_BYTES: usize = 96 * 1024;

static WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn lock() -> &'static Mutex<()> {
    WRITE_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub public_key: String,
    pub encrypted_private_key: String,
    /// Base64 of the PBKDF2 salt. Stored with the ciphertext because a wrapped key
    /// without its salt cannot be unwrapped — the two are one artefact.
    pub salt: String,
    pub fingerprint: String,
    pub kdf: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    pub updated_at: String,
}

#[derive(Deserialize)]
pub struct PutKeyRequest {
    pub public_key: String,
    pub encrypted_private_key: String,
    pub salt: String,
    pub fingerprint: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    /// Describes how the private key was wrapped, e.g. `pbkdf2-sha256:310000:aes-256-gcm`.
    /// Recorded so a future client knows what it is looking at.
    pub kdf: String,
}

fn load_store() -> HashMap<String, StoredKey> {
    match fs::read_to_string(STORE_PATH) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn save_store(store: &HashMap<String, StoredKey>) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(store).unwrap_or_default();
    let tmp = format!("{STORE_PATH}.tmp");
    fs::write(&tmp, body)?;
    fs::rename(&tmp, STORE_PATH)
}

fn json<T: Serialize>(value: &T, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(serde_json::to_vec(value).unwrap_or_default())
        .with_status_code(status)
        .with_header(json_header())
}

fn fail(code: &str, message: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    json(&ErrorResponse { error: message.into(), code: code.into() }, status)
}

/// A fingerprint is 40 hex characters (v4) or 64 (v5), and nothing else.
fn fingerprint_is_sane(fingerprint: &str) -> bool {
    let cleaned: String = fingerprint.chars().filter(|c| !c.is_whitespace()).collect();
    (cleaned.len() == 40 || cleaned.len() == 64) && cleaned.chars().all(|c| c.is_ascii_hexdigit())
}

/// The public key must be armoured OpenPGP text; accepting arbitrary bytes here would
/// turn this into a free file host attached to an account.
fn public_key_is_sane(armored: &str) -> bool {
    armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        && armored.contains("-----END PGP PUBLIC KEY BLOCK-----")
}

fn kdf_is_sane(kdf: &str) -> bool {
    // Refuse a description that claims no encryption: the private key must never be
    // stored readable, and an empty or "none" marker means the client sent plaintext.
    let trimmed = kdf.trim();
    !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("none") && trimmed.len() <= 120
}

fn now_utc() -> String {
    // Seconds since the epoch, formatted the way the rest of the API reports time.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs.to_string()
}

/// GET /api/user/pgpkey — the stored key, or `{ "exists": false }`.
pub fn get_key(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return fail("unauthorized", "Unauthorized", 401),
    };
    match load_store().remove(&user.username) {
        Some(key) => json(&serde_json::json!({
            "exists": true,
            "public_key": key.public_key,
            "encrypted_private_key": key.encrypted_private_key,
            "salt": key.salt,
            "name": key.name,
            "email": key.email,
            "fingerprint": key.fingerprint,
            "kdf": key.kdf,
            "updated_at": key.updated_at,
        }), 200),
        None => json(&serde_json::json!({ "exists": false }), 200),
    }
}

/// PUT /api/user/pgpkey — replace the account's OpenPGP identity.
pub fn put_key(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return fail("unauthorized", "Unauthorized", 401),
    };
    let body: PutKeyRequest = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    if !public_key_is_sane(&body.public_key) {
        return fail("bad_public_key", "That is not an armoured OpenPGP public key", 400);
    }
    if !fingerprint_is_sane(&body.fingerprint) {
        return fail("bad_fingerprint", "A fingerprint is 40 or 64 hex characters", 400);
    }
    if !kdf_is_sane(&body.kdf) {
        return fail(
            "refuse_unwrapped_private_key",
            "The private key must be encrypted by the browser before it is sent here",
            400,
        );
    }
    if body.encrypted_private_key.trim().is_empty() {
        return fail("missing_private_key", "The encrypted private key is empty", 400);
    }
    // The salt travels with the ciphertext; without it the key is unrecoverable.
    match base64::engine::general_purpose::STANDARD.decode(body.salt.as_bytes()) {
        Ok(bytes) if bytes.len() >= 16 => {}
        _ => return fail("bad_salt", "The salt must be at least 16 bytes, base64", 400),
    }
    if body.encrypted_private_key.len() > MAX_FIELD_BYTES || body.public_key.len() > MAX_FIELD_BYTES {
        return fail("too_large", "That key is larger than this endpoint accepts", 413);
    }
    // Base64-decodable, because that is what the browser says it sent. This catches a
    // client that forgot to encode, and an accidental plaintext key with a kdf label.
    if base64::engine::general_purpose::STANDARD
        .decode(body.encrypted_private_key.as_bytes())
        .is_err()
    {
        return fail("bad_encoding", "The encrypted private key is not base64", 400);
    }
    if body.encrypted_private_key.contains("BEGIN PGP PRIVATE KEY BLOCK") {
        return fail(
            "refuse_unwrapped_private_key",
            "The private key must be encrypted by the browser before it is sent here",
            400,
        );
    }

    let _guard = lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut store = load_store();
    store.insert(user.username.clone(), StoredKey {
        public_key: body.public_key,
        encrypted_private_key: body.encrypted_private_key,
        salt: body.salt,
        fingerprint: body.fingerprint.to_uppercase().replace(' ', ""),
        kdf: body.kdf,
        name: body.name,
        email: body.email,
        updated_at: now_utc(),
    });
    match save_store(&store) {
        Ok(_) => json(&MessageResponse { message: "Key saved to your account".into() }, 200),
        Err(e) => fail("storage_error", &format!("Could not save the key: {e}"), 500),
    }
}

/// DELETE /api/user/pgpkey — forget the identity on the account (the browser's copy is
/// the client's business).
pub fn delete_key(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return fail("unauthorized", "Unauthorized", 401),
    };
    let _guard = lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut store = load_store();
    if store.remove(&user.username).is_none() {
        return fail("not_found", "There is no key on this account", 404);
    }
    match save_store(&store) {
        Ok(_) => json(&MessageResponse { message: "Key removed".into() }, 200),
        Err(e) => fail("storage_error", &format!("Could not save: {e}"), 500),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_40_or_64_hex_and_nothing_else() {
        assert!(fingerprint_is_sane("A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"));
        assert!(fingerprint_is_sane("a1b2 c3d4 e5f6 0718 293a 4b5c 6d7e 8f90 1234 5678"));
        assert!(!fingerprint_is_sane("not-a-fingerprint"));
        assert!(!fingerprint_is_sane("A1B2C3D4"));
        assert!(!fingerprint_is_sane("G1B2C3D4E5F60718293A4B5C6D7E8F9012345678"));
    }

    #[test]
    fn a_public_key_must_be_armoured_pgp() {
        assert!(public_key_is_sane(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxx\n-----END PGP PUBLIC KEY BLOCK-----\n"
        ));
        assert!(!public_key_is_sane("<html>hello</html>"));
        assert!(!public_key_is_sane("-----BEGIN PGP PUBLIC KEY BLOCK-----\nno end"));
    }

    #[test]
    fn a_key_claiming_to_be_unwrapped_is_refused() {
        assert!(!kdf_is_sane(""));
        assert!(!kdf_is_sane("none"));
        assert!(!kdf_is_sane("NONE   "));
        assert!(kdf_is_sane("pbkdf2-sha256:310000:aes-256-gcm"));
    }

    #[test]
    fn the_store_round_trips_through_a_file() {
        let key = StoredKey {
            public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----".into(),
            encrypted_private_key: "AAAA".into(),
            salt: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            fingerprint: "A1B2".into(),
            name: "Tibs".into(),
            email: "tibs@slothlee.xyz".into(),
            kdf: "pbkdf2-sha256:310000:aes-256-gcm".into(),
            updated_at: now_utc(),
        };
        let mut store = HashMap::new();
        store.insert("tibs".to_string(), key.clone());
        let text = serde_json::to_string(&store).unwrap();
        let back: HashMap<String, StoredKey> = serde_json::from_str(&text).unwrap();
        assert_eq!(back["tibs"].encrypted_private_key, "AAAA");
        assert_eq!(back["tibs"].kdf, "pbkdf2-sha256:310000:aes-256-gcm");
    }

    #[test]
    fn a_plaintext_private_key_is_caught_by_the_base64_check() {
        let armoured = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nsecret\n-----END PGP PRIVATE KEY BLOCK-----";
        assert!(base64::engine::general_purpose::STANDARD
            .decode(armoured.as_bytes())
            .is_err());
    }
}
