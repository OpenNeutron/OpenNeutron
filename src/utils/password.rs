//! Server-side pepper for stored password hashes.
//!
//! The web client hashes passwords with bcrypt and a *fixed* salt before sending
//! them, so the server receives the same string for two users who chose the same
//! password. Storing that verbatim means a stolen user database shows which
//! accounts share a password and lets an attacker attack every hash at once.
//!
//! Each stored hash is therefore wrapped in an HMAC whose key is derived from a
//! server-side master secret and the account's own random salt:
//!
//!     stored = "v2$" + base64(HMAC(HMAC(master, user_salt), client_hash))
//!
//! Consequences:
//!   * identical passwords store different values (different user salts)
//!   * a database leak alone is not enough to check candidate passwords - the
//!     master secret lives in the config, not in the database
//!   * the client is unchanged: it still sends its bcrypt hash, and the server
//!     applies (or strips) the pepper around it
//!
//! Legacy hashes (no "v2$" prefix) still verify and are upgraded on next login.

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const PREFIX: &str = "v2$";

static MASTER: OnceLock<Vec<u8>> = OnceLock::new();

/// Install the master secret once at startup. Calling this again is a no-op.
pub fn init_master(secret: &[u8]) {
    let _ = MASTER.set(secret.to_vec());
}

fn master() -> &'static [u8] {
    MASTER.get().map(|s| s.as_slice()).unwrap_or(&[])
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        padded[..32].copy_from_slice(&digest);
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] ^= padded[i];
        outer_pad[i] ^= padded[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_digest);
    out
}

fn per_user_key(user_salt: &str) -> [u8; 32] {
    hmac_sha256(master(), user_salt.as_bytes())
}

/// Wrap a client-supplied password hash for storage.
pub fn wrap(user_salt: &str, client_hash: &str) -> String {
    let key = per_user_key(user_salt);
    let tag = hmac_sha256(&key, client_hash.as_bytes());
    format!("{}{}", PREFIX, STANDARD.encode(tag))
}

/// True when `stored` is a pre-pepper hash that should be upgraded on next login.
pub fn is_legacy(stored: &str) -> bool {
    !stored.starts_with(PREFIX)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a presented client hash against a stored value, peppered or legacy.
pub fn verify(stored: &str, user_salt: &str, presented: &str) -> bool {
    if is_legacy(stored) {
        return constant_time_eq(stored.as_bytes(), presented.as_bytes());
    }
    let candidate = wrap(user_salt, presented);
    constant_time_eq(candidate.as_bytes(), stored.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_is_not_the_raw_hash() {
        init_master(b"master-secret");
        let wrapped = wrap("abc123", "$2a$10$somehash");
        assert!(wrapped.starts_with(PREFIX));
        assert!(!wrapped.contains("somehash"), "the raw hash must not survive");
    }

    #[test]
    fn the_same_password_wraps_differently_per_user() {
        init_master(b"master-secret");
        let a = wrap("salt-one", "$2a$10$identical");
        let b = wrap("salt-two", "$2a$10$identical");
        assert_ne!(a, b, "per-user salt must make identical passwords differ");
    }

    #[test]
    fn a_wrapped_hash_verifies_for_the_right_password_only() {
        init_master(b"master-secret");
        let wrapped = wrap("salt-one", "$2a$10$right");
        assert!(verify(&wrapped, "salt-one", "$2a$10$right"));
        assert!(!verify(&wrapped, "salt-one", "$2a$10$wrong"));
        assert!(!verify(&wrapped, "salt-two", "$2a$10$right"));
    }

    #[test]
    fn legacy_hashes_still_verify_and_are_flagged() {
        init_master(b"master-secret");
        assert!(is_legacy("$2a$10$legacy"));
        assert!(verify("$2a$10$legacy", "salt-one", "$2a$10$legacy"));
        assert!(!verify("$2a$10$legacy", "salt-one", "$2a$10$other"));
    }
}
