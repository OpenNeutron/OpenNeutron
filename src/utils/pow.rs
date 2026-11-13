//! Proof-of-work gate for open registration.
//!
//! Signup is public, so a script can mint mailboxes as fast as it can POST.
//! Rate limiting caps one host; a proof-of-work challenge puts a real cost on
//! every account without a captcha vendor, a tracking script or an account with
//! a third party.
//!
//! The client searches for a nonce such that `sha256(challenge + nonce)` starts
//! with `difficulty` zero **bits**. The server re-hashes once: verification is
//! free, solving is not. Challenges are single-use and expire.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// ~262k hashes on average: a fraction of a second in a browser worker, and
/// roughly a thousand times that to farm in bulk.
const DIFFICULTY_BITS: u32 = 14;
const CHALLENGE_TTL_SECONDS: u64 = 900;

#[derive(Serialize)]
pub struct Challenge {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_in: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Issued challenges, with the time they were handed out.
static ISSUED: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();

fn issued() -> &'static Mutex<HashMap<String, u64>> {
    ISSUED.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn issue() -> Challenge {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let challenge = hex::encode(bytes);
    let stamp = now();

    if let Ok(mut map) = issued().lock() {
        // Drop anything past its life so the map cannot grow without bound.
        map.retain(|_, issued_at| stamp.saturating_sub(*issued_at) < CHALLENGE_TTL_SECONDS);
        map.insert(challenge.clone(), stamp);
    }

    Challenge {
        challenge,
        difficulty: DIFFICULTY_BITS,
        expires_in: CHALLENGE_TTL_SECONDS,
    }
}

fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
            continue;
        }
        bits += byte.leading_zeros();
        break;
    }
    bits
}

/// Check a solution, consuming the challenge so it cannot be replayed.
pub fn verify(challenge: &str, nonce: &str) -> Result<(), &'static str> {
    if challenge.is_empty() || nonce.is_empty() || nonce.len() > 64 {
        return Err("pow_required");
    }

    let issued_at = {
        let mut map = match issued().lock() {
            Ok(m) => m,
            Err(_) => return Err("pow_unavailable"),
        };
        match map.remove(challenge) {
            Some(stamp) => stamp,
            // Unknown or already spent: both mean "solve a fresh one".
            None => return Err("pow_invalid"),
        }
    };

    if now().saturating_sub(issued_at) > CHALLENGE_TTL_SECONDS {
        return Err("pow_expired");
    }

    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    hasher.update(nonce.as_bytes());
    let digest = hasher.finalize();

    if leading_zero_bits(&digest) < DIFFICULTY_BITS {
        return Err("pow_invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0x00, 0x0f, 0xff]), 12);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x01]), 23);
    }
}
