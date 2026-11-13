//! Post-quantum protection for mail at rest.
//!
//! Stored mail is AES-256-GCM under a key that is wrapped to the account's RSA
//! key. RSA is the one part of that stack a quantum computer breaks outright, and
//! mail is exactly the long-lived data an attacker would harvest today and open
//! later. So the wrap becomes hybrid: the AES key is derived from **both**
//! an RSA-OAEP seed and an ML-KEM-768 (FIPS 203) shared secret. Opening a message
//! needs both; breaking one leaves the other standing.
//!
//! Envelope, carried in the existing `message_key` slot:
//!
//! ```text
//! "SLQ" | 0x01 | rsa_ct_len (u16 BE) | rsa_ct | mlkem_ct (1088 bytes)
//! ```
//!
//! No magic prefix means the blob predates this change: the reader unwraps it
//! with RSA alone, forever, because mail already stored can never be re-created.
//!
//! Key material lives in a sidecar (`data/pqkeys.json`) because `User` is
//! positional bincode: adding a field would make every existing record
//! unreadable. The public half is stored as sent; the private half is stored
//! **already encrypted by the browser** under the password-derived wrap key, so
//! this server sees exactly what it sees for the RSA key — ciphertext.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::utils::cryptography::PublicKey;

pub const HYBRID_MAGIC: [u8; 4] = [0x53, 0x4c, 0x51, 0x01]; // "SLQ" + version 1
pub const MLKEM_CT_LEN: usize = 1088;

fn sidecar() -> PathBuf {
    PathBuf::from("data/pqkeys.json")
}

#[derive(Clone, Debug)]
pub struct PqKeys {
    /// ML-KEM-768 encapsulation key, base64 (1184 bytes decoded).
    pub public_key: String,
    /// Decapsulation key, encrypted by the browser. Opaque here.
    pub encrypted_private_key: String,
    pub created_at: u64,
}

fn read_all() -> Value {
    std::fs::read_to_string(sidecar())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| json!({ "users": {} }))
}

fn write_all(value: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let tmp = sidecar().with_extension("json.tmp");
    // Write-then-rename: a half-written key store would lock every account out
    // of its own mail, which is the one failure this feature must never cause.
    std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, sidecar()).map_err(|e| e.to_string())
}

pub fn get(username: &str) -> Option<PqKeys> {
    let all = read_all();
    let entry = all.get("users")?.get(username)?;
    Some(PqKeys {
        public_key: entry.get("public_key")?.as_str()?.to_string(),
        encrypted_private_key: entry.get("encrypted_private_key")?.as_str()?.to_string(),
        created_at: entry.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
    })
}

pub fn set(username: &str, public_key: &str, encrypted_private_key: &str) -> Result<(), String> {
    // Refuse anything that is not a real ML-KEM-768 key rather than store a
    // stub that every future wrap would then encapsulate to.
    let raw = STANDARD
        .decode(public_key.trim())
        .map_err(|_| "public key is not base64".to_string())?;
    if raw.len() != 1184 {
        return Err(format!(
            "public key must be 1184 bytes for ML-KEM-768, got {}",
            raw.len()
        ));
    }
    if encrypted_private_key.trim().is_empty() {
        return Err("encrypted private key is empty".to_string());
    }

    let mut all = read_all();
    if !all.get("users").map(|u| u.is_object()).unwrap_or(false) {
        all["users"] = json!({});
    }
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    all["users"][username] = json!({
        "public_key": public_key.trim(),
        "encrypted_private_key": encrypted_private_key.trim(),
        "created_at": created,
        "version": 1,
    });
    write_all(&all)
}

pub fn remove(username: &str) -> Result<(), String> {
    let mut all = read_all();
    if let Some(users) = all.get_mut("users").and_then(|u| u.as_object_mut()) {
        users.remove(username);
    }
    write_all(&all)
}

/// Derive the data key from both secrets. Bind the account name so a blob
/// replayed onto another account derives a different key and fails to open.
fn combine(rsa_seed: &[u8], mlkem_secret: &[u8], username: &str) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut ikm = Vec::with_capacity(rsa_seed.len() + mlkem_secret.len());
    ikm.extend_from_slice(rsa_seed);
    ikm.extend_from_slice(mlkem_secret);
    let hk = Hkdf::<Sha256>::new(Some(b"sloth-mail/atrest/v1"), &ikm);
    let mut out = [0u8; 32];
    hk.expand(username.as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF output length");
    out
}

/// Encrypt `data` to a hybrid of the RSA key and the account's ML-KEM key.
///
/// Returns `(message_key_envelope, aes_ciphertext)`, matching `encrypt_split`
/// so the storage layer does not change at all.
pub fn encrypt_hybrid(
    rsa_public: &PublicKey,
    mlkem_public_b64: &str,
    data: &[u8],
    username: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
    use ml_kem::kem::Encapsulate;
    use ml_kem::{EncapsulationKey, MlKem768};
    use rand::RngCore;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPublicKey};

    let rsa_pub = RsaPublicKey::from_public_key_der(&rsa_public.0)
        .map_err(|e| format!("failed to parse RSA public key: {}", e))?;

    let ek_bytes = STANDARD
        .decode(mlkem_public_b64.trim())
        .map_err(|_| "post-quantum key is not base64".to_string())?;
    let key = ml_kem::kem::Key::<EncapsulationKey<MlKem768>>::try_from(ek_bytes.as_slice())
        .map_err(|_| format!("post-quantum key must be 1184 bytes, got {}", ek_bytes.len()))?;
    let ek = EncapsulationKey::<MlKem768>::new(&key)
        .map_err(|_| "post-quantum key failed validation".to_string())?;

    let mut rng = rand::thread_rng();

    // RSA half: a random seed wrapped to the account key.
    let mut rsa_seed = [0u8; 32];
    rng.fill_bytes(&mut rsa_seed);
    let rsa_ct = rsa_pub
        .encrypt(&mut rng, Oaep::new::<sha2::Sha256>(), &rsa_seed)
        .map_err(|e| format!("RSA-OAEP encryption failed: {}", e))?;

    // Post-quantum half: an ML-KEM encapsulation to the account's PQ key.
    let (ct, ss) = ek.encapsulate();
    let mlkem_ct = ct.as_slice().to_vec();
    if mlkem_ct.len() != MLKEM_CT_LEN {
        return Err(format!("unexpected ML-KEM ciphertext length {}", mlkem_ct.len()));
    }

    let key_bytes = combine(&rsa_seed, ss.as_slice(), username);
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), data)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    let mut aes_ciphertext = Vec::with_capacity(12 + ciphertext.len());
    aes_ciphertext.extend_from_slice(&nonce_bytes);
    aes_ciphertext.extend_from_slice(&ciphertext);

    let mut envelope = Vec::with_capacity(4 + 2 + rsa_ct.len() + MLKEM_CT_LEN);
    envelope.extend_from_slice(&HYBRID_MAGIC);
    envelope.extend_from_slice(&(rsa_ct.len() as u16).to_be_bytes());
    envelope.extend_from_slice(&rsa_ct);
    envelope.extend_from_slice(&mlkem_ct);

    Ok((envelope, aes_ciphertext))
}

pub fn is_hybrid(message_key: &[u8]) -> bool {
    message_key.len() > 4 && message_key[..4] == HYBRID_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
    use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
    use ml_kem::{DecapsulationKey, MlKem768};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

    struct Fixture {
        rsa_private: RsaPrivateKey,
        rsa_public_der: Vec<u8>,
        dk: DecapsulationKey<MlKem768>,
        ek_b64: String,
    }

    fn fixture() -> Fixture {
        let mut rng = rand::thread_rng();
        let rsa_private = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
        let rsa_public_der = {
            use rsa::pkcs8::EncodePublicKey;
            rsa_private.to_public_key().to_public_key_der().unwrap().as_bytes().to_vec()
        };
        let (dk, ek) = MlKem768::generate_keypair();
        let ek_b64 = STANDARD.encode(ek.to_bytes().as_slice());
        Fixture { rsa_private, rsa_public_der, dk, ek_b64 }
    }

    fn open(fx: &Fixture, username: &str, envelope: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        use rsa::Oaep as _Oaep;
        let _ = _Oaep::new::<sha2::Sha256>();
        if &envelope[..4] != &HYBRID_MAGIC {
            return Err("not a hybrid envelope".into());
        }
        let rsa_len = u16::from_be_bytes([envelope[4], envelope[5]]) as usize;
        let rsa_ct = &envelope[6..6 + rsa_len];
        let mlkem_ct = &envelope[6 + rsa_len..];

        let rsa_pub = RsaPublicKey::from_public_key_der(&fx.rsa_public_der).unwrap();
        let _ = rsa_pub;
        let mut rng = rand::thread_rng();
        let rsa_seed = fx
            .rsa_private
            .decrypt(Oaep::new::<sha2::Sha256>(), rsa_ct)
            .map_err(|e| format!("rsa: {}", e))?;
        let _ = &mut rng;

        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(mlkem_ct)
            .map_err(|_| "bad mlkem ciphertext".to_string())?;
        let ss = fx.dk.decapsulate(&ct);
        let key_bytes = combine(&rsa_seed, ss.as_slice(), username);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        cipher
            .decrypt(Nonce::from_slice(&data[..12]), &data[12..])
            .map_err(|_| "aes-gcm: authentication failed".to_string())
    }

    #[test]
    fn a_hybrid_blob_opens_with_both_keys() {
        let fx = fixture();
        let public = PublicKey(fx.rsa_public_der.clone());
        let (envelope, data) = encrypt_hybrid(&public, &fx.ek_b64, b"the body", "tibs").unwrap();
        assert_eq!(open(&fx, "tibs", &envelope, &data).unwrap(), b"the body");
    }

    #[test]
    fn two_wraps_of_one_message_never_share_ciphertext() {
        let fx = fixture();
        let public = PublicKey(fx.rsa_public_der.clone());
        let (a, a_data) = encrypt_hybrid(&public, &fx.ek_b64, b"same", "tibs").unwrap();
        let (b, b_data) = encrypt_hybrid(&public, &fx.ek_b64, b"same", "tibs").unwrap();
        assert_ne!(a, b, "the RSA half must be randomised");
        assert_ne!(a_data, b_data, "the nonce must be random per message");
    }

    #[test]
    fn breaking_the_post_quantum_half_closes_the_message() {
        // This is the property that makes the wrap hybrid: with RSA alone the
        // message must not open. Corrupt one byte of the ML-KEM ciphertext and
        // keep everything else intact.
        let fx = fixture();
        let public = PublicKey(fx.rsa_public_der.clone());
        let (envelope, data) = encrypt_hybrid(&public, &fx.ek_b64, b"secret", "tibs").unwrap();
        let mut damaged = envelope.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0xff;
        assert!(open(&fx, "tibs", &damaged, &data).is_err());
    }

    #[test]
    fn a_blob_does_not_move_between_accounts() {
        let fx = fixture();
        let public = PublicKey(fx.rsa_public_der.clone());
        let (envelope, data) = encrypt_hybrid(&public, &fx.ek_b64, b"mine", "tibs").unwrap();
        assert!(open(&fx, "someone-else", &envelope, &data).is_err());
    }

    #[test]
    fn short_keys_are_refused() {
        let fx = fixture();
        let public = PublicKey(fx.rsa_public_der.clone());
        assert!(encrypt_hybrid(&public, "AAAA", b"x", "tibs").is_err());
    }

    #[test]
    fn legacy_blobs_are_not_mistaken_for_hybrid_ones() {
        let legacy = vec![0x9a; 512]; // raw RSA ciphertext, no prefix
        assert!(!is_hybrid(&legacy));
        let fx = fixture();
        let public = PublicKey(fx.rsa_public_der.clone());
        let (envelope, _) = encrypt_hybrid(&public, &fx.ek_b64, b"x", "tibs").unwrap();
        assert!(is_hybrid(&envelope));
    }

    #[test]
    fn the_encoded_key_is_the_documented_size() {
        let fx = fixture();
        assert_eq!(STANDARD.decode(&fx.ek_b64).unwrap().len(), 1184);
        // And it parses back into a usable encapsulation key.
        let raw = STANDARD.decode(&fx.ek_b64).unwrap();
        let key = ml_kem::kem::Key::<ml_kem::EncapsulationKey<MlKem768>>::try_from(raw.as_slice()).unwrap();
        let ek = ml_kem::EncapsulationKey::<MlKem768>::new(&key).unwrap();
        let (ct, _ss) = ek.encapsulate();
        assert_eq!(ct.as_slice().len(), MLKEM_CT_LEN);
    }
}
