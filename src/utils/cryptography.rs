use std::io::BufReader;
use std::sync::Arc;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rcgen::generate_simple_self_signed;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rsa::{RsaPublicKey, Oaep};
use rsa::pkcs8::DecodePublicKey;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256Hash(pub [u8; 32]);

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = STANDARD.encode(&self.0);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        Ok(PublicKey(decoded))
    }
}

impl Serialize for Sha256Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = STANDARD.encode(&self.0);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Sha256Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        if decoded.len() != 32 {
            return Err(serde::de::Error::custom("sha256 hash must be 32 bytes"));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&decoded);
        Ok(Sha256Hash(hash))
    }
}



pub fn make_tls_config(tls: &crate::config::TlsSettings) -> Arc<ServerConfig> {
    if tls.self_signed {
        log::info!("[TLS] Generating self-signed certificate");
        let cert = generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let cert_chain = vec![CertificateDer::from(cert_der)];
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .unwrap();
        Arc::new(config)
    } else {
        let cert_path = tls.cert_path.as_deref()
            .expect("tls.cert_path is required when tls.self_signed is false");
        let key_path = tls.key_path.as_deref()
            .expect("tls.key_path is required when tls.self_signed is false");

        log::info!("[TLS] Loading certificate from '{}' and key from '{}'", cert_path, key_path);

        let cert_file = std::fs::File::open(cert_path)
            .unwrap_or_else(|e| panic!("Failed to open TLS cert '{}': {}", cert_path, e));
        let key_file = std::fs::File::open(key_path)
            .unwrap_or_else(|e| panic!("Failed to open TLS key '{}': {}", key_path, e));

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut BufReader::new(cert_file))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|e| panic!("Failed to parse TLS cert '{}': {}", cert_path, e));

        let mut keys: Vec<PrivatePkcs8KeyDer<'static>> =
            rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(key_file))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|e| panic!("Failed to parse TLS key '{}': {}", key_path, e));

        if keys.is_empty() {
            panic!("No PKCS8 private keys found in '{}'", key_path);
        }

        let private_key = PrivateKeyDer::Pkcs8(keys.remove(0));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .unwrap();
        Arc::new(config)
    }
}

pub fn sha256_hash(data: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Sha256Hash(hash)
}

pub fn hash_public_key(public_key: &PublicKey) -> Sha256Hash {
    sha256_hash(&public_key.0)
}

#[allow(dead_code)]
pub fn hash_password(password_hash_string: String) -> Sha256Hash { 
    sha256_hash(password_hash_string.as_bytes())
}

pub fn public_key_from_string(public_key_string: String) -> PublicKey {
    
    let decoded = STANDARD.decode(public_key_string).expect("Invalid base64 public key");
    PublicKey(decoded)
}










/// Encrypt 'data' using hybrid RSA-OAEP + AES-256-GCM and return the two parts split:
/// - 'message_key': RSA-OAEP encrypted 32-byte AES-256 key
/// - 'aes_ciphertext': 'nonce (12 bytes) || ciphertext || GCM tag (16 bytes)'
///
/// The two parts are stored separately in the 'Email' struct ('message_key' and 'raw_data').
/// To produce the SMTP wire blob, call 'pack_encrypted_email' on the two parts.
pub fn encrypt_split(public_key: &PublicKey, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let rsa_pub = RsaPublicKey::from_public_key_der(&public_key.0)
        .map_err(|e| format!("Failed to parse RSA public key: {}", e))?;

    let mut rng = rand::thread_rng();

    let mut aes_key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut aes_key_bytes);
    rng.fill_bytes(&mut nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    let enc_aes_key = rsa_pub
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &aes_key_bytes)
        .map_err(|e| format!("RSA-OAEP encryption failed: {}", e))?;

    let mut aes_ciphertext = Vec::with_capacity(12 + ciphertext.len());
    aes_ciphertext.extend_from_slice(&nonce_bytes);
    aes_ciphertext.extend_from_slice(&ciphertext);

    Ok((enc_aes_key, aes_ciphertext))
}

/// Pack split encrypted parts into the SMTP wire format:
/// '[ 4 bytes big-endian: len(message_key) ][ message_key ][ aes_ciphertext ]'
pub fn pack_encrypted_email(message_key: &[u8], aes_ciphertext: &[u8]) -> Vec<u8> {
    let key_len = message_key.len() as u32;
    let mut packed = Vec::with_capacity(4 + message_key.len() + aes_ciphertext.len());
    packed.extend_from_slice(&key_len.to_be_bytes());
    packed.extend_from_slice(message_key);
    packed.extend_from_slice(aes_ciphertext);
    packed
}

/// Unpack the SMTP wire format into '(message_key, aes_ciphertext)'.
pub fn unpack_encrypted_email(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if data.len() < 4 {
        return Err("Encrypted blob too short to contain length prefix".into());
    }
    let key_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + key_len {
        return Err(format!(
            "Encrypted blob truncated: expected {} bytes for message_key, only {} available",
            key_len,
            data.len() - 4
        ));
    }
    let message_key = data[4..4 + key_len].to_vec();
    let aes_ciphertext = data[4 + key_len..].to_vec();
    Ok((message_key, aes_ciphertext))
}

/// Encrypt 'data' and return a single packed blob (for SMTP wire use).
/// Format: '[ 4 bytes big-endian: len(E_K) ][ E_K ][ nonce (12 bytes) ][ ciphertext || tag ]'
#[allow(dead_code)]
pub fn encrypt_email_for_public_key(public_key: &PublicKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let (message_key, aes_ciphertext) = encrypt_split(public_key, data)?;
    Ok(pack_encrypted_email(&message_key, &aes_ciphertext))
}