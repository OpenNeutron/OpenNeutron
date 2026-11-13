//! Security keys (WebAuthn / FIDO2) as a second factor.
//!
//! A YubiKey signs a challenge with a private key that never leaves the device. The
//! server stores only the public key and a signature counter, so a stolen
//! `webauthn.json` cannot be used to sign in — unlike `twofactor.json`, which holds
//! shared secrets.
//!
//! Kept in a JSON sidecar for the same reason as 2FA: `users.bin` is bincode with
//! positional fields, so a new field there invalidates every existing account.
//!
//! What this is *not*: passwordless login. The mailbox private key is derived from
//! the password in the browser, so the password must still be typed to decrypt
//! anything. The key replaces the TOTP code, not the password.

use ciborium::value::Value as Cbor;
use p256::ecdsa::{
    signature::Verifier, Signature as EcdsaSignature, VerifyingKey as EcdsaKey,
};
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

const STORE: &str = "data/webauthn.json";
/// One account should not need more than a key per device it owns. A cap keeps a
/// compromised session from filling the file with keys it controls.
pub const MAX_KEYS_PER_USER: usize = 10;
/// Flag bit 0 of the authenticator data: attested credential data is present.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKey {
    /// Credential id, base64url (no padding) — the handle the browser sends back.
    pub id: String,
    /// COSE public key, base64 (standard) — enough to verify, useless for signing.
    pub public_key: String,
    /// COSE algorithm. -7 is ES256, the only one a YubiKey 5 offers for WebAuthn here.
    pub alg: i64,
    /// The authenticator's signature counter. Strictly increasing per assertion when
    /// the device supports it; a regression means a cloned key.
    #[serde(default)]
    pub sign_count: u32,
    pub name: String,
    pub created_at: u64,
    #[serde(default)]
    pub last_used_at: u64,
}

static KEYS: OnceLock<Mutex<HashMap<String, Vec<SecurityKey>>>> = OnceLock::new();

fn store() -> &'static Mutex<HashMap<String, Vec<SecurityKey>>> {
    KEYS.get_or_init(|| {
        let mut map: HashMap<String, Vec<SecurityKey>> = HashMap::new();
        if Path::new(STORE).exists() {
            match fs::read_to_string(STORE) {
                Ok(raw) => match serde_json::from_str(&raw) {
                    Ok(parsed) => map = parsed,
                    Err(e) => log::error!("[WebAuthn] {} is not valid JSON: {}", STORE, e),
                },
                Err(e) => log::error!("[WebAuthn] cannot read {}: {}", STORE, e),
            }
        }
        Mutex::new(map)
    })
}

fn persist(map: &HashMap<String, Vec<SecurityKey>>) -> Result<(), String> {
    let body = serde_json::to_string_pretty(map).map_err(|e| e.to_string())?;
    let tmp = format!("{}.tmp", STORE);
    fs::write(&tmp, body).map_err(|e| e.to_string())?;
    fs::rename(&tmp, STORE).map_err(|e| e.to_string())
}

pub fn list(username: &str) -> Vec<SecurityKey> {
    store()
        .lock()
        .map(|m| m.get(username).cloned().unwrap_or_default())
        .unwrap_or_default()
}

pub fn count(username: &str) -> usize {
    list(username).len()
}

pub fn has_any(username: &str) -> bool {
    count(username) > 0
}

pub fn get(username: &str, id: &str) -> Option<SecurityKey> {
    list(username).into_iter().find(|k| k.id == id)
}

pub fn add(username: &str, key: SecurityKey) -> Result<(), String> {
    let mut map = store().lock().map_err(|_| "lock poisoned".to_string())?;
    let entry = map.entry(username.to_string()).or_default();
    if entry.len() >= MAX_KEYS_PER_USER {
        return Err(format!("at most {} security keys per account", MAX_KEYS_PER_USER));
    }
    if entry.iter().any(|k| k.id == key.id) {
        return Err("that security key is already registered".into());
    }
    entry.push(key);
    persist(&map)
}

pub fn remove(username: &str, id: &str) -> Result<(), String> {
    let mut map = store().lock().map_err(|_| "lock poisoned".to_string())?;
    let Some(entry) = map.get_mut(username) else {
        return Err("no security keys registered".into());
    };
    let before = entry.len();
    entry.retain(|k| k.id != id);
    if entry.len() == before {
        return Err("no such security key".into());
    }
    if entry.is_empty() {
        map.remove(username);
    }
    persist(&map)
}

/// Record that a key was used: store the new counter and the time.
///
/// Called only after an assertion verifies, so a failed attempt cannot advance the
/// counter and lock the real key out.
pub fn record_use(username: &str, id: &str, counter: u32, now: u64) -> Result<(), String> {
    let mut map = store().lock().map_err(|_| "lock poisoned".to_string())?;
    if let Some(entry) = map.get_mut(username) {
        if let Some(k) = entry.iter_mut().find(|k| k.id == id) {
            k.sign_count = counter;
            k.last_used_at = now;
            return persist(&map);
        }
    }
    Err("no such security key".into())
}

/// Everything an assertion proves, once verified.
#[derive(Debug)]
pub struct Asserted {
    pub credential_id: String,
    pub sign_count: u32,
    pub user_verified: bool,
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    // The browser sends base64url without padding; accept either alphabet so a
    // client that pads does not fail for cosmetic reasons.
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &c in bytes {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => continue,
            _ => return Err("invalid base64url".into()),
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn b64_std_decode(s: &str) -> Result<Vec<u8>, String> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = T.iter().position(|&t| t == c).ok_or("invalid base64")? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Parse the COSE key a security key hands over at registration (RFC 8152).
/// Only ES256 is accepted: it is what the hardware in scope speaks, and refusing
/// anything else is safer than trying to verify a curve we have not exercised.
pub fn cose_to_verifying_key(cose_bytes: &[u8]) -> Result<EcdsaKey, String> {
    let value: Cbor = ciborium::de::from_reader(cose_bytes).map_err(|e| format!("cose: {}", e))?;
    let Cbor::Map(map) = value else {
        return Err("cose key is not a map".into());
    };
    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;
    for (k, v) in map {
        let key = match k {
            Cbor::Integer(i) => i128::from(i),
            _ => continue,
        };
        match key {
            1 => kty = v.as_integer().map(i128::from),
            3 => alg = v.as_integer().map(i128::from),
            -1 => crv = v.as_integer().map(i128::from),
            -2 => x = v.as_bytes().cloned(),
            -3 => y = v.as_bytes().cloned(),
            _ => {}
        }
    }
    if kty != Some(2) {
        return Err("cose kty is not EC2".into());
    }
    if alg != Some(-7) {
        return Err("unsupported algorithm: only ES256 (-7) is accepted".into());
    }
    if crv != Some(1) {
        return Err("unsupported curve: only P-256 is accepted".into());
    }
    let (x, y) = (x.ok_or("cose key missing x")?, y.ok_or("cose key missing y")?);
    if x.len() != 32 || y.len() != 32 {
        return Err("cose coordinates must be 32 bytes".into());
    }
    let point = EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
    EcdsaKey::from_encoded_point(&point).map_err(|_| "cose key is not a valid P-256 point".into())
}

/// Split authenticator data into the parts every check needs.
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    credential_id: Option<&'a [u8]>,
    cose_key: Option<&'a [u8]>,
}

fn parse_auth_data(data: &[u8]) -> Result<AuthData<'_>, String> {
    if data.len() < 37 {
        return Err("authenticator data is too short".into());
    }
    let rp_id_hash = &data[0..32];
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    if flags & FLAG_AT == 0 {
        return Ok(AuthData { rp_id_hash, flags, sign_count, credential_id: None, cose_key: None });
    }
    let mut cursor = 37 + 16; // aaguid
    if data.len() < cursor + 2 {
        return Err("attested credential data truncated".into());
    }
    let id_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
    cursor += 2;
    if data.len() < cursor + id_len {
        return Err("credential id truncated".into());
    }
    let credential_id = &data[cursor..cursor + id_len];
    cursor += id_len;
    let cose_key = &data[cursor..];
    Ok(AuthData { rp_id_hash, flags, sign_count, credential_id: Some(credential_id), cose_key: Some(cose_key) })
}

/// What a registration produced, before the server decides to store it.
pub struct Registered {
    pub credential_id: String,
    /// COSE public key, base64 — stored as text so the sidecar stays readable.
    pub public_key: String,
    pub alg: i64,
}

/// Verify `navigator.credentials.create()` output.
///
/// Attestation is deliberately `none`: we are not identifying the hardware, only
/// binding a public key to this account. Verifying a vendor attestation chain would
/// add a trust store for no security gain here.
pub fn verify_registration(
    client_data_json: &[u8],
    attestation_object: &[u8],
    expected_challenge: &str,
    expected_origin: &str,
    rp_id: &str,
) -> Result<Registered, String> {
    check_client_data(client_data_json, "webauthn.create", expected_challenge, expected_origin)?;

    let value: Cbor =
        ciborium::de::from_reader(attestation_object).map_err(|e| format!("attestation: {}", e))?;
    let Cbor::Map(map) = value else {
        return Err("attestation object is not a map".into());
    };
    let mut auth_data = None;
    for (k, v) in map {
        if let Cbor::Text(name) = k {
            if name == "authData" {
                auth_data = v.as_bytes().cloned();
            }
        }
    }
    let auth_data = auth_data.ok_or("attestation object has no authData")?;
    let parsed = parse_auth_data(&auth_data)?;

    if parsed.rp_id_hash != Sha256::digest(rp_id.as_bytes()).as_slice() {
        return Err("credential was created for a different site".into());
    }
    if parsed.flags & FLAG_UP == 0 {
        return Err("the key did not report a user presence check".into());
    }
    let id = parsed.credential_id.ok_or("attestation has no credential id")?;
    let cose = parsed.cose_key.ok_or("attestation has no public key")?;

    // Refuse a key we cannot verify, at enrolment rather than at first login.
    cose_to_verifying_key(cose)?;

    Ok(Registered {
        credential_id: b64url_encode(id),
        public_key: b64_std_encode(cose),
        alg: -7,
    })
}

/// Verify `navigator.credentials.get()` output against a stored key.
///
/// `expected_challenge` must be the value this server issued for this sign-in and
/// must not have been used before — a replayed assertion is a valid signature over
/// an old challenge, which is why the challenge store, not the signature, is the
/// thing that makes login single-use.
pub fn verify_assertion(
    key: &SecurityKey,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    expected_challenge: &str,
    expected_origin: &str,
    rp_id: &str,
    username: &str,
    now: u64,
) -> Result<Asserted, String> {
    check_client_data(client_data_json, "webauthn.get", expected_challenge, expected_origin)?;

    let parsed = parse_auth_data(authenticator_data)?;
    if parsed.rp_id_hash != Sha256::digest(rp_id.as_bytes()).as_slice() {
        return Err("assertion is for a different site".into());
    }
    if parsed.flags & FLAG_UP == 0 {
        return Err("the key did not report a user presence check".into());
    }

    let cose_bytes = b64_decode_any(&key.public_key)?;
    let verifying_key = cose_to_verifying_key(&cose_bytes)?;
    let client_hash = Sha256::digest(client_data_json);
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&client_hash);

    let sig = EcdsaSignature::from_der(signature).map_err(|_| "malformed signature".to_string())?;
    verifying_key
        .verify(&signed, &sig)
        .map_err(|_| "signature does not verify for this key".to_string())?;

    // A counter that went backwards is the documented signal of a cloned
    // authenticator. Devices that do not implement it always send 0.
    if parsed.sign_count != 0 && parsed.sign_count <= key.sign_count {
        return Err("signature counter did not advance — this key may be cloned".into());
    }

    // Verification stays pure: the caller records the use once it has decided the
    // sign-in succeeds, so a verification helper cannot mutate state as a side effect.
    let _ = (username, now);

    Ok(Asserted {
        credential_id: key.id.clone(),
        sign_count: parsed.sign_count,
        user_verified: parsed.flags & FLAG_UV != 0,
    })
}

fn check_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<(), String> {
    let v: serde_json::Value =
        serde_json::from_slice(client_data_json).map_err(|_| "clientDataJSON is not JSON".to_string())?;
    if v.get("type").and_then(|t| t.as_str()) != Some(expected_type) {
        return Err(format!("client data type is not {}", expected_type));
    }
    if v.get("challenge").and_then(|c| c.as_str()) != Some(expected_challenge) {
        return Err("challenge does not match the one issued".into());
    }
    if v.get("origin").and_then(|o| o.as_str()) != Some(expected_origin) {
        return Err("origin does not match this site".into());
    }
    Ok(())
}

pub fn b64_std_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn b64url_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

pub fn b64_decode_any(s: &str) -> Result<Vec<u8>, String> {
    if s.contains('-') || s.contains('_') {
        b64url_decode(s)
    } else {
        b64_std_decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value as Cbor;
    use p256::ecdsa::{signature::Signer, SigningKey};

    const RP_ID: &str = "mail.slothlee.xyz";
    const ORIGIN: &str = "https://mail.slothlee.xyz";

    /// A fixed P-256 key standing in for the YubiKey's own.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32].into()).expect("fixed key")
    }

    fn cose_key_bytes(key: &SigningKey, alg: i64) -> Vec<u8> {
        let point = key.verifying_key().to_encoded_point(false);
        let cose = Cbor::Map(vec![
            (Cbor::Integer(1.into()), Cbor::Integer(2.into())),        // kty: EC2
            (Cbor::Integer(3.into()), Cbor::Integer(alg.into())),      // alg
            (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),     // crv: P-256
            (Cbor::Integer((-2).into()), Cbor::Bytes(point.x().unwrap().to_vec())),
            (Cbor::Integer((-3).into()), Cbor::Bytes(point.y().unwrap().to_vec())),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&cose, &mut out).unwrap();
        out
    }

    fn auth_data(key: &SigningKey, counter: u32, with_attested: bool, cred_id: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(Sha256::digest(RP_ID.as_bytes()).as_slice());
        let flags = FLAG_UP | if with_attested { FLAG_AT } else { 0 } | FLAG_UV;
        d.push(flags);
        d.extend_from_slice(&counter.to_be_bytes());
        if with_attested {
            d.extend_from_slice(&[0u8; 16]); // aaguid
            d.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
            d.extend_from_slice(cred_id);
            d.extend_from_slice(&cose_key_bytes(key, -7));
        }
        d
    }

    fn client_data(kind: &str, challenge: &str) -> Vec<u8> {
        format!(r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#, kind, challenge, ORIGIN)
            .into_bytes()
    }

    fn attestation(auth: &[u8]) -> Vec<u8> {
        let obj = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth.to_vec())),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&obj, &mut out).unwrap();
        out
    }

    fn assert_args(key: &SecurityKey, cd: &[u8], auth: &[u8], sig: Vec<u8>, challenge: &str) -> Result<Asserted, String> {
        verify_assertion(key, cd, auth, &sig, challenge, ORIGIN, RP_ID, "webtest", 1_700_000_000)
    }

    #[test]
    fn a_registration_yields_the_credential_the_key_chose() {
        let sk = signing_key();
        let cred_id = b"yubikey-serial-0001";
        let auth = auth_data(&sk, 0, true, cred_id);
        let cd = client_data("webauthn.create", "chal-reg");

        let out = verify_registration(&cd, &attestation(&auth), "chal-reg", ORIGIN, RP_ID)
            .expect("registration should verify");
        assert_eq!(out.credential_id, b64url_encode(b"yubikey-serial-0001"));
        assert_eq!(out.alg, -7);
        // And the stored form must be usable again at login time.
        assert!(cose_to_verifying_key(&b64_decode_any(&out.public_key).unwrap()).is_ok());
    }

    #[test]
    fn registration_is_refused_for_another_site() {
        let sk = signing_key();
        let auth = auth_data(&sk, 0, true, b"id");
        let cd = client_data("webauthn.create", "chal");
        assert!(verify_registration(&cd, &attestation(&auth), "chal", ORIGIN, "example.com").is_err());
    }

    #[test]
    fn a_correct_assertion_verifies() {
        let sk = signing_key();
        let cose = cose_key_bytes(&sk, -7);
        let key = SecurityKey {
            id: "kid".into(), public_key: b64_std_encode(&cose), alg: -7, sign_count: 4,
            name: "YubiKey".into(), created_at: 0, last_used_at: 0,
        };
        let auth = auth_data(&sk, 5, false, b"");
        let cd = client_data("webauthn.get", "chal-1");
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&cd));
        let sig: EcdsaSignature = sk.sign(&signed);

        let out = assert_args(&key, &cd, &auth, sig.to_der().as_bytes().to_vec(), "chal-1")
            .expect("assertion should verify");
        assert_eq!(out.sign_count, 5);
        assert!(out.user_verified, "UV flag was set");
    }

    #[test]
    fn a_replayed_or_foreign_challenge_is_refused() {
        let sk = signing_key();
        let key = SecurityKey {
            id: "kid".into(), public_key: b64_std_encode(&cose_key_bytes(&sk, -7)), alg: -7, sign_count: 0,
            name: "YubiKey".into(), created_at: 0, last_used_at: 0,
        };
        let auth = auth_data(&sk, 1, false, b"");
        let cd = client_data("webauthn.get", "chal-issued");
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&cd));
        let sig: EcdsaSignature = sk.sign(&signed);

        // Same signature, different challenge than the one we issued.
        let err = assert_args(&key, &cd, &auth, sig.to_der().as_bytes().to_vec(), "chal-other").unwrap_err();
        assert!(err.contains("challenge"), "got: {err}");
    }

    #[test]
    fn an_assertion_signed_by_a_different_key_is_refused() {
        let sk = signing_key();
        let other = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let key = SecurityKey {
            id: "kid".into(), public_key: b64_std_encode(&cose_key_bytes(&sk, -7)), alg: -7, sign_count: 0,
            name: "YubiKey".into(), created_at: 0, last_used_at: 0,
        };
        let auth = auth_data(&sk, 1, false, b"");
        let cd = client_data("webauthn.get", "chal");
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&cd));
        let sig: EcdsaSignature = other.sign(&signed);

        let err = assert_args(&key, &cd, &auth, sig.to_der().as_bytes().to_vec(), "chal").unwrap_err();
        assert!(err.contains("signature"), "got: {err}");
    }

    #[test]
    fn a_counter_that_does_not_advance_is_treated_as_a_clone() {
        let sk = signing_key();
        let key = SecurityKey {
            id: "kid".into(), public_key: b64_std_encode(&cose_key_bytes(&sk, -7)), alg: -7, sign_count: 5,
            name: "YubiKey".into(), created_at: 0, last_used_at: 0,
        };
        let auth = auth_data(&sk, 5, false, b"");
        let cd = client_data("webauthn.get", "chal");
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&cd));
        let sig: EcdsaSignature = sk.sign(&signed);

        let err = assert_args(&key, &cd, &auth, sig.to_der().as_bytes().to_vec(), "chal").unwrap_err();
        assert!(err.contains("cloned"), "got: {err}");
    }

    #[test]
    fn only_es256_keys_are_accepted() {
        let sk = signing_key();
        let err = cose_to_verifying_key(&cose_key_bytes(&sk, -257)).unwrap_err();
        assert!(err.contains("ES256"), "got: {err}");
    }
}
