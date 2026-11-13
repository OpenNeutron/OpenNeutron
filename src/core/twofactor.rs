//! Two-factor authentication state (TOTP, RFC 6238).
//!
//! Kept in a JSON sidecar rather than on `struct User`: `users.bin` is bincode
//! with positional fields, so adding a field there silently invalidates every
//! existing account.
//!
//! The server stores the shared secret because it must be able to verify the
//! code — but nothing here can decrypt mail. Losing this file locks nobody out
//! of their archive; it only disables the second factor.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

type HmacSha1 = Hmac<Sha1>;

const STEP_SECONDS: u64 = 30;
/// Accepted drift, in steps, either side of now. One step = 30 s, so this
/// tolerates a clock that is a little fast or slow without widening the window
/// enough to make guessing practical.
const DRIFT_STEPS: u64 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TwoFactorEntry {
    /// Base32 secret. Present while enrolment is pending, and after it is active.
    pub secret: String,
    /// Unix time the first valid code was seen; 0 while still pending.
    pub enabled_at: u64,
    /// SHA-256 of each unused recovery code.
    #[serde(default)]
    pub recovery_hashes: Vec<String>,
    /// Highest step already accepted, so a code cannot be replayed.
    #[serde(default)]
    pub last_step: u64,
}

impl TwoFactorEntry {
    pub fn is_active(&self) -> bool {
        self.enabled_at > 0 && !self.secret.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TwoFactorStore {
    #[serde(default)]
    pub entries: HashMap<String, TwoFactorEntry>,
}

fn store_path() -> &'static str {
    "data/twofactor.json"
}

static STORE: OnceLock<Mutex<TwoFactorStore>> = OnceLock::new();

fn store() -> &'static Mutex<TwoFactorStore> {
    STORE.get_or_init(|| {
        let loaded = fs::read_to_string(store_path())
            .ok()
            .and_then(|raw| serde_json::from_str::<TwoFactorStore>(&raw).ok())
            .unwrap_or_default();
        log::info!("[2FA] Loaded {} entries", loaded.entries.len());
        Mutex::new(loaded)
    })
}

fn save(store: &TwoFactorStore) -> std::io::Result<()> {
    let path = Path::new(store_path());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(store)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    {
        use std::io::Write;
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/* ---------------------------------------------------------------- base32 --- */

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(B32[idx] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(B32[idx] as char);
    }
    out
}

pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for ch in input.chars() {
        if ch == '=' || ch.is_whitespace() || ch == '-' {
            continue;
        }
        let upper = ch.to_ascii_uppercase();
        let value = B32.iter().position(|&c| c as char == upper)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/* ------------------------------------------------------------------- totp --- */

/// HMAC-SHA1 one-time password for an explicit counter (RFC 4226).
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation: the low nibble of the last byte picks the offset.
    let offset = (digest[19] & 0x0f) as usize;
    let truncated = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    truncated % 1_000_000
}

pub fn step_for(unix: u64) -> u64 {
    unix / STEP_SECONDS
}

pub fn totp_at(secret: &[u8], unix: u64) -> u32 {
    hotp(secret, step_for(unix))
}

/// Split a 6-digit code into a zero-padded string.
pub fn format_code(code: u32) -> String {
    format!("{:06}", code)
}

/// Check a submitted code against the accepted window, refusing replays.
///
/// Returns the matched step so the caller can record it.
pub fn verify_code(secret: &[u8], submitted: &str, now: u64, last_step: u64) -> Option<u64> {
    let cleaned: String = submitted.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.len() != 6 {
        return None;
    }
    let current = step_for(now);
    for delta in 0..=DRIFT_STEPS {
        for candidate in [current.checked_sub(delta), current.checked_add(delta)] {
            let Some(step) = candidate else { continue };
            // A step that was already accepted stays accepted for the rest of
            // its 30-second window, so enrolling and immediately signing in
            // does not make the user wait for the next code. Anything older
            // than the last accepted step is refused, which is what stops a
            // captured code from being replayed later.
            if step < last_step {
                continue;
            }
            if format_code(hotp(secret, step)) == cleaned {
                return Some(step);
            }
        }
    }
    None
}

/* --------------------------------------------------------------- helpers --- */

pub fn new_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; 20]; // 160 bits, per RFC 4226 recommendation
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

pub fn hash_recovery_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            let mut bytes = [0u8; 5];
            rng.fill_bytes(&mut bytes);
            let hexed = hex::encode(bytes).to_uppercase();
            format!("{}-{}", &hexed[0..5], &hexed[5..10])
        })
        .collect()
}

pub fn otpauth_url(username: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/Sloth%20Lee%20Mail:{}?secret={}&issuer=Sloth%20Lee%20Mail&algorithm=SHA1&digits=6&period=30",
        urlencoding(username),
        secret_b32
    )
}

fn urlencoding(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            '@' => "%40".to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

/* ------------------------------------------------------------------- API --- */

pub fn get(username: &str) -> Option<TwoFactorEntry> {
    store().lock().ok()?.entries.get(username).cloned()
}

pub fn is_enabled(username: &str) -> bool {
    get(username).map(|e| e.is_active()).unwrap_or(false)
}

/// Begin enrolment: store a pending secret, replacing any unconfirmed one.
/// An already-active entry is left untouched so a stolen session cannot
/// silently swap the second factor.
pub fn start_enrollment(username: &str, secret_b32: &str) -> Result<bool, String> {
    let mut guard = store().lock().map_err(|_| "store poisoned".to_string())?;
    if guard.entries.get(username).map(|e| e.is_active()).unwrap_or(false) {
        return Ok(false);
    }
    guard.entries.insert(
        username.to_string(),
        TwoFactorEntry {
            secret: secret_b32.to_string(),
            enabled_at: 0,
            recovery_hashes: Vec::new(),
            last_step: 0,
        },
    );
    save(&guard).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Confirm enrolment with a code; enables 2FA and installs the recovery codes.
pub fn confirm_enrollment(username: &str, code: &str, codes: Vec<String>, now: u64) -> Result<(), String> {
    let mut guard = store().lock().map_err(|_| "store poisoned".to_string())?;
    let entry = guard
        .entries
        .get_mut(username)
        .ok_or_else(|| "no pending enrolment".to_string())?;
    if entry.is_active() {
        return Err("already enabled".to_string());
    }
    let secret = base32_decode(&entry.secret).ok_or_else(|| "bad secret".to_string())?;
    let step = verify_code(&secret, code, now, entry.last_step)
        .ok_or_else(|| "invalid_code".to_string())?;
    entry.enabled_at = now;
    entry.last_step = step;
    entry.recovery_hashes = codes.iter().map(|c| hash_recovery_code(c)).collect();
    save(&guard).map_err(|e| e.to_string())
}

/// Verify a login code, advancing the replay guard on success.
pub fn verify_login_code(username: &str, code: &str, now: u64) -> bool {
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let Some(entry) = guard.entries.get_mut(username) else {
        return false;
    };
    if !entry.is_active() {
        return false;
    }
    let Some(secret) = base32_decode(&entry.secret) else {
        return false;
    };
    match verify_code(&secret, code, now, entry.last_step) {
        Some(step) => {
            entry.last_step = step;
            let _ = save(&guard);
            true
        }
        None => false,
    }
}

/// Spend a recovery code. One use only, because each is removed on success.
pub fn consume_recovery_code(username: &str, code: &str) -> bool {
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let Some(entry) = guard.entries.get_mut(username) else {
        return false;
    };
    let hashed = hash_recovery_code(code);
    if let Some(pos) = entry.recovery_hashes.iter().position(|h| h == &hashed) {
        entry.recovery_hashes.remove(pos);
        let _ = save(&guard);
        return true;
    }
    false
}

pub fn recovery_codes_remaining(username: &str) -> usize {
    get(username).map(|e| e.recovery_hashes.len()).unwrap_or(0)
}

/// Disable 2FA. The caller must have proven possession first.
pub fn disable(username: &str) -> Result<(), String> {
    let mut guard = store().lock().map_err(|_| "store poisoned".to_string())?;
    guard.entries.remove(username);
    save(&guard).map_err(|e| e.to_string())
}
