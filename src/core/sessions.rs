//! Session registry, so a token can be listed and revoked.
//!
//! JWTs are stateless: without a record here, "sign out this device" is a
//! promise the server cannot keep. Each login gets a random id that travels in
//! the token, and the auth path refuses an id that is no longer present.
//!
//! Sidecar, not `struct User` — `users.bin` is bincode with positional fields.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub username: String,
    /// SHA-256 of the issued token. The token itself is never stored.
    pub token_hash: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub ip: String,
    pub created_at: u64,
    pub last_seen_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStore {
    #[serde(default)]
    pub entries: HashMap<String, SessionRecord>,
    /// Per-account cutoff: any token issued before this is refused, which is
    /// what makes "sign out everywhere" also kill tokens minted before this
    /// registry existed.
    #[serde(default)]
    pub revoked_before: HashMap<String, u64>,
}

fn store_path() -> &'static str {
    "data/sessions.json"
}

static STORE: OnceLock<Mutex<SessionStore>> = OnceLock::new();

fn store() -> &'static Mutex<SessionStore> {
    STORE.get_or_init(|| {
        let loaded = fs::read_to_string(store_path())
            .ok()
            .and_then(|raw| serde_json::from_str::<SessionStore>(&raw).ok())
            .unwrap_or_default();
        log::info!("[Sessions] Loaded {} records", loaded.entries.len());
        Mutex::new(loaded)
    })
}

fn save(data: &SessionStore) -> std::io::Result<()> {
    let path = Path::new(store_path());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    {
        use std::io::Write;
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn new_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Register a freshly minted token and return its session id.
pub fn create(username: &str, token: &str, user_agent: &str, ip: &str, now: u64) -> String {
    let id = new_id();
    record(&id, username, token, user_agent, ip, now);
    id
}


/// Reduce an address to a network prefix before storing it.
///
/// The full address of a signed-in device is more than the feature needs: the
/// sessions list only has to tell a user *which* device is which, and /24 (or
/// /48) does that while storing far less about where they are.
fn truncate_address(ip: &str) -> String {
    let ip = ip.trim();
    if ip.is_empty() {
        return String::new();
    }
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        // Unparseable (a proxy header, a hostname): store nothing rather than
        // guess at a value we cannot reason about.
        Err(_) => String::new(),
    }
}

/// Register a token under an id the caller already put in the token.
pub fn record(id: &str, username: &str, token: &str, user_agent: &str, ip: &str, now: u64) {
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    guard.entries.insert(
        id.to_string(),
        SessionRecord {
            username: username.to_string(),
            token_hash: hash_token(token),
            user_agent: user_agent.chars().take(200).collect(),
            ip: truncate_address(ip),
            created_at: now,
            last_seen_at: now,
        },
    );
    if let Err(e) = save(&guard) {
        log::warn!("[Sessions] Could not persist new session for '{}': {}", username, e);
    }
}

/// Is this token still allowed to act?
///
/// Returns false when the session was revoked, when the token's session id is
/// unknown, or when the token predates a "sign out everywhere".
pub fn validate(username: &str, sid: Option<&str>, issued_at: u64, token: &str, now: u64) -> bool {
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(_) => return true, // never lock everyone out because of a poisoned lock
    };

    if let Some(cutoff) = guard.revoked_before.get(username) {
        if issued_at < *cutoff {
            return false;
        }
    }

    let Some(sid) = sid else {
        // Token minted before the registry existed. Accepted while it has not
        // been cut off above, so the upgrade does not sign the whole server out.
        return true;
    };

    let Some(record) = guard.entries.get_mut(sid) else {
        return false;
    };
    if record.username != username {
        return false;
    }
    if record.token_hash != hash_token(token) {
        // Same id, different token: treat as forged.
        return false;
    }
    // Keep last-seen fresh without writing on every single request.
    if now.saturating_sub(record.last_seen_at) >= 60 {
        record.last_seen_at = now;
        let _ = save(&guard);
    }
    true
}

pub fn list(username: &str) -> Vec<(String, SessionRecord)> {
    let guard = match store().lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    let mut rows: Vec<(String, SessionRecord)> = guard
        .entries
        .iter()
        .filter(|(_, r)| r.username == username)
        .map(|(id, r)| (id.clone(), r.clone()))
        .collect();
    rows.sort_by(|a, b| b.1.last_seen_at.cmp(&a.1.last_seen_at));
    rows
}

/// Revoke one session. Refuses to remove a record belonging to another account.
pub fn revoke(username: &str, sid: &str) -> bool {
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    match guard.entries.get(sid) {
        Some(record) if record.username == username => {}
        _ => return false,
    }
    guard.entries.remove(sid);
    if let Err(e) = save(&guard) {
        log::warn!("[Sessions] Could not persist revocation: {}", e);
    }
    true
}

/// Drop every session for an account and refuse anything issued before now.
pub fn revoke_all(username: &str, now: u64) -> usize {
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    let ids: Vec<String> = guard
        .entries
        .iter()
        .filter(|(_, r)| r.username == username)
        .map(|(id, _)| id.clone())
        .collect();
    for id in &ids {
        guard.entries.remove(id);
    }
    guard.revoked_before.insert(username.to_string(), now);
    if let Err(e) = save(&guard) {
        log::warn!("[Sessions] Could not persist revoke-all: {}", e);
    }
    ids.len()
}

/// Used when an account is deleted: no dangling records, no cutoff left behind.
pub fn clear_user(username: &str) {
    let mut guard = match store().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    guard.entries.retain(|_, r| r.username != username);
    guard.revoked_before.remove(username);
    if let Err(e) = save(&guard) {
        log::warn!("[Sessions] Could not clear sessions for '{}': {}", username, e);
    }
}
