//! Recovery addresses and outstanding password-reset tokens.
//!
//! This lives in its own JSON file rather than on `User` on purpose: the account
//! store is serialised with bincode, which is positional. Adding fields to
//! `User` makes every existing `users.bin` misparse - the map then loads with
//! garbage keys, and the next save writes that garbage back. Recovery state has
//! nothing to do with account identity, so it belongs in a sidecar that can
//! evolve without touching that layout.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct RecoveryEntry {
    /// Address the reset link may be sent to. Never the mailbox itself.
    #[serde(default)]
    pub email: Option<String>,
    /// SHA-256 (hex) of the outstanding token; the token itself is never stored.
    #[serde(default)]
    pub token_hash: Option<String>,
    /// Unix seconds after which `token_hash` is worthless.
    #[serde(default)]
    pub expires_at: u64,
    /// The mailbox private key, wrapped a second time under a key derived from
    /// the user's recovery secret. Opaque here: the server can store it but
    /// never open it.
    #[serde(default)]
    pub wrapped_key: Option<String>,
    /// Salt the client used when deriving that wrapping key.
    #[serde(default)]
    pub kdf_salt: Option<String>,
    /// SHA-256 of the client's auth proof. The proof is itself a one-way hash of
    /// the recovery secret, so this verifier proves possession of the secret
    /// without the server ever seeing it - and cannot be turned back into the
    /// key that unwraps `wrapped_key`.
    #[serde(default)]
    pub auth_proof_hash: Option<String>,
    #[serde(default)]
    pub key_set_at: u64,
    #[serde(default)]
    pub key_used_at: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct RecoveryFile {
    #[serde(default)]
    entries: HashMap<String, RecoveryEntry>,
}

pub struct RecoveryStore {
    path: String,
    entries: Mutex<HashMap<String, RecoveryEntry>>,
}

impl RecoveryStore {
    pub fn load(path: &str) -> Self {
        let entries = match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str::<RecoveryFile>(&text)
                .map(|f| f.entries)
                .unwrap_or_else(|e| {
                    log::warn!("[Recovery] {} is unreadable ({}); starting empty", path, e);
                    HashMap::new()
                }),
            Err(_) => HashMap::new(),
        };
        RecoveryStore {
            path: path.to_string(),
            entries: Mutex::new(entries),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, RecoveryEntry>> {
        match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn get(&self, username: &str) -> RecoveryEntry {
        self.lock().get(username).cloned().unwrap_or_default()
    }

    /// Atomic write: temp file, fsync, rename. A half-written recovery file must
    /// never be able to look like "no recovery address on file".
    fn save(&self, entries: &HashMap<String, RecoveryEntry>) -> io::Result<()> {
        if let Some(parent) = Path::new(&self.path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let body = serde_json::to_vec_pretty(&RecoveryFile {
            entries: entries.clone(),
        })
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let tmp = format!("{}.tmp", self.path);
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }

    pub fn set_email(&self, username: &str, email: Option<String>) -> io::Result<()> {
        let mut entries = self.lock();
        let entry = entries.entry(username.to_string()).or_default();
        entry.email = email;
        self.save(&entries)
    }

    pub fn set_token(&self, username: &str, token_hash: String, expires_at: u64) -> io::Result<()> {
        let mut entries = self.lock();
        let entry = entries.entry(username.to_string()).or_default();
        entry.token_hash = Some(token_hash);
        entry.expires_at = expires_at;
        self.save(&entries)
    }

    /// Username owning a live token hash, if any.
    pub fn find_by_token_hash(&self, hash: &str, now: u64) -> Option<String> {
        let entries = self.lock();
        entries
            .iter()
            .find(|(_, e)| {
                e.token_hash.as_deref() == Some(hash) && e.expires_at > now
            })
            .map(|(name, _)| name.clone())
    }

    /// Store a freshly created recovery key wrapping.
    pub fn set_key(
        &self,
        username: &str,
        wrapped_key: String,
        kdf_salt: String,
        auth_proof_hash: String,
        now: u64,
    ) -> io::Result<()> {
        let mut entries = self.lock();
        let entry = entries.entry(username.to_string()).or_default();
        entry.wrapped_key = Some(wrapped_key);
        entry.kdf_salt = Some(kdf_salt);
        entry.auth_proof_hash = Some(auth_proof_hash);
        entry.key_set_at = now;
        entry.key_used_at = 0;
        self.save(&entries)
    }

    /// The wrapped key + salt, for anyone who can prove they hold the secret.
    /// This is ciphertext: handing it out is useless without the recovery key.
    pub fn wrapped_key(&self, username: &str) -> Option<(String, String, u64)> {
        let entries = self.lock();
        let e = entries.get(username)?;
        match (&e.wrapped_key, &e.kdf_salt) {
            (Some(w), Some(s)) => Some((w.clone(), s.clone(), e.key_set_at)),
            _ => None,
        }
    }

    /// True when the supplied auth proof is the one on file.
    pub fn proof_matches(&self, username: &str, proof_hash: &str) -> bool {
        let entries = self.lock();
        match entries.get(username).and_then(|e| e.auth_proof_hash.as_deref()) {
            Some(stored) => {
                // Length-independent compare; both are hex digests of fixed size.
                stored.len() == proof_hash.len()
                    && stored
                        .bytes()
                        .zip(proof_hash.bytes())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                        == 0
            }
            None => false,
        }
    }

    /// Burn the recovery key after it has been used, and record when.
    pub fn mark_key_used(&self, username: &str, now: u64) -> io::Result<()> {
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(username) {
            entry.wrapped_key = None;
            entry.kdf_salt = None;
            entry.auth_proof_hash = None;
            entry.key_used_at = now;
        }
        self.save(&entries)
    }

    pub fn has_key(&self, username: &str) -> Option<(u64, u64)> {
        let entries = self.lock();
        entries
            .get(username)
            .filter(|e| e.wrapped_key.is_some())
            .map(|e| (e.key_set_at, e.key_used_at))
    }

    /// Forget everything about a deleted account.
    pub fn remove(&self, username: &str) -> io::Result<()> {
        let mut entries = self.lock();
        if entries.remove(username).is_some() {
            return self.save(&entries);
        }
        Ok(())
    }

    /// Drop the outstanding token after it is redeemed or superseded.
    pub fn clear_token(&self, username: &str) -> io::Result<()> {
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(username) {
            entry.token_hash = None;
            entry.expires_at = 0;
        }
        self.save(&entries)
    }
}

static STORE: std::sync::OnceLock<RecoveryStore> = std::sync::OnceLock::new();

/// Initialise once at startup.
pub fn init(path: &str) {
    let _ = STORE.set(RecoveryStore::load(path));
}

/// Process-wide store. Falls back to the default path if init was skipped.
pub fn store() -> &'static RecoveryStore {
    STORE.get_or_init(|| RecoveryStore::load("data/recovery.json"))
}
