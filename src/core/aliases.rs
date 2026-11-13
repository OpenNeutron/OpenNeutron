//! Disposable addresses that deliver to a real account.
//!
//! An alias is a local part (`shop-8f2k@slothlee.xyz`) that resolves to an
//! account on delivery. It exists so a person can hand out an address, watch
//! what arrives, and kill it when it starts getting sold — without touching
//! their real address or the mailbox behind it.
//!
//! Stored in `data/aliases.json`, never on the `User` struct: that file is
//! bincode and positional, so a new field there makes every existing record
//! unreadable.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static LOCK: Mutex<()> = Mutex::new(());

/// How many aliases one account may hold, disabled ones included.
pub const MAX_PER_ACCOUNT: usize = 10;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Alias {
    /// The account this address delivers to.
    pub username: String,
    #[serde(default)]
    pub label: String,
    pub created_at: u64,
    /// Set when the address stops working. Kept rather than deleted so the
    /// person can see what they killed and when.
    #[serde(default)]
    pub disabled_at: Option<u64>,
    /// Messages delivered through this address.
    #[serde(default)]
    pub received: u64,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Store {
    #[serde(default)]
    pub aliases: BTreeMap<String, Alias>,
}

fn data_dir() -> PathBuf {
    PathBuf::from("data")
}

fn path() -> PathBuf {
    data_dir().join("aliases.json")
}

fn read_at(path: &PathBuf) -> Store {
    match fs::read(path) {
        Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => Store::default(),
    }
}

/// Write to a temporary file and rename, so a crash mid-write cannot leave a
/// half-written store that loses every alias at once.
fn write_at(path: &PathBuf, store: &Store) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_vec_pretty(store).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

pub fn load() -> Store {
    read_at(&path())
}

/// The account an address delivers to, or None when the alias is unknown or
/// has been switched off.
pub fn resolve(local: &str) -> Option<String> {
    let store = load();
    let key = local.to_ascii_lowercase();
    match store.aliases.get(&key) {
        Some(a) if a.disabled_at.is_none() => Some(a.username.clone()),
        _ => None,
    }
}

/// Count a delivery. Best effort: a failed write must never drop the message
/// that has already been accepted.
pub fn bump(local: &str) {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let key = local.to_ascii_lowercase();
    if let Some(a) = store.aliases.get_mut(&key) {
        a.received = a.received.saturating_add(1);
        if let Err(e) = write_at(&path, &store) {
            log::warn!("[Aliases] Could not record delivery for '{}': {}", key, e);
        }
    }
}

pub fn list(username: &str) -> Vec<(String, Alias)> {
    load()
        .aliases
        .into_iter()
        .filter(|(_, a)| a.username.eq_ignore_ascii_case(username))
        .collect()
}

#[derive(Debug, PartialEq)]
pub enum CreateError {
    TooMany,
    Taken,
    Invalid,
}

/// Reserved local parts: mail sent to these would be mistaken for something
/// the service itself owns.
const RESERVED: &[&str] = &["admin", "postmaster", "abuse", "hostmaster", "root", "mailer-daemon", "noreply", "support"];

pub fn valid_local(local: &str) -> bool {
    let len = local.len();
    if !(3..=32).contains(&len) {
        return false;
    }
    if local.starts_with('-') || local.ends_with('-') {
        return false;
    }
    if !local.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return false;
    }
    !RESERVED.contains(&local)
}

const WORDS_A: &[&str] = &[
    "amber", "brisk", "calm", "dusk", "ember", "faint", "glad", "hush", "ivory", "jade",
    "keen", "lilac", "mild", "north", "opal", "plain", "quiet", "rust", "soft", "tide",
];
const WORDS_B: &[&str] = &[
    "otter", "heron", "maple", "cedar", "finch", "cobalt", "meadow", "pebble", "harbor", "lantern",
    "sparrow", "willow", "summit", "ripple", "thistle", "badger", "canyon", "fern", "gable", "moth",
];

fn pseudo(n: usize) -> usize {
    // Cheap per-call variety; uniqueness is enforced by the caller anyway.
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos() as usize).unwrap_or(0);
    (t ^ (now() as usize).rotate_left(7)) % n
}

/// A readable default: `quiet-otter-418`.
fn suggest() -> String {
    format!("{}-{}-{:03}", WORDS_A[pseudo(WORDS_A.len())], WORDS_B[pseudo(WORDS_B.len())], pseudo(900) + 100)
}

/// Create an alias for `username`. `want` is the local part the person asked
/// for; when it is empty a readable one is generated.
///
/// `taken` answers whether a name is already in use by anything on the
/// service — an account or another alias.
pub fn create<F>(username: &str, want: &str, label: &str, taken: F) -> Result<String, CreateError>
where
    F: Fn(&str) -> bool,
{
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);

    let mine = store.aliases.values().filter(|a| a.username.eq_ignore_ascii_case(username)).count();
    if mine >= MAX_PER_ACCOUNT {
        return Err(CreateError::TooMany);
    }

    let mut candidate = want.trim().to_ascii_lowercase();
    if candidate.is_empty() {
        for _ in 0..25 {
            let s = suggest();
            if !store.aliases.contains_key(&s) && !taken(&s) {
                candidate = s;
                break;
            }
        }
        if candidate.is_empty() {
            return Err(CreateError::Taken);
        }
    } else {
        if !valid_local(&candidate) {
            return Err(CreateError::Invalid);
        }
        if store.aliases.contains_key(&candidate) || taken(&candidate) {
            return Err(CreateError::Taken);
        }
    }

    store.aliases.insert(
        candidate.clone(),
        Alias {
            username: username.to_string(),
            label: label.trim().chars().take(64).collect(),
            created_at: now(),
            disabled_at: None,
            received: 0,
        },
    );
    write_at(&path, &store).map_err(|e| {
        log::error!("[Aliases] Could not save: {}", e);
        CreateError::Invalid
    })?;
    Ok(candidate)
}

/// Switch an address off (or back on). Returns false when it is not the
/// caller's, so the endpoint can answer 404 without revealing another
/// account's aliases.
pub fn set_disabled(username: &str, local: &str, disabled: bool) -> io::Result<bool> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let key = local.to_ascii_lowercase();
    let alias = match store.aliases.get_mut(&key) {
        Some(a) if a.username.eq_ignore_ascii_case(username) => a,
        _ => return Ok(false),
    };
    alias.disabled_at = if disabled { Some(now()) } else { None };
    write_at(&path, &store)?;
    Ok(true)
}

/// Drop every alias an account holds. Called when the account itself goes, so a
/// deleted account leaves no address behind that still accepts mail nobody can
/// ever read.
pub fn purge(username: &str) -> io::Result<usize> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let before = store.aliases.len();
    store.aliases.retain(|_, a| !a.username.eq_ignore_ascii_case(username));
    let removed = before - store.aliases.len();
    if removed > 0 {
        write_at(&path, &store)?;
    }
    Ok(removed)
}

/// Remove an address outright. Mail already delivered stays in the mailbox.
pub fn delete(username: &str, local: &str) -> io::Result<bool> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let key = local.to_ascii_lowercase();
    match store.aliases.get(&key) {
        Some(a) if a.username.eq_ignore_ascii_case(username) => {}
        _ => return Ok(false),
    }
    store.aliases.remove(&key);
    write_at(&path, &store)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_parts() {
        assert!(valid_local("shop-8f2k"));
        assert!(valid_local("abc"));
        assert!(!valid_local("ab"));
        assert!(!valid_local("-abc"));
        assert!(!valid_local("abc-"));
        assert!(!valid_local("Upper"));
        assert!(!valid_local("sp ace"));
        assert!(!valid_local("admin"));
    }

    #[test]
    fn suggested_names_are_usable() {
        for _ in 0..20 {
            let s = suggest();
            assert!(valid_local(&s), "{} should be a valid alias", s);
        }
    }
}
