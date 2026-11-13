//! Which address a message actually arrived at.
//!
//! When mail comes to an alias it lands in the owner's mailbox like any other
//! message, and nothing in the `Email` record says which door it came through —
//! that struct is bincode and positional, so adding a field would make every
//! existing message unreadable. This sidecar holds the association instead.
//!
//! It exists for one reason: a reply should go out from the address the sender
//! wrote to, not from the owner's real one.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static LOCK: Mutex<()> = Mutex::new(());

/// How long to remember an arrival. Long enough for a slow reply, short enough
/// that the file does not grow without bound.
pub const KEEP_SECONDS: u64 = 180 * 24 * 3600;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Arrival {
    /// The alias local part the message was addressed to.
    pub alias: String,
    pub at: u64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Store {
    #[serde(default)]
    pub arrivals: BTreeMap<String, Arrival>,
}

fn path() -> PathBuf {
    PathBuf::from("data").join("arrival.json")
}

fn read_at(path: &PathBuf) -> Store {
    match fs::read(path) {
        Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => Store::default(),
    }
}

fn write_at(path: &PathBuf, store: &Store) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_vec(store).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Remember the alias a message came through. Best effort: a failure here must
/// never cost the message that has already been accepted.
pub fn record(uid: u128, alias: &str) {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    store.arrivals.insert(
        uid.to_string(),
        Arrival { alias: alias.to_ascii_lowercase(), at: now() },
    );
    if let Err(e) = write_at(&path, &store) {
        log::warn!("[Arrival] Could not record '{}' for {}: {}", alias, uid, e);
    }
}

/// The alias a message came through, if it came through one.
pub fn get(uid: u128) -> Option<String> {
    read_at(&path()).arrivals.get(&uid.to_string()).map(|a| a.alias.clone())
}

/// Drop entries older than the retention window.
pub fn sweep_old(at: u64) {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let before = store.arrivals.len();
    store.arrivals.retain(|_, a| at.saturating_sub(a.at) < KEEP_SECONDS);
    if store.arrivals.len() != before {
        if let Err(e) = write_at(&path, &store) {
            log::warn!("[Arrival] Could not prune: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_is_stored_lowercase() {
        let a = Arrival { alias: "Shop-8F2K".to_ascii_lowercase(), at: 1 };
        assert_eq!(a.alias, "shop-8f2k");
    }

    #[test]
    fn uid_keys_round_trip() {
        let uid: u128 = 141028704008735132943253786642523431803;
        let store = Store::default();
        assert!(store.arrivals.get(&uid.to_string()).is_none());
    }
}
