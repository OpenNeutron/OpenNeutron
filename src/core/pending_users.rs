//! Accounts created by self-registration that no operator has approved yet.
//!
//! `users.bin` is bincode and positional: adding a field to `User` makes every
//! existing record unreadable (see the runbook). So pending state is a sidecar,
//! `data/pending_users.json`, keyed by lowercase username.
//!
//! Deleting the entry *is* the activation - there is no second flag on the
//! account to fall out of sync with it, and a stale entry can be removed with
//! any text editor on the host.
//!
//! The account itself is created at signup, because the login path has to
//! verify the password before it may say "waiting for approval": answering
//! ahead of the password check would confirm which names are queued to anyone
//! who asks.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Relative to the app's working directory, like every other data file here.
pub const STORE_PATH: &str = "data/pending_users.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingUser {
    pub username: String,
    pub requested_at: u64,
    /// Address the request came from, so abuse is visible in the queue.
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub user_agent: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    entries: BTreeMap<String, PendingUser>,
}

/// Serialises read-modify-write cycles: two signups landing at once must not
/// each load the file, add their own entry, and overwrite the other.
static LOCK: Mutex<()> = Mutex::new(());

fn key(username: &str) -> String {
    username.trim().to_lowercase()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn path() -> PathBuf {
    PathBuf::from(STORE_PATH)
}

fn read_at(path: &Path) -> Store {
    // A missing or damaged file means "nothing is pending". That fails open for
    // login (an unreadable queue cannot block approvals), but every write below
    // rewrites the whole file, and the operator sees the loss in `list`.
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn write_at(path: &Path, store: &Store) -> io::Result<()> {
    let text = serde_json::to_string_pretty(store)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    // Write beside the target and rename: a crash mid-write must not leave a
    // truncated queue behind, because a truncated queue silently approves
    // everybody it drops.
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

fn add_at(path: &Path, username: &str, ip: &str, user_agent: &str) -> io::Result<PendingUser> {
    let _held = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut store = read_at(path);

    let username = key(username);
    let entry = store.entries.entry(username.clone()).or_insert_with(|| PendingUser {
        username: username.clone(),
        requested_at: now(),
        ip: String::new(),
        user_agent: String::new(),
    });
    entry.ip = ip.to_string();
    entry.user_agent = user_agent.to_string();
    let entry = entry.clone();

    write_at(path, &store)?;
    Ok(entry)
}

/// Queue an account for approval.
///
/// Re-registering the same name keeps the original request time and only
/// refreshes the address, so a retry cannot push somebody to the back of the
/// queue or overwrite the record of where the first request came from.
pub fn add(username: &str, ip: &str, user_agent: &str) -> io::Result<PendingUser> {
    add_at(&path(), username, ip, user_agent)
}

fn contains_at(path: &Path, username: &str) -> bool {
    read_at(path).entries.contains_key(&key(username))
}

/// Is this account waiting for approval? Called on every login.
pub fn contains(username: &str) -> bool {
    contains_at(&path(), username)
}

fn list_at(path: &Path) -> Vec<PendingUser> {
    let store = read_at(path);
    let mut entries: Vec<PendingUser> = store.entries.into_values().collect();
    entries.sort_by(|a, b| b.requested_at.cmp(&a.requested_at).then(a.username.cmp(&b.username)));
    entries
}

/// Every queued account, newest first.
pub fn list() -> Vec<PendingUser> {
    list_at(&path())
}

fn remove_at(path: &Path, username: &str) -> io::Result<bool> {
    let _held = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut store = read_at(path);
    let removed = store.entries.remove(&key(username)).is_some();
    if removed {
        write_at(path, &store)?;
    }
    Ok(removed)
}

/// Activate an account. Returns whether it was queued at all.
pub fn remove(username: &str) -> io::Result<bool> {
    remove_at(&path(), username)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// A store file of its own per test: these run in parallel.
    fn temp_path() -> PathBuf {
        let unique = format!(
            "pending-users-test-{}-{}.json",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let mut path = std::env::temp_dir();
        path.push(unique);
        let _ = fs::remove_file(&path);
        path
    }

    fn add_at(path: &Path, username: &str, ip: &str) -> PendingUser {
        super::add_at(path, username, ip, "").unwrap()
    }

    #[test]
    fn entries_survive_a_round_trip() {
        let path = temp_path();
        add_at(&path, "alice", "203.0.113.9");

        let store = read_at(&path);
        assert!(store.entries.contains_key("alice"));
        let entry = &store.entries["alice"];
        assert_eq!(entry.ip, "203.0.113.9");
        assert!(entry.requested_at > 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_retry_refreshes_the_address_but_keeps_one_entry_and_its_place() {
        let path = temp_path();
        let first = add_at(&path, "erin", "203.0.113.1");
        let again = add_at(&path, "Erin", "203.0.113.2");

        assert_eq!(again.requested_at, first.requested_at);
        assert_eq!(again.ip, "203.0.113.2");
        assert_eq!(again.username, "erin");
        assert_eq!(read_at(&path).entries.len(), 1);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn usernames_are_keyed_case_insensitively() {
        assert_eq!(key("Alice"), "alice");
        assert_eq!(key("  ALICE\n"), "alice");
    }

    #[test]
    fn contains_matches_regardless_of_case_and_whitespace() {
        let path = temp_path();
        add_at(&path, "alice", "203.0.113.9");
        assert!(contains_at(&path, "alice"));
        assert!(contains_at(&path, " Alice "));
        assert!(!contains_at(&path, "bob"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn removing_the_entry_is_the_activation() {
        let path = temp_path();
        add_at(&path, "carol", "192.0.2.7");
        assert!(contains_at(&path, "carol"));

        assert!(remove_at(&path, "carol").unwrap());
        assert!(!contains_at(&path, "carol"));
        // Removing twice is not an error, it just is not a removal.
        assert!(!remove_at(&path, "carol").unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn removing_an_unknown_account_does_not_rewrite_the_file() {
        let path = temp_path();
        add_at(&path, "dave", "192.0.2.8");
        let before = fs::read_to_string(&path).unwrap();
        assert!(!remove_at(&path, "nobody").unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn listing_is_newest_first() {
        let path = temp_path();
        let mut store = read_at(&path);
        for (name, stamp) in [("old", 100u64), ("new", 300), ("middle", 200)] {
            store.entries.insert(
                name.to_string(),
                PendingUser {
                    username: name.to_string(),
                    requested_at: stamp,
                    ip: String::new(),
                    user_agent: String::new(),
                },
            );
        }
        write_at(&path, &store).unwrap();

        let names: Vec<String> = list_at(&path).into_iter().map(|e| e.username).collect();
        assert_eq!(names, vec!["new", "middle", "old"]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_damaged_file_reads_as_empty_instead_of_panicking() {
        let path = temp_path();
        fs::write(&path, "{ not json").unwrap();
        let store = read_at(&path);
        assert!(store.entries.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn writes_leave_no_partial_file_behind() {
        let path = temp_path();
        add_at(&path, "bob", "198.51.100.4");
        let text = fs::read_to_string(&path).unwrap();
        // A complete document, not a prefix of one: this is what the rename buys.
        assert!(serde_json::from_str::<Store>(&text).is_ok());
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(".tmp");
        assert!(!Path::new(&tmp).exists());
        let _ = fs::remove_file(&path);
    }
}
