//! Trash: a delete that can be taken back for thirty days.
//!
//! Deleting used to be immediate and final the moment the confirmation was pressed. Now a
//! message is first moved to the trash: it stays in its owner's received or sent list (so
//! the existing read paths, which check those lists, keep working for the Trash view), and
//! the list endpoints leave it out. Restoring takes it out of the trash again; nothing about
//! the message itself changed in between.
//!
//! The record is a sidecar for the same reason `ephemeral.json` is: `User` is bincode, and a
//! new field on the struct would make `users.bin` unreadable.
//!
//! Permanent deletion — emptying the trash, deleting from inside it, or the thirty days
//! running out — goes through `purge`, which removes the blob first and only then records
//! the uid in the signed deletion log. A message that is merely in the trash is not logged
//! as deleted, because it is not.
//!
//! `data/trash.json`:
//! ```json
//! { "users": { "alice": { "<uid>": { "uid": ..., "kind": "inbox", "trashed_at": 1793... } } } }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::{EmailStorage, UserStorage};

pub const STORE_PATH: &str = "data/trash.json";

/// How long a message waits in the trash before it is deleted for good.
pub const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub uid: u128,
    /// "inbox" for received mail, "sent" for the owner's own sent copy.
    pub kind: String,
    pub trashed_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    users: BTreeMap<String, BTreeMap<String, Item>>,
}

static LOCK: Mutex<()> = Mutex::new(());

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn path() -> PathBuf {
    PathBuf::from(STORE_PATH)
}

fn read_at(path: &Path) -> Store {
    // A damaged or missing file means "nothing is in the trash": every message shows in its
    // folder again. That is the safe direction — a lost record can resurface mail, never
    // delete it.
    fs::read_to_string(path).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
}

fn write_at(path: &Path, store: &Store) -> io::Result<()> {
    let text = serde_json::to_string_pretty(store).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

pub fn add_at(path: &Path, username: &str, uid: u128, kind: &str, at: u64) -> io::Result<()> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = read_at(path);
    store.users.entry(username.to_string()).or_default().insert(
        uid.to_string(),
        Item { uid, kind: kind.to_string(), trashed_at: at },
    );
    write_at(path, &store)
}

/// Take a message out of the trash. Ok(false) when it was not there.
pub fn remove_at(path: &Path, username: &str, uid: u128) -> io::Result<bool> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = read_at(path);
    let removed = match store.users.get_mut(username) {
        Some(items) => items.remove(&uid.to_string()).is_some(),
        None => false,
    };
    if !removed {
        return Ok(false);
    }
    if store.users.get(username).map(|items| items.is_empty()).unwrap_or(false) {
        store.users.remove(username);
    }
    write_at(path, &store)?;
    Ok(true)
}

pub fn list_at(path: &Path, username: &str) -> Vec<Item> {
    let store = read_at(path);
    let mut items: Vec<Item> = store.users.get(username).map(|m| m.values().cloned().collect()).unwrap_or_default();
    // Most recently trashed first, the way the folder reads.
    items.sort_by(|a, b| b.trashed_at.cmp(&a.trashed_at));
    items
}

/// Every (owner, item) whose thirty days have run out at `stamp`.
pub fn due_at(path: &Path, stamp: u64) -> Vec<(String, Item)> {
    let store = read_at(path);
    let mut due = Vec::new();
    for (owner, items) in &store.users {
        for item in items.values() {
            if item.trashed_at.saturating_add(RETENTION_SECONDS) <= stamp {
                due.push((owner.clone(), item.clone()));
            }
        }
    }
    due
}

pub fn add(username: &str, uid: u128, kind: &str) -> io::Result<()> {
    add_at(&path(), username, uid, kind, now())
}

pub fn remove(username: &str, uid: u128) -> io::Result<bool> {
    remove_at(&path(), username, uid)
}

pub fn list(username: &str) -> Vec<Item> {
    list_at(&path(), username)
}

/// The uids a list endpoint must leave out for this owner.
pub fn trashed_uids(username: &str) -> HashSet<u128> {
    list(username).into_iter().map(|item| item.uid).collect()
}

/// The owner's received mail that is not in the trash: what an unread count should count.
pub fn inbox_ids(user: &crate::core::User) -> Vec<u128> {
    let trashed = trashed_uids(&user.username);
    user.emailIds.iter().copied().filter(|id| !trashed.contains(id)).collect()
}

/// Delete one message for good: blob first, then the owner's lists and groups, then the
/// trash record, then the signed log. Returns false (and changes nothing) when the blob
/// could not be removed.
pub fn purge(user_storage: &UserStorage, email_storage: &EmailStorage, owner: &str, uid: u128) -> bool {
    if email_storage.emailExists(uid) {
        if let Err(e) = email_storage.delete_email(uid) {
            log::warn!("[Trash] Could not delete blob {}: {}", uid, e);
            return false;
        }
    }
    user_storage.detach_email(owner, uid);
    user_storage.remove_email_from_groups(owner, uid);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Trash] Failed to persist index after deleting {}: {}", uid, e);
    }
    let _ = remove(owner, uid);
    if let Err(e) = crate::core::mailboxlog::append(owner, "deleted", &uid.to_string()) {
        log::warn!("[Log] Could not record deletion of {}: {}", uid, e);
    }
    true
}

/// Delete what has waited thirty days. A record whose message is already gone (a timer, a
/// crash midway) is dropped without a log entry: it was logged when it went.
pub fn sweep(user_storage: &UserStorage, email_storage: &EmailStorage) {
    for (owner, item) in due_at(&path(), now()) {
        if !email_storage.emailExists(item.uid) {
            let _ = remove(&owner, item.uid);
            continue;
        }
        if purge(user_storage, email_storage, &owner, item.uid) {
            log::info!("[Trash] Deleted uid={} for '{}' after {} days in the trash", item.uid, owner, RETENTION_SECONDS / 86_400);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("trash-test-{}-{}-{}", name, std::process::id(), now()));
        let _ = fs::create_dir_all(&dir);
        dir.join("trash.json")
    }

    #[test]
    fn a_trashed_message_is_listed_and_can_be_restored() {
        let p = temp("restore");
        add_at(&p, "alice", 7, "inbox", 100).unwrap();
        add_at(&p, "alice", 9, "sent", 200).unwrap();
        let items = list_at(&p, "alice");
        assert_eq!(items.iter().map(|i| i.uid).collect::<Vec<_>>(), vec![9, 7], "newest first");
        assert_eq!(items[0].kind, "sent");
        assert!(remove_at(&p, "alice", 7).unwrap());
        assert!(!remove_at(&p, "alice", 7).unwrap(), "restoring twice says it was not there");
        assert_eq!(list_at(&p, "alice").len(), 1);
    }

    #[test]
    fn owners_do_not_see_each_others_trash() {
        let p = temp("owners");
        add_at(&p, "alice", 1, "inbox", 100).unwrap();
        assert!(list_at(&p, "bob").is_empty());
        assert!(!remove_at(&p, "bob", 1).unwrap(), "bob cannot restore alice's message");
        assert_eq!(list_at(&p, "alice").len(), 1);
    }

    #[test]
    fn only_messages_older_than_thirty_days_are_due() {
        let p = temp("due");
        add_at(&p, "alice", 1, "inbox", 1_000).unwrap();
        add_at(&p, "alice", 2, "inbox", 1_000 + RETENTION_SECONDS).unwrap();
        let due = due_at(&p, 1_000 + RETENTION_SECONDS);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1.uid, 1);
    }

    #[test]
    fn a_damaged_record_means_an_empty_trash_not_lost_mail() {
        let p = temp("damaged");
        fs::write(&p, "{ not json").unwrap();
        assert!(list_at(&p, "alice").is_empty());
        assert!(due_at(&p, u64::MAX).is_empty());
    }

    #[test]
    fn a_128_bit_uid_survives_the_round_trip() {
        let p = temp("u128");
        let uid: u128 = 79077153517879815893541103082182958680;
        add_at(&p, "alice", uid, "sent", 5).unwrap();
        assert_eq!(list_at(&p, "alice")[0].uid, uid);
    }
}
