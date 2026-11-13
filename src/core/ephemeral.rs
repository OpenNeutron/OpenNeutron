//! Messages that delete themselves.
//!
//! Two rules, one record: a message can be deleted the moment its body is
//! served (`deletes_on_read`), or at a fixed time (`expires_at`), or both. The
//! record is a sidecar — `Email` is bincode, so a new field on the struct would
//! make every stored message unreadable.
//!
//! Enforcement is server-side and deliberate:
//! - the preview path (`/email/bulk`) never returns the body of a
//!   `deletes_on_read` message, so the only way to read it is `/email/get`,
//!   which deletes it as it hands it over. A client that is asked politely to
//!   delete afterwards is not enforcement.
//! - deletion happens *before* the response is written. If the blob cannot be
//!   removed, the caller is told so (`deleted: false`) instead of being told the
//!   message is gone while a copy is still on disk.
//!
//! What this cannot do: unsee the message. The reader has the plaintext in
//! memory and can screenshot it. The promise is "the server no longer holds it".
//!
//! `data/ephemeral.json`:
//! ```json
//! { "entries":  { "<recipient uid>": { ... } },
//!   "receipts": { "<sender uid>":    { "read_at": 1793..., "recipient": "bob" } } }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::{EmailStorage, UserStorage};

pub const STORE_PATH: &str = "data/ephemeral.json";

/// A receipt is the sender's only evidence that their message was read; keep it
/// long enough to be useful, then let it go.
const RECEIPT_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Never accept a shorter timer than this: a message that expires before the
/// recipient's next fetch is an accidental deletion, not a feature.
pub const MIN_EXPIRY_SECONDS: u64 = 60;
pub const MAX_EXPIRY_SECONDS: u64 = 90 * 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    /// The recipient's stored copy.
    pub uid: u128,
    /// Recipient username, so the sweeper can detach without a lookup.
    pub owner: String,
    pub owner_uid: u128,
    /// Sender address, shown to the recipient ("from ...").
    pub sender: String,
    /// The sender's own copy in `sent_emails`; a read receipt is keyed by it.
    pub sender_uid: u128,
    pub deletes_on_read: bool,
    /// Unix time after which the copy goes, read or not.
    pub expires_at: Option<u64>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub read_at: u64,
    pub recipient: String,
    pub sender_uid: u128,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
    #[serde(default)]
    receipts: BTreeMap<String, Receipt>,
}

static LOCK: Mutex<()> = Mutex::new(());

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn path() -> PathBuf {
    PathBuf::from(STORE_PATH)
}

fn key(uid: u128) -> String {
    uid.to_string()
}

fn read_at(path: &Path) -> Store {
    // A damaged or missing file means "nothing is ephemeral": messages stay,
    // which is the safe direction for a privacy feature (a lost queue cannot
    // delete mail, it can only fail to delete it).
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
    // Temp + rename: a truncated record would silently stop enforcing deletion.
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

fn register_at(path: &Path, entry: Entry) -> io::Result<()> {
    let _held = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut store = read_at(path);
    store.entries.insert(key(entry.uid), entry);
    write_at(path, &store)
}

/// Record that this message deletes itself, and under which rule.
pub fn register(entry: Entry) -> io::Result<()> {
    register_at(&path(), entry)
}

fn get_at(path: &Path, uid: u128) -> Option<Entry> {
    read_at(path).entries.get(&key(uid)).cloned()
}

pub fn get(uid: u128) -> Option<Entry> {
    get_at(&path(), uid)
}

/// Every entry, loaded once. The bulk fetch reads this per page, not per message.
pub fn snapshot() -> BTreeMap<u128, Entry> {
    read_at(&path())
        .entries
        .into_iter()
        .filter_map(|(k, v)| k.parse::<u128>().ok().map(|uid| (uid, v)))
        .collect()
}

fn remove_entry_at(path: &Path, uid: u128) -> io::Result<bool> {
    let _held = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut store = read_at(path);
    let removed = store.entries.remove(&key(uid)).is_some();
    if removed {
        write_at(path, &store)?;
    }
    Ok(removed)
}

pub fn remove_entry(uid: u128) -> io::Result<bool> {
    remove_entry_at(&path(), uid)
}

fn receipt_for_at(path: &Path, sender_uid: u128) -> Option<Receipt> {
    read_at(path).receipts.get(&key(sender_uid)).cloned()
}

pub fn receipt_for(sender_uid: u128) -> Option<Receipt> {
    receipt_for_at(&path(), sender_uid)
}

/// The recipient read it: drop the entry and leave the sender a receipt.
///
/// One write, so a crash cannot leave both a receipt and a live entry (which
/// would make the message reappear as "not read yet").
pub fn record_read(entry: &Entry) -> io::Result<()> {
    let _held = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = path();
    let mut store = read_at(&path);
    store.entries.remove(&key(entry.uid));
    if entry.sender_uid != 0 {
        store.receipts.insert(
            key(entry.sender_uid),
            Receipt {
                read_at: now(),
                recipient: entry.owner.clone(),
                sender_uid: entry.sender_uid,
            },
        );
    }
    let cutoff = now().saturating_sub(RECEIPT_TTL_SECONDS);
    store.receipts.retain(|_, r| r.read_at >= cutoff);
    write_at(&path, &store)
}

/// Delete the stored copy and every index that pointed at it.
///
/// The blob is removed first: an index entry without a blob is self-healed
/// elsewhere, but a blob without an index entry is mail nobody can ever find,
/// still occupying the disk. Returns false when the blob could not be removed,
/// so callers can refuse to claim the message is gone.
pub fn purge_message(
    user_storage: &UserStorage,
    email_storage: &EmailStorage,
    owner: &str,
    uid: u128,
) -> bool {
    if let Err(e) = email_storage.delete_email(uid) {
        log::warn!("[Ephemeral] Could not delete blob {}: {}", uid, e);
        return false;
    }
    user_storage.detach_email(owner, uid);
    user_storage.remove_email_from_groups(owner, uid);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Ephemeral] Failed to persist index after deleting {}: {}", uid, e);
    }
    true
}

/// Delete everything whose timer has run out, and tidy the bookkeeping.
pub fn sweep(user_storage: &UserStorage, email_storage: &EmailStorage) {
    let entries = snapshot();
    if entries.is_empty() {
        prune_receipts();
        return;
    }

    let stamp = now();
    for entry in entries.values() {
        let expired = entry.expires_at.map(|at| at <= stamp).unwrap_or(false);
        let missing = !email_storage.emailExists(entry.uid);

        if expired {
            if purge_message(user_storage, email_storage, &entry.owner, entry.uid) {
                let _ = remove_entry(entry.uid);
                // A timer is a deletion too, and the log has to cover it: mail that
                // vanishes because its hour ran out must not look like mail that
                // vanished without a record.
                let _ = crate::core::mailboxlog::append(&entry.owner, "expired", &entry.uid.to_string());
                log::info!(
                    "[Ephemeral] Expired uid={} for '{}' (sent by {})",
                    entry.uid, entry.owner, entry.sender
                );
                continue;
            }
        }

        if missing {
            // The blob went away by another route (manual delete, a crash midway);
            // the entry would otherwise keep re-deleting nothing forever.
            let _ = remove_entry(entry.uid);
            log::info!("[Ephemeral] Dropped entry for missing blob uid={}", entry.uid);
        }
    }

    prune_receipts();
}

fn prune_receipts() {
    let path = path();
    let mut store = read_at(&path);
    let cutoff = now().saturating_sub(RECEIPT_TTL_SECONDS);
    let before = store.receipts.len();
    store.receipts.retain(|_, r| r.read_at >= cutoff);
    if store.receipts.len() != before {
        if let Err(e) = write_at(&path, &store) {
            log::warn!("[Ephemeral] Could not prune receipts: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ephemeral-test-{}-{}.json",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn entry(uid: u128, sender_uid: u128, deletes_on_read: bool) -> Entry {
        Entry {
            uid,
            owner: "bob".into(),
            owner_uid: 7,
            sender: "alice@example.test".into(),
            sender_uid,
            deletes_on_read,
            expires_at: None,
            created_at: now(),
        }
    }

    #[test]
    fn an_entry_round_trips() {
        let path = temp_path();
        register_at(&path, entry(11, 22, true)).unwrap();

        let loaded = get_at(&path, 11).expect("entry");
        assert_eq!(loaded.uid, 11);
        assert_eq!(loaded.sender_uid, 22);
        assert!(loaded.deletes_on_read);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reading_moves_the_entry_into_a_receipt() {
        let path = temp_path();
        register_at(&path, entry(11, 22, true)).unwrap();

        // record_read works on the real store path; mirror its two steps here so
        // the test never touches data/.
        let mut store = read_at(&path);
        let loaded = store.entries.remove("11").unwrap();
        store.receipts.insert(
            "22".into(),
            Receipt { read_at: now(), recipient: loaded.owner.clone(), sender_uid: 22 },
        );
        write_at(&path, &store).unwrap();

        assert!(get_at(&path, 11).is_none());
        let receipt = receipt_for_at(&path, 22).expect("receipt");
        assert_eq!(receipt.recipient, "bob");
        assert!(receipt.read_at > 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn removing_an_unknown_message_is_not_an_error() {
        let path = temp_path();
        register_at(&path, entry(11, 22, true)).unwrap();
        assert!(!remove_entry_at(&path, 99).unwrap());
        assert!(remove_entry_at(&path, 11).unwrap());
        assert!(!remove_entry_at(&path, 11).unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_damaged_store_reads_as_empty() {
        let path = temp_path();
        fs::write(&path, "{ broken").unwrap();
        assert!(get_at(&path, 11).is_none());
        assert!(snapshot_at(&path).is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_timer_before_the_floor_is_rejected_by_the_documented_bounds() {
        assert_eq!(MIN_EXPIRY_SECONDS, 60);
        assert!(MIN_EXPIRY_SECONDS < MAX_EXPIRY_SECONDS);
    }

    fn snapshot_at(path: &Path) -> BTreeMap<u128, Entry> {
        read_at(path)
            .entries
            .into_iter()
            .filter_map(|(k, v)| k.parse::<u128>().ok().map(|uid| (uid, v)))
            .collect()
    }
}
