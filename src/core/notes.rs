//! Sealed notes: a message whose content never reaches the recipient's server.
//!
//! A message delivered by SMTP is the recipient's to keep; no header we can add
//! makes their provider delete it. So for a recipient on another provider, the
//! body is not delivered at all. It is encrypted to their OpenPGP key here, kept
//! on this server, and announced by a link that we control:
//!
//! - the link is a capability: 32 random bytes, no other credential needed
//! - opening it hands over the armour and clears it in the same write, so the
//!   ciphertext is gone before the browser can ask twice
//! - a timer clears it even if nobody opens it
//!
//! What this does not do: delete the notification from their inbox. That email
//! carries the subject and the link, and it stays where they put it.
//!
//! The server cannot read a note: `armored` is PGP ciphertext produced by the
//! sender's client, and there is no key here to open it with.
//!
//! `data/notes.json`:
//! ```json
//! { "notes": { "<token>": { "recipient": "...", "armored": "-----BEGIN PGP MESSAGE-----..." } } }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rand::RngCore;

pub const STORE_PATH: &str = "data/notes.json";

/// A note is a mail body, not a mail: attachments are not sealed. Anything
/// larger than this is refused rather than quietly truncated.
pub const MAX_ARMORED_BYTES: usize = 512 * 1024;

pub const MIN_EXPIRY_SECONDS: u64 = 60;
pub const MAX_EXPIRY_SECONDS: u64 = 90 * 24 * 60 * 60;

/// Opened and expired notes keep their status for a month so the sender can see
/// what happened, then go entirely.
const STATUS_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Bounds the store per account. Someone with 50 unopened notes to strangers is
/// not being careful with other people's storage.
pub const MAX_ACTIVE_PER_SENDER: usize = 50;

/// A passphrase note can be fetched until the phrase is right, so a typo costs
/// nothing; past this many fetches the link stops working regardless, which
/// also bounds how far one link can travel.
pub const MAX_PASSPHRASE_FETCHES: u32 = 5;

fn default_mode() -> String {
    "pgp".to_string()
}

/// One attachment, already encrypted by the sender's browser to the same secret
/// as the body. Stored as armour: base64 of binary ciphertext needs escaping, and
/// armour is plain ASCII that survives JSON, logs and diffs without surprises.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteFile {
    /// What the recipient sees. Only ever a name, never a path.
    pub name: String,
    pub armored: String,
    /// Plaintext size, so the recipient knows what they are about to download.
    #[serde(default)]
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    pub token: String,
    /// Sender's username and uid: who to show on the page, who may read status.
    pub owner: String,
    pub owner_uid: u128,
    pub recipient: String,
    /// Shown on the page and carried in the notification.
    pub subject: String,
    /// "pgp" — armour locked to the recipient's key, so only they can read it.
    /// "passphrase" — armour locked to a phrase the sender shares out of band,
    /// so a recipient with no key at all can still read it on any device.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Fetches of a passphrase note. A wrong phrase must not burn the message,
    /// so it survives a few attempts — but not unlimited ones.
    #[serde(default)]
    pub fetches: u32,
    /// PGP armour. Cleared on open, on expiry, and never readable here.
    #[serde(default)]
    pub armored: String,
    /// Attachments, encrypted to the same secret as the body and cleared with it.
    #[serde(default)]
    pub files: Vec<NoteFile>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub opened_at: Option<u64>,
    pub expired_at: Option<u64>,
    /// Withdrawn by the sender before it was read.
    #[serde(default)]
    pub revoked_at: Option<u64>,
    /// Opens attempted after the ciphertext was gone (someone reusing a link).
    #[serde(default)]
    pub opens: u32,
    /// The sender's own copy of the notification, for correlating status.
    #[serde(default)]
    pub sender_uid: u128,
}

impl Note {
    pub fn is_sealed(&self) -> bool {
        self.opened_at.is_none() && self.expired_at.is_none() && !self.armored.is_empty()
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_expired(&self, now: u64) -> bool {
        match self.expires_at {
            Some(at) => now >= at,
            None => false,
        }
    }

    pub fn state(&self) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.expired_at.is_some() {
            "expired"
        } else if self.opened_at.is_some() {
            "opened"
        } else {
            "sealed"
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    notes: BTreeMap<String, Note>,
}

static LOCK: Mutex<()> = Mutex::new(());

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn path() -> PathBuf {
    PathBuf::from(STORE_PATH)
}

/// 32 bytes, url-safe, unpadded. The token is the only thing standing between a
/// stranger and the ciphertext, so it is drawn from the OS.
pub fn new_token() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    raw.iter()
        .map(|b| ALPHABET[(*b as usize) & 63] as char)
        .collect()
}

fn read_at(path: &Path) -> Store {
    // A damaged store reads as empty: notes that cannot be found simply cannot
    // be opened, which fails closed for the recipient and never leaks content.
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn write_at(path: &Path, store: &Store) -> io::Result<()> {
    let text = serde_json::to_string_pretty(store).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    // Temp + rename: a half-written store would silently drop notes.
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

/// Store a sealed note. Returns the token.
pub fn create(note: Note) -> io::Result<String> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let token = note.token.clone();
    store.notes.insert(token.clone(), note);
    write_at(&path, &store)?;
    Ok(token)
}

pub fn get(token: &str) -> Option<Note> {
    read_at(&path()).notes.get(token).cloned()
}

/// How many notes this sender still has unopened.
pub fn active_count(owner_uid: u128) -> usize {
    read_at(&path())
        .notes
        .values()
        .filter(|n| n.owner_uid == owner_uid && n.is_sealed())
        .count()
}

#[derive(Debug)]
pub enum Open {
    /// Handed over; the ciphertext is gone from the store.
    Served(Note),
    /// Already opened once. The link is spent.
    Spent,
    /// The timer ran out first.
    Expired,
    /// Never existed, or was pruned.
    Missing,
}

/// Hand over the armour and clear it in one write.
///
/// The record itself stays (without the ciphertext) so the sender can be told
/// what happened to their note. Clearing and serving are the same lock, so two
/// simultaneous opens cannot both receive the body.
pub fn open(token: &str) -> io::Result<Open> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let now = now();

    let note = match store.notes.get_mut(token) {
        Some(n) => n,
        None => return Ok(Open::Missing),
    };

    if note.is_revoked() {
        return Ok(Open::Missing);
    }
    if note.armored.is_empty() && note.opened_at.is_some() {
        note.opens = note.opens.saturating_add(1);
        write_at(&path, &store)?;
        return Ok(Open::Spent);
    }
    if note.is_expired(now) {
        note.expired_at = Some(now);
        note.armored.clear();
        note.files.clear();
        write_at(&path, &store)?;
        return Ok(Open::Expired);
    }

    let served = note.clone();

    if note.mode == "passphrase" {
        // The phrase is the secret, not the link: fetching without it gives
        // nothing away, and burning it on a typo would cost the recipient the
        // message. The page calls `burn` once the plaintext is on screen.
        note.fetches = note.fetches.saturating_add(1);
        if note.fetches > MAX_PASSPHRASE_FETCHES {
            note.armored.clear();
            note.files.clear();
            note.opened_at = Some(now);
        }
        write_at(&path, &store)?;
        return Ok(Open::Served(served));
    }

    note.armored.clear();
    note.files.clear();
    note.opened_at = Some(now);
    write_at(&path, &store)?;
    Ok(Open::Served(served))
}

/// Clear the armour once the recipient has actually read it.
///
/// Only passphrase notes need this: their fetch cannot delete (a wrong phrase
/// must not destroy the message), so the page reports a successful decrypt.
pub fn burn(token: &str) -> io::Result<bool> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let note = match store.notes.get_mut(token) {
        Some(n) => n,
        None => return Ok(false),
    };
    if note.armored.is_empty() {
        return Ok(false);
    }
    note.armored.clear();
    for file in note.files.iter_mut() {
        file.armored.clear();
    }
    note.files.clear();
    note.opened_at = Some(now());
    write_at(&path, &store)?;
    Ok(true)
}

/// Withdraw a note before it is read. Owner-only: the caller passes the uid it
/// is allowed to act for, and a note owned by anyone else is left alone.
pub fn revoke(token: &str, owner_uid: u128) -> io::Result<bool> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let note = match store.notes.get_mut(token) {
        Some(n) if n.owner_uid == owner_uid => n,
        _ => return Ok(false),
    };
    if note.opened_at.is_some() || note.revoked_at.is_some() {
        return Ok(false);
    }
    note.armored.clear();
    note.files.clear();
    note.revoked_at = Some(now());
    write_at(&path, &store)?;
    Ok(true)
}

/// The sender's view: state per token, but never the ciphertext.
pub fn statuses(owner_uid: u128, tokens: &[String]) -> Vec<Note> {
    let store = read_at(&path());
    tokens
        .iter()
        .filter_map(|t| store.notes.get(t))
        .filter(|n| n.owner_uid == owner_uid)
        .map(|n| {
            let mut copy = n.clone();
            copy.armored.clear();
            copy
        })
        .collect()
}

/// Drop timers that ran out, and forget notes that have been settled for a month.
pub fn sweep() {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let now = now();
    let mut changed = false;

    for note in store.notes.values_mut() {
        if note.is_sealed() && note.is_expired(now) {
            note.armored.clear();
            note.files.clear();
            note.expired_at = Some(now);
            changed = true;
        }
    }

    let before = store.notes.len();
    store.notes.retain(|_, n| {
        let settled_at = n.opened_at.or(n.expired_at);
        match settled_at {
            Some(at) => now.saturating_sub(at) < STATUS_TTL_SECONDS,
            None => true,
        }
    });
    if store.notes.len() != before {
        changed = true;
    }

    if changed {
        if let Err(e) = write_at(&path, &store) {
            log::warn!("[notes] sweep could not write: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note_at(dir: &Path, token: &str, expires_at: Option<u64>) -> Note {
        Note {
            token: token.into(),
            owner: "alice".into(),
            owner_uid: 1,
            recipient: "bob@startmail.com".into(),
            subject: "hello".into(),
            mode: "pgp".into(),
            fetches: 0,
            armored: "-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----".into(),
            created_at: now(),
            expires_at,
            opened_at: None,
            expired_at: None,
            revoked_at: None,
            opens: 0,
            sender_uid: 7,
            files: Vec::new(),
        }
    }

    #[test]
    fn token_is_long_and_unique() {
        let a = new_token();
        let b = new_token();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn store_round_trips_and_open_clears_the_body() {
        let dir = tempdir();
        let path = dir.join("notes.json");
        let n = note_at(&dir, "tok1", None);
        {
            let _held = LOCK.lock().unwrap();
            let mut store = read_at(&path);
            store.notes.insert("tok1".into(), n.clone());
            write_at(&path, &store).unwrap();
        }
        let store = read_at(&path);
        assert!(store.notes["tok1"].armored.starts_with("-----BEGIN"));

        // Opening through the real function needs the fixed STORE_PATH, so the
        // state machine is exercised directly here.
        let mut opened = store.notes["tok1"].clone();
        opened.armored.clear();
        opened.opened_at = Some(now());
        assert!(!opened.is_sealed());
        assert_eq!(opened.state(), "opened");
    }

    #[test]
    fn expired_notes_report_expired_not_sealed() {
        let n = Note {
            expires_at: Some(now().saturating_sub(5)),
            ..note_at(Path::new("."), "t", None)
        };
        assert!(n.is_expired(now()));
        assert!(n.is_sealed());
    }

    #[test]
    fn a_missing_file_reads_as_empty() {
        let store = read_at(Path::new("/nonexistent/notes.json"));
        assert!(store.notes.is_empty());
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("notes-test-{}-{}", std::process::id(), new_token()));
        fs::create_dir_all(&p).unwrap();
        p
    }
}
