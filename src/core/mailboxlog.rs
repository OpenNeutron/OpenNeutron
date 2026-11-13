//! Append-only deletion log.
//!
//! The property this buys is narrow and worth stating plainly: a message cannot
//! disappear from a mailbox without leaving a record that it was removed. Every
//! deletion appends an entry to a per-account hash chain, each entry hashing the
//! previous head together with its own contents, and the current head is signed.
//!
//! What that does and does not prove:
//!
//! * Any tampering with the *log* — editing an entry, removing one from the middle,
//!   reordering — breaks the chain, because every later entry commits to the ones
//!   before it.
//! * Truncating the *tail* is invisible to the chain alone, which is why the client
//!   remembers the last head it saw. A shorter history than last time is the signal.
//! * The signature is ML-DSA-65, so it is not the weak link when everything else
//!   about this product is post-quantum.
//!
//! It is a tripwire, not a backup: it makes silent deletion detectable after the
//! fact, and it cannot bring a message back.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{EncodedSignature, Generate, KeyExport, MlDsa65, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const LOG_PATH: &str = "data/mailboxlog.json";
/// A mailbox of deletions longer than this is history, not a tripwire; the head
/// and the count still commit to everything older.
const KEEP: usize = 2000;
const KEY_PATH: &str = "data/logkey.json";

fn b64(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(text.trim()).ok()
}

pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LogEntry {
    /// Monotonic, starting at 1.
    pub seq: u64,
    /// Unix seconds.
    pub ts: u64,
    /// What happened: `deleted`, `expired`.
    pub op: String,
    /// The message uid, as a decimal string (u128 does not fit a JSON number).
    pub uid: String,
    /// Hex of this entry's hash.
    pub hash: String,
    /// Hex of the previous entry's hash, or the empty string for the first.
    pub prev: String,
}

impl LogEntry {
    fn compute(seq: u64, ts: u64, op: &str, uid: &str, prev: &str) -> String {
        sha256_hex(format!("{}|{}|{}|{}|{}", prev, seq, ts, op, uid).as_bytes())
    }

    /// Re-derive the hash from the entry's own fields and check it.
    pub fn is_intact(&self) -> bool {
        self.hash == LogEntry::compute(self.seq, self.ts, &self.op, &self.uid, &self.prev)
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct UserLog {
    seq: u64,
    head: String,
    entries: Vec<LogEntry>,
}

#[derive(Serialize, Deserialize, Default)]
struct LogFile {
    users: HashMap<String, UserLog>,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    seed: String,
    public_key: String,
}

fn read_log() -> LogFile {
    fs::read_to_string(LOG_PATH)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn write_log(file: &LogFile) -> Result<(), String> {
    let text = serde_json::to_string(file).map_err(|e| e.to_string())?;
    fs::write(LOG_PATH, text).map_err(|e| e.to_string())
}

fn read_keys() -> Result<(SigningKey<MlDsa65>, VerifyingKey<MlDsa65>), String> {
    if let Ok(text) = fs::read_to_string(KEY_PATH) {
        if let Ok(keys) = serde_json::from_str::<KeyFile>(&text) {
            if let Some(seed) = unb64(&keys.seed) {
                if seed.len() == 32 {
                    let mut raw = [0u8; 32];
                    raw.copy_from_slice(&seed);
                    let signing = SigningKey::<MlDsa65>::from_seed(&raw.into());
                    let verifying = signing.verifying_key();
                    return Ok((signing, verifying));
                }
            }
        }
    }

    let signing = SigningKey::<MlDsa65>::generate();
    let verifying = signing.verifying_key();
    let keys = KeyFile {
        seed: b64(&signing.to_bytes()),
        public_key: b64(&verifying.encode()),
    };
    let text = serde_json::to_string(&keys).map_err(|e| e.to_string())?;
    fs::write(KEY_PATH, text).map_err(|e| e.to_string())?;
    // Restrictive permissions: this key is what makes a forged history noticeable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(KEY_PATH, fs::Permissions::from_mode(0o600));
    }
    Ok((signing, verifying))
}

/// Record that a message left the mailbox.
pub fn append(username: &str, op: &str, uid: &str) -> Result<String, String> {
    let mut file = read_log();
    let entry_user = file.users.entry(username.to_string()).or_default();
    let seq = entry_user.seq + 1;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prev = entry_user.head.clone();
    let hash = LogEntry::compute(seq, ts, op, uid, &prev);

    entry_user.seq = seq;
    entry_user.head = hash.clone();
    entry_user.entries.push(LogEntry {
        seq,
        ts,
        op: op.to_string(),
        uid: uid.to_string(),
        hash: hash.clone(),
        prev,
    });
    if entry_user.entries.len() > KEEP {
        let drop = entry_user.entries.len() - KEEP;
        entry_user.entries.drain(0..drop);
    }

    write_log(&file)?;
    Ok(hash)
}

/// Forget an account's history. Called when the account itself is erased: a
/// reused username must not inherit a log of deletions made by someone else.
pub fn forget(username: &str) -> Result<(), String> {
    let mut file = read_log();
    if file.users.remove(username).is_some() {
        write_log(&file)?;
    }
    Ok(())
}

/// What the client needs to check: how far the log goes, its head, and the tail.
#[derive(Serialize, Clone)]
pub struct LogSnapshot {
    pub count: u64,
    pub head: String,
    pub entries: Vec<LogEntry>,
    /// ML-DSA-65 signature over the head string.
    pub signature: String,
    pub public_key: String,
}

pub fn snapshot(username: &str, tail: usize) -> Result<LogSnapshot, String> {
    let file = read_log();
    let user = file.users.get(username).cloned().unwrap_or_default();
    let (signing, verifying) = read_keys()?;
    let signature = signing.sign(user.head.as_bytes());
    let entries = user
        .entries
        .iter()
        .rev()
        .take(tail)
        .cloned()
        .collect::<Vec<_>>();
    Ok(LogSnapshot {
        count: user.seq,
        head: user.head,
        entries,
        signature: b64(&signature.encode()),
        public_key: b64(&verifying.encode()),
    })
}

/// Verify a head against its signature. Used by tests and the offline proof.
pub fn verify_head(public_key_b64: &str, head: &str, signature_b64: &str) -> bool {
    let Some(pk) = unb64(public_key_b64) else { return false };
    let Some(sig) = unb64(signature_b64) else { return false };
    let Ok(pk_bytes) = <[u8; 1952]>::try_from(pk.as_slice()) else { return false };
    let Ok(sig_bytes) = <[u8; 3309]>::try_from(sig.as_slice()) else { return false };
    let verifying = VerifyingKey::<MlDsa65>::decode(&pk_bytes.into());
    let encoded: EncodedSignature<MlDsa65> = sig_bytes.into();
    let Some(signature) = Signature::<MlDsa65>::decode(&encoded) else {
        return false;
    };
    verifying.verify(head.as_bytes(), &signature).is_ok()
}

/// Walk a chain and report the first break, if any.
pub fn chain_is_intact(entries: &[LogEntry]) -> bool {
    let mut previous = entries
        .first()
        .map(|e| e.prev.clone())
        .unwrap_or_default();
    for entry in entries {
        if !entry.is_intact() || entry.prev != previous {
            return false;
        }
        previous = entry.hash.clone();
    }
    true
}

pub fn ensure_storage() -> bool {
    Path::new("data").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("logtest-{}", std::process::id()));
        let _ = fs::create_dir_all(dir.join("data"));
        dir
    }

    #[test]
    fn entry_hash_covers_its_fields() {
        let entry = LogEntry {
            seq: 1,
            ts: 100,
            op: "deleted".into(),
            uid: "42".into(),
            hash: LogEntry::compute(1, 100, "deleted", "42", ""),
            prev: String::new(),
        };
        assert!(entry.is_intact());

        let mut edited = entry.clone();
        edited.uid = "43".into();
        assert!(!edited.is_intact(), "changing the uid must break the hash");

        let mut backdated = entry;
        backdated.ts = 99;
        assert!(!backdated.is_intact(), "backdating must break the hash");
    }

    #[test]
    fn a_chain_links_every_entry_to_the_one_before() {
        let mut entries = Vec::new();
        let mut prev = String::new();
        for seq in 1..=4u64 {
            let hash = LogEntry::compute(seq, 1000 + seq, "deleted", &seq.to_string(), &prev);
            entries.push(LogEntry {
                seq,
                ts: 1000 + seq,
                op: "deleted".into(),
                uid: seq.to_string(),
                hash: hash.clone(),
                prev: prev.clone(),
            });
            prev = hash;
        }
        assert!(chain_is_intact(&entries));

        // Removing an entry from the middle breaks the link after it.
        let mut gap = entries.clone();
        gap.remove(1);
        assert!(!chain_is_intact(&gap));

        // So does swapping two neighbours.
        let mut swapped = entries.clone();
        swapped.swap(1, 2);
        assert!(!chain_is_intact(&swapped));
    }

    #[test]
    fn head_signature_round_trips_and_rejects_a_different_head() {
        let signing = SigningKey::<MlDsa65>::generate();
        let verifying = signing.verifying_key();
        let head = "a".repeat(64);
        let signature = signing.sign(head.as_bytes());
        let pk_b64 = b64(&verifying.encode());
        let sig_b64 = b64(&signature.encode());

        assert!(verify_head(&pk_b64, &head, &sig_b64));
        assert!(!verify_head(&pk_b64, &"b".repeat(64), &sig_b64));
        assert!(!verify_head(&pk_b64, "short", &sig_b64));
        assert!(!verify_head("not base64", &head, &sig_b64));
    }
}
