//! Queue for mail that arrives before the recipient has a key.
//!
//! The SMTP server has to answer `250` once it accepts a message, so it cannot
//! refuse mail for an account that is still being set up. Dropping it loses the
//! message with no trace for either side. Instead the raw message is written to
//! `data/pending/<username>/` and delivered the moment the account's public key
//! appears — which happens at first-time setup.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::smtp::ReceivedEmail;

#[derive(Serialize, Deserialize)]
struct PendingMessage {
    from: String,
    to: Vec<String>,
    #[serde(default)]
    content: String,
    #[serde(default)]
    is_e2ee: bool,
    received_at: u64,
    /// Whole RFC 5322 message (or the E2EE blob), base64.
    raw_data: String,
}

fn queue_root() -> PathBuf {
    PathBuf::from("data/pending")
}

fn user_dir(username: &str) -> PathBuf {
    // The username is validated on account creation, but never let it climb out
    // of the queue directory anyway.
    let safe: String = username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    queue_root().join(if safe.is_empty() { "_invalid".to_string() } else { safe })
}

/// Store a message for later delivery. Returns the file written.
pub fn queue(username: &str, received: &ReceivedEmail) -> std::io::Result<PathBuf> {
    let dir = user_dir(username);
    fs::create_dir_all(&dir)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let record = PendingMessage {
        from: received.from.clone(),
        to: received.to.clone(),
        content: received.content.clone(),
        is_e2ee: received.is_e2ee,
        received_at: now,
        raw_data: STANDARD.encode(&received.raw_data),
    };

    // Distinct per message: timestamp plus a random suffix, so two messages in
    // the same second cannot overwrite each other.
    let mut suffix = [0u8; 4];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut suffix);
    let name = format!("{}-{}.json", now, hex::encode(suffix));
    let path = dir.join(name);

    let body = serde_json::to_vec(&record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(&path, body)?;
    log::info!(
        "[Pending] Held message for '{}' from <{}> until the account has a key",
        username,
        received.from
    );
    Ok(path)
}

/// Deliver everything held for this account. Call after a public key is stored.
///
/// Returns how many messages were delivered. Files that fail to deliver stay
/// queued, so nothing is dropped on a partial failure.
pub fn drain(
    username: &str,
    user: &crate::core::User,
    email_storage: &crate::core::EmailStorage,
    user_storage: &crate::core::UserStorage,
) -> usize {
    let dir = user_dir(username);
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return 0, // nothing queued: the common case
    };

    let mut delivered = 0usize;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .collect();
    paths.sort(); // oldest first

    for path in paths {
        match deliver_one(&path, username, user, email_storage, user_storage) {
            Ok(()) => {
                delivered += 1;
                let _ = fs::remove_file(&path);
            }
            Err(e) => log::warn!(
                "[Pending] Could not deliver '{}' for '{}': {} — leaving it queued",
                path.display(),
                username,
                e
            ),
        }
    }

    if delivered > 0 {
        log::info!("[Pending] Delivered {} held message(s) to '{}'", delivered, username);
    }
    delivered
}

fn deliver_one(
    path: &Path,
    username: &str,
    user: &crate::core::User,
    email_storage: &crate::core::EmailStorage,
    user_storage: &crate::core::UserStorage,
) -> Result<(), String> {
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let record: PendingMessage = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let bytes = STANDARD
        .decode(&record.raw_data)
        .map_err(|e| format!("bad base64: {}", e))?;

    let mut received = ReceivedEmail::new();
    received.from = record.from;
    received.to = record.to;
    received.content = record.content;
    received.raw_data = bytes;
    received.is_e2ee = record.is_e2ee;

    let email = crate::core::Email::new(received, user);
    email_storage.save_email(&email).map_err(|e| e.to_string())?;

    user_storage.mutate_user(username, |u| {
        if !u.emailIds.contains(&email.uid) {
            u.emailIds.push(email.uid);
        }
    });
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Pending] Delivered but could not persist user '{}': {}", username, e);
    }
    Ok(())
}

/// How many messages are waiting for this account.
pub fn count(username: &str) -> usize {
    fs::read_dir(user_dir(username))
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
                .count()
        })
        .unwrap_or(0)
}
