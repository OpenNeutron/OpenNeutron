//! Importing mail that was not delivered here.
//!
//! `POST /api/import/message`  (session)  one RFC 822 message, base64
//!
//! Export has always existed; without this, a person can leave with their mail
//! but cannot arrive with it. The work is deliberately the same work SMTP does:
//! the bytes are parsed for their envelope, encrypted to the account key by
//! `Email::new`, written to the same blob store and appended to the same index,
//! so an imported message is indistinguishable from a delivered one afterwards.
//!
//! Two things are deliberately different from delivery:
//!
//! - No push notification. Importing a thousand messages must not fire a
//!   thousand notifications at a phone in someone's pocket.
//! - The original date is preserved (the browser parses the `Date` header and
//!   sends it), because an archive that all arrives "today" sorts wrongly and
//!   reads as lost history.
//!
//! A message that has been imported once is not imported again: the Message-ID
//! goes into a sidecar set, so a retried upload after a failure does not double
//! the mailbox. The set is a sidecar because `Email` is positional bincode.

use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{email::Email, EmailStorage, User, UserStorage};
use crate::smtp::ReceivedEmail;

/// One message. 20 MB is roughly the largest thing an archive holds; anything
/// larger is usually a mistake or an abuse, and either way the import should
/// report it rather than eat the container's memory.
const MAX_MESSAGE_BYTES: usize = 20 * 1024 * 1024;
/// Keep the dedupe set bounded; a mailbox of 50k imports is already unusual.
const MAX_SEEN_IDS: usize = 50_000;

#[derive(Deserialize)]
struct ImportRequest {
    /// Base64 of the raw message, exactly as it sits in the file.
    raw: String,
    /// Unix seconds from the message's own `Date` header, parsed by the client.
    /// Clamped here: an archive is allowed to be old, not to be from the future.
    #[serde(default)]
    date_unix: Option<u64>,
}

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
}

fn json_error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    out(
        status,
        serde_json::to_vec(&json!({ "error": message, "code": code })).unwrap_or_default(),
    )
}

/// Header block to map, with the same lowercasing the SMTP path uses.
fn split_headers(raw: &[u8]) -> (String, usize) {
    // Files carry CRLF, but plenty of tools write bare LF. Both are a separator.
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return (String::from_utf8_lossy(&raw[..pos]).to_string(), pos + 4);
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return (String::from_utf8_lossy(&raw[..pos]).to_string(), pos + 2);
    }
    (String::from_utf8_lossy(raw).to_string(), raw.len())
}


/// Lowercase hex SHA-256, for identifying a message that has no Message-ID.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    // Folded headers continue on the next line with leading whitespace; a
    // Message-ID or a long From can be folded, so join the continuations.
    let mut lines = headers.lines();
    let mut collecting = false;
    let mut value = String::new();
    for line in lines.by_ref() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if collecting {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if collecting {
            break;
        }
        if let Some((key, rest)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(name) {
                value.push_str(rest.trim());
                collecting = true;
            }
        }
    }
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// A bare address out of `"Name <a@b>"`, or the value itself.
fn address_of(value: &str) -> String {
    if let (Some(open), Some(close)) = (value.rfind('<'), value.rfind('>')) {
        if close > open {
            return value[open + 1..close].trim().to_string();
        }
    }
    value.trim().trim_matches('"').to_string()
}

fn seen_path() -> std::path::PathBuf {
    std::path::PathBuf::from("data/imported.json")
}

/// Message-ID -> uid of the message that carried it.
///
/// The uid matters: a message the person has since deleted is no longer in the
/// mailbox, so importing the archive again should bring it back rather than
/// report it as already here.
fn load_seen() -> Vec<(String, String)> {
    std::fs::read_to_string(seen_path())
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("seen").and_then(|i| i.as_object()).cloned())
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|uid| (k.clone(), uid.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn remember_seen(id: &str, uid: u128) {
    let mut seen = load_seen();
    seen.retain(|(existing, _)| existing != id);
    seen.push((id.to_string(), uid.to_string()));
    if seen.len() > MAX_SEEN_IDS {
        let start = seen.len() - MAX_SEEN_IDS / 2;
        seen.drain(0..start);
    }
    let as_map: std::collections::BTreeMap<&String, &String> =
        seen.iter().map(|(k, v)| (k, v)).collect();
    let body = serde_json::to_vec(&json!({ "seen": as_map })).unwrap_or_default();
    let tmp = seen_path().with_extension("json.tmp");
    // Write-then-rename: a crash mid-write must not leave a truncated set that
    // would let a re-import double every message.
    if std::fs::write(&tmp, &body).is_ok() {
        let _ = std::fs::rename(&tmp, seen_path());
    }
}

pub fn message(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    let req: ImportRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Import is not a way to get mail stored in the clear: without a key the
    // message would sit readable on the server, which is the one thing this
    // mailbox promises never happens.
    if user.publicKey.is_none() {
        return json_error(
            409,
            "no_encryption_key",
            "Finish setting up your encryption keys before importing mail",
        );
    }

    let raw = match STANDARD.decode(req.raw.trim()) {
        Ok(bytes) => bytes,
        Err(_) => return json_error(400, "invalid_message", "That message is not valid base64"),
    };
    if raw.is_empty() {
        return json_error(400, "empty_message", "That message is empty");
    }
    if raw.len() > MAX_MESSAGE_BYTES {
        return json_error(
            413,
            "message_too_large",
            "That message is larger than 20 MB",
        );
    }

    let (header_block, body_start) = split_headers(&raw);
    let message_id = header_value(&header_block, "message-id");
    // Identity for dedupe: the Message-ID when there is one, otherwise the bytes
    // themselves. Plenty of mail — and every message a test writes by hand — has
    // no Message-ID, and without a fallback restoring the same archive twice
    // duplicates the whole mailbox.
    let identity = message_id
        .clone()
        .unwrap_or_else(|| format!("sha256:{}", sha256_hex(&raw)));
    if !identity.is_empty() {
        // Skipped only if that copy is still in the mailbox. A deleted message
        // is not "already here", and a re-import is how someone gets it back.
        let still_here = load_seen().into_iter().any(|(seen_id, seen_uid)| {
            seen_id == identity
                && seen_uid
                    .parse::<u128>()
                    .map(|uid| user.emailIds.contains(&uid))
                    .unwrap_or(false)
        });
        if still_here {
            return out(
                200,
                serde_json::to_vec(&json!({ "skipped": true, "message_id": identity }))
                    .unwrap_or_default(),
            );
        }
    }

    let from_header = header_value(&header_block, "from").unwrap_or_else(|| "unknown".to_string());
    let sender = address_of(&from_header);

    let mut headers = std::collections::HashMap::new();
    for line in header_block.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let k = key.trim().to_lowercase();
            if !k.is_empty() && !headers.contains_key(&k) {
                headers.insert(k, value.trim().to_string());
            }
        }
    }

    // The mailbox this lands in. `User` carries no address of its own (the
    // struct is positional bincode and must not grow), so it is built from the
    // account name and the domain the storage was configured with.
    let own_address = format!("{}@{}", user.username, user_storage.domain);

    let mut received = ReceivedEmail::new();
    received.from = sender;
    received.to = vec![own_address];
    received.raw_data = raw.clone();
    received.headers = headers;
    received.content = String::from_utf8_lossy(&raw[body_start.min(raw.len())..]).to_string();
    received.dkim_status = "imported".to_string();
    received.is_e2ee = false;

    let mut email = Email::new(received, &user);
    email.secure = true;
    // Keep the archive's own chronology. A future date is not a date.
    if let Some(when) = req.date_unix {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if when > 0 && when <= now + 86_400 {
            email.timestamp = when;
        }
    }
    let uid = email.uid;
    let sender_for_groups = email.from.clone();

    if let Err(e) = email_storage.save_email(&email) {
        log::error!("[Import] Could not save blob for '{}': {}", user.username, e);
        return json_error(500, "save_failed", "The message could not be stored");
    }

    user_storage.mutate_user(&user.username, |u| {
        if !u.emailIds.contains(&uid) {
            u.emailIds.push(uid);
        }
    });
    user_storage.add_email_to_matching_groups(&user.username, uid, &sender_for_groups);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Import] Failed to persist the index after importing for '{}': {}", user.username, e);
    }
    remember_seen(&identity, uid);

    log::info!("[Import] '{}' imported message uid={} from <{}>", user.username, uid, sender_for_groups);
    out(
        200,
        serde_json::to_vec(&json!({
            "uid": uid.to_string(),
            "skipped": false,
            "from": sender_for_groups,
            "timestamp": email.timestamp,
        }))
        .unwrap_or_default(),
    )
}
