//! Web Key Directory (WKD) publishing.
//!
//! WKD is how a *correspondent's* mail client finds your public key without you
//! sending it to them: it fetches
//!
//!     https://openpgpkey.<domain>/<hash>/hu/<hash>
//!
//! where `hash = zbase32(sha1(lowercased-local-part))`. The client computes the
//! hash (it already has SHA-1 via WebCrypto) and posts the dearmored key here;
//! the server's only jobs are storing the bytes and answering status.

use base64::Engine as _;
use serde::Deserialize;
use serde_json;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::{json_header, ErrorResponse, MessageResponse};
use crate::api::request::read_json_body;
use crate::core::{EmailStorage, User, UserStorage};

#[derive(Deserialize)]
pub struct PublishKeyRequest {
    /// zbase32(sha1(local part)), computed by the client.
    pub hash: String,
    /// The public key, dearmored (binary) and base64'd.
    pub key_b64: String,
    pub email: String,
    pub fingerprint: String,
}

fn wkd_dir() -> PathBuf {
    PathBuf::from("data/wkd")
}

fn hash_is_sane(hash: &str) -> bool {
    // z-base-32 of a 20-byte digest is 32 characters; allow the standard alphabet.
    (32..=40).contains(&hash.len())
        && hash
            .chars()
            .all(|c| "ybndrfg8ejkmcpqxot1uwisza345h769".contains(c))
}

/// POST /pgp/wkd/publish
pub fn publish_wkd(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };

    let body: PublishKeyRequest = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    if !hash_is_sane(&body.hash) {
        return error(400, "bad_hash", "That is not a valid WKD identifier");
    }

    // The account may only publish its own address.
    let own_address = format!("{}@{}", user.username, user_storage.domain).to_lowercase();
    if body.email.to_lowercase() != own_address {
        return error(403, "forbidden_address", "You can only publish your own key");
    }

    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(body.key_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return error(400, "bad_key", "The key was not valid base64"),
    };
    if key_bytes.len() < 64 {
        return error(400, "bad_key", "That key looks truncated");
    }

    let dir = wkd_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        return error(500, "io_error", &format!("Could not prepare the WKD directory: {e}"));
    }

    // `<hash>.pub` is what nginx serves at /<hash>/hu/<hash>.
    let key_path = dir.join(format!("{}.pub", body.hash));
    let tmp_path = dir.join(format!("{}.pub.tmp", body.hash));
    if let Err(e) = fs::write(&tmp_path, &key_bytes) {
        return error(500, "io_error", &format!("Could not write the key: {e}"));
    }
    if let Err(e) = fs::rename(&tmp_path, &key_path) {
        let _ = fs::remove_file(&tmp_path);
        return error(500, "io_error", &format!("Could not publish the key: {e}"));
    }

    let entry = serde_json::json!({
        "email": own_address,
        "fingerprint": body.fingerprint.to_uppercase(),
        "hash": body.hash,
        "updated": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    });
    let _ = fs::write(
        dir.join(format!("{}.json", body.hash)),
        serde_json::to_vec_pretty(&entry).unwrap_or_default(),
    );

    let mut resp = Response::from_data(
        serde_json::to_vec(&MessageResponse {
            message: format!("Published. Your key will be discoverable at /{}/hu/{}", body.hash, body.hash),
        })
        .unwrap(),
    )
    .with_status_code(200);
    resp.add_header(json_header());
    resp
}

/// GET /pgp/wkd/status — has this account published a key, and which one?
pub fn wkd_status(
    _request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };
    let own_address = format!("{}@{}", user.username, user_storage.domain).to_lowercase();

    let dir = wkd_dir();
    let mut found: Option<serde_json::Value> = None;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(raw) = fs::read(&path) {
                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&raw) {
                    if parsed
                        .get("email")
                        .and_then(|v| v.as_str())
                        .map(|e| e == own_address)
                        .unwrap_or(false)
                    {
                        found = Some(parsed);
                    }
                }
            }
        }
    }

    let body = serde_json::json!({
        "published": found.is_some(),
        "email": own_address,
        "fingerprint": found.as_ref().and_then(|v| v.get("fingerprint")).cloned(),
        "hash": found.as_ref().and_then(|v| v.get("hash")).cloned(),
        "updated": found.as_ref().and_then(|v| v.get("updated")).cloned(),
    });

    let mut resp = Response::from_data(serde_json::to_vec(&body).unwrap()).with_status_code(200);
    resp.add_header(json_header());
    resp
}

fn error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&ErrorResponse {
        code: code.to_string(),
        error: message.to_string(),
    })
    .unwrap();
    let mut resp = Response::from_data(body).with_status_code(status);
    resp.add_header(json_header());
    resp
}
