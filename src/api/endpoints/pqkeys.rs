//! Account post-quantum keys.
//!
//! `GET  /api/user/pq-keys` — does this account have one, and what is stored.
//! `POST /api/user/pq-keys` — record the ML-KEM-768 public key and the
//! browser-encrypted private key.
//!
//! The private half arrives already wrapped under the password-derived key, so
//! this server stores ciphertext exactly as it does for the RSA key. It cannot
//! decapsulate anything, which is the whole point.

use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{pqkeys, EmailStorage, User, UserStorage};

#[derive(Deserialize)]
struct SetPqKeysRequest {
    public_key: String,
    encrypted_private_key: String,
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

pub fn get(
    _request: &mut Request,
    user: Option<User>,
    _u: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    match pqkeys::get(&user.username) {
        Some(keys) => out(
            200,
            serde_json::to_vec(&json!({
                "enabled": true,
                "public_key": keys.public_key,
                "encrypted_private_key": keys.encrypted_private_key,
                "created_at": keys.created_at,
            }))
            .unwrap_or_default(),
        ),
        None => out(
            200,
            serde_json::to_vec(&json!({ "enabled": false })).unwrap_or_default(),
        ),
    }
}

pub fn set(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    let req: SetPqKeysRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // A key that only exists for an account the server has no RSA key for would
    // never be used; refuse rather than store something inert.
    if user.publicKey.is_none() {
        return json_error(
            409,
            "no_rsa_key",
            "Finish setting up your encryption keys first",
        );
    }
    if let Err(e) = pqkeys::set(&user.username, &req.public_key, &req.encrypted_private_key) {
        return json_error(400, "invalid_pq_key", &e);
    }
    let _ = user_storage;
    log::info!("[pq] '{}' enabled post-quantum protection", user.username);
    out(
        200,
        serde_json::to_vec(&json!({
            "enabled": true,
            "message": "Post-quantum protection enabled for new mail",
        }))
        .unwrap_or_default(),
    )
}


/// What still sits in the old envelope.
///
/// The server can see which messages are hybrid-sealed and which are not without
/// opening anything: the envelope carries its own version. It cannot re-seal them
/// — that needs the account's private key, which lives in the browser — so this
/// reports the work and the client does it.
pub fn migration(
    _request: &mut Request,
    user: Option<User>,
    _u: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    let enabled = pqkeys::get(&user.username).is_some();

    let mut sealed = 0usize;
    let mut pending: Vec<String> = Vec::new();
    let mut total = 0usize;
    for uid in &user.emailIds {
        let email = match email_storage.read_email(*uid) {
            Ok(e) => e,
            // A dangling uid is not a migration problem; skip it quietly.
            Err(_) => continue,
        };
        total += 1;
        match &email.message_key {
            Some(key) if pqkeys::is_hybrid(key) => sealed += 1,
            // Either an RSA-wrapped key or no key at all: both are weaker than the
            // hybrid envelope and both can be re-sealed by the browser.
            _ => {
                if pending.len() < BATCH {
                    pending.push(uid.to_string());
                }
            }
        }
    }

    out(
        200,
        serde_json::to_vec(&json!({
            "enabled": enabled,
            "total": total,
            "sealed": sealed,
            "pending": total.saturating_sub(sealed),
            "uids": pending,
            "batch": BATCH,
        }))
        .unwrap_or_default(),
    )
}

/// How many messages one call asks the browser to re-seal.
const BATCH: usize = 20;

pub fn remove(
    _request: &mut Request,
    user: Option<User>,
    _u: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    if let Err(e) = pqkeys::remove(&user.username) {
        return json_error(500, "remove_failed", &e);
    }
    log::info!("[pq] '{}' removed post-quantum protection", user.username);
    out(200, serde_json::to_vec(&json!({ "enabled": false })).unwrap_or_default())
}
