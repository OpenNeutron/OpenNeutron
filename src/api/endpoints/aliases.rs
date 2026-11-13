//! Disposable addresses, over HTTP.
//!
//! - `GET  /api/aliases`         list the caller's addresses
//! - `POST /api/aliases`         create one (generated, or a name they chose)
//! - `POST /api/aliases/disable` switch one off or back on
//! - `POST /api/aliases/delete`  remove it for good
//!
//! Mail to a switched-off address is refused at delivery time, so the address
//! stops working for the sender rather than silently filling a hidden folder.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{aliases, User, UserStorage, EmailStorage};

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn notify(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    out(status, serde_json::to_vec(&json!({ "error": message, "code": code })).unwrap_or_default())
}

#[derive(Serialize)]
struct AliasRow {
    local: String,
    address: String,
    label: String,
    created_at: u64,
    disabled_at: Option<u64>,
    received: u64,
}

fn domain() -> String {
    crate::config::get().server.domain.clone()
}

pub fn list(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let dom = domain();
    let mut rows: Vec<AliasRow> = aliases::list(&user.username)
        .into_iter()
        .map(|(local, a)| AliasRow {
            address: format!("{}@{}", local, dom),
            local,
            label: a.label,
            created_at: a.created_at,
            disabled_at: a.disabled_at,
            received: a.received,
        })
        .collect();
    rows.sort_by_key(|r| r.created_at);
    out(
        200,
        serde_json::to_vec(&json!({
            "aliases": rows,
            "limit": aliases::MAX_PER_ACCOUNT,
            "domain": dom,
        }))
        .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
pub struct CreateRequest {
    /// Optional: a name they picked. Empty means "make me one".
    #[serde(default)]
    pub local: String,
    #[serde(default)]
    pub label: String,
}

pub fn create(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let req: CreateRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // A name is free only if no account and no other alias already answers to
    // it — mail to it must be unambiguous.
    let taken = |candidate: &str| -> bool { user_storage.get_user(candidate).is_some() };

    match aliases::create(&user.username, &req.local, &req.label, taken) {
        Ok(local) => {
            let dom = domain();
            out(
                200,
                serde_json::to_vec(&json!({
                    "local": local,
                    "address": format!("{}@{}", local, dom),
                }))
                .unwrap_or_default(),
            )
        }
        Err(aliases::CreateError::TooMany) => notify(
            409,
            "too_many",
            &format!("You can hold {} addresses at a time. Delete one first.", aliases::MAX_PER_ACCOUNT),
        ),
        Err(aliases::CreateError::Taken) => notify(409, "taken", "That name is already in use"),
        Err(aliases::CreateError::Invalid) => notify(
            400,
            "invalid",
            "Use 3–32 characters: lower-case letters, digits and hyphens, not at either end",
        ),
    }
}

#[derive(Deserialize)]
pub struct OneRequest {
    pub local: String,
    #[serde(default)]
    pub disabled: bool,
}

pub fn disable(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let req: OneRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match aliases::set_disabled(&user.username, &req.local, req.disabled) {
        Ok(true) => out(200, serde_json::to_vec(&json!({ "disabled": req.disabled })).unwrap_or_default()),
        Ok(false) => notify(404, "not_found", "No such address on your account"),
        Err(e) => {
            log::error!("[Aliases] disable failed: {}", e);
            notify(500, "store_failed", "Could not change that address")
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteRequest {
    pub local: String,
}

pub fn delete(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let req: DeleteRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match aliases::delete(&user.username, &req.local) {
        Ok(true) => out(200, serde_json::to_vec(&json!({ "deleted": true })).unwrap_or_default()),
        Ok(false) => notify(404, "not_found", "No such address on your account"),
        Err(e) => {
            log::error!("[Aliases] delete failed: {}", e);
            notify(500, "store_failed", "Could not delete that address")
        }
    }
}
