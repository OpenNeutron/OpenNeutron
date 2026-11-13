//! Scheduled send, over HTTP.
//!
//! - `GET  /api/scheduled`         what this account has waiting, and when
//! - `POST /api/scheduled/cancel`  withdraw one before it goes
//!
//! A scheduled message is created by `POST /email/send` with `send_at` set: the
//! message is stored as the client built it and released by the sweeper, which
//! uses the same signing and MX path as an immediate send.

use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{scheduled, User, UserStorage, EmailStorage};

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn notify(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    out(status, serde_json::to_vec(&json!({ "error": message, "code": code })).unwrap_or_default())
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
    let rows = scheduled::list(&user.username);
    out(
        200,
        serde_json::to_vec(&json!({
            "items": rows,
            "now": scheduled::now(),
            "limit": scheduled::MAX_PENDING_PER_OWNER,
        }))
        .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
pub struct CancelRequest {
    pub id: String,
}

pub fn cancel(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let req: CancelRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match scheduled::cancel(&user.username, &req.id) {
        Ok(true) => out(200, serde_json::to_vec(&json!({ "cancelled": true })).unwrap_or_default()),
        // Already gone out, already cancelled, or not the caller's: one answer for
        // all three, so this cannot be used to probe for message ids.
        Ok(false) => notify(409, "not_cancellable", "That message has already gone, or is not yours"),
        Err(e) => {
            log::error!("[Scheduled] cancel failed: {}", e);
            notify(500, "store_failed", "Could not cancel that message")
        }
    }
}
