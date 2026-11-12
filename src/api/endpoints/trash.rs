//! Trash endpoints: move a message to the trash, take it back, list it, empty it.
//!
//! See `core::trash` for why the trash is a sidecar and what "permanent" means here.

use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::{json_header, ErrorResponse, MessageResponse};
use crate::api::request::read_json_body;
use crate::core::{trash, EmailStorage, User, UserStorage};

type Resp = Response<Cursor<Vec<u8>>>;

fn error(status: u16, code: &str, message: &str) -> Resp {
    let body = serde_json::to_vec(&ErrorResponse { error: message.into(), code: code.into() }).unwrap();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn ok<T: Serialize>(value: &T) -> Resp {
    Response::from_data(serde_json::to_vec(value).unwrap()).with_status_code(200).with_header(json_header())
}

#[derive(Deserialize)]
pub struct UidRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    pub uid: u128,
}

#[derive(Serialize)]
struct TrashedResponse {
    message: String,
    uid: u128,
    kind: String,
}

#[derive(Serialize)]
struct TrashItem {
    uid: u128,
    kind: String,
    trashed_at: u64,
    /// Unix time it will be deleted for good.
    deletes_at: u64,
}

#[derive(Serialize)]
struct TrashListResponse {
    items: Vec<TrashItem>,
    retention_days: u64,
}

#[derive(Serialize)]
struct EmptyResponse {
    deleted: usize,
    failed: usize,
}

/// Which of the owner's lists a uid belongs to, if either.
fn kind_of(user: &User, uid: u128) -> Option<&'static str> {
    if user.emailIds.contains(&uid) {
        Some("inbox")
    } else if user.sent_emails.contains(&uid) {
        Some("sent")
    } else {
        None
    }
}

/// POST /email/trash - move one of the caller's messages (received or sent) to the trash.
pub fn trash_email(request: &mut Request, user: Option<User>, _users: Arc<UserStorage>, _mail: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else { return error(401, "unauthorized", "Unauthorized") };
    let req: UidRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(kind) = kind_of(&user, req.uid) else {
        return error(404, "email_not_found", "Email not found");
    };
    if let Err(e) = trash::add(&user.username, req.uid, kind) {
        log::warn!("[Trash] Could not record uid={} for '{}': {}", req.uid, user.username, e);
        return error(500, "trash_failed", "Could not move that to the trash; nothing changed");
    }
    ok(&TrashedResponse { message: "Moved to trash".into(), uid: req.uid, kind: kind.into() })
}

/// POST /email/restore - take a message out of the trash, back to the folder it came from.
pub fn restore_email(request: &mut Request, user: Option<User>, _users: Arc<UserStorage>, _mail: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else { return error(401, "unauthorized", "Unauthorized") };
    let req: UidRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match trash::remove(&user.username, req.uid) {
        Ok(true) => ok(&MessageResponse { message: "Restored".into() }),
        Ok(false) => error(404, "not_in_trash", "That message is not in the trash"),
        Err(e) => {
            log::warn!("[Trash] Could not restore uid={} for '{}': {}", req.uid, user.username, e);
            error(500, "restore_failed", "Could not restore that message; it is still in the trash")
        }
    }
}

/// POST /email/trash/list - the caller's trash, newest first. Only messages that still exist
/// and are still the caller's are listed; a stale record (a timer took the message) is skipped.
pub fn list_trash(_request: &mut Request, user: Option<User>, _users: Arc<UserStorage>, mail: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else { return error(401, "unauthorized", "Unauthorized") };
    let items = trash::list(&user.username)
        .into_iter()
        .filter(|item| kind_of(&user, item.uid).is_some() && mail.emailExists(item.uid))
        .map(|item| TrashItem {
            uid: item.uid,
            kind: item.kind,
            trashed_at: item.trashed_at,
            deletes_at: item.trashed_at.saturating_add(trash::RETENTION_SECONDS),
        })
        .collect();
    ok(&TrashListResponse { items, retention_days: trash::RETENTION_SECONDS / 86_400 })
}

/// POST /email/trash/empty - delete everything in the caller's trash, for good.
pub fn empty_trash(_request: &mut Request, user: Option<User>, users: Arc<UserStorage>, mail: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else { return error(401, "unauthorized", "Unauthorized") };
    let mut deleted = 0;
    let mut failed = 0;
    for item in trash::list(&user.username) {
        if kind_of(&user, item.uid).is_none() {
            // Not the caller's any more (or already gone): drop the record, log nothing.
            let _ = trash::remove(&user.username, item.uid);
            continue;
        }
        if trash::purge(&users, &mail, &user.username, item.uid) {
            deleted += 1;
        } else {
            failed += 1;
        }
    }
    ok(&EmptyResponse { deleted, failed })
}
