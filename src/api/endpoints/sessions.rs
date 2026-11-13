//! Session management: list the devices signed in, revoke one, or all.
//!
//! The id is the only handle the client has; it is never the token itself.

use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User, sessions};
use crate::api::dto::{ErrorResponse, json_header};
use crate::api::request::read_json_body;
use crate::utils::jwt::validate_jwt;

type Resp = Response<Cursor<Vec<u8>>>;

fn error(status: u16, code: &str, message: &str) -> Resp {
    let body = serde_json::to_vec(&ErrorResponse { error: message.into(), code: code.into() }).unwrap();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn ok_json(value: serde_json::Value) -> Resp {
    Response::from_data(serde_json::to_vec(&value).unwrap())
        .with_status_code(200)
        .with_header(json_header())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The session id of the caller, read from their own token.
fn caller_sid(request: &Request) -> Option<String> {
    let token = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.to_string().trim_start_matches("Bearer ").trim().to_string())?;
    validate_jwt(&token).ok().and_then(|c| c.sid)
}

/// GET /user/sessions
pub fn list(request: &mut Request, user: Option<User>, _us: Arc<UserStorage>, _es: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let current = caller_sid(request);
    let rows: Vec<serde_json::Value> = sessions::list(&user.username)
        .into_iter()
        .map(|(id, record)| {
            serde_json::json!({
                "id": id,
                "current": current.as_deref() == Some(id.as_str()),
                "user_agent": record.user_agent,
                "ip": record.ip,
                // The country, not the city: a session list needs to answer "is this
                // somewhere I have been", and a city is both less reliable and more
                // than the question needs.
                "country": crate::core::geoip::country(&record.ip),
                "created_at": record.created_at,
                "last_seen_at": record.last_seen_at,
            })
        })
        .collect();
    ok_json(serde_json::json!({ "sessions": rows, "count": rows.len() }))
}

/// POST /user/sessions/revoke  { id }
pub fn revoke(request: &mut Request, user: Option<User>, _us: Arc<UserStorage>, _es: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let Some(id) = body.get("id").and_then(|v| v.as_str()) else {
        return error(400, "invalid_request", "Which session?");
    };
    let current = caller_sid(request);
    if sessions::revoke(&user.username, id) {
        log::warn!("[Sessions] '{}' signed out session {}", user.username, &id[..id.len().min(8)]);
        ok_json(serde_json::json!({
            "message": "Signed out",
            "current": current.as_deref() == Some(id),
        }))
    } else {
        // Unknown id, or one belonging to another account: same answer, so this
        // cannot be used to probe which session ids exist.
        error(404, "not_found", "That session is no longer signed in")
    }
}

/// POST /user/sessions/revoke-all
pub fn revoke_all(_request: &mut Request, user: Option<User>, _us: Arc<UserStorage>, _es: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let removed = sessions::revoke_all(&user.username, now_unix());
    log::warn!("[Sessions] '{}' signed out everywhere ({} sessions)", user.username, removed);
    ok_json(serde_json::json!({
        "message": "Signed out on all devices",
        "revoked": removed,
    }))
}
