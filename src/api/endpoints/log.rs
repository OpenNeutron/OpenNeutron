//! Reading the deletion log.
//!
//! The client does the checking: it gets the head, its ML-DSA-65 signature and
//! the tail of the chain, verifies the signature locally and remembers the head
//! it saw. Nothing here is trusted to the server beyond the data itself, which is
//! the point of a tripwire.

use crate::api::dto::json_header;
use crate::core::mailboxlog;
use crate::core::{EmailStorage, User, UserStorage};
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
}

fn json_error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    out(
        status,
        serde_json::to_vec(&serde_json::json!({ "error": message, "code": code })).unwrap_or_default(),
    )
}

/// How much of the chain the client receives. The head commits to the rest.
const TAIL: usize = 25;

pub fn snapshot(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };

    match mailboxlog::snapshot(&user.username, TAIL) {
        Ok(snap) => out(
            200,
            serde_json::to_vec(&serde_json::json!({
                "count": snap.count,
                "head": snap.head,
                "signature": snap.signature,
                "public_key": snap.public_key,
                "entries": snap.entries,
                "tail": TAIL,
            }))
            .unwrap_or_default(),
        ),
        Err(e) => json_error(500, "log_unavailable", &e),
    }
}
