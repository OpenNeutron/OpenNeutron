//! New-mail notifications, over HTTP.
//!
//! - `GET  /api/push/key`          the VAPID public key to subscribe with
//! - `POST /api/push/subscribe`    register this browser
//! - `POST /api/push/unsubscribe`  stop
//! - `GET  /api/push/status`       how many browsers are registered
//! - `POST /api/push/test`         send one now, so a user can prove it works
//!
//! A subscription is a URL and two keys the browser generates. Nothing here can
//! send mail or read it; the worst a stolen endpoint could do is show a
//! notification, and it cannot even read that.

use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{push, EmailStorage, User, UserStorage};

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn notify(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    out(status, serde_json::to_vec(&json!({ "error": message, "code": code })).unwrap_or_default())
}

pub fn key(
    _request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    match push::public_key() {
        Some(key) => out(200, serde_json::to_vec(&json!({ "key": key })).unwrap_or_default()),
        None => notify(500, "push_unavailable", "Could not prepare a push key"),
    }
}

/// Where browsers actually register for web push, and the shape of the path that
/// proves it. A fixed list is not elegant, but the alternative is letting a
/// signed-in account make this server POST to any host it names.
///
/// Chrome hands out `https://<something>.google.com/fcm/send/<id>`, not the
/// `fcm.googleapis.com` host the documentation suggests, so the check is on the
/// pair (host, path) rather than on a hostname alone.
fn is_push_service(endpoint: &str) -> bool {
    if endpoint.len() > 2000 {
        return false;
    }
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return false;
    };
    let mut parts = rest.splitn(2, '/');
    let host = parts
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = format!("/{}", parts.next().unwrap_or(""));

    let chrome = path.starts_with("/fcm/send/")
        && (host == "fcm.googleapis.com"
            || host == "android.googleapis.com"
            || host.ends_with(".google.com"));
    let firefox = host.ends_with("push.services.mozilla.com") && path.starts_with("/wpush/");
    let apple = host == "web.push.apple.com" || host.ends_with(".push.apple.com");
    let edge = host.ends_with("notify.windows.com");
    chrome || firefox || apple || edge
}

#[derive(Deserialize)]
struct Keys {
    p256dh: String,
    auth: String,
}

#[derive(Deserialize)]
struct SubscribeRequest {
    endpoint: String,
    keys: Keys,
    #[serde(default)]
    ua: String,
}

pub fn subscribe(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let req: SubscribeRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // An endpoint is a URL this server will POST to. Left unchecked, an account
    // could aim that at any host and use us as a caller — so only the push
    // services the browsers actually use are accepted.
    if !is_push_service(&req.endpoint) {
        return notify(400, "invalid_endpoint", "That does not look like a push endpoint");
    }
    // Length is the whole check that matters: every later send seals to these
    // bytes, and a stub key is accepted here, stored, then fails at send time
    // with "bad p256dh: Invalid input length" once per message. Refusing it at
    // subscribe is the only place the subscriber can see the failure.
    match keys_are_usable(&req.keys.p256dh, &req.keys.auth) {
        Ok(()) => {}
        Err(why) => return notify(400, "invalid_keys", why),
    }

    push::save(&user.username, &req.endpoint, &req.keys.p256dh, &req.keys.auth, &req.ua);
    out(200, serde_json::to_vec(&json!({ "message": "Notifications are on" })).unwrap_or_default())
}


/// A P-256 public key is an uncompressed point (65 bytes: `04` + X + Y) and the
/// auth secret is 16 bytes, both base64url without padding.
fn keys_are_usable(p256dh: &str, auth: &str) -> Result<(), &'static str> {
    let point = b64url(p256dh).ok_or("The subscription's public key is not valid base64url")?;
    if point.len() != 65 || point[0] != 4 {
        return Err("The subscription's public key is not a P-256 point");
    }
    let secret = b64url(auth).ok_or("The subscription's auth secret is not valid base64url")?;
    if secret.len() != 16 {
        return Err("The subscription's auth secret is the wrong length");
    }
    Ok(())
}

fn b64url(raw: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    URL_SAFE_NO_PAD.decode(trimmed.trim_end_matches('=')).ok()
}

#[derive(Deserialize)]
struct UnsubscribeRequest {
    endpoint: String,
}

pub fn unsubscribe(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let req: UnsubscribeRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    push::remove(&user.username, &req.endpoint);
    out(200, serde_json::to_vec(&json!({ "message": "Notifications are off" })).unwrap_or_default())
}

pub fn status(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let count = push::count_for(&user.username);
    out(
        200,
        serde_json::to_vec(&json!({
            "subscribed": count > 0,
            "count": count,
            "supported": true,
        }))
        .unwrap_or_default(),
    )
}

/// A test push, sent to this account's own browsers only. Without this nobody
/// can tell "it is broken" from "no mail arrived".
pub fn test(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    if push::count_for(&user.username) == 0 {
        return notify(409, "not_subscribed", "This account has no browser registered for notifications");
    }
    let delivered = push::notify(
        &user.username,
        "Test notification",
        "If you can see this, mail will reach you here too.",
    );
    out(200, serde_json::to_vec(&json!({ "delivered": delivered })).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_vendors_browsers_use() {
        assert!(is_push_service("https://fcm.googleapis.com/fcm/send/abc"));
        assert!(is_push_service("https://updates.push.services.mozilla.com/wpush/v2/xyz"));
        assert!(is_push_service("https://web.push.apple.com/QGx"));
        assert!(is_push_service("https://wns2-par02p.notify.windows.com/w/?token=x"));
        // What Chrome really hands out, and what this deployment saw in the wild.
        assert!(is_push_service("https://jmt17.google.com/fcm/send/fm-o02qkyNg:APA91b"));
    }

    #[test]
    fn refuses_anything_else() {
        assert!(!is_push_service("http://fcm.googleapis.com/fcm/send/abc"));
        assert!(!is_push_service("https://example.com/push"));
        assert!(!is_push_service("https://fcm.googleapis.com.evil.test/push"));
        assert!(!is_push_service("https://jmt17.google.com/not-a-push-path"));
        assert!(!is_push_service("https://updates.push.services.mozilla.com/other"));
        assert!(!is_push_service("https://127.0.0.1/push"));
        assert!(!is_push_service(""));
    }
}
