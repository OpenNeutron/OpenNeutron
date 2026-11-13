//! Sealed notes over HTTP.
//!
//! Three public-ish pieces and one authenticated:
//! - `POST /api/note/create`  (session)  mint a note from armour the client built
//! - `GET  /api/note?t=…`     (public)   the page: a summary, then a button
//! - `POST /api/note/open`    (public)   hand over the armour, once
//! - `POST /api/note/status`  (session)  sender's view of their notes
//!
//! The page is separate from the open call on purpose. Providers and security
//! scanners fetch links to look at them; if a GET consumed the note, a robot
//! would burn it before the recipient ever saw it. Only the button burns it.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tiny_http::{Header, Request, Response, Method};
use std::io::Cursor;

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{notes, User, UserStorage, EmailStorage};

#[derive(Deserialize)]
struct CreateRequest {
    recipient: String,
    #[serde(default)]
    subject: String,
    /// PGP armour, produced by the sender's browser. Never logged.
    armored: String,
    /// Delete as soon as it is opened. A note is always single-use, so this only
    /// decides whether the *notification* says so.
    #[serde(default)]
    deletes_on_read: bool,
    /// "pgp" (default) seals to the recipient's key; "passphrase" seals to a
    /// phrase the sender shares separately, for recipients without a key.
    #[serde(default)]
    mode: Option<String>,
    /// Seconds until the timer clears it, regardless of opens.
    #[serde(default)]
    expires_in_seconds: Option<u64>,
    /// Attachments, each already encrypted to the same secret as the body. Only
    /// for passphrase notes: the page that can read the body can decrypt them in
    /// the same place, with the same phrase.
    #[serde(default)]
    files: Vec<FileInput>,
}

#[derive(Deserialize)]
struct FileInput {
    name: String,
    armored: String,
    #[serde(default)]
    size: u64,
}

/// Caps that keep one note from becoming a file host: five attachments, and the
/// armour of all of them together under six megabytes.
const MAX_FILES: usize = 5;
const MAX_FILES_ARMOR: usize = 6_000_000;

/// A display name, never a path: separators and control characters removed, and
/// short enough to render in a list.
fn safe_name(raw: &str) -> String {
    // Only the last segment survives: "../evil/x" and "C:\\tmp\\x" both reduce to
    // "x", so nothing here can name a path the recipient's browser would follow.
    let last = raw.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(raw);
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\' && *c != ':')
        .collect();
    let trimmed = cleaned.trim().trim_start_matches('.').trim();
    let name = if trimmed.is_empty() { "attachment" } else { trimmed };
    name.chars().take(80).collect()
}

#[derive(Serialize)]
struct CreateResponse {
    token: String,
    url: String,
    expires_at: Option<u64>,
    deletes_on_read: bool,
    mode: String,
}

#[derive(Deserialize)]
struct OpenRequest {
    token: String,
}

#[derive(Deserialize)]
struct StatusRequest {
    tokens: Vec<String>,
}

#[derive(Serialize)]
struct StatusItem {
    token: String,
    state: String,
    subject: String,
    recipient: String,
    mode: String,
    created_at: u64,
    opened_at: Option<u64>,
    expires_at: Option<u64>,
    revoked_at: Option<u64>,
}

fn json_error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&json!({ "error": message, "code": code })).unwrap_or_default();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn html_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap()
}

fn no_store_header() -> Header {
    Header::from_bytes(&b"Cache-Control"[..], &b"no-store, no-cache, must-revalidate"[..]).unwrap()
}

/// Keeps the token out of any Referer header a link inside the page might set.
fn referrer_header() -> Header {
    Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]).unwrap()
}

fn nosniff_header() -> Header {
    Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap()
}

fn html(body: String, status: u16) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body.into_bytes())
        .with_status_code(status)
        .with_header(html_header())
        .with_header(no_store_header())
        .with_header(referrer_header())
        .with_header(nosniff_header())
}

/// Where the link should point. `server.public_url` wins because the API is
/// reached through a proxy whose Host header is not always the public name.
fn base_url(request: &Request) -> String {
    if let Some(url) = crate::config::get().server.public_url.as_ref() {
        let trimmed = url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    for header in request.headers() {
        if header.field.equiv("Host") {
            let host = header.value.as_str().trim();
            if !host.is_empty() {
                return format!("https://{}", host);
            }
        }
    }
    format!("https://{}", crate::utils::emailutils::get_server_domain())
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Human date for the page. Deliberately UTC and unambiguous.
fn stamp(secs: u64) -> String {
    crate::utils::unix_to_iso(secs)
        .replace('T', " ")
        .chars()
        .take(16)
        .collect::<String>()
        + " UTC"
}

pub fn create(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };

    let req: CreateRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if req.recipient.trim().is_empty() {
        return json_error(400, "missing_recipient", "A sealed note needs a recipient");
    }
    let armored = req.armored.trim();
    if armored.is_empty() {
        return json_error(400, "empty_note", "A sealed note needs an encrypted body");
    }
    if !armored.starts_with("-----BEGIN PGP MESSAGE-----") {
        // Anything else is not armour we can protect: refuse rather than store
        // a body the sender believes is sealed and is not.
        return json_error(400, "not_armored", "The sealed body must be PGP armour");
    }
    if armored.len() > notes::MAX_ARMORED_BYTES {
        return json_error(413, "note_too_large", "A sealed note is a message body, not an attachment");
    }

    let mode = match req.mode.as_deref() {
        None | Some("") | Some("pgp") => "pgp".to_string(),
        Some("passphrase") => "passphrase".to_string(),
        Some(other) => {
            return json_error(400, "bad_mode", &format!("Unknown note mode '{}'", other));
        }
    };

    let now = notes::now();
    let expires_at = match req.expires_in_seconds {
        Some(secs) => {
            let secs = secs.clamp(notes::MIN_EXPIRY_SECONDS, notes::MAX_EXPIRY_SECONDS);
            Some(now + secs)
        }
        None => None,
    };

    // Attachments only travel with a passphrase note: in key mode the page hands
    // the recipient armour for their own client, and asking them to decrypt five
    // more files by hand would be worse than refusing.
    if !req.files.is_empty() && mode != "passphrase" {
        return json_error(
            400,
            "files_need_passphrase",
            "Attachments need the passphrase lock — switch the seal to a passphrase to send files",
        );
    }
    if req.files.len() > MAX_FILES {
        return json_error(400, "too_many_files", &format!("At most {} attachments per note", MAX_FILES));
    }
    let total_armor: usize = req.files.iter().map(|f| f.armored.len()).sum();
    if total_armor > MAX_FILES_ARMOR {
        return json_error(413, "files_too_large", "Those attachments are too large for one note");
    }

    if notes::active_count(user.uid) >= notes::MAX_ACTIVE_PER_SENDER {
        return json_error(429, "too_many_notes", "Too many unopened notes; open or cancel some first");
    }

    let token = notes::new_token();
    let note = notes::Note {
        token: token.clone(),
        owner: user.username.clone(),
        owner_uid: user.uid,
        recipient: req.recipient.trim().to_string(),
        subject: req.subject.clone(),
        mode: mode.clone(),
        fetches: 0,
        armored: armored.to_string(),
        files: req
            .files
            .iter()
            .map(|f| notes::NoteFile {
                name: safe_name(&f.name),
                armored: f.armored.clone(),
                size: f.size,
            })
            .collect(),
        created_at: now,
        expires_at,
        opened_at: None,
        expired_at: None,
        revoked_at: None,
        opens: 0,
        sender_uid: 0,
    };

    if let Err(e) = notes::create(note) {
        log::error!("[Notes] Could not store a note for {}: {}", user.username, e);
        return json_error(500, "store_failed", "Could not store the note");
    }

    let url = format!("{}/api/note?t={}", base_url(request), token);
    let body = serde_json::to_vec(&CreateResponse {
        mode,
        token,
        url,
        expires_at,
        deletes_on_read: req.deletes_on_read,
    })
    .unwrap_or_default();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// The page. Renders the current state without consuming anything.
pub fn page(
    request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let token = match query_param(request.url(), "t") {
        Some(t) if !t.is_empty() => t,
        _ => return html(render_missing(), 404),
    };

    let note = match notes::get(&token) {
        Some(n) => n,
        None => return html(render_missing(), 404),
    };

    if note.is_revoked() {
        return html(render_gone("This note was withdrawn", "The sender took it back before it was read."), 410);
    }
    if note.expired_at.is_some() || (note.is_sealed() && note.is_expired(notes::now())) {
        let when = note.expires_at.map(stamp).unwrap_or_default();
        return html(render_gone("This note expired", &format!("It was closed on {}.", when)), 410);
    }
    if note.opened_at.is_some() {
        let when = note.opened_at.map(stamp).unwrap_or_default();
        return html(render_gone("This note has already been opened", &format!("It was opened on {} and deleted.", when)), 410);
    }

    let expiry = match note.expires_at {
        Some(at) => format!("This note closes on {}.", stamp(at)),
        None => "This note does not expire on its own; opening it deletes it.".to_string(),
    };
    html(render_sealed(&note.subject, &note.owner, &note.recipient, &expiry, &token, &note.mode), 200)
}

pub fn open(
    request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let req: OpenRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match notes::open(&req.token) {
        Ok(notes::Open::Served(note)) => {
            let body = serde_json::to_vec(&json!({
                "armored": note.armored,
                "from": note.owner,
                "subject": note.subject,
                "recipient": note.recipient,
                "created_at": note.created_at,
                "files": note
                    .files
                    .iter()
                    .map(|f| json!({ "name": f.name, "armored": f.armored, "size": f.size }))
                    .collect::<Vec<_>>(),
                "deleted": true,
            }))
            .unwrap_or_default();
            let mut response = Response::from_data(body).with_header(json_header());
            response.add_header(no_store_header());
            response
        }
        Ok(notes::Open::Spent) => json_error(410, "already_opened", "This note has already been opened and deleted"),
        Ok(notes::Open::Expired) => json_error(410, "expired", "This note expired before it was opened"),
        Ok(notes::Open::Missing) => json_error(404, "no_such_note", "There is no note at this address"),
        Err(e) => {
            log::error!("[Notes] Open failed: {}", e);
            json_error(500, "store_failed", "Could not open the note")
        }
    }
}

/// Clear a passphrase note once the recipient has read it. Called by the page
/// after a successful decrypt; harmless if it arrives twice.
pub fn burn(
    request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    #[derive(Deserialize)]
    struct BurnRequest {
        token: String,
    }
    let req: BurnRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match notes::burn(&req.token) {
        Ok(_) => {
            let body = serde_json::to_vec(&json!({ "burned": true })).unwrap_or_default();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        Err(e) => {
            log::error!("[Notes] Burn failed: {}", e);
            json_error(500, "store_failed", "Could not burn the note")
        }
    }
}

/// Withdraw a note. Only the account that created it can, and only before it
/// has been read — after that there is nothing left to withdraw.
pub fn revoke(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    #[derive(Deserialize)]
    struct RevokeRequest {
        token: String,
    }
    let req: RevokeRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match notes::revoke(&req.token, user.uid) {
        Ok(true) => {
            let body = serde_json::to_vec(&json!({ "revoked": true })).unwrap_or_default();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        // Already opened, already revoked, or not the caller's: the same answer,
        // so a caller cannot use this to learn whether a token exists.
        Ok(false) => json_error(409, "not_revocable", "That note is already read, withdrawn, or not yours"),
        Err(e) => {
            log::error!("[Notes] Revoke failed: {}", e);
            json_error(500, "store_failed", "Could not withdraw the note")
        }
    }
}

pub fn status(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    let req: StatusRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if req.tokens.len() > 200 {
        return json_error(400, "too_many", "Ask about at most 200 notes at a time");
    }

    let items: Vec<StatusItem> = notes::statuses(user.uid, &req.tokens)
        .into_iter()
        .map(|n| StatusItem {
            state: n.state().to_string(),
            token: n.token,
            subject: n.subject,
            recipient: n.recipient,
            mode: n.mode,
            created_at: n.created_at,
            opened_at: n.opened_at,
            expires_at: n.expires_at,
            revoked_at: n.revoked_at,
        })
        .collect();

    let body = serde_json::to_vec(&json!({ "notes": items })).unwrap_or_default();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

// ---- page rendering -------------------------------------------------------

const PAGE_CSS: &str = r#"
/* The sealed note is the only page a stranger ever sees, and it was the last
   place still wearing a different palette: neon mint on a green-black gradient,
   nothing like the app it belongs to. These are the app's own values, written
   out because this page ships without the stylesheet that declares them. */
:root {
  color-scheme: dark;
  --ink-1: #e9eee0; --ink-2: #b6c2ab; --ink-3: #98a68e;
  --line: #232b1d; --line-strong: #2f3927;
  --card: #161c15; --field: #0e130d; --primary: #86bf6a; --sand: #c8a17a;
  --serif: ui-serif, "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100dvh; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 18px;
  padding: 24px 18px calc(24px + env(safe-area-inset-bottom));
  background: linear-gradient(180deg, #131913 0%, #0d120c 62%, #0a0e0a 100%);
  color: var(--ink-1); font: 15px/1.55 var(--sans);
  -webkit-font-smoothing: antialiased;
}
.wrap { width: 100%; max-width: 540px; }
.brand {
  display: flex; align-items: center; gap: 9px; padding: 0 2px 12px;
}
.brand .mark { width: 22px; height: 22px; flex: none; }
.brand .name {
  font: 550 11.5px/1 var(--sans); letter-spacing: .14em; text-transform: uppercase;
  color: var(--ink-3);
}
.brand .tag {
  margin-left: auto; font: 500 10.5px/1 var(--mono); letter-spacing: .1em;
  text-transform: uppercase; color: var(--ink-4);
}
.card {
  background: var(--card); border: 1px solid var(--line); border-radius: 16px;
  padding: 26px 24px; box-shadow: 0 18px 50px rgba(0,0,0,.45);
}
.seal {
  width: 40px; height: 40px; border-radius: 10px; display: grid; place-items: center;
  background: #1b2318; border: 1px solid var(--line-strong); margin-bottom: 18px;
  color: var(--sand);
}
.seal svg { width: 19px; height: 19px; }
h1 {
  font: 500 26px/1.22 var(--serif); letter-spacing: -.015em; margin: 0 0 8px;
  color: var(--ink-1); text-wrap: balance;
}
.sub { color: var(--ink-3); font-size: 13.5px; margin: 0 0 20px; max-width: 44ch; }
.label {
  display: block; font: 550 11px/1 var(--sans); letter-spacing: .11em;
  text-transform: uppercase; color: var(--ink-3); margin: 0 0 8px;
}
button {
  width: 100%; min-height: 46px; padding: 12px 16px;
  font: 600 14.5px/1.2 var(--sans); color: #0d1309;
  background: var(--primary); border: 1px solid transparent; border-radius: 10px;
  cursor: pointer; transition: transform .12s ease, filter .12s ease;
}
button:hover { filter: brightness(1.05); }
button:active { transform: scale(.99); }
button:disabled { opacity: .55; cursor: default; }
button.ghost {
  background: transparent; color: var(--ink-2);
  border: 1px solid var(--line-strong);
}
button.ghost:hover { background: #1b2318; color: var(--ink-1); }
input[type=password], input[type=text] {
  width: 100%; min-height: 46px; padding: 12px 14px;
  font: 15px/1.2 var(--sans); color: var(--ink-1);
  background: var(--field); border: 1px solid #27301f; border-radius: 10px;
  margin-bottom: 12px; outline: none;
  transition: border-color .12s ease;
}
input[type=password]:focus, input[type=text]:focus {
  border-color: var(--primary); box-shadow: 0 0 0 3px rgba(134,191,106,.13);
}
.row { display: flex; gap: 10px; }
.row button { flex: 1; }
pre {
  white-space: pre-wrap; word-break: break-all; margin: 0 0 14px;
  background: var(--field); border: 1px solid var(--line); border-radius: 10px;
  padding: 14px; font: 11.5px/1.5 var(--mono); color: var(--ink-2);
  max-height: 46vh; overflow: auto;
}
/* The note itself is the only long-form text on the page: serif, at a measure
   a person can actually read. */
.note {
  font: 400 16.5px/1.68 var(--serif); color: var(--ink-1);
  white-space: pre-wrap; word-break: break-word; margin: 0 0 4px;
  max-height: 56vh; overflow: auto;
}
.meta {
  font: 11px/1.5 var(--mono); letter-spacing: .04em; color: var(--ink-4);
  border-top: 1px solid var(--line); padding-top: 13px; margin-top: 20px;
}
.meta b { color: var(--ink-2); font-weight: 500; }
.warn { color: var(--sand); font-size: 12.5px; margin: 12px 0 0; }
.err { color: #e0593f; font-size: 12.5px; margin: 12px 0 0; }
.gone { color: var(--ink-3); }
a { color: var(--primary); text-underline-offset: 2px; }
.foot {
  padding: 2px 2px 0; font: 11px/1.5 var(--mono); color: var(--ink-4);
  text-align: center; letter-spacing: .03em;
}
/* Opening the note is the one moment on this page worth moving: the form gives
   way and the text arrives, rather than the page blinking. */
@keyframes rise {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: none; }
}
#out:not([hidden]), .card > .note { animation: rise .42s cubic-bezier(.2,.7,.2,1) both; }
@media (prefers-reduced-motion: reduce) {
  *, #out:not([hidden]) { animation: none !important; transition: none !important; }
}
@media (max-width: 420px) {
  .card { padding: 22px 18px; border-radius: 14px; }
  h1 { font-size: 22px; }
  body { padding: 16px 12px 24px; justify-content: flex-start; }
}
"#;

/// The mark, byte for byte the one the app draws (SlothMark.jsx), and the lock
/// that sits above the headline. Both are inline: this page carries no assets.
const MARK: &str = r##"<svg class="mark" viewBox="0 0 24 24" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="fur" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#c8a17a"/><stop offset="1" stop-color="#a97f57"/></linearGradient></defs><circle cx="12" cy="12" r="11" fill="url(#fur)"/><path d="M12 5.2c3.9 0 6.6 2.9 6.6 6.9 0 4.3-2.9 7-6.6 7s-6.6-2.7-6.6-7c0-4 2.7-6.9 6.6-6.9Z" fill="#f4ead6"/><ellipse cx="8.6" cy="10.9" rx="2.7" ry="2.3" fill="#5c4632" transform="rotate(-14 8.6 10.9)"/><ellipse cx="15.4" cy="10.9" rx="2.7" ry="2.3" fill="#5c4632" transform="rotate(14 15.4 10.9)"/><circle cx="9.1" cy="11.1" r="0.95" fill="#10120f"/><circle cx="14.9" cy="11.1" r="0.95" fill="#10120f"/><ellipse cx="12" cy="14.9" rx="1.6" ry="1.15" fill="#5c4632"/></svg>"##;

const LOCK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="10.5" width="16" height="9.5" rx="2.5"/><path d="M8 10.5V7.6a4 4 0 0 1 8 0v2.9"/></svg>"##;

fn shell(title: &str, inner: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\
         <meta name=\"robots\" content=\"noindex, nofollow\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <meta name=\"theme-color\" content=\"#10150f\">\
         <title>{}</title><style>{}</style></head><body>\
         <div class=\"wrap\">\
           <div class=\"brand\">{}<span class=\"name\">Sloth Lee</span>\
             <span class=\"tag\">sealed note</span></div>\
           <div class=\"card\">{}</div>\
         </div></body></html>",
        escape(title),
        PAGE_CSS,
        MARK,
        inner
    )
}

fn render_missing() -> String {
    let inner = format!(
        r#"<div class="seal">{}</div><h1>There is no note at this address</h1><p class="sub gone">The link may be mistyped, or the note may have been deleted after it was read.</p>"#,
        LOCK
    );
    shell("No such note", &inner)
}

fn render_gone(headline: &str, detail: &str) -> String {
    let inner = format!(
        r#"<div class="seal">{}</div><h1>{}</h1><p class="sub gone">{}</p><div class="meta">Nothing is stored on the server: the content was deleted when the note was closed.</div>"#,
        LOCK, escape(headline), escape(detail)
    );
    shell(headline, &inner)
}

/// Shared script: the open call, minus what each mode does with the armour.
const OPEN_JS: &str = r#"
async function fetchNote() {
  const r = await fetch('/api/note/open', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: '__TOKEN__' }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || 'Could not open the note');
  return d;
}
"#;

/// Key mode: the recipient already has a private key, so hand over the armour
/// and get out of the way — with a file they can hand to their PGP app.
const PGP_JS: &str = r#"
const btn = document.getElementById('reveal');
btn.addEventListener('click', async () => {
  btn.disabled = true; btn.textContent = 'Opening…';
  try {
    const d = await fetchNote();
    const armor = d.armored;
    document.getElementById('armor').textContent = armor;
    document.getElementById('out').hidden = false;
    btn.remove();
    document.getElementById('copy').addEventListener('click', async () => {
      const el = document.getElementById('copy');
      try { await navigator.clipboard.writeText(armor); el.textContent = 'Copied'; }
      catch (e) { el.textContent = 'Select the text and copy'; }
    });
    document.getElementById('save').addEventListener('click', () => {
      const blob = new Blob([armor], { type: 'application/pgp-encrypted' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'sealed-note.asc';
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    });
  } catch (e) {
    btn.disabled = false; btn.textContent = 'Try again';
    document.getElementById('msg').textContent = e.message;
  }
});
"#;

/// Passphrase mode: no key, no client — one field and the note is readable on
/// any device. The armour stays on the server until the phrase is right, so a
/// typo costs nothing, and is burned the moment the text appears.
const PASS_JS: &str = r#"
const btn = document.getElementById('reveal');
const phrase = document.getElementById('phrase');
// A button that refuses to work on an empty field is clearer than one that
// answers "type the passphrase" after the click.
const sync = () => { btn.disabled = (phrase.value || '').trim().length < 4; };
phrase.addEventListener('input', sync);
sync();
btn.addEventListener('click', async () => {
  const pass = (phrase.value || '').trim();
  const msg = document.getElementById('msg');
  if (pass.length < 4) { msg.textContent = 'Type the passphrase you were given.'; return; }
  btn.disabled = true; btn.textContent = 'Opening…';
  try {
    const d = await fetchNote();
    let text;
    try {
      const message = await openpgp.readMessage({ armoredMessage: d.armored });
      const out = await openpgp.decrypt({ message, passwords: [pass] });
      text = out.data;
    } catch (e) {
      btn.disabled = false; btn.textContent = 'Read the note';
      msg.textContent = 'That is not the passphrase — check it and try again. The note is still here.';
      return;
    }
    document.getElementById('text').textContent = text;
    document.getElementById('out').hidden = false;
    document.getElementById('form').hidden = true;

    // Attachments came in the same response, encrypted to the same phrase. The
    // bytes are already here, so nothing is fetched after this: the note is
    // burned below and the page still holds everything it needs.
    const files = d.files || [];
    if (files.length) {
      const box = document.getElementById('files');
      const heading = document.createElement('p');
      heading.className = 'label';
      heading.textContent = files.length === 1 ? 'Attachment' : 'Attachments';
      box.appendChild(heading);
      for (const f of files) {
        const btn = document.createElement('button');
        const kb = f.size ? ' (' + Math.max(1, Math.round(f.size / 1024)) + ' KB)' : '';
        btn.textContent = 'Download ' + f.name + kb;
        btn.className = 'ghost file';
        btn.addEventListener('click', async () => {
          const label = btn.textContent;
          btn.disabled = true;
          btn.textContent = 'Opening…';
          try {
            const m = await openpgp.readMessage({ armoredMessage: f.armored });
            const out = await openpgp.decrypt({ message: m, passwords: [pass], format: 'binary' });
            const blob = new Blob([out.data], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = f.name;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 60000);
            btn.textContent = 'Saved';
          } catch (e) {
            btn.disabled = false;
            btn.textContent = label;
            document.getElementById('msg').textContent = 'That file could not be opened: ' + e.message;
          }
        });
        box.appendChild(btn);
      }
    }
    fetch('/api/note/burn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: '__TOKEN__' }),
    });
  } catch (e) {
    btn.disabled = false; btn.textContent = 'Try again';
    msg.textContent = e.message;
  }
});
"#;

fn render_sealed(subject: &str, from: &str, to: &str, expiry: &str, token: &str, mode: &str) -> String {
    let subject_line = if subject.trim().is_empty() {
        "A sealed note".to_string()
    } else {
        subject.trim().to_string()
    };
    let token_js = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".to_string());
    let script = if mode == "passphrase" { PASS_JS } else { PGP_JS };
    let script = format!("{}\n{}", OPEN_JS, script).replace("__TOKEN__", token_js.trim_matches('"'));

    let form = if mode == "passphrase" {
        r#"<div id="form">
             <label class="label" for="phrase">Passphrase</label>
             <input id="phrase" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="The phrase the sender gave you">
             <button id="reveal">Read the note</button>
             <p class="warn">The phrase travels separately from this email — ask the sender if you do not have it.</p>
           </div>"#
    } else {
        r#"<button id="reveal">Open the note</button>"#
    };

    let out = if mode == "passphrase" {
        r#"<div id="out" hidden>
             <div id="text" class="note"></div>
             <div id="files"></div>
             <p class="warn">Read it now, or download anything attached: this note has been deleted from the server.</p>
           </div>
           <p class="err" id="msg"></p>"#
    } else {
        r#"<div id="out" hidden>
             <pre id="armor"></pre>
             <div class="row"><button id="copy">Copy</button><button id="save" class="ghost">Download .asc</button></div>
             <p class="warn">OpenPGP armour for your key. Your mail client may open the .asc directly; otherwise <code>gpg --decrypt</code> does it.</p>
           </div>
           <p class="err" id="msg"></p>"#
    };

    let lede = if mode == "passphrase" {
        format!("A sealed note from <b>{}</b>, locked with a passphrase this server never sees.", escape(from))
    } else {
        format!("A sealed note from <b>{}</b>, encrypted to your key. This server cannot read it.", escape(from))
    };

    let lib = if mode == "passphrase" {
        r#"<script src="/openpgp.min.js"></script>"#
    } else {
        ""
    };

    let inner = format!(
        r#"<div class="seal">{lock}</div>
           <h1>{subject}</h1>
           <p class="sub">{lede}</p>
           {form}
           <div class="meta">
             <div>To <b>{to}</b></div>
             <div>{expiry}</div>
           </div>
           {out}
           {lib}
           <script>{script}</script>"#,
        lock = LOCK,
        subject = escape(&subject_line),
        lede = lede,
        form = form,
        to = escape(to),
        expiry = escape(expiry),
        out = out,
        lib = lib,
        script = script,
    );
    shell(&subject_line, &inner)
}

/// The page is also reachable with HEAD, so a scanner sees the same status code
/// without a body. Registered separately in `main.rs`.
pub fn page_head(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let _ = Method::Get;
    let response = page(request, user, user_storage, email_storage);
    let status = response.status_code().0;
    Response::from_data(Vec::new()).with_status_code(status)
}

#[allow(dead_code)]
fn _assert_value_is_used(_: Value) {}
