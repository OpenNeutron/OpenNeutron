//! Manual-approval waiting list for self-registration.
//!
//! Open registration on a mail server means strangers can claim a mailbox, and
//! with no password recovery yet a lost password costs them the account. Until
//! recovery exists, registration is gated: a visitor requests access with an
//! email address, an operator approves it, and the approval yields a single-use
//! invite code that the signup form must present.
//!
//! State lives in a small JSON file so an operator can inspect it with any tool
//! and it survives restarts without introducing a database.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Deserialize, Serialize};
use tiny_http::{Request, Response};

use crate::api::dto::{json_header, ErrorResponse, MessageResponse};
use crate::api::request::read_json_body;
use crate::core::{EmailStorage, User, UserStorage};

// Matches the app's own relative data dir (see ServerSettings::blobs_dir);
// an absolute "/data" does not exist inside the container and every write failed.
const STORE_PATH: &str = "data/waitlist.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitlistEntry {
    pub email: String,
    #[serde(default)]
    pub note: String,
    pub requested_at: u64,
    /// "pending", "approved" or "used".
    pub status: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub approved_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    entries: HashMap<String, WaitlistEntry>,
}

static STORE: Mutex<Option<Store>> = Mutex::new(None);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load() -> Store {
    std::fs::read_to_string(STORE_PATH)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save(store: &Store) {
    match serde_json::to_string_pretty(store) {
        Ok(text) => {
            if let Err(e) = std::fs::write(STORE_PATH, text) {
                log::warn!("[Waitlist] Failed to persist: {}", e);
            }
        }
        Err(e) => log::warn!("[Waitlist] Failed to serialise: {}", e),
    }
}

/// Run `f` with the loaded store, persisting any change it makes.
fn with_store<T>(f: impl FnOnce(&mut Store) -> T) -> T {
    let mut guard = match STORE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.is_none() {
        *guard = Some(load());
    }
    let store = guard.as_mut().expect("store initialised above");
    let result = f(store);
    save(store);
    result
}

fn looks_like_email(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 5 || value.len() > 254 || value.contains(char::is_whitespace) {
        return false;
    }
    match value.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        }
        None => false,
    }
}

fn new_code() -> String {
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| format!("{:x}", rng.gen_range(0u8..16)))
        .collect()
}

/// Is a code valid, approved and unused? If so, mark it used and report success.
pub fn claim_code(code: &str) -> bool {
    let code = code.trim();
    if code.is_empty() {
        return false;
    }
    with_store(|store| {
        let found = store
            .entries
            .values_mut()
            .find(|e| e.code.as_deref() == Some(code) && e.status == "approved");
        match found {
            Some(entry) => {
                entry.status = "used".into();
                true
            }
            None => false,
        }
    })
}

fn error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&ErrorResponse {
        error: message.into(),
        code: code.into(),
    })
    .unwrap();
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
}

#[derive(Deserialize)]
struct RequestAccessBody {
    email: String,
    #[serde(default)]
    note: String,
}

/// Public: ask for an account.
pub fn request_access(
    request: &mut Request,
    _user: Option<User>,
    _users: Arc<UserStorage>,
    _email: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let body: RequestAccessBody = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let email = body.email.trim().to_lowercase();
    if !looks_like_email(&email) {
        return error(400, "invalid_email", "Enter a valid email address");
    }
    if body.note.len() > 500 {
        return error(400, "note_too_long", "Keep the note under 500 characters");
    }

    let fresh = with_store(|store| {
        // Re-requesting is harmless: it must not reset an approval or a used code.
        let absent = !store.entries.contains_key(&email);
        store.entries.entry(email.clone()).or_insert(WaitlistEntry {
            email: email.clone(),
            note: body.note.trim().to_string(),
            requested_at: now(),
            status: "pending".into(),
            code: None,
            approved_at: 0,
        });
        absent
    });
    log::info!("[Waitlist] Access requested by {}", email);

    // Tell the requester their request landed. Approvals are by hand, so
    // without this the page just... stops, and people assume it failed.
    // Only for genuinely new requests: a refresh must not send a second mail.
    if fresh {
        let subject = "Your request for a Sloth Lee Mail account";
        let body = format!(
            "Hello,\n\n\
             Your request for an account on Sloth Lee Mail has been received.\n\n\
             Accounts are approved by hand, so this can take a little while. If you\n\
             are approved you will get a second email containing a single-use invite\n\
             code; you will not need to request again.\n\n\
             If you did not request this, you can ignore this message.\n\n\
             -- \n\
             Sloth Lee Mail\n\
             https://mail.slothlee.xyz\n",
        );
        match crate::utils::mailer::send_plain(
            "mail@slothlee.xyz",
            &email,
            subject,
            &body,
        ) {
            Ok(()) => log::info!("[Waitlist] Confirmation sent to {}", email),
            Err(e) => log::warn!("[Waitlist] Could not send confirmation to {}: {}", email, e),
        }
    }

    let msg = serde_json::to_vec(&MessageResponse {
        message: "Request received. You will be contacted when it is approved.".into(),
    })
    .unwrap();
    Response::from_data(msg)
        .with_status_code(200)
        .with_header(json_header())
}

#[derive(Serialize)]
struct WaitlistResponse {
    entries: Vec<WaitlistEntry>,
    total: usize,
}

fn require_admin(user: Option<User>) -> Option<Response<Cursor<Vec<u8>>>> {
    match user {
        Some(u) if u.is_admin => None,
        Some(_) => Some(error(403, "forbidden", "Administrator privileges required")),
        None => Some(error(401, "unauthorized", "Unauthorized")),
    }
}

/// Admin: list every request.
pub fn list(
    _request: &mut Request,
    user: Option<User>,
    _users: Arc<UserStorage>,
    _email: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    if let Some(resp) = require_admin(user) {
        return resp;
    }

    let entries: Vec<WaitlistEntry> = with_store(|store| {
        let mut all: Vec<WaitlistEntry> = store.entries.values().cloned().collect();
        all.sort_by(|a, b| b.requested_at.cmp(&a.requested_at));
        all
    });

    let body = serde_json::to_vec(&WaitlistResponse {
        total: entries.len(),
        entries,
    })
    .unwrap();
    Response::from_data(body)
        .with_status_code(200)
        .with_header(json_header())
}

#[derive(Deserialize)]
struct ApproveBody {
    email: String,
}

#[derive(Serialize)]
struct ApproveResponse {
    email: String,
    code: String,
}

/// Admin: approve a request and mint its single-use invite code.
pub fn approve(
    request: &mut Request,
    user: Option<User>,
    _users: Arc<UserStorage>,
    _email: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    if let Some(resp) = require_admin(user) {
        return resp;
    }

    let body: ApproveBody = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let email = body.email.trim().to_lowercase();

    let outcome = with_store(|store| {
        match store.entries.get_mut(&email) {
            None => None,
            Some(entry) => {
                let code = if entry.status == "approved" {
                    entry.code.clone().unwrap_or_else(new_code)
                } else {
                    new_code()
                };
                entry.status = "approved".into();
                entry.code = Some(code.clone());
                entry.approved_at = now();
                Some(code)
            }
        }
    });

    match outcome {
        Some(code) => {
            log::info!("[Waitlist] Approved {}", email);

            // Hand the code over without the operator having to relay it: an
            // approval that only exists in an admin panel is an approval the
            // requester never hears about.
            let subject = "Your Sloth Lee Mail invite code";
            let body_text = format!(
                "Hello,\n\n\
                 Your request for an account on Sloth Lee Mail has been approved.\n\n\
                 Your invite code is:\n\n    {code}\n\n\
                 Create your mailbox here:\n\n    https://mail.slothlee.xyz/signup\n\n\
                 The code creates exactly one account and stops working once used.\n\
                 Keep this email until you have signed up.\n\n\
                 -- \n\
                 Sloth Lee Mail\n",
            );
            match crate::utils::mailer::send_plain("mail@slothlee.xyz", &email, subject, &body_text) {
                Ok(()) => log::info!("[Waitlist] Invite code emailed to {}", email),
                Err(e) => log::warn!("[Waitlist] Could not email invite to {}: {}", email, e),
            }

            let body = serde_json::to_vec(&ApproveResponse { email, code }).unwrap();
            Response::from_data(body)
                .with_status_code(200)
                .with_header(json_header())
        }
        None => error(404, "not_found", "No access request for that address"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_obviously_bad_addresses() {
        for bad in ["", "no-at", "@example.com", "user@localhost", "a b@example.com"] {
            assert!(!looks_like_email(bad), "{} should be rejected", bad);
        }
        assert!(looks_like_email("user@example.com"));
    }

    #[test]
    fn codes_are_unique_and_long() {
        let a = new_code();
        let b = new_code();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
    }
}
