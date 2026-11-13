//! One account per source address.
//!
//! Proof of work makes each account cost CPU, but CPU is cheap to rent: a farm
//! can still mint dozens of mailboxes from one machine. Binding a signup to the
//! address that created it makes bulk registration from a single host a
//! one-time event, while ordinary people - one person, one address - never
//! notice.
//!
//! The mapping is a JSON sidecar keyed by address, storing the username that
//! claimed it. Deleting the account releases the address, so an operator is not
//! permanently burned by one mistake.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

#[derive(Default, Serialize, Deserialize)]
struct Claims {
    /// address -> username
    addresses: HashMap<String, String>,
}

fn path() -> PathBuf {
    PathBuf::from("data/signup_ips.json")
}

fn cache() -> &'static Mutex<Option<Claims>> {
    static CELL: OnceLock<Mutex<Option<Claims>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

fn load() -> Claims {
    fs::read_to_string(path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn persist(claims: &Claims) {
    if let Ok(json) = serde_json::to_string_pretty(claims) {
        let _ = fs::write(path(), json);
    }
}

/// Reserve the address for this username.
///
/// An empty address is allowed through: a proxy misconfiguration that drops the
/// header must not lock the whole service, and the operator can see the gap in
/// the log. The same username re-registering is refused earlier, by the
/// username check.
pub fn claim(address: &str, username: &str) -> Result<(), &'static str> {
    let address = address.trim();
    if address.is_empty() {
        log::warn!(
            "[Signup] No client address available for '{}'; per-address limit not applied",
            username
        );
        return Ok(());
    }

    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(_) => return Err("signup_unavailable"),
    };
    if guard.is_none() {
        *guard = Some(load());
    }
    let claims = guard.as_mut().unwrap();

    if let Some(existing) = claims.addresses.get(address) {
        // Same name means a retry of an interrupted signup, not a new account.
        if existing != username {
            return Err("address_already_registered");
        }
        return Ok(());
    }

    claims.addresses.insert(address.to_string(), username.to_string());
    persist(claims);
    Ok(())
}

/// Give the address back when its account is deleted.
pub fn release_for(username: &str) {
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if guard.is_none() {
        *guard = Some(load());
    }
    let claims = guard.as_mut().unwrap();
    let before = claims.addresses.len();
    claims.addresses.retain(|_, name| name != username);
    if claims.addresses.len() != before {
        persist(claims);
    }
}

/// Read the client address nginx recorded, falling back through the chain.
pub fn client_address(headers: &[tiny_http::Header]) -> String {
    let mut real_ip = String::new();
    let mut forwarded = String::new();
    for header in headers {
        let name = header.field.as_str().as_str().to_ascii_lowercase();
        let value = header.value.as_str().trim().to_string();
        if name == "x-real-ip" && real_ip.is_empty() {
            real_ip = value;
        } else if name == "x-forwarded-for" && forwarded.is_empty() {
            // The left-most entry is the original client.
            forwarded = value
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
        }
    }
    if !real_ip.is_empty() {
        real_ip
    } else {
        forwarded
    }
}
