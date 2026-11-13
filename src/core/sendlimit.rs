//! Per-account outbound limits.
//!
//! Opening registration to the public means anyone can hold an address on this
//! domain, and one abusive account can get the domain blocklisted for everyone.
//! The mailbox is a shared reputation, so the cost of abuse has to land on the
//! account that causes it before it reaches the receiving side.
//!
//! A JSON sidecar counts sends per account per rolling day. Deliberately
//! simple: a rejected send is far cheaper than a blocklisted domain, and a
//! legitimate user will never come near these numbers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Generous for people, painful for a spam run.
const DAILY_LIMIT: u32 = 200;
/// An account younger than a day is the one a spammer mints in bulk, so it
/// starts with far less rope. Ordinary people send a handful of messages on
/// their first day; a farm hits this wall immediately.
const PROBATION_HOURS: u64 = 24;
const PROBATION_DAILY_LIMIT: u32 = 20;
/// A single message may not fan out to an unbounded recipient list.
const MAX_RECIPIENTS_PER_SEND: usize = 50;

#[derive(Default, Serialize, Deserialize)]
struct Counters {
    /// username -> (unix day, count)
    accounts: HashMap<String, (u64, u32)>,
}

fn path() -> PathBuf {
    PathBuf::from("data/sendcount.json")
}

fn cache() -> &'static Mutex<Option<Counters>> {
    static CELL: OnceLock<Mutex<Option<Counters>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

fn today() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

pub struct Limit {
    pub remaining: u32,
    pub daily_limit: u32,
}

/// Count a send against the account, or refuse it.
pub fn check_and_count(
    username: &str,
    recipients: usize,
    account_created: u64,
) -> Result<Limit, &'static str> {
    if recipients == 0 {
        return Err("no_recipients");
    }
    if recipients > MAX_RECIPIENTS_PER_SEND {
        return Err("too_many_recipients");
    }

    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(_) => return Err("limit_unavailable"),
    };

    if guard.is_none() {
        *guard = Some(
            fs::read_to_string(path())
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
        );
    }
    let counters = guard.as_mut().unwrap();

    let day = today();
    let entry = counters
        .accounts
        .entry(username.to_string())
        .or_insert((day, 0));

    // A new day resets the window; the stored day is what makes it "per day"
    // rather than "since the file was created".
    if entry.0 != day {
        *entry = (day, 0);
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let on_probation = account_created > 0
        && now_secs.saturating_sub(account_created) < PROBATION_HOURS * 3600;
    let limit = if on_probation { PROBATION_DAILY_LIMIT } else { DAILY_LIMIT };

    if entry.1 >= limit {
        return Err("daily_limit_reached");
    }

    entry.1 += 1;
    let remaining = limit.saturating_sub(entry.1);

    // Persist best-effort: a failed write must not block a legitimate send,
    // and an under-count is corrected by the next successful write.
    if let Ok(json) = serde_json::to_string_pretty(counters) {
        let _ = fs::write(path(), json);
    }

    Ok(Limit {
        remaining,
        daily_limit: limit,
    })
}
