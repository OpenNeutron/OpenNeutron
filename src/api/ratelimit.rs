use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

/// Failure budget for a single account. Tight, because only one person should
/// ever be typing this account's password.
pub const MAX_ACCOUNT_FAILURES: usize = 10;

/// Failure budget for a source address. Deliberately much larger: many
/// legitimate users can share one address behind NAT or a corporate proxy, and
/// locking that address out would take all of them offline at once. It still
/// bounds a single host spraying passwords across many accounts.
pub const MAX_ADDRESS_FAILURES: usize = 100;

/// Sliding window over which failures are counted.
const WINDOW: Duration = Duration::from_secs(900); // 15 minutes

/// Stop the table itself from becoming a memory-exhaustion vector: an attacker
/// can otherwise mint an unbounded number of distinct keys by varying usernames.
const MAX_TRACKED_KEYS: usize = 20_000;

static FAILURES: Lazy<Mutex<HashMap<String, Vec<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn prune(entries: &mut Vec<Instant>, now: Instant) {
    entries.retain(|t| now.duration_since(*t) < WINDOW);
}

/// True when this key has exhausted its attempt budget and must be refused
/// without the credentials even being examined.
pub fn is_locked_out(key: &str, max_failures: usize) -> bool {
    let now = Instant::now();
    let mut map = match FAILURES.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    match map.get_mut(key) {
        Some(entries) => {
            prune(entries, now);
            entries.len() >= max_failures
        }
        None => false,
    }
}

/// Record a failed attempt against this key.
pub fn record_failure(key: &str) {
    let now = Instant::now();
    let mut map = match FAILURES.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };

    if map.len() >= MAX_TRACKED_KEYS && !map.contains_key(key) {
        map.retain(|_, entries| {
            prune(entries, now);
            !entries.is_empty()
        });
        if map.len() >= MAX_TRACKED_KEYS {
            // Still saturated - the lockouts already in force are the useful ones,
            // so drop this new key rather than growing without bound.
            return;
        }
    }

    let entries = map.entry(key.to_string()).or_default();
    prune(entries, now);
    entries.push(now);
}

/// Clear a key's history after a successful authentication.
pub fn record_success(key: &str) {
    let mut map = match FAILURES.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.remove(key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_after_the_configured_number_of_failures() {
        let key = "test-key-lockout";
        record_success(key);
        for _ in 0..MAX_ACCOUNT_FAILURES - 1 {
            record_failure(key);
            assert!(!is_locked_out(key, MAX_ACCOUNT_FAILURES));
        }
        record_failure(key);
        assert!(is_locked_out(key, MAX_ACCOUNT_FAILURES));
        record_success(key);
        assert!(!is_locked_out(key, MAX_ACCOUNT_FAILURES));
    }

    #[test]
    fn an_address_gets_a_larger_budget_than_an_account() {
        let key = "test-key-budgets";
        record_success(key);
        for _ in 0..MAX_ACCOUNT_FAILURES {
            record_failure(key);
        }
        assert!(is_locked_out(key, MAX_ACCOUNT_FAILURES));
        assert!(
            !is_locked_out(key, MAX_ADDRESS_FAILURES),
            "one account's failures should not lock out a shared source address"
        );
        record_success(key);
    }
}
