//! Per-account outbound send quota.
//!
//! OpenNeutron delivers outbound mail by resolving the recipient's MX itself, so
//! there is no relay that can apply a rate limit. Without a limiter inside the
//! app, one compromised password turns this host into a spam source and the IP
//! (and domain reputation) is destroyed for every other user.
//!
//! Two windows are enforced per account:
//!   * a per-minute burst cap, so a script cannot fire hundreds of messages at once
//!   * an hourly cap, which is what actually bounds abuse
//!
//! Counting is in-process. A restart clears the counters - acceptable, because the
//! hourly cap exists to bound sustained abuse, not to be an accounting ledger.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum sends in a rolling hour, per account.
const MAX_PER_HOUR: usize = 50;
/// Maximum sends in a rolling minute, per account.
const MAX_PER_MINUTE: usize = 10;
/// Window used for the hourly cap.
const WINDOW: Duration = Duration::from_secs(3600);
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Bucket {
    hits: Vec<Instant>,
}

/// `Option<HashMap>` so the map can be created lazily inside a const-initialised
/// Mutex.
static LIMITER: Mutex<Option<HashMap<String, Bucket>>> = Mutex::new(None);

/// Record an attempt for `user`, or reject it.
///
/// Returns `Err(retry_after_seconds)` when the account is over quota. Only
/// successful admissions are recorded, so a rejected attempt does not extend the
/// window and lock the user out further.
pub fn check_and_record(user: &str) -> Result<(), u64> {
    let now = Instant::now();
    let mut guard = match LIMITER.lock() {
        Ok(g) => g,
        // A poisoned lock must not take the mail server down: fail open on the
        // limiter rather than break sending entirely.
        Err(poisoned) => poisoned.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);

    let bucket = map.entry(user.to_string()).or_default();
    bucket.hits.retain(|t| now.duration_since(*t) < WINDOW);

    let last_minute = bucket
        .hits
        .iter()
        .filter(|t| now.duration_since(**t) < MINUTE)
        .count();

    if last_minute >= MAX_PER_MINUTE {
        return Err(MINUTE.as_secs());
    }
    if bucket.hits.len() >= MAX_PER_HOUR {
        return Err(WINDOW.as_secs());
    }

    bucket.hits.push(now);
    Ok(())
}

/// How many sends `user` has made inside the current hour. Used by diagnostics.
pub fn used_in_window(user: &str) -> usize {
    let now = Instant::now();
    match LIMITER.lock() {
        Ok(guard) => guard
            .as_ref()
            .and_then(|m| m.get(user))
            .map(|b| b.hits.iter().filter(|t| now.duration_since(**t) < WINDOW).count())
            .unwrap_or(0),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_up_to_the_minute_cap_then_refuses() {
        let user = "quota-test-minute";
        for i in 0..MAX_PER_MINUTE {
            assert!(check_and_record(user).is_ok(), "send {} should be admitted", i);
        }
        assert_eq!(
            check_and_record(user),
            Err(MINUTE.as_secs()),
            "the cap must refuse once reached"
        );
    }

    #[test]
    fn a_refused_send_does_not_consume_quota() {
        let user = "quota-test-refusal";
        for _ in 0..MAX_PER_MINUTE {
            let _ = check_and_record(user);
        }
        let before = used_in_window(user);
        let _ = check_and_record(user);
        assert_eq!(before, used_in_window(user), "a refusal must not add a hit");
    }

    #[test]
    fn accounts_are_limited_independently() {
        let a = "quota-test-a";
        let b = "quota-test-b";
        for _ in 0..MAX_PER_MINUTE {
            let _ = check_and_record(a);
        }
        assert!(check_and_record(a).is_err());
        assert!(check_and_record(b).is_ok(), "one account must not throttle another");
    }
}
