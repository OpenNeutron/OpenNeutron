//! Where a session is signed in from.
//!
//! The session registry has always stored the address; showing "Firefox on Windows"
//! with no place attached made seven rows look like seven of the same thing. Country
//! comes from a local MaxMind-format database (DB-IP Lite), so an address is never
//! handed to a third-party lookup service to answer a question about where someone
//! signed in.
//!
//! Missing database is not an error: the rows simply carry no country, which is the
//! truth. `data/geoip.mmdb` is refreshed by `mail-geoip-update.sh`.

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::sync::OnceLock;

const DB_PATH: &str = "data/geoip.mmdb";

static READER: OnceLock<Option<Reader<Vec<u8>>>> = OnceLock::new();

fn reader() -> Option<&'static Reader<Vec<u8>>> {
    READER
        .get_or_init(|| match Reader::open_readfile(DB_PATH) {
            Ok(r) => {
                log::info!("geoip: loaded {DB_PATH}");
                Some(r)
            }
            Err(e) => {
                log::warn!("geoip: no database at {DB_PATH} ({e}); session locations will be blank");
                None
            }
        })
        .as_ref()
}

/// ISO 3166-1 alpha-2 code for an address, or `None` when it is private, malformed or
/// simply not in the database.
pub fn country(ip: &str) -> Option<String> {
    let addr: IpAddr = normalise(ip)?.parse().ok()?;
    if !routable(&addr) {
        return None;
    }
    let record: geoip2::Country = reader()?.lookup(addr).ok()?;
    record
        .country
        .and_then(|c| c.iso_code)
        .map(|c| c.to_string())
}

/// The registry stores what the request actually carried, which is sometimes
/// `203.0.113.7` and sometimes a forwarded chain or a masked network
/// (`159.195.130.0/24`). The country belongs to the address either way: for a masked
/// network the network's own start address answers the question.
fn normalise(raw: &str) -> Option<&str> {
    let first = raw.split(',').next()?.trim();
    let addr = first.split('/').next()?.trim();
    let addr = addr.trim_start_matches("::ffff:");
    if addr.is_empty() {
        None
    } else {
        Some(addr)
    }
}

/// Loopback, link-local and RFC 1918 / RFC 4193 space has no country, and asking the
/// database about it only produces noise.
fn routable(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()),
        IpAddr::V6(v6) => {
            let s = v6.to_string();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || s.starts_with("fc")
                || s.starts_with("fd")
                || s.starts_with("fe80"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_loopback_have_no_country() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.9.9", "::1", "fd00::1"] {
            assert_eq!(country(ip), None, "{ip} should not resolve to a country");
        }
    }

    #[test]
    fn garbage_is_not_a_country() {
        assert_eq!(country(""), None);
        assert_eq!(country("not-an-ip"), None);
    }

    #[test]
    fn a_masked_network_or_forwarded_chain_still_has_a_country() {
        // The session registry stores what the request carried: sometimes a masked
        // network, sometimes a forwarded chain.
        assert_eq!(normalise("159.195.130.0/24"), Some("159.195.130.0"));
        assert_eq!(normalise("203.0.113.9, 70.41.3.18"), Some("203.0.113.9"));
        assert_eq!(normalise("::ffff:198.51.100.4"), Some("198.51.100.4"));
        assert_eq!(normalise("   "), None);
    }

    /// Only meaningful with the database present; skips otherwise so the suite stays
    /// runnable on a machine without it.
    #[test]
    fn known_addresses_resolve_when_the_database_is_there() {
        if reader().is_none() {
            return;
        }
        // Documented sample addresses from the MaxMind test data: 81.2.69.142 is GB.
        assert_eq!(country("81.2.69.142").as_deref(), Some("GB"));
        assert_eq!(country("8.8.8.8").as_deref(), Some("US"));
    }
}
