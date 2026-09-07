use crate::core::User;
use crate::utils::dkim::DkimSigner;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use once_cell::sync::OnceCell;
use rand::RngCore;

static DKIM_SIGNER: OnceCell<Arc<DkimSigner>> = OnceCell::new();
static SERVER_DOMAIN: OnceCell<String> = OnceCell::new();

pub fn init_dkim_signer(signer: DkimSigner) {
    let _ = DKIM_SIGNER.set(Arc::new(signer));
}

pub fn get_dkim_signer() -> Option<&'static Arc<DkimSigner>> {
    DKIM_SIGNER.get()
}

pub fn init_server_domain(domain: String) {
    let _ = SERVER_DOMAIN.set(domain);
}

pub fn get_server_domain() -> &'static str {
    SERVER_DOMAIN.get().map(|s| s.as_str()).unwrap_or("localhost")
}

/// Build a per-user email UID.
///
/// The low half carries the send time in its top 32 bits (so UIDs still sort by
/// arrival) and 32 random bits below it. A pure second-resolution timestamp
/// collides whenever a user receives two messages in the same second, and since
/// blobs are stored under '<uid>.bin' a collision silently overwrites the older
/// message.
pub fn generate_email_uid(user: &User) -> u128 {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut entropy = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let nonce = u32::from_be_bytes(entropy) as u64;
    let low = (timestamp << 32) | nonce;
    ((user.uid as u128) << 64) | (low as u128)
}

/// Resolve MX record for a domain. Returns the lowest-priority MX host, or falls
/// back to the domain itself (implicit MX per RFC 5321).
pub fn resolve_mx(domain: &str) -> Option<String> {
    use std::net::UdpSocket;
    use std::time::Duration;

    // A random transaction ID plus a connected socket is the minimum defence
    // against off-path answer spoofing: a fixed ID lets anyone who can guess the
    // source port inject a forged MX pointing mail at a host they control.
    let txid = random_txid();
    let query = build_mx_query(domain, txid);
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    socket.connect(RESOLVER).ok()?;
    socket.send(&query).ok()?;

    let mut buf = [0u8; 4096];
    let len = socket.recv(&mut buf).ok()?;
    if !response_matches_query(&buf[..len], txid) {
        log::warn!("[DNS] Discarded MX response for '{}' that did not match the query", domain);
        return None;
    }
    let records = parse_mx_response(&buf[..len]);

    if records.is_empty() {
        // RFC 5321 s.5: if no MX, try A record (use domain itself)
        Some(domain.to_string())
    } else {
        // Pick lowest priority
        records.into_iter().min_by_key(|(prio, _)| *prio).map(|(_, host)| host)
    }
}

pub(crate) const RESOLVER: &str = "8.8.8.8:53";

pub(crate) fn random_txid() -> u16 {
    let mut bytes = [0u8; 2];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    u16::from_be_bytes(bytes)
}

/// Accept a datagram only if it is a response to the transaction we sent.
pub(crate) fn response_matches_query(data: &[u8], txid: u16) -> bool {
    if data.len() < 12 {
        return false;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let is_response = data[2] & 0x80 != 0;
    id == txid && is_response
}

fn build_mx_query(domain: &str, txid: u16) -> Vec<u8> {
    let mut q = Vec::new();
    // Header: random ID, flags=0x0100 (RD), QDCOUNT=1
    q.extend_from_slice(&txid.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x0F, 0x00, 0x01]); // Type=MX, Class=IN
    q
}

fn parse_mx_response(data: &[u8]) -> Vec<(u16, String)> {
    if data.len() < 12 {
        return vec![];
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return vec![];
    }

    // Skip question section
    let mut pos = 12;
    pos = skip_dns_name(data, pos);
    if pos + 4 > data.len() {
        return vec![];
    }
    pos += 4;

    let mut results = Vec::new();
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }
        pos = skip_dns_name(data, pos);
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 8; // type(2) + class(2) + ttl(4)
        let rdlen = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + rdlen > data.len() {
            break;
        }

        if rtype == 15 && rdlen >= 4 {
            // MX record: 2 bytes priority + name
            let priority = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let name = read_dns_name(data, pos + 2);
            if !name.is_empty() {
                results.push((priority, name));
            }
        }

        pos += rdlen;
    }

    results
}

fn read_dns_name(data: &[u8], mut pos: usize) -> String {
    let mut parts = Vec::new();
    let mut jumps = 0;
    while pos < data.len() {
        let b = data[pos];
        if b == 0 {
            break;
        }
        if b & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                break;
            }
            let offset = ((b as usize & 0x3F) << 8) | data[pos + 1] as usize;
            pos = offset;
            jumps += 1;
            if jumps > 10 {
                break; // guard against loops
            }
            continue;
        }
        let len = b as usize;
        pos += 1;
        if pos + len > data.len() {
            break;
        }
        parts.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    parts.join(".")
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() {
        let b = data[pos];
        if b == 0 {
            return pos + 1;
        }
        if b & 0xC0 == 0xC0 {
            return pos + 2;
        }
        pos += 1 + (b as usize);
    }
    pos
}