//! Telling the browser that mail has arrived.
//!
//! Web Push is three pieces of cryptography and one HTTP POST, and none of them
//! can be skipped: an ES256 JWT that says which server is asking (VAPID), an
//! ECDH handshake with the browser's own key pair so no push service can read a
//! word of the payload, and a request to an endpoint the browser handed us.
//!
//! The payload carries a sender and a count and nothing else. A notification is
//! drawn on a lock screen, which is a place mail was never meant to be read, so
//! this module deliberately never puts a subject or a body on it.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

static LOCK: Mutex<()> = Mutex::new(());

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------------------------------------------------------------- the store

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sub {
    pub username: String,
    pub endpoint: String,
    /// The browser's public key, base64url, 65-byte uncompressed point.
    pub p256dh: String,
    /// The shared secret the browser generated for this subscription.
    pub auth: String,
    pub created_at: u64,
    #[serde(default)]
    pub ua: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Store {
    #[serde(default)]
    pub subs: BTreeMap<String, Sub>,
}

fn path() -> PathBuf {
    PathBuf::from("data").join("push.json")
}

fn read_store(path: &PathBuf) -> Store {
    match fs::read(path) {
        Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => Store::default(),
    }
}

fn write_store(path: &PathBuf, store: &Store) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_vec(store).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// One subscription per endpoint: the same browser re-subscribing must not stack
/// up duplicate pushes.
fn key_for(username: &str, endpoint: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"push-sub").unwrap();
    mac.update(username.as_bytes());
    mac.update(b"\0");
    mac.update(endpoint.as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..12])
}

pub fn save(username: &str, endpoint: &str, p256dh: &str, auth: &str, ua: &str) {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_store(&path);
    let key = key_for(username, endpoint);
    let created_at = store.subs.get(&key).map(|s| s.created_at).unwrap_or_else(now);
    store.subs.insert(
        key,
        Sub {
            username: username.to_string(),
            endpoint: endpoint.to_string(),
            p256dh: p256dh.to_string(),
            auth: auth.to_string(),
            created_at,
            ua: ua.to_string(),
        },
    );
    if let Err(e) = write_store(&path, &store) {
        log::warn!("[Push] Could not save a subscription: {}", e);
    }
}

pub fn remove(username: &str, endpoint: &str) {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_store(&path);
    let key = key_for(username, endpoint);
    if store.subs.remove(&key).is_some() {
        if let Err(e) = write_store(&path, &store) {
            log::warn!("[Push] Could not remove a subscription: {}", e);
        }
    }
}

pub fn for_user(username: &str) -> Vec<Sub> {
    read_store(&path())
        .subs
        .into_values()
        .filter(|s| s.username.eq_ignore_ascii_case(username))
        .collect()
}

pub fn count_for(username: &str) -> usize {
    for_user(username).len()
}

/// Drop dead subscriptions: a push service answering 404 or 410 means this
/// browser is gone for good, and keeping it would mean pushing into a hole.
fn forget(endpoint: &str) {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_store(&path);
    let before = store.subs.len();
    store.subs.retain(|_, s| s.endpoint != endpoint);
    if store.subs.len() != before {
        let _ = write_store(&path, &store);
    }
}

pub fn purge_user(username: &str) {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_store(&path);
    let before = store.subs.len();
    store.subs.retain(|_, s| !s.username.eq_ignore_ascii_case(username));
    if store.subs.len() != before {
        let _ = write_store(&path, &store);
    }
}

// ---------------------------------------------------------------- VAPID keys

#[derive(Serialize, Deserialize)]
struct VapidKeys {
    /// The private scalar, base64url — 32 bytes.
    private: String,
    /// Uncompressed SEC1 point, base64url — what the browser needs.
    public: String,
    #[serde(default)]
    created_at: u64,
}

fn vapid_path() -> PathBuf {
    PathBuf::from("data").join("vapid.json")
}

fn load_or_make_vapid() -> Option<(SigningKey, String)> {
    let path = vapid_path();
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(keys) = serde_json::from_slice::<VapidKeys>(&bytes) {
            if let Ok(raw) = URL_SAFE_NO_PAD.decode(&keys.private) {
                if let Ok(key) = SigningKey::from_slice(&raw) {
                    return Some((key, keys.public));
                }
            }
            log::warn!("[Push] VAPID keys in {} are unreadable — making new ones", path.display());
        }
    }

    let key = SigningKey::random(&mut rand::rngs::OsRng);
    let raw = key.to_bytes().to_vec();
    let public = key.verifying_key().to_encoded_point(false);
    let public_b64 = URL_SAFE_NO_PAD.encode(public.as_bytes());
    let keys = VapidKeys {
        private: URL_SAFE_NO_PAD.encode(&raw),
        public: public_b64.clone(),
        created_at: now(),
    };
    if let Ok(body) = serde_json::to_vec(&keys) {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        if let Err(e) = fs::write(&path, &body) {
            log::warn!("[Push] Could not store VAPID keys: {}", e);
        }
    }
    log::info!("[Push] Generated a VAPID key pair");
    Some((key, public_b64))
}

/// The public half, for the browser to subscribe with.
pub fn public_key() -> Option<String> {
    load_or_make_vapid().map(|(_, public)| public)
}

// ------------------------------------------------------------ the crypto

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC takes any key length");
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&out);
    prk
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(len);
    let mut block: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("HMAC takes any key length");
        mac.update(&block);
        mac.update(info);
        mac.update(&[counter]);
        block = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(len);
    okm
}

/// RFC 8291 §3.4: encrypt `plaintext` so only that browser can read it.
pub fn encrypt(sub: &Sub, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let ua_public_bytes = URL_SAFE_NO_PAD
        .decode(&sub.p256dh)
        .map_err(|e| format!("bad p256dh: {}", e))?;
    let auth_secret = URL_SAFE_NO_PAD
        .decode(&sub.auth)
        .map_err(|e| format!("bad auth secret: {}", e))?;
    let ua_public = PublicKey::from_sec1_bytes(&ua_public_bytes)
        .map_err(|e| format!("not a P-256 point: {}", e))?;

    let ephemeral = p256::ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng);
    let as_public = ephemeral.public_key().to_encoded_point(false);
    let shared = ephemeral.diffie_hellman(&ua_public);

    // The handshake: the two public keys go into the key derivation, so a shared
    // secret cannot be replayed against a different pair of endpoints.
    let mut info = b"WebPush: info\x00".to_vec();
    info.extend_from_slice(ua_public_bytes.as_slice());
    info.extend_from_slice(as_public.as_bytes());
    let prk = hkdf_extract(&auth_secret, shared.raw_secret_bytes());
    let ikm = hkdf_expand(&prk, &info, 32);

    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    let cek = hkdf_expand(&hkdf_extract(&salt, &ikm), b"Content-Encoding: aes128gcm\x00", 16);
    let nonce = hkdf_expand(&hkdf_extract(&salt, &ikm), b"Content-Encoding: nonce\x00", 12);

    let cipher = Aes128Gcm::new_from_slice(&cek).map_err(|e| format!("cipher: {}", e))?;
    let mut record = plaintext.to_vec();
    // One record, and the last one: 0x02 is the delimiter that says so.
    record.push(0x02);
    let body = cipher
        .encrypt(Nonce::from_slice(&nonce), record.as_slice())
        .map_err(|e| format!("encrypt: {}", e))?;

    // header: salt | rs | idlen | our public key, then the sealed record
    let mut out = Vec::with_capacity(16 + 4 + 1 + 65 + body.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&4096u32.to_be_bytes());
    out.push(as_public.as_bytes().len() as u8);
    out.extend_from_slice(as_public.as_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

// --------------------------------------------------------------- the request

fn origin_of(endpoint: &str) -> String {
    let rest = endpoint.strip_prefix("https://").unwrap_or(endpoint);
    let host = rest.split('/').next().unwrap_or(rest);
    format!("https://{}", host)
}

fn vapid_header(key: &SigningKey, public_b64: &str, endpoint: &str, contact: &str) -> String {
    let header = serde_json::json!({"typ": "JWT", "alg": "ES256"});
    let claims = serde_json::json!({
        "aud": origin_of(endpoint),
        "exp": now() + 12 * 3600,
        "sub": contact,
    });
    let encoded_header = URL_SAFE_NO_PAD.encode(header.to_string());
    let encoded_claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signing_input = format!("{}.{}", encoded_header, encoded_claims);
    let signature: Signature = key.sign(signing_input.as_bytes());
    let token = format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    format!("vapid t={}, k={}", token, public_b64)
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// A single verified HTTPS POST. The push endpoints are the browser vendors'
/// own hosts, so this one does check certificates — unlike the opportunistic
/// STARTTLS used towards stranger mail servers.
fn post_https(endpoint: &str, headers: &[(String, String)], body: &[u8]) -> Result<u16, String> {
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| "endpoint is not https".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        _ => (authority.to_string(), 443),
    };

    let addr = (host.as_str(), port)
        .to_socket_addrs_first()
        .ok_or_else(|| format!("cannot resolve {}", host))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(15))
        .map_err(|e| format!("connect {}: {}", host, e))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).ok();

    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| format!("bad host name {}: {}", host, e))?;
    let conn = rustls::ClientConnection::new(tls_config(), server_name)
        .map_err(|e| format!("tls: {}", e))?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);

    let mut head = format!("POST {} HTTP/1.1\r\nHost: {}\r\n", path, authority);
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\nUser-Agent: SlothLeeMail/1.0\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{}: {}\r\n", name, value));
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).map_err(|e| format!("write: {}", e))?;
    stream.write_all(body).map_err(|e| format!("write body: {}", e))?;
    stream.flush().ok();

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > 16_384 {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            // Push services answer and hang up without a TLS close_notify, which
            // rustls reports as an error even though the status line has already
            // arrived. What matters is whether we got an answer, not how it ended.
            Err(e) => {
                if response.is_empty() {
                    return Err(format!("read: {}", e));
                }
                break;
            }
        }
    }

    let text = String::from_utf8_lossy(&response);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "no status line".to_string())?;
    Ok(status)
}

trait ToSocketAddrsFirst {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr>;
}

impl ToSocketAddrsFirst for (&str, u16) {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok().and_then(|mut it| it.next())
    }
}

fn contact() -> String {
    let domain = crate::utils::emailutils::get_server_domain();
    format!("mailto:admin@{}", domain)
}

/// Push one message to every browser this account registered. Returns how many
/// were delivered; dead subscriptions are dropped on the way.
pub fn notify(username: &str, title: &str, body: &str) -> usize {
    let subs = for_user(username);
    if subs.is_empty() {
        return 0;
    }
    let Some((key, public_b64)) = load_or_make_vapid() else {
        log::warn!("[Push] No VAPID key, cannot push");
        return 0;
    };

    let payload = serde_json::json!({
        "title": title,
        "body": body,
        "tag": "new-mail",
        "url": "/",
    })
    .to_string();

    let mut delivered = 0;
    for sub in subs {
        let sealed = match encrypt(&sub, payload.as_bytes()) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::warn!("[Push] Could not seal a payload: {}", e);
                continue;
            }
        };
        let headers = vec![
            ("Authorization".to_string(), vapid_header(&key, &public_b64, &sub.endpoint, &contact())),
            ("Content-Encoding".to_string(), "aes128gcm".to_string()),
            ("Content-Type".to_string(), "application/octet-stream".to_string()),
            ("TTL".to_string(), "86400".to_string()),
            ("Urgency".to_string(), "normal".to_string()),
        ];
        match post_https(&sub.endpoint, &headers, &sealed) {
            Ok(201) | Ok(200) | Ok(202) => delivered += 1,
            Ok(404) | Ok(410) => {
                log::info!("[Push] Subscription gone ({}), forgetting it", sub.endpoint);
                forget(&sub.endpoint);
            }
            Ok(status) => log::warn!("[Push] Push service said {} for {}", status, sub.endpoint),
            Err(e) => log::warn!("[Push] Push failed: {}", e),
        }
    }
    delivered
}

/// Push on its own thread: delivery to a mailbox must never wait on somebody
/// else's push service.
pub fn notify_async(username: &str, title: &str, body: &str) {
    let username = username.to_string();
    let title = title.to_string();
    let body = body.to_string();
    std::thread::spawn(move || {
        notify(&username, &title, &body);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_expand_matches_a_longer_output() {
        let prk = hkdf_extract(b"salt", b"input key material");
        let a = hkdf_expand(&prk, b"info", 16);
        let b = hkdf_expand(&prk, b"info", 32);
        assert_eq!(a, b[..16]);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn origin_is_the_host_not_the_path() {
        assert_eq!(
            origin_of("https://fcm.googleapis.com/wp/abc123"),
            "https://fcm.googleapis.com"
        );
    }

    #[test]
    fn the_key_is_stable_and_a_point() {
        let first = public_key().expect("a key");
        let second = public_key().expect("a key");
        assert_eq!(first, second);
        let raw = URL_SAFE_NO_PAD.decode(&first).unwrap();
        assert_eq!(raw.len(), 65);
        assert_eq!(raw[0], 4);
    }
}
