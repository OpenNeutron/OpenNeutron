pub mod cryptography;
pub mod dkim;
pub mod emailutils;
pub mod jwt;
pub mod mailer;
pub mod timeutils;
pub mod password;
pub mod quota;

pub use cryptography::make_tls_config;
pub use cryptography::Sha256Hash;
pub use dkim::DkimStatus;
pub use dkim::DkimSigner;
pub use timeutils::unix_to_iso;
pub mod pow;

/// Decode a base64 payload the way the send API does. One place, so a stored
/// scheduled message decodes under exactly the rules it was accepted with.
pub fn decode_payload(data: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(data).map_err(|e| format!("invalid base64: {}", e))
}
