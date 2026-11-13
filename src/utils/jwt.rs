use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use jsonwebtoken::errors::Error as JwtError;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::OnceLock;
use rand::rngs::OsRng;
use rand::RngCore;

const JWT_EXPIRY_SECONDS: usize = 3600;

/// Returns the JWT secret bytes to use for this process lifetime.
/// On first call the secret is resolved from the global config (or a random
/// 32-byte value is generated if no secret is configured) and then cached.
fn jwt_secret() -> &'static [u8] {
    static SECRET: OnceLock<Vec<u8>> = OnceLock::new();
    SECRET.get_or_init(|| {
        // Try to read from global config
        if let Some(jwt_cfg) = &crate::config::get().jwt {
            if let Some(secret) = &jwt_cfg.secret {
                if !secret.is_empty() {
                    if secret.len() < MIN_SECRET_LEN {
                        log::warn!(
                            "[JWT] jwt.secret is only {} bytes - use at least {} random bytes, \
                             otherwise the signing key is brute-forceable and anyone can mint \
                             tokens for any account.",
                            secret.len(),
                            MIN_SECRET_LEN
                        );
                    }
                    return secret.as_bytes().to_vec();
                }
            }
        }
        // Fall back to a cryptographically random per-process secret. This must come
        // from the OS CSPRNG: a secret derived from the clock and the pid is guessable
        // by anyone who can observe either, which would let an attacker forge tokens.
        let mut bytes = vec![0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        log::warn!("[JWT] No jwt.secret in config - using a random key. Tokens will be invalidated on restart.");
        bytes
    })
}

/// HS256 keys shorter than this offer less security than the digest itself.
const MIN_SECRET_LEN: usize = 32;

/// Call once at startup (after 'config::init') to eagerly resolve and log the
/// JWT secret so the random-key warning appears during boot, not on first login.
pub fn init() {
    let _ = jwt_secret();
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
    /// Present only on short-lived login challenges. A full session token has
    /// no scope, so a challenge can never be used as a session token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Session id, so the token can be listed and revoked. Absent on tokens
    /// minted before the registry existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// Secret bytes reused as the master key for password peppering.
///
/// Reusing the JWT secret means the pepper cannot drift out of sync with the
/// configuration: there is exactly one secret to protect and rotate.
pub fn pepper_material() -> Vec<u8> {
    jwt_secret().to_vec()
}

pub fn generate_jwt(username: &str) -> Result<String, JwtError> {
    generate_jwt_with_sid(username, None)
}

/// Session token carrying the id that the registry can revoke.
pub fn generate_jwt_with_sid(username: &str, sid: Option<&str>) -> Result<String, JwtError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = Claims {
        sub: username.to_string(),
        iat: now,
        exp: now + JWT_EXPIRY_SECONDS,
        scope: None,
        sid: sid.map(|s| s.to_string()),
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret()))
}

pub fn validate_jwt(token: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    // Pin the accepted algorithm set to HS256 only and require an expiry, so a
    // token cannot be replayed forever or presented with a swapped 'alg' header.
    validation.algorithms = vec![Algorithm::HS256];
    validation.required_spec_claims = ["exp".to_string()].into_iter().collect();
    validation.leeway = 0;
    decode::<Claims>(token, &DecodingKey::from_secret(jwt_secret()), &validation)
        .map(|data| data.claims)
}

/// Token proving the password step passed, valid only long enough to enter a
/// code. Scoped so it cannot stand in for a session token.
pub fn generate_challenge_jwt(username: &str) -> Result<String, JwtError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = Claims {
        sub: username.to_string(),
        iat: now,
        exp: now + CHALLENGE_EXPIRY_SECONDS,
        scope: Some("mfa".to_string()),
        sid: None,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret()))
}

/// 5 minutes: long enough to open an authenticator app, short enough that a
/// leaked challenge is worthless.
const CHALLENGE_EXPIRY_SECONDS: usize = 300;
