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
}

pub fn generate_jwt(username: &str) -> Result<String, JwtError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = Claims {
        sub: username.to_string(),
        iat: now,
        exp: now + JWT_EXPIRY_SECONDS,
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
