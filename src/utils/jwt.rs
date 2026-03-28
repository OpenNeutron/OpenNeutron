use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use jsonwebtoken::errors::Error as JwtError;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::OnceLock;

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
                    return secret.as_bytes().to_vec();
                }
            }
        }
        // Fall back to a random secret for this process run
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        // Use a mix of time+pid for a simple random seed (no crypto dep needed)
        let mut h = DefaultHasher::new();
        SystemTime::now().hash(&mut h);
        std::process::id().hash(&mut h);
        // Stretch to 32 bytes
        let seed = h.finish();
        let mut bytes = Vec::with_capacity(32);
        for i in 0u64..4 {
            bytes.extend_from_slice(&(seed ^ i.wrapping_mul(0x9e3779b97f4a7c15)).to_le_bytes());
        }
        log::warn!("[JWT] No jwt.secret in config - using a random key. Tokens will be invalidated on restart.");
        bytes
    })
}

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
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret()),
        &Validation::new(Algorithm::HS256),
    )
    .map(|data| data.claims)
}
