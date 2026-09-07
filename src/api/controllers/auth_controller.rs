use crate::core::{UserStorage, EmailStorage};
use crate::utils::jwt::generate_jwt;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub struct AuthResult {
    pub token: String,
    pub force_reset: bool,
    pub is_admin: bool,
    pub username: String,
    pub public_key: Option<String>,
    pub unread_emails: usize,
    pub salt: String,
    pub encrypted_private_key: Option<String>,
}

pub struct AuthError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl AuthError {
    fn new(status: u16, code: &str, message: &str) -> Self {
        AuthError { status, code: code.to_string(), message: message.to_string() }
    }

    /// The single failure that login is allowed to report.
    ///
    /// Distinguishing "no such user" from "wrong password" turns the login
    /// endpoint into a mailbox enumeration oracle, which on a mail server also
    /// leaks who has an account here.
    fn invalid_credentials() -> Self {
        AuthError::new(401, "invalid_credentials", "Invalid username or password")
    }
}

pub fn authenticate(
    username: &str,
    password: &str,
    user_storage: &UserStorage,
    email_storage: &EmailStorage,
) -> Result<AuthResult, AuthError> {
    let user = match user_storage.get_user(username) {
        Some(u) => u,
        None => return Err(AuthError::invalid_credentials()),
    };

    if !user.verify_password(password) {
        return Err(AuthError::invalid_credentials());
    }

    let token = generate_jwt(username)
        .map_err(|e| AuthError::new(500, "token_error", &e.to_string()))?;
    let force_reset = user.needs_force_reset();
    let public_key = user.publicKey.as_ref().map(|pk| STANDARD.encode(&pk.0));
    let unread_emails = email_storage.count_unread(&user.emailIds);

    let mut updated = user.clone();
    updated.lastLogin = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    user_storage.update_user(updated);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Auth] Failed to persist last-login time for '{}': {}", username, e);
    }

    Ok(AuthResult {
        token,
        force_reset,
        is_admin: user.is_admin,
        username: user.username.clone(),
        public_key,
        unread_emails,
        salt: user.salt.clone(),
        encrypted_private_key: user.encrypted_private_key.clone(),
    })
}
