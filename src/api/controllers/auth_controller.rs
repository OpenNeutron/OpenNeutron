use crate::core::{UserStorage, EmailStorage};
use crate::utils::jwt::generate_jwt;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub struct AuthResult {
    pub token: String,
    pub force_reset: bool,
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
}


pub fn authenticate(
    username: &str,
    password: &str,
    user_storage: &UserStorage,
    email_storage: &EmailStorage,
) -> Result<AuthResult, AuthError> {
    let user = user_storage
        .get_user(username)
        .ok_or_else(|| AuthError::new(404, "user_not_found", "User not found"))?;

    if !user.verify_password(password.to_string()) {
        return Err(AuthError::new(401, "wrong_password", "Invalid password"));
    }

    let token = generate_jwt(username)
        .map_err(|e| AuthError::new(500, "token_error", &e.to_string()))?;
    let force_reset = user.needs_force_reset();
    let public_key = user.publicKey.as_ref().map(|pk| STANDARD.encode(&pk.0));
    let unread_emails = email_storage.count_unread(&user.emailIds);

    Ok(AuthResult {
        token,
        force_reset,
        username: user.username.clone(),
        public_key,
        unread_emails,
        salt: user.salt.clone(),
        encrypted_private_key: user.encrypted_private_key.clone(),
    })
}
