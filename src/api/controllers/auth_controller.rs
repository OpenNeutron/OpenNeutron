use crate::core::{UserStorage, EmailStorage};
use crate::utils::jwt::generate_challenge_jwt;
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
    /// Set when the password was right but a second factor is still owed.
    pub two_factor_required: bool,
    pub challenge: Option<String>,
    /// Session id carried by the token, so the client can show which row is
    /// the device it is holding.
    pub session_id: Option<String>,
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
    authenticate_with_client(username, password, user_storage, email_storage, "", "")
}

/// Same check, but records the calling device against the new session.
pub fn authenticate_with_client(
    username: &str,
    password: &str,
    user_storage: &UserStorage,
    email_storage: &EmailStorage,
    user_agent: &str,
    ip: &str,
) -> Result<AuthResult, AuthError> {
    let user = match user_storage.get_user(username) {
        Some(u) => u,
        None => return Err(AuthError::invalid_credentials()),
    };

    if !user.verify_password_peppered(password) {
        return Err(AuthError::invalid_credentials());
    }

    // Self-registered accounts wait for an operator. This sits *between* the
    // password check and any token, on purpose: it must come after the password
    // (otherwise it confirms which names are queued to anyone who asks) and
    // before token issuance (otherwise the account is approved by being able to
    // log in at all). A pending account is never locked out by this - the login
    // handler only counts 401s against the rate limiter.
    if crate::core::pending_users::contains(username) {
        log::info!("[Auth] '{}' is waiting for account approval", username);
        return Err(AuthError::new(
            403,
            "account_pending",
            "Your account is waiting for approval",
        ));
    }

    // Second factor: the password alone must not yield a session, and it must
    // not leak key material, the salt or admin status either. A registered
    // security key counts on its own, so enrolling one cannot quietly weaken
    // anything if TOTP is later switched off.
    if crate::core::twofactor::is_enabled(username) || crate::core::webauthn::has_any(username) {
        let challenge = generate_challenge_jwt(username)
            .map_err(|e| AuthError::new(500, "token_error", &e.to_string()))?;
        log::info!("[Auth] '{}' passed the password step; second factor required", username);
        return Ok(AuthResult {
            token: String::new(),
            force_reset: false,
            is_admin: false,
            username: username.to_string(),
            public_key: None,
            unread_emails: 0,
            salt: String::new(),
            encrypted_private_key: None,
            two_factor_required: true,
            challenge: Some(challenge),
            session_id: None,
        });
    }

    // Mint the session id first: it has to be inside the token, and the token
    // hash is what the registry stores.
    let session_id = crate::core::sessions::new_id();
    let token = crate::utils::jwt::generate_jwt_with_sid(username, Some(&session_id))
        .map_err(|e| AuthError::new(500, "token_error", &e.to_string()))?;
    let issued = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::core::sessions::record(&session_id, username, &token, user_agent, ip, issued);
    let force_reset = user.needs_force_reset();
    let public_key = user.publicKey.as_ref().map(|pk| STANDARD.encode(&pk.0));
    let unread_emails = email_storage.count_unread(&crate::core::trash::inbox_ids(&user));

    // Touch only the fields this path owns. Replacing the whole record would
    // overwrite email ids added by a concurrent delivery with the stale clone.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    user_storage.mutate_user(username, |u| {
        u.lastLogin = now;
        // First login of a pre-pepper account upgrades its stored hash in place.
        u.seal_password();
    });
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
        two_factor_required: false,
        challenge: None,
        session_id: Some(session_id),
    })
}
