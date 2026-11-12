//! Two-factor authentication endpoints.
//!
//! Enrolment, login-time verification, and disable. `login_with_code` is the
//! only public one: it redeems the short-lived scoped challenge that the
//! password step hands out, so no session exists until a code is proven.

use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::core::twofactor;
use crate::api::dto::{ErrorResponse, json_header};
use crate::api::request::read_json_body;
use crate::api::{ratelimit, dto::LoginResponse};
use crate::utils::jwt::{generate_challenge_jwt, validate_jwt};

type Resp = Response<Cursor<Vec<u8>>>;

fn error(status: u16, code: &str, message: &str) -> Resp {
    let body = serde_json::to_vec(&ErrorResponse { error: message.into(), code: code.into() }).unwrap();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn ok_json(value: serde_json::Value) -> Resp {
    Response::from_data(serde_json::to_vec(&value).unwrap())
        .with_status_code(200)
        .with_header(json_header())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// GET /user/2fa
pub fn status(_req: &mut Request, user: Option<User>, _us: Arc<UserStorage>, _es: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let entry = twofactor::get(&user.username);
    let enabled = entry.as_ref().map(|e| e.is_active()).unwrap_or(false);
    let pending = entry
        .as_ref()
        .map(|e| !e.secret.is_empty() && !e.is_active())
        .unwrap_or(false);
    ok_json(serde_json::json!({
        "enabled": enabled,
        "pending": pending,
        "enabled_at": entry.as_ref().map(|e| e.enabled_at).unwrap_or(0),
        "recovery_codes_remaining": if enabled { twofactor::recovery_codes_remaining(&user.username) } else { 0 },
    }))
}

/// POST /user/2fa/start — mint a secret; shown exactly once.
pub fn start(_req: &mut Request, user: Option<User>, _us: Arc<UserStorage>, _es: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let secret = twofactor::new_secret();
    let secret_b32 = twofactor::base32_encode(&secret);
    match twofactor::start_enrollment(&user.username, &secret_b32) {
        Ok(true) => {}
        Ok(false) => {
            return error(
                409,
                "already_enabled",
                "Two-factor authentication is already on. Turn it off first to re-enrol.",
            )
        }
        Err(e) => {
            log::error!("[2FA] start failed for '{}': {}", user.username, e);
            return error(500, "storage_error", "Could not start enrolment");
        }
    }
    let codes = twofactor::generate_recovery_codes(10);
    log::info!("[2FA] enrolment started for '{}'", user.username);
    ok_json(serde_json::json!({
        "secret": secret_b32,
        "otpauth_url": twofactor::otpauth_url(&user.username, &secret_b32),
        "recovery_codes": codes,
    }))
}

/// POST /user/2fa/confirm — prove the authenticator works, then switch it on.
pub fn confirm(request: &mut Request, user: Option<User>, _us: Arc<UserStorage>, _es: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // Enrolment must be completed with an authenticator code, never a recovery
    // code: this step exists to prove the app is actually generating them.
    let codes = twofactor::generate_recovery_codes(10);
    match twofactor::confirm_enrollment(&user.username, &code, codes.clone(), now_unix()) {
        Ok(()) => {
            log::info!("[2FA] enabled for '{}'", user.username);
            ok_json(serde_json::json!({
                "message": "Two-factor authentication is on",
                "recovery_codes": codes,
            }))
        }
        Err(e) if e == "invalid_code" => error(400, "invalid_code", "That code is not valid"),
        Err(e) => {
            log::warn!("[2FA] confirm failed for '{}': {}", user.username, e);
            error(400, "not_pending", "Start setup again")
        }
    }
}

/// POST /user/2fa/disable — needs a live code or a recovery code.
pub fn disable(request: &mut Request, user: Option<User>, user_storage: Arc<UserStorage>, _es: Arc<EmailStorage>) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !twofactor::is_enabled(&user.username) {
        return error(400, "not_enabled", "Two-factor authentication is not on");
    }
    let accepted = twofactor::verify_login_code(&user.username, &code, now_unix())
        || twofactor::consume_recovery_code(&user.username, &code);
    if !accepted {
        log::warn!("[2FA] wrong code on disable attempt for '{}'", user.username);
        return error(401, "invalid_code", "That code is not valid");
    }
    // The account may have been removed while the code was being typed.
    if user_storage.get_user(&user.username).is_none() {
        return error(401, "unauthorized", "Unauthorized");
    }
    match twofactor::disable(&user.username) {
        Ok(()) => {
            log::warn!("[2FA] DISABLED for '{}'", user.username);
            ok_json(serde_json::json!({ "message": "Two-factor authentication is off" }))
        }
        Err(e) => {
            log::error!("[2FA] disable failed for '{}': {}", user.username, e);
            error(500, "storage_error", "Could not disable two-factor")
        }
    }
}

/// POST /auth/login/2fa — redeem a challenge token with a code.
pub fn login_with_code(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Resp {
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let challenge = body.get("challenge").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Only a scoped challenge is accepted here; a session token is not a
    // challenge, and a bare username certainly is not.
    let claims = match validate_jwt(&challenge) {
        Ok(c) => c,
        Err(_) => {
            return error(401, "invalid_challenge", "That login attempt expired; sign in again")
        }
    };
    if claims.scope.as_deref() != Some("mfa") {
        return error(401, "invalid_challenge", "That login attempt expired; sign in again");
    }

    let username = claims.sub.to_lowercase();
    let user_key = format!("user:{}", username);
    if ratelimit::is_locked_out(&user_key, ratelimit::MAX_ACCOUNT_FAILURES) {
        return error(429, "too_many_attempts", "Too many attempts; try again later");
    }
    if !twofactor::is_enabled(&username) {
        return error(400, "not_enabled", "Two-factor is not on for this account");
    }

    let accepted = twofactor::verify_login_code(&username, &code, now_unix())
        || twofactor::consume_recovery_code(&username, &code);
    if !accepted {
        ratelimit::record_failure(&user_key);
        log::warn!("[2FA] failed second factor for '{}'", username);
        return error(401, "invalid_code", "That code is not valid");
    }

    let Some(user) = user_storage.get_user(&username) else {
        return error(401, "invalid_challenge", "That login attempt expired; sign in again");
    };
    let session_id = crate::core::sessions::new_id();
    let token = match crate::utils::jwt::generate_jwt_with_sid(&username, Some(&session_id)) {
        Ok(t) => t,
        Err(e) => return error(500, "token_error", &e.to_string()),
    };
    let user_agent = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("User-Agent"))
        .map(|h| h.value.to_string())
        .unwrap_or_default();
    let ip = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("X-Real-IP"))
        .map(|h| h.value.to_string())
        .filter(|v| !v.trim().is_empty())
        .or_else(|| request.remote_addr().map(|a| a.ip().to_string()))
        .unwrap_or_default();
    crate::core::sessions::record(&session_id, &username, &token, &user_agent, &ip, now_unix());
    ratelimit::record_success(&user_key);

    let public_key = user.publicKey.as_ref().map(|pk| {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(&pk.0)
    });
    let unread = email_storage.count_unread(&crate::core::trash::inbox_ids(&user));

    log::info!("[2FA] '{}' completed login with a second factor", username);
    ok_json(serde_json::to_value(LoginResponse {
        token,
        force_reset: user.needs_force_reset(),
        is_admin: user.is_admin,
        username: user.username.clone(),
        public_key,
        unread_emails: unread,
        salt: user.salt.clone(),
        encrypted_private_key: user.encrypted_private_key.clone(),
        two_factor_required: false,
        challenge: None,
        two_factor_methods: Vec::new(),
        session_id: Some(session_id),
    }).unwrap())
}

/// Used by the password step when the account has 2FA on.
pub fn issue_challenge(username: &str) -> Result<String, String> {
    generate_challenge_jwt(username).map_err(|e| e.to_string())
}
