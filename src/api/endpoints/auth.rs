use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::api::dto::{LoginRequest, LoginResponse, ErrorResponse, json_header};
use crate::api::request::read_json_body;
use crate::api::ratelimit;
use crate::api::controllers::auth_controller;

fn error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&ErrorResponse { error: message.into(), code: code.into() }).unwrap();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

pub fn login(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    // nginx sits in front of the API, so remote_addr is always the docker
    // bridge. The header it sets is the only useful address — and it is only
    // trusted because the API cannot be reached except through nginx.
    let client_ip = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("X-Real-IP"))
        .map(|h| h.value.to_string())
        .filter(|v| !v.trim().is_empty())
        .or_else(|| request.remote_addr().map(|addr| addr.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let login_req: LoginRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = login_req.username.trim().to_lowercase();

    // Throttle by account and by source address: the first stops an attacker
    // grinding one mailbox, the second stops one host spraying many mailboxes.
    let user_key = format!("user:{}", username);
    let ip_key = format!("ip:{}", client_ip);
    if ratelimit::is_locked_out(&user_key, ratelimit::MAX_ACCOUNT_FAILURES)
        || ratelimit::is_locked_out(&ip_key, ratelimit::MAX_ADDRESS_FAILURES)
    {
        log::warn!("[Auth] Rate limit hit for user '{}' from {}", username, client_ip);
        return error(
            429,
            "too_many_attempts",
            "Too many failed login attempts; try again later",
        );
    }

    let user_agent = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("User-Agent"))
        .map(|h| h.value.to_string())
        .unwrap_or_default();

    match auth_controller::authenticate_with_client(
        &username,
        &login_req.password,
        &user_storage,
        &_email_storage,
        &user_agent,
        &client_ip,
    ) {
        Ok(result) => {
            ratelimit::record_success(&user_key);
            ratelimit::record_success(&ip_key);
            let body = serde_json::to_vec(&LoginResponse {
                token: result.token,
                force_reset: result.force_reset,
                is_admin: result.is_admin,
                username: result.username,
                public_key: result.public_key,
                unread_emails: result.unread_emails,
                salt: result.salt,
                encrypted_private_key: result.encrypted_private_key,
                two_factor_required: result.two_factor_required,
                challenge: result.challenge,
                session_id: result.session_id,
                two_factor_methods: {
                    // Only the factors this account can actually satisfy: offering a
                    // button that cannot work is how people conclude the key is broken.
                    let mut methods = Vec::new();
                    if result.two_factor_required {
                        if crate::core::twofactor::is_enabled(&username) {
                            methods.push("totp".to_string());
                        }
                        if crate::core::webauthn::has_any(&username) {
                            methods.push("webauthn".to_string());
                        }
                    }
                    methods
                },
            }).unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        Err(e) => {
            if e.status == 401 {
                ratelimit::record_failure(&user_key);
                ratelimit::record_failure(&ip_key);
                log::info!("[Auth] Failed login for '{}' from {}", username, client_ip);
            }
            error(e.status, &e.code, &e.message)
        }
    }
}
