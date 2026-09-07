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
    let client_ip = request
        .remote_addr()
        .map(|addr| addr.ip().to_string())
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

    match auth_controller::authenticate(&username, &login_req.password, &user_storage, &_email_storage) {
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
