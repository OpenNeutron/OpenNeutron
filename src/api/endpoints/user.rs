use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::core::user::validate_username;
use crate::api::dto::{UserDto, CreateUserRequest, SetupPasswordRequest, UserSetCredentialsRequest, ErrorResponse, MessageResponse, json_header};
use crate::api::request::read_json_body;
use crate::utils::cryptography::public_key_from_string;

fn error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&ErrorResponse { error: message.into(), code: code.into() }).unwrap();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

/// Client-side password hashes and encrypted key blobs are fixed-size strings.
/// Bounding them keeps a single account from bloating the user store.
const MAX_PASSWORD_HASH_LEN: usize = 512;
const MAX_ENCRYPTED_KEY_LEN: usize = 16_384;

fn validate_credential_lengths(
    password: Option<&String>,
    encrypted_private_key: Option<&String>,
) -> Result<(), Response<Cursor<Vec<u8>>>> {
    if let Some(pw) = password {
        if pw.is_empty() || pw.len() > MAX_PASSWORD_HASH_LEN {
            return Err(error(400, "invalid_password", "Password token has an invalid length"));
        }
    }
    if let Some(key) = encrypted_private_key {
        if key.len() > MAX_ENCRYPTED_KEY_LEN {
            return Err(error(400, "invalid_encrypted_key", "Encrypted private key is too large"));
        }
    }
    Ok(())
}

pub fn get_me(
    _request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    match user {
        Some(u) => {
            let body = serde_json::to_vec(&UserDto::new(&u, &user_storage.domain)).unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        None => error(401, "unauthorized", "Unauthorized"),
    }
}

pub fn register(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    // Self-registration hands out a mailbox on this server's domain, so it stays
    // closed unless the operator opts in.
    if !crate::config::get().server.allow_open_registration {
        return error(
            403,
            "registration_disabled",
            "Self-registration is disabled; ask an administrator to create your account",
        );
    }

    let req: CreateUserRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = req.username.trim().to_lowercase();
    if let Err(reason) = validate_username(&username) {
        return error(400, "invalid_username", reason);
    }
    if let Err(resp) = validate_credential_lengths(Some(&req.password), Some(&req.encrypted_private_key)) {
        return resp;
    }

    let public_key = match public_key_from_string(&req.public_key) {
        Ok(key) => key,
        Err(reason) => return error(400, "invalid_public_key", &reason),
    };

    if user_storage.check_user_exists(&username) {
        return error(409, "username_taken", "Username already taken");
    }

    let user = User::create_user(username.clone(), req.password, public_key, req.encrypted_private_key);
    user_storage.add_user(user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after register: {}", e);
    }
    log::info!("[API] Account '{}' self-registered", username);

    let msg = serde_json::to_vec(&MessageResponse { message: "User created".into() }).unwrap();
    Response::from_data(msg).with_status_code(201).with_header(json_header())
}

pub fn setup_password(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };

    if !user.needs_force_reset() {
        return error(409, "password_already_set", "Password already set");
    }

    let req: SetupPasswordRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_credential_lengths(Some(&req.password), Some(&req.encrypted_private_key)) {
        return resp;
    }
    let public_key = match public_key_from_string(&req.public_key) {
        Ok(key) => key,
        Err(reason) => return error(400, "invalid_public_key", &reason),
    };

    // Re-read the account under the same request so a concurrent setup cannot be
    // overwritten with a stale copy, and confirm it is still unconfigured.
    let current = match user_storage.get_user(&user.username) {
        Some(u) if u.needs_force_reset() => u,
        Some(_) => return error(409, "password_already_set", "Password already set"),
        None => return error(401, "unauthorized", "Unauthorized"),
    };

    let mut updated_user = current;
    updated_user.passwordHash = Some(req.password);
    updated_user.publicKey = Some(public_key);
    updated_user.encrypted_private_key = Some(req.encrypted_private_key);
    // The one-time provisioning secret must not survive as a second password.
    updated_user.setup_token = None;
    user_storage.update_user(updated_user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after setup_password: {}", e);
    }
    log::info!("[API] Account '{}' completed first-time setup", user.username);

    let msg = serde_json::to_vec(&MessageResponse { message: "Password set".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn set_credentials(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };

    let req: UserSetCredentialsRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if req.password.is_none() && req.public_key.is_none() && req.encrypted_private_key.is_none() {
        return error(400, "nothing_to_update", "Nothing to update");
    }
    if let Err(resp) = validate_credential_lengths(req.password.as_ref(), req.encrypted_private_key.as_ref()) {
        return resp;
    }

    // Work from the stored record rather than the copy captured at authentication
    // time, so this write does not clobber concurrent changes to other fields.
    let mut updated = match user_storage.get_user(&user.username) {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };

    if let Some(pw) = req.password {
        updated.passwordHash = Some(pw);
        updated.setup_token = None;
    }
    if let Some(pk) = req.public_key {
        match public_key_from_string(&pk) {
            Ok(key) => updated.publicKey = Some(key),
            Err(reason) => return error(400, "invalid_public_key", &reason),
        }
    }
    if let Some(epk) = req.encrypted_private_key {
        updated.encrypted_private_key = Some(epk);
    }
    user_storage.update_user(updated);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after set_credentials: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Credentials updated".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}
