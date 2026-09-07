use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::core::user::validate_username;
use crate::api::dto::{
    UserDto, AdminUsersResponse, AdminCreateUserRequest, AdminCreateUserResponse,
    AdminDeleteUserRequest, AdminSetCredentialsRequest, AdminSetAdminRequest,
    UserDiskUsageDto, AdminDiskUsageResponse, AdminResetResponse, ErrorResponse,
    MessageResponse, json_header,
};
use crate::api::request::read_json_body;
use crate::utils::cryptography::public_key_from_string;

fn error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&ErrorResponse { error: message.into(), code: code.into() }).unwrap();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

/// Re-check the caller's privilege inside the handler.
///
/// The router already gates every '/api/admin/*' route on 'RouteAuth::Admin';
/// this second check means a route accidentally registered with the wrong auth
/// level still cannot be used to administer the server.
fn require_admin(user: Option<User>) -> Result<User, Response<Cursor<Vec<u8>>>> {
    match user {
        Some(u) if u.is_admin => Ok(u),
        Some(u) => {
            log::warn!("[Admin] Non-admin user '{}' attempted an administrative action", u.username);
            Err(error(403, "forbidden", "Administrator privileges required"))
        }
        None => Err(error(401, "unauthorized", "Unauthorized")),
    }
}

/// True if 'username' is the only account left with administrator rights.
fn is_last_admin(user_storage: &UserStorage, username: &str) -> bool {
    let admins: Vec<String> = user_storage
        .get_all_users()
        .into_iter()
        .filter(|u| u.is_admin)
        .map(|u| u.username)
        .collect();
    admins.len() == 1 && admins[0] == username
}

pub fn list_users(
    _request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    if let Err(resp) = require_admin(user) {
        return resp;
    }

    let all_users = user_storage.get_all_users();
    let dtos: Vec<UserDto> = all_users.iter().map(|u| UserDto::new(u, &user_storage.domain)).collect();
    let total = dtos.len();
    let body = serde_json::to_vec(&AdminUsersResponse { users: dtos, total }).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn add_user(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match require_admin(user) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let req: AdminCreateUserRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = req.username.trim().to_lowercase();
    if let Err(reason) = validate_username(&username) {
        return error(400, "invalid_username", reason);
    }

    if user_storage.check_user_exists(&username) {
        return error(409, "username_taken", "Username already taken");
    }

    // Accounts are created without a password. The one-time setup token below is
    // the only credential that unlocks the account, and it is returned exactly
    // once - to the administrator who created it.
    let new_user = User::create_provisioned_user(username.clone(), req.is_admin);
    let setup_token = new_user.setup_token.clone().unwrap_or_default();
    user_storage.add_user(new_user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Admin] Failed to persist after add_user: {}", e);
    }
    log::info!(
        "[Admin] '{}' created account '{}' (is_admin={})",
        caller.username, username, req.is_admin
    );

    let resp = AdminCreateUserResponse {
        message: "User created".into(),
        force_reset: true,
        setup_token,
    };
    let msg = serde_json::to_vec(&resp).unwrap();
    Response::from_data(msg).with_status_code(201).with_header(json_header())
}

pub fn delete_user(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match require_admin(user) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let req: AdminDeleteUserRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = req.username.trim().to_lowercase();
    if !user_storage.check_user_exists(&username) {
        return error(404, "user_not_found", "User not found");
    }
    if username == caller.username {
        return error(409, "cannot_delete_self", "An administrator cannot delete their own account");
    }
    if is_last_admin(&user_storage, &username) {
        return error(409, "last_admin", "Cannot delete the last remaining administrator");
    }

    let email_ids = user_storage.delete_user(&username);
    email_storage.delete_emails_for_user(&email_ids);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Admin] Failed to persist after delete_user: {}", e);
    }
    log::info!("[Admin] '{}' deleted account '{}'", caller.username, username);

    let msg = serde_json::to_vec(&MessageResponse { message: "User deleted".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn set_credentials(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match require_admin(user) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let req: AdminSetCredentialsRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = req.username.trim().to_lowercase();
    let user = match user_storage.get_user(&username) {
        Some(u) => u,
        None => return error(404, "user_not_found", "User not found"),
    };

    if req.password.is_none() && req.public_key.is_none() && req.encrypted_private_key.is_none() {
        return error(400, "nothing_to_update", "Nothing to update");
    }

    let mut updated = user.clone();
    let mut new_setup_token = None;

    if let Some(pw) = req.password {
        if pw.is_empty() {
            // Clearing the password puts the account back into the setup state.
            // It must get a fresh one-time token, never become passwordless-open.
            let token = crate::core::user::gen_setup_token();
            updated.passwordHash = None;
            updated.setup_token = Some(token.clone());
            new_setup_token = Some(token);
        } else {
            updated.passwordHash = Some(pw);
            updated.setup_token = None;
        }
        // An administrator changed someone else's credentials: every session
        // issued under the old password must stop working immediately.
        updated.revoke_existing_sessions();
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
        log::warn!("[Admin] Failed to persist after set_credentials: {}", e);
    }
    log::info!("[Admin] '{}' updated credentials for '{}'", caller.username, username);

    let resp = AdminResetResponse {
        message: "Credentials updated".into(),
        setup_token: new_setup_token,
    };
    let msg = serde_json::to_vec(&resp).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn set_admin(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match require_admin(user) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let req: AdminSetAdminRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = req.username.trim().to_lowercase();
    let user = match user_storage.get_user(&username) {
        Some(u) => u,
        None => return error(404, "user_not_found", "User not found"),
    };

    if !req.is_admin && is_last_admin(&user_storage, &username) {
        return error(409, "last_admin", "Cannot remove the last remaining administrator");
    }

    let mut updated = user.clone();
    updated.is_admin = req.is_admin;
    user_storage.update_user(updated);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Admin] Failed to persist after set_admin: {}", e);
    }
    log::info!(
        "[Admin] '{}' set is_admin={} for '{}'",
        caller.username, req.is_admin, username
    );

    let msg = serde_json::to_vec(&MessageResponse { message: "Admin status updated".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn disk_usage(
    _request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    if let Err(resp) = require_admin(user) {
        return resp;
    }

    let all_users = user_storage.get_all_users();
    let users: Vec<UserDiskUsageDto> = all_users.iter().map(|u| {
        UserDiskUsageDto {
            username: u.username.clone(),
            email_count: u.emailIds.len(),
            disk_usage_bytes: email_storage.get_user_disk_usage(&u.emailIds),
        }
    }).collect();

    let body = serde_json::to_vec(&AdminDiskUsageResponse { users }).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}
