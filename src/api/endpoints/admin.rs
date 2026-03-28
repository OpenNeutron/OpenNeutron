use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::api::dto::{
    UserDto, AdminUsersResponse, AdminCreateUserRequest, AdminCreateUserResponse,
    AdminDeleteUserRequest, AdminSetCredentialsRequest, AdminSetAdminRequest,
    UserDiskUsageDto, AdminDiskUsageResponse, ErrorResponse,
    MessageResponse, json_header,
};
use crate::utils::cryptography::public_key_from_string;

pub fn list_users(
    _request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let all_users = user_storage.get_all_users();
    let dtos: Vec<UserDto> = all_users.iter().map(|u| UserDto::new(u, &user_storage.domain)).collect();
    let total = dtos.len();
    let body = serde_json::to_vec(&AdminUsersResponse { users: dtos, total }).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn add_user(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to read body".into(), code: "body_read_error".into() }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    let req: AdminCreateUserRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if user_storage.check_user_exists(&req.username) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Username already taken".into(), code: "username_taken".into() }).unwrap();
        return Response::from_data(err).with_status_code(409).with_header(json_header());
    }

    let user = User::create_admin_user(req.username);
    user_storage.add_user(user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Admin] Failed to persist after add_user: {}", e);
    }

    let resp = AdminCreateUserResponse { message: "User created".into(), force_reset: true };
    let msg = serde_json::to_vec(&resp).unwrap();
    Response::from_data(msg).with_status_code(201).with_header(json_header())
}

pub fn delete_user(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to read body".into(), code: "body_read_error".into() }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    let req: AdminDeleteUserRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user_storage.check_user_exists(&req.username) {
        let err = serde_json::to_vec(&ErrorResponse { error: "User not found".into(), code: "user_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    let email_ids = user_storage.delete_user(&req.username);
    email_storage.delete_emails_for_user(&email_ids);

    let msg = serde_json::to_vec(&MessageResponse { message: "User deleted".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn set_credentials(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to read body".into(), code: "body_read_error".into() }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    let req: AdminSetCredentialsRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let user = match user_storage.get_user(&req.username) {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "User not found".into(), code: "user_not_found".into() }).unwrap();
            return Response::from_data(err).with_status_code(404).with_header(json_header());
        }
    };

    if req.password.is_none() && req.public_key.is_none() && req.encrypted_private_key.is_none() {
        let err = serde_json::to_vec(&ErrorResponse { error: "Nothing to update".into(), code: "nothing_to_update".into() }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    let mut updated = user.clone();
    if let Some(pw) = req.password {
        updated.passwordHash = Some(pw);
    }
    if let Some(pk) = req.public_key {
        updated.publicKey = Some(public_key_from_string(pk));
    }
    if let Some(epk) = req.encrypted_private_key {
        updated.encrypted_private_key = Some(epk);
    }
    user_storage.update_user(updated);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Admin] Failed to persist after set_credentials: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Credentials updated".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn set_admin(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to read body".into(), code: "body_read_error".into() }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    let req: AdminSetAdminRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let user = match user_storage.get_user(&req.username) {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "User not found".into(), code: "user_not_found".into() }).unwrap();
            return Response::from_data(err).with_status_code(404).with_header(json_header());
        }
    };

    let mut updated = user.clone();
    updated.is_admin = req.is_admin;
    user_storage.update_user(updated);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Admin] Failed to persist after set_admin: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Admin status updated".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn disk_usage(
    _request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
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
