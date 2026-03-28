use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::api::dto::{UserDto, CreateUserRequest, SetupPasswordRequest, UserSetCredentialsRequest, ErrorResponse, MessageResponse, json_header};
use crate::utils::cryptography::public_key_from_string;

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
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            Response::from_data(err).with_status_code(401).with_header(json_header())
        }
    }
}

pub fn register(
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

    let req: CreateUserRequest = match serde_json::from_str(&body) {
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

    let user = User::create_user(req.username, req.password, req.public_key, req.encrypted_private_key);
    user_storage.add_user(user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after register: {}", e);
    }

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
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    if !user.needs_force_reset() {
        let err = serde_json::to_vec(&ErrorResponse { error: "Password already set".into(), code: "password_already_set".into() }).unwrap();
        return Response::from_data(err).with_status_code(409).with_header(json_header());
    }

    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to read body".into(), code: "body_read_error".into() }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    let req: SetupPasswordRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let mut updated_user = user.clone();
    updated_user.passwordHash = Some(req.password);
    updated_user.publicKey = Some(public_key_from_string(req.public_key));
    updated_user.encrypted_private_key = Some(req.encrypted_private_key);
    user_storage.update_user(updated_user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after setup_password: {}", e);
    }

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
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to read body".into(), code: "body_read_error".into() }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    let req: UserSetCredentialsRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
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
        log::warn!("[API] Failed to persist after set_credentials: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Credentials updated".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}
