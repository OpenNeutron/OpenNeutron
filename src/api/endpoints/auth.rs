use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::api::dto::{LoginRequest, LoginResponse, ErrorResponse, json_header};
use crate::api::controllers::auth_controller;

pub fn login(
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

    let login_req: LoginRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    match auth_controller::authenticate(&login_req.username, &login_req.password, &user_storage, &_email_storage) {
        Ok(result) => {
            let body = serde_json::to_vec(&LoginResponse {
                token: result.token,
                force_reset: result.force_reset,
                username: result.username,
                public_key: result.public_key,
                unread_emails: result.unread_emails,
                salt: result.salt,
                encrypted_private_key: result.encrypted_private_key,
            }).unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        Err(e) => {
            let err = serde_json::to_vec(&ErrorResponse { error: e.message, code: e.code }).unwrap();
            Response::from_data(err).with_status_code(e.status).with_header(json_header())
        }
    }
}
