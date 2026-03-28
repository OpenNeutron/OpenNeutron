use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crate::core::{UserStorage, EmailStorage, User};
use crate::utils::unix_to_iso;
use crate::api::dto::{
    GetEmailRequest, EmailBytesResponse, GetEmailsBulkRequest, EmailsBulkResponse,
    EmailUidsResponse, DeleteEmailRequest, SetEmailBytesRequest, GetRecentEmailsRequest,
    SendEmailRequest, MarkEmailReadRequest, SetEmailStarredRequest, ErrorResponse, MessageResponse, json_header,
    GetPublicKeysRequest, GetPublicKeysResponse, RecipientPublicKey,
    SendEncryptedRequest, SendEncryptedResponse, DeliveryResult,
};
use crate::smtp::EmailSendingFSM;
use crate::utils::emailutils;
use crate::core::Email;

pub fn get_email(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: GetEmailRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user.emailIds.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    match email_storage.read_email(req.uid) {
        Ok(email) => {
            let resp = EmailBytesResponse {
                uid: email.uid,
                data: STANDARD.encode(&email.raw_data),
                message_key: email.message_key.as_ref().map(|k| STANDARD.encode(k)),
                received_at: unix_to_iso(email.timestamp),
                e2ee: email.e2ee,
            };
            let body = serde_json::to_vec(&resp).unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
            Response::from_data(err).with_status_code(404).with_header(json_header())
        }
    }
}

pub fn get_emails_bulk(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: GetEmailsBulkRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    
    let allowed_uids: Vec<u128> = req.uids.into_iter()
        .filter(|uid| user.emailIds.contains(uid))
        .collect();

    let emails = email_storage.get_emails_bulk(allowed_uids).unwrap_or_default();
    let email_responses: Vec<EmailBytesResponse> = emails.iter().map(|e| {
        EmailBytesResponse {
            uid: e.uid,
            data: STANDARD.encode(&e.raw_data),
            message_key: e.message_key.as_ref().map(|k| STANDARD.encode(k)),
            received_at: unix_to_iso(e.timestamp),
            e2ee: e.e2ee,
        }
    }).collect();

    let resp = EmailsBulkResponse { emails: email_responses };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn list_email_uids(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let resp = EmailUidsResponse { uids: user.emailIds.clone() };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn delete_email(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: DeleteEmailRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user.emailIds.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    
    let mut updated_user = user.clone();
    updated_user.emailIds.retain(|&id| id != req.uid);
    user_storage.update_user(updated_user);
    user_storage.remove_email_from_groups(&user.username, req.uid);

    
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist user storage after email delete: {}", e);
    }

    
    if let Err(_) = email_storage.delete_email(req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to delete email".into(), code: "delete_failed".into() }).unwrap();
        return Response::from_data(err).with_status_code(500).with_header(json_header());
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Email deleted".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn set_email_bytes(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: SetEmailBytesRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user.emailIds.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    let decoded = match STANDARD.decode(&req.data) {
        Ok(d) => d,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid base64 data".into(), code: "invalid_base64".into() }).unwrap();
            return Response::from_data(err).with_status_code(400).with_header(json_header());
        }
    };

    let new_message_key = if let Some(mk) = &req.message_key {
        match STANDARD.decode(mk) {
            Ok(k) => Some(Some(k)),
            Err(_) => {
                let err = serde_json::to_vec(&ErrorResponse { error: "Invalid base64 message_key".into(), code: "invalid_base64".into() }).unwrap();
                return Response::from_data(err).with_status_code(400).with_header(json_header());
            }
        }
    } else {
        None // not provided - leave existing value unchanged
    };

    match email_storage.read_email(req.uid) {
        Ok(mut email) => {
            email.raw_data = decoded;
            if let Some(mk) = new_message_key {
                email.message_key = mk;
            }
            if let Err(_) = email_storage.save_email(&email) {
                let err = serde_json::to_vec(&ErrorResponse { error: "Failed to save email".into(), code: "save_failed".into() }).unwrap();
                return Response::from_data(err).with_status_code(500).with_header(json_header());
            }
            let msg = serde_json::to_vec(&MessageResponse { message: "Email updated".into() }).unwrap();
            Response::from_data(msg).with_status_code(200).with_header(json_header())
        }
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
            Response::from_data(err).with_status_code(404).with_header(json_header())
        }
    }
}

pub fn list_recent_email_uids(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
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

    let req: GetRecentEmailsRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    
    let uids: Vec<u128> = user.emailIds.iter().rev()
        .skip(req.offset)
        .take(req.limit)
        .copied()
        .collect();

    let resp = EmailUidsResponse { uids };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn send_email(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let _user = match user {
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

    let req: SendEmailRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let data = match STANDARD.decode(&req.data) {
        Ok(d) => d,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid base64 data".into(), code: "invalid_base64".into() }).unwrap();
            return Response::from_data(err).with_status_code(400).with_header(json_header());
        }
    };

    let port = req.smtp_port.unwrap_or(25);
    let domain = emailutils::get_server_domain();
    let mut fsm = match EmailSendingFSM::connect(&req.smtp_host, port, domain) {
        Ok(f) => f,
        Err(e) => {
            let err = serde_json::to_vec(&ErrorResponse {
                error: format!("Failed to connect to SMTP server: {}", e),
                code: "smtp_connect_error".into(),
            }).unwrap();
            return Response::from_data(err).with_status_code(502).with_header(json_header());
        }
    };

    match fsm.send(&req.from, &req.to, &data) {
        Ok(()) => {
            let msg = serde_json::to_vec(&MessageResponse { message: "Email sent".into() }).unwrap();
            Response::from_data(msg).with_status_code(200).with_header(json_header())
        }
        Err(e) => {
            let err = serde_json::to_vec(&ErrorResponse {
                error: format!("SMTP error: {}", e),
                code: "smtp_error".into(),
            }).unwrap();
            Response::from_data(err).with_status_code(502).with_header(json_header())
        }
    }
}

pub fn mark_email_read(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: MarkEmailReadRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user.emailIds.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    match email_storage.read_email(req.uid) {
        Ok(mut email) => {
            email.mark_as_read();
            if let Err(_) = email_storage.save_email(&email) {
                let err = serde_json::to_vec(&ErrorResponse { error: "Failed to save email".into(), code: "save_failed".into() }).unwrap();
                return Response::from_data(err).with_status_code(500).with_header(json_header());
            }
            let msg = serde_json::to_vec(&MessageResponse { message: "Email marked as read".into() }).unwrap();
            Response::from_data(msg).with_status_code(200).with_header(json_header())
        }
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
            Response::from_data(err).with_status_code(404).with_header(json_header())
        }
    }
}

pub fn mark_email_unread(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: MarkEmailReadRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user.emailIds.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    match email_storage.read_email(req.uid) {
        Ok(mut email) => {
            email.mark_as_unread();
            if let Err(_) = email_storage.save_email(&email) {
                let err = serde_json::to_vec(&ErrorResponse { error: "Failed to save email".into(), code: "save_failed".into() }).unwrap();
                return Response::from_data(err).with_status_code(500).with_header(json_header());
            }
            let msg = serde_json::to_vec(&MessageResponse { message: "Email marked as unread".into() }).unwrap();
            Response::from_data(msg).with_status_code(200).with_header(json_header())
        }
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
            Response::from_data(err).with_status_code(404).with_header(json_header())
        }
    }
}

pub fn set_email_starred(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: SetEmailStarredRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user.emailIds.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    match email_storage.read_email(req.uid) {
        Ok(mut email) => {
            email.set_starred(req.starred);
            if let Err(_) = email_storage.save_email(&email) {
                let err = serde_json::to_vec(&ErrorResponse { error: "Failed to save email".into(), code: "save_failed".into() }).unwrap();
                return Response::from_data(err).with_status_code(500).with_header(json_header());
            }
            let msg = serde_json::to_vec(&MessageResponse { message: if req.starred { "Email starred" } else { "Email unstarred" }.into() }).unwrap();
            Response::from_data(msg).with_status_code(200).with_header(json_header())
        }
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
            Response::from_data(err).with_status_code(404).with_header(json_header())
        }
    }
}

/// POST /email/publickeys - return public keys for a list of addresses
pub fn get_public_keys(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let _user = match user {
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

    let req: GetPublicKeysRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let domain = &user_storage.domain;
    let mut result_map: std::collections::HashMap<String, RecipientPublicKey> = std::collections::HashMap::new();
    let mut external_by_domain: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for address in &req.addresses {
        if let Some(pos) = address.find('@') {
            let username = &address[..pos];
            let addr_domain = &address[pos + 1..];
            if addr_domain.eq_ignore_ascii_case(domain) {
                let pk = user_storage.get_user(username).and_then(|u| {
                    u.publicKey.map(|k| STANDARD.encode(&k.0))
                });
                let key_type = if pk.is_some() { "openneutron-1" } else { "none" };
                result_map.insert(address.clone(), RecipientPublicKey {
                    address: address.clone(),
                    public_key: pk,
                    key_type: key_type.to_string(),
                });
            } else {
                external_by_domain
                    .entry(addr_domain.to_lowercase())
                    .or_default()
                    .push(address.clone());
            }
        } else {
            result_map.insert(address.clone(), RecipientPublicKey {
                address: address.clone(),
                public_key: None,
                key_type: "none".to_string(),
            });
        }
    }

    let ehlo_domain = emailutils::get_server_domain();
    for (ext_domain, addresses) in &external_by_domain {
        let mut queried = false;
        if let Some(mx_host) = emailutils::resolve_mx(ext_domain) {
            if let Ok(mut fsm) = EmailSendingFSM::connect(&mx_host, 25, ehlo_domain) {
                if let Ok(key_results) = fsm.query_opntrn_keys(addresses) {
                    for (addr, key_info) in key_results {
                        match key_info {
                            Some((kt, kb)) => {
                                result_map.insert(addr.clone(), RecipientPublicKey {
                                    address: addr,
                                    public_key: Some(kb),
                                    key_type: kt,
                                });
                            }
                            None => {
                                result_map.insert(addr.clone(), RecipientPublicKey {
                                    address: addr,
                                    public_key: None,
                                    key_type: "none".to_string(),
                                });
                            }
                        }
                    }
                    queried = true;
                }
            }
        }
        if !queried {
            for addr in addresses {
                result_map.entry(addr.clone()).or_insert(RecipientPublicKey {
                    address: addr.clone(),
                    public_key: None,
                    key_type: "none".to_string(),
                });
            }
        }
    }

    let keys: Vec<RecipientPublicKey> = req.addresses.iter().map(|addr| {
        result_map.remove(addr).unwrap_or(RecipientPublicKey {
            address: addr.clone(),
            public_key: None,
            key_type: "none".to_string(),
        })
    }).collect();

    let resp = GetPublicKeysResponse { keys };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// POST /email/sendencrypted - new encrypted sending flow
pub fn send_encrypted(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: SendEncryptedRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let domain = emailutils::get_server_domain();
    let sender_address = format!("{}@{}", user.username, domain);

    // --- 1. Save the local copy to sender's sent_emails ---
    let local_data = match STANDARD.decode(&req.localcopy.raw_data) {
        Ok(d) => d,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid base64 in localcopy.raw_data".into(), code: "invalid_base64".into() }).unwrap();
            return Response::from_data(err).with_status_code(400).with_header(json_header());
        }
    };

    let local_message_key = if let Some(mk) = &req.localcopy.message_key {
        match STANDARD.decode(mk) {
            Ok(k) => Some(k),
            Err(_) => {
                let err = serde_json::to_vec(&ErrorResponse { error: "Invalid base64 in localcopy.message_key".into(), code: "invalid_base64".into() }).unwrap();
                return Response::from_data(err).with_status_code(400).with_header(json_header());
            }
        }
    } else {
        None
    };

    let pk_hash_bytes = match STANDARD.decode(&req.localcopy.public_key_hash) {
        Ok(d) if d.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&d);
            arr
        }
        _ => [0u8; 32],
    };

    let sent_uid = emailutils::generate_email_uid(&user);
    let sent_email = Email {
        uid: sent_uid,
        secure: true,
        read: true,
        starred: false,
        e2ee: req.localcopy.e2ee,
        userid: user.uid,
        from: sender_address.clone(),
        to: req.localcopy.to.clone(),
        timestamp: req.localcopy.timestamp,
        publicKeyHash: crate::utils::Sha256Hash(pk_hash_bytes),
        raw_data: local_data,
        message_key: local_message_key,
    };

    if let Err(e) = email_storage.save_email(&sent_email) {
        let err = serde_json::to_vec(&ErrorResponse {
            error: format!("Failed to save local copy: {}", e),
            code: "save_failed".into(),
        }).unwrap();
        return Response::from_data(err).with_status_code(500).with_header(json_header());
    }

    // Add to user's sent_emails
    let mut updated_user = user.clone();
    updated_user.sent_emails.push(sent_uid);
    user_storage.update_user(updated_user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist user storage after sent email: {}", e);
    }

    // --- 2. For each recipient, DKIM-sign (if available) and send via SMTP ---
    let dkim_signer = emailutils::get_dkim_signer();
    let mut delivery_results = Vec::new();

    // Group recipients by domain for efficient delivery
    let mut by_domain: std::collections::HashMap<String, Vec<(String, Vec<u8>, bool)>> = std::collections::HashMap::new();
    for (address, payload) in &req.recipients {
        // For E2EE payloads: decode aes_encrypted + data_encrypted, then pack into the SMTP wire blob.
        // For plaintext payloads: data_encrypted is the raw RFC 5322 email bytes.
        let wire_bytes = if payload.e2ee {
            let enc_key = match STANDARD.decode(&payload.aes_encrypted) {
                Ok(k) => k,
                Err(_) => {
                    delivery_results.push(DeliveryResult {
                        address: address.clone(),
                        success: false,
                        error: Some("Invalid base64 in aes_encrypted".into()),
                    });
                    continue;
                }
            };
            let aes_ct = match STANDARD.decode(&payload.data_encrypted) {
                Ok(d) => d,
                Err(_) => {
                    delivery_results.push(DeliveryResult {
                        address: address.clone(),
                        success: false,
                        error: Some("Invalid base64 in data_encrypted".into()),
                    });
                    continue;
                }
            };
            crate::utils::cryptography::pack_encrypted_email(&enc_key, &aes_ct)
        } else {
            match STANDARD.decode(&payload.data_encrypted) {
                Ok(d) => d,
                Err(_) => {
                    delivery_results.push(DeliveryResult {
                        address: address.clone(),
                        success: false,
                        error: Some("Invalid base64 in data_encrypted".into()),
                    });
                    continue;
                }
            }
        };

        // DKIM-sign only non-E2EE payloads - E2EE payloads are binary encrypted blobs,
        // not RFC 5322 text; signing them would prepend a DKIM header and corrupt the blob.
        let signed_bytes = if payload.e2ee {
            wire_bytes
        } else {
            match dkim_signer {
                Some(signer) => {
                    match signer.sign(&wire_bytes) {
                        Ok(signed) => signed,
                        Err(e) => {
                            log::warn!("[SMTP] DKIM signing failed for {}: {} - sending unsigned", address, e);
                            wire_bytes
                        }
                    }
                }
                None => wire_bytes,
            }
        };

        let rcpt_domain = match address.find('@') {
            Some(pos) => address[pos + 1..].to_lowercase(),
            None => {
                delivery_results.push(DeliveryResult {
                    address: address.clone(),
                    success: false,
                    error: Some("Invalid email address".into()),
                });
                continue;
            }
        };

        by_domain
            .entry(rcpt_domain)
            .or_default()
            .push((address.clone(), signed_bytes, payload.e2ee));
    }

    // Send to each domain
    for (rcpt_domain, recipients) in &by_domain {
        // Resolve MX for the domain
        let mx_host = match emailutils::resolve_mx(rcpt_domain) {
            Some(host) => host,
            None => {
                for (addr, _, _) in recipients {
                    delivery_results.push(DeliveryResult {
                        address: addr.clone(),
                        success: false,
                        error: Some(format!("MX lookup failed for domain '{}'", rcpt_domain)),
                    });
                }
                continue;
            }
        };

        // Send each email separately (different data per recipient)
        for (address, data, is_e2ee) in recipients {
            let mut fsm = match EmailSendingFSM::connect(&mx_host, 25, domain) {
                Ok(f) => f,
                Err(e) => {
                    delivery_results.push(DeliveryResult {
                        address: address.clone(),
                        success: false,
                        error: Some(format!("SMTP connect to '{}' failed: {}", mx_host, e)),
                    });
                    continue;
                }
            };

            let to_list = vec![address.clone()];
            let send_result = if *is_e2ee {
                fsm.send_e2ee(&sender_address, &to_list, data)
            } else {
                fsm.send(&sender_address, &to_list, data)
            };
            match send_result {
                Ok(()) => {
                    delivery_results.push(DeliveryResult {
                        address: address.clone(),
                        success: true,
                        error: None,
                    });
                }
                Err(e) => {
                    delivery_results.push(DeliveryResult {
                        address: address.clone(),
                        success: false,
                        error: Some(format!("SMTP error: {}", e)),
                    });
                }
            }
        }
    }

    let resp = SendEncryptedResponse {
        message: "Send completed".into(),
        sent_email_uid: sent_uid,
        delivery_results,
    };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// POST /email/sent/list - list all sent email UIDs
pub fn list_sent_email_uids(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let resp = EmailUidsResponse { uids: user.sent_emails.clone() };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// POST /email/sent/recent - paginated sent emails, newest first
pub fn list_recent_sent_email_uids(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
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

    let req: GetRecentEmailsRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let uids: Vec<u128> = user.sent_emails.iter().rev()
        .skip(req.offset)
        .take(req.limit)
        .copied()
        .collect();

    let resp = EmailUidsResponse { uids };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// POST /email/sent/get - retrieve a single sent email by UID
pub fn get_sent_email(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: GetEmailRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user.sent_emails.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    match email_storage.read_email(req.uid) {
        Ok(email) => {
            let resp = EmailBytesResponse {
                uid: email.uid,
                data: STANDARD.encode(&email.raw_data),
                message_key: email.message_key.as_ref().map(|k| STANDARD.encode(k)),
                received_at: unix_to_iso(email.timestamp),
                e2ee: email.e2ee,
            };
            let body = serde_json::to_vec(&resp).unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
            Response::from_data(err).with_status_code(404).with_header(json_header())
        }
    }
}

/// POST /email/sent/bulk - retrieve multiple sent emails by UIDs
pub fn get_sent_emails_bulk(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
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

    let req: GetEmailsBulkRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let allowed_uids: Vec<u128> = req.uids.into_iter()
        .filter(|uid| user.sent_emails.contains(uid))
        .collect();

    let emails = email_storage.get_emails_bulk(allowed_uids).unwrap_or_default();
    let email_responses: Vec<EmailBytesResponse> = emails.iter().map(|e| {
        EmailBytesResponse {
            uid: e.uid,
            data: STANDARD.encode(&e.raw_data),
            message_key: e.message_key.as_ref().map(|k| STANDARD.encode(k)),
            received_at: unix_to_iso(e.timestamp),
            e2ee: e.e2ee,
        }
    }).collect();

    let resp = EmailsBulkResponse { emails: email_responses };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}
