use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User, Group};
use crate::api::dto::{
    GroupDto, GroupsListResponse, CreateGroupRequest, GetGroupRequest,
    UpdateGroupRequest, DeleteGroupRequest, GroupEmailRequest,
    ErrorResponse, MessageResponse, json_header,
};

pub fn list_groups(
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

    let resp = GroupsListResponse { groups: user.groups.iter().map(GroupDto::from).collect() };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn create_group(
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

    let req: CreateGroupRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let group = Group::new(req.title, req.filter_addresses.unwrap_or_default());
    let dto = GroupDto::from(&group);
    user_storage.add_group(&user.username, group);

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after group create: {}", e);
    }

    let body = serde_json::to_vec(&dto).unwrap();
    Response::from_data(body).with_status_code(201).with_header(json_header())
}

pub fn get_group(
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

    let req: GetGroupRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    match user.groups.iter().find(|g| g.uid == req.uid) {
        Some(group) => {
            let body = serde_json::to_vec(&GroupDto::from(group)).unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
            Response::from_data(err).with_status_code(404).with_header(json_header())
        }
    }
}

pub fn update_group(
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

    let req: UpdateGroupRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    let existing = match user.groups.iter().find(|g| g.uid == req.uid) {
        Some(g) => g.clone(),
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
            return Response::from_data(err).with_status_code(404).with_header(json_header());
        }
    };

    let updated = Group {
        uid: existing.uid,
        title: req.title.unwrap_or(existing.title),
        email_uids: existing.email_uids,
        filter_addresses: req.filter_addresses
            .map(|addrs| addrs.into_iter().map(|a| a.to_lowercase()).collect())
            .unwrap_or(existing.filter_addresses),
    };

    user_storage.update_group(&user.username, updated.clone());

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after group update: {}", e);
    }

    let body = serde_json::to_vec(&GroupDto::from(&updated)).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn delete_group(
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

    let req: DeleteGroupRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user_storage.delete_group(&user.username, req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after group delete: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Group deleted".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn add_email_to_group(
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

    let req: GroupEmailRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user.emailIds.contains(&req.email_uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    if !user_storage.add_email_to_group(&user.username, req.group_uid, req.email_uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after add-email-to-group: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Email added to group".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn remove_email_from_group(
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

    let req: GroupEmailRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid JSON".into(), code: "invalid_json".into() }).unwrap();
            return Response::from_data(err).with_status_code(422).with_header(json_header());
        }
    };

    if !user_storage.remove_email_from_group(&user.username, req.group_uid, req.email_uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after remove-email-from-group: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Email removed from group".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}
