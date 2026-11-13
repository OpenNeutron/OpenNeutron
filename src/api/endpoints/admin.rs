use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::core::user::validate_username;
use crate::api::dto::{
    UserDto, AdminUsersResponse, AdminCreateUserRequest, AdminCreateUserResponse,
    AdminDeleteUserRequest, AdminSetCredentialsRequest, AdminSetAdminRequest,
    UserDiskUsageDto, AdminDiskUsageResponse, AdminResetResponse, ErrorResponse,
    AdminRecoveryAddressRequest, AdminRecoveryAddressResponse, AdminSendRecoveryRequest,
    AdminSendRecoveryResponse,
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

/// Remove an account and everything attached to it: mail, sessions, second
/// factor, recovery record and the signup address claim.
///
/// Shared by the admin delete route and by denying a pending signup, so a denial
/// cannot leave state behind that a later account with the same name inherits.
fn erase_account(user_storage: &UserStorage, email_storage: &EmailStorage, username: &str) {
    let email_ids = user_storage.delete_user(username);
    // Free the address that created this account, so one bad signup does not
    // permanently lock out whoever shares that address.
    crate::core::signup_ip::release_for(username);
    // Its addresses go with it: an alias left behind would keep accepting mail
    // for a mailbox that no longer exists.
    match crate::core::scheduled::purge(username) {
        Ok(n) if n > 0 => log::info!("[Admin] Dropped {} queued message(s) for '{}'", n, username),
        Ok(_) => {}
        Err(e) => log::warn!("[Admin] Could not drop queued messages for '{}': {}", username, e),
    }
    // A push subscription is a way to reach a device. Nothing should be able to
    // reach it once the account is gone.
    crate::core::push::purge_user(username);
    match crate::core::aliases::purge(username) {
        Ok(n) if n > 0 => log::info!("[Admin] Removed {} alias(es) for '{}'", n, username),
        Ok(_) => {}
        Err(e) => log::warn!("[Admin] Could not remove aliases for '{}': {}", username, e),
    }
    // A post-quantum key left behind is worse than clutter: if the name is ever
    // reused, new mail would be sealed to a decapsulation key nobody holds.
    if let Err(e) = crate::core::pqkeys::remove(username) {
        log::warn!("[Admin] Could not remove post-quantum keys for '{}': {}", username, e);
    }
    // The deletion log goes with the account, for the same reason the keys do.
    if let Err(e) = crate::core::mailboxlog::forget(username) {
        log::warn!("[Admin] Could not clear the deletion log for '{}': {}", username, e);
    }
    // A deleted account must not linger in the approval queue: approving a ghost
    // would 404, and the panel would keep offering a button that cannot work.
    if let Err(e) = crate::core::pending_users::remove(username) {
        log::warn!("[Admin] Could not clear pending entry for '{}': {}", username, e);
    }
    if let Err(e) = crate::core::recovery::store().remove(username) {
        log::warn!("[Recovery] Could not clear recovery record for '{}': {}", username, e);
    }
    // A deletion must not leave a second factor behind: a later account with the
    // same name would inherit it and be locked out at login.
    if let Err(e) = crate::core::twofactor::disable(username) {
        log::warn!("[2FA] Could not clear two-factor entry for '{}': {}", username, e);
    }
    crate::core::sessions::clear_user(username);
    email_storage.delete_emails_for_user(&email_ids);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Admin] Failed to persist after deleting '{}': {}", username, e);
    }
}

/// Every local part that should accept mail: real accounts, plus the aliases
/// that are switched on.
///
/// Postfix asks this before accepting a message, so a name missing here is
/// rejected at RCPT time — a disabled alias is refused by Postfix rather than
/// accepted and dropped here, and an unknown address never reaches the store at
/// all. Pending signups are left out: they cannot read mail yet, so accepting it
/// would only store ciphertext nobody can open.
pub fn recipients(
    _request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    if let Err(resp) = require_admin(user) {
        return resp;
    }

    let queued: std::collections::HashSet<String> = crate::core::pending_users::list()
        .into_iter()
        .map(|entry| entry.username)
        .collect();

    let mut names: Vec<String> = user_storage
        .get_all_users()
        .into_iter()
        .filter(|u| !queued.contains(&u.username))
        .map(|u| u.username)
        .collect();

    for (local, alias) in crate::core::aliases::load().aliases {
        if alias.disabled_at.is_none() {
            names.push(local);
        }
    }

    names.sort();
    names.dedup();
    let body = serde_json::to_vec(&json!({ "recipients": names })).unwrap_or_default();
    Response::from_data(body).with_status_code(200).with_header(json_header())
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
    let queued: std::collections::HashSet<String> = crate::core::pending_users::list()
        .into_iter()
        .map(|entry| entry.username)
        .collect();
    let dtos: Vec<UserDto> = all_users
        .iter()
        .map(|u| UserDto::new(u, &user_storage.domain).with_pending(queued.contains(&u.username)))
        .collect();
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

    erase_account(&user_storage, &email_storage, &username);
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
    updated.seal_password();
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

/// Loose address check: one '@', a dot in the domain, no whitespace. The address
/// is only used as an envelope recipient, so strict RFC parsing would reject
/// valid unusual addresses for no benefit.
fn plausible_address(email: &str) -> bool {
    if email.len() < 5 || email.len() > 254 || email.contains(char::is_whitespace) {
        return false;
    }
    let mut parts = email.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) => {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        }
        _ => false,
    }
}

pub fn set_recovery_address(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match require_admin(user) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let req: AdminRecoveryAddressRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = req.username.trim().to_lowercase();
    let target = match user_storage.get_user(&username) {
        Some(u) => u,
        None => return error(404, "user_not_found", "User not found"),
    };

    let cleared = req
        .email
        .as_ref()
        .map(|e| e.trim().to_lowercase())
        .filter(|e| !e.is_empty());

    if let Some(email) = &cleared {
        if !plausible_address(email) {
            return error(400, "invalid_email", "That does not look like an email address");
        }
    }

    if let Err(e) = crate::core::recovery::store().set_email(&username, cleared.clone()) {
        log::warn!("[Recovery] Failed to persist recovery address: {}", e);
        return error(500, "storage_error", "Could not save that address");
    }
    log::info!(
        "[Recovery] '{}' set recovery address for '{}' to {}",
        caller.username,
        username,
        cleared.as_deref().unwrap_or("(none)")
    );

    let body = serde_json::to_vec(&AdminRecoveryAddressResponse {
        username,
        recovery_email: cleared,
    })
    .unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// Mint a single-use reset token and mail it to the recovery address.
pub fn send_recovery(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match require_admin(user) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let req: AdminSendRecoveryRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = req.username.trim().to_lowercase();
    let target = match user_storage.get_user(&username) {
        Some(u) => u,
        None => return error(404, "user_not_found", "User not found"),
    };

    let store = crate::core::recovery::store();
    let recovery = match store.get(&username).email.clone() {
        Some(e) if !e.trim().is_empty() => e,
        _ => {
            return error(
                400,
                "no_recovery_address",
                "No recovery address on file for this account. Add one first.",
            )
        }
    };

    const TTL_MINUTES: u64 = 60;
    let token = crate::core::user::gen_setup_token();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Err(e) = store.set_token(&username, crate::core::user::sha256_hex(&token), now + TTL_MINUTES * 60) {
        log::warn!("[Recovery] Failed to persist reset token: {}", e);
        return error(500, "storage_error", "Could not create a reset token");
    }

    let domain = crate::utils::emailutils::get_server_domain();
    let link = format!("https://{}/reset?t={}", domain, token);
    let body = format!(
        "Someone requested a password reset for the mailbox '{username}' on {domain}.\n\n         Open this link to choose a new password:\n\n  {link}\n\n         The link works once and expires in {ttl} minutes.\n\n         Important: your password is what unlocks the private key that decrypts your\
         mailbox. Setting a new password creates a new key, so mail encrypted to the\
         old key can no longer be read. If you still have an exported copy of your old\
         private key, you can import it again afterwards.\n\n         If you did not ask for this, ignore this message - your password stays as it is.\n",
        username = username,
        domain = domain,
        link = link,
        ttl = TTL_MINUTES
    );

    let from = format!("no-reply@{domain}");
    let send_result = crate::utils::mailer::send_plain(
        &from,
        &recovery,
        "Reset your Sloth Lee Mail password",
        &body,
    );

    let (emailed, mail_error) = match &send_result {
        Ok(()) => (true, None),
        Err(e) => {
            log::warn!("[Recovery] Could not email {} for '{}': {}", recovery, username, e);
            (false, Some(e.clone()))
        }
    };

    log::info!(
        "[Recovery] '{}' minted a reset token for '{}' (emailed to {}: {})",
        caller.username,
        username,
        recovery,
        emailed
    );

    let resp = AdminSendRecoveryResponse {
        sent_to: recovery,
        token,
        expires_in_minutes: TTL_MINUTES,
        emailed,
        mail_error,
    };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

// ---------------------------------------------------------------------------
// Self-registration approval queue
//
// A signup without an invite code creates an account that cannot sign in and
// queues it in `data/pending_users.json`. Approving removes the queue entry -
// that removal is the activation - and denying deletes the account outright, so
// an unapproved name cannot sit on a mailbox and receive mail that nobody can
// read.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PendingActionRequest {
    pub username: String,
}

#[derive(Serialize)]
struct PendingListResponse {
    entries: Vec<crate::core::pending_users::PendingUser>,
    total: usize,
}

#[derive(Serialize)]
struct PendingApproveResponse {
    username: String,
    approved: bool,
}

/// GET /api/admin/pending - accounts waiting for approval.
pub fn list_pending(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    if let Err(resp) = require_admin(user) {
        return resp;
    }

    let entries = crate::core::pending_users::list();
    let body = serde_json::to_vec(&PendingListResponse {
        total: entries.len(),
        entries,
    })
    .unwrap();
    Response::from_data(body)
        .with_status_code(200)
        .with_header(json_header())
}

/// POST /api/admin/pending/approve - let a queued account sign in.
pub fn approve_pending(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match require_admin(user) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let req: PendingActionRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let username = req.username.trim().to_lowercase();
    if username.is_empty() {
        return error(400, "invalid_username", "No account name given");
    }

    // An account deleted while it sat in the queue leaves a stale entry; drop it
    // instead of approving a name that no longer exists.
    if !user_storage.check_user_exists(&username) {
        let _ = crate::core::pending_users::remove(&username);
        return error(404, "user_not_found", "That account no longer exists");
    }

    match crate::core::pending_users::remove(&username) {
        Ok(true) => {
            log::info!("[Admin] Approved account '{}' (by '{}')", username, caller.username);
            let body = serde_json::to_vec(&PendingApproveResponse {
                username,
                approved: true,
            })
            .unwrap();
            Response::from_data(body)
                .with_status_code(200)
                .with_header(json_header())
        }
        Ok(false) => error(404, "not_pending", "That account is not waiting for approval"),
        Err(e) => {
            log::warn!("[Admin] Could not approve '{}': {}", username, e);
            error(500, "pending_unavailable", "Could not update the approval queue")
        }
    }
}

/// POST /api/admin/pending/deny - delete a queued account.
pub fn deny_pending(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match require_admin(user) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let req: PendingActionRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let username = req.username.trim().to_lowercase();
    if username.is_empty() {
        return error(400, "invalid_username", "No account name given");
    }
    if username == caller.username {
        return error(409, "cannot_delete_self", "An administrator cannot delete their own account");
    }
    if !user_storage.check_user_exists(&username) {
        // Nothing to delete; still clear the queue entry so the name is free.
        let _ = crate::core::pending_users::remove(&username);
        return error(404, "user_not_found", "That account no longer exists");
    }
    if is_last_admin(&user_storage, &username) {
        return error(409, "last_admin", "Cannot delete the last remaining administrator");
    }

    // erase_account() clears the queue entry along with the account.
    erase_account(&user_storage, &email_storage, &username);
    log::info!("[Admin] '{}' denied account '{}'", caller.username, username);

    let msg = serde_json::to_vec(&MessageResponse {
        message: "Account request denied and account removed".into(),
    })
    .unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}
