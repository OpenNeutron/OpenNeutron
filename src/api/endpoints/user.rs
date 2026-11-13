use serde_json;
use base64::Engine as _;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User};
use crate::core::user::validate_username;
use crate::api::dto::{UserDto, UserKeyResponse, CreateUserRequest, SetupPasswordRequest, UserSetCredentialsRequest, ResetWithTokenRequest, SetRecoveryKeyRequest, RecoveryKeyStatusResponse, RecoveryFetchRequest, RecoveryFetchResponse, RecoveryRestoreRequest, ErrorResponse, MessageResponse, json_header};
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

/// What the registration approval gate decided for one signup.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// The account may be used immediately.
    Immediate,
    /// The account is created but cannot sign in until an operator approves it.
    Pending,
    /// A code was presented and did not claim: tell the person, do not queue.
    RejectCode,
}

/// Decide how a signup is admitted.
///
/// Without manual approval every signup is immediate. With it, a claimed code
/// admits at once and an absent code queues the account. A *presented* code that
/// does not claim is a mistake or a spent invite - queueing that would look like
/// success while the person waits for an approval nobody asked for.
fn admission(requires_approval: bool, has_code: bool, code_claimed: bool) -> Admission {
    if !requires_approval || code_claimed {
        Admission::Immediate
    } else if has_code {
        Admission::RejectCode
    } else {
        Admission::Pending
    }
}

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

/// POST /user/key — the caller's own key material.
///
/// The private key is stored wrapped with the login password, so returning it to
/// an authenticated session reveals nothing without that password. It exists so a
/// browser that lost its localStorage (new device, cleared storage, switched
/// profiles) can still unlock, instead of being permanently stuck on
/// "no encrypted key found in storage".
pub fn get_own_key(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };

    let body = serde_json::to_vec(&UserKeyResponse {
        salt: user.salt.clone(),
        public_key: user.publicKey.as_ref().map(|k| base64::engine::general_purpose::STANDARD.encode(&k.0)),
        encrypted_private_key: user.encrypted_private_key.clone(),
    })
    .unwrap();

    Response::from_data(body).with_status_code(200).with_header(json_header())
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

/// GET /signup/challenge - hand out a proof-of-work puzzle.
pub fn signup_challenge(
    _request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let challenge = crate::utils::pow::issue();
    Response::from_data(serde_json::to_vec(&challenge).unwrap())
        .with_status_code(200)
        .with_header(json_header())
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

    // Proof of work first: it is the cheapest thing to check and the most
    // expensive thing to fake.
    let pow_challenge = req.pow_challenge.clone().unwrap_or_default();
    let pow_nonce = req.pow_nonce.clone().unwrap_or_default();
    if let Err(code) = crate::utils::pow::verify(&pow_challenge, &pow_nonce) {
        let message = match code {
            "pow_expired" => "That signup check expired; reload the page and try again",
            "pow_invalid" => "That signup check is not valid; reload the page and try again",
            _ => "Complete the signup check before creating an account",
        };
        return error(400, code, message);
    }

    let username = req.username.trim().to_lowercase();
    if let Err(reason) = validate_username(&username) {
        return error(400, "invalid_username", reason);
    }
    if let Err(resp) = validate_credential_lengths(Some(&req.password), req.encrypted_private_key.as_ref()) {
        return resp;
    }

    let public_key = match req.public_key.as_ref() {
        Some(pk) => match public_key_from_string(pk) {
            Ok(key) => Some(key),
            Err(reason) => return error(400, "invalid_public_key", &reason),
        },
        None => None,
    };

    if user_storage.check_user_exists(&username) {
        return error(409, "username_taken", "Username already taken");
    }

    // One account per address: proof of work prices a signup, this bounds how
    // many one machine can take. The proxy header decides that; the socket
    // address is only used to make the approval queue entry informative when the
    // API is called directly (local tooling, tests).
    let proxied_address = crate::core::signup_ip::client_address(request.headers());
    let queue_address = if proxied_address.is_empty() {
        request
            .remote_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default()
    } else {
        proxied_address.clone()
    };

    // Approval gate. An account created here is not usable until an operator
    // approves it; a code the operator handed out still admits it at once, so
    // existing invites keep working.
    let has_code = req
        .invite_code
        .as_deref()
        .map(|c| !c.trim().is_empty())
        .unwrap_or(false);
    let code_claimed = if has_code {
        req.invite_code
            .as_deref()
            .map(crate::api::endpoints::waitlist::claim_code)
            .unwrap_or(false)
    } else {
        false
    };
    let pending = match admission(
        crate::config::get().server.registration_requires_approval,
        has_code,
        code_claimed,
    ) {
        Admission::Immediate => false,
        Admission::Pending => true,
        Admission::RejectCode => {
            return error(
                403,
                "invite_required",
                "That invite code is not valid, or it has already been used",
            )
        }
    };

    let per_ip_enabled = crate::config::get().server.one_account_per_ip;
    if per_ip_enabled {
        if let Err(code) = crate::core::signup_ip::claim(&proxied_address, &username) {
            let message = if code == "address_already_registered" {
                "An account has already been created from this address"
            } else {
                "Signup is temporarily unavailable"
            };
            return error(409, code, message);
        }
    }

    // The first account on a server with no *usable* administrator becomes the
    // administrator. A seeded admin with no password is excluded: its setup token
    // is printed to the log once and cannot be used from the web client (which
    // hashes whatever you type), so counting it would leave the deployment
    // administered by nobody.
    //
    // A pending account is never an administrator: an unapproved stranger must
    // not become admin just by being first in the queue.
    let bootstrap_admin = !pending
        && !user_storage
            .get_all_users()
            .iter()
            .any(|u| u.is_admin && u.passwordHash.is_some());

    // Queue before the account exists. Login checks both the queue and the
    // account store, so this order fails closed: a crash in between leaves a
    // queue entry with no account (login says "wrong password") rather than an
    // account nobody reviewed.
    if pending {
        let user_agent = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("User-Agent"))
            .map(|h| h.value.to_string())
            .unwrap_or_default();
        if let Err(e) = crate::core::pending_users::add(&username, &queue_address, &user_agent) {
            log::warn!("[API] Could not queue signup for '{}': {}", username, e);
            return error(
                503,
                "signup_unavailable",
                "Signup is temporarily unavailable; try again in a moment",
            );
        }
    }

    // From here on the account either exists or the address claim is released,
    // so a failed signup does not burn the visitor's address.
    // The registered password token becomes a one-time setup token rather than a
    // stored password. The user authenticates once with it, receives the
    // server-generated salt, and only then generates and wraps the key pair via
    // '/api/user/setup'. Wrapping at registration time - before the salt exists -
    // produced keys that could never be decrypted again on any later login.
    let mut user = User::create_provisioned_user(username.clone(), bootstrap_admin);
    user.setup_token = Some(req.password.clone());
    if let Some(key) = public_key {
        user.publicKey = Some(key);
    }
    if let Some(blob) = req.encrypted_private_key {
        user.encrypted_private_key = Some(blob);
    }

    user_storage.add_user(user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after register: {}", e);
        // Do not hold an address hostage for an account that was never stored,
        // and do not leave a queue entry that can never be approved.
        crate::core::signup_ip::release_for(&username);
        if pending {
            let _ = crate::core::pending_users::remove(&username);
        }
        return error(500, "signup_failed", "Could not create the account; try again");
    }
    log::info!(
        "[API] Account '{}' self-registered (pending={}, bootstrap_admin={})",
        username,
        pending,
        bootstrap_admin
    );

    if pending {
        let body = serde_json::to_vec(&serde_json::json!({
            "pending": true,
            "message": "Your account is waiting for approval",
        }))
        .unwrap();
        return Response::from_data(body)
            .with_status_code(202)
            .with_header(json_header());
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "User created".into() }).unwrap();
    Response::from_data(msg).with_status_code(201).with_header(json_header())
}

pub fn setup_password(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };

    // "Setup" means "finish this account": either it has no password yet (an
    // account an administrator created) or it has a password but no keys yet (a
    // self-signed-up account, whose password was chosen at registration). An
    // account that already has keys is configured and must not be re-keyed here.
    let needs_password = user.needs_force_reset();
    if !needs_password && user.encrypted_private_key.is_some() {
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
        Some(u) if u.needs_force_reset() || u.encrypted_private_key.is_none() => u,
        Some(_) => return error(409, "password_already_set", "Password already set"),
        None => return error(401, "unauthorized", "Unauthorized"),
    };

    let mut updated_user = current;
    // A self-signed-up account keeps the password it registered with: the caller
    // is authenticated, but this endpoint is not a password reset, and letting it
    // write one here would turn a session token into a credential change.
    if needs_password {
        updated_user.passwordHash = Some(req.password);
        updated_user.seal_password();
    }
    updated_user.publicKey = Some(public_key);
    updated_user.encrypted_private_key = Some(req.encrypted_private_key);
    // The one-time provisioning secret must not survive as a second password.
    updated_user.setup_token = None;
    user_storage.update_user(updated_user);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after setup_password: {}", e);
    }
    log::info!("[API] Account '{}' completed first-time setup", user.username);

    // Anything sent to this address before it had a key has been held; now it
    // can be encrypted to the account and delivered.
    if let Some(fresh) = user_storage.get_user(&user.username) {
        let held = crate::core::pending::count(&fresh.username);
        if held > 0 {
            crate::core::pending::drain(&fresh.username, &fresh, &email_storage, &user_storage);
        }
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
    updated.seal_password();
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

/// Public: redeem a reset token mailed to the account's recovery address.
///
/// No session is involved - the token *is* the proof. Only its SHA-256 is on
/// disk, it is single-use, and it expires, so a leaked 'users.bin' cannot be
/// replayed to take over an account.
pub fn reset_with_token(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let req: ResetWithTokenRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let token = req.token.trim();
    let credentials = req.credentials.trim();
    if token.len() < 32 {
        return error(400, "invalid_token", "That reset link is invalid or has expired");
    }
    if credentials.len() < 20 || credentials.len() > MAX_PASSWORD_HASH_LEN {
        return error(400, "invalid_credentials", "The new password could not be accepted");
    }

    let wanted = crate::core::user::sha256_hex(token);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Expired tokens are treated exactly like unknown ones.
    let recovery = crate::core::recovery::store();
    let username = match recovery.find_by_token_hash(&wanted, now) {
        Some(name) => name,
        None => return error(400, "invalid_token", "That reset link is invalid or has expired"),
    };

    let mut target = match user_storage.get_user(&username) {
        Some(u) => u,
        None => return error(400, "invalid_token", "That reset link is invalid or has expired"),
    };

    let username = target.username.clone();
    // The stored hash is peppered with the account salt, so the salt has to be
    // final before sealing - rotating it afterwards makes the new password
    // unverifiable.
    target.salt = crate::core::user::gen_salt();
    target.passwordHash = Some(credentials.to_string());
    target.seal_password();
    target.setup_token = None;
    // The old private key was wrapped with the old password, which nobody can
    // produce any more. Clearing it lets the client mint a fresh identity on
    // first sign-in instead of dead-ending on an unopenable key.
    target.encrypted_private_key = None;
    target.publicKey = None;
    target.revoke_existing_sessions();

    user_storage.update_user(target);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Recovery] Failed to persist reset for '{}': {}", username, e);
    }
    let _ = recovery.clear_token(&username);
    log::info!("[Recovery] Password reset completed for '{}'", username);

    let body = serde_json::to_vec(&MessageResponse {
        message: "Password updated. Sign in with your new password to create a new key.".into(),
    })
    .unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Authenticated: store the recovery-key wrapping of the caller's own key.
pub fn set_recovery_key(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };
    let req: SetRecoveryKeyRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let wrapped = req.wrapped_key.trim();
    let salt = req.kdf_salt.trim();
    let proof = req.auth_proof.trim();

    if wrapped.len() < 32 || wrapped.len() > MAX_ENCRYPTED_KEY_LEN {
        return error(400, "invalid_key", "That recovery key blob was not accepted");
    }
    if salt.is_empty() || salt.len() > 128 {
        return error(400, "invalid_salt", "That salt was not accepted");
    }
    if proof.len() != 64 || !proof.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error(400, "invalid_proof", "That recovery proof was not accepted");
    }

    // Store only the hash of the proof: a leaked recovery.json then yields
    // neither the secret nor the wrapping key.
    let proof_hash = crate::core::user::sha256_hex(&proof.to_lowercase());
    if let Err(e) = crate::core::recovery::store().set_key(
        &caller.username,
        wrapped.to_string(),
        salt.to_string(),
        proof_hash,
        now_secs(),
    ) {
        log::warn!("[Recovery] Could not store recovery key for '{}': {}", caller.username, e);
        return error(500, "storage_error", "Could not store the recovery key");
    }
    log::info!("[Recovery] '{}' created a recovery key", caller.username);

    let body = serde_json::to_vec(&MessageResponse {
        message: "Recovery key saved".into(),
    })
    .unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// Authenticated: does this account have a recovery key, and when was it used?
pub fn recovery_key_status(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let caller = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };
    let entry = crate::core::recovery::store().get(&caller.username);
    let resp = RecoveryKeyStatusResponse {
        set: entry.wrapped_key.is_some(),
        set_at: entry.key_set_at,
        used_at: entry.key_used_at,
    };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// Public: hand back the wrapped key so a client that holds the recovery secret
/// can unwrap it locally. This is ciphertext - useless without the secret - and
/// it is the only way to recover the *key* rather than just the password.
pub fn fetch_recovery_blob(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let req: RecoveryFetchRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let username = req.username.trim().to_lowercase();
    if user_storage.get_user(&username).is_none() {
        return error(404, "not_found", "No recovery key on file for that account");
    }
    let account_salt = user_storage.get_user(&username).map(|u| u.salt).unwrap_or_default();
    match crate::core::recovery::store().wrapped_key(&username) {
        Some((wrapped_key, kdf_salt, set_at)) => {
            let body = serde_json::to_vec(&RecoveryFetchResponse {
                wrapped_key,
                kdf_salt,
                account_salt,
                set_at,
            })
            .unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        None => error(404, "not_found", "No recovery key on file for that account"),
    }
}

/// Public: redeem a recovery key. The client proves possession with a one-way
/// proof derived from the secret, then hands back the private key re-wrapped
/// under the new password. The key itself is unchanged, so old mail still reads.
pub fn restore_with_recovery_key(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let req: RecoveryRestoreRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let username = req.username.trim().to_lowercase();
    let proof = req.auth_proof.trim();
    let credentials = req.credentials.trim();

    if proof.len() != 64 || !proof.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error(400, "invalid_proof", "That recovery key did not match this account");
    }
    if credentials.len() < 20 || credentials.len() > MAX_PASSWORD_HASH_LEN {
        return error(400, "invalid_credentials", "The new password could not be accepted");
    }
    if req.wrapped_key.trim().len() < 32 || req.wrapped_key.trim().len() > MAX_ENCRYPTED_KEY_LEN {
        return error(400, "invalid_key", "The re-wrapped key was not accepted");
    }

    let store = crate::core::recovery::store();
    let mut target = match user_storage.get_user(&username) {
        Some(u) => u,
        None => return error(400, "invalid_proof", "That recovery key did not match this account"),
    };
    if !store.proof_matches(&username, &crate::core::user::sha256_hex(&proof.to_lowercase())) {
        log::warn!("[Recovery] Rejected recovery attempt for '{}': proof mismatch", username);
        return error(400, "invalid_proof", "That recovery key did not match this account");
    }

    // The salt is deliberately NOT rotated: the client wrapped the recovered
    // key with the account's existing salt, and the key must stay the same for
    // old mail to remain readable.
    target.passwordHash = Some(credentials.to_string());
    target.seal_password();
    target.setup_token = None;
    // Same private key, newly wrapped: the public key is untouched, which is
    // exactly why previously received mail still decrypts.
    target.encrypted_private_key = Some(req.wrapped_key.trim().to_string());
    target.revoke_existing_sessions();

    user_storage.update_user(target);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Recovery] Failed to persist recovery restore for '{}': {}", username, e);
        return error(500, "storage_error", "Could not save the account");
    }
    // One use only: the same recovery key must not work twice.
    let _ = store.mark_key_used(&username, now_secs());
    log::info!("[Recovery] Account '{}' restored with a recovery key", username);

    let body = serde_json::to_vec(&MessageResponse {
        message: "Account restored. Sign in with your new password.".into(),
    })
    .unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// POST /user/delete-account - the account holder closing their own mailbox.
///
/// Requires the password token, so a borrowed session alone cannot destroy an
/// account. Everything tied to the account goes with it: mail, blobs, recovery
/// record, second factor, sessions and the address claim.
pub fn delete_own_account(
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

    #[derive(serde::Deserialize)]
    struct DeleteOwnRequest {
        /// The same client-side password token that login accepts.
        password: String,
    }

    let req: DeleteOwnRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match user.passwordHash.as_deref() {
        // Same verification the login uses: the stored value is a peppered
        // bcrypt hash, so a plain string comparison would always fail.
        Some(_) if user.verify_password_peppered(&req.password) => {}
        Some(_) => {
            let err = serde_json::to_vec(&ErrorResponse {
                error: "That password is not correct".into(),
                code: "invalid_password".into(),
            }).unwrap();
            return Response::from_data(err).with_status_code(403).with_header(json_header());
        }
        None => {
            let err = serde_json::to_vec(&ErrorResponse {
                error: "This account has no password set".into(),
                code: "no_password".into(),
            }).unwrap();
            return Response::from_data(err).with_status_code(409).with_header(json_header());
        }
    }

    let username = user.username.clone();
    let email_ids = user_storage.delete_user(&username);
    crate::core::signup_ip::release_for(&username);
    if let Err(e) = crate::core::recovery::store().remove(&username) {
        log::warn!("[Account] Could not clear recovery record for '{}': {}", username, e);
    }
    if let Err(e) = crate::core::twofactor::disable(&username) {
        log::warn!("[Account] Could not clear two-factor entry for '{}': {}", username, e);
    }
    crate::core::sessions::clear_user(&username);
    email_storage.delete_emails_for_user(&email_ids);
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Account] Failed to persist after self-deletion: {}", e);
    }
    log::info!("[Account] '{}' deleted their own account", username);

    let msg = serde_json::to_vec(&MessageResponse { message: "Account deleted".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_manual_approval_every_signup_is_immediate() {
        assert_eq!(admission(false, false, false), Admission::Immediate);
        assert_eq!(admission(false, true, false), Admission::Immediate);
    }

    #[test]
    fn a_claimed_code_admits_at_once() {
        assert_eq!(admission(true, true, true), Admission::Immediate);
    }

    #[test]
    fn no_code_under_manual_approval_queues_the_account() {
        assert_eq!(admission(true, false, false), Admission::Pending);
    }

    #[test]
    fn a_code_that_does_not_claim_is_rejected_instead_of_queued() {
        assert_eq!(admission(true, true, false), Admission::RejectCode);
    }
}
