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
    EmailFlagResponse, EmailFlagsResponse,
    EphemeralStatusItem, EphemeralStatusRequest, EphemeralStatusResponse,
};
use crate::smtp::EmailSendingFSM;
use crate::utils::emailutils;
use crate::core::Email;
use crate::api::request::read_json_body;

/// Upper bound on recipients per send request. Without it, one API call can fan
/// out into an unbounded number of outbound SMTP connections.
const MAX_RECIPIENTS: usize = 100;

/// Build the response for ordinary mail. Ephemeral fields are filled in by the
/// handlers that know about a deleting message.
fn plain_response(email: &Email) -> EmailBytesResponse {
    EmailBytesResponse {
        uid: email.uid,
        read: email.read,
        starred: email.starred,
        data: STANDARD.encode(&email.raw_data),
        message_key: email.message_key.as_ref().map(|k| STANDARD.encode(k)),
        received_at: unix_to_iso(email.timestamp),
        e2ee: email.e2ee,
        ephemeral: None,
        expires_at: None,
        deleted: false,
        from: Some(email.from.clone()),
        alias: crate::core::arrival::get(email.uid),
    }
}

pub fn get_email(
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

    let req: GetEmailRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if !user.emailIds.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    match email_storage.read_email(req.uid) {
        Ok(email) => {
            let mut resp = plain_response(&email);

            // A message that deletes on read is deleted *here*, before its body
            // is handed over. Asking the client to delete it afterwards would be
            // a request, not a rule: the preview path withholds the body for
            // exactly this reason, so this is the only way to read it.
            if let Some(entry) = crate::core::ephemeral::get(email.uid) {
                resp.ephemeral = Some(if entry.deletes_on_read { "read".into() } else { "expire".into() });
                resp.expires_at = entry.expires_at;

                if entry.deletes_on_read {
                    if crate::core::ephemeral::purge_message(&user_storage, &email_storage, &user.username, email.uid) {
                        resp.deleted = true;
                        log::info!("[Ephemeral] '{}' opened and deleted uid={}", user.username, email.uid);
                        if let Err(e) = crate::core::ephemeral::record_read(&entry) {
                            log::warn!("[Ephemeral] Deleted uid={} but could not record the receipt: {}", email.uid, e);
                        }
                    } else {
                        // The copy is still on disk: report that, never the promise.
                        log::warn!("[Ephemeral] Could not delete uid={} for '{}'", email.uid, user.username);
                    }
                }
            }

            let body = serde_json::to_vec(&resp).unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        Err(err) => {
            // Self-heal: the index claims a message the storage no longer has.
            let missing = format!("{}", err).to_lowercase().contains("not found");
            if missing && user_storage.detach_email(&user.username, req.uid) {
                log::warn!(
                    "[Email] Detached UID {} from '{}' — index entry had no blob",
                    req.uid, user.username
                );
            }
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

    let req: GetEmailsBulkRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    
    let allowed_uids: Vec<u128> = req.uids.into_iter()
        .filter(|uid| user.emailIds.contains(uid))
        .collect();

    let emails = email_storage.get_emails_bulk(allowed_uids).unwrap_or_default();
    // One read of the ephemeral store for the whole page, not one per message.
    let ephemeral = crate::core::ephemeral::snapshot();
    let email_responses: Vec<EmailBytesResponse> = emails.iter().map(|e| {
        let mut resp = plain_response(e);
        if let Some(entry) = ephemeral.get(&e.uid) {
            resp.ephemeral = Some(if entry.deletes_on_read { "read".into() } else { "expire".into() });
            resp.expires_at = entry.expires_at;
            if entry.deletes_on_read {
                // The body is deliberately withheld here: a preview fetch must not
                // be able to consume (or retain) a message that deletes on open.
                resp.data = String::new();
                resp.message_key = None;
            }
        }
        resp
    }).collect();

    let resp = EmailsBulkResponse { emails: email_responses };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// POST /email/flags — read/starred state for every email this account owns.
///
/// Deliberately separate from the bulk fetch: this response carries no message
/// data, so a client can restore its mailbox state without decrypting anything.
pub fn email_flags(
    _request: &mut Request,
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

    let mut all: Vec<u128> = user.emailIds.clone();
    all.extend(user.sent_emails.iter().copied());
    all.sort_unstable();
    all.dedup();

    let emails = email_storage.get_emails_bulk(all).unwrap_or_default();
    let flags: Vec<EmailFlagResponse> = emails
        .iter()
        .map(|e| EmailFlagResponse { uid: e.uid, read: e.read, starred: e.starred })
        .collect();

    let body = serde_json::to_vec(&EmailFlagsResponse { flags }).unwrap();
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

    let req: DeleteEmailRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if !user.emailIds.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    
    user_storage.mutate_user(&user.username, |u| u.emailIds.retain(|&id| id != req.uid));
    user_storage.remove_email_from_groups(&user.username, req.uid);

    
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist user storage after email delete: {}", e);
    }

    
    if let Err(_) = email_storage.delete_email(req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to delete email".into(), code: "delete_failed".into() }).unwrap();
        return Response::from_data(err).with_status_code(500).with_header(json_header());
    }
    // Written only after the blob is gone: a log entry for a message that is
    // still there would be worse than no entry at all.
    if let Err(e) = crate::core::mailboxlog::append(&user.username, "deleted", &req.uid.to_string()) {
        log::warn!("[Log] Could not record deletion of {}: {}", req.uid, e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Email deleted".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

/// POST /email/sent/delete - delete one of the caller's own sent copies.
///
/// The inbox delete only ever looked in `emailIds`, so a message deleted from the Sent folder
/// answered 404 and stayed. A sent copy is the sender's own blob (the recipient's copy is a
/// different blob with its own uid), so deleting it touches nobody else's mail.
pub fn delete_sent_email(
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

    let req: DeleteEmailRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if !user.sent_emails.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    user_storage.mutate_user(&user.username, |u| u.sent_emails.retain(|&id| id != req.uid));
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist user storage after sent delete: {}", e);
    }

    if let Err(_) = email_storage.delete_email(req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Failed to delete email".into(), code: "delete_failed".into() }).unwrap();
        return Response::from_data(err).with_status_code(500).with_header(json_header());
    }
    // Same signed log as the inbox: written only after the blob is gone.
    if let Err(e) = crate::core::mailboxlog::append(&user.username, "deleted", &req.uid.to_string()) {
        log::warn!("[Log] Could not record deletion of sent copy {}: {}", req.uid, e);
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

    let req: SetEmailBytesRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
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

    let req: GetRecentEmailsRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
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

/// One shape for every reason a message could not be queued, so both send
/// endpoints answer the same way.
fn schedule_error(e: crate::core::scheduled::QueueError) -> Response<Cursor<Vec<u8>>> {
    use crate::core::scheduled::QueueError;
    let (status, code, message) = match e {
        QueueError::TooMany => (
            409,
            "too_many_scheduled",
            format!(
                "You already have {} messages waiting. Send or cancel one first.",
                crate::core::scheduled::MAX_PENDING_PER_OWNER
            ),
        ),
        QueueError::TooSoon => (400, "send_at_too_soon", "Pick a time at least a minute from now".to_string()),
        QueueError::TooFar => (400, "send_at_too_far", "That is more than a year away".to_string()),
    };
    let err = serde_json::to_vec(&ErrorResponse { error: message, code: code.into() }).unwrap();
    Response::from_data(err).with_status_code(status).with_header(json_header())
}

/// Who this message goes out as.
///
/// The account address is the default. A caller may also send as one of their own
/// switched-on aliases — which is what makes an alias a two-way address rather
/// than a mailbox you can only read. Anything else (someone else's alias, a
/// switched-off one, an address on another domain) is refused rather than
/// quietly replaced: a message that goes out under the wrong name is worse than
/// one that does not go out.
fn sender_address_for(
    user: &User,
    wanted: Option<&str>,
) -> Result<String, Response<Cursor<Vec<u8>>>> {
    let domain = emailutils::get_server_domain();
    let real = format!("{}@{}", user.username, domain);

    let requested = wanted.map(|w| w.trim().to_ascii_lowercase()).filter(|w| !w.is_empty());
    let local = match requested {
        None => return Ok(real),
        Some(value) => value.split('@').next().unwrap_or("").to_string(),
    };
    if local.is_empty() || local == user.username.to_ascii_lowercase() {
        return Ok(real);
    }

    let store = crate::core::aliases::load();
    match store.aliases.get(&local) {
        Some(alias) if alias.username.eq_ignore_ascii_case(&user.username) && alias.disabled_at.is_none() => {
            Ok(format!("{}@{}", local, domain))
        }
        Some(alias) if alias.username.eq_ignore_ascii_case(&user.username) => {
            let err = serde_json::to_vec(&ErrorResponse {
                error: format!("'{}' is switched off — turn it back on to send from it", local),
                code: "alias_disabled".into(),
            })
            .unwrap();
            Err(Response::from_data(err).with_status_code(409).with_header(json_header()))
        }
        _ => {
            let err = serde_json::to_vec(&ErrorResponse {
                error: format!("'{}' is not one of your addresses", local),
                code: "unknown_alias".into(),
            })
            .unwrap();
            Err(Response::from_data(err).with_status_code(400).with_header(json_header()))
        }
    }
}

pub fn send_email(
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

    let req: SendEmailRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Outbound limits: the domain's reputation is shared by every account, so
    // one spammer costs everyone. Counted before the send is attempted, so a
    // failing relay cannot be used to probe for free.
    let recipient_count = req.to.iter().filter(|r| !r.trim().is_empty()).count();
    match crate::core::sendlimit::check_and_count(&user.username, recipient_count, user.userCreated) {
        Ok(_) => {}
        Err(code) => {
            let message = match code {
                "too_many_recipients" => "That is more recipients than one message may have; split it up",
                "daily_limit_reached" => "You have reached today's sending limit on this account",
                _ => "This message cannot be sent",
            };
            let err = serde_json::to_vec(&ErrorResponse {
                error: message.into(),
                code: code.into(),
            })
            .unwrap();
            return Response::from_data(err).with_status_code(429).with_header(json_header());
        }
    }

    let data = match STANDARD.decode(&req.data) {
        Ok(d) => d,
        Err(_) => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Invalid base64 data".into(), code: "invalid_base64".into() }).unwrap();
            return Response::from_data(err).with_status_code(400).with_header(json_header());
        }
    };

    if req.to.is_empty() || req.to.len() > MAX_RECIPIENTS {
        let err = serde_json::to_vec(&ErrorResponse {
            error: format!("Provide between 1 and {} recipients", MAX_RECIPIENTS),
            code: "invalid_recipients".into(),
        }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    // The envelope sender is the authenticated account, never a client-supplied
    // value: honouring 'req.from' would let any user send mail as anyone,
    // including as another local user or as a third-party domain.
    // Outbound quota: there is no relay to throttle, so the limit lives here.
    if let Err(retry_after) = crate::utils::quota::check_and_record(&user.username) {
        let err = serde_json::to_vec(&ErrorResponse {
            error: format!(
                "Sending limit reached. Try again in about {} seconds.",
                retry_after
            ),
            code: "rate_limited".into(),
        })
        .unwrap();
        return Response::from_data(err)
            .with_status_code(429)
            .with_header(json_header());
    }

    let sender_address = match sender_address_for(&user, req.from_alias.as_deref()) {
        Ok(address) => address,
        Err(resp) => return resp,
    };
    if !req.from.trim().is_empty() && !req.from.eq_ignore_ascii_case(&sender_address) {
        log::warn!(
            "[API] User '{}' tried to send with envelope sender '{}' - overriding with '{}'",
            user.username, req.from, sender_address
        );
    }

    // A message for later is stored now and released by the sweeper through the
    // same delivery path. The sending limits were counted above, when the
    // message was accepted: queueing cannot be used to exceed them.
    if let Some(at) = req.send_at.filter(|at| *at > 0) {
        match crate::core::scheduled::queue(
            &user.username,
            req.to.clone(),
            crate::core::scheduled::Kind::Raw,
            req.data.clone(),
            req.subject.clone(),
            at,
        ) {
            Ok(item) => {
                let body = serde_json::to_vec(&serde_json::json!({
                    "scheduled": true, "id": item.id, "send_at": item.send_at, "to": item.to,
                })).unwrap();
                return Response::from_data(body).with_status_code(200).with_header(json_header());
            }
            Err(e) => return schedule_error(e),
        }
    }

    // Delivery targets are resolved from each recipient's own domain. Taking a
    // host and port from the request body would turn this endpoint into an
    // arbitrary-destination TCP client against the server's internal network.
    if !req.smtp_host.trim().is_empty() {
        log::warn!(
            "[API] Ignoring client-supplied smtp_host '{}' from user '{}'",
            req.smtp_host, user.username
        );
    }

    // One delivery path for both an immediate send and a released scheduled
    // message, so signing and MX resolution cannot drift apart.
    let (delivered, failures) = emailutils::deliver_raw(&sender_address, &req.to, &data);

    if delivered == 0 {
        let err = serde_json::to_vec(&ErrorResponse {
            error: format!("Delivery failed: {}", failures.join("; ")),
            code: "smtp_error".into(),
        }).unwrap();
        return Response::from_data(err).with_status_code(502).with_header(json_header());
    }

    let msg = serde_json::to_vec(&MessageResponse {
        message: if failures.is_empty() {
            "Email sent".to_string()
        } else {
            format!("Email sent to {} of {} recipients", delivered, req.to.len())
        },
    }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
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

    let req: MarkEmailReadRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
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

    let req: MarkEmailReadRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
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

    let req: SetEmailStarredRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
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

    let req: GetPublicKeysRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
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
            if let Ok(mut fsm) = EmailSendingFSM::connect(&mx_host, 25, emailutils::get_helo_domain()) {
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

    let req: SendEncryptedRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // An edit must name a time. Without one this would fall through to the normal
    // send path and deliver a *second* copy while the held one stayed queued — the
    // worst possible outcome, because the sender thinks they corrected it once.
    let editing = req.replace_id.as_deref().map(str::trim).filter(|id| !id.is_empty());
    if editing.is_some() && req.send_at.filter(|at| *at > 0).is_none() {
        let err = serde_json::to_vec(&ErrorResponse {
            error: "An edited message still needs a time — it is still held".into(),
            code: "replace_needs_time".into(),
        })
        .unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    // Held for later: store the request as it arrived and let the sweeper replay
    // it through this same endpoint, so a scheduled message is encrypted, saved
    // and delivered by exactly the code that sends one now.
    if let Some(at) = req.send_at.filter(|at| *at > 0) {
        // Strip the scheduling fields from what is stored: the held copy must be
        // a "send now" request, or releasing it would queue it again.
        let held = serde_json::to_value(&req).ok().map(|mut value| {
            if let Some(obj) = value.as_object_mut() {
                obj.remove("send_at");
                obj.remove("subject");
                // A released copy must not try to edit anything: the id it names
                // is what it was, not what it is about to become.
                obj.remove("replace_id");
            }
            value
        });
        let payload = match held.and_then(|value| serde_json::to_string(&value).ok()) {
            Some(p) => p,
            None => {
                log::error!("[API] Could not serialise a scheduled send");
                let err = serde_json::to_vec(&ErrorResponse {
                    error: "Could not hold that message for later".into(),
                    code: "schedule_failed".into(),
                }).unwrap();
                return Response::from_data(err).with_status_code(500).with_header(json_header());
            }
        };
        let to: Vec<String> = req.recipients.keys().cloned().collect();
        let replacing = editing;

        let queued = match replacing {
            Some(id) => crate::core::scheduled::reschedule(
                &user.username,
                id,
                to,
                payload,
                req.subject.clone(),
                at,
            )
            .map(|maybe| maybe.map(|item| (item, true))),
            None => crate::core::scheduled::queue(
                &user.username,
                to,
                crate::core::scheduled::Kind::Encrypted,
                payload,
                req.subject.clone(),
                at,
            )
            .map(|item| Some((item, false))),
        };

        match queued {
            Ok(Some((item, replaced))) => {
                let body = serde_json::to_vec(&serde_json::json!({
                    "scheduled": true,
                    "replaced": replaced,
                    "id": item.id,
                    "send_at": item.send_at,
                    "to": item.to,
                }))
                .unwrap();
                return Response::from_data(body).with_status_code(200).with_header(json_header());
            }
            // Nothing of theirs is pending under that id: one answer for "already
            // sent", "already cancelled" and "not yours", so ids cannot be probed.
            Ok(None) => {
                let err = serde_json::to_vec(&ErrorResponse {
                    error: "That message has already gone, or cannot be edited".into(),
                    code: "not_editable".into(),
                })
                .unwrap();
                return Response::from_data(err).with_status_code(409).with_header(json_header());
            }
            Err(e) => return schedule_error(e),
        }
    }

    if req.recipients.is_empty() || req.recipients.len() > MAX_RECIPIENTS {
        let err = serde_json::to_vec(&ErrorResponse {
            error: format!("Provide between 1 and {} recipients", MAX_RECIPIENTS),
            code: "invalid_recipients".into(),
        }).unwrap();
        return Response::from_data(err).with_status_code(400).with_header(json_header());
    }

    let domain = emailutils::get_server_domain();
    // Outbound quota: there is no relay to throttle, so the limit lives here.
    if let Err(retry_after) = crate::utils::quota::check_and_record(&user.username) {
        let err = serde_json::to_vec(&ErrorResponse {
            error: format!(
                "Sending limit reached. Try again in about {} seconds.",
                retry_after
            ),
            code: "rate_limited".into(),
        })
        .unwrap();
        return Response::from_data(err)
            .with_status_code(429)
            .with_header(json_header());
    }

    let sender_address = match sender_address_for(&user, req.from_alias.as_deref()) {
        Ok(address) => address,
        Err(resp) => return resp,
    };

    // Disappearing mail, if the sender asked for it. Enforceable only for local
    // mailboxes: another provider's copy is theirs, not ours to delete.
    let ephemeral_policy = req.ephemeral.filter(|policy| !policy.is_noop());

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
        // Server clock, not the client's: a caller-supplied timestamp can be set
        // arbitrarily far in the past or future to reorder or hide a sent message.
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(req.localcopy.timestamp),
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
    // In place under the storage lock: replacing the record drops concurrent writes.
    user_storage.mutate_user(&user.username, |u| {
        if !u.sent_emails.contains(&sent_uid) {
            u.sent_emails.push(sent_uid);
        }
    });
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist user storage after sent email: {}", e);
    }

    // --- 2. For each recipient, DKIM-sign (if available) and send via SMTP ---
    let dkim_signer = emailutils::get_dkim_signer();
    let mut delivery_results = Vec::new();

    // Group recipients by domain for efficient delivery
    let mut by_domain: std::collections::HashMap<String, Vec<(String, Vec<u8>, bool)>> = std::collections::HashMap::new();
    for (address, payload) in &req.recipients {
        // A recipient whose mailbox lives on this server must not leave it.
        // Sending their copy out over SMTP and re-parsing it on the way back is
        // what used to strip the AES key from internal mail, leaving ciphertext
        // that its owner could never open.
        let local_username = address
            .rsplit_once('@')
            .filter(|(_, d)| d.eq_ignore_ascii_case(&emailutils::get_server_domain()))
            .map(|(l, _)| l.to_string());

        if let Some(username) = local_username {
            if let Some(recipient_user) = user_storage.get_user(&username) {
                let body = match STANDARD.decode(&payload.data_encrypted) {
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
                let enc_key = STANDARD.decode(&payload.aes_encrypted).ok().filter(|k| !k.is_empty());
                let email = Email {
                    uid: emailutils::generate_email_uid(&recipient_user),
                    secure: payload.e2ee,
                    read: false,
                    starred: false,
                    e2ee: payload.e2ee,
                    userid: recipient_user.uid,
                    from: sender_address.clone(),
                    to: vec![address.clone()],
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    publicKeyHash: recipient_user
                        .publicKey
                        .as_ref()
                        .map(crate::utils::cryptography::hash_public_key)
                        .unwrap_or(crate::utils::cryptography::Sha256Hash([0u8; 32])),
                    raw_data: body,
                    message_key: enc_key,
                };
                match email_storage.save_email(&email) {
                    Ok(_) => {
                        user_storage.mutate_user(&username, |u| {
                            if !u.emailIds.contains(&email.uid) {
                                u.emailIds.push(email.uid);
                            }
                        });
                        user_storage.add_email_to_matching_groups(&username, email.uid, &email.from);
                        let _ = user_storage.save_to_file();

                        // Record the rule before claiming the delivery: if it cannot
                        // be written, take the copy back out. A message delivered
                        // under a promise the server cannot keep is worse than one
                        // that never arrived.
                        if let Some(policy) = ephemeral_policy {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let entry = crate::core::ephemeral::Entry {
                                uid: email.uid,
                                owner: username.clone(),
                                owner_uid: recipient_user.uid,
                                sender: format!("{}@{}", user.username, emailutils::get_server_domain()),
                                sender_uid: sent_uid,
                                deletes_on_read: policy.deletes_on_read,
                                expires_at: policy.expires_at(now),
                                created_at: now,
                            };
                            if let Err(e) = crate::core::ephemeral::register(entry) {
                                log::error!(
                                    "[API] Rolling back local delivery to '{}': could not record the disappearing rule: {}",
                                    address, e
                                );
                                let _ = email_storage.delete_email(email.uid);
                                user_storage.detach_email(&username, email.uid);
                                let _ = user_storage.save_to_file();
                                delivery_results.push(DeliveryResult {
                                    address: address.clone(),
                                    success: false,
                                    error: Some("Could not apply the disappearing rule; nothing was delivered".into()),
                                });
                                continue;
                            }
                        }

                        // A message from another mailbox on this server is still
                        // a message: the recipient should hear about it the same way.
                        crate::core::push::notify_async(
                            &username,
                            "New mail",
                            &format!("From {}@{}", user.username, emailutils::get_server_domain()),
                        );

                        delivery_results.push(DeliveryResult {
                            address: address.clone(),
                            success: true,
                            error: None,
                        });
                        log::info!(
                            "[API] Local delivery to '{}' stored directly (e2ee={})",
                            address, payload.e2ee
                        );
                    }
                    Err(e) => {
                        log::error!("[API] Local delivery to '{}' failed: {}", address, e);
                        delivery_results.push(DeliveryResult {
                            address: address.clone(),
                            success: false,
                            error: Some("Could not be stored".into()),
                        });
                    }
                }
                continue;
            }
        }

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
            let mut fsm = match EmailSendingFSM::connect(&mx_host, 25, emailutils::get_helo_domain()) {
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

    let req: GetRecentEmailsRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
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

    let req: GetEmailRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if !user.sent_emails.contains(&req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    match email_storage.read_email(req.uid) {
        Ok(email) => {
            let resp = plain_response(&email);
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

    let req: GetEmailsBulkRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let allowed_uids: Vec<u128> = req.uids.into_iter()
        .filter(|uid| user.sent_emails.contains(uid))
        .collect();

    let emails = email_storage.get_emails_bulk(allowed_uids).unwrap_or_default();
    let email_responses: Vec<EmailBytesResponse> = emails.iter().map(plain_response).collect();

    let resp = EmailsBulkResponse { emails: email_responses };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// POST /api/email/ephemeral — how a disappearing message stands, from either
/// side. The recipient's own copy reports "armed" (and its timer); the sender's
/// sent copy reports "read" once the recipient opened it, because the recipient's
/// copy no longer exists to ask about.
pub fn ephemeral_status(
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

    let req: EphemeralStatusRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // One read of the store for the whole request.
    let entries = crate::core::ephemeral::snapshot();
    let mut items: Vec<EphemeralStatusItem> = Vec::new();

    for raw_uid in req.uids {
        let uid = match raw_uid.value() {
            Some(uid) => uid,
            None => continue, // an id we cannot read is an id we cannot answer for
        };
        // The recipient's copy: only answered for mail they actually own.
        if user.emailIds.contains(&uid) {
            if let Some(entry) = entries.get(&uid) {
                items.push(EphemeralStatusItem {
                    uid,
                    state: "armed".into(),
                    read_at: None,
                    expires_at: entry.expires_at,
                    recipient: None,
                });
            }
            continue;
        }

        // The sender's copy: a receipt means the other side is gone.
        if user.sent_emails.contains(&uid) {
            if let Some(receipt) = crate::core::ephemeral::receipt_for(uid) {
                items.push(EphemeralStatusItem {
                    uid,
                    state: "read".into(),
                    read_at: Some(receipt.read_at),
                    expires_at: None,
                    recipient: Some(receipt.recipient),
                });
            } else if let Some(entry) = entries.values().find(|e| e.sender_uid == uid) {
                items.push(EphemeralStatusItem {
                    uid,
                    state: "armed".into(),
                    read_at: None,
                    expires_at: entry.expires_at,
                    recipient: Some(entry.owner.clone()),
                });
            }
        }
    }

    let body = serde_json::to_vec(&EphemeralStatusResponse { items }).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}
