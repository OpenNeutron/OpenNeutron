mod smtp;
mod utils;
mod core;
mod api;
mod config;

use std::io::{Read, Result, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use rustls::ServerConfig;
use log::{info, warn, error, debug};

use smtp::{EmailReceivingFSM, MaybeTlsStream};
use utils::make_tls_config;
use core::UserStorage;
use core::Email;
use core::EmailStorage;
use tiny_http::Server;
use core::get_or_init_storage;
use std::sync::Arc;
use api::Router;

pub enum CommandResult {
    Continue,
    UpgradeToTls,
    Close,
}

fn init_logger(level: &str) {
    let level_filter = match level {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info"  => log::LevelFilter::Info,
        "warn"  => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _       => log::LevelFilter::Info,
    };
    env_logger::Builder::new()
        .filter_level(level_filter)
        .format_timestamp_secs()
        .init();
}

fn main() -> Result<()> {
    let cfg = config::Config::load("config.yml").unwrap_or_else(|e| {
        eprintln!("[Config] Failed to load config.yml: {}. Using defaults.", e);
        config::Config::default()
    });
    config::init(cfg.clone());
    init_logger(&cfg.logging.level);
    info!("Starting OpenNeutron Mail Server");
    utils::jwt::init();
    utils::password::init_master(&utils::jwt::pepper_material());

    let tls_config = make_tls_config(&cfg.tls);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", cfg.server.smtp_port))?;
    let user_storage: Arc<UserStorage> = Arc::new(get_or_init_storage(cfg.storage.users_file.clone(), cfg.server.domain.clone()));
    let email_storage: Arc<EmailStorage> = Arc::new(EmailStorage::new(cfg.storage.blobs_dir.clone()));
    // Recovery addresses/reset tokens live beside the account store but in their
    // own file: 'users.bin' is bincode, so its layout must never change to add a
    // field (doing so makes every existing store misparse).
    core::recovery::init("data/recovery.json");

    // Reconcile before serving: a blob on disk whose uid is missing from its
    // owner's index is invisible in the mailbox, and older builds could drop ids
    // when a login replaced the whole user record. This re-attaches them.
    reconcile_orphaned_emails(&user_storage, &email_storage);

    let user_storage_clone = Arc::clone(&user_storage);
    let email_storage_clone = Arc::clone(&email_storage);
    let api_port = cfg.server.api_port;
    let domain = cfg.server.domain.clone();
    let dkim_enabled = cfg.dkim.as_ref().map(|d| d.enabled).unwrap_or(true);

    // Init global domain for outgoing SMTP
    utils::emailutils::init_server_domain(cfg.server.domain.clone());

    // The name we announce over SMTP. Defaults to 'mail.<domain>' because that is
    // the host that carries the A/AAAA records and the reverse DNS entry; using the
    // bare domain announces a name whose A record points at a web host instead.
    let helo_name = cfg
        .server
        .hostname
        .clone()
        .unwrap_or_else(|| format!("mail.{}", cfg.server.domain));
    info!("[SMTP] Announcing as '{}'", helo_name);
    utils::emailutils::init_helo_domain(helo_name.clone());

    // Try to load DKIM signing key
    if let Some(ref dkim_cfg) = cfg.dkim {
        if let (Some(pk_path), Some(selector)) = (&dkim_cfg.private_key_path, &dkim_cfg.selector) {
            match utils::DkimSigner::load(pk_path, &cfg.server.domain, selector) {
                Ok(signer) => {
                    info!("[DKIM] Loaded signing key from '{}' (selector='{}')", pk_path, selector);
                    utils::emailutils::init_dkim_signer(signer);
                }
                Err(e) => {
                    warn!("[DKIM] Failed to load signing key: {} - outgoing mail will not be DKIM-signed", e);
                }
            }
        }
    }

    
    thread::spawn(move || {
        run_server(
            user_storage_clone,
            email_storage_clone,
            api_port,
        ).unwrap();
    });

    // Disappearing mail whose timer ran out. A minute-granularity sweep is
    // enough for a feature measured in hours and days, and it runs here because
    // this thread owns the process lifetime.
    {
        let sweeper_users = Arc::clone(&user_storage);
        let sweeper_mail = Arc::clone(&email_storage);
        thread::spawn(move || loop {
            crate::core::ephemeral::sweep(&sweeper_users, &sweeper_mail);
            crate::core::trash::sweep(&sweeper_users, &sweeper_mail);
            crate::core::notes::sweep();
            crate::core::arrival::sweep_old(crate::core::arrival::now());
            thread::sleep(std::time::Duration::from_secs(60));
        });

        // Messages held for a chosen time. Thirty seconds is close enough to the
        // minute people pick.
        let sweeper_port = api_port;
        thread::spawn(move || loop {
            for item in crate::core::scheduled::due(crate::core::scheduled::now()) {
                use crate::core::scheduled::Kind;
                match item.kind {
                    Kind::Raw => {
                        let sender = format!("{}@{}", item.owner, crate::utils::emailutils::get_server_domain());
                        let data = match crate::utils::decode_payload(&item.data) {
                            Ok(d) => d,
                            Err(e) => {
                                log::warn!("[Scheduled] '{}' has an undecodable body: {}", item.id, e);
                                let _ = crate::core::scheduled::finish(&item.id, Some("the stored body was unreadable".into()));
                                continue;
                            }
                        };
                        let (delivered, failures) = crate::utils::emailutils::deliver_raw(&sender, &item.to, &data);
                        if delivered == 0 && !failures.is_empty() {
                            log::warn!("[Scheduled] '{}' failed: {}", item.id, failures.join("; "));
                            let _ = crate::core::scheduled::finish(&item.id, Some(failures.join("; ")));
                        } else {
                            log::info!("[Scheduled] '{}' released to {} recipient(s)", item.id, delivered);
                            let _ = crate::core::scheduled::finish(&item.id, None);
                        }
                    }
                    Kind::Encrypted => {
                        // Replayed through the send endpoint as its owner: the
                        // encryption, the sent copy and the disappearing rule are
                        // the endpoint's job, not a second implementation's.
                        let released = match crate::utils::jwt::generate_jwt(&item.owner) {
                            Ok(token) => release_over_http(sweeper_port, &token, &item.data),
                            Err(e) => Err(format!("could not sign the release: {:?}", e)),
                        };
                        match released {
                            Ok(200) => {
                                log::info!("[Scheduled] '{}' released", item.id);
                                let _ = crate::core::scheduled::finish(&item.id, None);
                            }
                            Ok(code) => {
                                log::warn!("[Scheduled] '{}' was refused with {}", item.id, code);
                                let _ = crate::core::scheduled::finish(&item.id, Some(format!("the server answered {}", code)));
                            }
                            Err(e) => {
                                log::warn!("[Scheduled] '{}' could not be released: {}", item.id, e);
                                let _ = crate::core::scheduled::finish(&item.id, Some(e));
                            }
                        }
                    }
                }
            }
            crate::core::scheduled::sweep_old(crate::core::scheduled::now());
            thread::sleep(std::time::Duration::from_secs(30));
        });
    }

    info!("SMTP server listening on 0.0.0.0:{}", cfg.server.smtp_port);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => { warn!("[SMTP] Accept error: {}", e); continue; }
        };
        let remote = match stream.peer_addr() {
            Ok(r) => r,
            Err(e) => { warn!("[SMTP] peer_addr error: {}", e); continue; }
        };
        info!("[SMTP] Connection from {}", remote);

        let tls_config = tls_config.clone();
        let user_storage = Arc::clone(&user_storage);
        let email_storage = Arc::clone(&email_storage);
        let domain = domain.clone();
        let helo = helo_name.clone();

        thread::spawn(move || {
            if let Err(e) = handle_smtp_connection(
                stream, remote.to_string(), tls_config,
                user_storage, email_storage, domain, helo, dkim_enabled,
            ) {
                warn!("[SMTP {}] Connection error: {}", remote, e);
            }
        });
    }

    Ok(())
}

fn handle_smtp_connection(
    stream: TcpStream,
    remote: String,
    tls_config: Arc<ServerConfig>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
    domain: String,
    helo_name: String,
    dkim_enabled: bool,
) -> Result<()> {
    // Without deadlines an idle or slow-drip connection pins a thread forever,
    // so a handful of open sockets can starve the SMTP listener.
    stream.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(120)))?;

    let mut stream = MaybeTlsStream::Plain(stream);
    stream.write_all(format!("220 {} ESMTP ready\r\n", helo_name).as_bytes())?;
    stream.flush()?;

    let mut buffer = [0; 4096];
    let mut email_fsm = EmailReceivingFSM::new(&domain, &helo_name, Arc::clone(&user_storage), remote.clone());

    loop {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            debug!("[SMTP] Connection closed by client");
            break;
        }

        let bytes = buffer[..bytes_read].to_vec();
        // Only log printable ASCII - never dump binary data-phase bytes into the log
        if bytes.iter().all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\r' || b == b'\n' || b == b'\t') {
            debug!("[SMTP {}] >> {}", remote, String::from_utf8_lossy(&bytes).trim());
        } else {
            debug!("[SMTP {}] >> <{} binary bytes>", remote, bytes.len());
        }

        match email_fsm.handle_command(&mut stream, bytes)? {
            CommandResult::Continue => {}
            CommandResult::UpgradeToTls => {
                stream = stream.upgrade(tls_config.clone())?;
                email_fsm.notify_tls_upgraded();
            }
            CommandResult::Close => break,
        }
    }

    email_fsm.parse_body();
    let mut received = email_fsm.get_email();

    if dkim_enabled {
        let dkim_result = utils::dkim::verify(&String::from_utf8_lossy(&received.raw_data));
        match &dkim_result {
            utils::DkimStatus::Pass => info!("[SMTP] DKIM: pass for <{}>", received.from),
            utils::DkimStatus::Fail(reason) => warn!("[SMTP] DKIM: fail for <{}> - {}", received.from, reason),
            utils::DkimStatus::None => info!("[SMTP] DKIM: no signature from <{}>", received.from),
        }
        received.dkim_status = format!("{}", dkim_result);
    }

    info!("[SMTP] Email received for: {:?}", received.to);

    if received.to.is_empty() {
        warn!("[SMTP] No RCPT TO recipients - nothing to deliver");
        return Ok(());
    }

    for recipient in &received.to {
        let (username, recipient_domain) = match recipient.find('@') {
            Some(pos) => (&recipient[..pos], Some(&recipient[pos + 1..])),
            None => (recipient.as_str(), None),
        };

        if let Some(r_domain) = recipient_domain {
            if !r_domain.eq_ignore_ascii_case(&domain) {
                debug!("[SMTP] Skipping foreign-domain recipient '{}'", recipient);
                continue;
            }
        }

        debug!("[SMTP] Delivering to RCPT '{}' -> local user '{}'", recipient, username);

        // An alias is a real address that delivers to a real mailbox. Resolve it
        // to the owning account before anything else looks at the name, so the
        // blob, the pending hold and the group matching all land on the right
        // person. A switched-off alias resolves to nothing and the message is
        // refused here rather than disappearing into a hidden folder.
        // The RCPT local part, kept because `username` below becomes the owner.
        let delivered_to = username.to_ascii_lowercase();
        let alias_owner: Option<String> = if user_storage.get_user(username).is_some() {
            None
        } else {
            match core::aliases::resolve(username) {
                Some(owner) => {
                    info!("[SMTP] '{}' is an alias for account '{}'", username, owner);
                    core::aliases::bump(username);
                    Some(owner)
                }
                None => {
                    if core::aliases::load().aliases.contains_key(&username.to_ascii_lowercase()) {
                        info!("[SMTP] Address '{}' is switched off - refusing '{}'", username, recipient);
                    }
                    None
                }
            }
        };
        let username: &str = match alias_owner.as_deref() {
            Some(owner) => owner,
            None => username,
        };

        match user_storage.get_user(username) {
            None => {
                warn!("[SMTP] User '{}' not found - skipping '{}'", username, recipient);
            }
            Some(user) => {
                debug!("[SMTP] User '{}' found (uid={}, has_public_key={})",
                    username, user.uid, user.publicKey.is_some());

                if user.publicKey.is_none() {
                    // Accepted at SMTP level already, so the message must not be
                    // dropped: hold it and deliver once the key exists.
                    match core::pending::queue(username, &received) {
                        Ok(path) => info!(
                            "[SMTP] User '{}' has no public key yet - held message at '{}'",
                            username, path.display()
                        ),
                        Err(e) => error!(
                            "[SMTP] User '{}' has no public key and the message could not be held: {}",
                            username, e
                        ),
                    }
                    continue;
                }

                let email = if received.is_e2ee {
                    info!("[SMTP] E2EE email for '{}' - storing as-is (client-encrypted)", username);
                    Email::new_e2ee(received.clone(), &user)
                } else {
                    debug!("[SMTP] Standard email for '{}' - server-side encrypting", username);
                    let mut e = Email::new(received.clone(), &user);
                    e.secure = true;
                    e
                };
                let blob_path = format!("data/blobs/{}.bin", email.uid);
                debug!("[SMTP] Saving email blob to '{}'", blob_path);

                match email_storage.save_email(&email) {
                    Ok(_) => {
                        info!("[SMTP] Blob saved successfully");

                        // In-place: replacing the whole object here would drop
                        // any field a concurrent request wrote since the clone.
                        user_storage.mutate_user(username, |u| {
                            if !u.emailIds.contains(&email.uid) {
                                u.emailIds.push(email.uid);
                            }
                        });

                        user_storage.add_email_to_matching_groups(username, email.uid, &received.from);

                        // Remember the door it came through, so a reply can go back
                        // out from the same address rather than the owner's real one.
                        if alias_owner.is_some() {
                            core::arrival::record(email.uid, &delivered_to);
                        }

                        if let Err(e) = user_storage.save_to_file() {
                            warn!("[SMTP] Failed to persist user storage after delivery for '{}': {}", username, e);
                        }

                        // Tell their browsers, on a thread of its own: saving mail
                        // must never wait on somebody else's push service.
                        core::push::notify_async(
                            username,
                            "New mail",
                            &format!("From {}", received.from),
                        );

                        info!("[SMTP] Email uid={} queued for user '{}' (total emails: {})",
                            email.uid, username,
                            user_storage.get_user(username).map(|u| u.emailIds.len()).unwrap_or(0));
                    }
                    Err(e) => {
                        error!("[SMTP] Failed to save email blob for user '{}': {}", username, e);
                    }
                }
            }
        }
    }

    Ok(())
}


fn run_server(user_storage: Arc<UserStorage>, email_storage: Arc<EmailStorage>, api_port: u16) -> Result<()> {
    use tiny_http::Method;
    use api::endpoints;
    use api::RouteAuth::{Open, Authenticated, Admin};

    let server = Server::http(format!("0.0.0.0:{}", api_port)).unwrap();
    let mut router = Router::new(Arc::clone(&user_storage), Arc::clone(&email_storage));

    // Unauthenticated.
    router.add_route(Method::Post, "/api/auth/login",     Open, endpoints::auth::login);
    router.add_route(Method::Post, "/api/auth/login/2fa", Open, endpoints::twofactor::login_with_code);
    router.add_route(Method::Post, "/api/auth/login/webauthn/begin", Open, endpoints::webauthn::login_begin);
    router.add_route(Method::Post, "/api/auth/login/webauthn/finish", Open, endpoints::webauthn::login_finish);
    router.add_route(Method::Get,  "/api/user/webauthn", Authenticated, endpoints::webauthn::list);
    router.add_route(Method::Post, "/api/user/webauthn/register/begin", Authenticated, endpoints::webauthn::register_begin);
    router.add_route(Method::Post, "/api/user/webauthn/register/finish", Authenticated, endpoints::webauthn::register_finish);
    router.add_route(Method::Post, "/api/user/webauthn/remove", Authenticated, endpoints::webauthn::remove);
    router.add_route(Method::Get,  "/api/signup/challenge", Open, endpoints::user::signup_challenge);
    router.add_route(Method::Post, "/api/user/register",  Open, endpoints::user::register);
    router.add_route(Method::Post, "/api/user/delete-account", Authenticated, endpoints::user::delete_own_account);
    router.add_route(Method::Post, "/api/user/reset",     Open, endpoints::user::reset_with_token);
    router.add_route(Method::Post, "/api/user/recovery-key",        Authenticated, endpoints::user::set_recovery_key);
    router.add_route(Method::Get,  "/api/user/recovery-key",        Authenticated, endpoints::user::recovery_key_status);
    // Two-factor authentication (own account only).
    router.add_route(Method::Get,  "/api/user/2fa",          Authenticated, endpoints::twofactor::status);
    router.add_route(Method::Post, "/api/user/2fa/start",    Authenticated, endpoints::twofactor::start);
    router.add_route(Method::Post, "/api/user/2fa/confirm",  Authenticated, endpoints::twofactor::confirm);
    router.add_route(Method::Post, "/api/user/2fa/disable",  Authenticated, endpoints::twofactor::disable);
    // Session management (own sessions only).
    router.add_route(Method::Get,  "/api/user/sessions",             Authenticated, endpoints::sessions::list);
    router.add_route(Method::Post, "/api/user/sessions/revoke",      Authenticated, endpoints::sessions::revoke);
    router.add_route(Method::Post, "/api/user/sessions/revoke-all",  Authenticated, endpoints::sessions::revoke_all);
    router.add_route(Method::Post, "/api/user/recovery-key/blob",   Open, endpoints::user::fetch_recovery_blob);
    router.add_route(Method::Post, "/api/user/recovery-key/restore", Open, endpoints::user::restore_with_recovery_key);

    // Sealed notes: the ciphertext stays here, so the recipient's provider has
    // nothing to keep. The page and the open call are separate so a link
    // scanner that follows the URL does not consume the note.
    router.add_route(Method::Get,  "/api/note",        Open, endpoints::notes::page);
    router.add_route(Method::Head, "/api/note",        Open, endpoints::notes::page_head);
    router.add_route(Method::Post, "/api/note/open",   Open, endpoints::notes::open);
    router.add_route(Method::Post, "/api/note/burn",   Open, endpoints::notes::burn);

    // Any signed-in account, acting on its own data.
    router.add_route(Method::Post,      "/api/user/setup",          Authenticated, endpoints::user::setup_password);
    router.add_route(Method::Post,      "/api/user/credentials",    Authenticated, endpoints::user::set_credentials);
    router.add_route(Method::Get,       "/api/user/me",             Authenticated, endpoints::user::get_me);
    router.add_route(Method::Post,      "/api/user/key",              Authenticated,  endpoints::user::get_own_key);
    router.add_route(Method::Post,      "/api/pgp/wkd/publish",     Authenticated,  endpoints::pgp::publish_wkd);
    router.add_route(Method::Get,       "/api/pgp/wkd/status",      Authenticated,  endpoints::pgp::wkd_status);
    router.add_route(Method::Get,       "/api/user/pgpkey",         Authenticated,  endpoints::pgpkey::get_key);
    router.add_route(Method::Put,       "/api/user/pgpkey",         Authenticated,  endpoints::pgpkey::put_key);
    router.add_route(Method::Delete,    "/api/user/pgpkey",         Authenticated,  endpoints::pgpkey::delete_key);
    router.add_route(Method::Get,       "/api/me",                  Authenticated, endpoints::user::get_me);
    // Sealed notes, from the sender's side.
    router.add_route(Method::Post,      "/api/note/create",         Authenticated, endpoints::notes::create);
    // Mail that arrives from a file rather than over SMTP.
    router.add_route(Method::Post,      "/api/import/message",      Authenticated, endpoints::import::message);
    // Post-quantum protection for mail at rest (ML-KEM-768 public key + the
    // browser-wrapped secret key, both opaque to this server).
    router.add_route(Method::Get,       "/api/user/pq-keys",    Authenticated, endpoints::pqkeys::get);
    router.add_route(Method::Post,      "/api/user/pq-keys",    Authenticated, endpoints::pqkeys::set);
    router.add_route(Method::Delete,    "/api/user/pq-keys",    Authenticated, endpoints::pqkeys::remove);
    // Work list for re-sealing mail stored before post-quantum protection.
    router.add_route(Method::Get,       "/api/pq/migration",      Authenticated, endpoints::pqkeys::migration);
    // Deletion log: what left the mailbox, in a chain the client can check.
    router.add_route(Method::Get,       "/api/user/log",          Authenticated, endpoints::log::snapshot);
    router.add_route(Method::Post,      "/api/note/status",         Authenticated, endpoints::notes::status);
    router.add_route(Method::Post,      "/api/note/revoke",         Authenticated, endpoints::notes::revoke);
    router.add_route(Method::Get,       "/api/admin/recipients",    Admin, endpoints::admin::recipients);
    router.add_route(Method::Get,       "/api/scheduled",           Authenticated, endpoints::scheduled::list);
    router.add_route(Method::Post,      "/api/scheduled/cancel",    Authenticated, endpoints::scheduled::cancel);
    // New-mail notifications. The key is public by design: the browser needs it
    // before it can subscribe, and it proves nothing on its own.
    router.add_route(Method::Get,  "/api/push/key",         Open,          endpoints::push::key);
    router.add_route(Method::Post, "/api/push/subscribe",   Authenticated, endpoints::push::subscribe);
    router.add_route(Method::Post, "/api/push/unsubscribe", Authenticated, endpoints::push::unsubscribe);
    router.add_route(Method::Get,  "/api/push/status",      Authenticated, endpoints::push::status);
    router.add_route(Method::Post, "/api/push/test",        Authenticated, endpoints::push::test);

    router.add_route(Method::Get,       "/api/aliases",             Authenticated, endpoints::aliases::list);
    router.add_route(Method::Post,      "/api/aliases",             Authenticated, endpoints::aliases::create);
    router.add_route(Method::Post,      "/api/aliases/disable",     Authenticated, endpoints::aliases::disable);
    router.add_route(Method::Post,      "/api/aliases/delete",      Authenticated, endpoints::aliases::delete);

    // Administrators only. These routes act on *other* accounts, so a valid
    // session is not enough - the router enforces 'is_admin' before dispatching.
    router.add_route(Method::Get,       "/api/admin/users",             Admin, endpoints::admin::list_users);
    router.add_route(Method::Post,      "/api/admin/users",             Admin, endpoints::admin::add_user);
    router.add_route(Method::Delete,    "/api/admin/users",             Admin, endpoints::admin::delete_user);
    router.add_route(Method::Post,      "/api/admin/users/credentials", Admin, endpoints::admin::set_credentials);
    router.add_route(Method::Post,      "/api/admin/users/recovery-address", Admin, endpoints::admin::set_recovery_address);
    router.add_route(Method::Post,      "/api/admin/users/send-recovery",   Admin, endpoints::admin::send_recovery);
    router.add_route(Method::Post,      "/api/admin/users/admin",       Admin, endpoints::admin::set_admin);
    router.add_route(Method::Get,       "/api/admin/disk-usage",        Admin, endpoints::admin::disk_usage);

    // Self-registration approval queue: accounts created without an invite code.
    router.add_route(Method::Get,       "/api/admin/pending",           Admin, endpoints::admin::list_pending);
    router.add_route(Method::Post,      "/api/admin/pending/approve",   Admin, endpoints::admin::approve_pending);
    router.add_route(Method::Post,      "/api/admin/pending/deny",      Admin, endpoints::admin::deny_pending);

    // Manual-approval waiting list for public signup.
    router.add_route(Method::Post, "/api/waitlist/request",        Open,  endpoints::waitlist::request_access);
    router.add_route(Method::Get,  "/api/admin/waitlist",          Admin, endpoints::waitlist::list);
    router.add_route(Method::Post, "/api/admin/waitlist/approve",  Admin, endpoints::waitlist::approve);

    router.add_route(Method::Post,      "/api/email/get",        Authenticated,  endpoints::email::get_email);
    router.add_route(Method::Post,      "/api/email/bulk",       Authenticated,  endpoints::email::get_emails_bulk);
    router.add_route(Method::Post,      "/api/email/list",       Authenticated,  endpoints::email::list_email_uids);
    router.add_route(Method::Post,      "/api/email/delete",     Authenticated,  endpoints::email::delete_email);
    router.add_route(Method::Post,      "/api/email/set",        Authenticated,  endpoints::email::set_email_bytes);
    router.add_route(Method::Post,      "/api/email/recent",          Authenticated,  endpoints::email::list_recent_email_uids);
    router.add_route(Method::Post,      "/api/email/send",            Authenticated,  endpoints::email::send_email);
    router.add_route(Method::Post,      "/api/email/read",            Authenticated,  endpoints::email::mark_email_read);
    router.add_route(Method::Post,      "/api/email/ephemeral",       Authenticated,  endpoints::email::ephemeral_status);
    router.add_route(Method::Post,      "/api/email/unread",          Authenticated,  endpoints::email::mark_email_unread);
    router.add_route(Method::Post,      "/api/email/star",            Authenticated,  endpoints::email::set_email_starred);
    router.add_route(Method::Post,      "/api/email/flags",           Authenticated,  endpoints::email::email_flags);
    router.add_route(Method::Post,      "/api/email/publickeys",      Authenticated,  endpoints::email::get_public_keys);
    router.add_route(Method::Post,      "/api/email/sendencrypted",   Authenticated,  endpoints::email::send_encrypted);
    router.add_route(Method::Post,      "/api/email/sent/list",       Authenticated,  endpoints::email::list_sent_email_uids);
    router.add_route(Method::Post,      "/api/email/sent/recent",     Authenticated,  endpoints::email::list_recent_sent_email_uids);
    router.add_route(Method::Post,      "/api/email/sent/get",        Authenticated,  endpoints::email::get_sent_email);
    router.add_route(Method::Post,      "/api/email/sent/bulk",       Authenticated,  endpoints::email::get_sent_emails_bulk);
    router.add_route(Method::Post,      "/api/email/sent/delete",     Authenticated,  endpoints::email::delete_sent_email);
    router.add_route(Method::Post,      "/api/email/trash",           Authenticated,  endpoints::trash::trash_email);
    router.add_route(Method::Post,      "/api/email/restore",         Authenticated,  endpoints::trash::restore_email);
    router.add_route(Method::Post,      "/api/email/trash/list",      Authenticated,  endpoints::trash::list_trash);
    router.add_route(Method::Post,      "/api/email/trash/empty",     Authenticated,  endpoints::trash::empty_trash);

    router.add_route(Method::Get,       "/api/group/list",            Authenticated,  endpoints::group::list_groups);
    router.add_route(Method::Post,      "/api/group/create",          Authenticated,  endpoints::group::create_group);
    router.add_route(Method::Post,      "/api/group/get",             Authenticated,  endpoints::group::get_group);
    router.add_route(Method::Post,      "/api/group/update",          Authenticated,  endpoints::group::update_group);
    router.add_route(Method::Post,      "/api/group/delete",          Authenticated,  endpoints::group::delete_group);
    router.add_route(Method::Post,      "/api/group/add-email",       Authenticated,  endpoints::group::add_email_to_group);
    router.add_route(Method::Post,      "/api/group/remove-email",    Authenticated,  endpoints::group::remove_email_from_group);
    for request in server.incoming_requests() {
        //debug!("[API] {} {}", request.method(), request.url());
        router.handle_request(request);
    }
    Ok(())
}

/// Re-attach email blobs that exist on disk but are missing from their owner's
/// `emailIds` list. Idempotent and safe to run on every boot.
fn reconcile_orphaned_emails(user_storage: &UserStorage, email_storage: &EmailStorage) {
    let mut reattached = 0usize;
    let mut orphans = 0usize;

    for uid in email_storage.list_all_uids() {
        let email = match email_storage.read_email(uid) {
            Ok(e) => e,
            Err(e) => {
                warn!("[Storage] Unreadable blob {}: {}", uid, e);
                continue;
            }
        };

        match user_storage.get_user_by_uid(email.userid) {
            None => {
                orphans += 1;
                debug!("[Storage] Blob {} has no owning account (uid {})", uid, email.userid);
            }
            Some(user) => {
                // A sent copy is a blob too. It belongs to sent_emails only, so it
                // must never be attached to the inbox index (and any that already
                // were get detached here).
                if user.sent_emails.contains(&uid) {
                    if user.emailIds.contains(&uid) {
                        user_storage.mutate_user(&user.username, |u| u.emailIds.retain(|&id| id != uid));
                    }
                    continue;
                }
                if !user.emailIds.contains(&uid) {
                    user_storage.mutate_user(&user.username, |u| {
                        if !u.emailIds.contains(&uid) {
                            u.emailIds.push(uid);
                            u.emailIds.sort_unstable();
                        }
                    });
                    reattached += 1;
                }
            }
        }
    }

    // Prune index entries whose blob no longer exists (deleted out of band, or
    // removed by an interrupted cleanup). Without this the mailbox lists rows
    // that cannot be opened.
    let existing: std::collections::HashSet<u128> = email_storage.list_all_uids().into_iter().collect();
    let mut pruned = 0usize;
    for user in user_storage.get_all_users() {
        let stale_inbox = user.emailIds.iter().filter(|id| !existing.contains(id)).count();
        let stale_sent = user.sent_emails.iter().filter(|id| !existing.contains(id)).count();
        if stale_inbox + stale_sent > 0 {
            user_storage.mutate_user(&user.username, |u| {
                u.emailIds.retain(|id| existing.contains(id));
                u.sent_emails.retain(|id| existing.contains(id));
            });
            pruned += stale_inbox + stale_sent;
        }
    }
    if pruned > 0 {
        warn!("[Storage] Pruned {} index entr(ies) with no blob on disk", pruned);
        if let Err(e) = user_storage.save_to_file() {
            warn!("[Storage] Failed to persist pruned index: {}", e);
        }
    }

    if reattached > 0 {
        warn!(
            "[Storage] Re-attached {} email(s) that were missing from their accounts' index",
            reattached
        );
        if let Err(e) = user_storage.save_to_file() {
            warn!("[Storage] Failed to persist reconciled index: {}", e);
        }
    } else {
        info!("[Storage] Email index consistent ({} orphaned blob(s) ignored)", orphans);
    }
}

/// Hand a stored request back to our own API as the account that queued it.
///
/// A real HTTP call, not an internal shortcut: the released message then goes
/// through the endpoint every other send goes through. The connection is to
/// 127.0.0.1 and the token is minted here, so nothing is exposed by this.
fn release_over_http(port: u16, token: &str, body: &str) -> std::result::Result<u16, String> {
    use std::io::{Read, Write};

    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .map_err(|e| format!("could not reach the API: {}", e))?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(120)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));

    let head = format!(
        "POST /api/email/sendencrypted HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        token,
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().ok();

    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| e.to_string())?;
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "the API gave no status line".to_string())
}
