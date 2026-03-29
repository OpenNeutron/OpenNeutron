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

    let tls_config = make_tls_config(&cfg.tls);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", cfg.server.smtp_port))?;
    let user_storage: Arc<UserStorage> = Arc::new(get_or_init_storage(cfg.storage.users_file.clone(), cfg.server.domain.clone()));
    let email_storage: Arc<EmailStorage> = Arc::new(EmailStorage::new(cfg.storage.blobs_dir.clone()));

    let user_storage_clone = Arc::clone(&user_storage);
    let email_storage_clone = Arc::clone(&email_storage);
    let api_port = cfg.server.api_port;
    let domain = cfg.server.domain.clone();
    let dkim_enabled = cfg.dkim.as_ref().map(|d| d.enabled).unwrap_or(true);

    // Init global domain for outgoing SMTP
    utils::emailutils::init_server_domain(cfg.server.domain.clone());

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

        thread::spawn(move || {
            if let Err(e) = handle_smtp_connection(
                stream, remote.to_string(), tls_config,
                user_storage, email_storage, domain, dkim_enabled,
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
    dkim_enabled: bool,
) -> Result<()> {
    let mut stream = MaybeTlsStream::Plain(stream);
    stream.write_all(format!("220 {} ESMTP ready\r\n", domain).as_bytes())?;
    stream.flush()?;

    let mut buffer = [0; 4096];
    let mut email_fsm = EmailReceivingFSM::new(&domain, Arc::clone(&user_storage), remote.clone());

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

        match user_storage.get_user(username) {
            None => {
                warn!("[SMTP] User '{}' not found - skipping '{}'", username, recipient);
            }
            Some(user) => {
                debug!("[SMTP] User '{}' found (uid={}, has_public_key={})",
                    username, user.uid, user.publicKey.is_some());

                if user.publicKey.is_none() {
                    warn!("[SMTP] User '{}' has no public key yet - skipping delivery", username);
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

                        let mut updated_user = user.clone();
                        updated_user.emailIds.push(email.uid);
                        user_storage.update_user(updated_user);

                        user_storage.add_email_to_matching_groups(username, email.uid, &received.from);

                        if let Err(e) = user_storage.save_to_file() {
                            warn!("[SMTP] Failed to persist user storage after delivery for '{}': {}", username, e);
                        }
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

    let server = Server::http(format!("0.0.0.0:{}", api_port)).unwrap();
    let mut router = Router::new(Arc::clone(&user_storage), Arc::clone(&email_storage));

    
    router.add_route(Method::Post, "/api/auth/login",     false, endpoints::auth::login);
    router.add_route(Method::Post, "/api/user/register",  false, endpoints::user::register);

    
    router.add_route(Method::Post,      "/api/user/setup",          true,    endpoints::user::setup_password);
    router.add_route(Method::Post,      "/api/user/credentials",    true,    endpoints::user::set_credentials);
    router.add_route(Method::Get,       "/api/user/me",             true,    endpoints::user::get_me);
    router.add_route(Method::Get,       "/api/me",                  true,    endpoints::user::get_me);
    router.add_route(Method::Get,       "/api/admin/users",         true,    endpoints::admin::list_users);
    router.add_route(Method::Post,      "/api/admin/users",         true,    endpoints::admin::add_user);
    router.add_route(Method::Delete,    "/api/admin/users",         true,    endpoints::admin::delete_user);
    router.add_route(Method::Post,      "/api/admin/users/credentials", true, endpoints::admin::set_credentials);
    router.add_route(Method::Post,      "/api/admin/users/admin",   true,    endpoints::admin::set_admin);
    router.add_route(Method::Get,       "/api/admin/disk-usage",    true,    endpoints::admin::disk_usage);
    
    router.add_route(Method::Post,      "/api/email/get",        true,  endpoints::email::get_email);
    router.add_route(Method::Post,      "/api/email/bulk",       true,  endpoints::email::get_emails_bulk);
    router.add_route(Method::Post,      "/api/email/list",       true,  endpoints::email::list_email_uids);
    router.add_route(Method::Post,      "/api/email/delete",     true,  endpoints::email::delete_email);
    router.add_route(Method::Post,      "/api/email/set",        true,  endpoints::email::set_email_bytes);
    router.add_route(Method::Post,      "/api/email/recent",          true,  endpoints::email::list_recent_email_uids);
    router.add_route(Method::Post,      "/api/email/send",            true,  endpoints::email::send_email);
    router.add_route(Method::Post,      "/api/email/read",            true,  endpoints::email::mark_email_read);
    router.add_route(Method::Post,      "/api/email/unread",          true,  endpoints::email::mark_email_unread);
    router.add_route(Method::Post,      "/api/email/star",            true,  endpoints::email::set_email_starred);
    router.add_route(Method::Post,      "/api/email/publickeys",      true,  endpoints::email::get_public_keys);
    router.add_route(Method::Post,      "/api/email/sendencrypted",   true,  endpoints::email::send_encrypted);
    router.add_route(Method::Post,      "/api/email/sent/list",       true,  endpoints::email::list_sent_email_uids);
    router.add_route(Method::Post,      "/api/email/sent/recent",     true,  endpoints::email::list_recent_sent_email_uids);
    router.add_route(Method::Post,      "/api/email/sent/get",        true,  endpoints::email::get_sent_email);
    router.add_route(Method::Post,      "/api/email/sent/bulk",       true,  endpoints::email::get_sent_emails_bulk);
    
    router.add_route(Method::Get,       "/api/group/list",            true,  endpoints::group::list_groups);
    router.add_route(Method::Post,      "/api/group/create",          true,  endpoints::group::create_group);
    router.add_route(Method::Post,      "/api/group/get",             true,  endpoints::group::get_group);
    router.add_route(Method::Post,      "/api/group/update",          true,  endpoints::group::update_group);
    router.add_route(Method::Post,      "/api/group/delete",          true,  endpoints::group::delete_group);
    router.add_route(Method::Post,      "/api/group/add-email",       true,  endpoints::group::add_email_to_group);
    router.add_route(Method::Post,      "/api/group/remove-email",    true,  endpoints::group::remove_email_from_group);
    for request in server.incoming_requests() {
        //debug!("[API] {} {}", request.method(), request.url());
        router.handle_request(request);
    }
    Ok(())
}