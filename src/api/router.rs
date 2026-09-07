use crate::core::{EmailStorage, UserStorage};
use crate::core::User;
use crate::utils::jwt::validate_jwt;
use crate::api::dto::{ErrorResponse, json_header, cors_headers};
use tiny_http::{Response, Method, Header};
use std::collections::HashMap;
use std::sync::Arc;
use tiny_http::Request;
use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use serde_json;

type Handler = fn(
    &mut Request,
    Option<User>,
    Arc<UserStorage>,
    Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>>;

/// Authorization required to reach a route.
///
/// This is the single place where privilege is decided. 'Authenticated' means
/// only "some valid session"; it is NOT sufficient for administrative actions,
/// which must be registered as 'Admin'.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RouteAuth {
    /// No credentials required.
    Open,
    /// Any valid, non-expired session for an existing account.
    Authenticated,
    /// A valid session whose account currently has 'is_admin == true'.
    Admin,
}

fn error_response(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&ErrorResponse {
        error: message.to_string(),
        code: code.to_string(),
    })
    .unwrap_or_else(|_| b"{\"error\":\"internal error\",\"code\":\"internal_error\"}".to_vec());
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn add_cors_headers(mut response: Response<Cursor<Vec<u8>>>, origin: Option<&str>) -> Response<Cursor<Vec<u8>>> {
    for header in cors_headers(origin) {
        response = response.with_header(header);
    }
    response
}

pub struct Router {
    routes: HashMap<(Method, String), (RouteAuth, Handler)>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
}

impl Router {
    pub fn new(user_storage: Arc<UserStorage>, email_storage: Arc<EmailStorage>) -> Self {
        Router {
            routes: HashMap::new(),
            user_storage,
            email_storage,
        }
    }

    pub fn add_route(
        &mut self,
        method: Method,
        path: &str,
        auth: RouteAuth,
        handler: Handler,
    ) -> &mut Self {
        self.routes.insert((method, path.to_string()), (auth, handler));
        self
    }

    /// Resolve the caller's session, if any, and reject tokens that were issued
    /// before an administrator last reset the account's credentials.
    fn authenticate(&self, request: &Request) -> Option<User> {
        let claims = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .and_then(|h| {
                let value = h.value.to_string();
                let token = value.trim_start_matches("Bearer ").trim().to_string();
                validate_jwt(&token).ok()
            })?;

        let user = self.user_storage.get_user(&claims.sub)?;
        if (claims.iat as u64) < user.credentials_changed_at {
            log::info!(
                "[API] Rejected token for '{}' issued before an administrative credential reset",
                user.username
            );
            return None;
        }
        Some(user)
    }

    /// The route table is keyed on the path only, so query strings must be stripped
    /// before lookup - otherwise '/api/admin/users?x=1' would miss the table and
    /// fall through to the unauthenticated static-file branch.
    fn route_path(url: &str) -> &str {
        url.split('?').next().unwrap_or("/")
    }

    pub fn handle_request(&self, mut request: Request) {
        let url = request.url().to_string();
        let path = Self::route_path(&url).to_string();
        let method = request.method().clone();
        let origin = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Origin"))
            .map(|h| h.value.to_string());
        let origin_ref = origin.as_deref();

        if method == Method::Options {
            let exists = [Method::Get, Method::Post, Method::Put, Method::Delete]
                .iter()
                .any(|m| self.routes.contains_key(&(m.clone(), path.clone())));
            if exists {
                let response = Response::from_data("").with_status_code(204);
                let _ = request.respond(add_cors_headers(response, origin_ref));
                return;
            }
        }

        if let Some((auth, handler)) = self.routes.get(&(method.clone(), path.clone())) {
            let caller = match auth {
                RouteAuth::Open => None,
                RouteAuth::Authenticated | RouteAuth::Admin => {
                    let user = self.authenticate(&request);
                    match user {
                        None => {
                            let response = error_response(401, "unauthorized", "Unauthorized");
                            let _ = request.respond(add_cors_headers(response, origin_ref));
                            return;
                        }
                        Some(u) => {
                            if *auth == RouteAuth::Admin && !u.is_admin {
                                log::warn!(
                                    "[API] Denied admin route {} {} to non-admin user '{}'",
                                    method, path, u.username
                                );
                                let response =
                                    error_response(403, "forbidden", "Administrator privileges required");
                                let _ = request.respond(add_cors_headers(response, origin_ref));
                                return;
                            }
                            Some(u)
                        }
                    }
                }
            };

            // A panic inside a handler would otherwise unwind out of the single
            // request-accept loop and take the whole API server down, so any handler
            // fault is contained and reported as a 500 instead.
            let response = catch_unwind(AssertUnwindSafe(|| {
                handler(
                    &mut request,
                    caller,
                    Arc::clone(&self.user_storage),
                    Arc::clone(&self.email_storage),
                )
            }))
            .unwrap_or_else(|_| {
                log::error!("[API] Handler panicked while serving {} {}", method, path);
                error_response(500, "internal_error", "Internal server error")
            });

            let _ = request.respond(add_cors_headers(response, origin_ref));
            return;
        }

        // Static file serving for non-API paths, like a simple SPA fallback (in our case we use react, so we serve index.html for all non-API paths)
        if !path.starts_with("/api/") {
            let static_root = Path::new("data/static");
            let file_path = match safe_static_path(static_root, &path) {
                Some(candidate) if candidate.is_file() => candidate,
                _ => static_root.join("index.html"),
            };
            match std::fs::read(&file_path) {
                Ok(bytes) => {
                    let mime = mime_type(file_path.as_path());
                    let content_type = Header::from_bytes("Content-Type", mime).unwrap();
                    let response = Response::from_data(bytes)
                        .with_status_code(200)
                        .with_header(content_type);
                    let _ = request.respond(with_static_security_headers(response));
                    return;
                }
                Err(_) => {
                    // Fall through to 404
                }
            }
        }

        let response = error_response(404, "not_found", "Not Found");
        let _ = request.respond(add_cors_headers(response, origin_ref));
    }
}

/// Map a request path to a file inside 'root', or 'None' if it tries to escape.
///
/// The URL path is percent-decoded first (so '%2e%2e%2f' cannot smuggle a
/// traversal past the check) and then resolved component by component: any '..',
/// root prefix, or absolute segment aborts the lookup rather than climbing out of
/// the static directory.
fn safe_static_path(root: &Path, url_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(url_path);
    let relative = decoded.trim_start_matches('/');
    if relative.is_empty() {
        return None;
    }

    let mut resolved = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => {
                let text = part.to_str()?;
                if text.contains('\\') {
                    return None;
                }
                resolved.push(text);
            }
            // '.' is harmless but adds nothing; everything else is an escape attempt.
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }

    // Belt and braces: a symlink inside data/static could still point outside it.
    let canonical_root = root.canonicalize().ok()?;
    let canonical_target = resolved.canonicalize().ok()?;
    if !canonical_target.starts_with(&canonical_root) {
        return None;
    }
    Some(canonical_target)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(byte) = hex {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Static assets are same-origin only and must never be framed or MIME-sniffed.
fn with_static_security_headers(mut response: Response<Cursor<Vec<u8>>>) -> Response<Cursor<Vec<u8>>> {
    let headers = [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
    ];
    for (name, value) in headers {
        if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response = response.with_header(header);
        }
    }
    response
}

fn mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css")  => "text/css; charset=utf-8",
        Some("js")   => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png")  => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg")  => "image/svg+xml",
        Some("ico")  => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf")  => "font/ttf",
        Some("webp") => "image/webp",
        _            => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_paths_cannot_escape_the_root() {
        let root = Path::new("data/static");
        for attack in [
            "/../../etc/passwd",
            "/..%2f..%2fetc/passwd",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/assets/../../../Cargo.toml",
            "//etc/passwd",
        ] {
            assert!(
                safe_static_path(root, attack).is_none(),
                "traversal was not blocked: {}",
                attack
            );
        }
    }

    #[test]
    fn ordinary_asset_paths_still_resolve() {
        let root = Path::new("data/static");
        if root.join("index.html").is_file() {
            assert!(safe_static_path(root, "/index.html").is_some());
        }
    }

    #[test]
    fn query_strings_do_not_bypass_the_route_table() {
        assert_eq!(Router::route_path("/api/admin/users?x=1"), "/api/admin/users");
        assert_eq!(Router::route_path("/api/admin/users"), "/api/admin/users");
    }
}
