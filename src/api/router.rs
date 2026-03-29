use crate::core::{EmailStorage, UserStorage};
use crate::core::User;
use crate::utils::jwt::validate_jwt;
use crate::api::dto::{ErrorResponse, json_header, cors_headers};
use tiny_http::{Response, Method, Header};
use std::collections::HashMap;
use std::sync::Arc;
use tiny_http::Request;
use std::io::Cursor;
use std::path::Path;
use serde_json;

type Handler = fn(
    &mut Request,
    Option<User>,
    Arc<UserStorage>,
    Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>>;

fn add_cors_headers(mut response: Response<Cursor<Vec<u8>>>) -> Response<Cursor<Vec<u8>>> {
    for header in cors_headers() {
        response = response.with_header(header);
    }
    response
}
pub struct Router {
    routes: HashMap<(Method, String, bool), Handler>,
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
        secure: bool,
        handler: Handler,
    ) -> &mut Self {
        self.routes.insert((method, path.to_string(), secure), handler);
        self
    }

    pub fn handle_request(&self, mut request: Request) {
        let path = request.url().to_string();
        let method = request.method().clone();

        
        if method == Method::Options {
            let secure_exists = self.routes.contains_key(&(Method::Get, path.clone(), true)) ||
                               self.routes.contains_key(&(Method::Post, path.clone(), true)) ||
                               self.routes.contains_key(&(Method::Put, path.clone(), true)) ||
                               self.routes.contains_key(&(Method::Delete, path.clone(), true));
            let open_exists = self.routes.contains_key(&(Method::Get, path.clone(), false)) ||
                             self.routes.contains_key(&(Method::Post, path.clone(), false)) ||
                             self.routes.contains_key(&(Method::Put, path.clone(), false)) ||
                             self.routes.contains_key(&(Method::Delete, path.clone(), false));
            if secure_exists || open_exists {
                let response = Response::from_data("").with_status_code(200);
                let _ = request.respond(add_cors_headers(response));
                return;
            }
        }

        let secure_key = (method.clone(), path.clone(), true);
        if let Some(handler) = self.routes.get(&secure_key) {
            let auth_user = request
                .headers()
                .iter()
                .find(|h| h.field.equiv("Authorization"))
                .and_then(|h| {
                    let value = h.value.to_string();
                    let token = value.trim_start_matches("Bearer ").trim().to_string();
                    validate_jwt(&token).ok()
                })
                .and_then(|claims| self.user_storage.get_user(&claims.sub));

            if auth_user.is_none() {
                let body = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
                let response = Response::from_data(body).with_status_code(401).with_header(json_header());
                let _ = request.respond(add_cors_headers(response));
                return;
            }

            let response = handler(
                &mut request,
                auth_user,
                Arc::clone(&self.user_storage),
                Arc::clone(&self.email_storage),
            );
            let _ = request.respond(add_cors_headers(response));
            return;
        }

        let open_key = (method, path, false);
        if let Some(handler) = self.routes.get(&open_key) {
            let response = handler(
                &mut request,
                None,
                Arc::clone(&self.user_storage),
                Arc::clone(&self.email_storage),
            );
            let _ = request.respond(add_cors_headers(response));
            return;
        }

        // Static file serving for non-API paths, like a simple SPA fallback (in our case we use react, so we serve index.html for all non-API paths)
        let url_path = request.url().split('?').next().unwrap_or("/").to_string();
        if !url_path.starts_with("/api/") {
            let static_root = Path::new("data/static");
            let relative = url_path.trim_start_matches('/');
            let candidate = static_root.join(relative);
            let file_path = if candidate.is_file() {
                candidate
            } else {
                static_root.join("index.html")
            };
            match std::fs::read(&file_path) {
                Ok(bytes) => {
                    let mime = mime_type(file_path.as_path());
                    let content_type = Header::from_bytes("Content-Type", mime).unwrap();
                    let response = Response::from_data(bytes).with_status_code(200).with_header(content_type);
                    let _ = request.respond(response);
                    return;
                }
                Err(_) => {
                    // Fall through to 404
                }
            }
        }

        let body = serde_json::to_vec(&ErrorResponse { error: "Not Found".into(), code: "not_found".into() }).unwrap();
        let response = Response::from_data(body).with_status_code(404).with_header(json_header());
        let _ = request.respond(add_cors_headers(response));
    }
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