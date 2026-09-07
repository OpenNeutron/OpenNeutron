use serde::de::DeserializeOwned;
use std::io::{Cursor, Read};
use tiny_http::{Request, Response};

use crate::api::dto::{ErrorResponse, json_header};

fn error_response(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&ErrorResponse {
        error: message.to_string(),
        code: code.to_string(),
    })
    .unwrap_or_else(|_| b"{\"error\":\"internal error\",\"code\":\"internal_error\"}".to_vec());
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

/// Read and deserialize a JSON request body.
///
/// The body is bounded by 'server.max_request_body_bytes' before it is buffered:
/// without a cap, a single request advertising a huge (or chunked, unbounded)
/// body would let an unauthenticated client exhaust server memory.
pub fn read_json_body<T: DeserializeOwned>(request: &mut Request) -> Result<T, Response<Cursor<Vec<u8>>>> {
    let limit = crate::config::get().server.max_request_body_bytes;

    if let Some(declared) = request.body_length() {
        if declared > limit {
            return Err(error_response(
                413,
                "body_too_large",
                "Request body exceeds the configured limit",
            ));
        }
    }

    // Read one byte past the limit so an over-long body is detected rather than
    // silently truncated into something that happens to parse.
    let mut buffer = Vec::new();
    let read_result = request
        .as_reader()
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut buffer);

    if read_result.is_err() {
        return Err(error_response(400, "body_read_error", "Failed to read body"));
    }
    if buffer.len() > limit {
        return Err(error_response(
            413,
            "body_too_large",
            "Request body exceeds the configured limit",
        ));
    }

    serde_json::from_slice(&buffer)
        .map_err(|_| error_response(422, "invalid_json", "Invalid JSON"))
}
