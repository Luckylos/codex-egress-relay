//! The reverse-proxy request handler and shared application state.
//!
//! One `reqwest::Client` (rustls + aws-lc-rs, HTTP/2) is shared across all
//! requests so connections are pooled and keep-alive'd, mirroring how the real
//! Codex CLI reuses a single h2 connection per session. The request body is
//! read fully (bounded by `Config::max_body_bytes`) and replayed; the response
//! body is streamed back byte-for-byte with no decompression, so SSE from the
//! Responses API and any content-encoding pass through untouched.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::TryStreamExt;

use crate::config::Config;
use crate::identity::ResolvedIdentity;

/// Response headers that must not be forwarded back to the caller.
const STRIP_RESPONSE: &[&str] = &[
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

#[derive(Clone)]
pub struct AppState {
    pub client: reqwest::Client,
    pub cfg: Arc<Config>,
}

/// Liveness + effective-identity probe. Reports the synthesized identity so the
/// running configuration can be verified without inspecting an upstream request.
pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "upstream": state.cfg.upstream_base_url,
        "ua": state.cfg.user_agent,
        "originator": state.cfg.originator,
        "beta_features": state.cfg.beta_features,
        "installation_id": state.cfg.installation_id,
        "egress": "rustls-single-process",
    }))
}

/// Catch-all reverse proxy: rewrite the identity, forward to the fixed upstream,
/// stream the response back.
pub async fn proxy(State(state): State<AppState>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(|q| q.to_owned());

    let mut upstream_url = format!("{}{}", state.cfg.upstream_base_url, path);
    if let Some(q) = &query {
        upstream_url.push('?');
        upstream_url.push_str(q);
    }

    // Resolve the turn identity once, then project it onto both wire layers —
    // the header set and the body's client_metadata — so they cannot drift.
    let identity = ResolvedIdentity::resolve(&state.cfg, req.headers());
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let headers = identity.apply_to_headers(req.headers());

    let body_bytes = match axum::body::to_bytes(req.into_body(), state.cfg.max_body_bytes).await {
        Ok(b) => b,
        Err(e) => {
            return error_json(
                StatusCode::BAD_REQUEST,
                "proxy_read_error",
                &format!("read body: {e}"),
            );
        }
    };
    let body_bytes = identity.ensure_body_metadata(content_type.as_deref(), body_bytes);

    let start = Instant::now();
    eprintln!(">>> {method} {path} → {upstream_url}");

    let sent = state
        .client
        .request(method, &upstream_url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await;

    let upstream = match sent {
        Ok(r) => r,
        Err(e) => {
            let ms = start.elapsed().as_millis();
            if e.is_timeout() {
                eprintln!("<<< 504 TIMEOUT {path} ({ms}ms)");
                return error_json(
                    StatusCode::GATEWAY_TIMEOUT,
                    "proxy_timeout",
                    "Upstream timeout",
                );
            }
            eprintln!("<<< 502 CONNECT_ERROR {path} ({ms}ms): {e}");
            return error_json(
                StatusCode::BAD_GATEWAY,
                "proxy_connect_error",
                "Upstream connect error",
            );
        }
    };

    let status = upstream.status();
    let mut resp_headers = HeaderMap::new();
    for (name, value) in upstream.headers().iter() {
        if STRIP_RESPONSE
            .iter()
            .any(|s| name.as_str().eq_ignore_ascii_case(s))
        {
            continue;
        }
        resp_headers.insert(name.clone(), value.clone());
    }
    eprintln!(
        "<<< {} {path} ({}ms)",
        status.as_u16(),
        start.elapsed().as_millis()
    );

    // Stream the body back byte-for-byte (no decompression: the caller decodes
    // per content-encoding). SSE from the Responses API flows through untouched.
    let stream = upstream.bytes_stream().map_err(std::io::Error::other);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    response
}

/// Build a JSON error response in the OpenAI-style `{ "error": { ... } }` shape.
fn error_json(status: StatusCode, err_type: &str, message: &str) -> Response {
    let body = serde_json::json!({ "error": { "message": message, "type": err_type } }).to_string();
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/json"),
    );
    resp
}
