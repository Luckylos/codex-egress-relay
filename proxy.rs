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

#[cfg(test)]
mod tests {
    //! End-to-end coverage of the reverse-proxy handler wiring. Each test drives
    //! a real request through `proxy` against a throwaway mock upstream on an
    //! ephemeral port, so the whole chain — identity projection onto the wire,
    //! body metadata injection, path/query forwarding, response header stripping,
    //! and byte-for-byte body passthrough — is exercised as an integration, not a
    //! per-function unit. The identity/body *rules* are unit-tested in
    //! `identity.rs`; these tests prove the handler actually applies them.
    use super::*;
    use axum::Router;
    use std::sync::Mutex;

    /// The canned upstream response body. Doubles as the fixture for the
    /// byte-for-byte passthrough assertion.
    const CANNED_BODY: &[u8] = b"data: {\"ok\":true}\n\n";

    /// What the mock upstream saw on the wire, captured for assertions.
    #[derive(Default)]
    struct Recorded {
        path: String,
        query: Option<String>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    }

    /// Spawn a mock upstream that records the request it receives and always
    /// replies `200` with a custom header plus [`CANNED_BODY`]. Hyper adds its
    /// own `content-length`, giving the header-strip test a real hop-by-hop
    /// header to prove is dropped. Polls the port until the accept loop is live
    /// so the first request cannot race ahead of readiness.
    async fn spawn_recording_upstream() -> (String, Arc<Mutex<Option<Recorded>>>) {
        let slot = Arc::new(Mutex::new(None));
        let sink = slot.clone();
        let app = Router::new().fallback(move |req: Request| {
            let sink = sink.clone();
            async move {
                let (parts, body) = req.into_parts();
                let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                *sink.lock().unwrap() = Some(Recorded {
                    path: parts.uri.path().to_owned(),
                    query: parts.uri.query().map(|q| q.to_owned()),
                    headers: parts.headers,
                    body,
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header("x-upstream-custom", "yes")
                    .body(Body::from(CANNED_BODY))
                    .unwrap()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let addr = listener.local_addr().expect("mock upstream addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock upstream");
        });
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (format!("http://{addr}"), slot)
    }

    fn test_cfg(base: &str) -> Config {
        Config {
            upstream_base_url: base.to_owned(),
            port: 18092,
            user_agent: "codex-tui/0.145.0 (Debian 12.0.0; x86_64) unknown (codex-tui; 0.145.0)"
                .to_owned(),
            originator: "codex-tui".to_owned(),
            beta_features: "remote_compaction_v2".to_owned(),
            installation_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            accept_encoding: "gzip, deflate".to_owned(),
            max_body_bytes: 10 * 1024 * 1024,
            timeout_secs: 120,
        }
    }

    fn state_for(base: &str) -> AppState {
        AppState {
            client: crate::tls::build_client(30),
            cfg: Arc::new(test_cfg(base)),
        }
    }

    #[tokio::test]
    async fn forwards_path_and_query_to_upstream() {
        let (base, rec) = spawn_recording_upstream().await;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/responses?foo=bar&baz=1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"model":"m"}"#))
            .unwrap();
        proxy(State(state_for(&base)), req).await;

        let guard = rec.lock().unwrap();
        let r = guard.as_ref().expect("upstream received a request");
        assert_eq!(r.path, "/v1/responses");
        assert_eq!(r.query.as_deref(), Some("foo=bar&baz=1"));
    }

    #[tokio::test]
    async fn applies_synthesized_identity_to_upstream_request() {
        // A non-codex client (curl) must reach the upstream wearing the full
        // synthesized Codex identity, proving proxy runs resolve→apply_to_headers.
        let (base, rec) = spawn_recording_upstream().await;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header("user-agent", "curl/8.0")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"model":"m"}"#))
            .unwrap();
        proxy(State(state_for(&base)), req).await;

        let guard = rec.lock().unwrap();
        let r = guard.as_ref().unwrap();
        let ua = r.headers.get("user-agent").unwrap().to_str().unwrap();
        assert!(ua.starts_with("codex-tui/"), "curl UA replaced, got {ua:?}");
        assert!(r.headers.get("session-id").is_some());
        assert!(r.headers.get("x-codex-installation-id").is_some());
        assert!(r.headers.get("x-codex-turn-metadata").is_some());
    }

    #[tokio::test]
    async fn injects_client_metadata_into_json_body_on_the_wire() {
        // The gate field must be present in the body the upstream actually
        // receives, proving proxy runs ensure_body_metadata before sending.
        let (base, rec) = spawn_recording_upstream().await;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"model":"m","stream":true}"#))
            .unwrap();
        proxy(State(state_for(&base)), req).await;

        let guard = rec.lock().unwrap();
        let r = guard.as_ref().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["model"], "m");
        assert_eq!(v["stream"], true);
        assert!(
            v["client_metadata"]["x-codex-installation-id"].is_string(),
            "gate field must be injected on the wire"
        );
    }

    #[tokio::test]
    async fn strips_content_length_but_passes_custom_response_headers() {
        let (base, _rec) = spawn_recording_upstream().await;
        let req = Request::builder()
            .method("GET")
            .uri("/x")
            .body(Body::empty())
            .unwrap();
        let resp = proxy(State(state_for(&base)), req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("content-length").is_none(),
            "hop-by-hop content-length must be stripped"
        );
        assert_eq!(resp.headers().get("x-upstream-custom").unwrap(), "yes");
    }

    #[tokio::test]
    async fn streams_response_body_byte_for_byte() {
        let (base, _rec) = spawn_recording_upstream().await;
        let req = Request::builder()
            .method("GET")
            .uri("/x")
            .body(Body::empty())
            .unwrap();
        let resp = proxy(State(state_for(&base)), req).await;

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            bytes.as_ref(),
            CANNED_BODY,
            "response body must pass through verbatim"
        );
    }

    #[tokio::test]
    async fn connect_error_maps_to_502_json() {
        // Nothing listens on port 1 → a connect error (not a timeout) → 502 with
        // the OpenAI-style error envelope.
        let state = state_for("http://127.0.0.1:1");
        let req = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"model":"m"}"#))
            .unwrap();
        let resp = proxy(State(state), req).await;

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["type"], "proxy_connect_error");
    }

    #[tokio::test]
    async fn health_reports_identity_config() {
        let resp = health(State(state_for("http://upstream.test/codex")))
            .await
            .into_response();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["egress"], "rustls-single-process");
        assert_eq!(v["originator"], "codex-tui");
    }
}
