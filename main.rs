//! Codex egress proxy — single-process identity + TLS/H2 fingerprint layer.
//!
//! This is the Rust rewrite that collapses the former two-process chain
//!   client → FastAPI codex-ua-proxy (identity) → Rust relay (rustls egress) → upstream
//! into ONE process:
//!   client → codex-egress-relay (identity + rustls egress) → upstream
//! removing a loopback HTTP hop and the Python/uvicorn overhead per request.
//!
//! It replicates the REAL Codex CLI in two dimensions, both verified against a
//! captured interactive `codex` v0.145.0 session and tls.peet.ws:
//!
//!   1. IDENTITY (header set) — ported byte-for-byte from the Python proxy:
//!        user-agent, originator, session-id, thread-id, x-client-request-id,
//!        x-codex-window-id, x-codex-installation-id, x-codex-beta-features,
//!        x-codex-turn-metadata, accept-encoding. Client-sent casings of these
//!        are dropped first (dedup), then exactly one canonical copy re-set.
//!        Genuine client-supplied codex values are preserved; missing ones are
//!        synthesized session-coherently. `version`/`conversation_id` are NOT
//!        sent (the real client does not send them).
//!
//!   2. TLS/H2 FINGERPRINT — reqwest + rustls 0.23 + h2 crate (same as codex):
//!        JA4    : t13d1011h2_61a7ad8aa9b6_3fcd1a44f3e3
//!        Akamai : 2:0;4:2097152;5:16384;6:16384|5177345|0|m,s,a,p
//!      default-features=false disables reqwest auto gzip/deflate/brotli so the
//!      response body is streamed byte-for-byte (content-encoding preserved).
//!
//! Config (env, all optional except UPSTREAM_URL):
//!   CODEX_PROXY_UPSTREAM_URL      (required) e.g. https://new.sharedchat.cc/codex
//!   CODEX_PROXY_PORT              default 18092
//!   CODEX_PROXY_UA_VERSION        default 0.145.0
//!   CODEX_PROXY_ORIGINATOR        default codex-tui
//!   CODEX_PROXY_UA_OS             default "Debian 12.0.0; x86_64"
//!   CODEX_PROXY_UA_TERMINAL       default unknown
//!   CODEX_PROXY_USER_AGENT        default derived from the above
//!   CODEX_PROXY_BETA_FEATURES     default remote_compaction_v2
//!   CODEX_PROXY_INSTALLATION_ID   default random uuid (stable per process)
//!   CODEX_PROXY_ACCEPT_ENCODING   default "gzip, deflate"
//!   CODEX_PROXY_TIMEOUT           default 120 (seconds)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};
use futures_util::TryStreamExt;
use uuid::Uuid;

// Structural identity headers a real Codex CLI carries. Policy: "may be unused,
// must never be absent". Listed lowercased so any client-sent casing variant is
// dropped first, preventing duplicate headers that would flag the request as a
// spoof. `version`/`conversation_id` are intentionally NOT here.
const IDENTITY_HEADERS: &[&str] = &[
    "user-agent",
    "originator",
    "session-id",
    "session_id",
    "thread-id",
    "thread_id",
    "x-client-request-id",
    "x-codex-window-id",
    "x-codex-installation-id",
    "x-codex-beta-features",
    "x-codex-turn-metadata",
    "accept-encoding",
];

// Headers that must not be forwarded between hops (request side).
const HOP_BY_HOP: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
];

// Response headers not to forward back.
const STRIP_RESPONSE: &[&str] = &[
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

struct Config {
    upstream_base_url: String,
    port: u16,
    user_agent: String,
    originator: String,
    beta_features: String,
    installation_id: String,
    accept_encoding: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_owned())
}

impl Config {
    fn from_env() -> Self {
        let upstream_base_url = env_or("CODEX_PROXY_UPSTREAM_URL", "")
            .trim_end_matches('/')
            .to_owned();
        if upstream_base_url.is_empty() {
            panic!(
                "CODEX_PROXY_UPSTREAM_URL is required. \
                 Example: CODEX_PROXY_UPSTREAM_URL=https://new.sharedchat.cc/codex"
            );
        }
        let port: u16 = env_or("CODEX_PROXY_PORT", "18092").parse().unwrap_or(18092);

        let ua_version = env_or("CODEX_PROXY_UA_VERSION", "0.145.0");
        let originator = env_or("CODEX_PROXY_ORIGINATOR", "codex-tui");
        let ua_os = env_or("CODEX_PROXY_UA_OS", "Debian 12.0.0; x86_64");
        let ua_terminal = env_or("CODEX_PROXY_UA_TERMINAL", "unknown");
        // <originator>/<ver> (<os>) <terminal> (<originator>; <ver>)
        let default_ua = format!(
            "{originator}/{ua_version} ({ua_os}) {ua_terminal} ({originator}; {ua_version})"
        );
        let user_agent = env_or("CODEX_PROXY_USER_AGENT", &default_ua);

        let beta_features = env_or("CODEX_PROXY_BETA_FEATURES", "remote_compaction_v2");
        let installation_id = {
            let v = env_or("CODEX_PROXY_INSTALLATION_ID", "");
            if v.is_empty() { Uuid::new_v4().to_string() } else { v }
        };
        let accept_encoding = env_or("CODEX_PROXY_ACCEPT_ENCODING", "gzip, deflate");

        Config {
            upstream_base_url,
            port,
            user_agent,
            originator,
            beta_features,
            installation_id,
            accept_encoding,
        }
    }
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    cfg: Arc<Config>,
}

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
    let timeout: u64 = env_or("CODEX_PROXY_TIMEOUT", "120").parse().unwrap_or(120);
    let port = cfg.port;

    // Build the rustls ClientConfig ourselves so it is backed by the aws-lc-rs
    // crypto provider (NOT ring). This is what makes the ClientHello's
    // signature_algorithms include ecdsa_secp521r1_sha512 (0x0603) — the sole
    // byte that differed from the real Codex CLI's JA4 (verified by capturing
    // the native codex binary's ClientHello). aws-lc-rs is also the provider
    // the real Codex CLI uses, so the full sigalg set matches.
    //
    // ALPN offers h2 then http/1.1, exactly as the real client, so the JA4
    // ALPN marker stays `h2` and the negotiated protocol is HTTP/2.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws-lc-rs provider supports default protocol versions")
    .with_root_certificates(root_store)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // One shared rustls client => connection pooling / keep-alive, mirroring how
    // the real Codex CLI reuses a single h2 connection for a session. Do NOT
    // enable http2_prior_knowledge (that sends h2c and drops the TLS ALPN
    // handshake the fingerprint depends on).
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(Duration::from_secs(timeout))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .expect("failed to build rustls reqwest client");

    let state = AppState { client, cfg: Arc::new(cfg) };

    eprintln!(
        "codex-egress-relay v0.2 (single-process): upstream={} ua={} originator={} beta={} installation={} accept-encoding={:?} timeout={}s",
        state.cfg.upstream_base_url, state.cfg.user_agent, state.cfg.originator,
        state.cfg.beta_features, state.cfg.installation_id, state.cfg.accept_encoding, timeout,
    );

    let app = Router::new()
        .route("/health", get(health))
        .route("/*path", any(proxy))
        .with_state(state);

    // Binds on all interfaces to take over the former FastAPI listen port. The
    // upstream URL is fixed by env (no control header), so exposure only relays
    // to that one configured upstream.
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr} failed: {e}"));
    eprintln!("codex-egress-relay listening on http://{addr} (identity + rustls/h2 egress)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("codex-egress-relay shutting down");
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
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

/// Build the upstream header set: pass through non-hop, non-identity client
/// headers, then enforce the Codex CLI identity contract (ported from Python).
fn build_upstream_headers(cfg: &Config, incoming: &HeaderMap) -> HeaderMap {
    // Case-insensitive lookup of client-supplied values.
    let get = |name: &str| -> String {
        incoming
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };

    let mut out = HeaderMap::new();

    // Pass through everything that is not hop-by-hop and not an identity header
    // (identity headers are re-set canonically below; dropping here dedups any
    // client casing variant).
    for (name, value) in incoming.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lname.as_str()) || IDENTITY_HEADERS.contains(&lname.as_str()) {
            continue;
        }
        out.insert(name.clone(), value.clone());
    }

    // Recover genuine client-supplied identity values.
    let client_ua = get("user-agent");
    let client_orig = get("originator");
    let client_session = {
        let s = get("session-id");
        if s.is_empty() { get("session_id") } else { s }
    };
    let client_thread = {
        let s = get("thread-id");
        if s.is_empty() { get("thread_id") } else { s }
    };
    let client_reqid = get("x-client-request-id");
    let client_window = get("x-codex-window-id");
    let client_install = get("x-codex-installation-id");
    let client_beta = get("x-codex-beta-features");
    let client_turn_meta = get("x-codex-turn-metadata");

    let is_codex = |s: &str| s.starts_with("codex-") || s.starts_with("codex_");

    // user-agent: keep a real codex UA, else synthesize the canonical TUI UA.
    let ua = if is_codex(&client_ua) { client_ua.clone() } else { cfg.user_agent.clone() };
    // originator: keep a genuine codex* value, else default.
    let orig = if is_codex(&client_orig) { client_orig.clone() } else { cfg.originator.clone() };

    // accept-encoding: force the canonical codex value so a non-codex value
    // (br/zstd) never leaks upstream.
    // Session-coherent identity: the real client ties session-id, thread-id,
    // x-client-request-id, window-id and the turn-metadata session/thread fields
    // to ONE session UUID. Derive once, keep every dependent header consistent.
    let session_id = if client_session.is_empty() { Uuid::new_v4().to_string() } else { client_session };
    let thread_id = if client_thread.is_empty() { session_id.clone() } else { client_thread };
    let installation_id = if client_install.is_empty() { cfg.installation_id.clone() } else { client_install };
    let window_id = if client_window.is_empty() { format!("{session_id}:0") } else { client_window };
    let reqid = if client_reqid.is_empty() { session_id.clone() } else { client_reqid };
    let beta = if client_beta.is_empty() { cfg.beta_features.clone() } else { client_beta };

    let turn_meta = if !client_turn_meta.is_empty() {
        client_turn_meta
    } else {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        serde_json::json!({
            "installation_id": installation_id,
            "session_id": session_id,
            "thread_id": thread_id,
            "turn_id": Uuid::new_v4().to_string(),
            "window_id": window_id,
            "request_kind": "turn",
            "thread_source": "user",
            "sandbox": "none",
            "turn_started_at_unix_ms": now_ms,
        })
        .to_string()
    };

    let set = |m: &mut HeaderMap, k: &'static str, v: &str| {
        if let Ok(val) = HeaderValue::from_str(v) {
            m.insert(HeaderName::from_static(k), val);
        }
    };
    set(&mut out, "user-agent", &ua);
    set(&mut out, "originator", &orig);
    set(&mut out, "accept-encoding", &cfg.accept_encoding);
    set(&mut out, "session-id", &session_id);
    set(&mut out, "thread-id", &thread_id);
    set(&mut out, "x-client-request-id", &reqid);
    set(&mut out, "x-codex-window-id", &window_id);
    set(&mut out, "x-codex-installation-id", &installation_id);
    set(&mut out, "x-codex-beta-features", &beta);
    set(&mut out, "x-codex-turn-metadata", &turn_meta);

    out
}

async fn proxy(State(state): State<AppState>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(|q| q.to_owned());

    let mut upstream_url = format!("{}{}", state.cfg.upstream_base_url, path);
    if let Some(q) = &query {
        upstream_url.push('?');
        upstream_url.push_str(q);
    }

    let headers = build_upstream_headers(&state.cfg, req.headers());

    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            return error_json(StatusCode::BAD_REQUEST, "proxy_read_error", &format!("read body: {e}"));
        }
    };

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
                return error_json(StatusCode::GATEWAY_TIMEOUT, "proxy_timeout", "Upstream timeout");
            }
            eprintln!("<<< 502 CONNECT_ERROR {path} ({ms}ms): {e}");
            return error_json(StatusCode::BAD_GATEWAY, "proxy_connect_error", "Upstream connect error");
        }
    };

    let status = upstream.status();
    let mut resp_headers = HeaderMap::new();
    for (name, value) in upstream.headers().iter() {
        if STRIP_RESPONSE.iter().any(|s| name.as_str().eq_ignore_ascii_case(s)) {
            continue;
        }
        resp_headers.insert(name.clone(), value.clone());
    }
    eprintln!("<<< {} {path} ({}ms)", status.as_u16(), start.elapsed().as_millis());

    // Stream body back byte-for-byte (no decompression: caller decodes per
    // content-encoding). SSE from the Responses API flows through untouched.
    let stream = upstream.bytes_stream().map_err(std::io::Error::other);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    response
}

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
