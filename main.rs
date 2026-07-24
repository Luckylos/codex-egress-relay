//! Codex egress proxy — single-process identity + TLS/H2 fingerprint layer.
//!
//! Collapses the former two-process chain
//!   client → FastAPI codex-ua-proxy (identity) → Rust relay (rustls egress) → upstream
//! into ONE process:
//!   client → codex-egress-relay (identity + rustls egress) → upstream
//! removing a loopback HTTP hop and the Python/uvicorn overhead per request.
//!
//! It replicates the REAL Codex CLI in two dimensions, both verified against a
//! captured interactive `codex` v0.145.0 session:
//!
//! 1. IDENTITY (`identity` module) — the Codex CLI header contract:
//!    user-agent, originator, session-id, thread-id, x-client-request-id,
//!    x-codex-window-id, x-codex-installation-id, x-codex-beta-features,
//!    x-codex-turn-metadata, accept-encoding. Client-sent casings are
//!    dropped first (dedup), then exactly one canonical copy re-set.
//!    Genuine client-supplied codex values are preserved; missing ones are
//!    synthesized session-coherently. `version`/`conversation_id` are NOT
//!    sent (the real client does not send them).
//!
//! 2. TLS/H2 FINGERPRINT (`tls` module) — rustls 0.23 + aws-lc-rs + h2:
//!    JA4    : t13d1011h2_61a7ad8aa9b6_f9531d972513
//!    Akamai : 2:0;4:2097152;5:16384;6:16384|5177345|0|m,s,a,p
//!    The aws-lc-rs crypto provider (NOT ring) is what makes the JA4 match
//!    byte-for-byte; see `tls.rs` for the full rationale. reqwest's auto
//!    gzip/deflate/brotli is disabled so the response body streams
//!    byte-for-byte (content-encoding preserved).
//!
//! Config (env, see `config.rs`): only `CODEX_PROXY_UPSTREAM_URL` is required.

mod config;
mod identity;
mod proxy;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    routing::{any, get},
    Router,
};

use config::Config;
use proxy::{health, proxy as proxy_handler, AppState};

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
    let port = cfg.port;

    let client = tls::build_client(cfg.timeout_secs);

    eprintln!(
        "codex-egress-relay v0.2 (single-process): upstream={} ua={} originator={} \
         beta={} installation={} accept-encoding={:?} timeout={}s max-body={}B",
        cfg.upstream_base_url,
        cfg.user_agent,
        cfg.originator,
        cfg.beta_features,
        cfg.installation_id,
        cfg.accept_encoding,
        cfg.timeout_secs,
        cfg.max_body_bytes,
    );

    let state = AppState {
        client,
        cfg: Arc::new(cfg),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/*path", any(proxy_handler))
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

/// Resolve on either Ctrl-C (SIGINT, interactive) or SIGTERM (what systemd
/// sends on `restart`/`stop`). Handling SIGTERM lets axum drain in-flight
/// requests and exit promptly instead of being SIGKILLed after TimeoutStopSec.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    eprintln!("codex-egress-relay shutting down");
}
