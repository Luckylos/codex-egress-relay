//! Codex CLI identity synthesis — the header contract that gets a request past
//! a relay's client-identity gate and treated as a genuine Codex CLI turn.
//!
//! Ported byte-for-byte from the original Python `codex-ua-proxy`, then verified
//! against a captured interactive Codex CLI v0.145.0 session.
//!
//! ## Contract
//!
//! A real Codex CLI turn carries a fixed set of structural headers. Policy is
//! **"may be unused, must never be absent"**: every identity header is always
//! emitted exactly once, canonically cased. Client-sent casing variants are
//! dropped first (dedup) so the upstream never sees duplicates that would flag
//! the request as a spoof.
//!
//! ## Preserve vs. synthesize
//!
//! - If the client is a *genuine* Codex CLI (its UA/originator start with
//!   `codex-`/`codex_`), its supplied identity values are preserved untouched.
//! - Otherwise the canonical TUI identity is synthesized session-coherently:
//!   `session-id`, `thread-id`, `x-client-request-id`, `x-codex-window-id`, and
//!   the turn-metadata `session_id`/`thread_id` all derive from ONE session
//!   UUID, with `window-id = "<session>:0"`.
//!
//! `version` and `conversation_id` are intentionally never emitted — the real
//! client does not send them, so synthesizing them would itself be a tell.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::config::Config;

/// Structural identity headers a real Codex CLI carries. Listed lowercased so
/// any client-sent casing variant is dropped first. `version`/`conversation_id`
/// are intentionally NOT here.
pub const IDENTITY_HEADERS: &[&str] = &[
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

/// Request-side hop-by-hop headers that must not be forwarded.
pub const HOP_BY_HOP: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
];

/// Is this a genuine Codex client token (UA or originator)?
fn is_codex(s: &str) -> bool {
    s.starts_with("codex-") || s.starts_with("codex_")
}

/// Build the upstream header set: pass through non-hop, non-identity client
/// headers verbatim, then enforce the Codex CLI identity contract.
pub fn build_upstream_headers(cfg: &Config, incoming: &HeaderMap) -> HeaderMap {
    let get = |name: &str| -> String {
        incoming
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };

    let mut out = HeaderMap::new();

    // Pass through everything that is neither hop-by-hop nor an identity header
    // (identity headers are re-set canonically below; dropping them here dedups
    // any client casing variant).
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
        if s.is_empty() {
            get("session_id")
        } else {
            s
        }
    };
    let client_thread = {
        let s = get("thread-id");
        if s.is_empty() {
            get("thread_id")
        } else {
            s
        }
    };
    let client_reqid = get("x-client-request-id");
    let client_window = get("x-codex-window-id");
    let client_install = get("x-codex-installation-id");
    let client_beta = get("x-codex-beta-features");
    let client_turn_meta = get("x-codex-turn-metadata");

    // user-agent / originator: keep genuine codex values, else synthesize.
    let ua = if is_codex(&client_ua) {
        client_ua
    } else {
        cfg.user_agent.clone()
    };
    let orig = if is_codex(&client_orig) {
        client_orig
    } else {
        cfg.originator.clone()
    };

    // Session-coherent identity: tie every dependent header to ONE session UUID.
    let session_id = if client_session.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        client_session
    };
    let thread_id = if client_thread.is_empty() {
        session_id.clone()
    } else {
        client_thread
    };
    let installation_id = if client_install.is_empty() {
        cfg.installation_id.clone()
    } else {
        client_install
    };
    let window_id = if client_window.is_empty() {
        format!("{session_id}:0")
    } else {
        client_window
    };
    let reqid = if client_reqid.is_empty() {
        session_id.clone()
    } else {
        client_reqid
    };
    let beta = if client_beta.is_empty() {
        cfg.beta_features.clone()
    } else {
        client_beta
    };

    let turn_meta = if client_turn_meta.is_empty() {
        synthesize_turn_metadata(&installation_id, &session_id, &thread_id, &window_id)
    } else {
        client_turn_meta
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

/// Synthesize the `x-codex-turn-metadata` JSON blob a real turn carries, with a
/// fresh per-turn `turn_id` and the shared session/thread/window identifiers.
fn synthesize_turn_metadata(
    installation_id: &str,
    session_id: &str,
    thread_id: &str,
    window_id: &str,
) -> String {
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
}

/// Insert a header, silently skipping values that are not valid header content.
fn set(m: &mut HeaderMap, k: &'static str, v: &str) {
    if let Ok(val) = HeaderValue::from_str(v) {
        m.insert(HeaderName::from_static(k), val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> Config {
        Config {
            upstream_base_url: "https://upstream.test/codex".to_owned(),
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

    fn hv(m: &HeaderMap, k: &str) -> String {
        m.get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    }

    // --- Synthesize path: a non-codex client gets a full, coherent identity ---

    #[test]
    fn synthesizes_full_identity_for_non_codex_client() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        incoming.insert("user-agent", HeaderValue::from_static("curl/8.0"));

        let out = build_upstream_headers(&cfg, &incoming);

        // Non-codex UA/originator are replaced with the canonical values.
        assert_eq!(hv(&out, "user-agent"), cfg.user_agent);
        assert_eq!(hv(&out, "originator"), "codex-tui");
        // accept-encoding is forced canonical (a br/zstd value never leaks).
        assert_eq!(hv(&out, "accept-encoding"), "gzip, deflate");
        // Every structural identity header is present.
        for h in [
            "session-id",
            "thread-id",
            "x-client-request-id",
            "x-codex-window-id",
            "x-codex-installation-id",
            "x-codex-beta-features",
            "x-codex-turn-metadata",
        ] {
            assert!(!hv(&out, h).is_empty(), "missing identity header {h}");
        }
    }

    #[test]
    fn synthesized_identity_is_session_coherent() {
        let cfg = test_cfg();
        let incoming = HeaderMap::new();

        let out = build_upstream_headers(&cfg, &incoming);

        let session = hv(&out, "session-id");
        // thread-id, x-client-request-id mirror the session id.
        assert_eq!(hv(&out, "thread-id"), session);
        assert_eq!(hv(&out, "x-client-request-id"), session);
        // window-id is "<session>:0".
        assert_eq!(hv(&out, "x-codex-window-id"), format!("{session}:0"));

        // turn-metadata's session/thread fields agree with the headers.
        let tm: serde_json::Value =
            serde_json::from_str(&hv(&out, "x-codex-turn-metadata")).unwrap();
        assert_eq!(tm["session_id"], session);
        assert_eq!(tm["thread_id"], session);
        assert_eq!(tm["window_id"], format!("{session}:0"));
        assert_eq!(tm["installation_id"], cfg.installation_id);
        assert_eq!(tm["request_kind"], "turn");
    }

    // --- Preserve path: a genuine codex client is not tampered with ----------

    #[test]
    fn preserves_genuine_codex_client_identity() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        let real_ua = "codex-tui/0.145.0 (Ubuntu 24.04; x86_64) WezTerm (codex-tui; 0.145.0)";
        incoming.insert("user-agent", HeaderValue::from_static(real_ua));
        incoming.insert("originator", HeaderValue::from_static("codex-tui"));
        incoming.insert(
            "session-id",
            HeaderValue::from_static("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        );

        let out = build_upstream_headers(&cfg, &incoming);

        assert_eq!(hv(&out, "user-agent"), real_ua);
        assert_eq!(hv(&out, "originator"), "codex-tui");
        assert_eq!(
            hv(&out, "session-id"),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );
        // thread-id/window-id derive from the preserved session.
        assert_eq!(
            hv(&out, "thread-id"),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );
        assert_eq!(
            hv(&out, "x-codex-window-id"),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:0"
        );
    }

    // --- Dedup: client casing variants never produce duplicate headers -------

    #[test]
    fn dedups_client_casing_variants() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        // Client sends a mixed-case Session-Id AND snake_case session_id.
        incoming.insert("Session-Id", HeaderValue::from_static("client-session-xyz"));
        incoming.insert("session_id", HeaderValue::from_static("client-session-xyz"));

        let out = build_upstream_headers(&cfg, &incoming);

        // Exactly one canonical session-id survives.
        assert_eq!(out.get_all("session-id").iter().count(), 1);
        assert_eq!(hv(&out, "session-id"), "client-session-xyz");
    }

    // --- Passthrough: unrelated headers flow through untouched ----------------

    #[test]
    fn passes_through_non_identity_headers() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        incoming.insert("authorization", HeaderValue::from_static("Bearer sk-test"));
        incoming.insert("content-type", HeaderValue::from_static("application/json"));

        let out = build_upstream_headers(&cfg, &incoming);

        assert_eq!(hv(&out, "authorization"), "Bearer sk-test");
        assert_eq!(hv(&out, "content-type"), "application/json");
    }

    #[test]
    fn strips_hop_by_hop_headers() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        incoming.insert("host", HeaderValue::from_static("proxy.local"));
        incoming.insert("connection", HeaderValue::from_static("keep-alive"));

        let out = build_upstream_headers(&cfg, &incoming);

        assert!(out.get("host").is_none());
        assert!(out.get("connection").is_none());
    }

    #[test]
    fn non_codex_originator_is_replaced() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        incoming.insert("originator", HeaderValue::from_static("evilclient"));

        let out = build_upstream_headers(&cfg, &incoming);

        assert_eq!(hv(&out, "originator"), "codex-tui");
    }
}
