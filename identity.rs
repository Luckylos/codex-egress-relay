//! Codex CLI identity synthesis — the header + body contract that gets a
//! request past a relay's client-identity gate and treated as a genuine Codex
//! CLI turn.
//!
//! Ported from the original Python `codex-ua-proxy`, then verified against a
//! captured interactive Codex CLI v0.145.0 session and a live upstream gate.
//!
//! ## Single source of truth
//!
//! A turn's identity spans two wire layers:
//!
//!   1. the structural **headers** (`user-agent`, `session-id`, … ), and
//!   2. the request **body**'s `client_metadata` object — empirically the sole
//!      field the upstream gate validates (it checks that
//!      `client_metadata.x-codex-installation-id` is present).
//!
//! Both layers are *projections of one* [`ResolvedIdentity`], resolved once per
//! request. Because the installation-id, session, thread, window and turn ids
//! all come from that single value, the header layer and the body layer can
//! never disagree — the class of bug that plagues "patch the headers here,
//! patch the body there" designs is structurally impossible.
//!
//! ## Preserve vs. synthesize
//!
//! - A *genuine* Codex CLI (its UA/originator start with `codex-`/`codex_`, or
//!   it already carries the relevant field) is preserved untouched: its header
//!   values pass through, and a body that already has `client_metadata` is left
//!   byte-for-byte intact.
//! - Any other client gets a full, session-coherent identity synthesized:
//!   `session-id`, `thread-id`, `x-client-request-id`, `x-codex-window-id` and
//!   the turn-metadata all derive from ONE session UUID, with
//!   `window-id = "<session>:0"`, and a matching `client_metadata` is injected
//!   into the JSON body.
//!
//! `version` and `conversation_id` are intentionally never emitted — the real
//! client does not send them, so synthesizing them would itself be a tell.

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::config::Config;

/// Structural identity headers a real Codex CLI carries. Listed lowercased so
/// any client-sent casing variant is dropped first. `version`/`conversation_id`
/// are intentionally NOT here.
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

/// Request-side hop-by-hop headers that must not be forwarded.
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

/// Is this a genuine Codex client token (UA or originator)?
fn is_codex(s: &str) -> bool {
    s.starts_with("codex-") || s.starts_with("codex_")
}

/// The one resolved identity for a single turn. Every wire artifact — headers
/// and the body's `client_metadata` — is a projection of this value, so the two
/// layers cannot drift apart. Build with [`ResolvedIdentity::resolve`].
pub struct ResolvedIdentity {
    user_agent: String,
    originator: String,
    accept_encoding: String,
    session_id: String,
    thread_id: String,
    request_id: String,
    window_id: String,
    installation_id: String,
    beta_features: String,
    turn_id: String,
    turn_started_at_ms: u128,
    /// A genuine client's own `x-codex-turn-metadata` blob, preserved verbatim
    /// when present so a real Codex turn is never rewritten.
    client_turn_metadata: Option<String>,
}

impl ResolvedIdentity {
    /// Resolve the turn identity from the incoming request headers, preserving
    /// genuine Codex values and synthesizing session-coherent ones otherwise.
    pub fn resolve(cfg: &Config, incoming: &HeaderMap) -> Self {
        let get = |name: &str| -> String {
            incoming
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        };

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
        let user_agent = if is_codex(&client_ua) {
            client_ua
        } else {
            cfg.user_agent.clone()
        };
        let originator = if is_codex(&client_orig) {
            client_orig
        } else {
            cfg.originator.clone()
        };

        // Session-coherent identity: tie every dependent value to ONE session.
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
        let request_id = if client_reqid.is_empty() {
            session_id.clone()
        } else {
            client_reqid
        };
        let beta_features = if client_beta.is_empty() {
            cfg.beta_features.clone()
        } else {
            client_beta
        };
        let client_turn_metadata = if client_turn_meta.is_empty() {
            None
        } else {
            Some(client_turn_meta)
        };

        let turn_started_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        Self {
            user_agent,
            originator,
            accept_encoding: cfg.accept_encoding.clone(),
            session_id,
            thread_id,
            request_id,
            window_id,
            installation_id,
            beta_features,
            turn_id: Uuid::new_v4().to_string(),
            turn_started_at_ms,
            client_turn_metadata,
        }
    }

    /// Project onto the upstream header set: pass through every client header
    /// that is neither hop-by-hop nor an identity header (dropping identity
    /// headers here dedups any client casing variant), then emit each canonical
    /// identity header exactly once.
    pub fn apply_to_headers(&self, incoming: &HeaderMap) -> HeaderMap {
        let mut out = HeaderMap::new();
        for (name, value) in incoming.iter() {
            let lname = name.as_str().to_ascii_lowercase();
            if HOP_BY_HOP.contains(&lname.as_str()) || IDENTITY_HEADERS.contains(&lname.as_str()) {
                continue;
            }
            out.insert(name.clone(), value.clone());
        }

        set(&mut out, "user-agent", &self.user_agent);
        set(&mut out, "originator", &self.originator);
        set(&mut out, "accept-encoding", &self.accept_encoding);
        set(&mut out, "session-id", &self.session_id);
        set(&mut out, "thread-id", &self.thread_id);
        set(&mut out, "x-client-request-id", &self.request_id);
        set(&mut out, "x-codex-window-id", &self.window_id);
        set(&mut out, "x-codex-installation-id", &self.installation_id);
        set(&mut out, "x-codex-beta-features", &self.beta_features);
        set(
            &mut out,
            "x-codex-turn-metadata",
            &self.turn_metadata_json(),
        );
        out
    }

    /// Ensure a JSON request body carries the `client_metadata` object the
    /// upstream gate validates. A body that already has one (a genuine Codex
    /// turn) is returned byte-for-byte unchanged; anything that is not a JSON
    /// object — wrong content-type, unparseable, or a non-object top level —
    /// passes through untouched so non-Responses traffic is never corrupted.
    pub fn ensure_body_metadata(&self, content_type: Option<&str>, body: Bytes) -> Bytes {
        let is_json = content_type
            .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
            .unwrap_or(false);
        if !is_json {
            return body;
        }

        let Ok(serde_json::Value::Object(mut obj)) =
            serde_json::from_slice::<serde_json::Value>(&body)
        else {
            return body;
        };

        // A genuine codex body already carries client_metadata; never rewrite.
        if obj.contains_key("client_metadata") {
            return body;
        }

        obj.insert("client_metadata".to_owned(), self.client_metadata());
        serde_json::to_vec(&serde_json::Value::Object(obj))
            .map(Bytes::from)
            .unwrap_or(body)
    }

    /// The `x-codex-turn-metadata` JSON string — the client's own blob if it
    /// supplied one, else synthesized with a fresh per-turn `turn_id` and the
    /// shared session/thread/window identifiers.
    fn turn_metadata_json(&self) -> String {
        if let Some(tm) = &self.client_turn_metadata {
            return tm.clone();
        }
        serde_json::json!({
            "installation_id": self.installation_id,
            "session_id": self.session_id,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "window_id": self.window_id,
            "request_kind": "turn",
            "thread_source": "user",
            "sandbox": "none",
            "turn_started_at_unix_ms": self.turn_started_at_ms,
        })
        .to_string()
    }

    /// The body's `client_metadata` object, mirroring the real Codex CLI shape.
    /// `x-codex-installation-id` is the field the gate checks; the rest complete
    /// the genuine shape and stay coherent with the header layer.
    fn client_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "x-codex-installation-id": self.installation_id,
            "x-codex-turn-metadata": self.turn_metadata_json(),
            "x-codex-window-id": self.window_id,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "session_id": self.session_id,
        })
    }
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

    /// Resolve + project to headers, mirroring the proxy's request path.
    fn headers_for(cfg: &Config, incoming: &HeaderMap) -> HeaderMap {
        ResolvedIdentity::resolve(cfg, incoming).apply_to_headers(incoming)
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

        let out = headers_for(&cfg, &incoming);

        assert_eq!(hv(&out, "user-agent"), cfg.user_agent);
        assert_eq!(hv(&out, "originator"), "codex-tui");
        assert_eq!(hv(&out, "accept-encoding"), "gzip, deflate");
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

        let out = headers_for(&cfg, &incoming);

        let session = hv(&out, "session-id");
        assert_eq!(hv(&out, "thread-id"), session);
        assert_eq!(hv(&out, "x-client-request-id"), session);
        assert_eq!(hv(&out, "x-codex-window-id"), format!("{session}:0"));

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

        let out = headers_for(&cfg, &incoming);

        assert_eq!(hv(&out, "user-agent"), real_ua);
        assert_eq!(hv(&out, "originator"), "codex-tui");
        assert_eq!(
            hv(&out, "session-id"),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );
        assert_eq!(
            hv(&out, "thread-id"),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );
        assert_eq!(
            hv(&out, "x-codex-window-id"),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:0"
        );
    }

    // --- Dedup / passthrough / hop-by-hop ------------------------------------

    #[test]
    fn dedups_client_casing_variants() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        incoming.insert("Session-Id", HeaderValue::from_static("client-session-xyz"));
        incoming.insert("session_id", HeaderValue::from_static("client-session-xyz"));

        let out = headers_for(&cfg, &incoming);

        assert_eq!(out.get_all("session-id").iter().count(), 1);
        assert_eq!(hv(&out, "session-id"), "client-session-xyz");
    }

    #[test]
    fn passes_through_non_identity_headers() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        incoming.insert("authorization", HeaderValue::from_static("Bearer sk-test"));
        incoming.insert("content-type", HeaderValue::from_static("application/json"));

        let out = headers_for(&cfg, &incoming);

        assert_eq!(hv(&out, "authorization"), "Bearer sk-test");
        assert_eq!(hv(&out, "content-type"), "application/json");
    }

    #[test]
    fn strips_hop_by_hop_headers() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        incoming.insert("host", HeaderValue::from_static("proxy.local"));
        incoming.insert("connection", HeaderValue::from_static("keep-alive"));

        let out = headers_for(&cfg, &incoming);

        assert!(out.get("host").is_none());
        assert!(out.get("connection").is_none());
    }

    #[test]
    fn non_codex_originator_is_replaced() {
        let cfg = test_cfg();
        let mut incoming = HeaderMap::new();
        incoming.insert("originator", HeaderValue::from_static("evilclient"));

        let out = headers_for(&cfg, &incoming);

        assert_eq!(hv(&out, "originator"), "codex-tui");
    }

    // --- Body injection: the client_metadata gate contract -------------------

    #[test]
    fn injects_client_metadata_into_bare_json_body() {
        let cfg = test_cfg();
        let id = ResolvedIdentity::resolve(&cfg, &HeaderMap::new());
        let body = Bytes::from_static(br#"{"model":"gpt-5.6-terra","stream":true}"#);

        let out = id.ensure_body_metadata(Some("application/json"), body);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();

        // Original fields survive, client_metadata is added with the gate field.
        assert_eq!(v["model"], "gpt-5.6-terra");
        assert_eq!(v["stream"], true);
        assert!(
            v["client_metadata"]["x-codex-installation-id"].is_string(),
            "gate field must be present"
        );
    }

    #[test]
    fn injected_metadata_matches_header_installation_id() {
        // Single-source-of-truth guarantee: the body's installation id equals
        // the header's, because both project from one ResolvedIdentity.
        let cfg = test_cfg();
        let incoming = HeaderMap::new();
        let id = ResolvedIdentity::resolve(&cfg, &incoming);

        let header_install = {
            let h = id.apply_to_headers(&incoming);
            hv(&h, "x-codex-installation-id")
        };
        let body = id.ensure_body_metadata(
            Some("application/json"),
            Bytes::from_static(br#"{"model":"m"}"#),
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["client_metadata"]["x-codex-installation-id"],
            header_install
        );
        assert_eq!(header_install, cfg.installation_id);
    }

    #[test]
    fn preserves_body_that_already_has_client_metadata() {
        // A genuine codex body is returned byte-for-byte unchanged.
        let cfg = test_cfg();
        let id = ResolvedIdentity::resolve(&cfg, &HeaderMap::new());
        let original = br#"{"model":"m","client_metadata":{"x-codex-installation-id":"real"}}"#;
        let body = Bytes::from_static(original);

        let out = id.ensure_body_metadata(Some("application/json"), body);

        assert_eq!(
            out.as_ref(),
            &original[..],
            "existing metadata must not change"
        );
    }

    #[test]
    fn non_json_body_passes_through_untouched() {
        let cfg = test_cfg();
        let id = ResolvedIdentity::resolve(&cfg, &HeaderMap::new());
        let raw = Bytes::from_static(b"not json at all");

        let same = id
            .clone_for_test()
            .ensure_body_metadata(Some("text/plain"), raw.clone());
        assert_eq!(same.as_ref(), raw.as_ref());

        // Unparseable JSON content-type also passes through.
        let bad = id.ensure_body_metadata(Some("application/json"), Bytes::from_static(b"{bad"));
        assert_eq!(bad.as_ref(), b"{bad");
    }

    impl ResolvedIdentity {
        /// Test-only shallow rebuild so a second `ensure_body_metadata` call can
        /// run without moving the original (the method takes `&self`).
        fn clone_for_test(&self) -> Self {
            Self {
                user_agent: self.user_agent.clone(),
                originator: self.originator.clone(),
                accept_encoding: self.accept_encoding.clone(),
                session_id: self.session_id.clone(),
                thread_id: self.thread_id.clone(),
                request_id: self.request_id.clone(),
                window_id: self.window_id.clone(),
                installation_id: self.installation_id.clone(),
                beta_features: self.beta_features.clone(),
                turn_id: self.turn_id.clone(),
                turn_started_at_ms: self.turn_started_at_ms,
                client_turn_metadata: self.client_turn_metadata.clone(),
            }
        }
    }
}
