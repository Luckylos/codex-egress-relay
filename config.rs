//! Runtime configuration, sourced entirely from the environment.
//!
//! Only `CODEX_PROXY_UPSTREAM_URL` is required; everything else defaults to the
//! values captured from a real interactive Codex CLI v0.145.0 session so the
//! synthesized identity matches the genuine client out of the box.

use uuid::Uuid;

/// Read an env var, treating empty strings as absent.
pub fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// Immutable per-process configuration. Cloned identity values are cheap enough
/// (a handful of short strings) that we favor owned `String`s over lifetimes.
pub struct Config {
    pub upstream_base_url: String,
    pub port: u16,
    pub user_agent: String,
    pub originator: String,
    pub beta_features: String,
    pub installation_id: String,
    pub accept_encoding: String,
    /// Upper bound on a buffered request body (bytes). The body is read fully
    /// before replay to the upstream, so this caps memory per in-flight request.
    pub max_body_bytes: usize,
    /// Upstream request timeout (seconds).
    pub timeout_secs: u64,
}

impl Config {
    /// Build config from the environment, panicking only on a missing/empty
    /// required upstream URL (a fatal misconfiguration that must fail fast).
    pub fn from_env() -> Self {
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
            if v.is_empty() {
                Uuid::new_v4().to_string()
            } else {
                v
            }
        };
        let accept_encoding = env_or("CODEX_PROXY_ACCEPT_ENCODING", "gzip, deflate");
        let timeout_secs: u64 = env_or("CODEX_PROXY_TIMEOUT", "120").parse().unwrap_or(120);
        // Default 10 MiB, matching the former Python proxy's buffer ceiling.
        let max_body_bytes: usize = env_or("CODEX_PROXY_MAX_BODY_BYTES", "10485760")
            .parse()
            .unwrap_or(10 * 1024 * 1024);

        Config {
            upstream_base_url,
            port,
            user_agent,
            originator,
            beta_features,
            installation_id,
            accept_encoding,
            max_body_bytes,
            timeout_secs,
        }
    }
}
