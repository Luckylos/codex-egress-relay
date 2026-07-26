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

/// The real Codex CLI user-agent shape:
/// `<originator>/<ver> (<os>) <terminal> (<originator>; <ver>)`.
///
/// This exact layout is part of the fingerprint contract — the upstream gate
/// and any UA-based heuristic see this string, so a silent format drift would
/// break the disguise. Kept as a pure function so the shape is unit-testable
/// without touching the environment.
fn build_default_ua(originator: &str, version: &str, os: &str, terminal: &str) -> String {
    format!("{originator}/{version} ({os}) {terminal} ({originator}; {version})")
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
        let default_ua = build_default_ua(&originator, &ua_version, &ua_os, &ua_terminal);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ua_matches_real_codex_shape() {
        // The captured Codex CLI v0.145.0 user-agent, byte-for-byte. A change to
        // build_default_ua's format string that breaks the disguise fails here.
        let ua = build_default_ua("codex-tui", "0.145.0", "Debian 12.0.0; x86_64", "unknown");
        assert_eq!(
            ua,
            "codex-tui/0.145.0 (Debian 12.0.0; x86_64) unknown (codex-tui; 0.145.0)"
        );
    }

    #[test]
    fn default_ua_repeats_originator_and_version_in_both_segments() {
        // The originator and version appear twice: leading token and trailing
        // parenthetical. Both must track the inputs so a genuine-looking UA is
        // produced for any configured originator/version.
        let ua = build_default_ua("codex-cli", "1.2.3", "Ubuntu 24.04; x86_64", "WezTerm");
        assert_eq!(
            ua,
            "codex-cli/1.2.3 (Ubuntu 24.04; x86_64) WezTerm (codex-cli; 1.2.3)"
        );
    }

    #[test]
    fn env_or_treats_empty_string_as_absent() {
        // An env var set to "" must fall back to the default, not yield "".
        // Otherwise a blank override would silently blank an identity field.
        std::env::set_var("CODEX_PROXY_TEST_EMPTY", "");
        assert_eq!(env_or("CODEX_PROXY_TEST_EMPTY", "fallback"), "fallback");
        std::env::remove_var("CODEX_PROXY_TEST_EMPTY");

        std::env::set_var("CODEX_PROXY_TEST_SET", "value");
        assert_eq!(env_or("CODEX_PROXY_TEST_SET", "fallback"), "value");
        std::env::remove_var("CODEX_PROXY_TEST_SET");
    }
}
