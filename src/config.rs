//! Runtime configuration and the rules deciding which connections get opened up.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecryptMode {
    /// Decrypt everything except `deny`.
    All,
    /// Tunnel everything opaquely.
    None,
    /// Decrypt only hosts matching `allow`.
    Allowlist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRules {
    pub mode: DecryptMode,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl Default for DecryptRules {
    fn default() -> Self {
        Self {
            mode: DecryptMode::All,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamHttp2 {
    /// Mirror whatever the client negotiated with us.
    Auto,
    /// Always speak HTTP/1.1 to the origin.
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Port the phone points at.
    pub proxy_port: u16,
    /// Bind address for the proxy. Must be reachable from the LAN.
    pub proxy_host: String,
    /// Port serving the inspector UI and the REST API.
    pub ui_port: u16,
    pub ui_host: String,
    /// Root for CA material and saved collections.
    pub data_dir: PathBuf,
    /// Ring buffer size. Oldest flows are evicted past this.
    pub max_flows: usize,
    /// Per body capture ceiling in bytes. Larger bodies are truncated.
    pub max_body_bytes: u64,
    /// Total memory ceiling across all retained bodies.
    pub max_total_body_bytes: u64,
    pub decrypt: DecryptRules,
    pub upstream_http2: UpstreamHttp2,
    /// Accept invalid origin certificates instead of failing the flow.
    pub insecure_upstream: bool,
    /// Hostnames that serve the setup page instead of being forwarded.
    pub setup_hosts: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy_port: 9090,
            proxy_host: "0.0.0.0".to_string(),
            ui_port: 9091,
            ui_host: "0.0.0.0".to_string(),
            data_dir: default_data_dir(),
            max_flows: 5000,
            max_body_bytes: 10 * 1024 * 1024,
            max_total_body_bytes: 512 * 1024 * 1024,
            decrypt: DecryptRules::default(),
            upstream_http2: UpstreamHttp2::Auto,
            insecure_upstream: false,
            setup_hosts: vec![
                "proxima.setup".to_string(),
                "proxima.local".to_string(),
                "proxi.ma".to_string(),
            ],
        }
    }
}

pub fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".proxima")
}

/// Matches a hostname against an exact name or a `*.suffix` wildcard.
/// Case insensitive, and any port on the hostname is ignored.
pub fn host_matches(hostname: &str, pattern: &str) -> bool {
    let host = strip_port(hostname).to_ascii_lowercase();
    let pat = pattern.trim().to_ascii_lowercase();
    if pat.is_empty() {
        return false;
    }
    if pat == "*" {
        return true;
    }
    if let Some(suffix) = pat.strip_prefix("*.") {
        // "*.example.com" covers both sub.example.com and example.com itself,
        // which is what people mean when they type it.
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == pat
}

/// Removes a trailing `:port` and any brackets, leaving a bare hostname or IP.
pub fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[1..end],
            None => host,
        };
    }
    match host.rfind(':') {
        // A bare IPv6 address has several colons and no port.
        Some(idx) if host[..idx].contains(':') => host,
        Some(idx) => &host[..idx],
        None => host,
    }
}

/// Decides whether a CONNECT to `hostname` should be TLS intercepted.
pub fn should_decrypt(hostname: &str, rules: &DecryptRules) -> bool {
    if rules.deny.iter().any(|p| host_matches(hostname, p)) {
        return false;
    }
    match rules.mode {
        DecryptMode::None => false,
        DecryptMode::Allowlist => rules.allow.iter().any(|p| host_matches(hostname, p)),
        DecryptMode::All => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_wildcard_matching() {
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(host_matches("API.Example.COM", "api.example.com"));
        assert!(!host_matches("api.example.com", "example.com"));

        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("deep.api.example.com", "*.example.com"));
        assert!(host_matches("example.com", "*.example.com"));
        assert!(!host_matches("notexample.com", "*.example.com"));
        assert!(!host_matches("example.com.evil.net", "*.example.com"));

        assert!(host_matches("anything", "*"));
        assert!(!host_matches("anything", ""));
    }

    #[test]
    fn ports_are_ignored() {
        assert!(host_matches("api.example.com:8443", "api.example.com"));
        assert!(host_matches("[::1]:9090", "::1"));
        assert!(host_matches("::1", "::1"));
    }

    #[test]
    fn deny_beats_every_mode() {
        let rules = DecryptRules {
            mode: DecryptMode::All,
            allow: vec![],
            deny: vec!["*.bank.com".into()],
        };
        assert!(should_decrypt("api.example.com", &rules));
        assert!(!should_decrypt("login.bank.com", &rules));

        let allowlist = DecryptRules {
            mode: DecryptMode::Allowlist,
            allow: vec!["*.example.com".into()],
            deny: vec!["secret.example.com".into()],
        };
        assert!(should_decrypt("api.example.com", &allowlist));
        assert!(!should_decrypt("secret.example.com", &allowlist));
        assert!(!should_decrypt("other.net", &allowlist));

        let off = DecryptRules {
            mode: DecryptMode::None,
            allow: vec!["*".into()],
            deny: vec![],
        };
        assert!(!should_decrypt("api.example.com", &off));
    }
}
