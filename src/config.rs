//! Runtime configuration and the rules deciding which connections get opened up.

use std::path::{Path, PathBuf};

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

/* ------------------------------------------------------------------ */
/* rewriting                                                           */
/* ------------------------------------------------------------------ */

/// One change to make to a set of headers.
///
/// `Set` replaces every existing copy of the header rather than appending, which
/// is what someone overriding an `Authorization` means. `Remove` takes all of
/// them. Neither can be expressed as the other, and appending has no use case
/// here that is not better served by editing and replaying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "action")]
pub enum HeaderEdit {
    Set { name: String, value: String },
    Remove { name: String },
}

impl HeaderEdit {
    pub fn name(&self) -> &str {
        match self {
            HeaderEdit::Set { name, .. } | HeaderEdit::Remove { name } => name,
        }
    }
}

/// Where a rule sends the request instead of where it was addressed.
///
/// The `Host` header still carries the authority the client asked for, because
/// the point of pointing `api.example.com` at `127.0.0.1:3000` is to watch a
/// local service answer as that origin. TLS, on the other hand, is negotiated
/// with the target: a certificate for `api.example.com` is not what a local
/// server is holding, so an HTTPS redirect usually wants `--insecure` too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialTarget {
    pub host: String,
    pub port: Option<u16>,
}

/// A match and the edits to make when it matches.
///
/// Every condition left empty matches everything, so a rule with no conditions
/// applies to all traffic. That is the common case: the reason to reach for this
/// is usually "put my token on every request I am about to make".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewriteRule {
    /// Exact hosts or `*.suffix` patterns, matched the same way `--skip` is.
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    /// Matched against the path with its query string, as sent.
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub request_headers: Vec<HeaderEdit>,
    #[serde(default)]
    pub response_headers: Vec<HeaderEdit>,
    #[serde(default)]
    pub to: Option<DialTarget>,
}

impl RewriteRule {
    /// True when this rule applies to a request. `path` is the path and query
    /// as sent, `host` has no port.
    pub fn matches(&self, host: &str, method: &str, path: &str) -> bool {
        if !self.hosts.is_empty() && !self.hosts.iter().any(|p| host_matches(host, p)) {
            return false;
        }
        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|m| m.trim().eq_ignore_ascii_case(method))
        {
            return false;
        }
        match &self.path_prefix {
            Some(prefix) => path.starts_with(prefix.as_str()),
            None => true,
        }
    }

    /// True when the rule would change nothing, which is worth catching at the
    /// point it is configured rather than wondering later why nothing happened.
    pub fn is_noop(&self) -> bool {
        self.request_headers.is_empty() && self.response_headers.is_empty() && self.to.is_none()
    }
}

/// The rules in order. Later rules win, because that is how someone reading a
/// list top to bottom expects a list of overrides to behave.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RewriteRules {
    pub rules: Vec<RewriteRule>,
}

impl RewriteRules {
    pub fn is_empty(&self) -> bool {
        self.rules.iter().all(RewriteRule::is_noop)
    }

    /// Every rule that applies to this request, in order.
    ///
    /// One lifetime across the borrows and the returned iterator, so the filter
    /// can hold the strings it was given. Copying them into the closure instead
    /// would allocate three times on a path that runs twice per flow.
    pub fn matching<'a>(
        &'a self,
        host: &'a str,
        method: &'a str,
        path: &'a str,
    ) -> impl Iterator<Item = &'a RewriteRule> + 'a {
        self.rules
            .iter()
            .filter(move |rule| rule.matches(host, method, path))
    }

    /// Where this request should actually be sent. The last matching rule that
    /// names a target wins, consistent with how the header edits stack.
    pub fn dial_target<'a>(
        &'a self,
        host: &'a str,
        method: &'a str,
        path: &'a str,
    ) -> Option<&'a DialTarget> {
        self.matching(host, method, path)
            .filter_map(|rule| rule.to.as_ref())
            .last()
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
    /// Where finished flows are recorded for later querying. `None` keeps
    /// everything in memory, which is what a build without the `archive`
    /// feature can do at all.
    pub archive_path: Option<PathBuf>,
    pub decrypt: DecryptRules,
    /// Changes made to traffic on the way through, in order.
    pub rewrite: RewriteRules,
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
            archive_path: None,
            decrypt: DecryptRules::default(),
            rewrite: RewriteRules::default(),
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

/// Where the archive lives when one was asked for without a path.
pub fn default_archive_path(data_dir: &Path) -> PathBuf {
    data_dir.join("capture.duckdb")
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
