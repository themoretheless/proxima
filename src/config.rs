//! Runtime configuration and the rules deciding which connections get opened up.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::types::WsDirection;

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

/// Answer a matched request from a file or a literal body without going upstream.
///
/// The last matching rule that sets `mock` wins, same stacking as `to`. The
/// capture is marked mocked and carries rewrite notes so a faked response is
/// never confused with a real origin answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MockResponse {
    /// HTTP status. Defaults to 200 when omitted or zero.
    #[serde(default = "default_mock_status")]
    pub status: u16,
    /// Response headers as name/value pairs (not [`HeaderEdit`]): mock is a
    /// full answer, not an overlay on an upstream response.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Literal body (UTF-8). Used when `body_file` is absent or unreadable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Path to a file. Absolute, or relative to the process working directory.
    /// Wins over `body` when the file can be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_file: Option<String>,
}

fn default_mock_status() -> u16 {
    200
}

fn default_max_ws_messages() -> usize {
    crate::capture::DEFAULT_MAX_WS_MESSAGES
}

/// Default max body size eligible for rewrite when [`BodyRewrite::max_bytes`] is 0.
pub const DEFAULT_BODY_REWRITE_MAX_BYTES: u64 = 1_048_576;

/// One find/replace on a UTF-8 text surface. Literal match (not regex) for MVP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextReplace {
    pub find: String,
    pub replace: String,
}

/// Body rewrites for one half. Applied only when the collected body length is
/// at most `max_bytes` (default 1 MiB via [`DEFAULT_BODY_REWRITE_MAX_BYTES`]).
/// Oversize bodies are left unchanged with a note from the apply site.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyRewrite {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replacements: Vec<TextReplace>,
    /// Max body size eligible for rewrite. Default 1 MiB. Zero means use default.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub max_bytes: u64,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

impl BodyRewrite {
    /// True when there are no find/replace pairs to apply.
    pub fn is_noop(&self) -> bool {
        self.replacements.is_empty()
    }

    /// Effective size gate: zero means [`DEFAULT_BODY_REWRITE_MAX_BYTES`].
    pub fn effective_max_bytes(&self) -> u64 {
        if self.max_bytes == 0 {
            DEFAULT_BODY_REWRITE_MAX_BYTES
        } else {
            self.max_bytes
        }
    }
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
    /// Map local / mock: answer without dialling the origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mock: Option<MockResponse>,
    /// Literal find/replace on the path+query string (as sent).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_replacements: Vec<TextReplace>,
    /// Literal find/replace on the query string only, when a query is present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_replacements: Vec<TextReplace>,
    /// Request body find/replace, gated by [`BodyRewrite::max_bytes`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<BodyRewrite>,
    /// Response body find/replace, gated by [`BodyRewrite::max_bytes`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body: Option<BodyRewrite>,
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
        self.request_headers.is_empty()
            && self.response_headers.is_empty()
            && self.to.is_none()
            && self.mock.is_none()
            && self.path_replacements.is_empty()
            && self.query_replacements.is_empty()
            && self.request_body.as_ref().is_none_or(BodyRewrite::is_noop)
            && self.response_body.as_ref().is_none_or(BodyRewrite::is_noop)
    }

    /// True when this rule would rewrite the request body.
    pub fn has_request_body_rewrite(&self) -> bool {
        self.request_body
            .as_ref()
            .is_some_and(|body| !body.is_noop())
    }

    /// True when this rule would rewrite the response body.
    pub fn has_response_body_rewrite(&self) -> bool {
        self.response_body
            .as_ref()
            .is_some_and(|body| !body.is_noop())
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

    /// Map-local mock for this request. The last matching rule that sets
    /// [`RewriteRule::mock`] wins. Mock takes precedence over dial at the
    /// call site: when present, nothing is sent upstream.
    pub fn mock_response<'a>(
        &'a self,
        host: &'a str,
        method: &'a str,
        path: &'a str,
    ) -> Option<&'a MockResponse> {
        self.matching(host, method, path)
            .filter_map(|rule| rule.mock.as_ref())
            .last()
    }

    /// True when any matching rule would rewrite the request body, so the
    /// forward path must collect it instead of streaming.
    pub fn has_request_body_rewrite(&self, host: &str, method: &str, path: &str) -> bool {
        self.matching(host, method, path)
            .any(|rule| rule.request_body.as_ref().is_some_and(|b| !b.is_noop()))
    }

    /// True when any matching rule would rewrite the response body, so the
    /// forward path must collect it instead of streaming.
    pub fn has_response_body_rewrite(&self, host: &str, method: &str, path: &str) -> bool {
        self.matching(host, method, path)
            .any(|rule| rule.response_body.as_ref().is_some_and(|b| !b.is_noop()))
    }
}

/// PUT/GET body for the live HTTP rewrite (and map-local) rule list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewriteRulesBody {
    #[serde(default)]
    pub rules: Vec<RewriteRule>,
}

impl From<RewriteRules> for RewriteRulesBody {
    fn from(rules: RewriteRules) -> Self {
        Self { rules: rules.rules }
    }
}

impl From<RewriteRulesBody> for RewriteRules {
    fn from(body: RewriteRulesBody) -> Self {
        Self { rules: body.rules }
    }
}

/* ------------------------------------------------------------------ */
/* WebSocket frame rewriting                                           */
/* ------------------------------------------------------------------ */

/// One declarative match-and-action for a single WebSocket frame.
///
/// Conditions left empty match everything in that dimension. Empty `opcodes`
/// defaults to text and binary (1, 2) at apply time, never control frames, so a
/// bare rule cannot break keepalive or the close handshake.
///
/// Actions are mutually exclusive in practice: `drop` wins when set; otherwise
/// `replace_text` or `replace_base64` replaces the full payload. Matching is
/// per frame (not reassembled messages). See [`crate::proxy::ws_rewrite`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsRewriteRule {
    /// Exact hosts or `*.suffix` patterns, same as HTTP rewrite / `--skip`.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Path prefix of the upgrade request; empty or missing matches any path.
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// Empty means both directions.
    #[serde(default)]
    pub directions: Vec<WsDirection>,
    /// Empty means default data opcodes (1 text, 2 binary).
    #[serde(default)]
    pub opcodes: Vec<u8>,
    /// When set, the payload must be valid UTF-8 and match this regex.
    /// Compiled once by [`crate::proxy::ws_rewrite::WsRewriteEngine`]; invalid
    /// patterns fail engine construction rather than silently matching nothing.
    #[serde(default)]
    pub text_regex: Option<String>,
    /// When true, the frame is not written and is not recorded as a ws_message.
    #[serde(default)]
    pub drop: bool,
    /// Full payload replacement as UTF-8 text (preferred over base64 when both set).
    #[serde(default)]
    pub replace_text: Option<String>,
    /// Full payload replacement from standard base64.
    #[serde(default)]
    pub replace_base64: Option<String>,
}

impl WsRewriteRule {
    /// True when the rule would neither drop nor replace a frame.
    pub fn is_noop(&self) -> bool {
        !self.drop && self.replace_text.is_none() && self.replace_base64.is_none()
    }
}

/// Ordered WebSocket rewrite rules. The first matching non-noop rule wins.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WsRewriteRules {
    pub rules: Vec<WsRewriteRule>,
}

impl WsRewriteRules {
    pub fn is_empty(&self) -> bool {
        self.rules.iter().all(WsRewriteRule::is_noop)
    }
}

/// PUT `/api/ws-rewrite` body and GET response envelope.
///
/// Same rule list as [`WsRewriteRules`], but as an object (`{ "rules": [...] }`)
/// so the inspector and curl callers share one shape with breakpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsRewriteRulesBody {
    #[serde(default)]
    pub rules: Vec<WsRewriteRule>,
}

impl From<WsRewriteRules> for WsRewriteRulesBody {
    fn from(rules: WsRewriteRules) -> Self {
        Self { rules: rules.rules }
    }
}

impl From<WsRewriteRulesBody> for WsRewriteRules {
    fn from(body: WsRewriteRulesBody) -> Self {
        Self { rules: body.rules }
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

/* ------------------------------------------------------------------ */
/* QUIC / listen mode                                                  */
/* ------------------------------------------------------------------ */

/// Default UDP port when reverse-h3 is selected without an explicit port.
pub const DEFAULT_QUIC_PORT: u16 = 9443;

/// Default UDP port for the WireGuard userspace scaffold (`--wg-port`).
///
/// Same conventional listen port as kernel WireGuard. This is a bind target
/// only in P9; no Noise/WG crypto is shipped (see `--features wireguard`).
pub const DEFAULT_WG_PORT: u16 = 51820;

/// Operator-facing listen mode (CLI `--mode`, config files).
///
/// Regular is the classic TCP HTTPS proxy. ReverseH3 terminates QUIC/HTTP3 on
/// UDP and reverse-proxies to an origin. WireGuard is the future device-join
/// path (userspace scaffold; crypto not shipped). Tun is the local
/// TUN/packet-capture scaffold (no device open). The phone CONNECT path never
/// sees QUIC either way; reverse and WG are separate UDP listeners; TUN is not
/// a UDP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListenMode {
    /// Classic TCP HTTPS/HTTP proxy (phone CONNECT path).
    #[default]
    Regular,
    /// Terminate QUIC/HTTP3 on UDP and reverse-proxy to a configured origin.
    ReverseH3,
    /// WireGuard userspace device-join scaffold (UDP). Not a working tunnel yet.
    /// Explicit rename: kebab-case would yield `wire-guard`; CLI and docs use
    /// the single token `wireguard`.
    #[serde(rename = "wireguard")]
    WireGuard,
    /// Local TUN / packet-capture scaffold. Not a working capture path; no
    /// utun or `/dev/net/tun` is opened. CLI token is `tun`.
    Tun,
}

impl ListenMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::ReverseH3 => "reverse-h3",
            Self::WireGuard => "wireguard",
            Self::Tun => "tun",
        }
    }
}

impl std::fmt::Display for ListenMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ListenMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept underscores and hyphens the same way operators type them.
        let normalized = s.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "regular" => Ok(Self::Regular),
            "reverse-h3" | "reverseh3" | "reverse-http3" | "reverse-http-3" => {
                Ok(Self::ReverseH3)
            }
            "wireguard" | "wg" | "wire-guard" => Ok(Self::WireGuard),
            "tun" | "local-tun" | "packet-capture" => Ok(Self::Tun),
            other => Err(format!(
                "unknown listen mode {other:?}; expected regular, reverse-h3, wireguard, or tun"
            )),
        }
    }
}

/// Effective QUIC/UDP listener behavior after flags and defaults are resolved.
///
/// Distinct from [`ListenMode`]: Regular mode can still open an accept-only
/// UDP listener when `quic_port` is set, which is useful for skeleton testing
/// without a reverse origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicMode {
    /// No UDP listener.
    Off,
    /// Bind UDP and terminate QUIC; accept-only (no reverse upstream).
    Accept,
    /// Reverse-proxy HTTP/3 to a configured upstream authority.
    ReverseH3,
}

impl QuicMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Accept => "accept",
            Self::ReverseH3 => "reverse-h3",
        }
    }

    /// True when a UDP socket should be bound.
    pub fn wants_udp(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// CLI-ready QUIC knobs without depending on clap.
///
/// The binary, GUI, and tests all feed the same shape into
/// [`resolve_quic`] / [`Config::apply_quic`] so defaults and conflicts stay in
/// one place.
#[derive(Debug, Clone, Default)]
pub struct QuicCliFields {
    /// Explicit `--mode`. When `None`, inferred from `reverse_upstream`.
    pub mode: Option<ListenMode>,
    /// UDP port. `None` disables QUIC in Regular mode; ReverseH3 defaults to
    /// [`DEFAULT_QUIC_PORT`].
    pub quic_port: Option<u16>,
    /// Bind host for the QUIC UDP socket. `None` keeps the existing config host.
    pub quic_host: Option<String>,
    /// Reverse upstream authority `host` or `host:port` (`--reverse-h3`).
    pub reverse_upstream: Option<String>,
}

/// Resolved QUIC slice after validation and defaults (no feature-gate check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicSettings {
    pub mode: ListenMode,
    pub quic_mode: QuicMode,
    pub quic_port: Option<u16>,
    pub quic_host: String,
    pub reverse_h3: Option<String>,
}

impl QuicSettings {
    pub fn wants_quic(&self) -> bool {
        self.quic_mode.wants_udp()
    }
}

/// Whether this binary was built with `--features quic`.
pub fn quic_feature_enabled() -> bool {
    cfg!(feature = "quic")
}

/// Rebuild guidance when QUIC was requested without the Cargo feature.
pub fn quic_feature_required_message() -> &'static str {
    "QUIC/HTTP3 was requested but this binary was built without `--features quic`. \
     Rebuild with: cargo build --features quic (or cargo run --features quic -- ...)."
}

/// Normalize and validate a reverse upstream authority (`host` or `host:port`).
///
/// Rejects empty strings and full URLs with a scheme so operators are not
/// surprised by silent stripping.
pub fn normalize_reverse_authority(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(
            "--reverse-h3 must not be empty; pass host or host:port (default origin port 443)."
                .into(),
        );
    }
    if s.contains("://") {
        return Err(
            "--reverse-h3 expects host[:port], not a URL (omit the scheme)."
                .into(),
        );
    }
    let host = strip_port(s);
    if host.is_empty() {
        return Err("--reverse-h3 must include a host name or address.".into());
    }
    Ok(s.to_string())
}

/// Resolve CLI-ready QUIC fields into settings (defaults + conflict checks).
///
/// Does not check the Cargo feature; call [`Config::validate_quic`] (or
/// [`require_quic_feature`]) before binding UDP.
///
/// `default_host` is used when `fields.quic_host` is unset (typically the
/// current `Config.quic_host`, default `0.0.0.0`).
pub fn resolve_quic(fields: &QuicCliFields, default_host: &str) -> Result<QuicSettings, String> {
    let reverse = match fields.reverse_upstream.as_ref() {
        Some(raw) => Some(normalize_reverse_authority(raw)?),
        None => None,
    };

    let mode = fields.mode.unwrap_or(match &reverse {
        Some(_) => ListenMode::ReverseH3,
        None => ListenMode::Regular,
    });

    let quic_host = fields
        .quic_host
        .clone()
        .unwrap_or_else(|| default_host.to_string());
    if quic_host.parse::<std::net::IpAddr>().is_err() {
        return Err(format!(
            "quic host {quic_host:?} is not a valid IP address to bind \
             (use 0.0.0.0, 127.0.0.1, or ::)."
        ));
    }

    match mode {
        ListenMode::Regular => {
            if reverse.is_some() {
                return Err(
                    "--mode regular cannot be combined with --reverse-h3: reverse HTTP/3 \
                     needs --mode reverse-h3 (or omit --mode and pass --reverse-h3 alone)."
                        .into(),
                );
            }
            // Optional accept-only UDP: --quic-port without reverse is allowed
            // for skeleton / inspect paths. Regular mode still never invents
            // H3 flows on the TCP CONNECT listener.
            let quic_mode = if fields.quic_port.is_some() {
                QuicMode::Accept
            } else {
                QuicMode::Off
            };
            Ok(QuicSettings {
                mode: ListenMode::Regular,
                quic_mode,
                quic_port: fields.quic_port,
                quic_host,
                reverse_h3: None,
            })
        }
        ListenMode::ReverseH3 => {
            let reverse = reverse.ok_or_else(|| {
                "--mode reverse-h3 needs --reverse-h3 <host[:port]>: reverse HTTP/3 has no \
                 origin otherwise."
                    .to_string()
            })?;
            let port = fields.quic_port.unwrap_or(DEFAULT_QUIC_PORT);
            Ok(QuicSettings {
                mode: ListenMode::ReverseH3,
                quic_mode: QuicMode::ReverseH3,
                quic_port: Some(port),
                quic_host,
                reverse_h3: Some(reverse),
            })
        }
        // WireGuard is a separate UDP path. QUIC knobs alone do not enable
        // reverse-h3 here; reverse_upstream with this mode is a conflict.
        ListenMode::WireGuard => {
            if reverse.is_some() {
                return Err(
                    "--mode wireguard cannot be combined with --reverse-h3: WireGuard and \
                     reverse HTTP/3 are separate UDP paths; co-enable is not supported yet."
                        .into(),
                );
            }
            // Optional accept-only QUIC remains available only via Regular mode.
            // WireGuard mode keeps quic off so dual UDP lifecycle is not half-wired.
            if fields.quic_port.is_some() {
                return Err(
                    "--mode wireguard cannot be combined with --quic-port: co-enable of \
                     WireGuard and QUIC listeners is not supported in this scaffold."
                        .into(),
                );
            }
            Ok(QuicSettings {
                mode: ListenMode::WireGuard,
                quic_mode: QuicMode::Off,
                quic_port: None,
                quic_host,
                reverse_h3: None,
            })
        }
        // TUN is local capture scaffold, not a UDP listener. Same co-enable
        // refusal as WireGuard for reverse/quic ports.
        ListenMode::Tun => {
            if reverse.is_some() {
                return Err(
                    "--mode tun cannot be combined with --reverse-h3: local TUN scaffold and \
                     reverse HTTP/3 are separate paths; co-enable is not supported yet."
                        .into(),
                );
            }
            if fields.quic_port.is_some() {
                return Err(
                    "--mode tun cannot be combined with --quic-port: co-enable of the TUN \
                     scaffold and a QUIC/UDP listener is not supported in this scaffold."
                        .into(),
                );
            }
            Ok(QuicSettings {
                mode: ListenMode::Tun,
                quic_mode: QuicMode::Off,
                quic_port: None,
                quic_host,
                reverse_h3: None,
            })
        }
    }
}

/// Error when `wants` is true and the binary lacks `--features quic`.
pub fn require_quic_feature(wants: bool) -> Result<(), String> {
    if wants && !quic_feature_enabled() {
        Err(quic_feature_required_message().into())
    } else {
        Ok(())
    }
}

/* ------------------------------------------------------------------ */
/* WireGuard userspace scaffold                                        */
/* ------------------------------------------------------------------ */

/// CLI-ready WireGuard knobs without depending on clap.
///
/// Parallel to [`QuicCliFields`]. The binary and tests feed the same shape into
/// [`resolve_wireguard`] / [`Config::apply_wireguard`].
#[derive(Debug, Clone, Default)]
pub struct WgCliFields {
    /// Explicit `--mode`. `WireGuard` implies a WG listener even without a port.
    pub mode: Option<ListenMode>,
    /// UDP port for the WG listen socket. `None` disables unless mode is
    /// WireGuard (then [`DEFAULT_WG_PORT`]).
    pub wg_port: Option<u16>,
    /// Bind host for the WG UDP socket. `None` keeps the existing config host.
    pub wg_host: Option<String>,
}

/// Resolved WireGuard slice after validation and defaults (no feature-gate check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgSettings {
    /// Listen mode after WG flags (WireGuard when a listener is wanted).
    pub mode: Option<ListenMode>,
    pub wg_port: Option<u16>,
    pub wg_host: String,
    /// True when a WG UDP socket should be bound.
    pub enabled: bool,
}

impl WgSettings {
    pub fn wants_wireguard(&self) -> bool {
        self.enabled
    }
}

/// Whether this binary was built with `--features wireguard`.
pub fn wireguard_feature_enabled() -> bool {
    cfg!(feature = "wireguard")
}

/// Rebuild guidance when WireGuard was requested without the Cargo feature.
pub fn wireguard_feature_required_message() -> &'static str {
    "WireGuard mode was requested but this binary was built without `--features wireguard`. \
     Rebuild with: cargo build --features wireguard (or cargo run --features wireguard -- ...). \
     Note: the scaffold binds a UDP port only; Noise/WG crypto and a working device tunnel \
     are not shipped yet."
}

/// Error when `wants` is true and the binary lacks `--features wireguard`.
pub fn require_wireguard_feature(wants: bool) -> Result<(), String> {
    if wants && !wireguard_feature_enabled() {
        Err(wireguard_feature_required_message().into())
    } else {
        Ok(())
    }
}

/// Resolve CLI-ready WireGuard fields (defaults + conflict checks).
///
/// Does not check the Cargo feature; call [`Config::validate_wireguard`]
/// before binding. `default_host` is used when `fields.wg_host` is unset.
///
/// Co-enable with reverse-h3 is rejected here when mode is ReverseH3; callers
/// that already applied QUIC must still run [`Config::validate_wireguard`] so
/// `reverse_h3` set on the config is caught too.
pub fn resolve_wireguard(fields: &WgCliFields, default_host: &str) -> Result<WgSettings, String> {
    let mode_is_wg = fields.mode == Some(ListenMode::WireGuard);
    let wants = fields.wg_port.is_some() || mode_is_wg;

    let wg_host = fields
        .wg_host
        .clone()
        .unwrap_or_else(|| default_host.to_string());
    if wants && wg_host.parse::<std::net::IpAddr>().is_err() {
        return Err(format!(
            "wireguard host {wg_host:?} is not a valid IP address to bind \
             (use 0.0.0.0, 127.0.0.1, or ::)."
        ));
    }

    if !wants {
        return Ok(WgSettings {
            mode: None,
            wg_port: None,
            wg_host,
            enabled: false,
        });
    }

    if fields.mode == Some(ListenMode::ReverseH3) {
        return Err(
            "WireGuard cannot be combined with reverse-h3: they are separate UDP paths; \
             co-enable is not supported yet. Pick one of --mode reverse-h3 / --reverse-h3 \
             or --mode wireguard / --wireguard."
                .into(),
        );
    }

    if fields.mode == Some(ListenMode::Tun) {
        return Err(
            "WireGuard cannot be combined with TUN mode: co-enable of the WG UDP scaffold \
             and local TUN capture scaffold is not supported yet. Pick one of \
             --mode wireguard / --wireguard or --mode tun / --tun."
                .into(),
        );
    }

    let port = fields.wg_port.unwrap_or(DEFAULT_WG_PORT);
    Ok(WgSettings {
        mode: Some(ListenMode::WireGuard),
        wg_port: Some(port),
        wg_host,
        enabled: true,
    })
}

/* ------------------------------------------------------------------ */
/* Local TUN / packet-capture scaffold                                 */
/* ------------------------------------------------------------------ */

/// CLI-ready TUN knobs without depending on clap.
///
/// Parallel to [`WgCliFields`]. TUN is a bool mode signal, not a UDP port.
#[derive(Debug, Clone, Default)]
pub struct TunCliFields {
    /// Explicit `--mode`. `Tun` implies the scaffold even without `--tun`.
    pub mode: Option<ListenMode>,
    /// Bare `--tun` flag (or equivalent config bool).
    pub tun: bool,
}

/// Resolved TUN slice after validation and defaults (no feature-gate check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSettings {
    /// Listen mode after TUN flags (`Some(Tun)` when enabled).
    pub mode: Option<ListenMode>,
    /// True when the TUN scaffold task should be started.
    pub tun: bool,
    /// True when a TUN scaffold is wanted.
    pub enabled: bool,
}

impl TunSettings {
    pub fn wants_tun(&self) -> bool {
        self.enabled
    }
}

/// Whether this binary was built with `--features tun`.
pub fn tun_feature_enabled() -> bool {
    cfg!(feature = "tun")
}

/// Rebuild guidance when TUN was requested without the Cargo feature.
pub fn tun_feature_required_message() -> &'static str {
    "TUN / local capture mode was requested but this binary was built without `--features tun`. \
     Rebuild with: cargo build --features tun (or cargo run --features tun -- ...). \
     Note: the scaffold starts a no-op task only; utun//dev/net/tun open and working \
     packet capture are not shipped yet."
}

/// Error when `wants` is true and the binary lacks `--features tun`.
pub fn require_tun_feature(wants: bool) -> Result<(), String> {
    if wants && !tun_feature_enabled() {
        Err(tun_feature_required_message().into())
    } else {
        Ok(())
    }
}

/// Resolve CLI-ready TUN fields (defaults + conflict checks).
///
/// Does not check the Cargo feature; call [`Config::validate_tun`] before
/// starting the serve task. Co-enable with reverse-h3 / QUIC / WireGuard is
/// rejected when those flags are visible on the CLI fields; callers that
/// already applied QUIC/WG must still run [`Config::validate_tun`] so fields
/// already on the config are caught too.
pub fn resolve_tun(fields: &TunCliFields) -> Result<TunSettings, String> {
    let mode_is_tun = fields.mode == Some(ListenMode::Tun);
    let wants = fields.tun || mode_is_tun;

    if !wants {
        return Ok(TunSettings {
            mode: None,
            tun: false,
            enabled: false,
        });
    }

    if fields.mode == Some(ListenMode::ReverseH3) {
        return Err(
            "TUN cannot be combined with reverse-h3: they are separate paths; \
             co-enable is not supported yet. Pick one of --mode reverse-h3 / --reverse-h3 \
             or --mode tun / --tun."
                .into(),
        );
    }

    if fields.mode == Some(ListenMode::WireGuard) {
        return Err(
            "TUN cannot be combined with WireGuard: co-enable of the local capture scaffold \
             and the WG UDP scaffold is not supported yet. Pick one of --mode tun / --tun \
             or --mode wireguard / --wireguard."
                .into(),
        );
    }

    Ok(TunSettings {
        mode: Some(ListenMode::Tun),
        tun: true,
        enabled: true,
    })
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
    /// Per-flow WebSocket frame retention window (most recent frames).
    /// Defaults to [`crate::capture::DEFAULT_MAX_WS_MESSAGES`].
    #[serde(default = "default_max_ws_messages")]
    pub max_ws_messages: usize,
    /// Where finished flows are recorded for later querying. `None` keeps
    /// everything in memory, which is what a build without the `archive`
    /// feature can do at all.
    pub archive_path: Option<PathBuf>,
    pub decrypt: DecryptRules,
    /// Changes made to traffic on the way through, in order.
    pub rewrite: RewriteRules,
    /// Per-frame WebSocket rewrite/drop rules. Empty keeps the zero-latency
    /// byte-copy observe path (unless WS breakpoints force parse-before-forward).
    #[serde(default)]
    pub ws_rewrite: WsRewriteRules,
    pub upstream_http2: UpstreamHttp2,
    /// Accept invalid origin certificates instead of failing the flow.
    pub insecure_upstream: bool,
    /// Hostnames that serve the setup page instead of being forwarded.
    pub setup_hosts: Vec<String>,
    /// Operator listen mode. See [`ListenMode`].
    #[serde(default)]
    pub mode: ListenMode,
    /// UDP port for QUIC/HTTP3. `None` disables the QUIC listener (default).
    /// Requires a build with `--features quic`.
    pub quic_port: Option<u16>,
    /// Bind host for the QUIC UDP socket (IP address).
    pub quic_host: String,
    /// When set with `quic_port`, reverse-proxy HTTP/3 to this authority
    /// (`host` or `host:port`). Same value as CLI `--reverse-h3`.
    pub reverse_h3: Option<String>,
    /// UDP port for the WireGuard userspace scaffold. `None` disables the WG
    /// listener (default). Requires a build with `--features wireguard`.
    /// Crypto and a working device tunnel are not shipped; this is bind + API
    /// surface only in P9.
    pub wg_port: Option<u16>,
    /// Bind host for the WireGuard UDP socket (IP address).
    pub wg_host: String,
    /// Local TUN / packet-capture scaffold. `false` disables (default).
    /// Requires a build with `--features tun`. Does not open utun or
    /// `/dev/net/tun`; the serve task is shutdown-watch only in P10.
    #[serde(default)]
    pub tun: bool,
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
            max_ws_messages: default_max_ws_messages(),
            archive_path: None,
            decrypt: DecryptRules::default(),
            rewrite: RewriteRules::default(),
            ws_rewrite: WsRewriteRules::default(),
            upstream_http2: UpstreamHttp2::Auto,
            insecure_upstream: false,
            setup_hosts: vec![
                "proxima.setup".to_string(),
                "proxima.local".to_string(),
                "proxi.ma".to_string(),
            ],
            mode: ListenMode::Regular,
            quic_port: None,
            quic_host: "0.0.0.0".to_string(),
            reverse_h3: None,
            wg_port: None,
            wg_host: "0.0.0.0".to_string(),
            tun: false,
        }
    }
}

impl Config {
    /// True when a QUIC/UDP listener should be started (`quic_port` set).
    pub fn wants_quic(&self) -> bool {
        self.quic_mode().wants_udp()
    }

    /// True when a WireGuard UDP scaffold should be started (`wg_port` set).
    pub fn wants_wireguard(&self) -> bool {
        self.wg_port.is_some() || self.mode == ListenMode::WireGuard
    }

    /// True when the local TUN scaffold task should be started.
    pub fn wants_tun(&self) -> bool {
        self.tun || self.mode == ListenMode::Tun
    }

    /// Effective QUIC behavior from the current fields.
    pub fn quic_mode(&self) -> QuicMode {
        match self.quic_port {
            None => QuicMode::Off,
            Some(_) if self.reverse_h3.is_some() || self.mode == ListenMode::ReverseH3 => {
                QuicMode::ReverseH3
            }
            Some(_) => QuicMode::Accept,
        }
    }

    /// Reverse upstream authority, if reverse-h3 is configured.
    pub fn reverse_upstream(&self) -> Option<&str> {
        self.reverse_h3.as_deref()
    }

    /// Alias used by some designs; same as [`Config::reverse_upstream`].
    pub fn quic_reverse_upstream(&self) -> Option<&str> {
        self.reverse_upstream()
    }

    /// Apply CLI-ready QUIC fields (defaults + conflict checks).
    ///
    /// Does not enforce the Cargo feature; call [`Config::validate_quic`]
    /// before binding so a non-quic build fails with rebuild guidance.
    pub fn apply_quic(&mut self, fields: QuicCliFields) -> Result<(), String> {
        let settings = resolve_quic(&fields, &self.quic_host)?;
        self.mode = settings.mode;
        self.quic_port = settings.quic_port;
        self.quic_host = settings.quic_host;
        self.reverse_h3 = settings.reverse_h3;
        self.validate_quic_shape()
    }

    /// Apply CLI-ready WireGuard fields (defaults + conflict checks).
    ///
    /// Does not enforce the Cargo feature; call [`Config::validate_wireguard`]
    /// before binding so a non-wireguard build fails with rebuild guidance.
    /// When WG is enabled, sets [`ListenMode::WireGuard`] and `wg_port`.
    pub fn apply_wireguard(&mut self, fields: WgCliFields) -> Result<(), String> {
        let settings = resolve_wireguard(&fields, &self.wg_host)?;
        if !settings.enabled {
            return self.validate_wireguard_shape();
        }
        if let Some(mode) = settings.mode {
            self.mode = mode;
        }
        self.wg_port = settings.wg_port;
        self.wg_host = settings.wg_host;
        self.validate_wireguard_shape()
    }

    /// Apply CLI-ready TUN fields (defaults + conflict checks).
    ///
    /// Does not enforce the Cargo feature; call [`Config::validate_tun`] before
    /// starting so a non-tun build fails with rebuild guidance. When enabled,
    /// sets [`ListenMode::Tun`] and `tun = true`.
    pub fn apply_tun(&mut self, fields: TunCliFields) -> Result<(), String> {
        let settings = resolve_tun(&fields)?;
        if !settings.enabled {
            return self.validate_tun_shape();
        }
        if let Some(mode) = settings.mode {
            self.mode = mode;
        }
        self.tun = settings.tun;
        self.validate_tun_shape()
    }

    /// Field consistency only (no Cargo feature check).
    pub fn validate_quic_shape(&self) -> Result<(), String> {
        if self.mode == ListenMode::ReverseH3 && self.reverse_h3.is_none() {
            return Err(
                "reverse-h3 mode needs reverse_h3 / --reverse-h3 <host[:port]>."
                    .into(),
            );
        }
        if self.mode == ListenMode::Regular && self.reverse_h3.is_some() {
            return Err(
                "regular mode cannot set reverse_h3; use reverse-h3 mode (or omit --mode)."
                    .into(),
            );
        }
        if self.mode == ListenMode::WireGuard && self.reverse_h3.is_some() {
            return Err(
                "wireguard mode cannot set reverse_h3; WireGuard and reverse HTTP/3 \
                 co-enable is not supported yet."
                    .into(),
            );
        }
        if self.mode == ListenMode::Tun && self.reverse_h3.is_some() {
            return Err(
                "tun mode cannot set reverse_h3; TUN scaffold and reverse HTTP/3 \
                 co-enable is not supported yet."
                    .into(),
            );
        }
        if let Some(ref upstream) = self.reverse_h3 {
            normalize_reverse_authority(upstream)?;
            if self.quic_port.is_none() {
                return Err(
                    "reverse HTTP/3 needs a quic_port (CLI defaults to 9443 when resolving flags)."
                        .into(),
                );
            }
        }
        if self.quic_port.is_some() {
            if self.quic_host.parse::<std::net::IpAddr>().is_err() {
                return Err(format!(
                    "quic_host {:?} is not a valid IP address to bind.",
                    self.quic_host
                ));
            }
        }
        Ok(())
    }

    /// WireGuard field consistency only (no Cargo feature check).
    ///
    /// Rejects reverse-h3 + wireguard co-enable and invalid bind hosts.
    pub fn validate_wireguard_shape(&self) -> Result<(), String> {
        if !self.wants_wireguard() {
            return Ok(());
        }
        if self.reverse_h3.is_some() || self.mode == ListenMode::ReverseH3 {
            return Err(
                "WireGuard cannot be combined with reverse-h3: they are separate UDP paths; \
                 co-enable is not supported yet."
                    .into(),
            );
        }
        if self.wants_quic() {
            return Err(
                "WireGuard cannot be combined with a QUIC/UDP listener in this scaffold: \
                 co-enable of dual UDP paths is not supported yet. Disable --quic / \
                 --quic-port / --reverse-h3 when using WireGuard."
                    .into(),
            );
        }
        if self.wants_tun() {
            return Err(
                "WireGuard cannot be combined with TUN mode: co-enable of the WG UDP scaffold \
                 and local TUN capture scaffold is not supported yet."
                    .into(),
            );
        }
        if self.wg_port.is_none() {
            return Err(
                "wireguard mode needs a wg_port (CLI defaults to 51820 when resolving flags)."
                    .into(),
            );
        }
        if self.wg_host.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "wg_host {:?} is not a valid IP address to bind.",
                self.wg_host
            ));
        }
        Ok(())
    }

    /// TUN field consistency only (no Cargo feature check).
    ///
    /// Rejects co-enable with reverse-h3, QUIC UDP, and WireGuard.
    pub fn validate_tun_shape(&self) -> Result<(), String> {
        if !self.wants_tun() {
            return Ok(());
        }
        if self.reverse_h3.is_some() || self.mode == ListenMode::ReverseH3 {
            return Err(
                "TUN cannot be combined with reverse-h3: they are separate paths; \
                 co-enable is not supported yet."
                    .into(),
            );
        }
        if self.wants_quic() {
            return Err(
                "TUN cannot be combined with a QUIC/UDP listener in this scaffold: \
                 co-enable is not supported yet. Disable --quic / --quic-port / \
                 --reverse-h3 when using TUN."
                    .into(),
            );
        }
        if self.wg_port.is_some() || self.mode == ListenMode::WireGuard {
            return Err(
                "TUN cannot be combined with WireGuard: co-enable of the local capture \
                 scaffold and the WG UDP scaffold is not supported yet."
                    .into(),
            );
        }
        if self.mode == ListenMode::Tun && !self.tun {
            // Mode alone without the bool is incomplete; apply_tun sets both.
            return Err(
                "tun mode needs tun=true (CLI --tun or --mode tun sets this when resolving)."
                    .into(),
            );
        }
        Ok(())
    }

    /// Shape checks plus hard fail when QUIC is wanted without `--features quic`.
    pub fn validate_quic(&self) -> Result<(), String> {
        self.validate_quic_shape()?;
        require_quic_feature(self.wants_quic())
    }

    /// Shape checks plus hard fail when WireGuard is wanted without the feature.
    pub fn validate_wireguard(&self) -> Result<(), String> {
        self.validate_wireguard_shape()?;
        // wants_wireguard is true for mode alone; require an actual port before
        // demanding the feature so incomplete configs fail on shape first.
        require_wireguard_feature(self.wg_port.is_some())
    }

    /// Shape checks plus hard fail when TUN is wanted without `--features tun`.
    pub fn validate_tun(&self) -> Result<(), String> {
        self.validate_tun_shape()?;
        require_tun_feature(self.tun)
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

    #[test]
    fn listen_mode_parses_kebab_and_aliases() {
        assert_eq!(
            "regular".parse::<ListenMode>().unwrap(),
            ListenMode::Regular
        );
        assert_eq!(
            "reverse-h3".parse::<ListenMode>().unwrap(),
            ListenMode::ReverseH3
        );
        assert_eq!(
            "reverse_h3".parse::<ListenMode>().unwrap(),
            ListenMode::ReverseH3
        );
        assert_eq!(
            "reverse-http3".parse::<ListenMode>().unwrap(),
            ListenMode::ReverseH3
        );
        assert_eq!(
            "wireguard".parse::<ListenMode>().unwrap(),
            ListenMode::WireGuard
        );
        assert_eq!("wg".parse::<ListenMode>().unwrap(), ListenMode::WireGuard);
        assert_eq!("tun".parse::<ListenMode>().unwrap(), ListenMode::Tun);
        assert_eq!(
            "local-tun".parse::<ListenMode>().unwrap(),
            ListenMode::Tun
        );
        assert_eq!(
            "packet-capture".parse::<ListenMode>().unwrap(),
            ListenMode::Tun
        );
        let bad = "nope".parse::<ListenMode>().expect_err("unknown mode");
        assert!(
            bad.contains("tun")
                && bad.contains("regular")
                && bad.contains("reverse-h3")
                && bad.contains("wireguard"),
            "FromStr help must list tun with the other modes: {bad}"
        );
        assert_eq!(ListenMode::ReverseH3.as_str(), "reverse-h3");
        assert_eq!(ListenMode::WireGuard.as_str(), "wireguard");
        assert_eq!(ListenMode::Tun.as_str(), "tun");
    }

    #[test]
    fn default_config_has_quic_and_wireguard_off() {
        let cfg = Config::default();
        assert_eq!(cfg.mode, ListenMode::Regular);
        assert_eq!(cfg.quic_port, None);
        assert!(cfg.reverse_h3.is_none());
        assert_eq!(cfg.quic_mode(), QuicMode::Off);
        assert!(!cfg.wants_quic());
        assert_eq!(cfg.quic_host, "0.0.0.0");
        assert_eq!(DEFAULT_QUIC_PORT, 9443);
        assert_eq!(cfg.wg_port, None);
        assert!(!cfg.wants_wireguard());
        assert_eq!(cfg.wg_host, "0.0.0.0");
        assert_eq!(DEFAULT_WG_PORT, 51820);
        assert!(!cfg.tun);
        assert!(!cfg.wants_tun());
    }

    #[test]
    fn resolve_accept_only_from_quic_port() {
        let settings = resolve_quic(
            &QuicCliFields {
                quic_port: Some(0),
                ..QuicCliFields::default()
            },
            "127.0.0.1",
        )
        .expect("accept-only should resolve");
        assert_eq!(settings.mode, ListenMode::Regular);
        assert_eq!(settings.quic_mode, QuicMode::Accept);
        assert_eq!(settings.quic_port, Some(0));
        assert!(settings.reverse_h3.is_none());
        assert!(settings.wants_quic());
    }

    #[test]
    fn resolve_reverse_h3_defaults_port_to_9443() {
        let settings = resolve_quic(
            &QuicCliFields {
                reverse_upstream: Some("cloudflare-quic.com".into()),
                ..QuicCliFields::default()
            },
            "0.0.0.0",
        )
        .expect("reverse should resolve");
        assert_eq!(settings.mode, ListenMode::ReverseH3);
        assert_eq!(settings.quic_mode, QuicMode::ReverseH3);
        assert_eq!(settings.quic_port, Some(DEFAULT_QUIC_PORT));
        assert_eq!(
            settings.reverse_h3.as_deref(),
            Some("cloudflare-quic.com")
        );
    }

    #[test]
    fn resolve_reverse_h3_keeps_explicit_port() {
        let settings = resolve_quic(
            &QuicCliFields {
                mode: Some(ListenMode::ReverseH3),
                quic_port: Some(8443),
                reverse_upstream: Some("origin.example:443".into()),
                quic_host: Some("127.0.0.1".into()),
                ..QuicCliFields::default()
            },
            "0.0.0.0",
        )
        .expect("explicit port");
        assert_eq!(settings.quic_port, Some(8443));
        assert_eq!(settings.quic_host, "127.0.0.1");
        assert_eq!(settings.reverse_h3.as_deref(), Some("origin.example:443"));
    }

    #[test]
    fn reverse_h3_mode_without_upstream_is_rejected() {
        let err = resolve_quic(
            &QuicCliFields {
                mode: Some(ListenMode::ReverseH3),
                ..QuicCliFields::default()
            },
            "0.0.0.0",
        )
        .expect_err("upstream required");
        assert!(
            err.contains("--reverse-h3"),
            "error should name the flag: {err}"
        );
    }

    #[test]
    fn regular_mode_with_reverse_upstream_is_rejected() {
        let err = resolve_quic(
            &QuicCliFields {
                mode: Some(ListenMode::Regular),
                reverse_upstream: Some("origin.example".into()),
                ..QuicCliFields::default()
            },
            "0.0.0.0",
        )
        .expect_err("conflict");
        assert!(
            err.contains("regular") && err.contains("reverse-h3"),
            "error should name both: {err}"
        );
    }

    #[test]
    fn empty_and_url_reverse_authorities_are_rejected() {
        assert!(normalize_reverse_authority("").is_err());
        assert!(normalize_reverse_authority("   ").is_err());
        assert!(normalize_reverse_authority("https://example.com").is_err());
        assert_eq!(
            normalize_reverse_authority(" example.com:443 ").unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn apply_quic_writes_fields_onto_config() {
        let mut cfg = Config::default();
        cfg.apply_quic(QuicCliFields {
            reverse_upstream: Some("api.example.com:443".into()),
            quic_port: Some(9444),
            ..QuicCliFields::default()
        })
        .expect("shape ok");
        assert_eq!(cfg.mode, ListenMode::ReverseH3);
        assert_eq!(cfg.quic_port, Some(9444));
        assert_eq!(cfg.reverse_upstream(), Some("api.example.com:443"));
        assert_eq!(cfg.quic_reverse_upstream(), Some("api.example.com:443"));
        assert_eq!(cfg.quic_mode(), QuicMode::ReverseH3);
        assert!(cfg.wants_quic());
        cfg.validate_quic_shape().expect("consistent");
    }

    #[test]
    fn validate_quic_requires_feature_when_udp_wanted() {
        let mut cfg = Config::default();
        cfg.quic_port = Some(9443);
        let result = cfg.validate_quic();
        if quic_feature_enabled() {
            assert!(result.is_ok(), "with feature, port alone is fine: {result:?}");
        } else {
            let err = result.expect_err("without feature, wants_quic must fail");
            assert!(
                err.contains("--features quic"),
                "rebuild guidance missing: {err}"
            );
        }
    }

    #[test]
    fn validate_quic_ok_when_quic_off() {
        Config::default()
            .validate_quic()
            .expect("default config never requires the quic feature");
    }

    #[test]
    fn quic_feature_required_message_names_rebuild_flag() {
        let msg = quic_feature_required_message();
        assert!(
            msg.contains("--features quic"),
            "operators need the exact Cargo feature name: {msg}"
        );
        assert!(
            msg.contains("cargo build") || msg.contains("cargo run"),
            "rebuild guidance should name cargo: {msg}"
        );
        assert_eq!(quic_feature_enabled(), cfg!(feature = "quic"));
    }

    #[test]
    fn require_quic_feature_only_fails_when_wanted_without_feature() {
        require_quic_feature(false).expect("off never needs the feature");
        let wanted = require_quic_feature(true);
        if quic_feature_enabled() {
            wanted.expect("with feature, wants=true is fine");
        } else {
            let err = wanted.expect_err("without feature, wants=true must fail");
            assert!(
                err.contains("--features quic"),
                "hard-fail must include rebuild guidance: {err}"
            );
        }
    }

    #[test]
    fn resolve_rejects_non_ip_quic_host() {
        let err = resolve_quic(
            &QuicCliFields {
                quic_port: Some(9443),
                quic_host: Some("not.an.ip".into()),
                ..QuicCliFields::default()
            },
            "0.0.0.0",
        )
        .expect_err("host must be a bindable IP");
        assert!(
            err.contains("not.an.ip") || err.contains("valid IP"),
            "error should name the bad host: {err}"
        );
    }

    #[test]
    fn validate_quic_shape_requires_port_when_reverse_set() {
        let mut cfg = Config::default();
        cfg.mode = ListenMode::ReverseH3;
        cfg.reverse_h3 = Some("origin.example:443".into());
        cfg.quic_port = None;
        let err = cfg
            .validate_quic_shape()
            .expect_err("reverse without UDP port is inconsistent");
        assert!(
            err.contains("quic_port") || err.contains("9443"),
            "shape error should mention the missing port: {err}"
        );
    }

    #[test]
    fn validate_quic_shape_rejects_bad_host_when_port_set() {
        let mut cfg = Config::default();
        cfg.quic_port = Some(9443);
        cfg.quic_host = "hostname.not.ip".into();
        let err = cfg
            .validate_quic_shape()
            .expect_err("hostname is not a bind address");
        assert!(
            err.contains("quic_host") || err.contains("valid IP"),
            "{err}"
        );
    }

    #[test]
    fn quic_mode_accept_vs_reverse_from_fields() {
        let mut accept = Config::default();
        accept.quic_port = Some(0);
        assert_eq!(accept.quic_mode(), QuicMode::Accept);
        assert!(accept.wants_quic());

        let mut reverse = Config::default();
        reverse.quic_port = Some(DEFAULT_QUIC_PORT);
        reverse.reverse_h3 = Some("origin.example".into());
        reverse.mode = ListenMode::ReverseH3;
        assert_eq!(reverse.quic_mode(), QuicMode::ReverseH3);
        assert!(reverse.wants_quic());
        reverse.validate_quic_shape().expect("consistent reverse shape");
    }

    #[test]
    fn listen_mode_serde_kebab_case() {
        let json = serde_json::to_string(&ListenMode::ReverseH3).unwrap();
        assert_eq!(json, "\"reverse-h3\"");
        let back: ListenMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ListenMode::ReverseH3);

        let wg_json = serde_json::to_string(&ListenMode::WireGuard).unwrap();
        assert_eq!(wg_json, "\"wireguard\"");
        let wg_back: ListenMode = serde_json::from_str(&wg_json).unwrap();
        assert_eq!(wg_back, ListenMode::WireGuard);

        let tun_json = serde_json::to_string(&ListenMode::Tun).unwrap();
        assert_eq!(tun_json, "\"tun\"");
        let tun_back: ListenMode = serde_json::from_str(&tun_json).unwrap();
        assert_eq!(tun_back, ListenMode::Tun);
    }

    #[test]
    fn resolve_wireguard_defaults_port_to_51820() {
        let settings = resolve_wireguard(
            &WgCliFields {
                mode: Some(ListenMode::WireGuard),
                ..WgCliFields::default()
            },
            "0.0.0.0",
        )
        .expect("wireguard mode should resolve");
        assert!(settings.enabled);
        assert_eq!(settings.wg_port, Some(DEFAULT_WG_PORT));
        assert_eq!(settings.mode, Some(ListenMode::WireGuard));
        assert!(settings.wants_wireguard());
    }

    #[test]
    fn resolve_wireguard_keeps_explicit_port() {
        let settings = resolve_wireguard(
            &WgCliFields {
                wg_port: Some(0),
                wg_host: Some("127.0.0.1".into()),
                ..WgCliFields::default()
            },
            "0.0.0.0",
        )
        .expect("explicit port");
        assert_eq!(settings.wg_port, Some(0));
        assert_eq!(settings.wg_host, "127.0.0.1");
    }

    #[test]
    fn reverse_h3_with_wireguard_is_rejected() {
        let err = resolve_wireguard(
            &WgCliFields {
                mode: Some(ListenMode::ReverseH3),
                wg_port: Some(DEFAULT_WG_PORT),
                ..WgCliFields::default()
            },
            "0.0.0.0",
        )
        .expect_err("co-enable must fail");
        assert!(
            err.contains("reverse-h3") && err.to_ascii_lowercase().contains("wireguard"),
            "error should name both paths: {err}"
        );
    }

    #[test]
    fn apply_wireguard_writes_fields_onto_config() {
        let mut cfg = Config::default();
        cfg.apply_wireguard(WgCliFields {
            wg_port: Some(51821),
            wg_host: Some("127.0.0.1".into()),
            ..WgCliFields::default()
        })
        .expect("shape ok");
        assert_eq!(cfg.mode, ListenMode::WireGuard);
        assert_eq!(cfg.wg_port, Some(51821));
        assert_eq!(cfg.wg_host, "127.0.0.1");
        assert!(cfg.wants_wireguard());
        cfg.validate_wireguard_shape().expect("consistent");
    }

    #[test]
    fn validate_wireguard_requires_feature_when_udp_wanted() {
        let mut cfg = Config::default();
        cfg.wg_port = Some(DEFAULT_WG_PORT);
        cfg.mode = ListenMode::WireGuard;
        let result = cfg.validate_wireguard();
        if wireguard_feature_enabled() {
            assert!(
                result.is_ok(),
                "with feature, port alone is fine: {result:?}"
            );
        } else {
            let err = result.expect_err("without feature, wants_wireguard must fail");
            assert!(
                err.contains("--features wireguard"),
                "rebuild guidance missing: {err}"
            );
        }
    }

    #[test]
    fn validate_wireguard_ok_when_off() {
        Config::default()
            .validate_wireguard()
            .expect("default config never requires the wireguard feature");
    }

    #[test]
    fn validate_wireguard_shape_rejects_quic_co_enable() {
        let mut cfg = Config::default();
        cfg.wg_port = Some(DEFAULT_WG_PORT);
        cfg.mode = ListenMode::WireGuard;
        cfg.quic_port = Some(DEFAULT_QUIC_PORT);
        let err = cfg
            .validate_wireguard_shape()
            .expect_err("dual UDP must fail");
        assert!(
            err.contains("QUIC") || err.contains("quic"),
            "error should mention QUIC: {err}"
        );
    }

    #[test]
    fn wireguard_feature_required_message_names_rebuild_flag() {
        let msg = wireguard_feature_required_message();
        assert!(
            msg.contains("--features wireguard"),
            "operators need the exact Cargo feature name: {msg}"
        );
        assert!(
            msg.contains("cargo build") || msg.contains("cargo run"),
            "rebuild guidance should name cargo: {msg}"
        );
        assert_eq!(wireguard_feature_enabled(), cfg!(feature = "wireguard"));
    }

    #[test]
    fn resolve_quic_wireguard_mode_rejects_reverse() {
        let err = resolve_quic(
            &QuicCliFields {
                mode: Some(ListenMode::WireGuard),
                reverse_upstream: Some("origin.example".into()),
                ..QuicCliFields::default()
            },
            "0.0.0.0",
        )
        .expect_err("wireguard + reverse is invalid");
        assert!(
            err.contains("wireguard") && err.contains("reverse-h3"),
            "{err}"
        );
    }

    #[test]
    fn resolve_wireguard_rejects_invalid_host() {
        let err = resolve_wireguard(
            &WgCliFields {
                wg_port: Some(DEFAULT_WG_PORT),
                wg_host: Some("not-an-ip".into()),
                ..WgCliFields::default()
            },
            "0.0.0.0",
        )
        .expect_err("host must be an IP");
        assert!(
            err.contains("not-an-ip") || err.contains("valid IP"),
            "error should name the bad host: {err}"
        );
    }

    #[test]
    fn resolve_wireguard_off_when_no_flags() {
        let settings = resolve_wireguard(&WgCliFields::default(), "0.0.0.0")
            .expect("empty fields are valid");
        assert!(!settings.enabled);
        assert!(!settings.wants_wireguard());
        assert_eq!(settings.wg_port, None);
        assert!(settings.mode.is_none());
    }

    #[test]
    fn validate_wireguard_shape_rejects_mode_without_port() {
        let mut cfg = Config::default();
        cfg.mode = ListenMode::WireGuard;
        cfg.wg_port = None;
        let err = cfg
            .validate_wireguard_shape()
            .expect_err("mode alone needs a port");
        assert!(
            err.contains("wg_port") || err.contains("port"),
            "shape error should mention port: {err}"
        );
    }

    #[test]
    fn validate_wireguard_shape_rejects_reverse_h3_field() {
        let mut cfg = Config::default();
        cfg.wg_port = Some(DEFAULT_WG_PORT);
        cfg.mode = ListenMode::WireGuard;
        cfg.reverse_h3 = Some("origin.example:443".into());
        let err = cfg
            .validate_wireguard_shape()
            .expect_err("reverse-h3 field + WG is invalid");
        assert!(
            err.to_ascii_lowercase().contains("wireguard")
                && err.contains("reverse"),
            "{err}"
        );
    }

    #[test]
    fn require_wireguard_feature_ok_when_not_wanted() {
        require_wireguard_feature(false).expect("off never requires the feature");
    }

    #[test]
    fn listen_mode_wire_guard_hyphen_alias() {
        assert_eq!(
            "wire-guard".parse::<ListenMode>().unwrap(),
            ListenMode::WireGuard
        );
    }

    #[test]
    fn resolve_tun_from_flag() {
        let settings = resolve_tun(&TunCliFields {
            tun: true,
            ..TunCliFields::default()
        })
        .expect("tun flag should resolve");
        assert!(settings.enabled);
        assert!(settings.tun);
        assert_eq!(settings.mode, Some(ListenMode::Tun));
        assert!(settings.wants_tun());
    }

    #[test]
    fn resolve_tun_from_mode() {
        let settings = resolve_tun(&TunCliFields {
            mode: Some(ListenMode::Tun),
            ..TunCliFields::default()
        })
        .expect("mode tun should resolve");
        assert!(settings.enabled);
        assert!(settings.tun);
        assert_eq!(settings.mode, Some(ListenMode::Tun));
    }

    #[test]
    fn resolve_tun_off_when_no_flags() {
        let settings = resolve_tun(&TunCliFields::default()).expect("empty is valid");
        assert!(!settings.enabled);
        assert!(!settings.tun);
        assert!(!settings.wants_tun());
        assert!(settings.mode.is_none());
    }

    #[test]
    fn reverse_h3_with_tun_is_rejected() {
        let err = resolve_tun(&TunCliFields {
            mode: Some(ListenMode::ReverseH3),
            tun: true,
            ..TunCliFields::default()
        })
        .expect_err("co-enable must fail");
        assert!(
            err.contains("reverse-h3") && err.to_ascii_lowercase().contains("tun"),
            "error should name both paths: {err}"
        );
    }

    #[test]
    fn wireguard_mode_with_tun_is_rejected() {
        let err = resolve_tun(&TunCliFields {
            mode: Some(ListenMode::WireGuard),
            tun: true,
            ..TunCliFields::default()
        })
        .expect_err("WG+TUN co-enable must fail");
        assert!(
            err.to_ascii_lowercase().contains("wireguard")
                && err.to_ascii_lowercase().contains("tun"),
            "{err}"
        );
    }

    #[test]
    fn apply_tun_writes_fields_onto_config() {
        let mut cfg = Config::default();
        cfg.apply_tun(TunCliFields {
            tun: true,
            ..TunCliFields::default()
        })
        .expect("shape ok");
        assert_eq!(cfg.mode, ListenMode::Tun);
        assert!(cfg.tun);
        assert!(cfg.wants_tun());
        cfg.validate_tun_shape().expect("consistent");
    }

    #[test]
    fn validate_tun_requires_feature_when_wanted() {
        let mut cfg = Config::default();
        cfg.tun = true;
        cfg.mode = ListenMode::Tun;
        let result = cfg.validate_tun();
        if tun_feature_enabled() {
            assert!(
                result.is_ok(),
                "with feature, tun alone is fine: {result:?}"
            );
        } else {
            let err = result.expect_err("without feature, wants_tun must fail");
            assert!(
                err.contains("--features tun"),
                "rebuild guidance missing: {err}"
            );
        }
    }

    #[test]
    fn validate_tun_ok_when_off() {
        Config::default()
            .validate_tun()
            .expect("default config never requires the tun feature");
    }

    #[test]
    fn validate_tun_shape_rejects_quic_co_enable() {
        let mut cfg = Config::default();
        cfg.tun = true;
        cfg.mode = ListenMode::Tun;
        cfg.quic_port = Some(DEFAULT_QUIC_PORT);
        let err = cfg
            .validate_tun_shape()
            .expect_err("TUN+QUIC must fail");
        assert!(
            err.contains("QUIC") || err.contains("quic"),
            "error should mention QUIC: {err}"
        );
    }

    #[test]
    fn validate_tun_shape_rejects_wireguard_co_enable() {
        let mut cfg = Config::default();
        cfg.tun = true;
        cfg.mode = ListenMode::Tun;
        cfg.wg_port = Some(DEFAULT_WG_PORT);
        let err = cfg
            .validate_tun_shape()
            .expect_err("TUN+WG must fail");
        assert!(
            err.to_ascii_lowercase().contains("wireguard"),
            "error should mention WireGuard: {err}"
        );
    }

    #[test]
    fn validate_tun_shape_rejects_reverse_h3_field() {
        let mut cfg = Config::default();
        cfg.tun = true;
        cfg.mode = ListenMode::Tun;
        cfg.reverse_h3 = Some("origin.example:443".into());
        let err = cfg
            .validate_tun_shape()
            .expect_err("reverse-h3 field + TUN is invalid");
        assert!(
            err.to_ascii_lowercase().contains("tun") && err.contains("reverse"),
            "{err}"
        );
    }

    #[test]
    fn tun_feature_required_message_names_rebuild_flag() {
        let msg = tun_feature_required_message();
        assert!(
            msg.contains("--features tun"),
            "operators need the exact Cargo feature name: {msg}"
        );
        assert!(
            msg.contains("cargo build") || msg.contains("cargo run"),
            "rebuild guidance should name cargo: {msg}"
        );
        assert_eq!(tun_feature_enabled(), cfg!(feature = "tun"));
    }

    #[test]
    fn require_tun_feature_only_fails_when_wanted_without_feature() {
        require_tun_feature(false).expect("off never requires the feature");
        let wanted = require_tun_feature(true);
        if tun_feature_enabled() {
            wanted.expect("with feature, wants=true is fine");
        } else {
            let err = wanted.expect_err("without feature, wants=true must fail");
            assert!(
                err.contains("--features tun"),
                "hard-fail must include rebuild guidance: {err}"
            );
        }
    }

    #[test]
    fn wants_tun_from_mode_alone_or_bool() {
        let mut cfg = Config::default();
        assert!(!cfg.wants_tun());
        cfg.mode = ListenMode::Tun;
        assert!(
            cfg.wants_tun(),
            "ListenMode::Tun alone signals wants_tun even before tun=true"
        );
        cfg.mode = ListenMode::Regular;
        cfg.tun = true;
        assert!(cfg.wants_tun(), "tun bool alone also wants the scaffold");
    }

    #[test]
    fn validate_tun_shape_rejects_mode_without_bool() {
        let mut cfg = Config::default();
        cfg.mode = ListenMode::Tun;
        cfg.tun = false;
        let err = cfg
            .validate_tun_shape()
            .expect_err("mode alone without tun=true is incomplete");
        assert!(
            err.contains("tun") && (err.contains("true") || err.contains("tun=")),
            "shape error should require tun=true: {err}"
        );
    }

    #[test]
    fn resolve_quic_tun_mode_rejects_reverse() {
        let err = resolve_quic(
            &QuicCliFields {
                mode: Some(ListenMode::Tun),
                reverse_upstream: Some("origin.example".into()),
                ..QuicCliFields::default()
            },
            "0.0.0.0",
        )
        .expect_err("tun + reverse is invalid");
        assert!(
            err.contains("tun") && err.contains("reverse-h3"),
            "{err}"
        );
    }

    #[test]
    fn resolve_wireguard_rejects_tun_mode() {
        let err = resolve_wireguard(
            &WgCliFields {
                mode: Some(ListenMode::Tun),
                wg_port: Some(DEFAULT_WG_PORT),
                ..WgCliFields::default()
            },
            "0.0.0.0",
        )
        .expect_err("tun mode + wg port is invalid");
        assert!(
            err.to_ascii_lowercase().contains("tun")
                && err.to_ascii_lowercase().contains("wireguard"),
            "{err}"
        );
    }

    #[test]
    fn default_config_has_empty_ws_rewrite() {
        let cfg = Config::default();
        assert!(cfg.ws_rewrite.is_empty());
        assert!(cfg.ws_rewrite.rules.is_empty());
    }

    #[test]
    fn mock_response_last_matching_rule_wins() {
        let rules = RewriteRules {
            rules: vec![
                RewriteRule {
                    path_prefix: Some("/api".into()),
                    mock: Some(MockResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: Some("first".into()),
                        body_file: None,
                    }),
                    ..RewriteRule::default()
                },
                RewriteRule {
                    path_prefix: Some("/api".into()),
                    mock: Some(MockResponse {
                        status: 503,
                        headers: vec![("x-mock".into(), "second".into())],
                        body: Some("second".into()),
                        body_file: None,
                    }),
                    ..RewriteRule::default()
                },
                // Matches host but no mock: must not clear the previous mock.
                RewriteRule {
                    hosts: vec!["api.example.com".into()],
                    to: Some(DialTarget {
                        host: "127.0.0.1".into(),
                        port: Some(9),
                    }),
                    ..RewriteRule::default()
                },
            ],
        };

        let mock = rules
            .mock_response("api.example.com", "GET", "/api/users")
            .expect("a mock");
        assert_eq!(mock.status, 503);
        assert_eq!(mock.body.as_deref(), Some("second"));
        assert_eq!(
            mock.headers,
            vec![("x-mock".into(), "second".into())],
            "last matching mock carries its own headers"
        );

        assert!(
            rules
                .mock_response("api.example.com", "GET", "/other")
                .is_none(),
            "path that matches no mock rule must not invent one"
        );
        assert!(
            rules
                .mock_response("other.net", "GET", "/api/users")
                .is_some(),
            "rules without host conditions still apply"
        );
    }

    #[test]
    fn mock_response_respects_host_method_and_path() {
        let rules = RewriteRules {
            rules: vec![RewriteRule {
                hosts: vec!["*.example.com".into()],
                methods: vec!["POST".into()],
                path_prefix: Some("/v1/".into()),
                mock: Some(MockResponse {
                    status: 201,
                    headers: Vec::new(),
                    body: Some("created".into()),
                    body_file: None,
                }),
                ..RewriteRule::default()
            }],
        };

        assert!(rules
            .mock_response("api.example.com", "POST", "/v1/items")
            .is_some());
        assert!(
            rules
                .mock_response("api.other.net", "POST", "/v1/items")
                .is_none(),
            "host"
        );
        assert!(
            rules
                .mock_response("api.example.com", "GET", "/v1/items")
                .is_none(),
            "method"
        );
        assert!(
            rules
                .mock_response("api.example.com", "POST", "/v2/items")
                .is_none(),
            "path"
        );
    }

    #[test]
    fn a_rule_with_only_mock_is_not_noop() {
        assert!(RewriteRule::default().is_noop());
        assert!(!RewriteRule {
            mock: Some(MockResponse {
                status: 200,
                headers: Vec::new(),
                body: Some("x".into()),
                body_file: None,
            }),
            ..RewriteRule::default()
        }
        .is_noop());
    }

    #[test]
    fn body_path_query_rewrite_is_noop() {
        assert!(RewriteRule::default().is_noop());
        assert!(
            RewriteRule {
                request_body: Some(BodyRewrite::default()),
                response_body: Some(BodyRewrite {
                    replacements: Vec::new(),
                    max_bytes: 4096,
                }),
                ..RewriteRule::default()
            }
            .is_noop(),
            "empty body replacement lists are still noop"
        );
        assert!(!RewriteRule {
            path_replacements: vec![TextReplace {
                find: "/a".into(),
                replace: "/b".into(),
            }],
            ..RewriteRule::default()
        }
        .is_noop());
        assert!(!RewriteRule {
            query_replacements: vec![TextReplace {
                find: "x=1".into(),
                replace: "x=2".into(),
            }],
            ..RewriteRule::default()
        }
        .is_noop());
        assert!(!RewriteRule {
            request_body: Some(BodyRewrite {
                replacements: vec![TextReplace {
                    find: "old".into(),
                    replace: "new".into(),
                }],
                max_bytes: 0,
            }),
            ..RewriteRule::default()
        }
        .is_noop());
        assert!(!RewriteRule {
            response_body: Some(BodyRewrite {
                replacements: vec![TextReplace {
                    find: "a".into(),
                    replace: "b".into(),
                }],
                max_bytes: 1024,
            }),
            ..RewriteRule::default()
        }
        .is_noop());
        assert!(
            BodyRewrite {
                replacements: Vec::new(),
                max_bytes: 0,
            }
            .is_noop()
        );
        assert_eq!(
            BodyRewrite::default().effective_max_bytes(),
            DEFAULT_BODY_REWRITE_MAX_BYTES
        );
        assert_eq!(
            BodyRewrite {
                replacements: Vec::new(),
                max_bytes: 99,
            }
            .effective_max_bytes(),
            99
        );
    }

    #[test]
    fn mock_response_serde_uses_camel_case() {
        let rule = RewriteRule {
            path_prefix: Some("/local".into()),
            mock: Some(MockResponse {
                status: 404,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: Some("missing".into()),
                body_file: Some("/tmp/fixture.json".into()),
            }),
            ..RewriteRule::default()
        };
        let json = serde_json::to_value(&rule).expect("serialize");
        assert_eq!(json["pathPrefix"], "/local");
        assert_eq!(json["mock"]["status"], 404);
        assert_eq!(json["mock"]["body"], "missing");
        assert_eq!(json["mock"]["bodyFile"], "/tmp/fixture.json");
        assert_eq!(
            json["mock"]["headers"],
            serde_json::json!([["content-type", "text/plain"]])
        );

        let back: RewriteRule = serde_json::from_value(json).expect("parse");
        assert_eq!(back, rule);

        // Omitted status defaults to 200 so a body-only map-local is valid JSON.
        let partial: MockResponse = serde_json::from_str(r#"{"body":"hi"}"#).expect("partial");
        assert_eq!(partial.status, 200);
        assert_eq!(partial.body.as_deref(), Some("hi"));
    }

    #[test]
    fn body_path_query_rewrite_serde_camel_case() {
        let rule = RewriteRule {
            path_replacements: vec![TextReplace {
                find: "/v1/".into(),
                replace: "/v2/".into(),
            }],
            query_replacements: vec![TextReplace {
                find: "token=old".into(),
                replace: "token=new".into(),
            }],
            request_body: Some(BodyRewrite {
                replacements: vec![TextReplace {
                    find: "\"role\":\"user\"".into(),
                    replace: "\"role\":\"admin\"".into(),
                }],
                max_bytes: 2048,
            }),
            response_body: Some(BodyRewrite {
                replacements: vec![TextReplace {
                    find: "error".into(),
                    replace: "ok".into(),
                }],
                max_bytes: 0,
            }),
            ..RewriteRule::default()
        };

        let json = serde_json::to_value(&rule).expect("serialize");
        assert_eq!(json["pathReplacements"][0]["find"], "/v1/");
        assert_eq!(json["pathReplacements"][0]["replace"], "/v2/");
        assert_eq!(json["queryReplacements"][0]["find"], "token=old");
        assert_eq!(json["queryReplacements"][0]["replace"], "token=new");
        assert_eq!(json["requestBody"]["maxBytes"], 2048);
        assert_eq!(
            json["requestBody"]["replacements"][0]["find"],
            "\"role\":\"user\""
        );
        assert_eq!(json["responseBody"]["replacements"][0]["replace"], "ok");
        assert!(
            json["responseBody"].get("maxBytes").is_none(),
            "zero maxBytes is omitted on the wire"
        );

        let back: RewriteRule = serde_json::from_value(json).expect("parse");
        assert_eq!(back, rule);

        // Empty rule omits the new fields; defaults stay empty / None.
        let empty = serde_json::to_value(RewriteRule::default()).expect("empty");
        assert!(empty.get("pathReplacements").is_none());
        assert!(empty.get("queryReplacements").is_none());
        assert!(empty.get("requestBody").is_none());
        assert!(empty.get("responseBody").is_none());

        let partial: RewriteRule =
            serde_json::from_str(r#"{"pathReplacements":[{"find":"a","replace":"b"}]}"#)
                .expect("partial");
        assert_eq!(partial.path_replacements.len(), 1);
        assert!(partial.query_replacements.is_empty());
        assert!(partial.request_body.is_none());
        assert!(partial.response_body.is_none());

        let body_only: BodyRewrite =
            serde_json::from_str(r#"{"replacements":[{"find":"x","replace":"y"}]}"#)
                .expect("body");
        assert_eq!(body_only.max_bytes, 0);
        assert_eq!(body_only.effective_max_bytes(), DEFAULT_BODY_REWRITE_MAX_BYTES);
    }

    #[test]
    fn ws_rewrite_rule_is_noop_until_action() {
        assert!(WsRewriteRule::default().is_noop());
        assert!(WsRewriteRule {
            hosts: vec!["chat.example.com".into()],
            path_prefix: Some("/ws".into()),
            directions: vec![WsDirection::Send],
            opcodes: vec![1],
            text_regex: Some("secret".into()),
            ..WsRewriteRule::default()
        }
        .is_noop());
        assert!(!WsRewriteRule {
            drop: true,
            ..WsRewriteRule::default()
        }
        .is_noop());
        assert!(!WsRewriteRule {
            replace_text: Some("x".into()),
            ..WsRewriteRule::default()
        }
        .is_noop());
        assert!(!WsRewriteRule {
            replace_base64: Some("YQ==".into()),
            ..WsRewriteRule::default()
        }
        .is_noop());
        assert!(WsRewriteRules {
            rules: vec![WsRewriteRule::default()]
        }
        .is_empty());
        assert!(!WsRewriteRules {
            rules: vec![WsRewriteRule {
                drop: true,
                ..WsRewriteRule::default()
            }]
        }
        .is_empty());
    }

    #[test]
    fn ws_rewrite_rule_serde_camel_case() {
        let rule = WsRewriteRule {
            hosts: vec!["chat.example.com".into()],
            path_prefix: Some("/ws".into()),
            directions: vec![WsDirection::Send],
            opcodes: vec![1, 2],
            text_regex: Some("secret".into()),
            drop: true,
            replace_text: None,
            replace_base64: None,
        };
        let json = serde_json::to_value(&rule).expect("serialize");
        assert_eq!(json["pathPrefix"], "/ws");
        assert_eq!(json["textRegex"], "secret");
        assert_eq!(json["replaceText"], serde_json::Value::Null);
        assert_eq!(json["replaceBase64"], serde_json::Value::Null);
        assert_eq!(json["directions"], serde_json::json!(["send"]));

        let body = WsRewriteRulesBody {
            rules: vec![rule.clone()],
        };
        let wire = serde_json::to_string(&body).expect("body");
        let back: WsRewriteRulesBody = serde_json::from_str(&wire).expect("parse");
        assert_eq!(back.rules, body.rules);

        // Transparent config list (startup file shape) still works.
        let list = WsRewriteRules {
            rules: vec![rule],
        };
        let list_json = serde_json::to_string(&list).expect("list");
        assert!(list_json.starts_with('['), "WsRewriteRules is transparent: {list_json}");
        let list_back: WsRewriteRules = serde_json::from_str(&list_json).expect("parse list");
        assert_eq!(list_back, list);
    }
}
