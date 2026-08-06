//! Shared domain model.
//!
//! Every module implements against these types: the proxy produces [`Flow`]
//! values, the capture store holds them, the API serialises them, and the
//! inspector page renders them. Bodies are never inlined in a [`Flow`]; they
//! live in the body store and are referenced by [`BodyMeta::id`].
//!
//! Serialisation is camelCase throughout because these structs cross the wire
//! to JavaScript in the browser.

use serde::{Deserialize, Serialize};

pub type FlowId = String;

/// A single header as it appeared on the wire. Order and duplicates are
/// preserved, which matters when debugging a server that treats them
/// differently from the spec.
pub type HeaderPair = (String, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpVersion {
    #[serde(rename = "1.0")]
    Http10,
    #[serde(rename = "1.1")]
    Http11,
    #[serde(rename = "2.0")]
    Http2,
}

impl HttpVersion {
    pub fn from_http(v: http::Version) -> Self {
        match v {
            http::Version::HTTP_10 => HttpVersion::Http10,
            http::Version::HTTP_2 => HttpVersion::Http2,
            _ => HttpVersion::Http11,
        }
    }
}

/// Descriptor for a captured body. The bytes live in the body store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyMeta {
    /// Key for body store lookups.
    pub id: String,
    /// Bytes actually retained, which is less than the real body if truncated.
    pub size: u64,
    /// Set when the body exceeded the capture limit and was cut short.
    pub truncated: bool,
    /// `Content-Encoding` exactly as sent.
    pub content_encoding: Option<String>,
    /// `Content-Type` exactly as sent.
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowRequest {
    pub method: String,
    /// Absolute URL, e.g. `https://api.example.com:8443/v1/users?id=1`.
    pub url: String,
    pub scheme: Scheme,
    /// `host[:port]` as addressed by the client, port omitted when default.
    pub authority: String,
    /// Hostname with no port.
    pub host: String,
    pub port: u16,
    /// Path including query string.
    pub path: String,
    pub http_version: HttpVersion,
    pub headers: Vec<HeaderPair>,
    pub body: Option<BodyMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: HttpVersion,
    pub headers: Vec<HeaderPair>,
    pub body: Option<BodyMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowState {
    /// Request headers seen, still reading the request body.
    Pending,
    /// Request forwarded, response in flight.
    Streaming,
    /// Response fully received.
    Complete,
    /// Upstream or TLS failure, see [`Flow::error`].
    Error,
    /// Client went away before completion.
    Aborted,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowTimings {
    /// Epoch milliseconds when the request line was seen.
    pub start: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_sent: Option<u64>,
    /// Epoch milliseconds of the first response byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowClient {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowServer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SNI the client asked us for during its handshake.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// ALPN negotiated with the client, e.g. `h2`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// TLS protocol negotiated with the origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    /// SHA-256 fingerprint of the origin leaf certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowKind {
    /// A regular request and response pair.
    Http,
    /// An upgraded WebSocket connection, see [`Flow::ws_messages`].
    Websocket,
    /// A CONNECT we chose not to decrypt, or non-HTTP bytes. Opaque.
    Tunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WsDirection {
    /// Client to server.
    Send,
    /// Server to client.
    Recv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsMessage {
    pub at: u64,
    pub direction: WsDirection,
    /// WebSocket opcode: 1 text, 2 binary, 8 close, 9 ping, 10 pong.
    pub opcode: u8,
    pub size: u64,
    pub truncated: bool,
    /// Inline payload for small text frames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Body store key for large or binary frames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowError {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Set when the client rejected our certificate, which almost always means
    /// the app pins. This is the single most confusing failure for users, so it
    /// gets its own flag rather than being buried in a message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub likely_pinning: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInfo {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Why this connection was not decrypted.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Flow {
    pub id: FlowId,
    pub kind: FlowKind,
    pub state: FlowState,
    /// True when we terminated TLS and can see plaintext.
    pub intercepted: bool,
    pub request: FlowRequest,
    pub response: Option<FlowResponse>,
    pub error: Option<FlowError>,
    pub timings: FlowTimings,
    pub client: FlowClient,
    pub server: FlowServer,
    /// Set when this flow was produced by replay rather than captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_messages: Option<Vec<WsMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelInfo>,
    /// What the rewrite rules changed on the way through, one note per change.
    ///
    /// A capture shows what went on the wire, so a header a rule added is
    /// indistinguishable in the record from one the client sent. These notes are
    /// how it can be told apart, and without them the honest capture becomes a
    /// confusing one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrites: Vec<String>,
}

/// Lightweight projection for the flow list. Excludes headers and bodies so a
/// live stream of thousands of rows stays cheap.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummary {
    pub id: FlowId,
    pub kind: FlowKind,
    pub state: FlowState,
    pub intercepted: bool,
    pub method: String,
    pub scheme: Scheme,
    pub authority: String,
    pub path: String,
    pub http_version: HttpVersion,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub request_size: u64,
    pub response_size: u64,
    pub start: u64,
    /// Total duration in milliseconds, absent while in flight.
    pub duration: Option<u64>,
    pub error: Option<String>,
    /// Surfaced in the list so a pinned host is obvious without opening it.
    pub likely_pinning: bool,
    /// The address the request came from, without its port. One machine opens a
    /// connection per request and a new port each time, so the port names a
    /// connection while the address names the device, and the device is what
    /// anyone watching two of them wants to tell apart.
    pub client: String,
}

/* ------------------------------------------------------------------ */
/* Live event stream: proxy -> store -> API websocket -> UI            */
/* ------------------------------------------------------------------ */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProxyEvent {
    #[serde(rename = "flow:new")]
    FlowNew { flow: Box<FlowSummary> },
    #[serde(rename = "flow:update")]
    FlowUpdate { flow: Box<FlowSummary> },
    #[serde(rename = "flow:done")]
    FlowDone { flow: Box<FlowSummary> },
    #[serde(rename = "ws:message")]
    WsMessageEvent { id: FlowId, message: Box<WsMessage> },
    #[serde(rename = "clear")]
    Clear,
    #[serde(rename = "status")]
    Status { status: Box<ServerStatus> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    pub proxy_port: u16,
    pub ui_port: u16,
    /// Every LAN address a phone could point at.
    pub addresses: Vec<String>,
    pub ca_fingerprint: String,
    pub ca_not_after: String,
    pub flow_count: usize,
    pub capturing: bool,
    /// Whether finished flows are being recorded to disk. The UI hides the
    /// query panel when they are not, since there would be nothing to query.
    pub archiving: bool,
    /// Flows the archive could not keep up with. Surfaced rather than only
    /// logged, because statistics with a silent hole in them are worse than
    /// statistics that say how big the hole is.
    pub archive_dropped: u64,
}

/* ------------------------------------------------------------------ */
/* Query                                                               */
/* ------------------------------------------------------------------ */

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowQuery {
    /// Substring match against method, url, status and content type.
    pub search: Option<String>,
    /// Exact hosts or `*.suffix` patterns.
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    /// Inclusive range, e.g. `(200, 299)` keeps 2xx only.
    pub status_range: Option<(u16, u16)>,
    #[serde(default)]
    pub kinds: Vec<FlowKind>,
    #[serde(default)]
    pub only_errors: bool,
    pub limit: Option<usize>,
    /// Cursor: return flows recorded before this sequence number.
    pub before: Option<u64>,
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
