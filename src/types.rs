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
    /// HTTP/3 over QUIC (UDP). Only produced by the `quic` feature path.
    /// Always compiled so API/HAR stay stable without linking quinn.
    #[serde(rename = "3.0")]
    Http3,
}

impl HttpVersion {
    pub fn from_http(v: http::Version) -> Self {
        match v {
            http::Version::HTTP_10 => HttpVersion::Http10,
            http::Version::HTTP_2 => HttpVersion::Http2,
            http::Version::HTTP_3 => HttpVersion::Http3,
            _ => HttpVersion::Http11,
        }
    }

    /// Short version token used in archive rows and list labels (`"3.0"`).
    pub fn as_label(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "1.0",
            HttpVersion::Http11 => "1.1",
            HttpVersion::Http2 => "2.0",
            HttpVersion::Http3 => "3.0",
        }
    }

    /// HAR 1.2 `httpVersion` string (`"HTTP/3"`).
    pub fn as_har(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2",
            HttpVersion::Http3 => "HTTP/3",
        }
    }
}

/// Wire transport for a captured flow.
///
/// TCP is the classic CONNECT/proxy path. QUIC is UDP-only and is only
/// produced by the optional `quic` feature (reverse H3, later WG/TUN). The
/// regular TCP proxy never invents [`Transport::Quic`] or HTTP/3 flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Quic,
}

impl Transport {
    /// Wire label used in JSON and the inspector (`"quic"` / `"tcp"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Quic => "quic",
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
    /// True when the frame was injected through the API rather than observed
    /// on the wire. Omitted from JSON when false so ordinary capture stays quiet.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub injected: bool,
    /// True when `text` / `body_id` hold inflated display bytes for a
    /// permessage-deflate message. `size` remains the on-wire payload length.
    /// Omitted from JSON when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compressed: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<FlowId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_messages: Option<Vec<WsMessage>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelInfo>,
    /// What the rewrite rules changed on the way through, one note per change.
    ///
    /// A capture shows what went on the wire, so a header a rule added is
    /// indistinguishable in the record from one the client sent. These notes are
    /// how it can be told apart, and without them the honest capture becomes a
    /// confusing one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrites: Vec<String>,
    /// True when the response was produced by map-local / mock rather than an
    /// origin. Omitted when false so ordinary flows stay quiet in JSON.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mocked: bool,
    /// Wire transport. `None` on older captures and ordinary TCP proxy flows
    /// (omit from JSON so TCP list rows stay quiet). H3 producers set
    /// [`Transport::Quic`]. Never set to a synthetic `tcp` label just to fill
    /// the field: omit means TCP (or unknown older capture).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    /// Proxima UUID for the client-facing multiplex session (not a wire QUIC
    /// CID or TLS session id). Shared by every request stream on that session
    /// so H2 over TLS and H3 over QUIC can group the same way in the list and
    /// HAR `connection` field. Minted once per client TLS session (H2) or
    /// client QUIC connection (H3). `None` for HTTP/1.x, opaque tunnels, and
    /// older captures that omit the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    /// Client-leg stream key when the stack exposes one. For H3 this is the
    /// QUIC stream id. For H2 it is the HTTP/2 stream id when available;
    /// otherwise `None` (do not invent wire-looking numbers). Distinct from
    /// [`Self::upstream_stream_id`] because MITM reopens the origin leg and
    /// must never claim client stream id equals origin stream id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u64>,
    /// Origin-leg stream id when the upstream session is also multiplexed
    /// (H3 reverse today; future pooled H2 upstream if recorded). `None` when
    /// the origin leg is plain TCP request/response or the id is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_stream_id: Option<u64>,
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
    /// Wire transport when known. Omitted for TCP so older list UIs stay quiet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    /// Client multiplex session grouping key (H2 TLS or H3 QUIC). See
    /// [`Flow::connection_id`]. Omitted when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    /// Client-leg stream key when known. See [`Flow::stream_id`]. Omitted when
    /// `None`. Full-flow-only `upstreamStreamId` is not projected here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u64>,
    /// True when the response was produced by map-local / mock rather than an
    /// origin. Omitted when false so ordinary list rows stay quiet in JSON.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mocked: bool,
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
    /// A WS frame or HTTP message is held before forward.
    #[serde(rename = "pause:hit")]
    PauseHit { pause: Box<PauseSnapshot> },
    /// A held pause was released, dropped, timed out, or cancelled.
    #[serde(rename = "pause:resolved")]
    PauseResolved {
        #[serde(rename = "pauseId")]
        pause_id: String,
        #[serde(rename = "flowId")]
        flow_id: FlowId,
        action: PauseResolveAction,
        reason: PauseResolveReason,
    },
    #[serde(rename = "clear")]
    Clear,
    #[serde(rename = "status")]
    Status { status: Box<ServerStatus> },
}

/* ------------------------------------------------------------------ */
/* Breakpoints / pauses (WS and HTTP via kind-tagged body)             */
/* ------------------------------------------------------------------ */

/// What kind of traffic a pause or breakpoint rule applies to.
///
/// Nested kind bodies (`ws` / `http`) keep the event shape shared without
/// flattening protocol fields into the top level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PauseKind {
    Ws,
    /// Request/response breakpoints. Not produced by the WS path.
    Http,
}

/// How a held pause was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PauseResolveAction {
    Release,
    Drop,
}

/// Who or what resolved the pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PauseResolveReason {
    User,
    Timeout,
    /// Connection closed or pump exited while the pause was still held.
    Closed,
}

/// Live pause as published on `pause:hit` and listed via the API.
///
/// Kind-specific detail lives under [`Self::ws`] / [`Self::http`] so both
/// protocols share one envelope without flattening fields into the top level.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PauseSnapshot {
    pub pause_id: String,
    pub flow_id: FlowId,
    pub kind: PauseKind,
    pub created_at: u64,
    pub expires_at: u64,
    /// WebSocket frame being held. Present when [`Self::kind`] is [`PauseKind::Ws`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws: Option<PauseWsBody>,
    /// HTTP request or response being held. Present when kind is [`PauseKind::Http`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<PauseHttpBody>,
}

/// Which half of an HTTP exchange a pause applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpPauseHalf {
    Request,
    Response,
}

/// HTTP half of a held pause.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PauseHttpBody {
    pub half: HttpPauseHalf,
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderPair>,
    pub size: u64,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_base64: Option<String>,
    /// Status code when half is response; omitted/None for request half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

/// WebSocket half of a held pause: direction, opcode and a payload snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PauseWsBody {
    pub direction: WsDirection,
    pub opcode: u8,
    pub size: u64,
    pub truncated: bool,
    /// Inline UTF-8 for small text frames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Base64 of the retained payload when not inlined as text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_base64: Option<String>,
}

/// A breakpoint rule. Runtime-only today; not persisted across restarts.
///
/// Empty `hosts` matches any host. Empty `directions` matches both. Empty
/// `opcodes` for a WS rule defaults to text and binary (1, 2), never control
/// frames: pausing ping/pong/close would break keepalive and the close
/// handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BreakpointRule {
    pub id: String,
    pub enabled: bool,
    pub kind: PauseKind,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Path prefix match; empty or missing matches any path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// Empty means both directions.
    #[serde(default)]
    pub directions: Vec<WsDirection>,
    /// Empty means default data opcodes (1 text, 2 binary) for WS rules.
    #[serde(default)]
    pub opcodes: Vec<u8>,
    /// How long the pump will hold a matching frame before auto-releasing the
    /// original. Zero is treated as a short safety floor by the hub.
    pub timeout_ms: u64,
    /// For [`PauseKind::Http`]: which half to pause. Defaults to request when
    /// omitted. Response half pauses after the origin reply is held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_half: Option<HttpPauseHalf>,
    /// For HTTP rules: empty means any method.
    #[serde(default)]
    pub methods: Vec<String>,
}

/// PUT /api/breakpoints body and GET response envelope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BreakpointRulesBody {
    #[serde(default)]
    pub rules: Vec<BreakpointRule>,
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
    /// Whether this binary was built with `--features quic` (UDP/QUIC stack).
    /// Independent of whether a UDP listener is currently bound; see
    /// [`Self::quic_port`]. Always present so clients can tell feature-off
    /// builds from feature-on builds with no listener.
    pub quic_enabled: bool,
    /// UDP port for the QUIC/HTTP3 listener when one is bound. `None` when
    /// no UDP socket is listening. Port 0 is rewritten to the OS-assigned
    /// value at start. The classic TCP proxy port never carries QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_port: Option<u16>,
    /// Short honesty note about QUIC visibility (feature off, no listener,
    /// or reverse mode). Regular TCP proxy mode never sees QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_note: Option<String>,
    /// Upstream authority for reverse H3 mode, if configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverse_h3: Option<String>,
    /// Whether this binary was built with `--features wireguard` (WG scaffold).
    /// Independent of whether a WG UDP listener is currently bound; see
    /// [`Self::wireguard_port`]. Always present so clients can tell feature-off
    /// builds from feature-on builds with no listener.
    pub wireguard_enabled: bool,
    /// UDP port for the WireGuard userspace scaffold when one is bound.
    /// `None` when no WG socket is listening. Port 0 is rewritten to the
    /// OS-assigned value at start. This is not a claim that device-join crypto
    /// works; the scaffold binds only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard_port: Option<u16>,
    /// Short honesty note about WireGuard (feature off, scaffold only, or
    /// crypto not shipped). Wi-Fi HTTP proxy settings never feed this path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard_note: Option<String>,
    /// Whether this binary was built with `--features tun` (local capture
    /// scaffold). Independent of whether the no-op TUN task is running; see
    /// [`Self::tun_active`]. Always present so clients can tell feature-off
    /// builds from feature-on builds with TUN idle.
    pub tun_enabled: bool,
    /// Whether the TUN scaffold task was started for this process. `Some(true)`
    /// means the shutdown-only serve task is configured, not that packets are
    /// captured. `None` when TUN was never requested (typical default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun_active: Option<bool>,
    /// Short honesty note about TUN (feature off, scaffold only, platform
    /// limits). Never claims working host packet capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun_note: Option<String>,
}

/* ------------------------------------------------------------------ */
/* Query                                                               */
/* ------------------------------------------------------------------ */

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowQuery {
    /// Substring match against method, url, status, content type, and
    /// multiplex `connection_id` (shared H2+H3 session key). Also matches the
    /// synthetic needles `mock` / `mocked` when [`Flow::mocked`] is true.
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
    /// When true, keep only map-local / mock flows (`flow.mocked`).
    #[serde(default)]
    pub only_mocked: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_http_maps_http3() {
        assert_eq!(
            HttpVersion::from_http(http::Version::HTTP_3),
            HttpVersion::Http3
        );
        assert_eq!(
            HttpVersion::from_http(http::Version::HTTP_2),
            HttpVersion::Http2
        );
        assert_eq!(
            HttpVersion::from_http(http::Version::HTTP_11),
            HttpVersion::Http11
        );
    }

    #[test]
    fn http3_serde_and_labels() {
        assert_eq!(HttpVersion::Http3.as_label(), "3.0");
        assert_eq!(HttpVersion::Http3.as_har(), "HTTP/3");
        let json = serde_json::to_string(&HttpVersion::Http3).unwrap();
        assert_eq!(json, "\"3.0\"");
        let back: HttpVersion = serde_json::from_str("\"3.0\"").unwrap();
        assert_eq!(back, HttpVersion::Http3);
    }

    #[test]
    fn transport_serde_lowercase() {
        assert_eq!(
            serde_json::to_string(&Transport::Quic).unwrap(),
            "\"quic\""
        );
        assert_eq!(serde_json::to_string(&Transport::Tcp).unwrap(), "\"tcp\"");
        let back: Transport = serde_json::from_str("\"quic\"").unwrap();
        assert_eq!(back, Transport::Quic);
        assert_eq!(Transport::Quic.as_str(), "quic");
        assert_eq!(Transport::Tcp.as_str(), "tcp");
    }

    #[test]
    fn pause_snapshot_deserialises_without_future_http_field() {
        // Kind-tagged envelope: clients may only know `ws` today; adding `http`
        // later must not break older snapshots that omit it.
        let bare = serde_json::json!({
            "pauseId": "p1",
            "flowId": "f1",
            "kind": "ws",
            "createdAt": 1,
            "expiresAt": 2,
            "ws": {
                "direction": "recv",
                "opcode": 2,
                "size": 2,
                "truncated": false,
                "dataBase64": "3q0="
            }
        });
        let snap: PauseSnapshot = serde_json::from_value(bare).expect("snapshot");
        assert_eq!(snap.kind, PauseKind::Ws);
        assert_eq!(snap.ws.as_ref().map(|w| w.opcode), Some(2));
        assert_eq!(
            snap.ws.as_ref().and_then(|w| w.data_base64.as_deref()),
            Some("3q0=")
        );

        // Http kind is reserved on the wire for the shared protocol.
        let http_kind: PauseKind = serde_json::from_str("\"http\"").expect("http kind");
        assert_eq!(http_kind, PauseKind::Http);
        assert_eq!(
            serde_json::to_string(&PauseKind::Http).expect("ser"),
            "\"http\""
        );
    }

    #[test]
    fn tcp_flow_omits_multiplex_fields_from_json() {
        let flow = Flow {
            id: "f1".into(),
            kind: FlowKind::Http,
            state: FlowState::Complete,
            intercepted: true,
            request: FlowRequest {
                method: "GET".into(),
                url: "https://example.com/".into(),
                scheme: Scheme::Https,
                authority: "example.com".into(),
                host: "example.com".into(),
                port: 443,
                path: "/".into(),
                http_version: HttpVersion::Http11,
                headers: Vec::new(),
                body: None,
            },
            response: None,
            error: None,
            timings: FlowTimings::default(),
            client: FlowClient {
                address: "127.0.0.1".into(),
                port: 1,
            },
            server: FlowServer::default(),
            replay_of: None,
            comment: None,
            ws_messages: None,
            tunnel: None,
            rewrites: Vec::new(),
            mocked: false,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        };
        let value = serde_json::to_value(&flow).unwrap();
        let obj = value.as_object().unwrap();
        assert!(!obj.contains_key("transport"));
        assert!(!obj.contains_key("connectionId"));
        assert!(!obj.contains_key("streamId"));
        assert!(!obj.contains_key("upstreamStreamId"));
        // Older clients can omit the new fields and still deserialise.
        let bare = serde_json::json!({
            "id": "f1",
            "kind": "http",
            "state": "complete",
            "intercepted": true,
            "request": {
                "method": "GET",
                "url": "https://example.com/",
                "scheme": "https",
                "authority": "example.com",
                "host": "example.com",
                "port": 443,
                "path": "/",
                "httpVersion": "1.1",
                "headers": []
            },
            "response": null,
            "error": null,
            "timings": { "start": 0 },
            "client": { "address": "127.0.0.1", "port": 1 },
            "server": {}
        });
        let decoded: Flow = serde_json::from_value(bare).unwrap();
        assert_eq!(decoded.transport, None);
        assert_eq!(decoded.connection_id, None);
        assert_eq!(decoded.stream_id, None);
        assert_eq!(decoded.upstream_stream_id, None);
    }

    #[test]
    fn h3_flow_serialises_multiplex_fields() {
        let flow = Flow {
            id: "h3-1".into(),
            kind: FlowKind::Http,
            state: FlowState::Complete,
            intercepted: true,
            request: FlowRequest {
                method: "GET".into(),
                url: "https://api.example.com/hello".into(),
                scheme: Scheme::Https,
                authority: "api.example.com".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/hello".into(),
                http_version: HttpVersion::Http3,
                headers: Vec::new(),
                body: None,
            },
            response: Some(FlowResponse {
                status: 200,
                status_text: "OK".into(),
                // Honest when origin is TCP h2 while client spoke h3.
                http_version: HttpVersion::Http2,
                headers: Vec::new(),
                body: None,
            }),
            error: None,
            timings: FlowTimings::default(),
            client: FlowClient {
                address: "10.0.0.2".into(),
                port: 4444,
            },
            server: FlowServer {
                alpn: Some("h3".into()),
                ..FlowServer::default()
            },
            replay_of: None,
            comment: None,
            ws_messages: None,
            tunnel: None,
            rewrites: Vec::new(),
            mocked: false,
            transport: Some(Transport::Quic),
            connection_id: Some("conn-uuid".into()),
            stream_id: Some(0),
            upstream_stream_id: Some(4),
        };
        let value = serde_json::to_value(&flow).unwrap();
        assert_eq!(value["request"]["httpVersion"], "3.0");
        assert_eq!(value["response"]["httpVersion"], "2.0");
        assert_eq!(value["transport"], "quic");
        assert_eq!(value["connectionId"], "conn-uuid");
        assert_eq!(value["streamId"], 0);
        assert_eq!(value["upstreamStreamId"], 4);
        assert_eq!(value["server"]["alpn"], "h3");

        let summary = FlowSummary {
            id: flow.id.clone(),
            kind: flow.kind,
            state: flow.state,
            intercepted: flow.intercepted,
            method: flow.request.method.clone(),
            scheme: flow.request.scheme,
            authority: flow.request.authority.clone(),
            path: flow.request.path.clone(),
            http_version: flow.request.http_version,
            status: Some(200),
            content_type: None,
            request_size: 0,
            response_size: 0,
            start: 0,
            duration: None,
            error: None,
            likely_pinning: false,
            client: flow.client.address.clone(),
            transport: flow.transport,
            connection_id: flow.connection_id.clone(),
            stream_id: flow.stream_id,
            mocked: flow.mocked,
        };
        let s = serde_json::to_value(&summary).unwrap();
        assert_eq!(s["httpVersion"], "3.0");
        assert_eq!(s["transport"], "quic");
        assert_eq!(s["connectionId"], "conn-uuid");
        assert_eq!(s["streamId"], 0);
        // upstreamStreamId is full-Flow only.
        assert!(s.get("upstreamStreamId").is_none());
    }

    #[test]
    fn h2_flow_serialises_multiplex_without_transport() {
        // Shared H2+H3 identity: TCP H2 may carry connectionId/streamId while
        // transport stays omitted (not Quic, not a synthetic "tcp" label).
        let flow = Flow {
            id: "h2-1".into(),
            kind: FlowKind::Http,
            state: FlowState::Complete,
            intercepted: true,
            request: FlowRequest {
                method: "GET".into(),
                url: "https://api.example.com/v1".into(),
                scheme: Scheme::Https,
                authority: "api.example.com".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/v1".into(),
                http_version: HttpVersion::Http2,
                headers: Vec::new(),
                body: None,
            },
            response: Some(FlowResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: HttpVersion::Http2,
                headers: Vec::new(),
                body: None,
            }),
            error: None,
            timings: FlowTimings::default(),
            client: FlowClient {
                address: "10.0.0.3".into(),
                port: 5001,
            },
            server: FlowServer {
                alpn: Some("h2".into()),
                ..FlowServer::default()
            },
            replay_of: None,
            comment: None,
            ws_messages: None,
            tunnel: None,
            rewrites: Vec::new(),
            mocked: false,
            transport: None,
            connection_id: Some("tls-session-uuid".into()),
            stream_id: Some(1),
            upstream_stream_id: None,
        };
        let value = serde_json::to_value(&flow).unwrap();
        assert_eq!(value["request"]["httpVersion"], "2.0");
        assert_eq!(value["connectionId"], "tls-session-uuid");
        assert_eq!(value["streamId"], 1);
        let obj = value.as_object().unwrap();
        assert!(
            !obj.contains_key("transport"),
            "TCP H2 must omit transport, not emit tcp/quic"
        );
        assert!(
            !obj.contains_key("upstreamStreamId"),
            "origin stream only when MITM reopens multiplex upstream"
        );

        let summary = FlowSummary {
            id: flow.id.clone(),
            kind: flow.kind,
            state: flow.state,
            intercepted: flow.intercepted,
            method: flow.request.method.clone(),
            scheme: flow.request.scheme,
            authority: flow.request.authority.clone(),
            path: flow.request.path.clone(),
            http_version: flow.request.http_version,
            status: Some(200),
            content_type: None,
            request_size: 0,
            response_size: 0,
            start: 0,
            duration: None,
            error: None,
            likely_pinning: false,
            client: flow.client.address.clone(),
            transport: flow.transport,
            connection_id: flow.connection_id.clone(),
            stream_id: flow.stream_id,
            mocked: flow.mocked,
        };
        let s = serde_json::to_value(&summary).unwrap();
        assert_eq!(s["httpVersion"], "2.0");
        assert_eq!(s["connectionId"], "tls-session-uuid");
        assert_eq!(s["streamId"], 1);
        assert!(s.as_object().unwrap().get("transport").is_none());
        assert!(s.as_object().unwrap().get("upstreamStreamId").is_none());

        // Round-trip keeps optional multiplex keys and leaves transport None.
        let back: Flow = serde_json::from_value(value).unwrap();
        assert_eq!(back.connection_id.as_deref(), Some("tls-session-uuid"));
        assert_eq!(back.stream_id, Some(1));
        assert_eq!(back.upstream_stream_id, None);
        assert_eq!(back.transport, None);
        assert_eq!(back.request.http_version, HttpVersion::Http2);
    }

    /// Proxy H2 path: mint connectionId per TLS session, leave streamId None
    /// until a real wire id is available (do not invent RFC 9113 numbers).
    #[test]
    fn h2_connection_only_omits_stream_keys_from_json() {
        let flow = Flow {
            id: "h2-conn-only".into(),
            kind: FlowKind::Http,
            state: FlowState::Pending,
            intercepted: true,
            request: FlowRequest {
                method: "GET".into(),
                url: "https://api.example.com/".into(),
                scheme: Scheme::Https,
                authority: "api.example.com".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/".into(),
                http_version: HttpVersion::Http2,
                headers: Vec::new(),
                body: None,
            },
            response: None,
            error: None,
            timings: FlowTimings::default(),
            client: FlowClient {
                address: "10.0.0.4".into(),
                port: 6000,
            },
            server: FlowServer {
                alpn: Some("h2".into()),
                ..FlowServer::default()
            },
            replay_of: None,
            comment: None,
            ws_messages: None,
            tunnel: None,
            rewrites: Vec::new(),
            mocked: false,
            transport: None,
            connection_id: Some("tls-session-only".into()),
            stream_id: None,
            upstream_stream_id: None,
        };
        let value = serde_json::to_value(&flow).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(value["connectionId"], "tls-session-only");
        assert!(!obj.contains_key("streamId"));
        assert!(!obj.contains_key("upstreamStreamId"));
        assert!(!obj.contains_key("transport"));

        let summary = FlowSummary {
            id: flow.id.clone(),
            kind: flow.kind,
            state: flow.state,
            intercepted: flow.intercepted,
            method: flow.request.method.clone(),
            scheme: flow.request.scheme,
            authority: flow.request.authority.clone(),
            path: flow.request.path.clone(),
            http_version: flow.request.http_version,
            status: None,
            content_type: None,
            request_size: 0,
            response_size: 0,
            start: 0,
            duration: None,
            error: None,
            likely_pinning: false,
            client: flow.client.address.clone(),
            transport: None,
            connection_id: flow.connection_id.clone(),
            stream_id: None,
            mocked: false,
        };
        let s = serde_json::to_value(&summary).unwrap();
        let sobj = s.as_object().unwrap();
        assert_eq!(s["connectionId"], "tls-session-only");
        assert!(!sobj.contains_key("streamId"));
        assert!(!sobj.contains_key("upstreamStreamId"));
        assert!(!sobj.contains_key("transport"));
        assert!(!sobj.contains_key("mocked"));
    }

    /// Bare FlowSummary JSON (older list rows) deserialises multiplex as None.
    #[test]
    fn bare_flow_summary_deserialises_multiplex_none() {
        let bare = serde_json::json!({
            "id": "s-old",
            "kind": "http",
            "state": "complete",
            "intercepted": true,
            "method": "GET",
            "scheme": "https",
            "authority": "example.com",
            "path": "/",
            "httpVersion": "1.1",
            "status": 200,
            "contentType": null,
            "requestSize": 0,
            "responseSize": 0,
            "start": 1,
            "duration": 2,
            "error": null,
            "likelyPinning": false,
            "client": "127.0.0.1"
        });
        let summary: FlowSummary = serde_json::from_value(bare).expect("bare summary");
        assert_eq!(summary.transport, None);
        assert_eq!(summary.connection_id, None);
        assert_eq!(summary.stream_id, None);
        assert!(!summary.mocked);
        // No upstreamStreamId field on the type; JSON must not invent one.
        let out = serde_json::to_value(&summary).unwrap();
        assert!(out.as_object().unwrap().get("upstreamStreamId").is_none());
        assert!(out.as_object().unwrap().get("connectionId").is_none());
        assert!(out.as_object().unwrap().get("streamId").is_none());
        assert!(out.as_object().unwrap().get("transport").is_none());
        assert!(out.as_object().unwrap().get("mocked").is_none());
    }

    /// H2 and H3 share the same multiplex wire keys; only transport differs.
    #[test]
    fn h2_and_h3_share_multiplex_wire_keys() {
        let h2 = Flow {
            id: "k-h2".into(),
            kind: FlowKind::Http,
            state: FlowState::Complete,
            intercepted: true,
            request: FlowRequest {
                method: "GET".into(),
                url: "https://example.com/h2".into(),
                scheme: Scheme::Https,
                authority: "example.com".into(),
                host: "example.com".into(),
                port: 443,
                path: "/h2".into(),
                http_version: HttpVersion::Http2,
                headers: Vec::new(),
                body: None,
            },
            response: None,
            error: None,
            timings: FlowTimings::default(),
            client: FlowClient {
                address: "1.1.1.1".into(),
                port: 1,
            },
            server: FlowServer::default(),
            replay_of: None,
            comment: None,
            ws_messages: None,
            tunnel: None,
            rewrites: Vec::new(),
            mocked: false,
            transport: None,
            connection_id: Some("sess".into()),
            stream_id: Some(7),
            upstream_stream_id: None,
        };
        let mut h3 = h2.clone();
        h3.id = "k-h3".into();
        h3.request.http_version = HttpVersion::Http3;
        h3.request.path = "/h3".into();
        h3.request.url = "https://example.com/h3".into();
        h3.transport = Some(Transport::Quic);
        h3.upstream_stream_id = Some(11);

        let v2 = serde_json::to_value(&h2).unwrap();
        let v3 = serde_json::to_value(&h3).unwrap();
        // Shared session/stream keys (camelCase, no protocol fork).
        assert_eq!(v2["connectionId"], "sess");
        assert_eq!(v3["connectionId"], "sess");
        assert_eq!(v2["streamId"], 7);
        assert_eq!(v3["streamId"], 7);
        // Transport is orthogonal: omit on TCP H2, quic only for H3.
        assert!(v2.as_object().unwrap().get("transport").is_none());
        assert_eq!(v3["transport"], "quic");
        assert!(v2.as_object().unwrap().get("upstreamStreamId").is_none());
        assert_eq!(v3["upstreamStreamId"], 11);
        // Client and origin stream ids stay distinct when both set.
        assert_ne!(v3["streamId"], v3["upstreamStreamId"]);
    }
}
