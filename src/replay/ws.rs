//! Replay captured WebSocket frames onto a live upgraded flow, or compose a
//! new dial with `replay_of`.
//!
//! Selects frames from a source flow's `ws_messages`, resolves payloads from
//! inline text or the body store, and injects them in order through
//! [`crate::proxy::websocket::WsRegistry::inject`]. Injected frames are written
//! immediately (no rewrite, no breakpoint pause) and recorded with
//! `injected: true`, same path as `POST .../ws/send`.
//!
//! ## Modes
//!
//! - **`live`**: inject onto an already-upgraded flow (default target = source).
//! - **`compose`**: dial a fresh HTTP/1.1 WebSocket to the source request's
//!   origin, create a new flow with `replay_of`, spawn the same pump as the
//!   proxy, then inject. `targetFlowId` is refused (target is always the new
//!   flow).
//!
//! ## Limits (honest capture, imperfect wire replay)
//!
//! - **Drop markers** (opcode 15): never injected. Auto-selection skips them;
//!   an explicit index to a marker fails closed.
//! - **Continuations** (opcode 0): inject only emits FIN frames, so a
//!   continuation cannot be replayed honestly. Auto-selection skips them;
//!   an explicit index fails closed.
//! - **Other non-data/control opcodes**: same as continuations.
//! - **Truncated captures**: fail closed. A partial payload must not be sent
//!   as if it were complete.
//! - **Missing body store bytes**: fail closed with a clear error (eviction or
//!   clear after capture). Empty payloads (`size == 0`) are allowed.
//! - **Compressed** (`permessage-deflate`): capture stores inflated display
//!   bytes in `text` / `body_id`. Replay injects those bytes uncompressed
//!   (legal, not wire-identical RSV1 frames).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result as AnyResult};
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use rand::RngCore;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tracing::debug;

use crate::capture::{is_ws_drop_marker, BodyStore, FlowInit, FlowStore};
use crate::config::strip_port;
use crate::proxy::breakpoint::PauseHub;
use crate::proxy::forward::Upstream;
use crate::proxy::headers;
use crate::proxy::websocket::{InjectError, WsRegistry};
use crate::proxy::ws_deflate::{self, PermessageDeflateParams};
use crate::proxy::ws_rewrite::WsRewriteHub;
use crate::proxy::websocket;
use crate::types::{
    now_ms, Flow, FlowClient, FlowError, FlowId, FlowKind, FlowRequest, FlowResponse, FlowServer,
    FlowState, HeaderPair, HttpVersion, Scheme, WsDirection, WsMessage,
};

/// Default cap on how many frames one replay may plan. Matches the per-flow
/// capture window so a full history can be selected without a hostile body.
pub const DEFAULT_MAX_FRAMES: usize = 4096;

/// Request body for `POST /api/flows/{sourceId}/ws/replay`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsReplayRequest {
    /// Live flow to inject into (`mode: live`). Defaults to the source id.
    /// Refused when `mode` is `"compose"` (target is always the new dial).
    pub target_flow_id: Option<String>,
    /// `"live"` (default) or `"compose"` (dial a new socket with `replay_of`).
    pub mode: Option<String>,
    /// Explicit indices into `source.ws_messages`. When omitted, every eligible
    /// frame after direction filter is planned (up to `max_frames`).
    pub indices: Option<Vec<usize>>,
    /// `"send"` and/or `"recv"`. Defaults to both.
    pub directions: Option<Vec<String>>,
    /// Sleep between successful injects (after each oneshot resolves).
    pub delay_ms: Option<u64>,
    /// When true (default), stop on the first inject failure.
    pub stop_on_error: Option<bool>,
    /// Cap on planned frames. Defaults to [`DEFAULT_MAX_FRAMES`].
    pub max_frames: Option<usize>,
}

/// Dependencies for compose mode (dial + pump).
pub struct ComposeDeps {
    pub store: Arc<FlowStore>,
    pub registry: Arc<WsRegistry>,
    pub pauses: Arc<PauseHub>,
    pub ws_rewrite: Arc<WsRewriteHub>,
    pub upstream: Upstream,
}

/// Plan failures (400/409) or dial/handshake failures (502).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeError {
    Plan(PlanError),
    Dial(String),
}

impl ComposeError {
    pub fn message(&self) -> &str {
        match self {
            ComposeError::Plan(p) => p.message(),
            ComposeError::Dial(m) => m,
        }
    }
}

impl From<PlanError> for ComposeError {
    fn from(value: PlanError) -> Self {
        ComposeError::Plan(value)
    }
}

/// Successful or partial reply body for the replay route.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WsReplayResult {
    pub source_flow_id: FlowId,
    pub target_flow_id: FlowId,
    pub mode: String,
    pub planned: usize,
    pub sent: usize,
    pub skipped: usize,
    pub messages: Vec<WsMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One frame ready to inject, with payload already resolved from capture.
#[derive(Debug, Clone)]
pub struct PlannedFrame {
    /// Index in the source `ws_messages` vector (for error messages).
    pub index: usize,
    pub direction: WsDirection,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// Why planning or early validation failed (maps to HTTP 4xx).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    BadRequest(String),
    /// Missing body bytes, truncated capture, or similar fail-closed cases that
    /// the route surfaces as 409 when nothing has been sent yet.
    Conflict(String),
}

impl PlanError {
    pub fn message(&self) -> &str {
        match self {
            PlanError::BadRequest(m) | PlanError::Conflict(m) => m,
        }
    }
}

/// True for opcodes `ws/send` and inject will accept.
pub fn is_injectable_opcode(opcode: u8) -> bool {
    matches!(opcode, 1 | 2 | 8 | 9 | 10)
}

/// Parses direction filter strings into [`WsDirection`] values.
pub fn parse_directions(raw: Option<&[String]>) -> Result<Option<Vec<WsDirection>>, PlanError> {
    let Some(list) = raw else {
        return Ok(None);
    };
    if list.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        match item.as_str() {
            "send" => out.push(WsDirection::Send),
            "recv" => out.push(WsDirection::Recv),
            other => {
                return Err(PlanError::BadRequest(format!(
                    "direction must be \"send\" or \"recv\", not \"{other}\""
                )));
            }
        }
    }
    Ok(Some(out))
}

/// Resolves the bytes to inject for one captured frame.
///
/// Prefers inline `text`, then body store via `body_id`, then empty when
/// `size == 0`. Truncated frames and missing non-empty payloads fail closed.
pub fn resolve_payload(
    message: &WsMessage,
    bodies: &BodyStore,
    index: usize,
) -> Result<Vec<u8>, PlanError> {
    if message.truncated {
        return Err(PlanError::Conflict(format!(
            "frame {index} was truncated in capture and cannot be replayed honestly"
        )));
    }
    if let Some(text) = &message.text {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(body_id) = &message.body_id {
        return match bodies.read(body_id) {
            Some(bytes) => Ok(bytes.to_vec()),
            None => Err(PlanError::Conflict(format!(
                "frame {index} body is missing from the store (evicted or cleared)"
            ))),
        };
    }
    if message.size == 0 {
        return Ok(Vec::new());
    }
    Err(PlanError::Conflict(format!(
        "frame {index} has size {} but no text or bodyId to replay",
        message.size
    )))
}

/// Builds the ordered inject list from a source history.
///
/// - With `indices`: each index is validated; markers, continuations, and other
///   non-injectable opcodes fail closed (nothing is planned).
/// - Without `indices`: markers and non-injectable opcodes are skipped; only
///   direction-filtered injectable frames are planned, up to `max_frames`.
///
/// Returns `(planned, skipped)` where `skipped` counts auto-skipped frames
/// (markers / bad opcodes / direction filter misses when auto-selecting).
pub fn plan_frames(
    messages: &[WsMessage],
    bodies: &BodyStore,
    indices: Option<&[usize]>,
    directions: Option<&[WsDirection]>,
    max_frames: usize,
) -> Result<(Vec<PlannedFrame>, usize), PlanError> {
    if max_frames == 0 {
        return Err(PlanError::BadRequest(
            "maxFrames must be at least 1".into(),
        ));
    }

    let direction_ok = |dir: WsDirection| -> bool {
        match directions {
            None => true,
            Some(list) => list.contains(&dir),
        }
    };

    let mut planned = Vec::new();
    let mut skipped = 0usize;

    if let Some(indices) = indices {
        for &index in indices {
            if index >= messages.len() {
                return Err(PlanError::BadRequest(format!(
                    "index {index} is out of range (source has {} frame{})",
                    messages.len(),
                    if messages.len() == 1 { "" } else { "s" }
                )));
            }
            let message = &messages[index];
            if is_ws_drop_marker(message) {
                return Err(PlanError::BadRequest(format!(
                    "index {index} is a retention drop marker and cannot be injected"
                )));
            }
            if !direction_ok(message.direction) {
                return Err(PlanError::BadRequest(format!(
                    "index {index} direction does not match the directions filter"
                )));
            }
            if !is_injectable_opcode(message.opcode) {
                return Err(PlanError::BadRequest(format!(
                    "index {index} has opcode {} which cannot be injected (only 1, 2, 8, 9, 10)",
                    message.opcode
                )));
            }
            let payload = resolve_payload(message, bodies, index)?;
            if message.opcode >= 8 && payload.len() > 125 {
                return Err(PlanError::BadRequest(format!(
                    "index {index} is a control frame with a payload longer than 125 bytes"
                )));
            }
            if planned.len() >= max_frames {
                return Err(PlanError::BadRequest(format!(
                    "selection exceeds maxFrames ({max_frames})"
                )));
            }
            planned.push(PlannedFrame {
                index,
                direction: message.direction,
                opcode: message.opcode,
                payload,
            });
        }
        return Ok((planned, skipped));
    }

    // Auto-select: skip markers and non-injectable opcodes.
    for (index, message) in messages.iter().enumerate() {
        if planned.len() >= max_frames {
            // Remaining eligible frames are not planned; count as skipped so
            // the caller can see the cap bit.
            let remaining = messages.len() - index;
            skipped = skipped.saturating_add(remaining);
            break;
        }
        if is_ws_drop_marker(message) {
            skipped += 1;
            continue;
        }
        if !direction_ok(message.direction) {
            skipped += 1;
            continue;
        }
        if !is_injectable_opcode(message.opcode) {
            skipped += 1;
            continue;
        }
        let payload = resolve_payload(message, bodies, index)?;
        if message.opcode >= 8 && payload.len() > 125 {
            return Err(PlanError::BadRequest(format!(
                "frame {index} is a control frame with a payload longer than 125 bytes"
            )));
        }
        planned.push(PlannedFrame {
            index,
            direction: message.direction,
            opcode: message.opcode,
            payload,
        });
    }

    Ok((planned, skipped))
}

/// Maps registry inject failures to a stable conflict message.
pub fn inject_error_message(err: InjectError) -> String {
    match err {
        InjectError::NotLive | InjectError::Closed => {
            "that flow has no live WebSocket to inject into".into()
        }
        InjectError::Full => {
            "the WebSocket inject queue is full; try again when the peer is reading".into()
        }
    }
}

/// Injects planned frames in order, awaiting each write before the next.
///
/// When `stop_on_error` is true, the first inject or write failure ends the
/// loop. When false, remaining frames are still attempted after a failure.
/// Mid-sequence progress is always returned (partial `sent` / `messages`).
pub async fn execute_live(
    registry: &WsRegistry,
    target_id: &str,
    planned: &[PlannedFrame],
    delay_ms: u64,
    stop_on_error: bool,
) -> (usize, Vec<WsMessage>, Option<String>) {
    let mut sent = 0usize;
    let mut messages = Vec::with_capacity(planned.len());
    let mut error: Option<String> = None;

    for (i, frame) in planned.iter().enumerate() {
        let reply = match registry.inject(
            target_id,
            frame.direction,
            frame.opcode,
            frame.payload.clone(),
        ) {
            Ok(rx) => rx,
            Err(err) => {
                let msg = inject_error_message(err);
                error = Some(format!(
                    "frame {} (source index {}): {msg}",
                    i, frame.index
                ));
                if stop_on_error {
                    break;
                }
                continue;
            }
        };

        match reply.await {
            Ok(message) => {
                sent += 1;
                messages.push(message);
            }
            Err(_) => {
                error = Some(format!(
                    "frame {} (source index {}): the WebSocket closed before the injected frame was written",
                    i, frame.index
                ));
                if stop_on_error {
                    break;
                }
                continue;
            }
        }

        if delay_ms > 0 && i + 1 < planned.len() {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    (sent, messages, error)
}

/// Plans and runs a live replay. Caller must have already checked that the
/// source flow exists and supplied its messages snapshot.
pub async fn replay_live(
    registry: &WsRegistry,
    bodies: &BodyStore,
    source_id: &str,
    target_id: &str,
    messages: &[WsMessage],
    request: &WsReplayRequest,
) -> Result<WsReplayResult, PlanError> {
    let mode = request.mode.as_deref().unwrap_or("live");
    if mode != "live" {
        return Err(PlanError::BadRequest(format!(
            "mode \"{mode}\" is not supported here; use replay_compose for \"compose\""
        )));
    }

    let max_frames = request.max_frames.unwrap_or(DEFAULT_MAX_FRAMES);
    let directions = parse_directions(request.directions.as_deref())?;
    let (planned, skipped) = plan_frames(
        messages,
        bodies,
        request.indices.as_deref(),
        directions.as_deref(),
        max_frames,
    )?;

    let delay_ms = request.delay_ms.unwrap_or(0);
    let stop_on_error = request.stop_on_error.unwrap_or(true);

    let (sent, recorded, error) =
        execute_live(registry, target_id, &planned, delay_ms, stop_on_error).await;

    // When nothing went out, surface inject failures as a plan-level conflict
    // so the HTTP layer can answer 409 like ws/send.
    if sent == 0 {
        if let Some(err) = error {
            return Err(PlanError::Conflict(err));
        }
    }

    Ok(WsReplayResult {
        source_flow_id: source_id.to_string(),
        target_flow_id: target_id.to_string(),
        mode: "live".into(),
        planned: planned.len(),
        sent,
        skipped,
        messages: recorded,
        error,
    })
}

/// Dials a new WebSocket from the source request, pumps it under a new flow
/// with `replay_of`, then injects the planned frames.
pub async fn replay_compose(
    deps: &ComposeDeps,
    source: &Flow,
    messages: &[WsMessage],
    request: &WsReplayRequest,
) -> Result<WsReplayResult, ComposeError> {
    let mode = request.mode.as_deref().unwrap_or("compose");
    if mode != "compose" {
        return Err(ComposeError::Plan(PlanError::BadRequest(format!(
            "mode \"{mode}\" is not compose"
        ))));
    }
    if request
        .target_flow_id
        .as_deref()
        .is_some_and(|s| !s.is_empty())
    {
        return Err(ComposeError::Plan(PlanError::BadRequest(
            "targetFlowId is not used in compose mode; the new dial is always the target".into(),
        )));
    }

    let max_frames = request.max_frames.unwrap_or(DEFAULT_MAX_FRAMES);
    let directions = parse_directions(request.directions.as_deref())?;
    let (planned, skipped) = plan_frames(
        messages,
        deps.store.bodies(),
        request.indices.as_deref(),
        directions.as_deref(),
        max_frames,
    )?;

    let new_id = match dial_and_start_compose(deps, source).await {
        Ok(id) => id,
        Err(err) => return Err(ComposeError::Dial(err)),
    };

    let delay_ms = request.delay_ms.unwrap_or(0);
    let stop_on_error = request.stop_on_error.unwrap_or(true);
    let (sent, recorded, error) = execute_live(
        deps.registry.as_ref(),
        &new_id,
        &planned,
        delay_ms,
        stop_on_error,
    )
    .await;

    if sent == 0 {
        if let Some(err) = error {
            return Err(ComposeError::Plan(PlanError::Conflict(err)));
        }
    }

    Ok(WsReplayResult {
        source_flow_id: source.id.clone(),
        target_flow_id: new_id,
        mode: "compose".into(),
        planned: planned.len(),
        sent,
        skipped,
        messages: recorded,
        error,
    })
}

/// Create flow, dial upgrade, spawn pump, wait until registry is live.
async fn dial_and_start_compose(deps: &ComposeDeps, source: &Flow) -> Result<FlowId, String> {
    let req = &source.request;
    let host = strip_port(&req.host).to_string();
    let port = req.port;
    let path = if req.path.is_empty() {
        "/".to_string()
    } else {
        req.path.clone()
    };

    let id = deps.store.create(FlowInit {
        kind: FlowKind::Websocket,
        intercepted: true,
        request: FlowRequest {
            method: req.method.clone(),
            url: req.url.clone(),
            scheme: req.scheme,
            authority: req.authority.clone(),
            host: req.host.clone(),
            port: req.port,
            path: path.clone(),
            http_version: HttpVersion::Http11,
            headers: req.headers.clone(),
            body: None,
        },
        client: FlowClient {
            address: "127.0.0.1".into(),
            port: 0,
        },
        server: FlowServer {
            address: Some(host.clone()),
            port: Some(port),
            ..FlowServer::default()
        },
        replay_of: Some(source.id.clone()),
        transport: None,
        connection_id: None,
        stream_id: None,
        upstream_stream_id: None,
    });
    deps.store.update(&id, |flow| {
        flow.ws_messages = Some(Vec::new());
    });

    let dial_result = dial_websocket_upgrade(&deps.upstream, req, &host, port, &path).await;
    let dialed = match dial_result {
        Ok(d) => d,
        Err(err) => {
            let msg = format!("{err:#}");
            deps.store.fail(
                &id,
                FlowError {
                    message: msg.clone(),
                    code: Some("compose".into()),
                    likely_pinning: None,
                },
            );
            return Err(msg);
        }
    };

    let connect_end = dialed.connect_end;
    let request_sent = dialed.request_sent;
    let response_start = dialed.response_start;
    let deflate = dialed.deflate;
    let response_headers = dialed.response_headers.clone();
    let facts = dialed.tls_facts;

    deps.store.update(&id, |flow| {
        flow.state = FlowState::Streaming;
        flow.timings.connect_end = Some(connect_end);
        flow.timings.request_sent = Some(request_sent);
        flow.timings.response_start = Some(response_start);
        if let Some(facts) = &facts {
            flow.timings.tls_end = facts.tls_end;
            flow.server.sni = facts.sni.clone();
            flow.server.alpn = facts.alpn.clone();
            flow.server.tls_version = facts.tls_version.clone();
            flow.server.cipher = facts.cipher.clone();
            flow.server.cert_fingerprint = facts.cert_fingerprint.clone();
        }
        flow.response = Some(FlowResponse {
            status: 101,
            status_text: "Switching Protocols".into(),
            http_version: HttpVersion::Http11,
            headers: response_headers,
            body: None,
        });
    });

    // Duplex stands in for the missing browser half. hold_end is drained so
    // origin→client frames do not fill the buffer and stall the pump.
    let (client_end, mut hold_end) = tokio::io::duplex(64 * 1024);
    let store = deps.store.clone();
    let registry = deps.registry.clone();
    let pauses = deps.pauses.clone();
    let ws_rewrite = deps.ws_rewrite.clone();
    let flow_id = id.clone();
    let ws_host = host.clone();
    let ws_path = path.clone();
    let upgraded = dialed.upstream_io;

    tokio::spawn(async move {
        // Discard anything written toward the synthetic client so Recv from
        // origin cannot block the pump forever.
        let drain = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match hold_end.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        };
        tokio::select! {
            _ = drain => {}
            _ = websocket::pump(
                client_end,
                upgraded,
                store,
                flow_id,
                registry,
                pauses,
                ws_rewrite,
                ws_host,
                ws_path,
                deflate,
            ) => {}
        }
    });

    // Wait until the pump has registered inject senders.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if deps.registry.is_live(&id) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let msg = "compose WebSocket pump did not become live in time".to_string();
            deps.store.fail(
                &id,
                FlowError {
                    message: msg.clone(),
                    code: Some("compose".into()),
                    likely_pinning: None,
                },
            );
            return Err(msg);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    Ok(id)
}

struct DialedWs {
    upstream_io: TokioIo<hyper::upgrade::Upgraded>,
    connect_end: u64,
    request_sent: u64,
    response_start: u64,
    response_headers: Vec<HeaderPair>,
    tls_facts: Option<crate::proxy::forward::TlsFacts>,
    deflate: PermessageDeflateParams,
}

async fn dial_websocket_upgrade(
    upstream: &Upstream,
    source_req: &FlowRequest,
    host: &str,
    port: u16,
    path: &str,
) -> AnyResult<DialedWs> {
    let stream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let _ = stream.set_nodelay(true);
    let connect_end = now_ms();

    match source_req.scheme {
        Scheme::Http => {
            let request_sent = now_ms();
            let (io, headers, deflate) =
                http1_upgrade(stream, source_req, host, port, path).await?;
            Ok(DialedWs {
                upstream_io: io,
                connect_end,
                request_sent,
                response_start: now_ms(),
                response_headers: headers,
                tls_facts: None,
                deflate,
            })
        }
        Scheme::Https => {
            let name = ServerName::try_from(host.to_string())
                .map_err(|_| anyhow!("{host} is not a usable TLS server name"))?;
            // Upgrades require HTTP/1.1; never offer h2.
            let tls = tokio_rustls::TlsConnector::from(upstream.client_config(false))
                .connect(name, stream)
                .await
                .with_context(|| format!("TLS handshake with {host}"))?;
            let facts = crate::proxy::forward::tls_facts(&tls, host);
            let request_sent = now_ms();
            let (io, headers, deflate) = http1_upgrade(tls, source_req, host, port, path).await?;
            Ok(DialedWs {
                upstream_io: io,
                connect_end,
                request_sent,
                response_start: now_ms(),
                response_headers: headers,
                tls_facts: Some(facts),
                deflate,
            })
        }
    }
}

async fn http1_upgrade<I>(
    io: I,
    source_req: &FlowRequest,
    host: &str,
    port: u16,
    path: &str,
) -> AnyResult<(
    TokioIo<hyper::upgrade::Upgraded>,
    Vec<HeaderPair>,
    PermessageDeflateParams,
)>
where
    I: tokio::io::AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .context("HTTP/1.1 handshake for WebSocket compose")?;
    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            debug!(error = %err, "compose upgrade connection ended");
        }
    });

    let mut map = HeaderMap::new();
    for (name, value) in &source_req.headers {
        if name.starts_with(':') {
            continue;
        }
        // Fresh key every dial; drop captured length/transfer framing.
        if name.eq_ignore_ascii_case("sec-websocket-key")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let Ok(n) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(v) = HeaderValue::from_str(value) else {
            continue;
        };
        map.append(n, v);
    }
    // Ensure upgrade framing is present even if capture stripped hop headers.
    map.insert(
        http::header::UPGRADE,
        HeaderValue::from_static("websocket"),
    );
    map.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("Upgrade"),
    );
    map.insert(
        http::header::SEC_WEBSOCKET_VERSION,
        HeaderValue::from_static("13"),
    );
    let mut key = [0u8; 16];
    rand::rng().fill_bytes(&mut key);
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
    map.insert(
        http::header::SEC_WEBSOCKET_KEY,
        HeaderValue::from_str(&key_b64).expect("base64 is valid header value"),
    );

    let authority = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    headers::set_host(&mut map, &authority);
    // Keep upgrade hop headers that for_upstream would otherwise strip.
    let sent = headers::for_upstream(&map, headers::Wire::Http1);
    // for_upstream with websocket upgrade keeps Connection/Upgrade; merge key.
    let mut sent = sent;
    for name in [
        http::header::SEC_WEBSOCKET_KEY,
        http::header::SEC_WEBSOCKET_VERSION,
        http::header::SEC_WEBSOCKET_EXTENSIONS,
        http::header::SEC_WEBSOCKET_PROTOCOL,
    ] {
        if let Some(v) = map.get(&name) {
            sent.insert(name, v.clone());
        }
    }
    // Always re-apply our generated key last.
    sent.insert(
        http::header::SEC_WEBSOCKET_KEY,
        HeaderValue::from_str(&key_b64).expect("base64"),
    );

    let uri: Uri = path
        .parse()
        .with_context(|| format!("{path} is not a usable request path"))?;
    let method = Method::from_bytes(source_req.method.as_bytes()).unwrap_or(Method::GET);
    let mut request = Request::new(Empty::<Bytes>::new());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.headers_mut() = sent;

    let mut response = sender
        .send_request(request)
        .await
        .context("sending WebSocket upgrade request")?;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(anyhow!(
            "origin answered {} instead of 101 Switching Protocols",
            response.status()
        ));
    }

    let response_headers = headers::to_pairs(response.headers());
    let ext_joined = {
        let mut parts = Vec::new();
        for val in response
            .headers()
            .get_all(http::header::SEC_WEBSOCKET_EXTENSIONS)
        {
            if let Ok(s) = val.to_str() {
                parts.push(s);
            }
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    };
    let deflate = ws_deflate::parse_sec_websocket_extensions(ext_joined.as_deref());

    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .context("taking the upgraded WebSocket stream")?;
    Ok((TokioIo::new(upgraded), response_headers, deflate))
}

/// Convenience for tests and call sites that hold an `Arc` registry.
pub async fn replay_live_arc(
    registry: &Arc<WsRegistry>,
    bodies: &BodyStore,
    source_id: &str,
    target_id: &str,
    messages: &[WsMessage],
    request: &WsReplayRequest,
) -> Result<WsReplayResult, PlanError> {
    replay_live(
        registry.as_ref(),
        bodies,
        source_id,
        target_id,
        messages,
        request,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{FlowStore, WS_DROPPED_OPCODE};
    use crate::types::WsDirection;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn msg(
        direction: WsDirection,
        opcode: u8,
        text: Option<&str>,
        size: u64,
        body_id: Option<String>,
    ) -> WsMessage {
        WsMessage {
            at: 1,
            direction,
            opcode,
            size,
            truncated: false,
            text: text.map(str::to_string),
            body_id,
            injected: false,
            compressed: false,
        }
    }

    fn marker() -> WsMessage {
        WsMessage {
            at: 0,
            direction: WsDirection::Send,
            opcode: WS_DROPPED_OPCODE,
            size: 10,
            truncated: true,
            text: Some("10 earlier messages discarded".into()),
            body_id: None,
            injected: false,
            compressed: false,
        }
    }

    #[test]
    fn auto_select_skips_markers_and_continuations() {
        let bodies = BodyStore::new(1024);
        let messages = vec![
            marker(),
            msg(WsDirection::Send, 1, Some("a"), 1, None),
            msg(WsDirection::Recv, 0, None, 0, None), // continuation
            msg(WsDirection::Recv, 2, None, 0, None), // empty binary
            msg(WsDirection::Send, 9, Some("p"), 1, None),
        ];
        let (planned, skipped) =
            plan_frames(&messages, &bodies, None, None, 4096).expect("plan");
        assert_eq!(planned.len(), 3);
        assert_eq!(skipped, 2);
        assert_eq!(planned[0].payload, b"a");
        assert_eq!(planned[0].index, 1);
        assert_eq!(planned[1].opcode, 2);
        assert_eq!(planned[2].opcode, 9);
    }

    #[test]
    fn explicit_index_to_marker_fails_closed() {
        let bodies = BodyStore::new(1024);
        let messages = vec![marker(), msg(WsDirection::Send, 1, Some("a"), 1, None)];
        let err = plan_frames(&messages, &bodies, Some(&[0]), None, 4096).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
        assert!(err.message().contains("drop marker"));
    }

    #[test]
    fn explicit_index_to_continuation_fails_closed() {
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(WsDirection::Send, 0, None, 0, None)];
        let err = plan_frames(&messages, &bodies, Some(&[0]), None, 4096).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
        assert!(err.message().contains("opcode 0"));
    }

    #[test]
    fn direction_filter_selects_send_only() {
        let bodies = BodyStore::new(1024);
        let messages = vec![
            msg(WsDirection::Send, 1, Some("out"), 3, None),
            msg(WsDirection::Recv, 1, Some("in"), 2, None),
        ];
        let dirs = vec![WsDirection::Send];
        let (planned, skipped) =
            plan_frames(&messages, &bodies, None, Some(&dirs), 4096).expect("plan");
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].payload, b"out");
        assert_eq!(skipped, 1);
    }

    #[test]
    fn missing_body_fails_closed() {
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(
            WsDirection::Send,
            2,
            None,
            4,
            Some("gone".into()),
        )];
        let err = plan_frames(&messages, &bodies, None, None, 4096).unwrap_err();
        assert!(matches!(err, PlanError::Conflict(_)));
        assert!(err.message().contains("missing"));
    }

    #[test]
    fn truncated_frame_fails_closed() {
        let bodies = BodyStore::new(1024);
        let mut m = msg(WsDirection::Send, 1, Some("partial"), 99, None);
        m.truncated = true;
        let err = plan_frames(&[m], &bodies, None, None, 4096).unwrap_err();
        assert!(matches!(err, PlanError::Conflict(_)));
        assert!(err.message().contains("truncated"));
    }

    #[test]
    fn body_store_payload_is_used_for_binary() {
        let store = FlowStore::new(4, 1024, 64 * 1024);
        let mut writer = store.bodies().writer(1024);
        writer.write(&[0xde, 0xad]);
        let meta = writer.finish(None, None);
        let messages = vec![msg(
            WsDirection::Recv,
            2,
            None,
            2,
            Some(meta.id.clone()),
        )];
        let (planned, _) =
            plan_frames(&messages, store.bodies(), Some(&[0]), None, 4096).expect("plan");
        assert_eq!(planned[0].payload, &[0xde, 0xad]);
    }

    #[test]
    fn out_of_range_index_is_bad_request() {
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(WsDirection::Send, 1, Some("a"), 1, None)];
        let err = plan_frames(&messages, &bodies, Some(&[5]), None, 4096).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
    }

    #[test]
    fn max_frames_caps_auto_select() {
        let bodies = BodyStore::new(1024);
        let messages: Vec<_> = (0..5)
            .map(|i| msg(WsDirection::Send, 1, Some(&format!("{i}")), 1, None))
            .collect();
        let (planned, skipped) =
            plan_frames(&messages, &bodies, None, None, 2).expect("plan");
        assert_eq!(planned.len(), 2);
        assert_eq!(skipped, 3);
    }

    #[test]
    fn parse_directions_rejects_unknown() {
        let raw = vec!["sideways".into()];
        let err = parse_directions(Some(&raw)).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
    }

    #[test]
    fn empty_payload_with_size_zero_is_allowed() {
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(WsDirection::Send, 2, None, 0, None)];
        let (planned, skipped) =
            plan_frames(&messages, &bodies, None, None, 4096).expect("plan");
        assert_eq!(planned.len(), 1);
        assert!(planned[0].payload.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn size_without_text_or_body_fails_closed() {
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(WsDirection::Send, 2, None, 4, None)];
        let err = plan_frames(&messages, &bodies, None, None, 4096).unwrap_err();
        assert!(matches!(err, PlanError::Conflict(_)));
        assert!(err.message().contains("no text or bodyId"));
    }

    #[test]
    fn text_is_preferred_over_body_id() {
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(
            WsDirection::Send,
            1,
            Some("inline"),
            6,
            Some("ignored-body".into()),
        )];
        let (planned, _) =
            plan_frames(&messages, &bodies, Some(&[0]), None, 4096).expect("plan");
        assert_eq!(planned[0].payload, b"inline");
    }

    #[test]
    fn compressed_display_bytes_still_resolve() {
        // Capture stores inflated display bytes; compressed flag must not block
        // payload resolution (replay injects them uncompressed).
        let bodies = BodyStore::new(1024);
        let mut m = msg(WsDirection::Send, 1, Some("inflated"), 8, None);
        m.compressed = true;
        let (planned, _) =
            plan_frames(&[m], &bodies, Some(&[0]), None, 4096).expect("plan");
        assert_eq!(planned[0].payload, b"inflated");
    }

    #[test]
    fn control_frame_payload_over_125_fails() {
        let bodies = BodyStore::new(1024);
        let big = "x".repeat(126);
        let messages = vec![msg(WsDirection::Send, 9, Some(&big), 126, None)];
        let err = plan_frames(&messages, &bodies, Some(&[0]), None, 4096).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
        assert!(err.message().contains("125"));
    }

    #[test]
    fn explicit_bad_opcode_fails_closed() {
        let bodies = BodyStore::new(1024);
        // Opcode 3 is reserved; not injectable.
        let messages = vec![msg(WsDirection::Send, 3, Some("x"), 1, None)];
        let err = plan_frames(&messages, &bodies, Some(&[0]), None, 4096).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
        assert!(err.message().contains("opcode 3"));
    }

    #[test]
    fn auto_select_skips_bad_opcodes_without_failing() {
        let bodies = BodyStore::new(1024);
        let messages = vec![
            msg(WsDirection::Send, 3, Some("x"), 1, None),
            msg(WsDirection::Send, 1, Some("ok"), 2, None),
        ];
        let (planned, skipped) =
            plan_frames(&messages, &bodies, None, None, 4096).expect("plan");
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].payload, b"ok");
        assert_eq!(skipped, 1);
    }

    #[test]
    fn explicit_index_direction_mismatch_fails() {
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(WsDirection::Recv, 1, Some("in"), 2, None)];
        let dirs = vec![WsDirection::Send];
        let err =
            plan_frames(&messages, &bodies, Some(&[0]), Some(&dirs), 4096).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
        assert!(err.message().contains("direction"));
    }

    #[test]
    fn explicit_selection_exceeding_max_frames_fails() {
        let bodies = BodyStore::new(1024);
        let messages = vec![
            msg(WsDirection::Send, 1, Some("a"), 1, None),
            msg(WsDirection::Send, 1, Some("b"), 1, None),
        ];
        let err =
            plan_frames(&messages, &bodies, Some(&[0, 1]), None, 1).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
        assert!(err.message().contains("maxFrames"));
    }

    #[test]
    fn max_frames_zero_is_bad_request() {
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(WsDirection::Send, 1, Some("a"), 1, None)];
        let err = plan_frames(&messages, &bodies, None, None, 0).unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
    }

    #[test]
    fn is_injectable_opcode_matches_ws_send() {
        for ok in [1u8, 2, 8, 9, 10] {
            assert!(is_injectable_opcode(ok), "opcode {ok} should be injectable");
        }
        for bad in [0u8, 3, 7, 11, 15] {
            assert!(
                !is_injectable_opcode(bad),
                "opcode {bad} must not be injectable"
            );
        }
    }

    #[test]
    fn inject_error_message_maps_not_live_and_full() {
        assert!(inject_error_message(InjectError::NotLive).contains("no live WebSocket"));
        assert!(inject_error_message(InjectError::Closed).contains("no live WebSocket"));
        assert!(inject_error_message(InjectError::Full).contains("full"));
    }

    #[test]
    fn request_denies_unknown_fields() {
        let err = serde_json::from_str::<WsReplayRequest>(r#"{"mode":"live","extra":1}"#);
        assert!(err.is_err(), "unknown fields must be refused");
    }

    #[test]
    fn request_defaults_deserialise_from_empty_object() {
        let req: WsReplayRequest = serde_json::from_str("{}").expect("empty object");
        assert!(req.target_flow_id.is_none());
        assert!(req.mode.is_none());
        assert!(req.indices.is_none());
        assert!(req.directions.is_none());
        assert!(req.delay_ms.is_none());
        assert!(req.stop_on_error.is_none());
        assert!(req.max_frames.is_none());
    }

    /// P11: README documents camelCase request/response keys. Lock both so the
    /// public API cannot silently rename under operators.
    #[test]
    fn request_and_result_use_readme_camel_case() {
        let req: WsReplayRequest = serde_json::from_str(
            r#"{
                "targetFlowId": "other",
                "mode": "live",
                "indices": [0, 2],
                "directions": ["send", "recv"],
                "delayMs": 50,
                "stopOnError": false,
                "maxFrames": 10
            }"#,
        )
        .expect("README-shaped body");
        assert_eq!(req.target_flow_id.as_deref(), Some("other"));
        assert_eq!(req.mode.as_deref(), Some("live"));
        assert_eq!(req.indices.as_deref(), Some(&[0usize, 2][..]));
        assert_eq!(
            req.directions.as_ref().map(|d| d.as_slice()),
            Some(&["send".to_string(), "recv".to_string()][..])
        );
        assert_eq!(req.delay_ms, Some(50));
        assert_eq!(req.stop_on_error, Some(false));
        assert_eq!(req.max_frames, Some(10));

        let result = WsReplayResult {
            source_flow_id: "src".into(),
            target_flow_id: "tgt".into(),
            mode: "live".into(),
            planned: 2,
            sent: 1,
            skipped: 1,
            messages: vec![],
            error: Some("stopped".into()),
        };
        let json = serde_json::to_value(&result).expect("serialize");
        for key in [
            "sourceFlowId",
            "targetFlowId",
            "mode",
            "planned",
            "sent",
            "skipped",
            "messages",
            "error",
        ] {
            assert!(
                json.get(key).is_some(),
                "WsReplayResult must serialise README key {key}: {json}"
            );
        }
        assert_eq!(json["sourceFlowId"], "src");
        assert_eq!(json["targetFlowId"], "tgt");
        assert_eq!(json["planned"], 2);
        assert_eq!(json["sent"], 1);
        assert_eq!(json["skipped"], 1);
        assert_eq!(json["error"], "stopped");
    }

    #[tokio::test]
    async fn execute_live_injects_in_order_and_marks_injected() {
        let registry = WsRegistry::new();
        let (tx_up, mut rx_up) = mpsc::channel(8);
        let (tx_client, _rx_client) = mpsc::channel(8);
        registry.register("t1".into(), tx_up, tx_client);

        // Drain injects in a task that completes the oneshots.
        let consumer = tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Some(cmd) = rx_up.recv().await {
                seen.push(cmd.payload.clone());
                let _ = cmd.reply.send(WsMessage {
                    at: 1,
                    direction: WsDirection::Send,
                    opcode: cmd.opcode,
                    size: cmd.payload.len() as u64,
                    truncated: false,
                    text: Some(String::from_utf8_lossy(&cmd.payload).into_owned()),
                    body_id: None,
                    injected: true,
                    compressed: false,
                });
            }
            seen
        });

        let planned = vec![
            PlannedFrame {
                index: 0,
                direction: WsDirection::Send,
                opcode: 1,
                payload: b"one".to_vec(),
            },
            PlannedFrame {
                index: 2,
                direction: WsDirection::Send,
                opcode: 1,
                payload: b"two".to_vec(),
            },
        ];
        let (sent, messages, error) = execute_live(&registry, "t1", &planned, 0, true).await;
        assert_eq!(sent, 2);
        assert!(error.is_none());
        assert!(messages.iter().all(|m| m.injected));
        assert_eq!(messages[0].text.as_deref(), Some("one"));
        assert_eq!(messages[1].text.as_deref(), Some("two"));

        registry.unregister("t1");
        let seen = consumer.await.expect("consumer");
        assert_eq!(seen, vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[tokio::test]
    async fn execute_live_not_live_returns_error_with_zero_sent() {
        let registry = WsRegistry::new();
        let planned = vec![PlannedFrame {
            index: 0,
            direction: WsDirection::Send,
            opcode: 1,
            payload: b"x".to_vec(),
        }];
        let (sent, messages, error) = execute_live(&registry, "missing", &planned, 0, true).await;
        assert_eq!(sent, 0);
        assert!(messages.is_empty());
        assert!(error.unwrap().contains("no live WebSocket"));
    }

    /// First frame succeeds; unregister mid-sequence; stop_on_error leaves partial progress.
    #[tokio::test]
    async fn execute_live_mid_sequence_failure_stops_with_partial_sent() {
        let registry = Arc::new(WsRegistry::new());
        let (tx_up, mut rx_up) = mpsc::channel(8);
        let (tx_client, _rx_client) = mpsc::channel(8);
        registry.register("t-partial".into(), tx_up, tx_client);

        let registry_for_consumer = Arc::clone(&registry);
        let consumer = tokio::spawn(async move {
            let mut count = 0usize;
            while let Some(cmd) = rx_up.recv().await {
                count += 1;
                let _ = cmd.reply.send(WsMessage {
                    at: 1,
                    direction: WsDirection::Send,
                    opcode: cmd.opcode,
                    size: cmd.payload.len() as u64,
                    truncated: false,
                    text: Some(String::from_utf8_lossy(&cmd.payload).into_owned()),
                    body_id: None,
                    injected: true,
                    compressed: false,
                });
                if count == 1 {
                    // Drop the live half after the first write so the second inject fails.
                    registry_for_consumer.unregister("t-partial");
                }
            }
            count
        });

        let planned = vec![
            PlannedFrame {
                index: 0,
                direction: WsDirection::Send,
                opcode: 1,
                payload: b"one".to_vec(),
            },
            PlannedFrame {
                index: 1,
                direction: WsDirection::Send,
                opcode: 1,
                payload: b"two".to_vec(),
            },
        ];
        let (sent, messages, error) =
            execute_live(registry.as_ref(), "t-partial", &planned, 0, true).await;
        assert_eq!(sent, 1);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].injected);
        assert!(error.is_some());
        assert!(error.unwrap().contains("no live WebSocket"));

        let _ = consumer.await;
    }

    /// With stop_on_error false, a mid-sequence NotLive still attempts remaining frames.
    #[tokio::test]
    async fn execute_live_continues_when_stop_on_error_is_false() {
        let registry = WsRegistry::new();
        // Never register: every inject fails.
        let planned = vec![
            PlannedFrame {
                index: 0,
                direction: WsDirection::Send,
                opcode: 1,
                payload: b"a".to_vec(),
            },
            PlannedFrame {
                index: 1,
                direction: WsDirection::Send,
                opcode: 1,
                payload: b"b".to_vec(),
            },
        ];
        let (sent, messages, error) =
            execute_live(&registry, "gone", &planned, 0, false).await;
        assert_eq!(sent, 0);
        assert!(messages.is_empty());
        // Last failure is retained.
        assert!(error.unwrap().contains("source index 1"));
    }

    /// delayMs uses the sleep path between successful injects; frames stay ordered.
    /// (No tokio test-util: only checks the path still completes, not virtual time.)
    #[tokio::test]
    async fn execute_live_with_delay_ms_still_sends_in_order() {
        let registry = WsRegistry::new();
        let (tx_up, mut rx_up) = mpsc::channel(8);
        let (tx_client, _rx_client) = mpsc::channel(8);
        registry.register("t-delay".into(), tx_up, tx_client);

        let consumer = tokio::spawn(async move {
            let mut payloads = Vec::new();
            while let Some(cmd) = rx_up.recv().await {
                payloads.push(cmd.payload.clone());
                let _ = cmd.reply.send(WsMessage {
                    at: 1,
                    direction: WsDirection::Send,
                    opcode: 1,
                    size: cmd.payload.len() as u64,
                    truncated: false,
                    text: None,
                    body_id: None,
                    injected: true,
                    compressed: false,
                });
            }
            payloads
        });

        let planned = vec![
            PlannedFrame {
                index: 0,
                direction: WsDirection::Send,
                opcode: 1,
                payload: b"a".to_vec(),
            },
            PlannedFrame {
                index: 1,
                direction: WsDirection::Send,
                opcode: 1,
                payload: b"b".to_vec(),
            },
        ];
        let (sent, messages, error) =
            execute_live(&registry, "t-delay", &planned, 1, true).await;
        assert_eq!(sent, 2);
        assert!(error.is_none());
        assert_eq!(messages.len(), 2);

        registry.unregister("t-delay");
        let payloads = consumer.await.expect("consumer");
        assert_eq!(payloads, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[tokio::test]
    async fn replay_live_end_to_end_conflict_when_not_live() {
        let registry = WsRegistry::new();
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(WsDirection::Send, 1, Some("hi"), 2, None)];
        let req = WsReplayRequest::default();
        let err = replay_live(&registry, &bodies, "s", "s", &messages, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, PlanError::Conflict(_)));
    }

    /// Partial progress (sent > 0) is a 200-shaped Ok result with error set, not Conflict.
    #[tokio::test]
    async fn replay_live_partial_progress_is_ok_with_error_field() {
        let registry = Arc::new(WsRegistry::new());
        let (tx_up, mut rx_up) = mpsc::channel(8);
        let (tx_client, _rx_client) = mpsc::channel(8);
        registry.register("t-ok-partial".into(), tx_up, tx_client);

        let registry_for_consumer = Arc::clone(&registry);
        let consumer = tokio::spawn(async move {
            if let Some(cmd) = rx_up.recv().await {
                let _ = cmd.reply.send(WsMessage {
                    at: 1,
                    direction: WsDirection::Send,
                    opcode: 1,
                    size: cmd.payload.len() as u64,
                    truncated: false,
                    text: Some(String::from_utf8_lossy(&cmd.payload).into_owned()),
                    body_id: None,
                    injected: true,
                    compressed: false,
                });
                registry_for_consumer.unregister("t-ok-partial");
            }
            // Drain any further (should be none after unregister).
            while rx_up.recv().await.is_some() {}
        });

        let bodies = BodyStore::new(1024);
        let messages = vec![
            msg(WsDirection::Send, 1, Some("first"), 5, None),
            msg(WsDirection::Send, 1, Some("second"), 6, None),
        ];
        let req = WsReplayRequest::default();
        let result = replay_live(
            registry.as_ref(),
            &bodies,
            "src",
            "t-ok-partial",
            &messages,
            &req,
        )
        .await
        .expect("partial progress must not be Conflict");
        assert_eq!(result.planned, 2);
        assert_eq!(result.sent, 1);
        assert_eq!(result.messages.len(), 1);
        assert!(result.messages[0].injected);
        assert!(result.error.is_some());

        let _ = consumer.await;
    }

    #[tokio::test]
    async fn replay_live_success_preserves_order_and_ids() {
        let registry = WsRegistry::new();
        let (tx_up, mut rx_up) = mpsc::channel(8);
        let (tx_client, _rx_client) = mpsc::channel(8);
        registry.register("tgt".into(), tx_up, tx_client);

        let consumer = tokio::spawn(async move {
            let mut payloads = Vec::new();
            while let Some(cmd) = rx_up.recv().await {
                payloads.push(cmd.payload.clone());
                let _ = cmd.reply.send(WsMessage {
                    at: 1,
                    direction: WsDirection::Send,
                    opcode: cmd.opcode,
                    size: cmd.payload.len() as u64,
                    truncated: false,
                    text: Some(String::from_utf8_lossy(&cmd.payload).into_owned()),
                    body_id: None,
                    injected: true,
                    compressed: false,
                });
            }
            payloads
        });

        let bodies = BodyStore::new(1024);
        let messages = vec![
            marker(),
            msg(WsDirection::Send, 1, Some("a"), 1, None),
            msg(WsDirection::Recv, 1, Some("b"), 1, None),
            msg(WsDirection::Send, 1, Some("c"), 1, None),
        ];
        let req = WsReplayRequest {
            indices: Some(vec![1, 3]),
            directions: Some(vec!["send".into()]),
            ..Default::default()
        };
        let result = replay_live(&registry, &bodies, "source-id", "tgt", &messages, &req)
            .await
            .expect("live replay");
        assert_eq!(result.source_flow_id, "source-id");
        assert_eq!(result.target_flow_id, "tgt");
        assert_eq!(result.mode, "live");
        assert_eq!(result.planned, 2);
        assert_eq!(result.sent, 2);
        assert!(result.error.is_none());
        assert_eq!(result.messages[0].text.as_deref(), Some("a"));
        assert_eq!(result.messages[1].text.as_deref(), Some("c"));

        registry.unregister("tgt");
        let payloads = consumer.await.expect("consumer");
        assert_eq!(payloads, vec![b"a".to_vec(), b"c".to_vec()]);
    }

    #[tokio::test]
    async fn compose_mode_is_refused_on_live_path() {
        let registry = WsRegistry::new();
        let bodies = BodyStore::new(1024);
        let messages = vec![msg(WsDirection::Send, 1, Some("hi"), 2, None)];
        let req = WsReplayRequest {
            mode: Some("compose".into()),
            ..Default::default()
        };
        let err = replay_live(&registry, &bodies, "s", "s", &messages, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, PlanError::BadRequest(_)));
        assert!(
            err.message().contains("compose") || err.message().contains("replay_compose"),
            "{}",
            err.message()
        );
    }

    #[tokio::test]
    async fn compose_rejects_target_flow_id() {
        use crate::config::Config;
        use crate::proxy::breakpoint::PauseHub;
        use crate::proxy::ws_rewrite::WsRewriteHub;
        use crate::types::{FlowClient, FlowRequest, FlowServer, FlowState, Scheme};

        let store = Arc::new(FlowStore::new(8, 1024, 4096));
        let config = Config::default();
        let upstream = crate::proxy::forward::Upstream::new(&config).expect("upstream");
        let deps = ComposeDeps {
            store: store.clone(),
            registry: Arc::new(WsRegistry::new()),
            pauses: Arc::new(PauseHub::new()),
            ws_rewrite: WsRewriteHub::empty(),
            upstream,
        };
        let source = Flow {
            id: "src".into(),
            kind: crate::types::FlowKind::Websocket,
            state: FlowState::Complete,
            intercepted: true,
            request: FlowRequest {
                method: "GET".into(),
                url: "http://127.0.0.1/ws".into(),
                scheme: Scheme::Http,
                authority: "127.0.0.1".into(),
                host: "127.0.0.1".into(),
                port: 80,
                path: "/ws".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            response: None,
            error: None,
            timings: Default::default(),
            client: FlowClient {
                address: "127.0.0.1".into(),
                port: 1,
            },
            server: FlowServer::default(),
            replay_of: None,
            comment: None,
            ws_messages: Some(vec![]),
            tunnel: None,
            rewrites: vec![],
            mocked: false,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        };
        let req = WsReplayRequest {
            mode: Some("compose".into()),
            target_flow_id: Some("other".into()),
            ..Default::default()
        };
        let err = replay_compose(&deps, &source, &[], &req)
            .await
            .expect_err("targetFlowId must be refused in compose");
        assert!(matches!(err, ComposeError::Plan(PlanError::BadRequest(_))));
    }
}
