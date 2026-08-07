//! REST endpoints, the live event socket and the certificate downloads.
//!
//! Every query parameter is parsed by hand rather than through serde. Two of
//! them repeat (`host`, `method`) and one is a compound range (`status`), which
//! form decoding does not express, and doing it here means a malformed value
//! becomes a 400 with a sentence a human can act on instead of a rejection the
//! UI has to guess at.

use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use bytes::Bytes;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use time::OffsetDateTime;
use tokio::sync::broadcast::error::RecvError;

use crate::types::{Flow, FlowKind, FlowQuery, FlowSummary, ProxyEvent};

use super::{inspector, setup, ApiState, Download};

/// A limit large enough to export everything anyone reasonably holds in the
/// ring buffer, small enough that a typo cannot ask for a gigabyte of JSON.
const MAX_LIMIT: usize = 10_000;
const MAX_SEARCH_LEN: usize = 512;
const MAX_FILTER_VALUES: usize = 64;
const MAX_QUERY_PAIRS: usize = 256;
const MAX_ID_LEN: usize = 128;
/// Long enough for any hand-written analytical query, short enough that the
/// endpoint cannot be used to push a payload at DuckDB's parser.
const MAX_SQL_LEN: usize = 8_192;
/// A browser tab that stopped reading must not pin a broadcast slot forever.
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const WS_PING_INTERVAL: Duration = Duration::from_secs(20);

// There is no CORS layer here and no origin is ever allowed, deliberately.
// This server listens on every interface so a phone can reach the setup page,
// it has no authentication, and every captured request it hands back carries
// that request's cookies and bearer tokens. `/api/send` on top of that is an
// HTTP client that will fetch any URL and hand the answer back. Naming even one
// origin gives whatever is listening on that origin all of it, and the
// inspector needs nothing here: it is served from this same origin, and a same
// origin fetch is not subject to CORS at all.
pub(super) fn build(state: ApiState) -> Router {
    // The endpoints that carry a whole request body read it with the `Bytes`
    // extractor, which otherwise stops at the axum default of 2 MB. Capture
    // keeps bodies up to `max_body_bytes`, 10 MB by default, and a replay of one
    // has to be able to carry it back out, so the limit follows the config
    // rather than the framework.
    let body_limit = usize::try_from(state.config.max_body_bytes).unwrap_or(usize::MAX);

    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/flows", get(list_flows).delete(clear_flows))
        .route("/api/flows/{id}", get(get_flow))
        .route("/api/flows/{id}/body/{which}", get(get_body))
        .route("/api/bodies/{id}", get(get_body_by_id))
        // Pretty-print + semantic highlight via themoretheless-tokenizer.
        .route(
            "/api/json/view",
            post(json_view).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route("/api/flows/{id}/curl", get(get_curl))
        .route(
            "/api/flows/{id}/replay",
            post(replay_flow).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route(
            "/api/flows/{id}/ws/send",
            post(ws_send).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route(
            "/api/flows/{id}/ws/replay",
            post(ws_replay).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route(
            "/api/send",
            post(send).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route("/api/har", get(get_har))
        .route("/api/archive/query", post(query_archive))
        .route("/api/archive/stats", get(archive_stats))
        .route(
            "/api/collections",
            get(list_collections).post(create_collection),
        )
        .route(
            "/api/collections/{id}",
            put(update_collection).delete(delete_collection),
        )
        .route(
            "/api/environments",
            get(list_environments).post(create_environment),
        )
        .route(
            "/api/environments/active",
            get(get_active_environment).put(put_active_environment),
        )
        .route(
            "/api/environments/{id}",
            put(update_environment).delete(delete_environment),
        )
        .route("/api/stream", get(stream))
        .route(
            "/api/breakpoints",
            get(get_breakpoints).put(put_breakpoints),
        )
        .route(
            "/api/ws-rewrite",
            get(get_ws_rewrite).put(put_ws_rewrite),
        )
        .route(
            "/api/rewrite",
            get(get_rewrite).put(put_rewrite),
        )
        .route("/api/pauses", get(list_pauses))
        .route("/api/pauses/{pauseId}", get(get_pause))
        .route(
            "/api/pauses/{pauseId}/release",
            post(release_pause).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route("/api/pauses/{pauseId}/drop", post(drop_pause))
        .route("/cert", get(cert_pem))
        .route("/cert.mobileconfig", get(cert_mobileconfig))
        .route("/setup", get(setup_page))
        .fallback(ui)
        .with_state(state)
}

/* ------------------------------------------------------------------ */
/* errors                                                              */
/* ------------------------------------------------------------------ */

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}

fn not_found(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, message)
}

/// The replay engine cannot tell a malformed target apart from an origin that
/// refused us, so both surface as a gateway failure carrying its own message.
fn upstream(error: anyhow::Error) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, error.to_string())
}

/* ------------------------------------------------------------------ */
/* flows                                                               */
/* ------------------------------------------------------------------ */

async fn get_status(State(state): State<ApiState>) -> Response {
    Json(super::status(&state)).into_response()
}

/// The shape `GET /api/flows` answers with. A named struct rather than a
/// `json!` literal so no serialisation of captured data can panic in a macro.
#[derive(serde::Serialize)]
struct FlowPage {
    flows: Vec<FlowSummary>,
    total: usize,
}

async fn list_flows(
    State(state): State<ApiState>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let query = parse_flow_query(raw.as_deref())?;
    let (flows, total) = state.store.query(&query);
    Ok(Json(FlowPage { flows, total }).into_response())
}

async fn clear_flows(State(state): State<ApiState>) -> Response {
    state.store.clear();
    tracing::info!("captured flows cleared");
    Json(json!({ "ok": true })).into_response()
}

async fn get_flow(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    let flow = state
        .store
        .get(&id)
        .ok_or_else(|| not_found("no flow with that id"))?;
    Ok(Json(flow).into_response())
}

/* ------------------------------------------------------------------ */
/* archive                                                             */
/* ------------------------------------------------------------------ */

#[derive(serde::Deserialize)]
struct QueryRequest {
    sql: String,
}

/// Runs one read only statement against the archive.
///
/// Two failures are told apart on purpose. No archive is a 503 with the flag
/// that turns it on, because nothing about the request was wrong. A statement
/// the archive refused is a 400 carrying DuckDB's own message, which names the
/// column or the syntax error, and is the only way anyone debugs a query.
async fn query_archive(
    State(state): State<ApiState>,
    Json(request): Json<QueryRequest>,
) -> Result<Response, ApiError> {
    let archive = archive(&state)?;
    if request.sql.len() > MAX_SQL_LEN {
        return Err(bad_request(format!(
            "that statement is {} characters, and the archive takes at most {MAX_SQL_LEN}",
            request.sql.len()
        )));
    }
    match archive.query(request.sql).await {
        Ok(result) => Ok(Json(result).into_response()),
        Err(err) => Err(archive_error(err)),
    }
}

async fn archive_stats(State(state): State<ApiState>) -> Result<Response, ApiError> {
    let archive = archive(&state)?;
    match archive.stats().await {
        Ok(stats) => Ok(Json(stats).into_response()),
        Err(err) => Err(archive_error(err)),
    }
}

/// Whose fault it was, as a status code. A saturated writer is not a bad
/// request: nothing about it was wrong and the same one may work in a moment,
/// so it says so rather than sending a client off to debug its own SQL.
fn archive_error(error: crate::capture::QueryError) -> ApiError {
    use crate::capture::QueryError;
    let status = match error {
        QueryError::Rejected(_) => StatusCode::BAD_REQUEST,
        QueryError::Busy => StatusCode::SERVICE_UNAVAILABLE,
        QueryError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    ApiError::new(status, error.to_string())
}

fn archive(state: &ApiState) -> Result<&crate::capture::Archive, ApiError> {
    state.store.archive().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "this run keeps no archive, so there is nothing to query. Start Proxima with \
             --archive to record finished flows to disk.",
        )
    })
}

#[derive(Clone, Copy)]
enum Side {
    Request,
    Response,
}

/// Request body for `POST /api/json/view`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonViewRequest {
    text: String,
}

/// Pretty-print and highlight JSON for the inspector. Display only: does not
/// touch capture storage. Empty or non-text input is a 400.
async fn json_view(Json(body): Json<JsonViewRequest>) -> Result<Response, ApiError> {
    let view = crate::json_view::view(&body.text).ok_or_else(|| {
        bad_request("give the endpoint a non-empty JSON (or JSON-looking) string")
    })?;
    Ok(Json(view).into_response())
}

async fn get_body(
    State(state): State<ApiState>,
    Path((id, which)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    // Everything that can be judged from the URL alone is judged first, so a
    // malformed request reads as a 400 whether or not the flow happens to exist.
    let side = match which.as_str() {
        "request" => Side::Request,
        "response" => Side::Response,
        _ => return Err(bad_request("body must be \"request\" or \"response\"")),
    };
    let params = parse_query(raw.as_deref());
    let decode = flag(&params, "decode")?;
    let download = flag(&params, "download")?;
    let pretty = flag(&params, "pretty")?;

    let flow = state
        .store
        .get(&id)
        .ok_or_else(|| not_found("no flow with that id"))?;

    let meta = match side {
        Side::Request => flow.request.body.clone(),
        Side::Response => flow.response.as_ref().and_then(|r| r.body.clone()),
    }
    .ok_or_else(|| not_found("that side of the flow carried no body"))?;

    let stored = state
        .store
        .bodies()
        .read(&meta.id)
        .ok_or_else(|| not_found("the body was dropped to stay inside the memory ceiling"))?;

    let (bytes, still_encoded) = if decode {
        match crate::capture::decode_body(&stored, meta.content_encoding.as_deref()) {
            Ok(plain) => (Bytes::from(plain), None),
            Err(err) => {
                // A body that will not decode is usually a truncated capture.
                // The raw bytes are still the most useful thing to hand back.
                tracing::debug!(flow = %id, error = %err, "could not decode a captured body");
                (stored, meta.content_encoding.clone())
            }
        }
    } else {
        (stored, meta.content_encoding.clone())
    };

    // Soft schema-free view (protobuf/gRPC/hex). Display only; store unchanged.
    if pretty {
        let view = crate::capture::soft_view(&bytes, meta.content_type.as_deref());
        return Ok(Json(view).into_response());
    }

    let mut response = Response::new(Body::from(bytes));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        meta.content_type
            .as_deref()
            .and_then(|value| HeaderValue::from_str(value).ok())
            .unwrap_or_else(|| HeaderValue::from_static("application/octet-stream")),
    );
    // These bytes came off a hostile network and are served from the same
    // origin as the API. Sniffing them into an executable type, or letting a
    // captured HTML body run script against the inspector, is not acceptable.
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if meta.truncated {
        headers.insert("x-proxima-truncated", HeaderValue::from_static("true"));
    }
    if let Some(encoding) = still_encoded {
        // Not Content-Encoding: the client asked for the bytes as captured, and
        // naming the encoding here would make the browser undo it.
        if let Ok(value) = HeaderValue::from_str(&encoding) {
            headers.insert("x-proxima-content-encoding", value);
        }
    }
    if download {
        let name = download_name(&flow, &which);
        if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
            headers.insert(header::CONTENT_DISPOSITION, value);
        }
    }

    Ok(response)
}

/// Load a body by its store id (WebSocket frame `bodyId`, or any other capture
/// body). Used for on-demand frame payload display without inlining large
/// binaries into the flow JSON.
async fn get_body_by_id(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    let params = parse_query(raw.as_deref());
    let download = flag(&params, "download")?;
    let pretty = flag(&params, "pretty")?;

    let stored = state
        .store
        .bodies()
        .read(&id)
        .ok_or_else(|| not_found("no body with that id (evicted or never stored)"))?;

    if pretty {
        let view = crate::capture::soft_view(&stored, None);
        return Ok(Json(view).into_response());
    }

    let mut response = Response::new(Body::from(stored));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if download {
        if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"body-{id}.bin\""))
        {
            headers.insert(header::CONTENT_DISPOSITION, value);
        }
    }
    Ok(response)
}

async fn get_curl(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    let flow = state
        .store
        .get(&id)
        .ok_or_else(|| not_found("no flow with that id"))?;

    let body = flow.request.body.as_ref().and_then(|meta| {
        let stored = state.store.bodies().read(&meta.id)?;
        // A gzipped blob pasted into a shell is useless, so hand cURL the
        // plaintext whenever it can be recovered.
        Some(
            crate::capture::decode_body(&stored, meta.content_encoding.as_deref())
                .unwrap_or_else(|_| stored.to_vec()),
        )
    });

    let curl = crate::replay::to_curl(&flow, body.as_deref());
    Ok(Json(json!({ "curl": curl })).into_response())
}

async fn replay_flow(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    // Checked up front so an unknown id is a 404 rather than a gateway error.
    if state.store.get(&id).is_none() {
        return Err(not_found("no flow with that id"));
    }
    let edits: crate::replay::SendEdits = parse_json_body(&body)?;
    let result = state.replay.from_flow(&id, edits).await.map_err(upstream)?;
    Ok(Json(result).into_response())
}

/// Replays captured WebSocket frames onto a live upgraded flow, or dials a new
/// compose socket with `replay_of`.
///
/// Selects frames from the source flow's history (optional indices and
/// direction filter), skips retention drop markers, resolves payloads from
/// inline text or the body store, and injects them in order through the same
/// path as [`ws_send`]. Injected frames skip rewrite and breakpoint rules and
/// are recorded with `injected: true`.
///
/// `mode: "live"` (default) injects onto an existing upgrade. `mode: "compose"`
/// dials a fresh HTTP/1.1 WebSocket from the source request, creates a new
/// flow, and injects there. Dial failures are 502.
async fn ws_replay(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let source_id = validate_id(&id)?;
    let source = state
        .store
        .get(&source_id)
        .ok_or_else(|| not_found("no flow with that id"))?;

    let request: crate::replay::WsReplayRequest = if body.is_empty() {
        crate::replay::WsReplayRequest::default()
    } else {
        parse_json_body(&body)?
    };

    let mode = request.mode.as_deref().unwrap_or("live");
    let messages = source.ws_messages.clone().unwrap_or_default();

    if mode == "compose" {
        let deps = crate::replay::ComposeDeps {
            store: state.store.clone(),
            registry: state.ws_registry.clone(),
            pauses: state.pauses.clone(),
            ws_rewrite: state.ws_rewrite.clone(),
            upstream: state.replay.upstream().clone(),
        };
        return match crate::replay::replay_compose(&deps, &source, &messages, &request).await {
            Ok(result) => Ok(Json(result).into_response()),
            Err(crate::replay::ComposeError::Plan(crate::replay::PlanError::BadRequest(msg))) => {
                Err(bad_request(msg))
            }
            Err(crate::replay::ComposeError::Plan(crate::replay::PlanError::Conflict(msg))) => {
                Err(ApiError::new(StatusCode::CONFLICT, msg))
            }
            Err(crate::replay::ComposeError::Dial(msg)) => Err(upstream(anyhow::anyhow!(msg))),
        };
    }

    if mode != "live" {
        return Err(bad_request(format!(
            "mode \"{mode}\" is not supported; use \"live\" or \"compose\""
        )));
    }

    let target_id = match &request.target_flow_id {
        Some(raw) if !raw.is_empty() => {
            let tid = validate_id(raw)?;
            if state.store.get(&tid).is_none() {
                return Err(not_found("no flow with that targetFlowId"));
            }
            tid
        }
        _ => source_id.clone(),
    };

    match crate::replay::replay_live(
        state.ws_registry.as_ref(),
        state.store.bodies(),
        &source_id,
        &target_id,
        &messages,
        &request,
    )
    .await
    {
        Ok(result) => Ok(Json(result).into_response()),
        Err(crate::replay::PlanError::BadRequest(msg)) => Err(bad_request(msg)),
        Err(crate::replay::PlanError::Conflict(msg)) => {
            Err(ApiError::new(StatusCode::CONFLICT, msg))
        }
    }
}

/// Injects one WebSocket frame into a live upgraded flow.
///
/// `direction` is relative to the client: `send` goes toward the origin
/// (masked), `recv` goes toward the client (unmasked). The frame is recorded
/// like any other, with `injected: true`.
async fn ws_send(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    if state.store.get(&id).is_none() {
        return Err(not_found("no flow with that id"));
    }
    let request: WsSendRequest = parse_json_body(&body)?;
    let direction = parse_ws_direction(&request.direction)?;
    let opcode = request.opcode;
    if !matches!(opcode, 1 | 2 | 8 | 9 | 10) {
        return Err(bad_request(
            "opcode must be 1 (text), 2 (binary), 8 (close), 9 (ping) or 10 (pong)",
        ));
    }
    let payload = ws_send_payload(&request)?;
    if opcode >= 8 && payload.len() > 125 {
        return Err(bad_request(
            "a control frame payload cannot be longer than 125 bytes",
        ));
    }

    let reply = match state.ws_registry.inject(&id, direction, opcode, payload) {
        Ok(rx) => rx,
        Err(crate::proxy::websocket::InjectError::NotLive)
        | Err(crate::proxy::websocket::InjectError::Closed) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "that flow has no live WebSocket to inject into",
            ));
        }
        Err(crate::proxy::websocket::InjectError::Full) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "the WebSocket inject queue is full; try again when the peer is reading",
            ));
        }
    };

    let message = reply.await.map_err(|_| {
        ApiError::new(
            StatusCode::CONFLICT,
            "the WebSocket closed before the injected frame was written",
        )
    })?;
    Ok(Json(json!({ "message": message })).into_response())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsSendRequest {
    direction: String,
    opcode: u8,
    text: Option<String>,
    data_base64: Option<String>,
    close_code: Option<u16>,
    close_reason: Option<String>,
}

fn parse_ws_direction(input: &str) -> Result<crate::types::WsDirection, ApiError> {
    match input {
        "send" => Ok(crate::types::WsDirection::Send),
        "recv" => Ok(crate::types::WsDirection::Recv),
        _ => Err(bad_request("direction must be \"send\" or \"recv\"")),
    }
}

/// Payload resolution: text UTF-8, else base64, else close (code BE + reason),
/// else empty.
fn ws_send_payload(request: &WsSendRequest) -> Result<Vec<u8>, ApiError> {
    if let Some(text) = &request.text {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(encoded) = &request.data_base64 {
        use base64::Engine as _;
        return base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|err| bad_request(format!("dataBase64 was not valid base64: {err}")));
    }
    if let Some(code) = request.close_code {
        let reason = request.close_reason.as_deref().unwrap_or("");
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        return Ok(payload);
    }
    Ok(Vec::new())
}

async fn send(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let spec: crate::replay::SendSpec = parse_json_body(&body)?;
    let result = state.replay.send(spec).await.map_err(upstream)?;
    Ok(Json(result).into_response())
}

/* ------------------------------------------------------------------ */
/* breakpoints and pauses                                              */
/* ------------------------------------------------------------------ */

async fn get_breakpoints(State(state): State<ApiState>) -> Response {
    Json(state.pauses.rules()).into_response()
}

async fn put_breakpoints(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let rules: crate::types::BreakpointRulesBody = parse_json_body(&body)?;
    state.pauses.set_rules(rules);
    Ok(Json(state.pauses.rules()).into_response())
}

/* ------------------------------------------------------------------ */
/* WebSocket rewrite / drop rules                                      */
/* ------------------------------------------------------------------ */

async fn get_ws_rewrite(State(state): State<ApiState>) -> Response {
    Json(state.ws_rewrite.rules()).into_response()
}

async fn put_ws_rewrite(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let rules: crate::config::WsRewriteRulesBody = parse_json_body(&body)?;
    match state.ws_rewrite.set_rules(rules) {
        Ok(saved) => Ok(Json(saved).into_response()),
        Err(err) => Err(bad_request(err)),
    }
}

/* ------------------------------------------------------------------ */
/* HTTP rewrite / map-host / map-local                                 */
/* ------------------------------------------------------------------ */

async fn get_rewrite(State(state): State<ApiState>) -> Response {
    Json(state.rewrite.rules_body()).into_response()
}

async fn put_rewrite(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let rules: crate::config::RewriteRulesBody = parse_json_body(&body)?;
    state.rewrite.set_rules(rules);
    Ok(Json(state.rewrite.rules_body()).into_response())
}

async fn list_pauses(State(state): State<ApiState>) -> Response {
    Json(json!({ "pauses": state.pauses.list() })).into_response()
}

async fn get_pause(
    State(state): State<ApiState>,
    Path(pause_id): Path<String>,
) -> Result<Response, ApiError> {
    let pause_id = validate_id(&pause_id)?;
    let pause = state
        .pauses
        .get(&pause_id)
        .ok_or_else(|| not_found("no pause with that id"))?;
    Ok(Json(pause).into_response())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleasePauseBody {
    /// When set, overrides the held opcode on release (WS).
    opcode: Option<u8>,
    text: Option<String>,
    data_base64: Option<String>,
    /// HTTP release overrides (ignored for WS pauses).
    method: Option<String>,
    url: Option<String>,
    /// HTTP response-half status override (0 / ignored for request half).
    status: Option<u16>,
    headers: Option<Vec<(String, String)>>,
}

async fn release_pause(
    State(state): State<ApiState>,
    Path(pause_id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let pause_id = validate_id(&pause_id)?;
    // Empty body means forward the original frame/message unchanged.
    let request: ReleasePauseBody = if body.is_empty() {
        ReleasePauseBody {
            opcode: None,
            text: None,
            data_base64: None,
            method: None,
            url: None,
            status: None,
            headers: None,
        }
    } else {
        parse_json_body(&body)?
    };

    let snapshot = state.pauses.get(&pause_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::GONE,
            "that pause is no longer held (already released, dropped, or timed out)",
        )
    })?;

    let decision = if snapshot.kind == crate::types::PauseKind::Http {
        let http = snapshot.http.as_ref().ok_or_else(|| {
            bad_request("HTTP pause is missing its body snapshot")
        })?;
        let (orig_opcode, orig_payload) = state.pauses.original(&pause_id).ok_or_else(|| {
            ApiError::new(
                StatusCode::GONE,
                "that pause is no longer held (already released, dropped, or timed out)",
            )
        })?;
        let _ = orig_opcode;
        let body_bytes = if request.text.is_some() || request.data_base64.is_some() {
            ws_send_payload(&WsSendRequest {
                direction: "send".into(),
                opcode: 1,
                text: request.text,
                data_base64: request.data_base64,
                close_code: None,
                close_reason: None,
            })?
        } else {
            orig_payload
        };
        crate::proxy::breakpoint::PauseDecision::HttpRelease {
            method: request.method.unwrap_or_else(|| http.method.clone()),
            url: request.url.unwrap_or_else(|| http.url.clone()),
            status: request.status.unwrap_or_else(|| http.status.unwrap_or(0)),
            headers: request
                .headers
                .unwrap_or_else(|| http.headers.clone()),
            body: body_bytes,
        }
    } else {
        let (orig_opcode, orig_payload) = state.pauses.original(&pause_id).ok_or_else(|| {
            ApiError::new(
                StatusCode::GONE,
                "that pause is no longer held (already released, dropped, or timed out)",
            )
        })?;
        let opcode = request.opcode.unwrap_or(orig_opcode);
        if !matches!(opcode, 0x0..=0x2 | 0x8..=0xa) {
            return Err(bad_request(
                "opcode must be a data or control frame (0-2 or 8-10)",
            ));
        }
        let payload = if request.text.is_some() || request.data_base64.is_some() {
            ws_send_payload(&WsSendRequest {
                direction: "send".into(),
                opcode,
                text: request.text,
                data_base64: request.data_base64,
                close_code: None,
                close_reason: None,
            })?
        } else {
            orig_payload
        };
        if opcode >= 8 && payload.len() > 125 {
            return Err(bad_request(
                "a control frame payload cannot be longer than 125 bytes",
            ));
        }
        crate::proxy::breakpoint::PauseDecision::Release { opcode, payload }
    };

    match state.pauses.resolve(
        &state.store,
        &pause_id,
        decision,
        crate::types::PauseResolveReason::User,
    ) {
        Ok(snapshot) => Ok(Json(json!({ "pause": snapshot, "action": "release" })).into_response()),
        Err(crate::proxy::breakpoint::ResolveError::NotFound)
        | Err(crate::proxy::breakpoint::ResolveError::AlreadyResolved) => Err(ApiError::new(
            StatusCode::GONE,
            "that pause is no longer held (already released, dropped, or timed out)",
        )),
    }
}

async fn drop_pause(
    State(state): State<ApiState>,
    Path(pause_id): Path<String>,
) -> Result<Response, ApiError> {
    let pause_id = validate_id(&pause_id)?;
    match state.pauses.resolve(
        &state.store,
        &pause_id,
        crate::proxy::breakpoint::PauseDecision::Drop,
        crate::types::PauseResolveReason::User,
    ) {
        Ok(snapshot) => Ok(Json(json!({ "pause": snapshot, "action": "drop" })).into_response()),
        Err(crate::proxy::breakpoint::ResolveError::NotFound)
        | Err(crate::proxy::breakpoint::ResolveError::AlreadyResolved) => Err(ApiError::new(
            StatusCode::GONE,
            "that pause is no longer held (already released, dropped, or timed out)",
        )),
    }
}

async fn get_har(
    State(state): State<ApiState>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let query = parse_flow_query(raw.as_deref())?;
    let flows = state.store.all(&query);
    let count = flows.len();
    let har = crate::capture::flows_to_har(&flows, state.store.bodies());

    let body = serde_json::to_vec(&har).map_err(|err| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not serialise the HAR: {err}"),
        )
    })?;
    tracing::info!(flows = count, "exported a HAR");

    let now = OffsetDateTime::now_utc();
    let name = format!(
        "proxima-{:04}{:02}{:02}-{:02}{:02}{:02}.har",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );

    let mut response = Response::new(Body::from(body));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}

/* ------------------------------------------------------------------ */
/* collections and environments                                        */
/* ------------------------------------------------------------------ */
/*
 * Payloads travel through here as serde_json::Value and are converted at the
 * boundary. That is what lets a POST omit fields the store requires: the
 * defaults are filled in as JSON before anything is deserialised, so creating a
 * collection does not mean sending an empty array you had to know about.
 *
 * The store answers an upsert with the stored value, whose id it may have just
 * generated, so that is what goes back rather than an echo of the request.
 */

async fn list_collections(State(state): State<ApiState>) -> Result<Response, ApiError> {
    Ok(Json(state.replay.collections().collections()).into_response())
}

async fn create_collection(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut value: serde_json::Value = parse_json_body(&body)?;
    // An empty id is the store's signal to mint one.
    fill(&mut value, "id", json!(""))?;
    fill(&mut value, "requests", json!([]))?;
    upsert_collection(&state, value)
}

async fn update_collection(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    let mut value: serde_json::Value = parse_json_body(&body)?;
    force_id(&mut value, &id)?;
    fill(&mut value, "requests", json!([]))?;
    upsert_collection(&state, value)
}

fn upsert_collection(state: &ApiState, value: serde_json::Value) -> Result<Response, ApiError> {
    let collection: crate::replay::Collection = serde_json::from_value(value)
        .map_err(|err| bad_request(format!("that is not a collection: {err}")))?;
    let saved = state
        .replay
        .collections()
        .upsert_collection(collection)
        .map_err(|err| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(Json(saved).into_response())
}

async fn delete_collection(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    let removed = state
        .replay
        .collections()
        .delete_collection(&id)
        .map_err(|err| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    if !removed {
        return Err(not_found("no collection with that id"));
    }
    Ok(Json(json!({ "ok": true })).into_response())
}

async fn list_environments(State(state): State<ApiState>) -> Result<Response, ApiError> {
    Ok(Json(state.replay.collections().environments()).into_response())
}

async fn get_active_environment(State(state): State<ApiState>) -> Response {
    Json(json!({
        "id": state.replay.collections().active_environment_id(),
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActiveEnvironmentBody {
    /// Null or omitted clears the active environment.
    id: Option<String>,
}

async fn put_active_environment(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request: ActiveEnvironmentBody = if body.is_empty() {
        ActiveEnvironmentBody { id: None }
    } else {
        parse_json_body(&body)?
    };
    let id = state
        .replay
        .collections()
        .set_active_environment(request.id)
        .map_err(|err| bad_request(err.to_string()))?;
    Ok(Json(json!({ "id": id })).into_response())
}

async fn create_environment(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut value: serde_json::Value = parse_json_body(&body)?;
    fill(&mut value, "id", json!(""))?;
    fill(&mut value, "variables", json!({}))?;
    upsert_environment(&state, value)
}

async fn update_environment(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    let mut value: serde_json::Value = parse_json_body(&body)?;
    force_id(&mut value, &id)?;
    fill(&mut value, "variables", json!({}))?;
    upsert_environment(&state, value)
}

fn upsert_environment(state: &ApiState, value: serde_json::Value) -> Result<Response, ApiError> {
    let environment: crate::replay::Environment = serde_json::from_value(value)
        .map_err(|err| bad_request(format!("that is not an environment: {err}")))?;
    let saved = state
        .replay
        .collections()
        .upsert_environment(environment)
        .map_err(|err| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(Json(saved).into_response())
}

async fn delete_environment(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = validate_id(&id)?;
    let removed = state
        .replay
        .collections()
        .delete_environment(&id)
        .map_err(|err| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    if !removed {
        return Err(not_found("no environment with that id"));
    }
    Ok(Json(json!({ "ok": true })).into_response())
}

/// The URL owns the identity on a PUT, whatever the body claims.
fn force_id(value: &mut serde_json::Value, id: &str) -> Result<(), ApiError> {
    match value.as_object_mut() {
        Some(object) => {
            object.insert("id".to_string(), json!(id));
            Ok(())
        }
        None => Err(bad_request("the body must be a JSON object")),
    }
}

/// Supplies a field the store requires but a caller should not have to send.
fn fill(
    value: &mut serde_json::Value,
    key: &str,
    default: serde_json::Value,
) -> Result<(), ApiError> {
    match value.as_object_mut() {
        Some(object) => {
            object.entry(key).or_insert(default);
            Ok(())
        }
        None => Err(bad_request("the body must be a JSON object")),
    }
}

/* ------------------------------------------------------------------ */
/* certificates, setup page, inspector                                 */
/* ------------------------------------------------------------------ */

async fn cert_pem(State(state): State<ApiState>) -> Response {
    axum_download(super::cert_download(&state.ca))
}

async fn cert_mobileconfig(State(state): State<ApiState>) -> Response {
    axum_download(super::mobileconfig_download(&state.ca))
}

fn axum_download(download: Download) -> Response {
    let mut response = Response::new(Body::from(download.body));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(download.content_type),
    );
    if let Some(disposition) = download.disposition {
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static(disposition),
        );
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn setup_page(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    Html(setup::render(&state, user_agent)).into_response()
}

async fn ui(uri: Uri) -> Response {
    inspector::serve(uri.path())
}

/* ------------------------------------------------------------------ */
/* live stream                                                         */
/* ------------------------------------------------------------------ */

async fn stream(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| pump(socket, state))
}

type Sender = SplitSink<WebSocket, Message>;

async fn pump(socket: WebSocket, state: ApiState) {
    let mut events = state.store.subscribe();
    let (mut tx, mut rx) = socket.split();

    // The status frame doubles as the handshake: it tells a fresh client what
    // it is connected to, and later repeats mean "your view is stale".
    if send_status(&mut tx, &state).await.is_err() {
        return;
    }

    let mut ping = tokio::time::interval(WS_PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick of an interval completes immediately.
    ping.tick().await;
    let mut awaiting_pong = false;

    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(event) => {
                    let text = match serde_json::to_string(&event) {
                        Ok(text) => text,
                        Err(err) => {
                            tracing::warn!(error = %err, "a proxy event would not serialise");
                            continue;
                        }
                    };
                    if send_frame(&mut tx, Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(missed)) => {
                    // Those events are gone for good. Staying quiet would leave
                    // the client confidently showing a list with holes in it,
                    // so repeat the status frame as a signal to refetch.
                    tracing::warn!(missed, "a stream client fell behind, asking it to resync");
                    if send_status(&mut tx, &state).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Closed) => break,
            },
            incoming = rx.next() => match incoming {
                Some(Ok(Message::Pong(_))) => awaiting_pong = false,
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(err)) => {
                    tracing::debug!(error = %err, "a stream client went away");
                    break;
                }
            },
            _ = ping.tick() => {
                if awaiting_pong {
                    tracing::debug!("a stream client stopped answering pings, dropping it");
                    break;
                }
                awaiting_pong = true;
                if send_frame(&mut tx, Message::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn send_status(tx: &mut Sender, state: &ApiState) -> Result<(), ()> {
    let event = ProxyEvent::Status {
        status: Box::new(super::status(state)),
    };
    match serde_json::to_string(&event) {
        Ok(text) => send_frame(tx, Message::Text(text.into())).await,
        Err(err) => {
            tracing::error!(error = %err, "the status frame would not serialise");
            Err(())
        }
    }
}

/// Sends with a deadline, because a client that has stopped reading would
/// otherwise block this task and hold its broadcast slot open indefinitely.
async fn send_frame(tx: &mut Sender, message: Message) -> Result<(), ()> {
    match tokio::time::timeout(WS_SEND_TIMEOUT, tx.send(message)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "a stream send failed");
            Err(())
        }
        Err(_) => {
            tracing::warn!("a stream client stopped reading, dropping it");
            Err(())
        }
    }
}

/* ------------------------------------------------------------------ */
/* parsing helpers                                                     */
/* ------------------------------------------------------------------ */

fn parse_json_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    let text = if body.is_empty() {
        "{}"
    } else {
        std::str::from_utf8(body).map_err(|_| bad_request("the body was not valid UTF-8"))?
    };
    serde_json::from_str(text).map_err(|err| bad_request(format!("could not read the body: {err}")))
}

fn validate_id(id: &str) -> Result<String, ApiError> {
    // Deliberately loose: the capture store owns the id format, and this only
    // has to keep control characters and path separators out of a lookup key.
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(bad_request("that is not a flow id"));
    }
    if id.chars().any(|c| c.is_control() || c == '/' || c == '\\') {
        return Err(bad_request("that is not a flow id"));
    }
    Ok(id.to_string())
}

fn parse_query(raw: Option<&str>) -> Vec<(String, String)> {
    raw.unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
        .take(MAX_QUERY_PAIRS)
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (decode_form(key), decode_form(value)),
            None => (decode_form(pair), String::new()),
        })
        .collect()
}

fn first<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn all<'a>(params: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    params
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
        .collect()
}

/// `?flag`, `?flag=1` and `?flag=true` all mean yes; anything unrecognised is a
/// mistake worth reporting rather than silently reading as no.
fn flag(params: &[(String, String)], key: &str) -> Result<bool, ApiError> {
    match first(params, key) {
        None => Ok(false),
        Some(value) => match value.trim().to_ascii_lowercase().as_str() {
            "" | "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(bad_request(format!(
                "{key} must be true or false, not \"{other}\""
            ))),
        },
    }
}

fn parse_flow_query(raw: Option<&str>) -> Result<FlowQuery, ApiError> {
    let params = parse_query(raw);
    let mut query = FlowQuery::default();

    if let Some(search) = first(&params, "search") {
        let search = search.trim();
        if search.len() > MAX_SEARCH_LEN {
            return Err(bad_request(format!(
                "search must be at most {MAX_SEARCH_LEN} characters"
            )));
        }
        if !search.is_empty() {
            query.search = Some(search.to_string());
        }
    }

    let hosts = all(&params, "host");
    if hosts.len() > MAX_FILTER_VALUES {
        return Err(bad_request(format!(
            "at most {MAX_FILTER_VALUES} host filters"
        )));
    }
    for host in hosts {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        if host.len() > 255 {
            return Err(bad_request("a host filter must be at most 255 characters"));
        }
        query.hosts.push(host.to_ascii_lowercase());
    }

    let methods = all(&params, "method");
    if methods.len() > MAX_FILTER_VALUES {
        return Err(bad_request(format!(
            "at most {MAX_FILTER_VALUES} method filters"
        )));
    }
    for method in methods {
        let method = method.trim();
        if method.is_empty() {
            continue;
        }
        // RFC 9110 tokens are wider than this, but no real method needs more
        // and the narrow set keeps junk out of the filter.
        if method.len() > 24
            || !method
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(bad_request(format!("\"{method}\" is not an HTTP method")));
        }
        query.methods.push(method.to_ascii_uppercase());
    }

    if let Some(status) = first(&params, "status") {
        let status = status.trim();
        if !status.is_empty() {
            query.status_range = Some(parse_status_range(status)?);
        }
    }

    let kinds = all(&params, "kind");
    if kinds.len() > MAX_FILTER_VALUES {
        return Err(bad_request(format!(
            "at most {MAX_FILTER_VALUES} kind filters"
        )));
    }
    for kind in kinds {
        let kind = kind.trim();
        if kind.is_empty() {
            continue;
        }
        query.kinds.push(parse_kind(kind)?);
    }

    query.only_errors = if params.iter().any(|(name, _)| name == "onlyErrors") {
        flag(&params, "onlyErrors")?
    } else {
        flag(&params, "only_errors")?
    };

    query.only_mocked = if params.iter().any(|(name, _)| name == "onlyMocked") {
        flag(&params, "onlyMocked")?
    } else {
        flag(&params, "only_mocked")?
    };

    if let Some(limit) = first(&params, "limit") {
        let limit = limit.trim();
        if !limit.is_empty() {
            let value: usize = limit
                .parse()
                .map_err(|_| bad_request("limit must be a whole number"))?;
            if value == 0 || value > MAX_LIMIT {
                return Err(bad_request(format!(
                    "limit must be between 1 and {MAX_LIMIT}"
                )));
            }
            query.limit = Some(value);
        }
    }

    if let Some(before) = first(&params, "before") {
        let before = before.trim();
        if !before.is_empty() {
            let value: u64 = before
                .parse()
                .map_err(|_| bad_request("before must be a whole number"))?;
            query.before = Some(value);
        }
    }

    Ok(query)
}

/// Accepts `200`, `200-299` and `2xx`.
fn parse_status_range(input: &str) -> Result<(u16, u16), ApiError> {
    let complaint = || bad_request(format!("\"{input}\" is not a status filter"));

    let (low, high) = if let Some((low, high)) = input.split_once('-') {
        (
            low.trim().parse::<u16>().map_err(|_| complaint())?,
            high.trim().parse::<u16>().map_err(|_| complaint())?,
        )
    } else {
        let lowered = input.to_ascii_lowercase();
        match lowered.strip_suffix("xx") {
            Some(class) => {
                let class: u16 = class.parse().map_err(|_| complaint())?;
                (class * 100, class * 100 + 99)
            }
            None => {
                let exact: u16 = lowered.parse().map_err(|_| complaint())?;
                (exact, exact)
            }
        }
    };

    if !(100..=599).contains(&low) || !(100..=599).contains(&high) || low > high {
        return Err(complaint());
    }
    Ok((low, high))
}

fn parse_kind(input: &str) -> Result<FlowKind, ApiError> {
    match input.to_ascii_lowercase().as_str() {
        "http" => Ok(FlowKind::Http),
        "websocket" | "ws" => Ok(FlowKind::Websocket),
        "tunnel" => Ok(FlowKind::Tunnel),
        other => Err(bad_request(format!(
            "\"{other}\" is not a flow kind, try http, websocket or tunnel"
        ))),
    }
}

/// A filename safe enough to interpolate into Content-Disposition without
/// worrying about quotes or line breaks.
fn download_name(flow: &Flow, which: &str) -> String {
    let path = flow.request.path.split(['?', '#']).next().unwrap_or("");
    let candidate = path.rsplit('/').find(|part| !part.is_empty()).unwrap_or("");
    let cleaned: String = candidate
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(64)
        .collect();

    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        let id: String = flow
            .id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            .take(32)
            .collect();
        format!("proxima-{id}-{which}.bin")
    } else {
        cleaned
    }
}

/// Percent decoding with the form rule that a plus is a space. Only query
/// strings reach this: paths are matched by the router, not decoded here.
fn decode_form(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* -------------------------------------------------------------- */
    /* the router as it is actually served                             */
    /* -------------------------------------------------------------- */

    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::http::Request;
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    const HOSTILE_ORIGIN: &str = "http://evil.example";
    /// A page on this origin used to be handed the whole capture. Kept as a
    /// test subject so the allowance cannot come back by accident.
    const LOCAL_DEV_ORIGIN: &str = "http://localhost:5173";

    fn state(dir: &std::path::Path) -> ApiState {
        let config = Arc::new(crate::Config {
            data_dir: dir.to_path_buf(),
            // Nothing in these tests speaks TLS, and reading the system trust
            // store would only add a way for them to fail for another reason.
            insecure_upstream: true,
            ..crate::Config::default()
        });
        let ca = Arc::new(crate::ca::CertAuthority::open(dir).expect("a certificate authority"));
        let store = Arc::new(crate::capture::FlowStore::new(
            16,
            config.max_body_bytes,
            64 * 1024 * 1024,
        ));
        let replay = Arc::new(
            crate::replay::ReplayEngine::new(config.clone(), store.clone())
                .expect("a replay engine"),
        );
        ApiState {
            config,
            ca,
            store,
            replay,
            proxy_port: 0,
            ui_port: 0,
            ws_registry: Arc::new(crate::proxy::websocket::WsRegistry::new()),
            pauses: Arc::new(crate::proxy::breakpoint::PauseHub::new()),
            ws_rewrite: crate::proxy::ws_rewrite::WsRewriteHub::empty(),
            rewrite: crate::proxy::rewrite::RewriteHub::empty(),
        }
    }

    /// Serves the real router on the loopback interface.
    async fn serve(state: ApiState) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a test inspector");
        let address = listener.local_addr().expect("the local address");
        let router = build(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        address
    }

    /// One request over its own connection, answered with what came back.
    async fn request(
        address: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> (StatusCode, HeaderMap) {
        let (status, headers, _) = request_with_body(address, method, path, headers, body).await;
        (status, headers)
    }

    async fn request_with_body(
        address: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> (StatusCode, HeaderMap, Bytes) {
        let stream = TcpStream::connect(address)
            .await
            .expect("connecting to the test inspector");
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("a handshake with the test inspector");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, address.to_string());
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(Full::new(body))
            .expect("a request the test controls");

        let response = sender
            .send_request(request)
            .await
            .expect("an answer from the test inspector");
        let (parts, body) = response.into_parts();
        let collected = body.collect().await.expect("response body").to_bytes();
        (parts.status, parts.headers, collected)
    }

    fn allow_origin(headers: &HeaderMap) -> Option<&str> {
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok())
    }

    #[tokio::test]
    async fn no_origin_at_all_is_allowed_to_read_the_capture() {
        let dir = tempfile::tempdir().unwrap();
        let address = serve(state(dir.path())).await;

        // A page anywhere else gets an answer it is not allowed to look at.
        // Without the header the browser refuses to hand the body to the script
        // that asked for it, and the capture stays where it was.
        for origin in [HOSTILE_ORIGIN, LOCAL_DEV_ORIGIN] {
            for path in ["/api/flows", "/api/status", "/api/har"] {
                let (status, headers) =
                    request(address, "GET", path, &[("origin", origin)], Bytes::new()).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(
                    allow_origin(&headers),
                    None,
                    "a page on {origin} was allowed to read {path}"
                );
            }
        }

        // A preflight is what a POST of JSON to /api/send has to pass first,
        // and answering one would hand a web page an HTTP client that fetches
        // any URL it likes and reads the reply.
        for origin in [HOSTILE_ORIGIN, LOCAL_DEV_ORIGIN] {
            let (_, headers) = request(
                address,
                "OPTIONS",
                "/api/send",
                &[
                    ("origin", origin),
                    ("access-control-request-method", "POST"),
                    ("access-control-request-headers", "content-type"),
                ],
                Bytes::new(),
            )
            .await;
            assert_eq!(
                allow_origin(&headers),
                None,
                "a page on {origin} was allowed to drive /api/send"
            );
        }
    }

    #[tokio::test]
    async fn the_inspectors_own_page_is_not_caught_by_the_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let address = serve(state(dir.path())).await;

        // A same origin fetch carries no Origin at all, or carries this
        // server's own, and either way the browser does not apply CORS to it.
        let (status, _) = request(address, "GET", "/api/status", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = request(address, "GET", "/api/flows", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_replayable_body_is_not_cut_off_below_the_capture_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let inner = state(dir.path());
        let ceiling = inner.config.max_body_bytes;
        let address = serve(inner).await;

        // Comfortably past the axum default of 2 MB and comfortably under the
        // 10 MB capture ceiling, so a request this size could have been
        // captured and must be replayable.
        let big = Bytes::from(vec![b'x'; 3 * 1024 * 1024]);
        assert!(big.len() as u64 <= ceiling);

        for path in [
            "/api/send",
            "/api/flows/whatever/replay",
            "/api/flows/whatever/ws/send",
            "/api/pauses/whatever/release",
        ] {
            let (status, _) = request(
                address,
                "POST",
                path,
                &[("content-type", "application/json")],
                big.clone(),
            )
            .await;
            assert_ne!(
                status,
                StatusCode::PAYLOAD_TOO_LARGE,
                "{path} refused a body the capture side would have accepted"
            );
        }
    }

    /// The inject route is reachable without a live socket: unknown flow is
    /// 404, known flow that is not upgraded is 409. Those two answers are what
    /// the inspector shows when the form is used against a dead or missing id.
    #[tokio::test]
    async fn ws_send_answers_404_and_409_without_a_live_socket() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let missing = serde_json::json!({
            "direction": "send",
            "opcode": 1,
            "text": "hello",
        });
        let body = Bytes::from(serde_json::to_vec(&missing).expect("json"));
        let (status, _) = request(
            address,
            "POST",
            "/api/flows/does-not-exist/ws/send",
            &[("content-type", "application/json")],
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A real flow that never upgraded has no inject channel.
        let id = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Http,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "https://example.com/".into(),
                scheme: crate::types::Scheme::Https,
                authority: "example.com".into(),
                host: "example.com".into(),
                port: 443,
                path: "/".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 1,
            },
            server: crate::types::FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });
        let path = format!("/api/flows/{id}/ws/send");
        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            body,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let bad = serde_json::json!({
            "direction": "sideways",
            "opcode": 1,
        });
        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&bad).expect("json")),
        )
        .await;
        // Validation runs after the flow is found; a known-but-dead flow still
        // fails on a bad body with 400 rather than 409.
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ws_send_rejects_bad_opcode_control_size_and_base64() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let id = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Websocket,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "http://ws.test/".into(),
                scheme: crate::types::Scheme::Http,
                authority: "ws.test".into(),
                host: "ws.test".into(),
                port: 80,
                path: "/".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 1,
            },
            server: crate::types::FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });
        let path = format!("/api/flows/{id}/ws/send");

        // Opcode 3 is reserved and not injectable.
        let bad_opcode = serde_json::json!({
            "direction": "send",
            "opcode": 3,
            "text": "nope",
        });
        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&bad_opcode).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Control frames are capped at 125 payload bytes.
        let too_big = "x".repeat(126);
        let control = serde_json::json!({
            "direction": "send",
            "opcode": 9,
            "text": too_big,
        });
        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&control).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let bad_b64 = serde_json::json!({
            "direction": "recv",
            "opcode": 2,
            "dataBase64": "!!!not-base64!!!",
        });
        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&bad_b64).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Helper: create a websocket flow with a short frame history.
    fn seed_ws_history(
        store: &crate::capture::FlowStore,
        frames: Vec<crate::types::WsMessage>,
    ) -> String {
        let id = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Websocket,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "http://ws.test/".into(),
                scheme: crate::types::Scheme::Http,
                authority: "ws.test".into(),
                host: "ws.test".into(),
                port: 80,
                path: "/".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 1,
            },
            server: crate::types::FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });
        store.update(&id, |flow| {
            flow.ws_messages = Some(frames);
        });
        id
    }

    fn text_frame(direction: crate::types::WsDirection, text: &str) -> crate::types::WsMessage {
        crate::types::WsMessage {
            at: 1,
            direction,
            opcode: 1,
            size: text.len() as u64,
            truncated: false,
            text: Some(text.into()),
            body_id: None,
            injected: false,
            compressed: false,
        }
    }

    /// Unknown source is 404; known source without a live target is 409.
    #[tokio::test]
    async fn ws_replay_answers_404_and_409_without_a_live_socket() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let body = Bytes::from(serde_json::to_vec(&serde_json::json!({})).expect("json"));
        let (status, _, _) = request_with_body(
            address,
            "POST",
            "/api/flows/does-not-exist/ws/replay",
            &[("content-type", "application/json")],
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let id = seed_ws_history(
            &store,
            vec![text_frame(crate::types::WsDirection::Send, "hello")],
        );
        let path = format!("/api/flows/{id}/ws/replay");
        let (status, _, resp) = request_with_body(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            body,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let err: serde_json::Value = serde_json::from_slice(&resp).expect("json");
        assert!(
            err.get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .contains("live"),
            "expected live conflict, got {err}"
        );
    }

    /// Explicit index to a drop marker is 400; bad mode is 400; out of range is 400.
    #[tokio::test]
    async fn ws_replay_rejects_marker_index_and_bad_mode() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let marker = crate::types::WsMessage {
            at: 0,
            direction: crate::types::WsDirection::Send,
            opcode: crate::capture::WS_DROPPED_OPCODE,
            size: 3,
            truncated: true,
            text: Some("3 earlier messages discarded".into()),
            body_id: None,
            injected: false,
            compressed: false,
        };
        let id = seed_ws_history(
            &store,
            vec![
                marker,
                text_frame(crate::types::WsDirection::Send, "kept"),
            ],
        );
        let path = format!("/api/flows/{id}/ws/replay");

        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({ "indices": [0] })).expect("json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({ "mode": "nope" })).expect("json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Compose refuses targetFlowId (target is always the new dial).
        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "mode": "compose",
                    "targetFlowId": "someone-else"
                }))
                .expect("json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({ "indices": [99] })).expect("json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// A live registry half receives multi-frame replay in order with injected:true.
    #[tokio::test]
    async fn ws_replay_live_injects_selected_frames_in_order() {
        use tokio::sync::mpsc;

        let dir = tempfile::tempdir().expect("a temp dir");
        let mut inner = state(dir.path());
        let store = inner.store.clone();
        let registry = Arc::new(crate::proxy::websocket::WsRegistry::new());
        inner.ws_registry = registry.clone();

        let id = seed_ws_history(
            &store,
            vec![
                text_frame(crate::types::WsDirection::Send, "first"),
                text_frame(crate::types::WsDirection::Recv, "ignored-by-filter"),
                text_frame(crate::types::WsDirection::Send, "second"),
            ],
        );

        let (tx_up, mut rx_up) = mpsc::channel(8);
        let (tx_client, _rx_client) = mpsc::channel(8);
        registry.register(id.clone(), tx_up, tx_client);

        let consumer = tokio::spawn(async move {
            let mut payloads = Vec::new();
            while let Some(cmd) = rx_up.recv().await {
                payloads.push(cmd.payload.clone());
                let _ = cmd.reply.send(crate::types::WsMessage {
                    at: 1,
                    direction: crate::types::WsDirection::Send,
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

        let address = serve(inner).await;
        let path = format!("/api/flows/{id}/ws/replay");
        let body = serde_json::json!({
            "directions": ["send"],
            "indices": [0, 2],
        });
        let (status, _, resp) = request_with_body(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&body).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let result: serde_json::Value = serde_json::from_slice(&resp).expect("json");
        assert_eq!(result.get("planned").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(result.get("sent").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(result.get("mode").and_then(|v| v.as_str()), Some("live"));
        let messages = result
            .get("messages")
            .and_then(|v| v.as_array())
            .expect("messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].get("injected"), Some(&serde_json::json!(true)));
        assert_eq!(messages[0].get("text").and_then(|v| v.as_str()), Some("first"));
        assert_eq!(messages[1].get("text").and_then(|v| v.as_str()), Some("second"));

        registry.unregister(&id);
        let payloads = consumer.await.expect("consumer");
        assert_eq!(payloads, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    /// Cross-flow target: source history injects onto another live id.
    #[tokio::test]
    async fn ws_replay_target_flow_id_uses_other_live_socket() {
        use tokio::sync::mpsc;

        let dir = tempfile::tempdir().expect("a temp dir");
        let mut inner = state(dir.path());
        let store = inner.store.clone();
        let registry = Arc::new(crate::proxy::websocket::WsRegistry::new());
        inner.ws_registry = registry.clone();

        let source_id = seed_ws_history(
            &store,
            vec![text_frame(crate::types::WsDirection::Send, "from-source")],
        );
        let target_id = seed_ws_history(&store, vec![]);

        let (tx_up, mut rx_up) = mpsc::channel(4);
        let (tx_client, _rx_client) = mpsc::channel(4);
        registry.register(target_id.clone(), tx_up, tx_client);

        let consumer = tokio::spawn(async move {
            let cmd = rx_up.recv().await.expect("one inject");
            let payload = cmd.payload.clone();
            let _ = cmd.reply.send(crate::types::WsMessage {
                at: 1,
                direction: crate::types::WsDirection::Send,
                opcode: 1,
                size: payload.len() as u64,
                truncated: false,
                text: Some(String::from_utf8_lossy(&payload).into_owned()),
                body_id: None,
                injected: true,
                compressed: false,
            });
            payload
        });

        let address = serve(inner).await;
        let path = format!("/api/flows/{source_id}/ws/replay");
        let body = serde_json::json!({ "targetFlowId": target_id });
        let (status, _, resp) = request_with_body(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&body).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let result: serde_json::Value = serde_json::from_slice(&resp).expect("json");
        assert_eq!(
            result.get("targetFlowId").and_then(|v| v.as_str()),
            Some(target_id.as_str())
        );
        assert_eq!(result.get("sent").and_then(|v| v.as_u64()), Some(1));

        registry.unregister(&target_id);
        let payload = consumer.await.expect("consumer");
        assert_eq!(payload, b"from-source");
    }

    /// Missing body store bytes fail closed as 409 before any inject is attempted.
    #[tokio::test]
    async fn ws_replay_missing_body_is_conflict() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let id = seed_ws_history(
            &store,
            vec![crate::types::WsMessage {
                at: 1,
                direction: crate::types::WsDirection::Send,
                opcode: 2,
                size: 4,
                truncated: false,
                text: None,
                body_id: Some("evicted-or-never-stored".into()),
                injected: false,
                compressed: false,
            }],
        );
        let path = format!("/api/flows/{id}/ws/replay");
        let (status, _, resp) = request_with_body(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&serde_json::json!({})).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let err: serde_json::Value = serde_json::from_slice(&resp).expect("json");
        let msg = err
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("");
        assert!(
            msg.contains("missing") || msg.contains("body"),
            "expected missing-body conflict, got {err}"
        );
    }

    /// Unknown targetFlowId is 404; source history is not rewritten.
    #[tokio::test]
    async fn ws_replay_unknown_target_flow_id_is_not_found() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let source_id = seed_ws_history(
            &store,
            vec![text_frame(crate::types::WsDirection::Send, "kept")],
        );
        let path = format!("/api/flows/{source_id}/ws/replay");
        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "targetFlowId": "no-such-target"
                }))
                .expect("json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Source history must stay untouched when the target is missing.
        let source = store.get(&source_id).expect("source still present");
        let msgs = source.ws_messages.expect("history");
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].injected);
        assert_eq!(msgs[0].text.as_deref(), Some("kept"));
    }

    /// Empty body uses defaults (auto-select skips non-injectable); explicit
    /// index to a continuation is 400.
    #[tokio::test]
    async fn ws_replay_empty_body_defaults_and_bad_opcode_is_400() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let id = seed_ws_history(
            &store,
            vec![crate::types::WsMessage {
                at: 1,
                direction: crate::types::WsDirection::Send,
                opcode: 0, // continuation: auto-select skips; explicit index fails closed
                size: 0,
                truncated: false,
                text: None,
                body_id: None,
                injected: false,
                compressed: false,
            }],
        );
        let path = format!("/api/flows/{id}/ws/replay");

        // Empty body is valid; auto-select plans nothing (continuation skipped).
        let (status, _, resp) =
            request_with_body(address, "POST", &path, &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let result: serde_json::Value = serde_json::from_slice(&resp).expect("json");
        assert_eq!(result.get("planned").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(result.get("sent").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(result.get("skipped").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(result.get("mode").and_then(|v| v.as_str()), Some("live"));

        let (status, _) = request(
            address,
            "POST",
            &path,
            &[("content-type", "application/json")],
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({ "indices": [0] })).expect("json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Rules and held pauses are reachable without a live peer: empty list,
    /// replace, and resolve of a missing id. The inspector depends on these.
    #[tokio::test]
    async fn breakpoints_round_trip_and_missing_pause_is_gone() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let address = serve(state(dir.path())).await;

        let (status, _, body) =
            request_with_body(address, "GET", "/api/breakpoints", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let got: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(got.get("rules").and_then(|v| v.as_array()).map(|a| a.len()), Some(0));

        let rules = serde_json::json!({
            "rules": [{
                "id": "ws-1",
                "enabled": true,
                "kind": "ws",
                "hosts": ["example.com"],
                "pathPrefix": "/chat",
                "directions": ["send"],
                "opcodes": [],
                "timeoutMs": 15000
            }]
        });
        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/breakpoints",
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&rules).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let saved: crate::types::BreakpointRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert_eq!(saved.rules.len(), 1);
        assert_eq!(saved.rules[0].id, "ws-1");
        assert!(saved.rules[0].enabled);
        assert_eq!(saved.rules[0].hosts, vec!["example.com"]);
        assert_eq!(saved.rules[0].path_prefix.as_deref(), Some("/chat"));
        assert_eq!(saved.rules[0].timeout_ms, 15_000);

        let (status, _, body) =
            request_with_body(address, "GET", "/api/pauses", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let pauses: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            pauses.get("pauses").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(0)
        );

        // Nothing held: resolve and get must not invent a pause.
        let (status, _) = request(
            address,
            "GET",
            "/api/pauses/does-not-exist",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = request(
            address,
            "POST",
            "/api/pauses/does-not-exist/drop",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::GONE);

        let (status, _) = request(
            address,
            "POST",
            "/api/pauses/does-not-exist/release",
            &[("content-type", "application/json")],
            Bytes::from_static(b"{}"),
        )
        .await;
        assert_eq!(status, StatusCode::GONE);

        // Clearing rules is a PUT of an empty list, same shape the UI uses.
        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/breakpoints",
            &[("content-type", "application/json")],
            Bytes::from_static(br#"{"rules":[]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let cleared: crate::types::BreakpointRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert!(cleared.rules.is_empty());
    }

    /// HTTP rewrite / map-local rules round-trip through GET|PUT, including the
    /// `mock` field the inspector and clients use to seed map-local answers.
    #[tokio::test]
    async fn rewrite_round_trip_preserves_mock_field() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let address = serve(state(dir.path())).await;

        let (status, _, body) =
            request_with_body(address, "GET", "/api/rewrite", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let empty: crate::config::RewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert!(empty.rules.is_empty());

        let rules = serde_json::json!({
            "rules": [{
                "hosts": ["api.example.com"],
                "pathPrefix": "/v1/",
                "methods": ["GET"],
                "mock": {
                    "status": 418,
                    "headers": [["x-map-local", "yes"]],
                    "body": "from map local",
                    "bodyFile": "/tmp/fixture.bin"
                }
            }]
        });
        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/rewrite",
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&rules).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let saved: crate::config::RewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert_eq!(saved.rules.len(), 1);
        assert_eq!(saved.rules[0].hosts, vec!["api.example.com"]);
        assert_eq!(saved.rules[0].path_prefix.as_deref(), Some("/v1/"));
        assert_eq!(saved.rules[0].methods, vec!["GET"]);
        let mock = saved.rules[0]
            .mock
            .as_ref()
            .expect("mock field must survive PUT");
        assert_eq!(mock.status, 418);
        assert_eq!(mock.body.as_deref(), Some("from map local"));
        assert_eq!(mock.body_file.as_deref(), Some("/tmp/fixture.bin"));
        assert_eq!(
            mock.headers,
            vec![("x-map-local".into(), "yes".into())]
        );

        let (status, _, body) =
            request_with_body(address, "GET", "/api/rewrite", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let again: crate::config::RewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert_eq!(again.rules.len(), 1);
        let mock = again.rules[0]
            .mock
            .as_ref()
            .expect("GET must return the same mock");
        assert_eq!(mock.status, 418);
        assert_eq!(mock.body.as_deref(), Some("from map local"));
        assert_eq!(mock.body_file.as_deref(), Some("/tmp/fixture.bin"));

        // Wire shape: camelCase field names the UI and curl both use.
        let wire: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert!(
            wire["rules"][0]["mock"]["bodyFile"].is_string(),
            "mock bodyFile must serialize as camelCase: {wire}"
        );

        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/rewrite",
            &[("content-type", "application/json")],
            Bytes::from_static(br#"{"rules":[]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let cleared: crate::config::RewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert!(cleared.rules.is_empty());
    }

    /// Path, query, and body rewrite fields round-trip through GET|PUT without
    /// stripping. Wire shape is camelCase (`pathReplacements`, `requestBody`).
    #[tokio::test]
    async fn rewrite_round_trip_preserves_path_and_body_fields() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let address = serve(state(dir.path())).await;

        let rules = serde_json::json!({
            "rules": [{
                "hosts": ["api.example.com"],
                "pathPrefix": "/v1/",
                "pathReplacements": [
                    {"find": "/v1/", "replace": "/v2/"},
                    {"find": "old", "replace": "new"}
                ],
                "queryReplacements": [
                    {"find": "draft", "replace": "live"}
                ],
                "requestBody": {
                    "replacements": [
                        {"find": "secret", "replace": "redacted"}
                    ],
                    "maxBytes": 2048
                },
                "responseBody": {
                    "replacements": [
                        {"find": "error", "replace": "ok"}
                    ]
                }
            }]
        });
        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/rewrite",
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&rules).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let saved: crate::config::RewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert_eq!(saved.rules.len(), 1);
        let rule = &saved.rules[0];
        assert_eq!(rule.hosts, vec!["api.example.com"]);
        assert_eq!(rule.path_prefix.as_deref(), Some("/v1/"));
        assert_eq!(rule.path_replacements.len(), 2);
        assert_eq!(rule.path_replacements[0].find, "/v1/");
        assert_eq!(rule.path_replacements[0].replace, "/v2/");
        assert_eq!(rule.path_replacements[1].find, "old");
        assert_eq!(rule.query_replacements.len(), 1);
        assert_eq!(rule.query_replacements[0].find, "draft");
        let req_body = rule
            .request_body
            .as_ref()
            .expect("requestBody must survive PUT");
        assert_eq!(req_body.max_bytes, 2048);
        assert_eq!(req_body.replacements.len(), 1);
        assert_eq!(req_body.replacements[0].find, "secret");
        assert_eq!(req_body.replacements[0].replace, "redacted");
        let resp_body = rule
            .response_body
            .as_ref()
            .expect("responseBody must survive PUT");
        assert_eq!(resp_body.replacements[0].find, "error");
        // Omitted maxBytes deserializes as 0 (engine default).
        assert_eq!(resp_body.max_bytes, 0);

        let (status, _, body) =
            request_with_body(address, "GET", "/api/rewrite", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let again: crate::config::RewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert_eq!(again.rules.len(), 1);
        assert_eq!(again.rules[0].path_replacements.len(), 2);
        assert_eq!(
            again.rules[0]
                .request_body
                .as_ref()
                .map(|b| b.max_bytes),
            Some(2048)
        );

        // Wire shape: camelCase field names curl and the UI both use.
        let wire: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert!(
            wire["rules"][0]["pathReplacements"].is_array(),
            "pathReplacements must serialize as camelCase: {wire}"
        );
        assert!(
            wire["rules"][0]["queryReplacements"].is_array(),
            "queryReplacements must serialize as camelCase: {wire}"
        );
        assert_eq!(wire["rules"][0]["requestBody"]["maxBytes"], 2048);
        assert!(
            wire["rules"][0]["requestBody"]["replacements"][0]["find"].is_string(),
            "{wire}"
        );
        assert!(
            wire["rules"][0]["responseBody"]["replacements"].is_array(),
            "{wire}"
        );
        // Empty lists are omitted on serialize so clients do not see noise.
        let empty_rule = serde_json::json!({ "rules": [{ "hosts": ["x"] }] });
        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/rewrite",
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&empty_rule).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let wire: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert!(
            wire["rules"][0].get("pathReplacements").is_none(),
            "empty pathReplacements should be skipped: {wire}"
        );
        assert!(
            wire["rules"][0].get("requestBody").is_none(),
            "absent requestBody should stay absent: {wire}"
        );
    }

    /// WS rewrite rules round-trip through GET|PUT; invalid regex is a 400 and
    /// leaves the previous list alone.
    #[tokio::test]
    async fn ws_rewrite_round_trip_and_invalid_regex_is_rejected() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let address = serve(state(dir.path())).await;

        let (status, _, body) =
            request_with_body(address, "GET", "/api/ws-rewrite", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let got: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            got.get("rules").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(0)
        );

        let rules = serde_json::json!({
            "rules": [{
                "hosts": ["chat.example.com"],
                "pathPrefix": "/ws",
                "directions": ["send"],
                "opcodes": [],
                "textRegex": "secret",
                "drop": true
            }]
        });
        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/ws-rewrite",
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&rules).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let saved: crate::config::WsRewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert_eq!(saved.rules.len(), 1);
        assert_eq!(saved.rules[0].hosts, vec!["chat.example.com"]);
        assert_eq!(saved.rules[0].path_prefix.as_deref(), Some("/ws"));
        assert!(saved.rules[0].drop);
        assert_eq!(saved.rules[0].text_regex.as_deref(), Some("secret"));

        let (status, _, body) =
            request_with_body(address, "GET", "/api/ws-rewrite", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let again: crate::config::WsRewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert_eq!(again.rules.len(), 1);

        let bad = serde_json::json!({
            "rules": [{
                "textRegex": "(",
                "drop": true
            }]
        });
        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/ws-rewrite",
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&bad).expect("json")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let err: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let message = err.get("error").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            message.contains("text_regex") || message.contains("regex"),
            "bad regex must name the field: {message}"
        );

        // Previous good rules must still be in force after a rejected PUT.
        let (status, _, body) =
            request_with_body(address, "GET", "/api/ws-rewrite", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let kept: crate::config::WsRewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert_eq!(kept.rules.len(), 1);
        assert!(kept.rules[0].drop);

        let (status, _, body) = request_with_body(
            address,
            "PUT",
            "/api/ws-rewrite",
            &[("content-type", "application/json")],
            Bytes::from_static(br#"{"rules":[]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let cleared: crate::config::WsRewriteRulesBody =
            serde_json::from_slice(&body).expect("rules body");
        assert!(cleared.rules.is_empty());
    }

    #[tokio::test]
    async fn release_and_drop_resolve_a_held_pause_once() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let pauses = inner.pauses.clone();
        let address = serve(inner).await;

        let held = pauses
            .hold_ws(
                &store,
                "flow-1".into(),
                crate::types::WsDirection::Send,
                1,
                5,
                false,
                b"hello",
                30_000,
            )
            .expect("under the concurrent pause cap");
        let pause_id = held.0;

        let (status, _, body) = request_with_body(
            address,
            "GET",
            &format!("/api/pauses/{pause_id}"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let snapshot: crate::types::PauseSnapshot =
            serde_json::from_slice(&body).expect("pause snapshot");
        assert_eq!(snapshot.pause_id, pause_id);
        assert_eq!(snapshot.flow_id, "flow-1");
        assert_eq!(snapshot.kind, crate::types::PauseKind::Ws);
        let ws = snapshot.ws.expect("ws body");
        assert_eq!(ws.opcode, 1);
        assert_eq!(ws.text.as_deref(), Some("hello"));

        // Edited release: opcode stays text, payload becomes the new text.
        let (status, _, body) = request_with_body(
            address,
            "POST",
            &format!("/api/pauses/{pause_id}/release"),
            &[("content-type", "application/json")],
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({ "text": "edited" })).expect("json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resolved: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(resolved.get("action").and_then(|v| v.as_str()), Some("release"));

        // Second resolve is gone, not a second write.
        let (status, _) = request(
            address,
            "POST",
            &format!("/api/pauses/{pause_id}/release"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::GONE);

        // A fresh hold can be dropped instead.
        let held = pauses
            .hold_ws(
                &store,
                "flow-2".into(),
                crate::types::WsDirection::Recv,
                2,
                2,
                false,
                &[0xde, 0xad],
                30_000,
            )
            .expect("under the concurrent pause cap");
        let pause_id = held.0;
        let (status, _, body) = request_with_body(
            address,
            "POST",
            &format!("/api/pauses/{pause_id}/drop"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let dropped: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(dropped.get("action").and_then(|v| v.as_str()), Some("drop"));
        assert_eq!(pauses.pending_count(), 0);
    }

    #[tokio::test]
    async fn empty_release_body_forwards_the_original_frame() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let pauses = inner.pauses.clone();
        let address = serve(inner).await;

        let (pause_id, mut rx) = pauses
            .hold_ws(
                &store,
                "flow-orig".into(),
                crate::types::WsDirection::Send,
                1,
                8,
                false,
                b"original",
                30_000,
            )
            .expect("held");

        // Omit body entirely: API must release the stored opcode/payload.
        let (status, _, body) = request_with_body(
            address,
            "POST",
            &format!("/api/pauses/{pause_id}/release"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resolved: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(resolved.get("action").and_then(|v| v.as_str()), Some("release"));

        let (decision, reason) = rx.try_recv().expect("decision delivered");
        match decision {
            crate::proxy::breakpoint::PauseDecision::Release { opcode, payload } => {
                assert_eq!(opcode, 1);
                assert_eq!(payload, b"original");
            }
            crate::proxy::breakpoint::PauseDecision::Drop => {
                panic!("empty release body must not drop")
            }
            crate::proxy::breakpoint::PauseDecision::HttpRelease { .. } => {
                panic!("WS release must not yield HTTP")
            }
        }
        assert_eq!(reason, crate::types::PauseResolveReason::User);
        assert_eq!(pauses.pending_count(), 0);
    }

    #[tokio::test]
    async fn http_response_release_can_override_status() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let pauses = inner.pauses.clone();
        let address = serve(inner).await;

        let (pause_id, mut rx) = pauses
            .hold_http_response(
                &store,
                "flow-resp".into(),
                "GET".into(),
                "https://example.com/api".into(),
                200,
                vec![("content-type".into(), "text/plain".into())],
                b"ok",
                false,
                30_000,
            )
            .expect("held");

        // Override status only; body and headers stay as held.
        let (status, _, body) = request_with_body(
            address,
            "POST",
            &format!("/api/pauses/{pause_id}/release"),
            &[("content-type", "application/json")],
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({ "status": 503 })).expect("json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resolved: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            resolved.get("action").and_then(|v| v.as_str()),
            Some("release")
        );

        let (decision, reason) = rx.try_recv().expect("decision delivered");
        match decision {
            crate::proxy::breakpoint::PauseDecision::HttpRelease {
                method,
                url,
                status: code,
                headers,
                body: payload,
            } => {
                assert_eq!(method, "GET");
                assert_eq!(url, "https://example.com/api");
                assert_eq!(code, 503);
                assert_eq!(
                    headers,
                    vec![("content-type".into(), "text/plain".into())]
                );
                assert_eq!(payload, b"ok");
            }
            other => panic!("expected HttpRelease, got {other:?}"),
        }
        assert_eq!(reason, crate::types::PauseResolveReason::User);
        assert_eq!(pauses.pending_count(), 0);
    }

    #[tokio::test]
    async fn http_response_empty_release_keeps_original_status() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let pauses = inner.pauses.clone();
        let address = serve(inner).await;

        let (pause_id, mut rx) = pauses
            .hold_http_response(
                &store,
                "flow-resp-empty".into(),
                "GET".into(),
                "https://example.com/".into(),
                404,
                vec![],
                b"missing",
                false,
                30_000,
            )
            .expect("held");

        let (status, _, body) = request_with_body(
            address,
            "POST",
            &format!("/api/pauses/{pause_id}/release"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resolved: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            resolved.get("action").and_then(|v| v.as_str()),
            Some("release")
        );

        let (decision, reason) = rx.try_recv().expect("decision delivered");
        match decision {
            crate::proxy::breakpoint::PauseDecision::HttpRelease {
                status: code,
                body: payload,
                ..
            } => {
                assert_eq!(code, 404);
                assert_eq!(payload, b"missing");
            }
            other => panic!("expected HttpRelease, got {other:?}"),
        }
        assert_eq!(reason, crate::types::PauseResolveReason::User);
        assert_eq!(pauses.pending_count(), 0);
    }

    #[test]
    fn parse_ws_direction_accepts_send_and_recv_only() {
        assert!(matches!(
            parse_ws_direction("send"),
            Ok(crate::types::WsDirection::Send)
        ));
        assert!(matches!(
            parse_ws_direction("recv"),
            Ok(crate::types::WsDirection::Recv)
        ));
        assert!(parse_ws_direction("sideways").is_err());
        assert!(parse_ws_direction("").is_err());
        assert!(parse_ws_direction("Send").is_err());
    }

    /// P11: README curl examples use camelCase bodies. Deserialise the same
    /// shapes so docs cannot drift from `WsSendRequest` field names.
    #[test]
    fn ws_send_request_deserializes_readme_camel_case() {
        let text: WsSendRequest = serde_json::from_str(
            r#"{"direction":"send","opcode":1,"text":"hello"}"#,
        )
        .expect("text body");
        assert_eq!(text.direction, "send");
        assert_eq!(text.opcode, 1);
        assert_eq!(text.text.as_deref(), Some("hello"));
        assert_eq!(ws_send_payload(&text).expect("payload"), b"hello");

        let binary: WsSendRequest = serde_json::from_str(
            r#"{"direction":"recv","opcode":2,"dataBase64":"AQID"}"#,
        )
        .expect("binary body");
        assert_eq!(binary.direction, "recv");
        assert_eq!(binary.opcode, 2);
        assert_eq!(
            ws_send_payload(&binary).expect("payload"),
            &[0x01, 0x02, 0x03]
        );

        let close: WsSendRequest = serde_json::from_str(
            r#"{"direction":"send","opcode":8,"closeCode":1000,"closeReason":"bye"}"#,
        )
        .expect("close body");
        assert_eq!(close.close_code, Some(1000));
        assert_eq!(close.close_reason.as_deref(), Some("bye"));
        let payload = ws_send_payload(&close).expect("payload");
        assert_eq!(&payload[..2], &1000u16.to_be_bytes());
        assert_eq!(&payload[2..], b"bye");

        // Snake_case field names are not accepted (docs and UI use camelCase).
        let snake = r#"{"direction":"send","opcode":2,"data_base64":"AQID"}"#;
        let parsed: WsSendRequest =
            serde_json::from_str(snake).expect("unknown snake keys are ignored without deny");
        assert!(
            parsed.data_base64.is_none(),
            "data_base64 must not bind; only dataBase64 is the public field"
        );
    }

    #[test]
    fn ws_send_payload_prefers_text_then_base64_then_close() {
        // text wins over everything else when present.
        let with_text = WsSendRequest {
            direction: "send".into(),
            opcode: 1,
            text: Some("hello".into()),
            data_base64: Some("AA==".into()),
            close_code: Some(1000),
            close_reason: Some("x".into()),
        };
        assert_eq!(ws_send_payload(&with_text).expect("ok"), b"hello");

        // base64 when no text.
        let with_b64 = WsSendRequest {
            direction: "send".into(),
            opcode: 2,
            text: None,
            data_base64: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0xde, 0xad],
            )),
            close_code: None,
            close_reason: None,
        };
        assert_eq!(ws_send_payload(&with_b64).expect("ok"), &[0xde, 0xad]);

        // close code + reason when neither text nor base64.
        let with_close = WsSendRequest {
            direction: "send".into(),
            opcode: 8,
            text: None,
            data_base64: None,
            close_code: Some(1001),
            close_reason: Some("going away".into()),
        };
        let payload = ws_send_payload(&with_close).expect("ok");
        assert_eq!(&payload[..2], &1001u16.to_be_bytes());
        assert_eq!(&payload[2..], b"going away");

        // close with code only is two bytes.
        let code_only = WsSendRequest {
            direction: "send".into(),
            opcode: 8,
            text: None,
            data_base64: None,
            close_code: Some(1000),
            close_reason: None,
        };
        assert_eq!(
            ws_send_payload(&code_only).expect("ok"),
            1000u16.to_be_bytes().to_vec()
        );

        // empty payload is allowed (ping with no body).
        let empty = WsSendRequest {
            direction: "send".into(),
            opcode: 9,
            text: None,
            data_base64: None,
            close_code: None,
            close_reason: None,
        };
        assert!(ws_send_payload(&empty).expect("ok").is_empty());

        // invalid base64 is a 400-shaped error.
        let bad = WsSendRequest {
            direction: "send".into(),
            opcode: 2,
            text: None,
            data_base64: Some("not%%valid".into()),
            close_code: None,
            close_reason: None,
        };
        let err = ws_send_payload(&bad).expect_err("bad base64");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn injected_false_is_omitted_from_ws_message_json() {
        // Ordinary capture stays quiet: only injected frames carry the flag.
        let plain = crate::types::WsMessage {
            at: 1,
            direction: crate::types::WsDirection::Send,
            opcode: 1,
            size: 1,
            truncated: false,
            text: Some("a".into()),
            body_id: None,
            injected: false,
            compressed: false,
        };
        let json = serde_json::to_value(&plain).expect("serialize");
        assert!(json.get("injected").is_none());
        assert!(json.get("compressed").is_none());

        let injected = crate::types::WsMessage {
            injected: true,
            ..plain.clone()
        };
        let json = serde_json::to_value(&injected).expect("serialize");
        assert_eq!(json.get("injected"), Some(&serde_json::json!(true)));
        assert!(json.get("compressed").is_none());

        // Inflated display for permessage-deflate; size remains wire length.
        let compressed = crate::types::WsMessage {
            compressed: true,
            size: 12,
            text: Some("hello inflated".into()),
            ..plain
        };
        let json = serde_json::to_value(&compressed).expect("serialize");
        assert_eq!(json.get("compressed"), Some(&serde_json::json!(true)));
        assert_eq!(json.get("size"), Some(&serde_json::json!(12)));
        assert_eq!(
            json.get("text"),
            Some(&serde_json::json!("hello inflated"))
        );
    }

    #[test]
    fn percent_and_plus_decoding() {
        assert_eq!(decode_form("a+b"), "a b");
        assert_eq!(decode_form("a%20b"), "a b");
        assert_eq!(decode_form("%D0%BF%D1%80"), "пр");
        assert_eq!(decode_form("%2e%2e"), "..");
        // A stray percent is data, not an error.
        assert_eq!(decode_form("100%"), "100%");
        assert_eq!(decode_form("%zz"), "%zz");
    }

    #[test]
    fn repeated_parameters_are_kept() {
        let params = parse_query(Some("host=a.com&host=b.com&method=GET"));
        assert_eq!(all(&params, "host"), vec!["a.com", "b.com"]);
        assert_eq!(first(&params, "method"), Some("GET"));
        assert_eq!(first(&params, "missing"), None);
    }

    #[test]
    fn valueless_parameters_read_as_true() {
        let params = parse_query(Some("download&decode=0&other=maybe"));
        assert!(flag(&params, "download").unwrap());
        assert!(!flag(&params, "decode").unwrap());
        assert!(!flag(&params, "absent").unwrap());
        assert!(flag(&params, "other").is_err());
    }

    #[test]
    fn status_filters() {
        assert_eq!(parse_status_range("200-299").unwrap(), (200, 299));
        assert_eq!(parse_status_range("404").unwrap(), (404, 404));
        assert_eq!(parse_status_range("5xx").unwrap(), (500, 599));
        assert_eq!(parse_status_range("2XX").unwrap(), (200, 299));

        for bad in ["", "abc", "299-200", "99", "600", "200-", "-299", "9xx"] {
            assert!(parse_status_range(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn query_parsing_end_to_end() {
        let query = parse_flow_query(Some(
            "search=token&host=API.Example.com&host=b.com&method=get&status=2xx&kind=ws&onlyErrors=1&onlyMocked=1&limit=50&before=900",
        ))
        .unwrap();

        assert_eq!(query.search.as_deref(), Some("token"));
        assert_eq!(query.hosts, vec!["api.example.com", "b.com"]);
        assert_eq!(query.methods, vec!["GET"]);
        assert_eq!(query.status_range, Some((200, 299)));
        assert_eq!(query.kinds.len(), 1);
        assert!(query.only_errors);
        assert!(query.only_mocked);
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.before, Some(900));

        let snake = parse_flow_query(Some("only_mocked=true")).unwrap();
        assert!(snake.only_mocked);
        let off = parse_flow_query(Some("onlyMocked=0")).unwrap();
        assert!(!off.only_mocked);
    }

    #[test]
    fn an_empty_query_is_the_default() {
        let query = parse_flow_query(None).unwrap();
        assert!(query.search.is_none());
        assert!(query.hosts.is_empty());
        assert!(query.limit.is_none());
        assert!(!query.only_errors);
        assert!(!query.only_mocked);
    }

    #[test]
    fn query_parsing_accepts_snake_case_only_errors_and_multi_filters() {
        // UI/REST use camelCase; snake_case is the documented alternate.
        let query = parse_flow_query(Some(
            "method=get&method=post&kind=http&kind=ws&only_errors=true&status=5xx",
        ))
        .unwrap();
        assert_eq!(query.methods, vec!["GET", "POST"]);
        assert_eq!(
            query.kinds,
            vec![
                crate::types::FlowKind::Http,
                crate::types::FlowKind::Websocket
            ]
        );
        assert!(query.only_errors);
        assert_eq!(query.status_range, Some((500, 599)));

        let off = parse_flow_query(Some("onlyErrors=0")).unwrap();
        assert!(!off.only_errors);

        let bare = parse_flow_query(Some("onlyErrors")).unwrap();
        assert!(bare.only_errors, "valueless onlyErrors is true");
    }

    #[test]
    fn hostile_query_values_are_rejected_not_clamped() {
        assert!(parse_flow_query(Some("limit=0")).is_err());
        assert!(parse_flow_query(Some("limit=99999999")).is_err());
        assert!(parse_flow_query(Some("limit=-1")).is_err());
        assert!(parse_flow_query(Some("limit=nine")).is_err());
        assert!(parse_flow_query(Some("before=tomorrow")).is_err());
        assert!(parse_flow_query(Some("kind=carrier-pigeon")).is_err());
        assert!(parse_flow_query(Some("method=GET%20/etc/passwd")).is_err());
        assert!(parse_flow_query(Some("onlyErrors=maybe")).is_err());
        assert!(parse_flow_query(Some("onlyMocked=maybe")).is_err());
        assert!(parse_flow_query(Some("status=99")).is_err());

        let long = "x".repeat(MAX_SEARCH_LEN + 1);
        assert!(parse_flow_query(Some(&format!("search={long}"))).is_err());
    }

    #[test]
    fn ids_reject_separators_and_control_characters() {
        assert!(validate_id("abc123").is_ok());
        assert!(validate_id("f-00_01.2").is_ok());
        assert!(validate_id("").is_err());
        assert!(validate_id("../../etc/passwd").is_err());
        assert!(validate_id("a\nb").is_err());
        assert!(validate_id(&"x".repeat(MAX_ID_LEN + 1)).is_err());
    }

    /// REST list and get expose the shared H2+H3 multiplex keys (camelCase).
    /// H2 omits transport; H3 may set transport=quic. No new top-level fields.
    #[tokio::test]
    async fn list_and_get_expose_shared_multiplex_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let h1 = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Http,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "https://example.com/h1".into(),
                scheme: crate::types::Scheme::Https,
                authority: "example.com".into(),
                host: "example.com".into(),
                port: 443,
                path: "/h1".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 1,
            },
            server: crate::types::FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });

        let h2 = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Http,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "https://example.com/h2".into(),
                scheme: crate::types::Scheme::Https,
                authority: "example.com".into(),
                host: "example.com".into(),
                port: 443,
                path: "/h2".into(),
                http_version: crate::types::HttpVersion::Http2,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 2,
            },
            server: crate::types::FlowServer {
                alpn: Some("h2".into()),
                ..Default::default()
            },
            replay_of: None,
            transport: None,
            connection_id: Some("tls-session-uuid".into()),
            stream_id: Some(1),
            upstream_stream_id: None,
        });

        let h3 = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Http,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "https://example.com/h3".into(),
                scheme: crate::types::Scheme::Https,
                authority: "example.com".into(),
                host: "example.com".into(),
                port: 443,
                path: "/h3".into(),
                http_version: crate::types::HttpVersion::Http3,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 3,
            },
            server: crate::types::FlowServer {
                alpn: Some("h3".into()),
                ..Default::default()
            },
            replay_of: None,
            transport: Some(crate::types::Transport::Quic),
            connection_id: Some("quic-conn-uuid".into()),
            stream_id: Some(0),
            upstream_stream_id: Some(4),
        });

        // List summaries: connectionId + streamId, no upstreamStreamId.
        let (status, _, body) =
            request_with_body(address, "GET", "/api/flows", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("list json");
        let flows = page["flows"].as_array().expect("flows array");
        assert_eq!(flows.len(), 3);

        let by_id = |id: &str| -> &serde_json::Value {
            flows
                .iter()
                .find(|f| f["id"] == id)
                .unwrap_or_else(|| panic!("missing flow {id}"))
        };

        let h1_sum = by_id(&h1);
        assert!(h1_sum.get("connectionId").is_none());
        assert!(h1_sum.get("streamId").is_none());
        assert!(h1_sum.get("transport").is_none());
        assert!(h1_sum.get("upstreamStreamId").is_none());

        let h2_sum = by_id(&h2);
        assert_eq!(h2_sum["connectionId"], "tls-session-uuid");
        assert_eq!(h2_sum["streamId"], 1);
        assert_eq!(h2_sum["httpVersion"], "2.0");
        assert!(
            h2_sum.get("transport").is_none(),
            "TCP H2 must omit transport on list rows"
        );
        assert!(h2_sum.get("upstreamStreamId").is_none());

        let h3_sum = by_id(&h3);
        assert_eq!(h3_sum["connectionId"], "quic-conn-uuid");
        assert_eq!(h3_sum["streamId"], 0);
        assert_eq!(h3_sum["transport"], "quic");
        assert_eq!(h3_sum["httpVersion"], "3.0");
        assert!(h3_sum.get("upstreamStreamId").is_none());

        // Full flow includes upstreamStreamId for reverse H3 only.
        let path = format!("/api/flows/{h2}");
        let (status, _, body) =
            request_with_body(address, "GET", &path, &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let flow: serde_json::Value = serde_json::from_slice(&body).expect("h2 flow");
        assert_eq!(flow["connectionId"], "tls-session-uuid");
        assert_eq!(flow["streamId"], 1);
        assert!(flow.get("transport").is_none());
        assert!(flow.get("upstreamStreamId").is_none());

        let path = format!("/api/flows/{h3}");
        let (status, _, body) =
            request_with_body(address, "GET", &path, &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let flow: serde_json::Value = serde_json::from_slice(&body).expect("h3 flow");
        assert_eq!(flow["connectionId"], "quic-conn-uuid");
        assert_eq!(flow["streamId"], 0);
        assert_eq!(flow["upstreamStreamId"], 4);
        assert_eq!(flow["transport"], "quic");

        // search=connectionId groups sibling streams via the shared key.
        let path = format!("/api/flows?search={}", "tls-session-uuid");
        let (status, _, body) =
            request_with_body(address, "GET", &path, &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("search json");
        let found = page["flows"].as_array().expect("flows");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["id"], h2);
    }

    /// GET /api/status and the event-socket Status frame share ServerStatus.
    /// Config quic fields must appear as camelCase without claiming the TCP
    /// proxy port is the QUIC listener.
    #[tokio::test]
    async fn status_exposes_quic_fields_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::Config {
            data_dir: dir.path().to_path_buf(),
            insecure_upstream: true,
            ..crate::Config::default()
        };
        cfg.quic_port = Some(9443);
        cfg.reverse_h3 = Some("origin.example:443".into());

        let config = Arc::new(cfg);
        let ca = Arc::new(crate::ca::CertAuthority::open(dir.path()).expect("ca"));
        let store = Arc::new(crate::capture::FlowStore::new(
            16,
            config.max_body_bytes,
            64 * 1024 * 1024,
        ));
        let replay = Arc::new(
            crate::replay::ReplayEngine::new(config.clone(), store.clone())
                .expect("replay engine"),
        );
        let address = serve(ApiState {
            config,
            ca,
            store,
            replay,
            proxy_port: 9090,
            ui_port: 9091,
            ws_registry: Arc::new(crate::proxy::websocket::WsRegistry::new()),
            pauses: Arc::new(crate::proxy::breakpoint::PauseHub::new()),
            ws_rewrite: crate::proxy::ws_rewrite::WsRewriteHub::empty(),
            rewrite: crate::proxy::rewrite::RewriteHub::empty(),
        })
        .await;

        let (status, _, body) =
            request_with_body(address, "GET", "/api/status", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("status json");

        assert_eq!(json["proxyPort"], 9090);
        assert_eq!(json["uiPort"], 9091);
        assert_eq!(
            json["quicEnabled"].as_bool(),
            Some(cfg!(feature = "quic")),
            "quicEnabled must reflect the Cargo feature, not whether UDP is bound"
        );
        assert_eq!(json["quicPort"], 9443);
        assert_eq!(json["reverseH3"], "origin.example:443");
        let note = json["quicNote"].as_str().expect("quicNote present");
        assert!(
            note.contains("9443") || note.contains("--features quic"),
            "quicNote must name the UDP port or guide rebuild: {note}"
        );
        assert!(
            note.contains("cannot see QUIC") || note.contains("WireGuard") || note.contains("TUN")
                || note.contains("--features quic"),
            "quicNote must stay honest about TCP vs QUIC: {note}"
        );
        // TCP proxy port is a separate field; clients must not treat it as QUIC.
        assert_ne!(json["proxyPort"], json["quicPort"]);
    }

    #[tokio::test]
    async fn status_omits_quic_port_when_udp_unbound() {
        let dir = tempfile::tempdir().unwrap();
        let address = serve(state(dir.path())).await;
        let (status, _, body) =
            request_with_body(address, "GET", "/api/status", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("status json");
        assert_eq!(
            json["quicEnabled"].as_bool(),
            Some(cfg!(feature = "quic"))
        );
        assert!(
            json.get("quicPort").is_none(),
            "default config must not claim a QUIC UDP port: {json}"
        );
        assert!(
            json.get("reverseH3").is_none(),
            "default config must omit reverseH3: {json}"
        );
        let note = json["quicNote"].as_str().expect("quicNote always present");
        assert!(
            note.contains("cannot see QUIC"),
            "default note must state TCP cannot see QUIC: {note}"
        );
        assert_eq!(
            json["wireguardEnabled"].as_bool(),
            Some(cfg!(feature = "wireguard"))
        );
        assert!(
            json.get("wireguardPort").is_none(),
            "default config must not claim a WG UDP port: {json}"
        );
        let wg_note = json["wireguardNote"]
            .as_str()
            .expect("wireguardNote always present");
        assert!(
            wg_note.contains("WireGuard") || wg_note.contains("wireguard"),
            "wireguardNote must be honest: {wg_note}"
        );
        assert_eq!(
            json["tunEnabled"].as_bool(),
            Some(cfg!(feature = "tun"))
        );
        assert!(
            json.get("tunActive").is_none(),
            "default config must not claim TUN is active: {json}"
        );
        let tun_note = json["tunNote"].as_str().expect("tunNote always present");
        assert!(
            tun_note.contains("TUN") || tun_note.contains("tun"),
            "tunNote must be honest: {tun_note}"
        );
    }

    #[tokio::test]
    async fn status_exposes_wireguard_fields_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::Config {
            data_dir: dir.path().to_path_buf(),
            ..crate::Config::default()
        };
        cfg.wg_port = Some(51820);
        cfg.mode = crate::config::ListenMode::WireGuard;

        let config = Arc::new(cfg);
        let ca = Arc::new(crate::ca::CertAuthority::open(dir.path()).expect("ca"));
        let store = Arc::new(crate::capture::FlowStore::new(
            16,
            config.max_body_bytes,
            64 * 1024 * 1024,
        ));
        let replay = Arc::new(
            crate::replay::ReplayEngine::new(config.clone(), store.clone())
                .expect("replay engine"),
        );
        let address = serve(ApiState {
            config,
            ca,
            store,
            replay,
            proxy_port: 9090,
            ui_port: 9091,
            ws_registry: Arc::new(crate::proxy::websocket::WsRegistry::new()),
            pauses: Arc::new(crate::proxy::breakpoint::PauseHub::new()),
            ws_rewrite: crate::proxy::ws_rewrite::WsRewriteHub::empty(),
            rewrite: crate::proxy::rewrite::RewriteHub::empty(),
        })
        .await;

        let (status, _, body) =
            request_with_body(address, "GET", "/api/status", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("status json");

        assert_eq!(
            json["wireguardEnabled"].as_bool(),
            Some(cfg!(feature = "wireguard")),
            "wireguardEnabled must reflect the Cargo feature"
        );
        assert_eq!(json["wireguardPort"], 51820);
        let note = json["wireguardNote"].as_str().expect("wireguardNote present");
        assert!(
            note.contains("51820")
                || note.contains("--features wireguard")
                || note.contains("scaffold")
                || note.contains("not"),
            "wireguardNote must be honest about scaffold: {note}"
        );
        assert_ne!(json["proxyPort"], json["wireguardPort"]);
    }

    /// GET /api/status exposes TUN scaffold flags from config without claiming
    /// host packet capture or inventing a UDP port.
    #[tokio::test]
    async fn status_exposes_tun_fields_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::Config {
            data_dir: dir.path().to_path_buf(),
            ..crate::Config::default()
        };
        cfg.tun = true;
        cfg.mode = crate::config::ListenMode::Tun;

        let config = Arc::new(cfg);
        let ca = Arc::new(crate::ca::CertAuthority::open(dir.path()).expect("ca"));
        let store = Arc::new(crate::capture::FlowStore::new(
            16,
            config.max_body_bytes,
            64 * 1024 * 1024,
        ));
        let replay = Arc::new(
            crate::replay::ReplayEngine::new(config.clone(), store.clone())
                .expect("replay engine"),
        );
        let address = serve(ApiState {
            config,
            ca,
            store,
            replay,
            proxy_port: 9090,
            ui_port: 9091,
            ws_registry: Arc::new(crate::proxy::websocket::WsRegistry::new()),
            pauses: Arc::new(crate::proxy::breakpoint::PauseHub::new()),
            ws_rewrite: crate::proxy::ws_rewrite::WsRewriteHub::empty(),
            rewrite: crate::proxy::rewrite::RewriteHub::empty(),
        })
        .await;

        let (status, _, body) =
            request_with_body(address, "GET", "/api/status", &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("status json");

        assert_eq!(
            json["tunEnabled"].as_bool(),
            Some(cfg!(feature = "tun")),
            "tunEnabled must reflect the Cargo feature"
        );
        assert_eq!(
            json["tunActive"].as_bool(),
            Some(true),
            "requested TUN must set tunActive true (scaffold task), not capture"
        );
        let note = json["tunNote"].as_str().expect("tunNote present");
        assert!(
            note.contains("scaffold")
                || note.contains("no")
                || note.contains("--features tun")
                || note.contains("not"),
            "tunNote must be honest about scaffold: {note}"
        );
        assert!(
            !note.to_ascii_lowercase().contains("capturing packets")
                && !note.to_ascii_lowercase().contains("live capture"),
            "tunNote must not claim working capture: {note}"
        );
        // No invented UDP port field for TUN mode.
        assert!(
            json.get("tunPort").is_none(),
            "TUN is not a UDP listener: {json}"
        );
    }

    /// List filters the UI pass relies on: method, kind, onlyErrors, status,
    /// host, and search. Combinations must AND across dimensions and return
    /// both the page and the unpaginated total.
    #[tokio::test]
    async fn list_flows_applies_method_kind_and_only_errors_filters() {
        let dir = tempfile::tempdir().expect("temp dir");
        let inner = state(dir.path());
        let store = inner.store.clone();
        let address = serve(inner).await;

        let ok_get = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Http,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "https://api.example.com/ok".into(),
                scheme: crate::types::Scheme::Https,
                authority: "api.example.com".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/ok".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 1,
            },
            server: crate::types::FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });
        store.update(&ok_get, |flow| {
            flow.response = Some(crate::types::FlowResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![("content-type".into(), "application/json".into())],
                body: None,
            });
        });
        store.finish(&ok_get);

        let bad_post = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Http,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "POST".into(),
                url: "https://api.example.com/fail".into(),
                scheme: crate::types::Scheme::Https,
                authority: "api.example.com".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/fail".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 2,
            },
            server: crate::types::FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });
        store.update(&bad_post, |flow| {
            flow.response = Some(crate::types::FlowResponse {
                status: 500,
                status_text: "Error".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: None,
            });
        });
        store.finish(&bad_post);

        let ws = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Websocket,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "https://ws.example.com/socket".into(),
                scheme: crate::types::Scheme::Https,
                authority: "ws.example.com".into(),
                host: "ws.example.com".into(),
                port: 443,
                path: "/socket".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 3,
            },
            server: crate::types::FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });
        store.finish(&ws);

        // method + onlyErrors: the POST 500 is the only hit.
        let (status, _, body) = request_with_body(
            address,
            "GET",
            "/api/flows?method=POST&onlyErrors=1",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["total"], 1);
        let flows = page["flows"].as_array().expect("flows");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["id"], bad_post);
        assert_eq!(flows[0]["method"], "POST");
        assert_eq!(flows[0]["status"], 500);

        // kind=ws alone.
        let (status, _, body) = request_with_body(
            address,
            "GET",
            "/api/flows?kind=ws",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["total"], 1);
        assert_eq!(page["flows"][0]["id"], ws);
        assert_eq!(page["flows"][0]["kind"], "websocket");

        // method=GET + kind=http + status=2xx (excludes the WS GET and the 500).
        let (status, _, body) = request_with_body(
            address,
            "GET",
            "/api/flows?method=GET&kind=http&status=2xx",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["total"], 1);
        assert_eq!(page["flows"][0]["id"], ok_get);

        // host + search + onlyErrors: nothing matches (POST failure is not /ok).
        let (status, _, body) = request_with_body(
            address,
            "GET",
            "/api/flows?host=api.example.com&search=%2Fok&onlyErrors=true",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["total"], 0);
        assert_eq!(page["flows"].as_array().expect("flows").len(), 0);

        // Multi-method OR via repeated params.
        let (status, _, body) = request_with_body(
            address,
            "GET",
            "/api/flows?method=GET&method=POST&kind=http",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["total"], 2);

        // onlyMocked: mark the 200 GET as map-local and filter to it.
        store.update(&ok_get, |flow| {
            flow.mocked = true;
        });
        let (status, _, body) = request_with_body(
            address,
            "GET",
            "/api/flows?onlyMocked=1&kind=http",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["total"], 1);
        assert_eq!(page["flows"][0]["id"], ok_get);
        assert_eq!(page["flows"][0]["mocked"], true);

        // search=mock finds the same row via the synthetic needle.
        let (status, _, body) = request_with_body(
            address,
            "GET",
            "/api/flows?search=mock",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["total"], 1);
        assert_eq!(page["flows"][0]["id"], ok_get);
    }

    /// Archive stats is always routed. Without `--archive` (and without the
    /// feature-built DuckDB store) the handler refuses with 503 rather than
    /// inventing empty totals. Full stats content lives behind
    /// `cfg(feature = "archive")` in capture/archive.rs.
    #[tokio::test]
    async fn archive_stats_unavailable_when_no_archive_is_configured() {
        let dir = tempfile::tempdir().expect("temp dir");
        let address = serve(state(dir.path())).await;

        let (status, _, body) = request_with_body(
            address,
            "GET",
            "/api/archive/stats",
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let text = json["error"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        assert!(
            text.contains("archive"),
            "503 body should explain the archive is off: {text}"
        );

        let (status, _, body) = request_with_body(
            address,
            "POST",
            "/api/archive/query",
            &[("content-type", "application/json")],
            Bytes::from(r#"{"sql":"SELECT 1"}"#.as_bytes().to_vec()),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let text = json["error"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        assert!(
            text.contains("archive"),
            "query without archive should also 503: {text}"
        );
    }
}
