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
    // The two endpoints that carry a whole request body read it with the `Bytes`
    // extractor, which otherwise stops at the axum default of 2 MB. Capture
    // accepts bodies four times that, and a replay of one has to be able to
    // carry it back out.
    let body_limit = usize::try_from(state.config.max_body_bytes).unwrap_or(usize::MAX);

    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/flows", get(list_flows).delete(clear_flows))
        .route("/api/flows/{id}", get(get_flow))
        .route("/api/flows/{id}/body/{which}", get(get_body))
        .route("/api/flows/{id}/curl", get(get_curl))
        .route(
            "/api/flows/{id}/replay",
            post(replay_flow).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route(
            "/api/send",
            post(send).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route("/api/har", get(get_har))
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
            "/api/environments/{id}",
            put(update_environment).delete(delete_environment),
        )
        .route("/api/stream", get(stream))
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

#[derive(Clone, Copy)]
enum Side {
    Request,
    Response,
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

async fn send(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let spec: crate::replay::SendSpec = parse_json_body(&body)?;
    let result = state.replay.send(spec).await.map_err(upstream)?;
    Ok(Json(result).into_response())
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
        // Drained so the connection can close cleanly rather than being reset.
        let _ = body.collect().await;
        (parts.status, parts.headers)
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

        for path in ["/api/send", "/api/flows/whatever/replay"] {
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
            "search=token&host=API.Example.com&host=b.com&method=get&status=2xx&kind=ws&onlyErrors=1&limit=50&before=900",
        ))
        .unwrap();

        assert_eq!(query.search.as_deref(), Some("token"));
        assert_eq!(query.hosts, vec!["api.example.com", "b.com"]);
        assert_eq!(query.methods, vec!["GET"]);
        assert_eq!(query.status_range, Some((200, 299)));
        assert_eq!(query.kinds.len(), 1);
        assert!(query.only_errors);
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.before, Some(900));
    }

    #[test]
    fn an_empty_query_is_the_default() {
        let query = parse_flow_query(None).unwrap();
        assert!(query.search.is_none());
        assert!(query.hosts.is_empty());
        assert!(query.limit.is_none());
        assert!(!query.only_errors);
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
}
