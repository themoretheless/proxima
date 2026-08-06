//! The capture store: every flow the proxy has seen, plus the live event feed.
//!
//! One [`FlowStore`] is shared by every connection task, the REST API and the
//! websocket feed, so all of it takes `&self` and locks internally. The locks
//! are deliberately short: nothing here awaits, and no guard ever escapes a
//! method, because a guard held across a yield point would stall every other
//! connection on the proxy.
//!
//! Retention has ceilings that have to agree with each other. Flows live in an
//! insertion ordered ring buffer, and evicting a flow also drops its bodies
//! from the [`BodyStore`]; forgetting the second half is how a debugging proxy
//! quietly eats a machine over an afternoon. A single flow is bounded too: a
//! WebSocket keeps at most [`MAX_WS_MESSAGES`] frames, and a body handed to a
//! flow that has already been evicted is released rather than left for the
//! global byte ceiling to find later.

pub mod archive;
pub mod bodies;
pub mod decode;
pub mod har;

use std::collections::{HashMap, VecDeque};

use base64::Engine as _;
use parking_lot::Mutex;
use rand::RngCore;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::config::host_matches;
use crate::types::{
    now_ms, Flow, FlowClient, FlowError, FlowId, FlowKind, FlowQuery, FlowRequest, FlowResponse,
    FlowServer, FlowState, FlowSummary, FlowTimings, HeaderPair, HttpVersion, ProxyEvent, Scheme,
    WsDirection, WsMessage,
};

pub use archive::{Archive, ArchiveRow, QueryResult};
pub use bodies::{BodyStore, BodyWriter};
pub use decode::{decode_body, is_textual};
pub use har::flows_to_har;

/// Deep enough that a websocket client doing a full page render does not lag,
/// small enough that a subscriber that stopped reading cannot cost much.
const EVENT_CAPACITY: usize = 1024;
const DEFAULT_QUERY_LIMIT: usize = 200;
const MAX_QUERY_LIMIT: usize = 1000;

/// WebSocket frames retained per flow. Frames are the one part of a flow whose
/// count the proxy does not control: a socket that stays open for a day keeps
/// appending, so the list is a window on the most recent traffic.
pub const MAX_WS_MESSAGES: usize = 4096;

/// How many frames go at once when the cap is reached. Discarding a single
/// frame per arrival would shift the whole retained window on every frame, so
/// the cost is amortised over a batch instead.
const WS_TRIM_BATCH: usize = 256;

/// Opcode of the synthetic frame that stands in for discarded ones. RFC 6455
/// reserves `0xf`, and the frame reader stops observing a socket that uses a
/// reserved opcode, so this can never collide with a captured frame. Consumers
/// key off it to render the gap; see [`is_ws_drop_marker`].
pub const WS_DROPPED_OPCODE: u8 = 0xf;

/// Everything the proxy knows when it first sees a request. The store fills in
/// the id, the state and the start timestamp.
pub struct FlowInit {
    pub kind: FlowKind,
    pub intercepted: bool,
    pub request: FlowRequest,
    pub client: FlowClient,
    pub server: FlowServer,
    pub replay_of: Option<FlowId>,
}

pub struct FlowStore {
    inner: Mutex<Inner>,
    events: broadcast::Sender<ProxyEvent>,
    bodies: BodyStore,
    max_flows: usize,
    max_body_bytes: u64,
    /// Where finished flows go to outlive the ring buffer. `None` unless an
    /// archive was configured, in which case the store behaves exactly as it
    /// did before this existed.
    archive: Option<Archive>,
}

struct Inner {
    flows: HashMap<FlowId, Stored>,
    /// Insertion order, oldest at the front. Sequence numbers rise with it, so
    /// this doubles as the ordering for the `before` cursor.
    order: VecDeque<FlowId>,
    next_seq: u64,
}

struct Stored {
    seq: u64,
    flow: Flow,
    /// Set once this flow has been handed to the archive, so the two paths that
    /// can archive it, reaching a terminal state and being evicted, cannot both
    /// write it.
    archived: bool,
}

impl FlowStore {
    pub fn new(max_flows: usize, max_body_bytes: u64, max_total_body_bytes: u64) -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            inner: Mutex::new(Inner {
                flows: HashMap::new(),
                order: VecDeque::new(),
                next_seq: 1,
            }),
            events,
            bodies: BodyStore::new(max_total_body_bytes),
            // A ring buffer of zero would evict every flow the instant it was
            // created, which no configuration can plausibly want.
            max_flows: max_flows.max(1),
            max_body_bytes,
            archive: None,
        }
    }

    /// Records finished flows to `archive` as well as holding them in memory.
    /// Takes the store by value because it is wired once, at startup, before
    /// the `Arc` that every connection shares is made.
    pub fn with_archive(mut self, archive: Archive) -> Self {
        self.archive = Some(archive);
        self
    }

    pub fn archive(&self) -> Option<&Archive> {
        self.archive.as_ref()
    }

    /// A receiver for the live feed. Receivers that fall behind get
    /// `RecvError::Lagged` and are expected to resynchronise by re-querying;
    /// the store never slows down for them.
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.events.subscribe()
    }

    pub fn create(&self, init: FlowInit) -> FlowId {
        let id = new_id();
        let flow = Flow {
            id: id.clone(),
            kind: init.kind,
            state: FlowState::Pending,
            intercepted: init.intercepted,
            request: init.request,
            response: None,
            error: None,
            timings: FlowTimings {
                start: now_ms(),
                ..FlowTimings::default()
            },
            client: init.client,
            server: init.server,
            replay_of: init.replay_of,
            comment: None,
            ws_messages: None,
            tunnel: None,
            rewrites: Vec::new(),
        };
        let summary = summarize(&flow);

        let mut orphaned_bodies = Vec::new();
        let mut to_archive = Vec::new();
        {
            let mut inner = self.inner.lock();
            let seq = inner.next_seq;
            inner.next_seq = inner.next_seq.saturating_add(1);
            inner.order.push_back(id.clone());
            inner.flows.insert(
                id.clone(),
                Stored {
                    seq,
                    flow,
                    archived: false,
                },
            );

            while inner.flows.len() > self.max_flows {
                let Some(oldest) = inner.order.pop_front() else {
                    break;
                };
                if let Some(evicted) = inner.flows.remove(&oldest) {
                    collect_body_ids(&evicted.flow, &mut orphaned_bodies);
                    // A flow evicted before it finished is still the only record
                    // that it happened, so it goes to the archive mid-flight
                    // rather than being lost with its state as it stands.
                    if self.archive.is_some() && !evicted.archived {
                        to_archive.push(archive_row(&evicted.flow, evicted.seq));
                    }
                }
            }
        }

        // Outside the flow lock: the two stores must never be locked in a
        // fixed order from more than one place.
        for body_id in &orphaned_bodies {
            self.bodies.remove(body_id);
        }
        self.send_to_archive(to_archive);
        if !orphaned_bodies.is_empty() {
            debug!(
                bodies = orphaned_bodies.len(),
                "evicted flows past the ring buffer limit"
            );
        }

        let _ = self.events.send(ProxyEvent::FlowNew {
            flow: Box::new(summary),
        });
        id
    }

    /// Mutates a flow in place and republishes it. `f` runs while the store is
    /// locked, so it must stay cheap and must not block.
    ///
    /// A body committed after its flow was evicted would otherwise have nothing
    /// left that knows its id, so an update for a flow that is gone still runs
    /// `f`, against a tombstone, purely to learn which bodies it was handing
    /// over. Those are released immediately rather than waiting for the global
    /// byte ceiling to notice them.
    pub fn update<F: FnOnce(&mut Flow)>(&self, id: &str, f: F) {
        let mut pending = Some(f);
        let summary = {
            let mut inner = self.inner.lock();
            match inner.flows.get_mut(id) {
                Some(stored) => {
                    if let Some(f) = pending.take() {
                        f(&mut stored.flow);
                    }
                    Some(summarize(&stored.flow))
                }
                None => None,
            }
        };
        match summary {
            Some(summary) => {
                let _ = self.events.send(ProxyEvent::FlowUpdate {
                    flow: Box::new(summary),
                });
            }
            // Expected after the ring buffer evicts a flow that is still in
            // flight, so this is not a warning.
            None => {
                debug!(%id, "update for a flow that is no longer stored");
                let mut orphaned = Vec::new();
                if let Some(f) = pending {
                    let mut tombstone = tombstone_flow(id);
                    f(&mut tombstone);
                    collect_body_ids(&tombstone, &mut orphaned);
                }
                for body_id in &orphaned {
                    self.bodies.remove(body_id);
                }
                if !orphaned.is_empty() {
                    debug!(
                        %id,
                        bodies = orphaned.len(),
                        "dropped a body committed after its flow was evicted"
                    );
                }
            }
        }
    }

    /// Marks a flow complete. A flow that already failed keeps its state, since
    /// the transport closing cleanly after an error does not undo the error.
    pub fn finish(&self, id: &str) {
        let mut row = None;
        let summary = {
            let mut inner = self.inner.lock();
            match inner.flows.get_mut(id) {
                Some(stored) => {
                    if stored.flow.timings.end.is_none() {
                        stored.flow.timings.end = Some(now_ms());
                    }
                    if !matches!(stored.flow.state, FlowState::Error | FlowState::Aborted) {
                        stored.flow.state = FlowState::Complete;
                    }
                    if self.archive.is_some() && !stored.archived {
                        stored.archived = true;
                        row = Some(archive_row(&stored.flow, stored.seq));
                    }
                    Some(summarize(&stored.flow))
                }
                None => None,
            }
        };
        self.send_to_archive(row);
        if let Some(summary) = summary {
            let _ = self.events.send(ProxyEvent::FlowDone {
                flow: Box::new(summary),
            });
        }
    }

    pub fn fail(&self, id: &str, error: FlowError) {
        let message = error.message.clone();
        let mut row = None;
        let summary = {
            let mut inner = self.inner.lock();
            match inner.flows.get_mut(id) {
                Some(stored) => {
                    stored.flow.state = FlowState::Error;
                    stored.flow.error = Some(error);
                    if stored.flow.timings.end.is_none() {
                        stored.flow.timings.end = Some(now_ms());
                    }
                    if self.archive.is_some() && !stored.archived {
                        stored.archived = true;
                        row = Some(archive_row(&stored.flow, stored.seq));
                    }
                    Some(summarize(&stored.flow))
                }
                None => None,
            }
        };
        self.send_to_archive(row);
        match summary {
            Some(summary) => {
                warn!(%id, host = %summary.authority, %message, "flow failed");
                let _ = self.events.send(ProxyEvent::FlowDone {
                    flow: Box::new(summary),
                });
            }
            None => debug!(%id, %message, "failure for a flow that is no longer stored"),
        }
    }

    /// Records one frame, keeping at most [`MAX_WS_MESSAGES`] of them. Frames
    /// past the cap are discarded oldest first, their bodies are released, and
    /// a marker frame is left at the head of the list so a reader can tell that
    /// the history is not complete.
    pub fn add_ws_message(&self, id: &str, message: WsMessage) {
        let mut orphaned = Vec::new();
        let (stored_ok, marker) = {
            let mut inner = self.inner.lock();
            match inner.flows.get_mut(id) {
                Some(stored) => {
                    let messages = stored.flow.ws_messages.get_or_insert_with(Vec::new);
                    messages.push(message.clone());
                    let marker = trim_ws_messages(messages, &mut orphaned);
                    (true, marker)
                }
                None => {
                    // The flow was evicted while its socket was still open, so
                    // nothing will ever reference this frame's body again.
                    if let Some(body_id) = &message.body_id {
                        orphaned.push(body_id.clone());
                    }
                    (false, None)
                }
            }
        };

        // Outside the flow lock: the two stores must never be locked in a
        // fixed order from more than one place.
        for body_id in &orphaned {
            self.bodies.remove(body_id);
        }

        if let Some(marker) = marker {
            debug!(
                %id,
                dropped = marker.size,
                "websocket frames discarded at the retention cap"
            );
            // Published before the frame that caused it so a live listener
            // trims its own history in the same order the store did.
            let _ = self.events.send(ProxyEvent::WsMessageEvent {
                id: id.to_string(),
                message: Box::new(marker),
            });
        }
        if stored_ok {
            let _ = self.events.send(ProxyEvent::WsMessageEvent {
                id: id.to_string(),
                message: Box::new(message),
            });
        }
    }

    pub fn get(&self, id: &str) -> Option<Flow> {
        self.inner.lock().flows.get(id).map(|s| s.flow.clone())
    }

    /// The sequence number of a flow, which is what [`FlowQuery::before`]
    /// expects as a cursor.
    pub fn seq_of(&self, id: &str) -> Option<u64> {
        self.inner.lock().flows.get(id).map(|s| s.seq)
    }

    /// Newest first. The returned count is how many flows match the filters
    /// ignoring both `before` and `limit`, so a paging UI can show a stable
    /// total while it walks the cursor backwards.
    pub fn query(&self, q: &FlowQuery) -> (Vec<FlowSummary>, usize) {
        let limit = q.limit.unwrap_or(DEFAULT_QUERY_LIMIT).min(MAX_QUERY_LIMIT);
        let mut page = Vec::new();
        let mut total = 0usize;

        let inner = self.inner.lock();
        for id in inner.order.iter().rev() {
            let Some(stored) = inner.flows.get(id) else {
                continue;
            };
            if !matches_query(&stored.flow, q) {
                continue;
            }
            total += 1;
            if page.len() >= limit {
                continue;
            }
            if let Some(before) = q.before {
                if stored.seq >= before {
                    continue;
                }
            }
            page.push(summarize(&stored.flow));
        }
        (page, total)
    }

    /// Every flow matching the filters, oldest first, for HAR export. `limit`
    /// and `before` are ignored on purpose: an export is not a page.
    pub fn all(&self, q: &FlowQuery) -> Vec<Flow> {
        let inner = self.inner.lock();
        inner
            .order
            .iter()
            .filter_map(|id| inner.flows.get(id))
            .filter(|stored| matches_query(&stored.flow, q))
            .map(|stored| stored.flow.clone())
            .collect()
    }

    /// Empties the in-memory view. The archive is not touched: clearing the
    /// list is how someone starts a fresh observation, not how they ask for
    /// yesterday's statistics to be destroyed. Anything not archived yet is
    /// written on the way out, so nothing vanishes without a trace.
    pub fn clear(&self) {
        let mut to_archive = Vec::new();
        {
            let mut inner = self.inner.lock();
            if self.archive.is_some() {
                for stored in inner.flows.values().filter(|s| !s.archived) {
                    to_archive.push(archive_row(&stored.flow, stored.seq));
                }
                // Oldest first, so the archive keeps the order the proxy saw.
                to_archive.sort_by_key(|row| row.seq);
            }
            inner.flows.clear();
            inner.order.clear();
        }
        self.bodies.clear();
        self.send_to_archive(to_archive);
        let _ = self.events.send(ProxyEvent::Clear);
    }

    /// Hands rows over, if there is an archive at all. Always called outside
    /// the store lock: the archive queue is bounded, and blocking on it while
    /// holding the lock would stall every connection on the proxy.
    fn send_to_archive<I: IntoIterator<Item = ArchiveRow>>(&self, rows: I) {
        let Some(archive) = &self.archive else {
            return;
        };
        for row in rows {
            archive.record(row);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn max_body_bytes(&self) -> u64 {
        self.max_body_bytes
    }

    pub fn max_flows(&self) -> usize {
        self.max_flows
    }

    pub fn bodies(&self) -> &BodyStore {
        &self.bodies
    }
}

/// Short, URL safe and random enough that ids never collide in a session.
/// 96 bits of entropy in 16 characters, because these end up in paths.
pub(crate) fn new_id() -> String {
    let mut raw = [0u8; 12];
    rand::rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

pub(crate) fn header_value(headers: &[HeaderPair], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

/// The content type a user would expect to see in the flow list: the response's
/// if there is one, otherwise the request's.
pub(crate) fn content_type_of(flow: &Flow) -> Option<String> {
    if let Some(response) = &flow.response {
        if let Some(body) = &response.body {
            if let Some(ct) = &body.content_type {
                return Some(ct.clone());
            }
        }
        if let Some(ct) = header_value(&response.headers, "content-type") {
            return Some(ct);
        }
    }
    if let Some(body) = &flow.request.body {
        if let Some(ct) = &body.content_type {
            return Some(ct.clone());
        }
    }
    header_value(&flow.request.headers, "content-type")
}

/// True for the synthetic frame that stands in for discarded ones. Its `size`
/// is the running number of frames discarded from this flow, not a byte count,
/// and its `text` says the same thing in words.
pub fn is_ws_drop_marker(message: &WsMessage) -> bool {
    message.opcode == WS_DROPPED_OPCODE
}

fn ws_drop_marker(dropped: u64, at: u64, direction: WsDirection) -> WsMessage {
    WsMessage {
        at,
        direction,
        opcode: WS_DROPPED_OPCODE,
        size: dropped,
        truncated: true,
        text: Some(format!(
            "{dropped} earlier messages discarded, keeping the most recent {MAX_WS_MESSAGES}"
        )),
        body_id: None,
    }
}

/// Trims the retained frames back under [`MAX_WS_MESSAGES`], collecting the
/// body ids the discarded frames owned. Returns the marker frame when anything
/// was discarded, so the caller can announce it.
fn trim_ws_messages(messages: &mut Vec<WsMessage>, orphaned: &mut Vec<String>) -> Option<WsMessage> {
    let had_marker = messages.first().is_some_and(is_ws_drop_marker);
    // The marker sits at index 0 and is not itself a captured frame.
    let head = usize::from(had_marker);
    let retained = messages.len() - head;
    if retained <= MAX_WS_MESSAGES {
        return None;
    }

    // Take a batch rather than the single frame that pushed us over, so a busy
    // socket does not shift the whole window on every arrival.
    let discard = (retained - MAX_WS_MESSAGES + WS_TRIM_BATCH).min(retained);
    let mut dropped = if had_marker { messages[0].size } else { 0 };
    let mut at = 0;
    let mut direction = WsDirection::Recv;
    for message in messages.drain(head..head + discard) {
        if let Some(body_id) = message.body_id {
            orphaned.push(body_id);
        }
        // The marker takes the place of the newest frame it replaces, so a
        // timeline puts the gap where the gap actually is.
        at = message.at;
        direction = message.direction;
        dropped = dropped.saturating_add(1);
    }

    let marker = ws_drop_marker(dropped, at, direction);
    match had_marker {
        true => messages[0] = marker.clone(),
        false => messages.insert(0, marker.clone()),
    }
    Some(marker)
}

/// A stand-in for a flow the store no longer holds. It exists only so a late
/// update has somewhere to write, and is read once for the body ids it picked
/// up before being thrown away. The empty response matters: an update that
/// attaches a response body writes through `flow.response`, and without one the
/// body would look unreferenced and be left in the store.
fn tombstone_flow(id: &str) -> Flow {
    Flow {
        id: id.to_string(),
        kind: FlowKind::Http,
        state: FlowState::Aborted,
        intercepted: false,
        request: FlowRequest {
            method: String::new(),
            url: String::new(),
            scheme: Scheme::Https,
            authority: String::new(),
            host: String::new(),
            port: 0,
            path: String::new(),
            http_version: HttpVersion::Http11,
            headers: Vec::new(),
            body: None,
        },
        response: Some(FlowResponse {
            status: 0,
            status_text: String::new(),
            http_version: HttpVersion::Http11,
            headers: Vec::new(),
            body: None,
        }),
        error: None,
        timings: FlowTimings::default(),
        client: FlowClient {
            address: String::new(),
            port: 0,
        },
        server: FlowServer::default(),
        replay_of: None,
        comment: None,
        ws_messages: None,
        tunnel: None,
        rewrites: Vec::new(),
    }
}

fn collect_body_ids(flow: &Flow, out: &mut Vec<String>) {
    if let Some(body) = &flow.request.body {
        out.push(body.id.clone());
    }
    if let Some(body) = flow.response.as_ref().and_then(|r| r.body.as_ref()) {
        out.push(body.id.clone());
    }
    if let Some(messages) = &flow.ws_messages {
        for message in messages {
            if let Some(id) = &message.body_id {
                out.push(id.clone());
            }
        }
    }
}

fn summarize(flow: &Flow) -> FlowSummary {
    let status = flow.response.as_ref().map(|r| r.status);
    let duration = match flow.timings.end {
        Some(end) if end >= flow.timings.start => Some(end - flow.timings.start),
        _ => None,
    };
    FlowSummary {
        id: flow.id.clone(),
        kind: flow.kind,
        state: flow.state,
        intercepted: flow.intercepted,
        method: flow.request.method.clone(),
        scheme: flow.request.scheme,
        authority: flow.request.authority.clone(),
        path: flow.request.path.clone(),
        http_version: flow.request.http_version,
        status,
        content_type: content_type_of(flow),
        request_size: flow.request.body.as_ref().map(|b| b.size).unwrap_or(0),
        response_size: flow
            .response
            .as_ref()
            .and_then(|r| r.body.as_ref())
            .map(|b| b.size)
            .unwrap_or(0),
        start: flow.timings.start,
        duration,
        error: flow.error.as_ref().map(|e| e.message.clone()),
        client: flow.client.address.clone(),
        likely_pinning: flow
            .error
            .as_ref()
            .and_then(|e| e.likely_pinning)
            .unwrap_or(false),
    }
}

/// Flattens a flow into the row the archive stores.
///
/// Bodies are represented by their size and content type only. Everything else
/// a flow knows is either a scalar column or, for headers, a JSON array of
/// `[name, value]` pairs that DuckDB can index into, which keeps one row per
/// flow and avoids a join for the one question headers get asked: which flows
/// carried this header.
pub(crate) fn archive_row(flow: &Flow, seq: u64) -> ArchiveRow {
    let summary = summarize(flow);
    ArchiveRow {
        seq,
        id: flow.id.clone(),
        kind: kind_name(flow.kind),
        state: state_name(flow.state),
        intercepted: flow.intercepted,
        method: flow.request.method.clone(),
        scheme: flow.request.scheme.as_str(),
        host: flow.request.host.clone(),
        port: flow.request.port,
        authority: flow.request.authority.clone(),
        path: flow.request.path.clone(),
        url: flow.request.url.clone(),
        http_version: version_name(flow.request.http_version),
        status: summary.status,
        content_type: summary.content_type,
        request_bytes: summary.request_size,
        response_bytes: summary.response_size,
        started_ms: flow.timings.start,
        duration_ms: summary.duration,
        error: summary.error,
        likely_pinning: summary.likely_pinning,
        client: flow.client.address.clone(),
        replay_of: flow.replay_of.clone(),
        request_headers: headers_json(&flow.request.headers),
        response_headers: flow.response.as_ref().map(|r| headers_json(&r.headers)),
        ws_messages: flow.ws_messages.as_ref().map(|m| m.len() as u64),
    }
}

/// Headers as a JSON array of pairs. Serialisation of a `Vec<(String, String)>`
/// cannot fail, so a failure here would be a bug in serde_json rather than
/// anything about this data, and an empty array keeps the column non-null.
fn headers_json(headers: &[HeaderPair]) -> String {
    serde_json::to_string(headers).unwrap_or_else(|_| "[]".to_string())
}

fn kind_name(kind: FlowKind) -> &'static str {
    match kind {
        FlowKind::Http => "http",
        FlowKind::Websocket => "websocket",
        FlowKind::Tunnel => "tunnel",
    }
}

fn state_name(state: FlowState) -> &'static str {
    match state {
        FlowState::Pending => "pending",
        FlowState::Streaming => "streaming",
        FlowState::Complete => "complete",
        FlowState::Error => "error",
        FlowState::Aborted => "aborted",
    }
}

fn version_name(version: HttpVersion) -> &'static str {
    match version {
        HttpVersion::Http10 => "1.0",
        HttpVersion::Http11 => "1.1",
        HttpVersion::Http2 => "2.0",
    }
}

fn matches_query(flow: &Flow, q: &FlowQuery) -> bool {
    if !q.kinds.is_empty() && !q.kinds.contains(&flow.kind) {
        return false;
    }

    if !q.hosts.is_empty()
        && !q
            .hosts
            .iter()
            .any(|pattern| host_matches(&flow.request.host, pattern))
    {
        return false;
    }

    if !q.methods.is_empty()
        && !q
            .methods
            .iter()
            .any(|m| m.trim().eq_ignore_ascii_case(&flow.request.method))
    {
        return false;
    }

    if let Some((low, high)) = q.status_range {
        match flow.response.as_ref().map(|r| r.status) {
            Some(status) if status >= low && status <= high => {}
            _ => return false,
        }
    }

    if q.only_errors {
        let failed = flow.state == FlowState::Error
            || flow.response.as_ref().is_some_and(|r| r.status >= 400);
        if !failed {
            return false;
        }
    }

    if let Some(search) = &q.search {
        let needle = search.trim().to_ascii_lowercase();
        if !needle.is_empty() {
            let status = flow
                .response
                .as_ref()
                .map(|r| r.status.to_string())
                .unwrap_or_default();
            let content_type = content_type_of(flow).unwrap_or_default();
            let hit = flow.request.method.to_ascii_lowercase().contains(&needle)
                || flow.request.url.to_ascii_lowercase().contains(&needle)
                || status.contains(&needle)
                || content_type.to_ascii_lowercase().contains(&needle);
            if !hit {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FlowResponse, HttpVersion, Scheme, WsDirection};

    fn init(method: &str, host: &str, path: &str) -> FlowInit {
        FlowInit {
            kind: FlowKind::Http,
            intercepted: true,
            request: FlowRequest {
                method: method.to_string(),
                url: format!("https://{host}{path}"),
                scheme: Scheme::Https,
                authority: host.to_string(),
                host: host.to_string(),
                port: 443,
                path: path.to_string(),
                http_version: HttpVersion::Http11,
                headers: vec![("accept".into(), "application/json".into())],
                body: None,
            },
            client: FlowClient {
                address: "192.168.1.20".into(),
                port: 51314,
            },
            server: FlowServer::default(),
            replay_of: None,
        }
    }

    fn respond(store: &FlowStore, id: &str, status: u16, content_type: &str) {
        store.update(id, |flow| {
            flow.response = Some(FlowResponse {
                status,
                status_text: "".into(),
                http_version: HttpVersion::Http11,
                headers: vec![("content-type".into(), content_type.to_string())],
                body: None,
            });
        });
        store.finish(id);
    }

    fn attach_request_body(store: &FlowStore, id: &str, payload: &[u8]) -> String {
        let mut writer = store.bodies().writer(store.max_body_bytes());
        writer.write(payload);
        let meta = writer.finish(None, Some("application/json".into()));
        let body_id = meta.id.clone();
        store.update(id, |flow| flow.request.body = Some(meta));
        body_id
    }

    #[test]
    fn the_store_can_be_shared_across_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FlowStore>();
        assert_send_sync::<BodyStore>();
        assert_send_sync::<BodyWriter>();
    }

    #[test]
    fn ids_are_short_url_safe_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let id = new_id();
            assert_eq!(id.len(), 16);
            assert!(id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
            assert!(seen.insert(id));
        }
    }

    #[test]
    fn create_populates_defaults_and_emits() {
        let store = FlowStore::new(10, 1024, 4096);
        let mut rx = store.subscribe();

        let id = store.create(init("GET", "api.example.com", "/v1/users"));
        let flow = store.get(&id).expect("flow stored");
        assert_eq!(flow.state, FlowState::Pending);
        assert!(flow.timings.start > 0);
        assert_eq!(store.len(), 1);

        match rx.try_recv() {
            Ok(ProxyEvent::FlowNew { flow }) => assert_eq!(flow.id, id),
            other => panic!("expected flow:new, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_events_follow_the_flow() {
        let store = FlowStore::new(10, 1024, 4096);
        let mut rx = store.subscribe();
        let id = store.create(init("POST", "api.example.com", "/v1/login"));
        assert!(matches!(rx.try_recv(), Ok(ProxyEvent::FlowNew { .. })));

        store.update(&id, |flow| flow.state = FlowState::Streaming);
        assert!(matches!(rx.try_recv(), Ok(ProxyEvent::FlowUpdate { .. })));

        respond(&store, &id, 200, "application/json");
        assert!(matches!(rx.try_recv(), Ok(ProxyEvent::FlowUpdate { .. })));
        match rx.try_recv() {
            Ok(ProxyEvent::FlowDone { flow }) => {
                assert_eq!(flow.status, Some(200));
                assert_eq!(flow.state, FlowState::Complete);
                assert!(flow.duration.is_some());
                assert_eq!(flow.content_type.as_deref(), Some("application/json"));
            }
            other => panic!("expected flow:done, got {other:?}"),
        }
    }

    #[test]
    fn failure_records_state_and_pinning() {
        let store = FlowStore::new(10, 1024, 4096);
        let id = store.create(init("GET", "pinned.example.com", "/"));
        store.fail(
            &id,
            FlowError {
                message: "client rejected our certificate".into(),
                code: Some("tls".into()),
                likely_pinning: Some(true),
            },
        );

        let flow = store.get(&id).expect("flow stored");
        assert_eq!(flow.state, FlowState::Error);
        assert!(flow.timings.end.is_some());

        let (page, _) = store.query(&FlowQuery::default());
        assert!(page[0].likely_pinning);

        // A late finish must not paper over the error.
        store.finish(&id);
        assert_eq!(
            store.get(&id).map(|f| f.state),
            Some(FlowState::Error),
            "finish must not overwrite an error state"
        );
    }

    #[test]
    fn websocket_messages_are_appended_and_broadcast() {
        let store = FlowStore::new(10, 1024, 4096);
        let id = store.create(init("GET", "ws.example.com", "/socket"));
        let mut rx = store.subscribe();

        store.add_ws_message(
            &id,
            WsMessage {
                at: now_ms(),
                direction: WsDirection::Send,
                opcode: 1,
                size: 5,
                truncated: false,
                text: Some("hello".into()),
                body_id: None,
            },
        );

        let flow = store.get(&id).expect("flow stored");
        assert_eq!(flow.ws_messages.as_ref().map(|m| m.len()), Some(1));
        assert!(matches!(
            rx.try_recv(),
            Ok(ProxyEvent::WsMessageEvent { .. })
        ));
    }

    fn ws_body(store: &FlowStore, payload: &[u8]) -> String {
        let mut writer = store.bodies().writer(store.max_body_bytes());
        writer.write(payload);
        writer.finish(None, None).id
    }

    fn ws_frame(body_id: Option<String>) -> WsMessage {
        WsMessage {
            at: now_ms(),
            direction: WsDirection::Recv,
            opcode: 2,
            size: 4,
            truncated: false,
            text: None,
            body_id,
        }
    }

    #[test]
    fn a_long_lived_socket_stays_bounded_and_frees_the_frames_it_drops() {
        let store = FlowStore::new(10, 1024, 8 * 1024 * 1024);
        let id = store.create(init("GET", "ws.example.com", "/socket"));

        let total = MAX_WS_MESSAGES + 1000;
        for _ in 0..total {
            let body_id = ws_body(&store, b"beef");
            store.add_ws_message(&id, ws_frame(Some(body_id)));
        }

        let flow = store.get(&id).expect("flow stored");
        let messages = flow.ws_messages.as_ref().expect("frames recorded");

        let marker = messages.first().expect("a marker at the head");
        assert!(
            is_ws_drop_marker(marker),
            "a trimmed flow must say so at the head of its frames"
        );
        assert!(
            marker.text.as_deref().is_some_and(|t| !t.is_empty()),
            "the marker must be readable, not just a magic opcode"
        );

        let kept = messages.len() - 1;
        assert!(
            kept <= MAX_WS_MESSAGES,
            "retained frames must stay under the cap, kept {kept}"
        );
        assert!(kept >= MAX_WS_MESSAGES - WS_TRIM_BATCH);
        assert_eq!(
            marker.size as usize + kept,
            total,
            "every frame is either kept or counted as dropped"
        );
        assert_eq!(
            messages.iter().filter(|m| is_ws_drop_marker(m)).count(),
            1,
            "the marker is updated in place, not stacked up"
        );

        assert_eq!(
            store.bodies().bytes_held(),
            kept as u64 * 4,
            "a dropped frame must not leave its body behind"
        );
        assert_eq!(store.bodies().len(), kept);
    }

    #[test]
    fn a_body_committed_after_its_flow_was_evicted_is_released() {
        let store = FlowStore::new(1, 1024, 1024 * 1024);
        let gone = store.create(init("POST", "api.example.com", "/upload"));
        store.create(init("GET", "api.example.com", "/next"));
        assert!(store.get(&gone).is_none(), "the first flow is evicted");
        assert_eq!(store.bodies().bytes_held(), 0);

        // A request body that finished streaming after the eviction.
        let mut writer = store.bodies().writer(store.max_body_bytes());
        writer.write(b"request payload");
        let request_meta = writer.finish(None, None);
        let request_body_id = request_meta.id.clone();
        store.update(&gone, |flow| flow.request.body = Some(request_meta));

        assert!(
            store.bodies().read(&request_body_id).is_none(),
            "a body whose flow is gone must be dropped, not left to the global ceiling"
        );

        // The same for a response body, which is attached through the response
        // object rather than the flow directly.
        let mut writer = store.bodies().writer(store.max_body_bytes());
        writer.write(b"response payload");
        let response_meta = writer.finish(None, None);
        let response_body_id = response_meta.id.clone();
        store.update(&gone, |flow| {
            if let Some(response) = flow.response.as_mut() {
                response.body = Some(response_meta);
            }
        });

        assert!(store.bodies().read(&response_body_id).is_none());

        // And for a websocket frame that arrived after the eviction.
        let frame_body_id = ws_body(&store, b"frame payload");
        store.add_ws_message(&gone, ws_frame(Some(frame_body_id.clone())));
        assert!(store.bodies().read(&frame_body_id).is_none());

        assert_eq!(store.bodies().bytes_held(), 0);
        assert!(store.bodies().is_empty());
    }

    #[test]
    fn a_live_flow_still_keeps_the_bodies_it_is_handed() {
        let store = FlowStore::new(4, 1024, 1024 * 1024);
        let id = store.create(init("POST", "api.example.com", "/upload"));
        let body_id = attach_request_body(&store, &id, b"still here");

        assert!(store.bodies().read(&body_id).is_some());
        assert_eq!(store.bodies().bytes_held(), 10);
    }

    #[test]
    fn eviction_drops_the_oldest_flow_and_frees_its_body() {
        let store = FlowStore::new(2, 1024, 1024 * 1024);

        let mut entries = Vec::new();
        for i in 0..3 {
            let id = store.create(init("GET", "api.example.com", &format!("/{i}")));
            let body_id = attach_request_body(&store, &id, b"hello world");
            entries.push((id, body_id));
        }

        assert_eq!(store.len(), 2, "ring buffer must not grow past max_flows");
        assert!(store.get(&entries[0].0).is_none(), "oldest flow evicted");
        assert!(store.get(&entries[1].0).is_some());
        assert!(store.get(&entries[2].0).is_some());

        assert!(
            store.bodies().read(&entries[0].1).is_none(),
            "evicting a flow must drop its body"
        );
        assert!(store.bodies().read(&entries[2].1).is_some());
        assert_eq!(
            store.bodies().bytes_held(),
            22,
            "two surviving bodies of eleven bytes each"
        );
    }

    #[test]
    fn clear_empties_flows_and_bodies() {
        let store = FlowStore::new(10, 1024, 1024 * 1024);
        let mut rx = store.subscribe();
        for i in 0..4 {
            let id = store.create(init("GET", "api.example.com", &format!("/{i}")));
            attach_request_body(&store, &id, b"payload bytes");
        }
        assert!(store.bodies().bytes_held() > 0);

        store.clear();

        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert_eq!(store.bodies().bytes_held(), 0);
        assert!(store.bodies().is_empty());

        let mut saw_clear = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(event, ProxyEvent::Clear) {
                saw_clear = true;
            }
        }
        assert!(saw_clear, "clear must be broadcast");
    }

    #[test]
    fn query_filters_by_host_method_status_and_search() {
        let store = FlowStore::new(100, 1024, 4096);

        let a = store.create(init("GET", "api.example.com", "/users"));
        respond(&store, &a, 200, "application/json");
        let b = store.create(init("POST", "cdn.example.com", "/upload"));
        respond(&store, &b, 500, "text/html");
        let c = store.create(init("GET", "other.net", "/ping"));
        respond(&store, &c, 404, "text/plain");
        let d = store.create(init("GET", "api.example.com", "/pending"));

        let (page, total) = store.query(&FlowQuery::default());
        assert_eq!(total, 4);
        assert_eq!(page.len(), 4);
        assert_eq!(page[0].id, d, "newest first");
        assert_eq!(page[3].id, a);

        let (page, total) = store.query(&FlowQuery {
            hosts: vec!["*.example.com".into()],
            ..FlowQuery::default()
        });
        assert_eq!(total, 3);
        assert!(page.iter().all(|f| f.authority.ends_with("example.com")));

        let (_, total) = store.query(&FlowQuery {
            methods: vec!["post".into()],
            ..FlowQuery::default()
        });
        assert_eq!(total, 1);

        let (page, total) = store.query(&FlowQuery {
            status_range: Some((200, 299)),
            ..FlowQuery::default()
        });
        assert_eq!(total, 1);
        assert_eq!(page[0].id, a);

        let (_, total) = store.query(&FlowQuery {
            status_range: Some((404, 500)),
            ..FlowQuery::default()
        });
        assert_eq!(total, 2, "status_range is inclusive at both ends");

        let (_, total) = store.query(&FlowQuery {
            only_errors: true,
            ..FlowQuery::default()
        });
        assert_eq!(total, 2, "4xx and 5xx count as errors");

        let (_, total) = store.query(&FlowQuery {
            search: Some("UPLOAD".into()),
            ..FlowQuery::default()
        });
        assert_eq!(total, 1, "search is case insensitive over the url");

        let (_, total) = store.query(&FlowQuery {
            search: Some("500".into()),
            ..FlowQuery::default()
        });
        assert_eq!(total, 1, "search matches status");

        let (_, total) = store.query(&FlowQuery {
            search: Some("text/html".into()),
            ..FlowQuery::default()
        });
        assert_eq!(total, 1, "search matches content type");

        let (_, total) = store.query(&FlowQuery {
            kinds: vec![FlowKind::Websocket],
            ..FlowQuery::default()
        });
        assert_eq!(total, 0);
    }

    #[test]
    fn query_limit_and_before_cursor_page_backwards() {
        let store = FlowStore::new(100, 1024, 4096);
        let mut ids = Vec::new();
        for i in 0..10 {
            ids.push(store.create(init("GET", "api.example.com", &format!("/{i}"))));
        }

        let (page, total) = store.query(&FlowQuery {
            limit: Some(4),
            ..FlowQuery::default()
        });
        assert_eq!(total, 10, "total counts matches before limiting");
        assert_eq!(page.len(), 4);
        assert_eq!(page[0].id, ids[9]);
        assert_eq!(page[3].id, ids[6]);

        let cursor = store
            .seq_of(&page[3].id)
            .expect("sequence for the last row");
        let (next, total) = store.query(&FlowQuery {
            limit: Some(4),
            before: Some(cursor),
            ..FlowQuery::default()
        });
        assert_eq!(total, 10, "the cursor does not change the total");
        assert_eq!(next.len(), 4);
        assert_eq!(next[0].id, ids[5], "cursor is exclusive");
        assert_eq!(next[3].id, ids[2]);

        let cursor = store.seq_of(&ids[1]).expect("sequence");
        let (tail, _) = store.query(&FlowQuery {
            before: Some(cursor),
            ..FlowQuery::default()
        });
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].id, ids[0]);

        let (page, _) = store.query(&FlowQuery {
            limit: Some(100_000),
            ..FlowQuery::default()
        });
        assert_eq!(page.len(), 10, "limit is capped, not rejected");
    }

    #[test]
    fn all_returns_every_match_oldest_first() {
        let store = FlowStore::new(100, 1024, 4096);
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = store.create(init("GET", "api.example.com", &format!("/{i}")));
            respond(&store, &id, 200, "application/json");
            ids.push(id);
        }
        store.create(init("GET", "other.net", "/x"));

        let all = store.all(&FlowQuery {
            limit: Some(2),
            hosts: vec!["api.example.com".into()],
            ..FlowQuery::default()
        });
        assert_eq!(all.len(), 5, "all ignores limit");
        assert_eq!(all[0].id, ids[0], "oldest first");
        assert_eq!(all[4].id, ids[4]);
    }
}
