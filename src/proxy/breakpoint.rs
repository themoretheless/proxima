//! Runtime breakpoints: hold a frame (or later an HTTP message) before forward.
//!
//! Rules live only in memory. When any enabled WebSocket rule matches a parsed
//! frame, the pump registers a pause here, publishes `pause:hit`, and waits for
//! release, drop, or the per-rule timeout. No enabled rules means the websocket
//! path stays on its zero-latency byte-copy loop.
//!
//! The protocol is kind-tagged from day one (`ws` now, `http` later) so HTTP
//! request/response pauses can share the same hub, events and resolve API
//! without flattening protocol fields into the top level.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::oneshot;
use tracing::debug;

use crate::capture::{new_id, FlowStore};
use crate::config::host_matches;
use crate::types::{
    now_ms, BreakpointRule, BreakpointRulesBody, FlowId, HeaderPair, HttpPauseHalf, PauseKind,
    PauseResolveAction, PauseResolveReason, PauseHttpBody, PauseSnapshot, PauseWsBody, ProxyEvent,
    WsDirection,
};

/// Caps concurrent held pauses so a flood of matching frames cannot stall the
/// process or fill the broadcast channel with `pause:hit` events. Past the
/// cap, matching frames are forwarded unchanged rather than held.
const MAX_CONCURRENT_PAUSES: usize = 64;

/// Floor when a rule sets `timeoutMs` to zero or omits a useful value.
const MIN_TIMEOUT_MS: u64 = 1_000;
/// Hard ceiling so a typo cannot hold a connection for a day.
const MAX_TIMEOUT_MS: u64 = 300_000;
/// Default when a rule is accepted without a sensible timeout.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// What the pump does with a held frame or HTTP message once the pause is resolved.
#[derive(Debug, Clone)]
pub enum PauseDecision {
    /// Forward this opcode and payload (re-encoded with the half's mask rules).
    Release { opcode: u8, payload: Vec<u8> },
    /// Forward (possibly edited) HTTP request/response bytes.
    HttpRelease {
        method: String,
        url: String,
        headers: Vec<HeaderPair>,
        body: Vec<u8>,
    },
    /// Do not write the frame / abort the HTTP exchange; clear the pause.
    Drop,
}

/// Why a resolve call was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No pause with that id is currently held.
    NotFound,
    /// Already released, dropped, timed out, or cancelled.
    AlreadyResolved,
}

/// One held frame waiting for the user, a timeout, or connection close.
struct Pending {
    snapshot: PauseSnapshot,
    /// Original opcode for timeout auto-release (WS).
    original_opcode: u8,
    /// Original payload for timeout auto-release and default release body (WS
    /// frame, or HTTP body).
    original_payload: Vec<u8>,
    /// Present for HTTP pauses so timeout can re-release the original message.
    original_http: Option<HttpOriginal>,
    /// Delivered once; double-resolve finds the entry gone.
    tx: oneshot::Sender<(PauseDecision, PauseResolveReason)>,
}

#[derive(Clone)]
struct HttpOriginal {
    method: String,
    url: String,
    headers: Vec<HeaderPair>,
}

/// Shared breakpoint rules and held pauses.
///
/// Lookups never hold the mutex across an await. The pump awaits a oneshot
/// returned by [`Self::hold_ws`]; the API resolves through
/// [`Self::resolve`].
#[derive(Default)]
pub struct PauseHub {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    rules: Vec<BreakpointRule>,
    pending: HashMap<String, Pending>,
}

impl PauseHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of the current rule list.
    pub fn rules(&self) -> BreakpointRulesBody {
        BreakpointRulesBody {
            rules: self.inner.lock().rules.clone(),
        }
    }

    /// Replaces the whole rule list. Invalid entries are normalised rather than
    /// rejected so a partial UI save does not leave the proxy with no rules.
    pub fn set_rules(&self, body: BreakpointRulesBody) {
        let mut rules = body.rules;
        for rule in &mut rules {
            normalise_rule(rule);
        }
        let mut inner = self.inner.lock();
        inner.rules = rules;
        debug!(count = inner.rules.len(), "breakpoint rules replaced");
    }

    /// True when at least one enabled WebSocket rule exists. The pump uses this
    /// to switch from byte-copy-first to parse-before-forward.
    pub fn any_ws_enabled(&self) -> bool {
        self.inner
            .lock()
            .rules
            .iter()
            .any(|r| r.enabled && r.kind == PauseKind::Ws)
    }

    /// True when at least one enabled HTTP request-half rule exists.
    pub fn any_http_request_enabled(&self) -> bool {
        self.inner.lock().rules.iter().any(|r| {
            r.enabled
                && r.kind == PauseKind::Http
                && r.http_half.unwrap_or(HttpPauseHalf::Request) == HttpPauseHalf::Request
        })
    }

    /// First enabled HTTP request rule that matches host, path and method.
    pub fn matching_http_request_rule(
        &self,
        host: &str,
        path: &str,
        method: &str,
    ) -> Option<BreakpointRule> {
        self.inner
            .lock()
            .rules
            .iter()
            .find(|r| rule_matches_http_request(r, host, path, method))
            .cloned()
    }

    /// First enabled WS rule that matches host, path, direction and opcode.
    pub fn matching_ws_rule(
        &self,
        host: &str,
        path: &str,
        direction: WsDirection,
        opcode: u8,
    ) -> Option<BreakpointRule> {
        self.inner
            .lock()
            .rules
            .iter()
            .find(|r| rule_matches_ws(r, host, path, direction, opcode))
            .cloned()
    }

    /// Registers a held WS frame. Returns `None` when the concurrent-pause cap
    /// is hit; the caller must then forward the original without pausing.
    pub fn hold_ws(
        &self,
        store: &FlowStore,
        flow_id: FlowId,
        direction: WsDirection,
        opcode: u8,
        size: u64,
        truncated: bool,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Option<(String, oneshot::Receiver<(PauseDecision, PauseResolveReason)>)> {
        let timeout_ms = clamp_timeout(timeout_ms);
        let (tx, rx) = oneshot::channel();
        let pause_id = new_id();
        let created_at = now_ms();
        let expires_at = created_at.saturating_add(timeout_ms);
        let ws = PauseWsBody {
            direction,
            opcode,
            size,
            truncated,
            text: snapshot_text(opcode, payload),
            data_base64: snapshot_base64(opcode, payload),
        };
        let snapshot = PauseSnapshot {
            pause_id: pause_id.clone(),
            flow_id: flow_id.clone(),
            kind: PauseKind::Ws,
            created_at,
            expires_at,
            ws: Some(ws),
            http: None,
        };

        {
            let mut inner = self.inner.lock();
            if inner.pending.len() >= MAX_CONCURRENT_PAUSES {
                debug!(
                    %flow_id,
                    cap = MAX_CONCURRENT_PAUSES,
                    "pause cap reached; forwarding without hold"
                );
                return None;
            }
            inner.pending.insert(
                pause_id.clone(),
                Pending {
                    snapshot: snapshot.clone(),
                    original_opcode: opcode,
                    original_payload: payload.to_vec(),
                    original_http: None,
                    tx,
                },
            );
        }

        store.publish(ProxyEvent::PauseHit {
            pause: Box::new(snapshot),
        });
        Some((pause_id, rx))
    }

    /// Registers a held HTTP request. Same cap behaviour as [`Self::hold_ws`].
    pub fn hold_http_request(
        &self,
        store: &FlowStore,
        flow_id: FlowId,
        method: String,
        url: String,
        headers: Vec<HeaderPair>,
        body: &[u8],
        truncated: bool,
        timeout_ms: u64,
    ) -> Option<(String, oneshot::Receiver<(PauseDecision, PauseResolveReason)>)> {
        let timeout_ms = clamp_timeout(timeout_ms);
        let (tx, rx) = oneshot::channel();
        let pause_id = new_id();
        let created_at = now_ms();
        let expires_at = created_at.saturating_add(timeout_ms);
        let http = PauseHttpBody {
            half: HttpPauseHalf::Request,
            method: method.clone(),
            url: url.clone(),
            headers: headers.clone(),
            size: body.len() as u64,
            truncated,
            text: snapshot_text(1, body),
            data_base64: snapshot_base64(1, body),
        };
        let snapshot = PauseSnapshot {
            pause_id: pause_id.clone(),
            flow_id: flow_id.clone(),
            kind: PauseKind::Http,
            created_at,
            expires_at,
            ws: None,
            http: Some(http),
        };

        {
            let mut inner = self.inner.lock();
            if inner.pending.len() >= MAX_CONCURRENT_PAUSES {
                debug!(
                    %flow_id,
                    cap = MAX_CONCURRENT_PAUSES,
                    "pause cap reached; forwarding HTTP without hold"
                );
                return None;
            }
            inner.pending.insert(
                pause_id.clone(),
                Pending {
                    snapshot: snapshot.clone(),
                    original_opcode: 0,
                    original_payload: body.to_vec(),
                    original_http: Some(HttpOriginal {
                        method,
                        url,
                        headers,
                    }),
                    tx,
                },
            );
        }

        store.publish(ProxyEvent::PauseHit {
            pause: Box::new(snapshot),
        });
        Some((pause_id, rx))
    }

    /// User or timeout resolve. On success the oneshot is fired and
    /// `pause:resolved` is published. Double-resolve is [`ResolveError::AlreadyResolved`].
    pub fn resolve(
        &self,
        store: &FlowStore,
        pause_id: &str,
        decision: PauseDecision,
        reason: PauseResolveReason,
    ) -> Result<PauseSnapshot, ResolveError> {
        let pending = {
            let mut inner = self.inner.lock();
            inner
                .pending
                .remove(pause_id)
                .ok_or(ResolveError::NotFound)?
        };
        let action = match &decision {
            PauseDecision::Release { .. } | PauseDecision::HttpRelease { .. } => {
                PauseResolveAction::Release
            }
            PauseDecision::Drop => PauseResolveAction::Drop,
        };
        let snapshot = pending.snapshot;
        // If the pump already timed out and dropped the receiver, the send
        // fails; still emit resolved once for the API caller so the UI clears.
        let _ = pending.tx.send((decision, reason));
        store.publish(ProxyEvent::PauseResolved {
            pause_id: snapshot.pause_id.clone(),
            flow_id: snapshot.flow_id.clone(),
            action,
            reason,
        });
        Ok(snapshot)
    }

    /// Timeout path: auto-release the original frame if still pending.
    ///
    /// Returns the decision the pump should apply. When the pause was already
    /// resolved (user won the race), returns `None` so the pump does nothing
    /// further with this id (the oneshot already delivered the user decision).
    pub fn resolve_timeout(
        &self,
        store: &FlowStore,
        pause_id: &str,
    ) -> Option<PauseDecision> {
        let pending = {
            let mut inner = self.inner.lock();
            inner.pending.remove(pause_id)?
        };
        let decision = if let Some(http) = pending.original_http {
            PauseDecision::HttpRelease {
                method: http.method,
                url: http.url,
                headers: http.headers,
                body: pending.original_payload,
            }
        } else {
            PauseDecision::Release {
                opcode: pending.original_opcode,
                payload: pending.original_payload,
            }
        };
        let _ = pending.tx.send((decision.clone(), PauseResolveReason::Timeout));
        store.publish(ProxyEvent::PauseResolved {
            pause_id: pending.snapshot.pause_id.clone(),
            flow_id: pending.snapshot.flow_id.clone(),
            action: PauseResolveAction::Release,
            reason: PauseResolveReason::Timeout,
        });
        Some(decision)
    }

    /// Connection closed: drop every pause for this flow without forwarding.
    pub fn cancel_flow(&self, store: &FlowStore, flow_id: &str) {
        let cancelled: Vec<Pending> = {
            let mut inner = self.inner.lock();
            let ids: Vec<String> = inner
                .pending
                .iter()
                .filter(|(_, p)| p.snapshot.flow_id == flow_id)
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| inner.pending.remove(&id))
                .collect()
        };
        for pending in cancelled {
            let _ = pending
                .tx
                .send((PauseDecision::Drop, PauseResolveReason::Closed));
            store.publish(ProxyEvent::PauseResolved {
                pause_id: pending.snapshot.pause_id,
                flow_id: pending.snapshot.flow_id,
                action: PauseResolveAction::Drop,
                reason: PauseResolveReason::Closed,
            });
        }
    }

    /// All currently held pauses, newest first by creation time.
    pub fn list(&self) -> Vec<PauseSnapshot> {
        let mut list: Vec<PauseSnapshot> = self
            .inner
            .lock()
            .pending
            .values()
            .map(|p| p.snapshot.clone())
            .collect();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list
    }

    pub fn get(&self, pause_id: &str) -> Option<PauseSnapshot> {
        self.inner
            .lock()
            .pending
            .get(pause_id)
            .map(|p| p.snapshot.clone())
    }

    /// Original frame stored for a pending pause (used when release omits a body).
    pub fn original(&self, pause_id: &str) -> Option<(u8, Vec<u8>)> {
        self.inner.lock().pending.get(pause_id).map(|p| {
            (
                p.original_opcode,
                p.original_payload.clone(),
            )
        })
    }

    pub fn pending_count(&self) -> usize {
        self.inner.lock().pending.len()
    }
}

/// Awaits a held pause's decision, auto-releasing the original on timeout.
///
/// The oneshot is the source of truth for the user path. On wall-clock timeout
/// we try [`PauseHub::resolve_timeout`]; if the user already won, we still take
/// the oneshot result (which may already be ready).
pub async fn await_decision(
    hub: &PauseHub,
    store: &FlowStore,
    pause_id: &str,
    timeout_ms: u64,
    mut rx: oneshot::Receiver<(PauseDecision, PauseResolveReason)>,
) -> PauseDecision {
    // Caller passes the rule timeout (already clamped when rules were set). A
    // floor of 1 ms keeps zero from meaning "wait forever".
    let timeout = Duration::from_millis(timeout_ms.max(1));
    match tokio::time::timeout(timeout, &mut rx).await {
        Ok(Ok((decision, _reason))) => decision,
        Ok(Err(_)) => {
            // Sender dropped without a send: treat as drop.
            PauseDecision::Drop
        }
        Err(_) => {
            // Wall clock: claim timeout if still pending.
            if let Some(decision) = hub.resolve_timeout(store, pause_id) {
                return decision;
            }
            // User resolved in the race window; take that decision if present.
            match rx.try_recv() {
                Ok((decision, _)) => decision,
                Err(_) => PauseDecision::Drop,
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* rule matching                                                       */
/* ------------------------------------------------------------------ */

fn rule_matches_http_request(rule: &BreakpointRule, host: &str, path: &str, method: &str) -> bool {
    if !rule.enabled || rule.kind != PauseKind::Http {
        return false;
    }
    if rule.http_half.unwrap_or(HttpPauseHalf::Request) != HttpPauseHalf::Request {
        return false;
    }
    if !rule.hosts.is_empty() && !rule.hosts.iter().any(|p| host_matches(host, p)) {
        return false;
    }
    if let Some(prefix) = rule.path_prefix.as_deref() {
        if !prefix.is_empty() && !path.starts_with(prefix) {
            return false;
        }
    }
    if !rule.methods.is_empty()
        && !rule
            .methods
            .iter()
            .any(|m| m.trim().eq_ignore_ascii_case(method))
    {
        return false;
    }
    true
}

fn rule_matches_ws(
    rule: &BreakpointRule,
    host: &str,
    path: &str,
    direction: WsDirection,
    opcode: u8,
) -> bool {
    if !rule.enabled || rule.kind != PauseKind::Ws {
        return false;
    }
    if !rule.hosts.is_empty() && !rule.hosts.iter().any(|p| host_matches(host, p)) {
        return false;
    }
    if let Some(prefix) = rule.path_prefix.as_deref() {
        if !prefix.is_empty() && !path.starts_with(prefix) {
            return false;
        }
    }
    if !rule.directions.is_empty() && !rule.directions.contains(&direction) {
        return false;
    }
    let opcodes = effective_opcodes(rule);
    opcodes.contains(&opcode)
}

/// Empty opcodes on a WS rule mean data frames only (text + binary).
fn effective_opcodes(rule: &BreakpointRule) -> Vec<u8> {
    if rule.opcodes.is_empty() {
        vec![1, 2]
    } else {
        rule.opcodes.clone()
    }
}

fn normalise_rule(rule: &mut BreakpointRule) {
    if rule.id.is_empty() {
        rule.id = new_id();
    }
    rule.timeout_ms = clamp_timeout(if rule.timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        rule.timeout_ms
    });
    // Drop nonsense opcodes rather than pausing on reserved values.
    rule.opcodes
        .retain(|op| matches!(*op, 0x0..=0x2 | 0x8..=0xa));
}

fn clamp_timeout(ms: u64) -> u64 {
    if ms == 0 {
        return MIN_TIMEOUT_MS;
    }
    ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS)
}

const INLINE_TEXT_LIMIT: usize = 4 * 1024;

fn snapshot_text(opcode: u8, payload: &[u8]) -> Option<String> {
    if opcode == 1 && payload.len() <= INLINE_TEXT_LIMIT {
        String::from_utf8(payload.to_vec()).ok()
    } else {
        None
    }
}

fn snapshot_base64(opcode: u8, payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }
    // Prefer text for small UTF-8 text frames; otherwise base64 the retained bytes.
    if snapshot_text(opcode, payload).is_some() {
        return None;
    }
    use base64::Engine as _;
    Some(base64::engine::general_purpose::STANDARD.encode(payload))
}

/// Shared context handed to the websocket pump when breakpoints may apply.
#[derive(Clone)]
pub struct WsPauseContext {
    pub hub: Arc<PauseHub>,
    pub host: String,
    pub path: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BreakpointRulesBody;

    fn store() -> FlowStore {
        FlowStore::new(8, 1024, 64 * 1024)
    }

    fn ws_rule(id: &str, opcodes: Vec<u8>, timeout_ms: u64) -> BreakpointRule {
        BreakpointRule {
            id: id.into(),
            enabled: true,
            kind: PauseKind::Ws,
            hosts: vec![],
            path_prefix: None,
            directions: vec![],
            opcodes,
            timeout_ms,
            http_half: None,
            methods: vec![],
        }
    }

    #[test]
    fn empty_opcodes_default_to_text_and_binary_not_control() {
        let hub = PauseHub::new();
        hub.set_rules(BreakpointRulesBody {
            rules: vec![ws_rule("r1", vec![], 5_000)],
        });
        assert!(hub
            .matching_ws_rule("h", "/", WsDirection::Send, 1)
            .is_some());
        assert!(hub
            .matching_ws_rule("h", "/", WsDirection::Send, 2)
            .is_some());
        assert!(hub
            .matching_ws_rule("h", "/", WsDirection::Send, 8)
            .is_none());
        assert!(hub
            .matching_ws_rule("h", "/", WsDirection::Send, 9)
            .is_none());
        assert!(hub
            .matching_ws_rule("h", "/", WsDirection::Send, 10)
            .is_none());
    }

    #[test]
    fn host_and_path_and_direction_filter() {
        let hub = PauseHub::new();
        hub.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "r1".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec!["*.example.com".into()],
                path_prefix: Some("/api".into()),
                directions: vec![WsDirection::Send],
                opcodes: vec![1],
                timeout_ms: 5_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        assert!(hub
            .matching_ws_rule("api.example.com", "/api/v1", WsDirection::Send, 1)
            .is_some());
        assert!(hub
            .matching_ws_rule("other.com", "/api/v1", WsDirection::Send, 1)
            .is_none());
        assert!(hub
            .matching_ws_rule("api.example.com", "/other", WsDirection::Send, 1)
            .is_none());
        assert!(hub
            .matching_ws_rule("api.example.com", "/api/v1", WsDirection::Recv, 1)
            .is_none());
    }

    #[test]
    fn disabled_rules_do_not_match_and_any_ws_enabled_tracks() {
        let hub = PauseHub::new();
        assert!(!hub.any_ws_enabled());
        hub.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "r1".into(),
                enabled: false,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 5_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        assert!(!hub.any_ws_enabled());
        assert!(hub
            .matching_ws_rule("h", "/", WsDirection::Send, 1)
            .is_none());
        hub.set_rules(BreakpointRulesBody {
            rules: vec![ws_rule("r1", vec![1], 5_000)],
        });
        assert!(hub.any_ws_enabled());
    }

    #[tokio::test]
    async fn hold_and_user_release() {
        let hub = Arc::new(PauseHub::new());
        let store = store();
        let mut events = store.subscribe();

        let (pause_id, rx) = hub
            .hold_ws(
                &store,
                "flow-1".into(),
                WsDirection::Send,
                1,
                5,
                false,
                b"hello",
                5_000,
            )
            .expect("held");

        let hit = events.recv().await.expect("pause:hit");
        match hit {
            ProxyEvent::PauseHit { pause } => {
                assert_eq!(pause.pause_id, pause_id);
                assert_eq!(pause.kind, PauseKind::Ws);
                assert_eq!(pause.ws.as_ref().unwrap().text.as_deref(), Some("hello"));
            }
            other => panic!("expected pause:hit, got {other:?}"),
        }

        hub.resolve(
            &store,
            &pause_id,
            PauseDecision::Release {
                opcode: 1,
                payload: b"edited".to_vec(),
            },
            PauseResolveReason::User,
        )
        .expect("resolve");

        let (decision, reason) = rx.await.expect("decision");
        assert!(matches!(
            decision,
            PauseDecision::Release { opcode: 1, payload } if payload == b"edited"
        ));
        assert_eq!(reason, PauseResolveReason::User);

        let resolved = events.recv().await.expect("pause:resolved");
        assert!(matches!(
            resolved,
            ProxyEvent::PauseResolved {
                action: PauseResolveAction::Release,
                reason: PauseResolveReason::User,
                ..
            }
        ));

        assert!(matches!(
            hub.resolve(
                &store,
                &pause_id,
                PauseDecision::Drop,
                PauseResolveReason::User
            ),
            Err(ResolveError::NotFound) | Err(ResolveError::AlreadyResolved)
        ));
        assert_eq!(hub.pending_count(), 0);
    }

    #[tokio::test]
    async fn drop_does_not_forward_decision_is_drop() {
        let hub = PauseHub::new();
        let store = store();
        let (pause_id, rx) = hub
            .hold_ws(
                &store,
                "flow-1".into(),
                WsDirection::Recv,
                2,
                3,
                false,
                &[1, 2, 3],
                5_000,
            )
            .expect("held");
        hub.resolve(
            &store,
            &pause_id,
            PauseDecision::Drop,
            PauseResolveReason::User,
        )
        .expect("drop");
        let (decision, _) = rx.await.expect("decision");
        assert!(matches!(decision, PauseDecision::Drop));
    }

    #[tokio::test]
    async fn timeout_auto_releases_original() {
        let hub = Arc::new(PauseHub::new());
        let store = Arc::new(store());
        let (pause_id, rx) = hub
            .hold_ws(
                &store,
                "flow-1".into(),
                WsDirection::Send,
                1,
                3,
                false,
                b"orig",
                // clamp will raise this to MIN_TIMEOUT_MS for real rules; call
                // await_decision with a tiny timeout directly for the test.
                30_000,
            )
            .expect("held");

        // Drive the short timeout ourselves rather than waiting MIN_TIMEOUT_MS.
        let decision = {
            let hub = hub.clone();
            let store = store.clone();
            let pause_id = pause_id.clone();
            tokio::spawn(async move {
                await_decision(&hub, &store, &pause_id, 50, rx).await
            })
            .await
            .expect("join")
        };

        match decision {
            PauseDecision::Release { opcode, payload } => {
                assert_eq!(opcode, 1);
                assert_eq!(payload, b"orig");
            }
            PauseDecision::Drop => panic!("timeout should release original"),
            PauseDecision::HttpRelease { .. } => panic!("WS timeout must not yield HTTP"),
        }
        assert_eq!(hub.pending_count(), 0);
    }

    #[tokio::test]
    async fn cancel_flow_drops_pending() {
        let hub = PauseHub::new();
        let store = store();
        let (pause_id, rx) = hub
            .hold_ws(
                &store,
                "flow-x".into(),
                WsDirection::Send,
                1,
                1,
                false,
                b"a",
                30_000,
            )
            .expect("held");
        hub.cancel_flow(&store, "flow-x");
        let (decision, reason) = rx.await.expect("decision");
        assert!(matches!(decision, PauseDecision::Drop));
        assert_eq!(reason, PauseResolveReason::Closed);
        assert!(hub.get(&pause_id).is_none());
    }

    #[test]
    fn pause_cap_refuses_further_holds() {
        let hub = PauseHub::new();
        let store = store();
        for i in 0..MAX_CONCURRENT_PAUSES {
            assert!(
                hub.hold_ws(
                    &store,
                    format!("f{i}"),
                    WsDirection::Send,
                    1,
                    1,
                    false,
                    b"x",
                    30_000,
                )
                .is_some(),
                "hold {i}"
            );
        }
        assert!(hub
            .hold_ws(
                &store,
                "overflow".into(),
                WsDirection::Send,
                1,
                1,
                false,
                b"x",
                30_000,
            )
            .is_none());
    }

    #[test]
    fn set_rules_normalises_id_timeout_and_opcodes() {
        let hub = PauseHub::new();
        hub.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: String::new(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                // 99 is reserved nonsense; 1 and 9 are kept.
                opcodes: vec![1, 99, 9],
                timeout_ms: 0,
                        http_half: None,
            methods: vec![],
        }],
        });
        let rules = hub.rules().rules;
        assert_eq!(rules.len(), 1);
        assert!(!rules[0].id.is_empty(), "empty id is replaced");
        assert_eq!(
            rules[0].timeout_ms, DEFAULT_TIMEOUT_MS,
            "zero timeout becomes the default then clamp"
        );
        assert_eq!(rules[0].opcodes, vec![1, 9]);

        hub.set_rules(BreakpointRulesBody {
            rules: vec![ws_rule("long", vec![1], MAX_TIMEOUT_MS + 1)],
        });
        assert_eq!(hub.rules().rules[0].timeout_ms, MAX_TIMEOUT_MS);
    }

    #[test]
    fn http_kind_rules_do_not_enable_or_match_ws() {
        // Shared protocol leaves an Http variant for later; the WS path must
        // ignore it so enabling an HTTP rule does not flip parse-before-forward.
        let hub = PauseHub::new();
        hub.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "http-later".into(),
                enabled: true,
                kind: PauseKind::Http,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 5_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        assert!(!hub.any_ws_enabled());
        assert!(hub
            .matching_ws_rule("h", "/", WsDirection::Send, 1)
            .is_none());
    }

    #[test]
    fn binary_payload_snapshot_uses_base64_not_text() {
        let hub = PauseHub::new();
        let store = store();
        let (pause_id, _rx) = hub
            .hold_ws(
                &store,
                "flow-bin".into(),
                WsDirection::Recv,
                2,
                2,
                false,
                &[0xde, 0xad],
                5_000,
            )
            .expect("held");
        let snap = hub.get(&pause_id).expect("listed");
        let ws = snap.ws.expect("ws body");
        assert!(ws.text.is_none());
        assert_eq!(ws.data_base64.as_deref(), Some("3q0="));
        assert!(snap.expires_at > snap.created_at);
    }

    #[test]
    fn pause_hit_event_json_is_kind_tagged_with_nested_ws() {
        // Wire shape shared with future HTTP pauses: envelope fields + kind body.
        let event = ProxyEvent::PauseHit {
            pause: Box::new(PauseSnapshot {
                pause_id: "p1".into(),
                flow_id: "f1".into(),
                kind: PauseKind::Ws,
                created_at: 100,
                expires_at: 31_100,
                ws: Some(PauseWsBody {
                    direction: WsDirection::Send,
                    opcode: 1,
                    size: 5,
                    truncated: false,
                    text: Some("hello".into()),
                    data_base64: None,
                }),
                http: None,
            }),
        };
        let value = serde_json::to_value(&event).expect("serialize");
        assert_eq!(value["type"], "pause:hit");
        let pause = &value["pause"];
        assert_eq!(pause["pauseId"], "p1");
        assert_eq!(pause["flowId"], "f1");
        assert_eq!(pause["kind"], "ws");
        assert_eq!(pause["createdAt"], 100);
        assert_eq!(pause["expiresAt"], 31_100);
        assert_eq!(pause["ws"]["direction"], "send");
        assert_eq!(pause["ws"]["opcode"], 1);
        assert_eq!(pause["ws"]["text"], "hello");
        // No flattened ws fields at the top level of the event.
        assert!(value.get("opcode").is_none());
        assert!(value.get("direction").is_none());

        let resolved = ProxyEvent::PauseResolved {
            pause_id: "p1".into(),
            flow_id: "f1".into(),
            action: PauseResolveAction::Drop,
            reason: PauseResolveReason::Closed,
        };
        let value = serde_json::to_value(&resolved).expect("serialize");
        assert_eq!(value["type"], "pause:resolved");
        assert_eq!(value["pauseId"], "p1");
        assert_eq!(value["action"], "drop");
        assert_eq!(value["reason"], "closed");
    }

    #[tokio::test]
    async fn user_release_wins_over_timeout_race() {
        let hub = Arc::new(PauseHub::new());
        let store = Arc::new(store());
        let (pause_id, rx) = hub
            .hold_ws(
                &store,
                "flow-1".into(),
                WsDirection::Send,
                1,
                3,
                false,
                b"orig",
                30_000,
            )
            .expect("held");

        hub.resolve(
            &store,
            &pause_id,
            PauseDecision::Release {
                opcode: 1,
                payload: b"user".to_vec(),
            },
            PauseResolveReason::User,
        )
        .expect("user first");

        let decision = await_decision(&hub, &store, &pause_id, 5_000, rx).await;
        match decision {
            PauseDecision::Release { opcode, payload } => {
                assert_eq!(opcode, 1);
                assert_eq!(payload, b"user");
            }
            PauseDecision::Drop => panic!("user release must win"),
            PauseDecision::HttpRelease { .. } => panic!("WS release must not yield HTTP"),
        }
        // Timeout after user resolve must not invent a second write.
        assert!(hub.resolve_timeout(&store, &pause_id).is_none());
        assert_eq!(hub.pending_count(), 0);
    }

    #[tokio::test]
    async fn timeout_then_user_resolve_is_not_found() {
        let hub = Arc::new(PauseHub::new());
        let store = Arc::new(store());
        let (pause_id, rx) = hub
            .hold_ws(
                &store,
                "flow-1".into(),
                WsDirection::Send,
                1,
                4,
                false,
                b"orig",
                30_000,
            )
            .expect("held");

        let decision = await_decision(&hub, &store, &pause_id, 40, rx).await;
        assert!(matches!(
            decision,
            PauseDecision::Release { payload, .. } if payload == b"orig"
        ));

        assert!(matches!(
            hub.resolve(
                &store,
                &pause_id,
                PauseDecision::Drop,
                PauseResolveReason::User
            ),
            Err(ResolveError::NotFound) | Err(ResolveError::AlreadyResolved)
        ));
    }
}
