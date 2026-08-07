//! Declarative rewrite and drop rules for upgraded WebSocket frames.
//!
//! HTTP header rewrites live in [`super::rewrite`] and only touch a
//! [`http::HeaderMap`]. Frame rewrites are a different job: they match on
//! direction, opcode and optional text payload, then either replace the full
//! payload or drop the frame before it is written. Keeping them in a separate
//! module stops WS rules from growing HTTP types and keeps the HeaderMap path
//! free of frame state.
//!
//! # Scope and limits (read before relying on a match)
//!
//! - **Per frame, not reassembly.** Each RFC 6455 frame is matched on its own.
//!   A fragmented text message split across continuation frames will not match
//!   a `text_regex` as one logical message.
//! - **Parse-before-forward only.** When any rule is non-empty (or any WS
//!   breakpoint is enabled), the pump parses each frame before writing it.
//!   Re-encoding may change the mask key; opcode and payload are what the rule
//!   left. With an empty rule list and no breakpoints, the zero-latency
//!   byte-copy observe path is unchanged.
//! - **Opaque and extension limits.** Broken framing forces opaque byte-copy.
//!   When permessage-deflate is negotiated on the 101, the pump also stays on
//!   raw-copy (no re-encode): structured rewrite / text_regex cannot usefully
//!   match compressed payloads, and re-encoding would strip RSV1 and break
//!   peers. Capture still inflates a copy for display; inject stays uncompressed.
//! - **Rewrite before pause.** Breakpoints observe the post-rewrite opcode and
//!   payload. A held frame is already rewritten; release forwards that body
//!   unless the user edits it again.
//! - **Capture honesty.** What goes on the wire is what is recorded in
//!   `ws_messages`. A replace leaves a note on [`crate::types::Flow::rewrites`]
//!   and records the rewritten frame. A drop leaves only a rewrite note: there
//!   is no `ws_message` for a frame that never left the proxy. Drop notes must
//!   not reuse the capture eviction marker (`WS_DROPPED_OPCODE`); that opcode
//!   means ring-buffer eviction, not a rewrite rule.
//! - **Inject skips rewrite.** Frames composed through the inject API are
//!   encoded and written as given. Config rules deliberately do not re-touch
//!   operator-injected traffic.
//! - **Runtime replaceable.** Startup config seeds the engine; the inspector
//!   and `GET|PUT /api/ws-rewrite` replace the whole list without restarting.
//!   Enabling rules mid-connection switches the pump into parse-before-forward
//!   on the next read (sticky for that half), same idea as breakpoints.

use std::sync::Arc;

use base64::Engine as _;
use parking_lot::Mutex;
use regex::Regex;
use tracing::debug;

use crate::config::{host_matches, WsRewriteRule, WsRewriteRules, WsRewriteRulesBody};
use crate::types::WsDirection;

/// Payloads larger than this skip `text_regex` matching so a pathological
/// pattern cannot run over multi-megabyte frames on the hot path.
const MAX_REGEX_PAYLOAD: usize = 1024 * 1024;

/// Result of applying the rule list to one parsed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsRewriteOutcome {
    /// Write this opcode and payload (may be unchanged or fully replaced).
    Forward {
        opcode: u8,
        payload: Vec<u8>,
        notes: Vec<String>,
    },
    /// Do not write the frame; do not record a `ws_message`.
    Drop { notes: Vec<String> },
}

/// Compiled, ready-to-apply WebSocket rewrite rules.
///
/// Built from config or a runtime PUT via [`Self::compile`]. Invalid
/// `text_regex` or `replace_base64` fails construction with a clear error
/// instead of matching nothing at runtime. Live traffic uses [`WsRewriteHub`],
/// which holds one of these and can swap it under a lock.
#[derive(Debug, Clone)]
pub struct WsRewriteEngine {
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    hosts: Vec<String>,
    path_prefix: Option<String>,
    directions: Vec<WsDirection>,
    /// Empty means text + binary at match time.
    opcodes: Vec<u8>,
    text_regex: Option<Regex>,
    drop: bool,
    /// When set and `drop` is false, full payload replacement.
    replace: Option<Vec<u8>>,
    /// Human-readable action label for notes.
    action_label: String,
}

impl WsRewriteEngine {
    /// An engine that never rewrites. Cheap to share and keeps the observe path
    /// on byte-copy when no other force is present.
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// True when no rule would drop or replace a frame.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Compiles config rules. Skips noops. Fails on invalid regex or base64.
    pub fn compile(rules: &WsRewriteRules) -> Result<Self, String> {
        let mut compiled = Vec::new();
        for (index, rule) in rules.rules.iter().enumerate() {
            if rule.is_noop() {
                continue;
            }
            compiled.push(
                compile_one(rule).map_err(|err| format!("ws rewrite rule #{index}: {err}"))?,
            );
        }
        Ok(Self { rules: compiled })
    }

    /// Applies the first matching rule. Non-matching frames return
    /// [`WsRewriteOutcome::Forward`] with empty notes and the original payload.
    pub fn apply(
        &self,
        host: &str,
        path: &str,
        direction: WsDirection,
        opcode: u8,
        payload: &[u8],
    ) -> WsRewriteOutcome {
        for rule in &self.rules {
            if !rule_matches(rule, host, path, direction, opcode, payload) {
                continue;
            }
            if rule.drop {
                return WsRewriteOutcome::Drop {
                    notes: vec![format!(
                        "websocket {} frame opcode {} dropped ({})",
                        direction_label(direction),
                        opcode,
                        rule.action_label
                    )],
                };
            }
            if let Some(replacement) = &rule.replace {
                return WsRewriteOutcome::Forward {
                    opcode,
                    payload: replacement.clone(),
                    notes: vec![format!(
                        "websocket {} frame opcode {} payload replaced ({} bytes -> {} bytes, {})",
                        direction_label(direction),
                        opcode,
                        payload.len(),
                        replacement.len(),
                        rule.action_label
                    )],
                };
            }
        }
        WsRewriteOutcome::Forward {
            opcode,
            payload: payload.to_vec(),
            notes: Vec::new(),
        }
    }
}

/// Shared, replaceable WebSocket rewrite rules for the proxy and the inspector.
///
/// Lookups never hold the mutex across an await: [`Self::apply`] is synchronous
/// and short. The source rule list is kept so GET returns what PUT last set
/// (including noops), while the engine only keeps actionable compiled rules.
#[derive(Debug, Default)]
pub struct WsRewriteHub {
    inner: Mutex<HubInner>,
}

#[derive(Debug)]
struct HubInner {
    /// Last accepted rule list, as the API sees it.
    source: Vec<WsRewriteRule>,
    engine: WsRewriteEngine,
}

impl Default for HubInner {
    fn default() -> Self {
        Self {
            source: Vec::new(),
            engine: WsRewriteEngine::empty(),
        }
    }
}

impl WsRewriteHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty hub: byte-copy observe path unless breakpoints force parse.
    pub fn empty() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Compiles config rules into a hub. Same errors as [`WsRewriteEngine::compile`].
    pub fn compile(rules: &WsRewriteRules) -> Result<Arc<Self>, String> {
        let engine = WsRewriteEngine::compile(rules)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(HubInner {
                source: rules.rules.clone(),
                engine,
            }),
        }))
    }

    /// Snapshot of the last accepted rule list (envelope for the REST API).
    pub fn rules(&self) -> WsRewriteRulesBody {
        WsRewriteRulesBody {
            rules: self.inner.lock().source.clone(),
        }
    }

    /// Replaces the whole rule list. Rejects invalid regex or base64 with a
    /// clear message so a bad PUT does not wipe working rules.
    pub fn set_rules(&self, body: WsRewriteRulesBody) -> Result<WsRewriteRulesBody, String> {
        let rules = WsRewriteRules::from(body);
        let engine = WsRewriteEngine::compile(&rules)?;
        let mut inner = self.inner.lock();
        inner.source = rules.rules.clone();
        inner.engine = engine;
        debug!(count = inner.source.len(), "ws rewrite rules replaced");
        Ok(WsRewriteRulesBody {
            rules: rules.rules,
        })
    }

    /// True when no compiled rule would drop or replace a frame.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().engine.is_empty()
    }

    /// Applies the first matching compiled rule (see [`WsRewriteEngine::apply`]).
    pub fn apply(
        &self,
        host: &str,
        path: &str,
        direction: WsDirection,
        opcode: u8,
        payload: &[u8],
    ) -> WsRewriteOutcome {
        self.inner
            .lock()
            .engine
            .apply(host, path, direction, opcode, payload)
    }
}

fn compile_one(rule: &WsRewriteRule) -> Result<CompiledRule, String> {
    let text_regex = match rule.text_regex.as_deref() {
        Some(pattern) if !pattern.is_empty() => Some(Regex::new(pattern).map_err(|err| {
            format!("invalid text_regex {pattern:?}: {err}")
        })?),
        _ => None,
    };

    let replace = if rule.drop {
        None
    } else if let Some(text) = rule.replace_text.as_ref() {
        Some(text.as_bytes().to_vec())
    } else if let Some(b64) = rule.replace_base64.as_ref() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|err| format!("invalid replace_base64: {err}"))?;
        Some(bytes)
    } else {
        None
    };

    let action_label = if rule.drop {
        "drop".to_string()
    } else if rule.replace_text.is_some() {
        "replace_text".to_string()
    } else {
        "replace_base64".to_string()
    };

    // Drop nonsense opcodes rather than matching reserved values by accident.
    let mut opcodes = rule.opcodes.clone();
    opcodes.retain(|op| matches!(*op, 0x0..=0x2 | 0x8..=0xa));

    Ok(CompiledRule {
        hosts: rule.hosts.clone(),
        path_prefix: rule.path_prefix.clone(),
        directions: rule.directions.clone(),
        opcodes,
        text_regex,
        drop: rule.drop,
        replace,
        action_label,
    })
}

fn rule_matches(
    rule: &CompiledRule,
    host: &str,
    path: &str,
    direction: WsDirection,
    opcode: u8,
    payload: &[u8],
) -> bool {
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
    if !opcodes.contains(&opcode) {
        return false;
    }
    if let Some(re) = &rule.text_regex {
        if payload.len() > MAX_REGEX_PAYLOAD {
            return false;
        }
        let Ok(text) = std::str::from_utf8(payload) else {
            return false;
        };
        if !re.is_match(text) {
            return false;
        }
    }
    true
}

/// Empty opcodes mean data frames only (text + binary), never control.
fn effective_opcodes(rule: &CompiledRule) -> Vec<u8> {
    if rule.opcodes.is_empty() {
        vec![1, 2]
    } else {
        rule.opcodes.clone()
    }
}

fn direction_label(direction: WsDirection) -> &'static str {
    match direction {
        WsDirection::Send => "send",
        WsDirection::Recv => "recv",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WsRewriteRule;

    fn engine(rules: Vec<WsRewriteRule>) -> WsRewriteEngine {
        WsRewriteEngine::compile(&WsRewriteRules { rules }).expect("compile")
    }

    #[test]
    fn empty_engine_forwards_unchanged() {
        let eng = WsRewriteEngine::empty();
        assert!(eng.is_empty());
        match eng.apply("h", "/", WsDirection::Send, 1, b"hi") {
            WsRewriteOutcome::Forward {
                opcode,
                payload,
                notes,
            } => {
                assert_eq!(opcode, 1);
                assert_eq!(payload, b"hi");
                assert!(notes.is_empty());
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn replace_text_changes_payload_and_notes() {
        let eng = engine(vec![WsRewriteRule {
            replace_text: Some("rewritten".into()),
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Send, 1, b"original") {
            WsRewriteOutcome::Forward {
                opcode,
                payload,
                notes,
            } => {
                assert_eq!(opcode, 1);
                assert_eq!(payload, b"rewritten");
                assert_eq!(notes.len(), 1);
                assert!(notes[0].contains("replaced"));
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn drop_rule_does_not_forward() {
        let eng = engine(vec![WsRewriteRule {
            drop: true,
            text_regex: Some("secret".into()),
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Recv, 1, b"has secret here") {
            WsRewriteOutcome::Drop { notes } => {
                assert_eq!(notes.len(), 1);
                assert!(notes[0].contains("dropped"));
            }
            other => panic!("expected drop, got {other:?}"),
        }
        // Non-matching text still goes through.
        match eng.apply("h", "/", WsDirection::Recv, 1, b"clean") {
            WsRewriteOutcome::Forward { notes, payload, .. } => {
                assert!(notes.is_empty());
                assert_eq!(payload, b"clean");
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn empty_opcodes_skip_control_frames() {
        let eng = engine(vec![WsRewriteRule {
            drop: true,
            ..WsRewriteRule::default()
        }]);
        for opcode in [8u8, 9, 10] {
            match eng.apply("h", "/", WsDirection::Send, opcode, b"") {
                WsRewriteOutcome::Forward { notes, .. } => assert!(notes.is_empty()),
                other => panic!("control frame {opcode} must not drop: {other:?}"),
            }
        }
        match eng.apply("h", "/", WsDirection::Send, 1, b"x") {
            WsRewriteOutcome::Drop { .. } => {}
            other => panic!("text should drop: {other:?}"),
        }
    }

    #[test]
    fn host_path_direction_and_opcode_filters() {
        let eng = engine(vec![WsRewriteRule {
            hosts: vec!["api.example.com".into()],
            path_prefix: Some("/ws".into()),
            directions: vec![WsDirection::Send],
            opcodes: vec![1],
            replace_text: Some("ok".into()),
            ..WsRewriteRule::default()
        }]);
        let hit = eng.apply(
            "api.example.com",
            "/ws/v1",
            WsDirection::Send,
            1,
            b"in",
        );
        match hit {
            WsRewriteOutcome::Forward { payload, notes, .. } => {
                assert_eq!(payload, b"ok");
                assert!(!notes.is_empty());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            eng.apply("other.com", "/ws/v1", WsDirection::Send, 1, b"in"),
            WsRewriteOutcome::Forward { notes, .. } if notes.is_empty()
        ));
        assert!(matches!(
            eng.apply("api.example.com", "/other", WsDirection::Send, 1, b"in"),
            WsRewriteOutcome::Forward { notes, .. } if notes.is_empty()
        ));
        assert!(matches!(
            eng.apply("api.example.com", "/ws/v1", WsDirection::Recv, 1, b"in"),
            WsRewriteOutcome::Forward { notes, .. } if notes.is_empty()
        ));
        assert!(matches!(
            eng.apply("api.example.com", "/ws/v1", WsDirection::Send, 2, b"in"),
            WsRewriteOutcome::Forward { notes, .. } if notes.is_empty()
        ));
    }

    #[test]
    fn replace_base64_decodes_at_compile() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode([0xde, 0xad]);
        let eng = engine(vec![WsRewriteRule {
            opcodes: vec![2],
            replace_base64: Some(b64),
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Send, 2, b"xx") {
            WsRewriteOutcome::Forward { payload, .. } => {
                assert_eq!(payload, &[0xde, 0xad]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn invalid_text_regex_fails_compile() {
        let err = WsRewriteEngine::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                text_regex: Some("(".into()),
                drop: true,
                ..WsRewriteRule::default()
            }],
        })
        .expect_err("bad regex");
        assert!(
            err.contains("text_regex") || err.contains("regex"),
            "error should name the field: {err}"
        );
    }

    #[test]
    fn invalid_replace_base64_fails_compile() {
        let err = WsRewriteEngine::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                replace_base64: Some("!!!not-base64!!!".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect_err("bad base64");
        assert!(
            err.contains("replace_base64") || err.contains("base64"),
            "error should name the field: {err}"
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let eng = engine(vec![
            WsRewriteRule {
                replace_text: Some("first".into()),
                ..WsRewriteRule::default()
            },
            WsRewriteRule {
                drop: true,
                ..WsRewriteRule::default()
            },
        ]);
        match eng.apply("h", "/", WsDirection::Send, 1, b"x") {
            WsRewriteOutcome::Forward { payload, .. } => assert_eq!(payload, b"first"),
            other => panic!("first rule should win: {other:?}"),
        }
    }

    #[test]
    fn noop_rules_make_empty_engine() {
        let eng = engine(vec![WsRewriteRule::default()]);
        assert!(eng.is_empty());
    }

    #[test]
    fn non_utf8_skips_text_regex() {
        let eng = engine(vec![WsRewriteRule {
            text_regex: Some(".".into()),
            drop: true,
            opcodes: vec![2],
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Send, 2, &[0xff, 0xfe]) {
            WsRewriteOutcome::Forward { notes, .. } => assert!(notes.is_empty()),
            other => panic!("binary non-utf8 must not match text_regex: {other:?}"),
        }
    }

    #[test]
    fn hub_rejects_bad_regex_without_clearing_prior_rules() {
        use crate::config::WsRewriteRulesBody;

        let hub = WsRewriteHub::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                drop: true,
                ..WsRewriteRule::default()
            }],
        })
        .expect("compile");
        assert!(!hub.is_empty());

        let err = hub
            .set_rules(WsRewriteRulesBody {
                rules: vec![WsRewriteRule {
                    text_regex: Some("(".into()),
                    drop: true,
                    ..WsRewriteRule::default()
                }],
            })
            .expect_err("bad regex");
        assert!(err.contains("text_regex") || err.contains("regex"), "{err}");

        assert!(!hub.is_empty());
        match hub.apply("h", "/", WsDirection::Send, 1, b"x") {
            WsRewriteOutcome::Drop { .. } => {}
            other => panic!("prior drop rule must remain: {other:?}"),
        }

        let body = hub.rules();
        assert_eq!(body.rules.len(), 1);
        assert!(body.rules[0].drop);
    }

    #[test]
    fn wildcard_host_matches() {
        let eng = engine(vec![WsRewriteRule {
            hosts: vec!["*.example.com".into()],
            drop: true,
            ..WsRewriteRule::default()
        }]);
        match eng.apply("api.example.com", "/", WsDirection::Send, 1, b"x") {
            WsRewriteOutcome::Drop { .. } => {}
            other => panic!("wildcard host should match: {other:?}"),
        }
        match eng.apply("other.net", "/", WsDirection::Send, 1, b"x") {
            WsRewriteOutcome::Forward { notes, .. } => assert!(notes.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn empty_opcodes_match_text_and_binary_only() {
        let eng = engine(vec![WsRewriteRule {
            replace_text: Some("hit".into()),
            ..WsRewriteRule::default()
        }]);
        for opcode in [1u8, 2] {
            match eng.apply("h", "/", WsDirection::Send, opcode, b"in") {
                WsRewriteOutcome::Forward { payload, notes, .. } => {
                    assert_eq!(payload, b"hit");
                    assert!(!notes.is_empty());
                }
                other => panic!("opcode {opcode} should match: {other:?}"),
            }
        }
        // Continuation frames are not default data opcodes for rewrite.
        match eng.apply("h", "/", WsDirection::Send, 0, b"in") {
            WsRewriteOutcome::Forward { notes, payload, .. } => {
                assert!(notes.is_empty());
                assert_eq!(payload, b"in");
            }
            other => panic!("continuation must not match by default: {other:?}"),
        }
    }

    #[test]
    fn explicit_opcodes_can_match_control_frames() {
        let eng = engine(vec![WsRewriteRule {
            opcodes: vec![9],
            drop: true,
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Send, 9, b"ping") {
            WsRewriteOutcome::Drop { notes } => {
                assert!(notes[0].contains("dropped"));
            }
            other => panic!("explicit ping opcode should drop: {other:?}"),
        }
        // Text still forwards when only ping is listed.
        match eng.apply("h", "/", WsDirection::Send, 1, b"text") {
            WsRewriteOutcome::Forward { notes, .. } => assert!(notes.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn oversized_payload_skips_text_regex() {
        let eng = engine(vec![WsRewriteRule {
            text_regex: Some("x".into()),
            drop: true,
            ..WsRewriteRule::default()
        }]);
        // Just over the 1 MiB regex cap: must not run the pattern.
        let big = vec![b'x'; MAX_REGEX_PAYLOAD + 1];
        match eng.apply("h", "/", WsDirection::Send, 1, &big) {
            WsRewriteOutcome::Forward { notes, payload, .. } => {
                assert!(notes.is_empty());
                assert_eq!(payload.len(), MAX_REGEX_PAYLOAD + 1);
            }
            other => panic!("oversized payload must skip text_regex: {other:?}"),
        }
        // At the cap, matching still works.
        let at_cap = vec![b'x'; MAX_REGEX_PAYLOAD];
        match eng.apply("h", "/", WsDirection::Send, 1, &at_cap) {
            WsRewriteOutcome::Drop { .. } => {}
            other => panic!("payload at cap should still match: {other:?}"),
        }
    }

    #[test]
    fn drop_notes_never_reuse_capture_eviction_opcode() {
        // Capture uses opcode 0xf as a ring-buffer eviction marker. Rewrite
        // drops leave notes only; they must not look like that marker.
        let eng = engine(vec![WsRewriteRule {
            drop: true,
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Send, 1, b"x") {
            WsRewriteOutcome::Drop { notes } => {
                assert_eq!(notes.len(), 1);
                assert!(
                    !notes[0].contains("0xf") && !notes[0].contains("0xF"),
                    "drop note must not mention capture eviction opcode: {}",
                    notes[0]
                );
                // Note describes a rewrite drop, not capture eviction.
                assert!(notes[0].contains("dropped"));
                assert!(notes[0].contains("opcode 1"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn replace_text_preferred_over_base64() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"from-b64");
        let eng = engine(vec![WsRewriteRule {
            replace_text: Some("from-text".into()),
            replace_base64: Some(b64),
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Send, 1, b"in") {
            WsRewriteOutcome::Forward { payload, notes, .. } => {
                assert_eq!(payload, b"from-text");
                assert!(notes[0].contains("replace_text"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn drop_wins_when_both_drop_and_replace_set() {
        let eng = engine(vec![WsRewriteRule {
            drop: true,
            replace_text: Some("ignored".into()),
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Send, 1, b"in") {
            WsRewriteOutcome::Drop { notes } => {
                assert!(notes[0].contains("drop"));
            }
            other => panic!("drop must win over replace: {other:?}"),
        }
    }

    #[test]
    fn hub_keeps_noop_rules_in_source_while_engine_is_empty() {
        use crate::config::WsRewriteRulesBody;

        let hub = WsRewriteHub::empty();
        let body = hub
            .set_rules(WsRewriteRulesBody {
                rules: vec![
                    WsRewriteRule::default(),
                    WsRewriteRule {
                        hosts: vec!["only-filters".into()],
                        ..WsRewriteRule::default()
                    },
                ],
            })
            .expect("noop list is valid");
        assert_eq!(body.rules.len(), 2);
        assert!(hub.is_empty(), "noop rules must not force parse-before-forward");
        assert_eq!(hub.rules().rules.len(), 2);

        // Actionable rule makes the engine non-empty.
        hub.set_rules(WsRewriteRulesBody {
            rules: vec![WsRewriteRule {
                replace_text: Some("x".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("ok");
        assert!(!hub.is_empty());
    }

    #[test]
    fn hub_set_rules_round_trip_replaces_list() {
        use crate::config::WsRewriteRulesBody;

        let hub = WsRewriteHub::empty();
        hub.set_rules(WsRewriteRulesBody {
            rules: vec![WsRewriteRule {
                drop: true,
                text_regex: Some("a+".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("ok");
        match hub.apply("h", "/", WsDirection::Recv, 1, b"aaa") {
            WsRewriteOutcome::Drop { .. } => {}
            other => panic!("{other:?}"),
        }

        hub.set_rules(WsRewriteRulesBody {
            rules: vec![WsRewriteRule {
                replace_text: Some("new".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("replace whole list");
        match hub.apply("h", "/", WsDirection::Recv, 1, b"aaa") {
            WsRewriteOutcome::Forward { payload, .. } => assert_eq!(payload, b"new"),
            other => panic!("old drop rule must be gone: {other:?}"),
        }
        assert_eq!(hub.rules().rules.len(), 1);
        assert!(!hub.rules().rules[0].drop);
    }

    #[test]
    fn nonsense_opcodes_are_stripped_at_compile() {
        // Reserved / capture-marker opcodes must not match by accident.
        let eng = engine(vec![WsRewriteRule {
            opcodes: vec![0xf, 3, 1],
            drop: true,
            ..WsRewriteRule::default()
        }]);
        match eng.apply("h", "/", WsDirection::Send, 0xf, b"") {
            WsRewriteOutcome::Forward { notes, .. } => assert!(notes.is_empty()),
            other => panic!("0xf must be stripped: {other:?}"),
        }
        match eng.apply("h", "/", WsDirection::Send, 3, b"") {
            WsRewriteOutcome::Forward { notes, .. } => assert!(notes.is_empty()),
            other => panic!("reserved opcode 3 must be stripped: {other:?}"),
        }
        match eng.apply("h", "/", WsDirection::Send, 1, b"") {
            WsRewriteOutcome::Drop { .. } => {}
            other => panic!("valid opcode 1 must remain: {other:?}"),
        }
    }
}
