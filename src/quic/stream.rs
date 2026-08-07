//! FlowStore integration for one HTTP/3 request stream.
//!
//! ## Contract
//!
//! - **Open**: client HEADERS on a request stream create exactly one
//!   [`FlowKind::Http`] with [`HttpVersion::Http3`], transport `quic`, and
//!   optional multiplex fields (`connection_id`, `stream_id`) using the same
//!   shared H2+H3 identity contract as TCP H2 (see [`crate::types::Flow`]).
//! - **Close**: the stream ends in either [`H3StreamFlow::finish`] (Complete)
//!   or [`H3StreamFlow::fail`] / [`H3StreamFlow::fail_code`] (Error). Dropping
//!   an open handle without a terminal call fails the flow so abandoned streams
//!   are never left Pending/Streaming forever.
//! - Control / QPACK / datagram traffic never opens a flow.
//! - Client-leg `stream_id` is never claimed to equal `upstream_stream_id`.
//!
//! Accept-only ([`super::http3`]) and reverse MITM ([`super::reverse`]) share
//! these hooks so capture lifecycle stays consistent.

use std::sync::Arc;

use crate::capture::{BodyWriter, FlowInit, FlowStore};
use crate::types::{
    now_ms, BodyMeta, FlowError, FlowId, FlowResponse, FlowState, HeaderPair, HttpVersion,
};

use super::http3::H3RequestMeta;

/// Stable error codes used on the H3 / QUIC stream path.
pub mod codes {
    /// Generic H3 framing / stream I/O failure after the request was accepted.
    pub const H3: &str = "h3";
    /// Origin dial or upstream request/response failure.
    pub const QUIC_UPSTREAM: &str = "quic_upstream";
    /// Stream task ended without finish/fail (Drop guard). Distinct from [`H3`].
    pub const H3_ABANDONED: &str = "h3_abandoned";
    /// Client-facing QUIC TLS rejected our leaf (UnknownCA / BadCertificate-like).
    ///
    /// Not proof of app pinning vs Chrome user-CA policy; see
    /// [`classify_client_handshake_error`].
    pub const QUIC_CERT_REJECT: &str = "quic_cert_reject";
    /// Upstream (or client) ALPN missing or not RFC9114 `h3`.
    pub const QUIC_ALPN: &str = "quic_alpn";
}

/// Result of classifying a client-facing QUIC handshake failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeClassify {
    pub code: &'static str,
    /// Same honesty caveats as TCP: UnknownCA-style alerts often mean the peer
    /// does not trust our chain. That includes Chrome user-CA refusal for QUIC
    /// and true app pinning; never treat `true` as proof of pinning alone.
    pub likely_pinning: Option<bool>,
    /// Operator-facing message (may mention Chrome user-CA when not clearly pin).
    pub message: String,
}

/// Map a client-leg handshake error onto a stable code and optional pinning flag.
///
/// Uses typed rustls alerts when reachable through `anyhow` sources, else
/// substring match (same pattern as TCP [`crate::proxy`] cert rejection).
pub fn classify_client_handshake_error(err: &anyhow::Error, sni_hint: Option<&str>) -> HandshakeClassify {
    let text = format!("{err:#}");
    let cert_reject = is_cert_reject_text(&text) || err_chain_is_cert_reject(err);
    let host = sni_hint.unwrap_or("client");
    if cert_reject {
        // TCP sets likely_pinning on UnknownCA-class alerts with the same caveat:
        // Chrome may refuse user CAs for QUIC without the app pinning.
        let chrome_note =
            " Chrome often refuses user-installed CAs for QUIC even when the leaf is valid; \
             force TCP/HTTP2 or use a client that trusts the Proxima root for H3.";
        HandshakeClassify {
            code: codes::QUIC_CERT_REJECT,
            likely_pinning: Some(true),
            message: format!(
                "QUIC handshake failed ({host}): peer rejected the Proxima certificate \
                 ({text}). This may be app pinning or client user-CA policy.{chrome_note}"
            ),
        }
    } else if is_alpn_fail_text(&text) {
        HandshakeClassify {
            code: codes::QUIC_ALPN,
            likely_pinning: None,
            message: format!("QUIC handshake failed ({host}): ALPN not h3: {text}"),
        }
    } else {
        HandshakeClassify {
            code: codes::H3,
            likely_pinning: None,
            message: format!("QUIC handshake failed ({host}): {text}"),
        }
    }
}

/// True when error text looks like a certificate trust rejection alert.
pub fn is_cert_reject_text(text: &str) -> bool {
    text.contains("UnknownCA")
        || text.contains("BadCertificate")
        || text.contains("CertificateUnknown")
        || text.contains("invalidpeercertificate")
        || text.to_ascii_lowercase().contains("unknown ca")
        || text.to_ascii_lowercase().contains("bad certificate")
        || text.to_ascii_lowercase().contains("certificate unknown")
}

fn is_alpn_fail_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("alpn") || lower.contains("negotiated protocols")
}

fn err_chain_is_cert_reject(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(re) = cause.downcast_ref::<rustls::Error>() {
            if matches!(
                re,
                rustls::Error::InvalidCertificate(_)
                    | rustls::Error::AlertReceived(
                        rustls::AlertDescription::UnknownCA
                            | rustls::AlertDescription::BadCertificate
                            | rustls::AlertDescription::CertificateUnknown
                    )
            ) {
                return true;
            }
        }
        let s = cause.to_string();
        if is_cert_reject_text(&s) {
            return true;
        }
    }
    false
}

/// Prefer a stable short code for inspector filters after a stream is open.
pub fn classify_bridge_error_code(err: &anyhow::Error) -> &'static str {
    let text = format!("{err:#}").to_ascii_lowercase();
    if text.contains("quic_alpn") || (text.contains("alpn") && text.contains("h3")) {
        return codes::QUIC_ALPN;
    }
    if text.contains("upstream")
        || text.contains("dial")
        || text.contains("connect")
        || text.contains("resolv")
    {
        return codes::QUIC_UPSTREAM;
    }
    codes::H3
}

/// Records a failed client-facing QUIC handshake as an Error flow.
///
/// Used when no H3 request stream was opened. Kind is Tunnel (no HTTP request
/// yet) with transport quic so the inspector list still shows the failure.
pub fn record_handshake_failure(
    store: &crate::capture::FlowStore,
    remote: std::net::SocketAddr,
    sni: Option<&str>,
    err: &anyhow::Error,
) -> crate::types::FlowId {
    use crate::capture::FlowInit;
    use crate::types::{
        FlowClient, FlowKind, FlowRequest, FlowServer, HttpVersion, Scheme, Transport,
    };

    let class = classify_client_handshake_error(err, sni);
    let host = sni.unwrap_or(&remote.ip().to_string()).to_string();
    let authority = host.clone();
    let init = FlowInit {
        kind: FlowKind::Tunnel,
        intercepted: false,
        request: FlowRequest {
            method: "QUIC".into(),
            url: format!("https://{authority}/"),
            scheme: Scheme::Https,
            authority: authority.clone(),
            host: host.clone(),
            port: remote.port(),
            path: String::new(),
            http_version: HttpVersion::Http3,
            headers: Vec::new(),
            body: None,
        },
        client: FlowClient {
            address: remote.ip().to_string(),
            port: remote.port(),
        },
        server: FlowServer {
            address: Some(host.clone()),
            port: None,
            sni: sni.map(|s| s.to_string()),
            alpn: None,
            tls_version: Some("QUIC".into()),
            cipher: None,
            cert_fingerprint: None,
        },
        replay_of: None,
        transport: Some(Transport::Quic),
        connection_id: None,
        stream_id: None,
        upstream_stream_id: None,
    };
    let id = store.create(init);
    store.fail(
        &id,
        crate::types::FlowError {
            message: class.message,
            code: Some(class.code.into()),
            likely_pinning: class.likely_pinning,
        },
    );
    id
}

/// Live FlowStore handle for one client-initiated H3 request stream.
///
/// Created by [`Self::open`] or [`Self::open_rewritten`]. Call
/// [`Self::finish`] or [`Self::fail`] (or helpers) exactly once; if the handle
/// is dropped without a terminal close, the flow is failed as abandoned.
pub struct H3StreamFlow {
    id: FlowId,
    store: Arc<FlowStore>,
    /// Set true once finish/fail has been applied so Drop is a no-op.
    closed: bool,
}

impl H3StreamFlow {
    /// Opens a flow for an accept-only (or already-rewritten) request stream.
    ///
    /// Emits `flow:new` via [`FlowStore::create`]. State starts as Pending.
    /// Crate-private: takes [`H3RequestMeta`], which is not part of the public API.
    pub(crate) fn open(store: Arc<FlowStore>, meta: &H3RequestMeta) -> Self {
        open_with_init(store, meta.to_flow_init())
    }

    /// Opens a reverse-mode flow whose capture authority matches the origin.
    ///
    /// Client-leg multiplex ids stay on `meta`; only host/port/authority/url
    /// and server SNI are rewritten for the inspector.
    pub(crate) fn open_rewritten(
        store: Arc<FlowStore>,
        meta: &H3RequestMeta,
        upstream_host: &str,
        upstream_port: u16,
        upstream_authority: &str,
    ) -> Self {
        open_with_init(
            store,
            meta.to_flow_init_rewritten(upstream_host, upstream_port, upstream_authority),
        )
    }

    /// Opens from a pre-built [`FlowInit`] (tests and alternate producers).
    pub fn open_init(store: Arc<FlowStore>, init: FlowInit) -> Self {
        open_with_init(store, init)
    }

    /// Flow id assigned at open (stable for the stream lifetime).
    pub fn id(&self) -> &FlowId {
        &self.id
    }

    /// Shared store (body writers, etc.).
    pub fn store(&self) -> &FlowStore {
        &self.store
    }

    /// Cloned Arc for spawning body work that outlives a short borrow.
    pub fn store_arc(&self) -> Arc<FlowStore> {
        Arc::clone(&self.store)
    }

    /// Bounded body writer using the store's per-body ceiling.
    pub fn body_writer(&self) -> BodyWriter {
        self.store.bodies().writer(self.store.max_body_bytes())
    }

    /// Records a reverse Host/authority rewrite note (or any rewrite audit line).
    pub fn note_rewrite(&self, note: impl Into<String>) {
        let note = note.into();
        self.store.update(&self.id, |flow| {
            flow.rewrites.push(note);
        });
    }

    /// Sets the origin-leg H3 stream id after the upstream request is opened.
    ///
    /// Distinct from the client-leg id stored at open; MITM never equates them.
    pub fn set_upstream_stream_id(&self, upstream_stream_id: u64) {
        self.store.update(&self.id, |flow| {
            flow.upstream_stream_id = Some(upstream_stream_id);
        });
    }

    /// Attaches a captured request body (or clears with `None` when empty).
    pub fn set_request_body(&self, body: Option<BodyMeta>) {
        self.store.update(&self.id, |flow| {
            flow.request.body = body;
        });
    }

    /// Marks `timings.request_sent` after the full request has left toward origin
    /// (or after the accept-only path has finished reading the client body).
    pub fn mark_request_sent(&self) {
        let ts = now_ms();
        self.store.update(&self.id, |flow| {
            flow.timings.request_sent = Some(ts);
        });
    }

    /// Records response headers, moves state to Streaming, stamps response_start.
    pub fn set_response(&self, response: FlowResponse) {
        let ts = now_ms();
        self.store.update(&self.id, |flow| {
            flow.state = FlowState::Streaming;
            flow.timings.response_start = Some(ts);
            flow.response = Some(response);
        });
    }

    /// Convenience: HTTP/3 response headers with optional status text fallback.
    pub fn set_response_h3(
        &self,
        status: u16,
        status_text: impl Into<String>,
        headers: Vec<HeaderPair>,
    ) {
        self.set_response(FlowResponse {
            status,
            status_text: status_text.into(),
            http_version: HttpVersion::Http3,
            headers,
            body: None,
        });
    }

    /// Attaches a captured response body onto an existing response.
    ///
    /// No-op if response headers were never recorded (caller should fail instead).
    pub fn set_response_body(&self, body: Option<BodyMeta>) {
        self.store.update(&self.id, |flow| {
            if let Some(response) = flow.response.as_mut() {
                response.body = body;
            }
        });
    }

    /// Generic in-place update while the stream is open (keep cheap; no await).
    pub fn update<F: FnOnce(&mut crate::types::Flow)>(&self, f: F) {
        self.store.update(&self.id, f);
    }

    /// Terminal success: Complete + `flow:done`. Consumes the handle.
    pub fn finish(mut self) {
        self.closed = true;
        self.store.finish(&self.id);
    }

    /// Terminal failure: Error + `flow:done`. Consumes the handle.
    pub fn fail(mut self, error: FlowError) {
        self.closed = true;
        self.store.fail(&self.id, error);
    }

    /// Fail with a stable code and free-form message.
    pub fn fail_code(self, code: impl Into<String>, message: impl Into<String>) {
        self.fail(FlowError {
            message: message.into(),
            code: Some(code.into()),
            likely_pinning: None,
        });
    }

    /// Fail with code, message, and optional likely_pinning (handshake path).
    pub fn fail_classified(
        self,
        code: impl Into<String>,
        message: impl Into<String>,
        likely_pinning: Option<bool>,
    ) {
        self.fail(FlowError {
            message: message.into(),
            code: Some(code.into()),
            likely_pinning,
        });
    }

    /// Fail with code [`codes::H3`].
    pub fn fail_h3(self, message: impl Into<String>) {
        self.fail_code(codes::H3, message);
    }

    /// Fail with code [`codes::QUIC_UPSTREAM`] (never sets likely_pinning).
    pub fn fail_upstream(self, message: impl Into<String>) {
        self.fail_code(codes::QUIC_UPSTREAM, message);
    }

    /// Fail with code [`codes::QUIC_ALPN`].
    pub fn fail_alpn(self, message: impl Into<String>) {
        self.fail_code(codes::QUIC_ALPN, message);
    }

    /// True after finish/fail; mainly for tests.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Drop for H3StreamFlow {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // Honest capture: a cancelled task or early return must not leave the
        // flow Pending/Streaming as if it were still live.
        self.store.fail(
            &self.id,
            FlowError {
                message: "h3 request stream ended without a terminal result".into(),
                code: Some(codes::H3_ABANDONED.into()),
                likely_pinning: None,
            },
        );
        self.closed = true;
    }
}

fn open_with_init(store: Arc<FlowStore>, init: FlowInit) -> H3StreamFlow {
    let id = store.create(init);
    H3StreamFlow {
        id,
        store,
        closed: false,
    }
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use crate::types::{FlowKind, FlowState, Transport};

    fn remote() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 40000)
    }

    fn meta(conn: &str, stream: u64, path: &str) -> H3RequestMeta {
        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://api.example.com{path}"))
            .header("accept", "*/*")
            .body(())
            .unwrap();
        let mut m = H3RequestMeta::from_http(
            req,
            remote(),
            Some("api.example.com".into()),
            Some(conn.into()),
            Some(stream),
        );
        m.alpn = Some("h3".into());
        m
    }

    #[test]
    fn open_emits_pending_http3_quic_flow() {
        let store = Arc::new(FlowStore::new(16, 1024, 4096));
        let m = meta("c-open", 0, "/open");
        let flow = H3StreamFlow::open(store.clone(), &m);
        let id = flow.id().clone();

        let got = store.get(&id).expect("flow");
        assert_eq!(got.state, FlowState::Pending);
        assert_eq!(got.kind, FlowKind::Http);
        assert!(got.intercepted);
        assert_eq!(got.request.http_version, HttpVersion::Http3);
        assert_eq!(got.transport, Some(Transport::Quic));
        assert_eq!(got.connection_id.as_deref(), Some("c-open"));
        assert_eq!(got.stream_id, Some(0));
        assert_eq!(got.upstream_stream_id, None);
        assert_eq!(got.server.alpn.as_deref(), Some("h3"));

        flow.finish();
        let done = store.get(&id).expect("flow");
        assert_eq!(done.state, FlowState::Complete);
        assert!(done.timings.end.is_some());
    }

    #[test]
    fn open_rewritten_records_origin_authority() {
        let store = Arc::new(FlowStore::new(8, 256, 1024));
        let m = meta("c-rw", 4, "/hello");
        let flow = H3StreamFlow::open_rewritten(
            store.clone(),
            &m,
            "origin.internal",
            443,
            "origin.internal",
        );
        flow.note_rewrite("reverse H3 rewrote authority api.example.com -> origin.internal");
        let id = flow.id().clone();
        flow.finish();

        let got = store.get(&id).expect("flow");
        assert_eq!(got.request.host, "origin.internal");
        assert_eq!(got.request.authority, "origin.internal");
        assert_eq!(got.request.url, "https://origin.internal/hello");
        assert_eq!(got.connection_id.as_deref(), Some("c-rw"));
        assert_eq!(got.stream_id, Some(4));
        assert!(!got.rewrites.is_empty());
    }

    #[test]
    fn lifecycle_request_response_finish() {
        let store = Arc::new(FlowStore::new(8, 1024, 4096));
        let flow = H3StreamFlow::open(store.clone(), &meta("c1", 8, "/echo"));
        let id = flow.id().clone();

        let mut w = flow.body_writer();
        w.write(b"ping");
        let req_body = w.finish(None, Some("text/plain".into()));
        flow.set_request_body(Some(req_body));
        flow.mark_request_sent();
        flow.set_upstream_stream_id(100);
        flow.set_response_h3(
            200,
            "OK",
            vec![("content-type".into(), "text/plain".into())],
        );

        let mut rw = flow.body_writer();
        rw.write(b"pong");
        let resp_body = rw.finish(None, Some("text/plain".into()));
        flow.set_response_body(Some(resp_body));
        flow.finish();

        let got = store.get(&id).expect("flow");
        assert_eq!(got.state, FlowState::Complete);
        assert_eq!(got.stream_id, Some(8));
        assert_eq!(got.upstream_stream_id, Some(100));
        assert_ne!(got.stream_id, got.upstream_stream_id);
        assert_eq!(got.request.body.as_ref().map(|b| b.size), Some(4));
        let resp = got.response.expect("response");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.http_version, HttpVersion::Http3);
        assert_eq!(resp.body.as_ref().map(|b| b.size), Some(4));
        assert!(got.timings.request_sent.is_some());
        assert!(got.timings.response_start.is_some());
    }

    #[test]
    fn fail_sets_upstream_code() {
        let store = Arc::new(FlowStore::new(4, 256, 1024));
        let flow = H3StreamFlow::open(store.clone(), &meta("c-err", 0, "/x"));
        let id = flow.id().clone();
        flow.fail(FlowError {
            message: "upstream reset".into(),
            code: Some(codes::QUIC_UPSTREAM.into()),
            likely_pinning: None,
        });
        let got = store.get(&id).expect("flow");
        assert_eq!(got.state, FlowState::Error);
        assert_eq!(
            got.error.as_ref().and_then(|e| e.code.as_deref()),
            Some(codes::QUIC_UPSTREAM)
        );
        assert_eq!(got.error.as_ref().map(|e| e.likely_pinning), Some(None));
    }

    #[test]
    fn fail_h3_and_fail_upstream_helpers() {
        let store = Arc::new(FlowStore::new(8, 256, 1024));

        let a = H3StreamFlow::open(store.clone(), &meta("c-a", 0, "/a"));
        let id_a = a.id().clone();
        a.fail_h3("decode failed");
        assert_eq!(
            store
                .get(&id_a)
                .unwrap()
                .error
                .as_ref()
                .and_then(|e| e.code.as_deref()),
            Some(codes::H3)
        );

        let b = H3StreamFlow::open(store.clone(), &meta("c-b", 4, "/b"));
        let id_b = b.id().clone();
        b.fail_upstream("dial refused");
        assert_eq!(
            store
                .get(&id_b)
                .unwrap()
                .error
                .as_ref()
                .and_then(|e| e.code.as_deref()),
            Some(codes::QUIC_UPSTREAM)
        );
    }

    #[test]
    fn drop_without_close_fails_as_abandoned() {
        let store = Arc::new(FlowStore::new(4, 256, 1024));
        let id = {
            let flow = H3StreamFlow::open(store.clone(), &meta("c-drop", 0, "/drop"));
            flow.id().clone()
            // drop here without finish/fail
        };
        let got = store.get(&id).expect("flow");
        assert_eq!(got.state, FlowState::Error);
        assert_eq!(
            got.error.as_ref().and_then(|e| e.code.as_deref()),
            Some(codes::H3_ABANDONED)
        );
        assert!(got
            .error
            .as_ref()
            .map(|e| e.message.contains("without a terminal"))
            .unwrap_or(false));
    }

    #[test]
    fn finish_then_drop_does_not_overwrite_complete() {
        let store = Arc::new(FlowStore::new(4, 256, 1024));
        let id = {
            let flow = H3StreamFlow::open(store.clone(), &meta("c-ok", 0, "/ok"));
            let id = flow.id().clone();
            flow.finish();
            id
        };
        let got = store.get(&id).expect("flow");
        assert_eq!(got.state, FlowState::Complete);
        assert!(got.error.is_none());
    }

    #[test]
    fn multiplex_open_hooks_share_connection_id() {
        let store = Arc::new(FlowStore::new(16, 1024, 4096));
        let conn = "mux-conn";
        let mut ids = Vec::new();
        for sid in [0u64, 4, 8] {
            let flow = H3StreamFlow::open(store.clone(), &meta(conn, sid, &format!("/s{sid}")));
            let id = flow.id().clone();
            flow.finish();
            ids.push((id, sid));
        }
        for (id, sid) in ids {
            let got = store.get(&id).expect("flow");
            assert_eq!(got.connection_id.as_deref(), Some(conn));
            assert_eq!(got.stream_id, Some(sid));
            assert_eq!(got.transport, Some(Transport::Quic));
            assert_eq!(got.state, FlowState::Complete);
        }
    }

    #[test]
    fn open_init_matches_open_from_meta() {
        let store = Arc::new(FlowStore::new(4, 256, 1024));
        let m = meta("c-init", 12, "/from-init");
        let flow = H3StreamFlow::open_init(store.clone(), m.to_flow_init());
        let id = flow.id().clone();
        flow.finish();
        let got = store.get(&id).expect("flow");
        assert_eq!(got.connection_id.as_deref(), Some("c-init"));
        assert_eq!(got.stream_id, Some(12));
        assert_eq!(got.request.path, "/from-init");
        assert_eq!(got.state, FlowState::Complete);
    }

    #[test]
    fn code_constants_are_distinct_and_stable() {
        assert_eq!(codes::H3, "h3");
        assert_eq!(codes::QUIC_UPSTREAM, "quic_upstream");
        assert_eq!(codes::H3_ABANDONED, "h3_abandoned");
        assert_eq!(codes::QUIC_CERT_REJECT, "quic_cert_reject");
        assert_eq!(codes::QUIC_ALPN, "quic_alpn");
        assert_ne!(codes::H3, codes::H3_ABANDONED);
    }

    #[test]
    fn classify_cert_reject_sets_code_and_pinning_caveat() {
        let err = anyhow::anyhow!("peer alert: UnknownCA");
        let c = classify_client_handshake_error(&err, Some("api.example"));
        assert_eq!(c.code, codes::QUIC_CERT_REJECT);
        assert_eq!(c.likely_pinning, Some(true));
        // P11 honesty: flag is a cert-reject signal, not pure app-pinning proof.
        assert!(
            c.message.contains("user-CA") || c.message.contains("user-installed CA"),
            "cert-reject message must name user-CA policy: {}",
            c.message
        );
        assert!(
            c.message.contains("pinning") && c.message.contains("may be"),
            "cert-reject message must keep pinning as one possibility only: {}",
            c.message
        );
        assert!(
            c.message.contains("Chrome") || c.message.contains("TCP/HTTP2"),
            "cert-reject message should point at Chrome QUIC policy or force-TCP: {}",
            c.message
        );
        assert!(
            !c.message.contains("proof of pinning")
                && !c.message.contains("definitely pinned")
                && !c.message.contains("pure pinning"),
            "message must not claim pure pinning proof: {}",
            c.message
        );
    }

    #[test]
    fn classify_generic_handshake_is_h3() {
        let err = anyhow::anyhow!("connection timed out");
        let c = classify_client_handshake_error(&err, None);
        assert_eq!(c.code, codes::H3);
        assert_eq!(c.likely_pinning, None);
    }

    #[test]
    fn classify_bridge_maps_alpn_and_upstream() {
        let alpn = anyhow::anyhow!("quic_alpn: upstream negotiated h2 not h3");
        assert_eq!(classify_bridge_error_code(&alpn), codes::QUIC_ALPN);
        let dial = anyhow::anyhow!("dial upstream H3: connection refused");
        assert_eq!(classify_bridge_error_code(&dial), codes::QUIC_UPSTREAM);
    }

    #[test]
    fn record_handshake_failure_creates_error_flow() {
        let store = FlowStore::new(4, 256, 1024);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let err = anyhow::anyhow!("tls: UnknownCA from peer");
        let id = record_handshake_failure(&store, remote, Some("app.example"), &err);
        let got = store.get(&id).expect("flow");
        assert_eq!(got.state, FlowState::Error);
        assert_eq!(got.transport, Some(Transport::Quic));
        assert_eq!(
            got.error.as_ref().and_then(|e| e.code.as_deref()),
            Some(codes::QUIC_CERT_REJECT)
        );
        assert_eq!(got.error.as_ref().and_then(|e| e.likely_pinning), Some(true));
        assert_eq!(got.server.sni.as_deref(), Some("app.example"));
    }

    #[test]
    fn classify_bridge_prefers_stable_codes_over_generic_h3() {
        // Stable taxonomy used by reverse bridge fail paths (acceptance: no ad-hoc codes).
        for (msg, want) in [
            ("quic_alpn: peer said h2", codes::QUIC_ALPN),
            ("ALPN negotiation failed: expected h3", codes::QUIC_ALPN),
            ("dial upstream H3: timed out", codes::QUIC_UPSTREAM),
            ("failed to connect to peer 1.2.3.4:443", codes::QUIC_UPSTREAM),
            ("h3 frame decode error on request stream", codes::H3),
        ] {
            assert_eq!(
                classify_bridge_error_code(&anyhow::anyhow!("{msg}")),
                want,
                "message {msg:?}"
            );
        }
    }
}
