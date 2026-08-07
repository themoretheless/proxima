//! HTTP/3 session accept and FlowStore mapping.
//!
//! ## Contract
//!
//! - One client-initiated H3 **request stream** becomes one [`FlowKind::Http`]
//!   with [`HttpVersion::Http3`]. Control / QPACK / datagram streams never
//!   become flows.
//! - This module terminates the client-facing leg only. Without reverse mode
//!   configured, each accepted request is answered with **501** and an honest
//!   body: the inspector still sees the request, and nothing pretends traffic
//!   was forwarded.
//! - Stream open/close go through [`super::stream::H3StreamFlow`] so accept-only
//!   and reverse share the same FlowStore lifecycle hooks.
//! - The regular TCP proxy port never receives these streams. QUIC is UDP-only;
//!   see the parent module docs and PLANS.md for WireGuard / TUN paths.
//!
//! Reverse MITM (upstream dial, Host rewrite, response proxying) lives in
//! [`super::reverse`]. Shared helpers here keep request → [`FlowInit`] mapping
//! consistent across accept-only and reverse.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use quinn::Incoming;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::ca::CertAuthority;
use crate::capture::{new_id, BodyWriter, FlowInit, FlowStore};
use crate::proxy::headers;
use crate::types::{
    FlowClient, FlowKind, FlowRequest, FlowServer, HttpVersion, Scheme, Transport,
};

use super::stream::{record_handshake_failure, H3StreamFlow};

/// Static body for the accept-only 501 response.
const ACCEPT_ONLY_BODY: &[u8] = b"Proxima QUIC endpoint accepted this HTTP/3 request. \
Enable reverse H3 mode to forward upstream.\n";

/// Completes the QUIC handshake and drives an h3 server session.
///
/// Each resolved request stream is spawned so one slow body does not block
/// other streams on the same connection. Stream tasks hold a clone of
/// `drain_tx` so serve's drain wait includes in-flight bridges.
///
/// Client handshake failures create an Error flow (`quic_cert_reject` when the
/// peer rejects our leaf) rather than disappearing into debug logs only.
///
/// **Security:** awaits the full 1-RTT handshake (`Incoming` → connection).
/// The server crypto config rejects 0-RTT (`max_early_data_size = 0`); this
/// path never treats early data as an established MITM session.
pub async fn accept_one(
    incoming: Incoming,
    _ca: Arc<CertAuthority>,
    store: Arc<FlowStore>,
    drain_tx: mpsc::Sender<()>,
) -> Result<()> {
    let remote = incoming.remote_address();
    // Full handshake only; server config has early data disabled (see tls).
    let conn = match incoming.await {
        Ok(c) => c,
        Err(err) => {
            let err = anyhow::Error::new(err).context("QUIC handshake");
            warn!(%remote, error = %err, "client QUIC handshake failed");
            record_handshake_failure(&store, remote, None, &err);
            return Err(err);
        }
    };
    let remote = conn.remote_address();
    let (sni, alpn) = client_handshake_names(&conn);
    // Defense in depth: MITM server advertises only h3; still refuse odd ALPN.
    if let Some(ref a) = alpn {
        if a.as_bytes() != super::ALPN_H3 {
            let err = anyhow::anyhow!(
                "{}: client negotiated ALPN {a:?}, expected h3",
                super::codes::QUIC_ALPN
            );
            warn!(%remote, sni = sni.as_deref().unwrap_or("-"), error = %err, "client ALPN rejected");
            record_handshake_failure(&store, remote, sni.as_deref(), &err);
            return Err(err);
        }
    }
    // Proxima identity for this client-facing QUIC leg (not a wire CID).
    let connection_id = new_id();
    info!(
        %remote,
        %connection_id,
        sni = sni.as_deref().unwrap_or("-"),
        alpn = alpn.as_deref().unwrap_or("-"),
        "QUIC connection accepted (HTTP/3)"
    );

    let quinn_conn = h3_quinn::Connection::new(conn);
    let mut h3 = h3::server::Connection::new(quinn_conn)
        .await
        .context("h3 server connection")?;

    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let (req, mut stream) = match resolver.resolve_request().await {
                    Ok(pair) => pair,
                    Err(err) => {
                        debug!(error = %err, %connection_id, "resolving h3 request failed");
                        continue;
                    }
                };
                let store = store.clone();
                let sni = sni.clone();
                let alpn = alpn.clone();
                let connection_id = connection_id.clone();
                let drain = drain_tx.clone();
                tokio::spawn(async move {
                    let _drain = drain;
                    if let Err(err) = handle_accept_only_request(
                        req,
                        &mut stream,
                        remote,
                        store,
                        sni,
                        alpn,
                        connection_id,
                    )
                    .await
                    {
                        debug!(error = %err, "h3 request handler failed");
                    }
                });
            }
            Ok(None) => break,
            Err(err) => {
                debug!(error = %err, %connection_id, "h3 accept ended");
                break;
            }
        }
    }
    Ok(())
}

/// Accept-only path: open flow, record body, answer 501, close flow.
async fn handle_accept_only_request(
    req: http::Request<()>,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    remote: SocketAddr,
    store: Arc<FlowStore>,
    sni: Option<String>,
    alpn: Option<String>,
    connection_id: String,
) -> Result<()> {
    let stream_id = stream.id().into_inner();
    let mut meta =
        H3RequestMeta::from_http(req, remote, sni, Some(connection_id), Some(stream_id));
    // Record negotiated client ALPN; do not invent h3 when handshake reported none.
    meta.alpn = alpn;
    debug!(
        connection_id = meta.connection_id.as_deref().unwrap_or("-"),
        stream_id = stream_id,
        method = %meta.method,
        authority = %meta.authority,
        path = %meta.path,
        "h3 request stream accepted"
    );

    // Open event: one Flow per request stream (Pending, Http3, transport quic).
    let flow = H3StreamFlow::open(store, &meta);

    // Capture request body (bounded). Drain even when empty so the stream is
    // ready for the response.
    let req_encoding = header_value(&meta.headers, "content-encoding");
    let req_type = header_value(&meta.headers, "content-type");
    match recv_body_into_store(stream, flow.store()).await {
        Ok(Some(writer)) => {
            let body_meta = writer.finish(req_encoding, req_type);
            flow.set_request_body(Some(body_meta));
        }
        Ok(None) => {}
        Err(err) => {
            flow.fail_h3(format!("reading h3 request body: {err:#}"));
            return Err(err);
        }
    }

    flow.mark_request_sent();

    let status = http::StatusCode::NOT_IMPLEMENTED;
    let resp = http::Response::builder()
        .status(status)
        .header("server", "proxima-quic")
        .header("content-type", "text/plain; charset=utf-8")
        .body(())
        .context("building h3 response")?;

    if let Err(err) = stream.send_response(resp).await {
        flow.fail_h3(format!("sending h3 response headers: {err}"));
        return Err(err).context("send h3 response");
    }

    flow.set_response_h3(
        status.as_u16(),
        status.canonical_reason().unwrap_or("").to_string(),
        vec![
            ("server".into(), "proxima-quic".into()),
            ("content-type".into(), "text/plain; charset=utf-8".into()),
        ],
    );

    let body_bytes = Bytes::from_static(ACCEPT_ONLY_BODY);
    if let Err(err) = stream.send_data(body_bytes.clone()).await {
        flow.fail_h3(format!("sending h3 response body: {err}"));
        return Err(err).context("send h3 body");
    }

    // File the 501 body so the inspector shows what the client received.
    let mut resp_writer = flow.body_writer();
    resp_writer.write(body_bytes.as_ref());
    let resp_meta = resp_writer.finish(None, Some("text/plain; charset=utf-8".into()));
    flow.set_response_body(Some(resp_meta));

    if let Err(err) = stream.finish().await {
        flow.fail_h3(format!("finishing h3 stream: {err}"));
        return Err(err).context("finish h3 stream");
    }

    // Close event: Complete.
    flow.finish();
    Ok(())
}

/* ------------------------------------------------------------------ */
/* Shared request → FlowInit mapping                                   */
/* ------------------------------------------------------------------ */

/// Decoded H3 request fields used to open a Flow.
///
/// Built only from h3-decoded pseudo-headers and field lines (no raw QPACK).
/// `connection_id` / `stream_id` follow the shared multiplex contract on
/// [`crate::types::Flow`]: Proxima UUID for the client-facing session (QUIC
/// here; TLS session for TCP H2), plus the client-leg stream key when known.
/// Both are copied onto the Flow for list grouping.
#[derive(Debug, Clone)]
pub(crate) struct H3RequestMeta {
    pub method: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub client: FlowClient,
    pub sni: Option<String>,
    /// Negotiated client-leg ALPN when known (honest; may be None).
    pub alpn: Option<String>,
    pub connection_id: Option<String>,
    pub stream_id: Option<u64>,
}

impl H3RequestMeta {
    /// Maps an h3-decoded [`http::Request`] plus peer facts into capture meta.
    pub(crate) fn from_http(
        req: http::Request<()>,
        remote: SocketAddr,
        sni: Option<String>,
        connection_id: Option<String>,
        stream_id: Option<u64>,
    ) -> Self {
        let method = req.method().as_str().to_string();
        let uri = req.uri();

        let scheme = match uri.scheme_str() {
            Some("http") => Scheme::Http,
            _ => Scheme::Https,
        };

        let host = uri
            .host()
            .map(|h| h.to_string())
            .or_else(|| sni.clone())
            .unwrap_or_else(|| remote.ip().to_string());

        let default_port = match scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        let port = uri.port_u16().unwrap_or(default_port);

        let path = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".into());

        let authority = uri
            .authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_else(|| {
                if (scheme == Scheme::Https && port == 443)
                    || (scheme == Scheme::Http && port == 80)
                {
                    host.clone()
                } else {
                    format!("{host}:{port}")
                }
            });

        let headers = headers::to_pairs(req.headers());

        Self {
            method,
            scheme,
            host,
            port,
            authority,
            path,
            headers,
            client: FlowClient {
                address: remote.ip().to_string(),
                port: remote.port(),
            },
            sni,
            // Filled by accept/reverse after client_handshake_names.
            alpn: None,
            connection_id,
            stream_id,
        }
    }

    /// Absolute URL as the inspector shows it.
    pub(crate) fn url(&self) -> String {
        format!("{}://{}{}", self.scheme.as_str(), self.authority, self.path)
    }

    /// Builds a [`FlowInit`] for FlowStore::create. One call per H3 request stream.
    pub(crate) fn to_flow_init(&self) -> FlowInit {
        FlowInit {
            kind: FlowKind::Http,
            intercepted: true,
            request: FlowRequest {
                method: self.method.clone(),
                url: self.url(),
                scheme: self.scheme,
                authority: self.authority.clone(),
                host: self.host.clone(),
                port: self.port,
                path: self.path.clone(),
                http_version: HttpVersion::Http3,
                headers: self.headers.clone(),
                body: None,
            },
            client: self.client.clone(),
            server: FlowServer {
                address: Some(self.host.clone()),
                port: Some(self.port),
                sni: self.sni.clone(),
                // Honest: only what the client handshake reported (may be None).
                alpn: self.alpn.clone(),
                tls_version: Some("QUIC".into()),
                cipher: None,
                cert_fingerprint: None,
            },
            replay_of: None,
            transport: Some(Transport::Quic),
            connection_id: self.connection_id.clone(),
            stream_id: self.stream_id,
            // Accept-only has no origin leg; reverse fills this after dial.
            upstream_stream_id: None,
        }
    }

    /// Like [`Self::to_flow_init`] but rewrites authority/host/port for reverse
    /// mode so the capture matches what is sent to the origin.
    pub(crate) fn to_flow_init_rewritten(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        upstream_authority: &str,
    ) -> FlowInit {
        let mut init = self.to_flow_init();
        init.request.host = upstream_host.to_string();
        init.request.port = upstream_port;
        init.request.authority = upstream_authority.to_string();
        init.request.url = format!(
            "{}://{}{}",
            init.request.scheme.as_str(),
            upstream_authority,
            init.request.path
        );
        init.server.address = Some(upstream_host.to_string());
        init.server.port = Some(upstream_port);
        // Origin-leg SNI is the upstream hostname, not the public reverse name.
        init.server.sni = Some(upstream_host.to_string());
        init
    }
}

/// Convenience for reverse / other call sites that already hold an http request.
///
/// Accept-only and reverse both go through [`H3RequestMeta`]; reverse then
/// rewrites authority via [`H3RequestMeta::to_flow_init_rewritten`].
///
/// Tested only today; kept as the shared mapping so producers do not fork
/// header/pseudo-header decode when they already hold an `http::Request`.
#[cfg(test)]
pub(crate) fn flow_init_from_request(
    req: &http::Request<()>,
    remote: SocketAddr,
    sni: Option<String>,
) -> FlowInit {
    // Clone headers/method/uri into a owned request for the shared parser.
    let mut builder = http::Request::builder().method(req.method()).uri(req.uri());
    for (name, value) in req.headers().iter() {
        builder = builder.header(name, value);
    }
    let owned = builder.body(()).expect("rebuild request for FlowInit");
    H3RequestMeta::from_http(owned, remote, sni, None, None).to_flow_init()
}

/* ------------------------------------------------------------------ */
/* Body + error helpers                                                */
/* ------------------------------------------------------------------ */

/// Reads the full H3 request body into a [`BodyWriter`], or `None` if empty.
async fn recv_body_into_store(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    store: &FlowStore,
) -> Result<Option<BodyWriter>> {
    let mut writer: Option<BodyWriter> = None;
    while let Some(mut chunk) = stream.recv_data().await.context("h3 recv body")? {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        if bytes.is_empty() {
            continue;
        }
        let w = writer.get_or_insert_with(|| store.bodies().writer(store.max_body_bytes()));
        w.write(&bytes);
    }
    Ok(writer)
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// SNI and ALPN from the completed client-facing QUIC handshake, when present.
///
/// Shared by accept-only and reverse so both legs record the same client facts.
pub(crate) fn client_handshake_names(
    conn: &quinn::Connection,
) -> (Option<String>, Option<String>) {
    let Some(data) = conn.handshake_data() else {
        return (None, None);
    };
    let Ok(hs) = data.downcast::<quinn::crypto::rustls::HandshakeData>() else {
        return (None, None);
    };
    let sni = hs.server_name;
    let alpn = hs
        .protocol
        .as_ref()
        .and_then(|p| std::str::from_utf8(p).ok())
        .map(|s| s.to_string());
    (sni, alpn)
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use http::{Method, Request};

    use crate::types::{FlowResponse, FlowState, HttpVersion};

    fn remote() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 54321)
    }

    fn request(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).expect("request")
    }

    #[test]
    fn from_http_decodes_pseudo_headers_into_flow_fields() {
        let req = request(
            "GET",
            "https://api.example.com:8443/v1/users?id=1",
            &[("accept", "application/json"), ("x-trace", "abc")],
        );
        let meta = H3RequestMeta::from_http(
            req,
            remote(),
            Some("api.example.com".into()),
            Some("conn-1".into()),
            Some(0),
        );

        assert_eq!(meta.method, "GET");
        assert_eq!(meta.scheme, Scheme::Https);
        assert_eq!(meta.host, "api.example.com");
        assert_eq!(meta.port, 8443);
        assert_eq!(meta.authority, "api.example.com:8443");
        assert_eq!(meta.path, "/v1/users?id=1");
        assert_eq!(
            meta.url(),
            "https://api.example.com:8443/v1/users?id=1"
        );
        assert_eq!(meta.connection_id.as_deref(), Some("conn-1"));
        assert_eq!(meta.stream_id, Some(0));
        assert_eq!(meta.sni.as_deref(), Some("api.example.com"));
        assert!(meta
            .headers
            .iter()
            .any(|(k, v)| k == "accept" && v == "application/json"));
    }

    #[test]
    fn default_https_port_omitted_from_authority_fallback() {
        let req = request("POST", "https://origin.test/submit", &[]);
        let meta = H3RequestMeta::from_http(req, remote(), None, None, None);
        assert_eq!(meta.port, 443);
        assert_eq!(meta.authority, "origin.test");
        assert_eq!(meta.path, "/submit");
        assert_eq!(meta.scheme, Scheme::Https);
    }

    #[test]
    fn http_scheme_uses_port_80() {
        let req = request("GET", "http://plain.example/x", &[]);
        let meta = H3RequestMeta::from_http(req, remote(), None, None, None);
        assert_eq!(meta.scheme, Scheme::Http);
        assert_eq!(meta.port, 80);
        assert_eq!(meta.url(), "http://plain.example/x");
    }

    #[test]
    fn missing_host_falls_back_to_sni_then_peer_ip() {
        // Absolute-form URI without host is unusual; path-only falls through.
        let req = request("GET", "/only-path", &[]);
        let with_sni =
            H3RequestMeta::from_http(req, remote(), Some("sni.example".into()), None, None);
        assert_eq!(with_sni.host, "sni.example");
        assert_eq!(with_sni.port, 443);

        let req = request("GET", "/only-path", &[]);
        let no_sni = H3RequestMeta::from_http(req, remote(), None, None, None);
        assert_eq!(no_sni.host, "10.0.0.5");
    }

    #[test]
    fn to_flow_init_is_http3_intercepted_with_negotiated_alpn() {
        let req = request(
            "PUT",
            "https://api.example.com/resource",
            &[("content-type", "text/plain")],
        );
        let mut meta = H3RequestMeta::from_http(
            req,
            remote(),
            Some("api.example.com".into()),
            Some("cid".into()),
            Some(4),
        );
        meta.alpn = Some("h3".into());
        let init = meta.to_flow_init();

        assert_eq!(init.kind, FlowKind::Http);
        assert!(init.intercepted);
        assert_eq!(init.request.http_version, HttpVersion::Http3);
        assert_eq!(init.request.method, "PUT");
        assert_eq!(init.request.host, "api.example.com");
        assert_eq!(init.request.path, "/resource");
        assert_eq!(init.server.alpn.as_deref(), Some("h3"));
        assert_eq!(init.server.sni.as_deref(), Some("api.example.com"));
        assert_eq!(init.server.tls_version.as_deref(), Some("QUIC"));
        assert_eq!(init.client.address, "10.0.0.5");
        assert_eq!(init.client.port, 54321);
        assert!(init.request.body.is_none());
        assert_eq!(init.transport, Some(Transport::Quic));
        assert_eq!(init.connection_id.as_deref(), Some("cid"));
        assert_eq!(init.stream_id, Some(4));
        assert_eq!(init.upstream_stream_id, None);
    }

    #[test]
    fn to_flow_init_does_not_invent_alpn_when_handshake_had_none() {
        let meta = H3RequestMeta::from_http(
            request("GET", "https://api.example.com/", &[]),
            remote(),
            None,
            None,
            None,
        );
        let init = meta.to_flow_init();
        assert!(init.server.alpn.is_none());
    }

    #[test]
    fn flow_store_create_records_complete_http3_request_and_body() {
        let store = FlowStore::new(32, 1024, 4096);
        let req = request(
            "POST",
            "https://api.example.com/echo",
            &[("content-type", "text/plain"), ("x-id", "42")],
        );
        let meta = H3RequestMeta::from_http(
            req,
            remote(),
            Some("api.example.com".into()),
            Some("c1".into()),
            Some(8),
        );
        let id = store.create(meta.to_flow_init());

        let mut writer = store.bodies().writer(store.max_body_bytes());
        writer.write(b"hello-h3");
        let body = writer.finish(None, Some("text/plain".into()));
        store.update(&id, |flow| {
            flow.request.body = Some(body);
            flow.state = FlowState::Streaming;
            flow.response = Some(FlowResponse {
                status: 501,
                status_text: "Not Implemented".into(),
                http_version: HttpVersion::Http3,
                headers: vec![("server".into(), "proxima-quic".into())],
                body: None,
            });
        });
        store.finish(&id);

        let flow = store.get(&id).expect("flow");
        assert_eq!(flow.state, FlowState::Complete);
        assert_eq!(flow.request.http_version, HttpVersion::Http3);
        assert_eq!(flow.request.method, "POST");
        assert_eq!(flow.request.path, "/echo");
        assert!(flow.intercepted);
        assert_eq!(flow.transport, Some(Transport::Quic));
        assert_eq!(flow.connection_id.as_deref(), Some("c1"));
        assert_eq!(flow.stream_id, Some(8));
        let body = flow.request.body.expect("request body");
        assert_eq!(body.size, 8);
        assert_eq!(
            store.bodies().read(&body.id).as_deref(),
            Some(&b"hello-h3"[..])
        );
        let resp = flow.response.expect("response");
        assert_eq!(resp.status, 501);
        assert_eq!(resp.http_version, HttpVersion::Http3);
    }

    #[test]
    fn fail_h3_marks_error_state() {
        use super::super::stream::H3StreamFlow;
        use std::sync::Arc;

        let store = Arc::new(FlowStore::new(8, 256, 1024));
        let meta = H3RequestMeta::from_http(
            request("GET", "https://x.test/", &[]),
            remote(),
            None,
            None,
            None,
        );
        let flow = H3StreamFlow::open(store.clone(), &meta);
        let id = flow.id().clone();
        flow.fail_h3("synthetic stream error");
        let got = store.get(&id).expect("flow");
        assert_eq!(got.state, FlowState::Error);
        assert_eq!(
            got.error.as_ref().and_then(|e| e.code.as_deref()),
            Some(super::super::codes::H3)
        );
    }

    #[test]
    fn flow_init_from_request_matches_from_http() {
        let req = request("DELETE", "https://api.example.com/item/1", &[("x", "y")]);
        let a = flow_init_from_request(&req, remote(), Some("api.example.com".into()));
        let b = H3RequestMeta::from_http(
            request("DELETE", "https://api.example.com/item/1", &[("x", "y")]),
            remote(),
            Some("api.example.com".into()),
            None,
            None,
        )
        .to_flow_init();
        assert_eq!(a.request.method, b.request.method);
        assert_eq!(a.request.url, b.request.url);
        assert_eq!(a.request.http_version, HttpVersion::Http3);
        assert_eq!(a.kind, FlowKind::Http);
    }

    #[test]
    fn method_is_preserved_case_from_http() {
        // http::Method normalises known methods; custom tokens stay as given.
        let req = Request::builder()
            .method(Method::from_bytes(b"PROPFIND").unwrap())
            .uri("https://dav.example/x")
            .body(())
            .unwrap();
        let meta = H3RequestMeta::from_http(req, remote(), None, None, None);
        assert_eq!(meta.method, "PROPFIND");
    }

    #[test]
    fn multiplexed_streams_share_connection_id_distinct_stream_ids() {
        // Optional D9 multiplex unit: one client QUIC leg (one connection_id)
        // carries many H3 request streams with distinct stream_id values.
        let store = FlowStore::new(16, 1024, 4096);
        let conn = "shared-quic-conn";
        let streams = [0u64, 4, 8];
        let mut ids = Vec::new();
        for sid in streams {
            let path = format!("/s{sid}");
            let meta = H3RequestMeta::from_http(
                request("GET", &format!("https://mux.example{path}"), &[]),
                remote(),
                Some("mux.example".into()),
                Some(conn.into()),
                Some(sid),
            );
            let id = store.create(meta.to_flow_init());
            store.finish(&id);
            ids.push(id);
        }

        let mut seen_streams = Vec::new();
        for id in &ids {
            let flow = store.get(id).expect("flow");
            assert_eq!(flow.connection_id.as_deref(), Some(conn));
            assert_eq!(flow.transport, Some(Transport::Quic));
            assert_eq!(flow.request.http_version, HttpVersion::Http3);
            assert!(flow.intercepted);
            seen_streams.push(flow.stream_id.expect("stream_id"));
        }
        seen_streams.sort_unstable();
        assert_eq!(seen_streams, vec![0, 4, 8]);
        // List grouping keys live on Flow and are mirrored into FlowSummary by
        // capture::summarize; here we only lock the store-side fields.
        for id in &ids {
            let flow = store.get(id).expect("flow");
            assert_eq!(flow.connection_id.as_deref(), Some(conn));
            assert!(flow.stream_id.is_some());
            assert_eq!(flow.transport, Some(Transport::Quic));
            assert_eq!(flow.state, FlowState::Complete);
        }
    }

    #[test]
    fn to_flow_init_rewritten_updates_url_and_server_not_client_stream() {
        let meta = H3RequestMeta::from_http(
            request("GET", "https://public.edge/hello", &[("x", "1")]),
            remote(),
            Some("public.edge".into()),
            Some("c-rewrite".into()),
            Some(12),
        );
        let init = meta.to_flow_init_rewritten("origin.internal", 443, "origin.internal");
        assert_eq!(init.request.host, "origin.internal");
        assert_eq!(init.request.port, 443);
        assert_eq!(init.request.authority, "origin.internal");
        assert_eq!(init.request.url, "https://origin.internal/hello");
        assert_eq!(init.request.path, "/hello");
        // Client-leg multiplex ids are preserved; upstream id is filled later.
        assert_eq!(init.connection_id.as_deref(), Some("c-rewrite"));
        assert_eq!(init.stream_id, Some(12));
        assert_eq!(init.upstream_stream_id, None);
        assert_eq!(init.server.sni.as_deref(), Some("origin.internal"));
        // ALPN is whatever the client handshake set on meta (none here).
        assert!(init.server.alpn.is_none());
        // Client field lines stay as decoded (including any Host); hop rules run
        // only on the wire send path.
        assert!(init
            .request
            .headers
            .iter()
            .any(|(k, v)| k == "x" && v == "1"));
    }

    #[test]
    fn header_value_is_case_insensitive() {
        let headers = vec![
            ("Content-Type".into(), "text/plain".into()),
            ("X-Other".into(), "n".into()),
        ];
        assert_eq!(
            header_value(&headers, "content-type").as_deref(),
            Some("text/plain")
        );
        assert_eq!(header_value(&headers, "CONTENT-TYPE").as_deref(), Some("text/plain"));
        assert!(header_value(&headers, "missing").is_none());
    }

    #[test]
    fn accept_only_body_is_honest_about_no_forward() {
        let text = std::str::from_utf8(ACCEPT_ONLY_BODY).expect("utf8");
        assert!(text.contains("reverse"), "body should mention reverse: {text}");
        assert!(
            text.contains("HTTP/3") || text.contains("QUIC"),
            "body should name the protocol: {text}"
        );
    }
}
