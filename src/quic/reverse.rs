//! Reverse HTTP/3 MITM: client speaks H3 to us, we open H3 upstream.
//!
//! ## What this path is
//!
//! A separate UDP listener (not the classic TCP proxy port) terminates QUIC
//! with a CA-minted leaf, decodes HTTP/3, rewrites the authority to a fixed
//! upstream, dials that origin over QUIC+H3, and bridges each request stream
//! as one [`Flow`]. The regular phone HTTP proxy still cannot see device QUIC;
//! reverse (and later WireGuard/TUN) is how UDP traffic enters Proxima.
//!
//! On macOS, bind and firewall behaviour for that UDP listener are documented
//! under [`super::udp`] ("macOS notes"). Localhost reverse e2e is the usual
//! Darwin developer path; LAN clients may need the Application Firewall to
//! allow the binary. There is no transparent pf redirect in this module.
//!
//! ## Per-stream bridge
//!
//! 1. Client HEADERS open a flow via [`super::stream::H3StreamFlow`] (`Http` /
//!    `Http3`, transport `quic`).
//! 2. Request body is teed into the body store while being sent upstream.
//! 3. Upstream response headers/body are returned to the client and recorded.
//! 4. Errors after open call [`H3StreamFlow::fail`] (never invent Complete).
//!
//! Multiplex: every stream on one client QUIC connection shares one
//! `connection_id` (Proxima UUID). Client and upstream stream ids are recorded
//! separately because MITM reopens the origin leg.
//!
//! Upstream dialing lives in [`super::forward_upstream`]. Hop-by-hop headers use
//! [`Wire::Http3`] (same rules as HTTP/2). QPACK control streams and datagrams
//! never become flows.
//!
//! ## Security: no 0-RTT
//!
//! Both legs disable early data via [`super::tls`] (`max_early_data_size = 0`,
//! `enable_early_data = false`). Upstream dials await a full 1-RTT handshake
//! and never call `into_0rtt`. MITM cannot forward 0-RTT: client tickets are
//! for Proxima's leaf, origin tickets are separate, and early data is
//! replayable.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use http::header::HeaderMap;
use http::Uri;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::ca::CertAuthority;
use crate::capture::{new_id, FlowStore};
use crate::proxy::headers::{self, Wire};

use super::endpoint::QuicEndpoint;
use super::forward_upstream::{dial_upstream_h3, split_host_port, UpstreamH3};
use super::http3::{client_handshake_names, H3RequestMeta};
use super::stream::{
    classify_bridge_error_code, codes, record_handshake_failure, H3StreamFlow,
};
use super::tls::client_crypto;

/// Cap hung DNS/handshake so reverse connection tasks cannot pin drain forever.
const REVERSE_DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Reverse-proxy configuration for one upstream authority.
#[derive(Debug, Clone)]
pub struct ReverseH3Config {
    /// host or host:port for the origin (default port 443).
    pub upstream: String,
    pub insecure_upstream: bool,
}

/// Parsed reverse origin (host, port, display authority).
#[derive(Debug, Clone)]
struct ReverseOrigin {
    host: String,
    port: u16,
    /// `host` or `host:port` for non-default HTTPS ports.
    authority: String,
    /// Original CLI/config spec used for dial (`host` or `host:port`).
    dial_spec: String,
}

impl ReverseOrigin {
    fn from_spec(spec: &str) -> Self {
        let (host, port) = split_host_port(spec, 443);
        let authority = format_authority(&host, port);
        Self {
            host,
            port,
            authority,
            dial_spec: spec.to_string(),
        }
    }
}

/// Client-facing multiplex identity for one QUIC connection.
#[derive(Debug, Clone)]
struct ClientLeg {
    remote: SocketAddr,
    connection_id: String,
    sni: Option<String>,
    alpn: Option<String>,
}

/// Accept client H3, forward each request upstream over H3, record flows.
///
/// Does not close the endpoint: `QuicServer::serve` owns close + drain.
/// Connection tasks hold a clone of `drain_tx` so serve can wait for them.
pub async fn run_reverse_h3(
    endpoint: &mut QuicEndpoint,
    _ca: Arc<CertAuthority>,
    store: Arc<FlowStore>,
    cfg: ReverseH3Config,
    mut shutdown: watch::Receiver<bool>,
    drain_tx: mpsc::Sender<()>,
) -> Result<()> {
    let client_config = client_crypto(cfg.insecure_upstream)?;
    endpoint.set_default_client_config(client_config);

    let origin = ReverseOrigin::from_spec(&cfg.upstream);
    info!(
        local = %endpoint.local_addr(),
        upstream = %cfg.upstream,
        authority = %origin.authority,
        "QUIC reverse H3 mode"
    );

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            incoming = endpoint.accept() => {
                match incoming {
                    None => break,
                    Some(connecting) => {
                        let store = store.clone();
                        let raw = endpoint.raw().clone();
                        let origin = origin.clone();
                        let drain = drain_tx.clone();
                        tokio::spawn(async move {
                            let _drain = drain.clone();
                            if let Err(err) =
                                reverse_one(connecting, raw, store, origin, drain).await
                            {
                                // Handshake/dial failures already warn + may record flows.
                                debug!(error = %err, "reverse h3 connection failed");
                            }
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

async fn reverse_one(
    incoming: quinn::Incoming,
    endpoint: quinn::Endpoint,
    store: Arc<FlowStore>,
    origin: ReverseOrigin,
    drain_tx: mpsc::Sender<()>,
) -> Result<()> {
    let remote = incoming.remote_address();
    let client_conn = match incoming.await {
        Ok(c) => c,
        Err(err) => {
            let err = anyhow::Error::new(err).context("client QUIC handshake");
            warn!(%remote, error = %err, "reverse client QUIC handshake failed");
            record_handshake_failure(&store, remote, None, &err);
            return Err(err);
        }
    };
    let remote = client_conn.remote_address();
    let (client_sni, client_alpn) = client_handshake_names(&client_conn);
    if let Some(ref a) = client_alpn {
        if a.as_bytes() != super::ALPN_H3 {
            let err = anyhow::anyhow!(
                "{}: client negotiated ALPN {a:?}, expected h3",
                codes::QUIC_ALPN
            );
            warn!(
                %remote,
                sni = client_sni.as_deref().unwrap_or("-"),
                error = %err,
                "reverse client ALPN rejected"
            );
            record_handshake_failure(&store, remote, client_sni.as_deref(), &err);
            return Err(err);
        }
    }
    // One Proxima UUID for every H3 request stream on this client QUIC leg.
    let connection_id = new_id();
    info!(
        %remote,
        %connection_id,
        sni = client_sni.as_deref().unwrap_or("-"),
        alpn = client_alpn.as_deref().unwrap_or("-"),
        upstream = %origin.authority,
        "reverse H3 client connected"
    );

    // Upstream dial (1-RTT, ALPN h3) with a hard timeout so hung DNS cannot pin drain.
    let upstream: UpstreamH3 = match tokio::time::timeout(
        REVERSE_DIAL_TIMEOUT,
        dial_upstream_h3(&endpoint, &origin.dial_spec),
    )
    .await
    {
        Ok(Ok(up)) => up,
        Ok(Err(err)) => {
            let err = err.context(format!(
                "dial upstream H3 {} ({})",
                origin.authority, codes::QUIC_UPSTREAM
            ));
            warn!(
                %remote,
                connection_id = %connection_id,
                upstream = %origin.authority,
                error = %err,
                "reverse upstream dial failed after client connect"
            );
            return Err(err);
        }
        Err(_) => {
            let err = anyhow::anyhow!(
                "dial upstream H3 {}: timed out after {}s ({})",
                origin.authority,
                REVERSE_DIAL_TIMEOUT.as_secs(),
                codes::QUIC_UPSTREAM
            );
            warn!(
                %remote,
                connection_id = %connection_id,
                upstream = %origin.authority,
                error = %err,
                "reverse upstream dial timed out"
            );
            return Err(err);
        }
    };
    let send_request = upstream.send_request;

    let mut h3_client_side = h3::server::Connection::new(h3_quinn::Connection::new(client_conn))
        .await
        .context("h3 client-facing connection")?;

    let client = ClientLeg {
        remote,
        connection_id: connection_id.clone(),
        sni: client_sni,
        alpn: client_alpn,
    };

    loop {
        match h3_client_side.accept().await {
            Ok(Some(resolver)) => {
                let (req, mut in_stream) = match resolver.resolve_request().await {
                    Ok(pair) => pair,
                    Err(err) => {
                        debug!(
                            error = %err,
                            connection_id = %client.connection_id,
                            "resolving reverse h3 request failed"
                        );
                        continue;
                    }
                };
                let store = store.clone();
                let mut out = send_request.clone();
                let origin = origin.clone();
                let client = client.clone();
                let drain = drain_tx.clone();
                tokio::spawn(async move {
                    let _drain = drain;
                    if let Err(err) =
                        proxy_request(req, &mut in_stream, &mut out, store, &origin, client).await
                    {
                        debug!(error = %err, "reverse h3 stream failed");
                    }
                });
            }
            Ok(None) => break,
            Err(err) => {
                debug!(
                    error = %err,
                    connection_id = %client.connection_id,
                    "reverse h3 accept ended"
                );
                break;
            }
        }
    }
    Ok(())
}

/// One client H3 request stream: open a flow, bridge bodies, close finish/fail.
async fn proxy_request(
    req: http::Request<()>,
    in_stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    out: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    store: Arc<FlowStore>,
    origin: &ReverseOrigin,
    client: ClientLeg,
) -> Result<()> {
    let stream_id = in_stream.id().into_inner();
    // Keep method/headers before from_http consumes the request.
    let method = req.method().clone();
    let client_headers = req.headers().clone();
    let mut meta = H3RequestMeta::from_http(
        req,
        client.remote,
        client.sni,
        Some(client.connection_id.clone()),
        Some(stream_id),
    );
    meta.alpn = client.alpn;

    let rewrite_note = if !authorities_match(&meta.authority, &origin.authority) {
        Some(format!(
            "reverse H3 rewrote authority {} -> {}",
            meta.authority, origin.authority
        ))
    } else {
        None
    };

    // Open event: capture uses origin-facing authority after reverse rewrite.
    let flow = H3StreamFlow::open_rewritten(
        store,
        &meta,
        &origin.host,
        origin.port,
        &origin.authority,
    );
    if let Some(note) = rewrite_note {
        flow.note_rewrite(note);
    }

    debug!(
        id = %flow.id(),
        connection_id = %client.connection_id,
        stream_id,
        method = %meta.method,
        path = %meta.path,
        upstream = %origin.authority,
        "reverse h3 stream bridging"
    );

    match bridge_stream(method, meta.path.clone(), client_headers, in_stream, out, &flow, origin)
        .await
    {
        Ok(()) => {
            // Close event: Complete (bridge already recorded response body).
            flow.finish();
            Ok(())
        }
        Err(err) => {
            let code = classify_bridge_error_code(&err);
            flow.fail_code(code, format!("{err:#}"));
            Err(err)
        }
    }
}

/// Forward one request/response pair after the flow is open.
///
/// Does not finish/fail the flow: the caller owns the terminal close event.
async fn bridge_stream(
    method: http::Method,
    path: String,
    client_headers: HeaderMap,
    in_stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    out: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    flow: &H3StreamFlow,
    origin: &ReverseOrigin,
) -> Result<()> {
    let req_encoding = headers::content_encoding(&client_headers);
    let req_mime = headers::content_type(&client_headers);

    // Hop-sanitised headers for the origin. Host is dropped; :authority comes
    // from the rewritten URI.
    let upstream_headers = headers::for_upstream(&client_headers, Wire::Http3);
    let upstream_uri = rewrite_upstream_uri(&path, &origin.authority)?;

    let mut builder = http::Request::builder().method(method).uri(upstream_uri);
    for (name, value) in upstream_headers.iter() {
        builder = builder.header(name, value);
    }
    let out_req = builder.body(()).context("building upstream request")?;

    let mut out_stream = out
        .send_request(out_req)
        .await
        .context("open upstream stream")?;

    // Origin stream id is distinct from the client-leg id (MITM reopens).
    let upstream_stream_id: u64 = out_stream.id().into_inner();
    flow.set_upstream_stream_id(upstream_stream_id);

    // Request body: tee into the body store while sending upstream.
    let mut req_writer = flow.body_writer();
    while let Some(mut chunk) = in_stream.recv_data().await.context("recv client body")? {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        req_writer.write(&bytes);
        out_stream
            .send_data(bytes)
            .await
            .context("send upstream body")?;
    }
    out_stream
        .finish()
        .await
        .context("finish upstream request")?;

    let request_body = if req_writer.seen() > 0 {
        Some(req_writer.finish(req_encoding, req_mime))
    } else {
        None
    };
    flow.set_request_body(request_body);
    flow.mark_request_sent();

    let resp = out_stream
        .recv_response()
        .await
        .context("upstream response headers")?;
    let status = resp.status();

    // Sanitise response hop headers before both capture and client send.
    let client_resp_headers = headers::for_client(resp.headers(), status);
    let resp_header_pairs = headers::to_pairs(&client_resp_headers);
    let resp_encoding = headers::content_encoding(&client_resp_headers);
    let resp_mime = headers::content_type(&client_resp_headers);

    flow.set_response_h3(
        status.as_u16(),
        status.canonical_reason().unwrap_or("").to_string(),
        resp_header_pairs,
    );

    let mut client_resp = http::Response::builder().status(status);
    for (name, value) in client_resp_headers.iter() {
        client_resp = client_resp.header(name, value);
    }
    in_stream
        .send_response(client_resp.body(()).context("client response")?)
        .await
        .context("send client response headers")?;

    let mut resp_writer = flow.body_writer();
    while let Some(mut chunk) = out_stream.recv_data().await.context("recv upstream body")? {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        resp_writer.write(&bytes);
        in_stream
            .send_data(bytes)
            .await
            .context("send client body")?;
    }
    in_stream.finish().await.context("finish client stream")?;

    let response_body = if resp_writer.seen() > 0 {
        Some(resp_writer.finish(resp_encoding, resp_mime))
    } else {
        None
    };
    flow.set_response_body(response_body);

    Ok(())
}

/* ------------------------------------------------------------------ */
/* Authority / URI helpers                                             */
/* ------------------------------------------------------------------ */

/// Build an absolute HTTPS URI aimed at the reverse upstream authority.
fn rewrite_upstream_uri(path: &str, upstream_authority: &str) -> Result<Uri> {
    let path = if path.is_empty() { "/" } else { path };
    let raw = format!("https://{upstream_authority}{path}");
    raw.parse::<Uri>()
        .with_context(|| format!("building upstream URI from {raw}"))
}

/// `host` or `host:port` for non-default HTTPS ports. IPv6 hosts are bracketed.
fn format_authority(host: &str, port: u16) -> String {
    let host_part = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host_part
    } else {
        format!("{host_part}:{port}")
    }
}

fn authorities_match(a: &str, b: &str) -> bool {
    let (ha, pa) = split_host_port(a, 443);
    let (hb, pb) = split_host_port(b, 443);
    ha.eq_ignore_ascii_case(&hb) && pa == pb
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::capture::FlowStore;
    use crate::types::{FlowKind, FlowState, HttpVersion, Scheme, Transport};

    #[test]
    fn format_authority_omits_default_https_port() {
        assert_eq!(format_authority("api.example", 443), "api.example");
        assert_eq!(format_authority("api.example", 8443), "api.example:8443");
        assert_eq!(format_authority("2001:db8::1", 443), "[2001:db8::1]");
        assert_eq!(format_authority("2001:db8::1", 8443), "[2001:db8::1]:8443");
    }

    #[test]
    fn rewrite_upstream_uri_replaces_authority_keeps_path() {
        let uri = rewrite_upstream_uri("/v1/hello?x=1", "origin.example:9443").expect("uri");
        assert_eq!(uri.scheme_str(), Some("https"));
        assert_eq!(
            uri.authority().map(|a| a.as_str()),
            Some("origin.example:9443")
        );
        assert_eq!(uri.path(), "/v1/hello");
        assert_eq!(uri.query(), Some("x=1"));
    }

    #[test]
    fn authorities_match_ignores_default_port_form() {
        assert!(authorities_match("api.example", "api.example:443"));
        assert!(!authorities_match("api.example", "other.example"));
        assert!(!authorities_match("api.example:443", "api.example:8443"));
    }

    #[test]
    fn classify_bridge_error_codes() {
        let up = anyhow::anyhow!("open upstream stream: connection reset");
        assert_eq!(classify_bridge_error_code(&up), codes::QUIC_UPSTREAM);
        let other = anyhow::anyhow!("recv client body: stream reset");
        assert_eq!(classify_bridge_error_code(&other), codes::H3);
        let alpn = anyhow::anyhow!("quic_alpn: upstream negotiated h2 not h3");
        assert_eq!(classify_bridge_error_code(&alpn), codes::QUIC_ALPN);
    }

    #[test]
    fn rewritten_flow_init_is_http3_quic_with_upstream_authority() {
        let remote = "10.0.0.9:40000".parse().unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("https://public.reverse.local/hello")
            .header("accept", "*/*")
            .header("host", "public.reverse.local")
            .body(())
            .unwrap();
        let meta = H3RequestMeta::from_http(
            req,
            remote,
            Some("public.reverse.local".into()),
            Some("conn-rev".into()),
            Some(0),
        );
        let init = meta.to_flow_init_rewritten("origin.example", 9443, "origin.example:9443");

        assert_eq!(init.kind, FlowKind::Http);
        assert!(init.intercepted);
        assert_eq!(init.transport, Some(Transport::Quic));
        assert_eq!(init.connection_id.as_deref(), Some("conn-rev"));
        assert_eq!(init.stream_id, Some(0));
        assert_eq!(init.upstream_stream_id, None);
        assert_eq!(init.request.http_version, HttpVersion::Http3);
        assert_eq!(init.request.host, "origin.example");
        assert_eq!(init.request.port, 9443);
        assert_eq!(init.request.authority, "origin.example:9443");
        assert_eq!(init.request.path, "/hello");
        assert_eq!(init.request.url, "https://origin.example:9443/hello");
        assert_eq!(init.request.scheme, Scheme::Https);
        // ALPN only when client handshake set it on meta (none in this unit path).
        assert!(init.server.alpn.is_none());
        assert_eq!(init.server.sni.as_deref(), Some("origin.example"));
        assert_eq!(init.server.address.as_deref(), Some("origin.example"));
        assert_eq!(init.server.port, Some(9443));

        // Client headers are still the decoded client field lines (including
        // a stale Host); hop sanitisation happens only on the upstream send.
        assert!(init
            .request
            .headers
            .iter()
            .any(|(k, v)| k == "accept" && v == "*/*"));
    }

    #[test]
    fn reverse_flow_create_records_multiplex_fields() {
        let store = Arc::new(FlowStore::new(16, 1024, 4096));
        let remote = "127.0.0.1:50000".parse().unwrap();
        let req = http::Request::builder()
            .method("POST")
            .uri("https://edge.local/api")
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        let meta = H3RequestMeta::from_http(
            req,
            remote,
            Some("edge.local".into()),
            Some("c9".into()),
            Some(4),
        );
        let flow = H3StreamFlow::open_rewritten(
            store.clone(),
            &meta,
            "origin.test",
            443,
            "origin.test",
        );
        let id = flow.id().clone();
        flow.set_upstream_stream_id(8);
        flow.note_rewrite("reverse H3 rewrote authority edge.local -> origin.test");
        flow.finish();

        let got = store.get(&id).expect("flow");
        assert_eq!(got.state, FlowState::Complete);
        assert_eq!(got.transport, Some(Transport::Quic));
        assert_eq!(got.connection_id.as_deref(), Some("c9"));
        assert_eq!(got.stream_id, Some(4));
        assert_eq!(got.upstream_stream_id, Some(8));
        assert_eq!(got.request.authority, "origin.test");
        assert!(!got.rewrites.is_empty());
        assert!(got.intercepted);
        assert_eq!(got.request.http_version, HttpVersion::Http3);
    }

    #[test]
    fn rewrite_upstream_uri_empty_path_becomes_slash() {
        let uri = rewrite_upstream_uri("", "origin.example").expect("uri");
        assert_eq!(uri.path(), "/");
        assert_eq!(uri.authority().map(|a| a.as_str()), Some("origin.example"));
        let slash = rewrite_upstream_uri("/", "origin.example:8443").expect("uri");
        assert_eq!(slash.path(), "/");
        assert_eq!(
            slash.authority().map(|a| a.as_str()),
            Some("origin.example:8443")
        );
    }

    #[test]
    fn two_reverse_streams_share_connection_distinct_client_and_upstream_ids() {
        // MITM never claims client stream_id == upstream_stream_id.
        let store = Arc::new(FlowStore::new(16, 1024, 4096));
        let remote = "127.0.0.1:51000".parse().unwrap();
        let conn = "rev-conn-mux";
        let pairs = [(0u64, 100u64), (4u64, 104u64)];
        let mut ids = Vec::new();
        for (client_sid, up_sid) in pairs {
            let req = http::Request::builder()
                .method("GET")
                .uri(format!("https://public.edge/s{client_sid}"))
                .body(())
                .unwrap();
            let meta = H3RequestMeta::from_http(
                req,
                remote,
                Some("public.edge".into()),
                Some(conn.into()),
                Some(client_sid),
            );
            let flow = H3StreamFlow::open_rewritten(
                store.clone(),
                &meta,
                "origin.test",
                443,
                "origin.test",
            );
            let id = flow.id().clone();
            flow.set_upstream_stream_id(up_sid);
            flow.finish();
            ids.push((id, client_sid, up_sid));
        }
        for (id, client_sid, up_sid) in ids {
            let got = store.get(&id).expect("flow");
            assert_eq!(got.connection_id.as_deref(), Some(conn));
            assert_eq!(got.stream_id, Some(client_sid));
            assert_eq!(got.upstream_stream_id, Some(up_sid));
            assert_ne!(
                got.stream_id, got.upstream_stream_id,
                "client and origin stream ids must stay distinct across MITM"
            );
        }
    }

    #[test]
    fn classify_bridge_error_dial_is_upstream() {
        let dial = anyhow::anyhow!("dial upstream H3: connection refused");
        assert_eq!(classify_bridge_error_code(&dial), codes::QUIC_UPSTREAM);
        let connect = anyhow::anyhow!("failed to connect to peer");
        assert_eq!(classify_bridge_error_code(&connect), codes::QUIC_UPSTREAM);
    }

    #[test]
    fn reverse_h3_config_clone_preserves_flags() {
        let cfg = ReverseH3Config {
            upstream: "origin.example:443".into(),
            insecure_upstream: true,
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.upstream, "origin.example:443");
        assert!(cloned.insecure_upstream);
    }

    #[test]
    fn reverse_dial_timeout_bounds_hung_upstream() {
        // Acceptance: reverse dial must not pin shared shutdown forever.
        assert_eq!(REVERSE_DIAL_TIMEOUT, Duration::from_secs(15));
        assert!(
            REVERSE_DIAL_TIMEOUT.as_secs() >= 1 && REVERSE_DIAL_TIMEOUT.as_secs() <= 60,
            "dial timeout should be finite and short enough for drain"
        );
    }
}
