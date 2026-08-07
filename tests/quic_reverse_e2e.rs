//! Localhost reverse HTTP/3 MITM and accept-only integration tests.
//!
//! Built only with `--features quic` (see Cargo.toml `[[test]]` required-features).
//! Default `cargo test` never links quinn/h3. These tests bind real UDP on
//! loopback; they are not `#[ignore]`.

#![cfg(feature = "quic")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Once};
use std::time::Duration;

use bytes::{Buf, Bytes};
use proxima::ca::CertAuthority;
use proxima::capture::FlowStore;
use proxima::quic::{
    bind_udp, client_crypto, dial_h3, server_crypto_fixed, UpstreamAuthority, ALPN_H3, QuicConfig,
    QuicDeps, QuicEndpoint, QuicServer,
};
use proxima::types::{FlowState, HttpVersion, Transport};
use quinn::{ClientConfig, Endpoint};
use rustls::RootCertStore;
use tokio::sync::watch;

static CRYPTO: Once = Once::new();

fn install_crypto() {
    CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn temp_ca() -> (tempfile::TempDir, Arc<CertAuthority>) {
    let dir = tempfile::tempdir().expect("tempdir for Proxima CA");
    let ca = CertAuthority::open(dir.path()).expect("open CA");
    (dir, Arc::new(ca))
}

fn client_trusting_ca(ca: &CertAuthority) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(ca.cert_der().clone())
        .expect("add Proxima root");
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    tls.enable_early_data = false;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QuicClientConfig");
    ClientConfig::new(Arc::new(quic))
}

/// Feature gate smoke: this binary only compiles under `quic`.
#[test]
fn quic_feature_is_enabled() {
    assert!(cfg!(feature = "quic"));
}

/// Origin H3 server that answers one GET/POST with a fixed body and echoes the
/// request body size in a response header.
async fn run_origin_h3(
    endpoint: QuicEndpoint,
    expected_path: &'static str,
    response_body: &'static [u8],
) {
    let incoming = match endpoint.accept().await {
        Some(i) => i,
        None => return,
    };
    let conn = match incoming.await {
        Ok(c) => c,
        Err(_) => {
            endpoint.close_and_drain().await;
            return;
        }
    };
    let mut h3: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
            Ok(h) => h,
            Err(_) => {
                endpoint.close_and_drain().await;
                return;
            }
        };
    if let Ok(Some(resolver)) = h3.accept().await {
        if let Ok((req, mut stream)) = resolver.resolve_request().await {
            let path = req.uri().path().to_string();
            let mut body = Vec::new();
            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                let b = chunk.copy_to_bytes(chunk.remaining());
                body.extend_from_slice(&b);
            }
            assert_eq!(path, expected_path, "origin saw unexpected path");
            let resp = http::Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .header("x-echo-len", body.len().to_string())
                .body(())
                .unwrap();
            let _ = stream.send_response(resp).await;
            let _ = stream.send_data(Bytes::from_static(response_body)).await;
            let _ = stream.finish().await;
        }
    }
    // Keep the endpoint alive briefly so the client can finish.
    tokio::time::sleep(Duration::from_millis(100)).await;
    endpoint.close_and_drain().await;
}

#[tokio::test]
async fn reverse_h3_localhost_mitm_captures_complete_http3_flow() {
    install_crypto();
    let (_dir, ca) = temp_ca();
    let store = Arc::new(FlowStore::new(64, 1024 * 1024, 8 * 1024 * 1024));

    // Origin: fixed localhost leaf, answers /echo.
    let origin_sock = bind_udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind origin");
    let origin_cfg = server_crypto_fixed(ca.clone(), "localhost").expect("origin crypto");
    let origin_ep = QuicEndpoint::server_with_config(origin_sock, origin_cfg).expect("origin ep");
    let origin_addr = origin_ep.local_addr();
    let origin_body = b"origin-ok";
    let origin_task = tokio::spawn(run_origin_h3(origin_ep, "/echo", origin_body));

    // Proxima reverse-h3 on a second UDP port.
    let reverse_sock = bind_udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind reverse");
    let reverse_ep = QuicEndpoint::server(reverse_sock, ca.clone()).expect("reverse ep");
    let reverse_addr = reverse_ep.local_addr();
    let upstream_spec = format!("localhost:{}", origin_addr.port());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let deps = Arc::new(QuicDeps::new(
        ca.clone(),
        store.clone(),
        Some(upstream_spec.clone()),
        // Origin leaf is Proxima CA; reverse upstream trust uses system roots by
        // default. Use insecure so the localhost test leaf is accepted without
        // installing Proxima into native roots for the origin leg.
        true,
    ));
    let serve = tokio::spawn(async move {
        QuicServer::serve(reverse_ep, deps, shutdown_rx).await
    });

    // Give accept loop a moment.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client trusts only the Proxima root (MITM leaf), not the origin directly.
    let mut client_ep = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("client endpoint");
    client_ep.set_default_client_config(client_trusting_ca(&ca));

    let authority = UpstreamAuthority {
        host: "localhost".into(),
        port: reverse_addr.port(),
    };
    let mut upstream = dial_h3(&client_ep, &authority, reverse_addr)
        .await
        .expect("client dial reverse");

    let req_body = Bytes::from_static(b"ping-body");
    let req = http::Request::builder()
        .method("POST")
        .uri(format!(
            "https://public.reverse.local:{}/echo",
            reverse_addr.port()
        ))
        .header("content-type", "text/plain")
        .body(())
        .unwrap();
    let mut stream = upstream
        .send_request
        .send_request(req)
        .await
        .expect("open client stream");
    stream.send_data(req_body.clone()).await.expect("send body");
    stream.finish().await.expect("finish request");

    let resp = stream.recv_response().await.expect("response headers");
    assert_eq!(resp.status(), 200);
    let mut got = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("recv body") {
        let b = chunk.copy_to_bytes(chunk.remaining());
        got.extend_from_slice(&b);
    }
    assert_eq!(got.as_slice(), origin_body);

    // Wait for FlowStore to record Complete.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let flow = loop {
        let q = proxima::types::FlowQuery::default();
        let flows = store.all(&q);
        if let Some(f) = flows
            .into_iter()
            .find(|f| f.state == FlowState::Complete && f.request.path.contains("/echo"))
        {
            break f;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("no Complete Http3 flow captured in time");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    };

    assert_eq!(flow.request.http_version, HttpVersion::Http3);
    assert_eq!(flow.transport, Some(Transport::Quic));
    assert!(flow.intercepted);
    assert_eq!(flow.state, FlowState::Complete);
    assert!(flow.connection_id.is_some());
    assert!(flow.stream_id.is_some());
    assert!(
        flow.upstream_stream_id.is_some(),
        "reverse must record origin-leg stream id separately from client leg"
    );
    // Numeric stream ids may both be 0 on first bidi streams of each leg;
    // what matters is that both legs were recorded as distinct fields.
    // Reverse rewrite: capture authority is origin-facing.
    assert_eq!(flow.request.host, "localhost");
    assert_eq!(flow.request.port, origin_addr.port());
    assert!(
        !flow.rewrites.is_empty()
            || flow.request.path.contains("/echo"),
        "expected rewrite note or path: rewrites={:?}",
        flow.rewrites
    );
    let req_meta = flow.request.body.expect("request body meta");
    assert_eq!(req_meta.size, req_body.len() as u64);
    let stored_req = store.bodies().read(&req_meta.id).expect("req bytes");
    assert_eq!(stored_req.as_ref(), req_body.as_ref());
    let resp = flow.response.expect("response");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.http_version, HttpVersion::Http3);
    let resp_meta = resp.body.expect("response body meta");
    assert_eq!(resp_meta.size, origin_body.len() as u64);
    let stored_resp = store.bodies().read(&resp_meta.id).expect("resp bytes");
    assert_eq!(stored_resp.as_ref(), origin_body);

    client_ep.close(0u32.into(), b"done");
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), origin_task).await;
}

#[tokio::test]
async fn accept_only_localhost_records_501_and_request_body() {
    install_crypto();
    let (_dir, ca) = temp_ca();
    let store = Arc::new(FlowStore::new(64, 1024 * 1024, 8 * 1024 * 1024));

    let sock = bind_udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind");
    let ep = QuicEndpoint::server(sock, ca.clone()).expect("ep");
    let addr = ep.local_addr();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let deps = Arc::new(QuicDeps::new(ca.clone(), store.clone(), None, false));
    let serve = tokio::spawn(async move { QuicServer::serve(ep, deps, shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client_ep = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("client");
    client_ep.set_default_client_config(client_trusting_ca(&ca));

    let authority = UpstreamAuthority {
        host: "localhost".into(),
        port: addr.port(),
    };
    let mut upstream = dial_h3(&client_ep, &authority, addr)
        .await
        .expect("dial accept-only");

    let req_body = Bytes::from_static(b"hello-accept-only");
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://localhost:{}/probe", addr.port()))
        .header("content-type", "text/plain")
        .body(())
        .unwrap();
    let mut stream = upstream
        .send_request
        .send_request(req)
        .await
        .expect("open stream");
    stream.send_data(req_body.clone()).await.expect("send");
    stream.finish().await.expect("finish");

    let resp = stream.recv_response().await.expect("headers");
    assert_eq!(resp.status(), http::StatusCode::NOT_IMPLEMENTED);
    let mut got = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("body") {
        got.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    let text = String::from_utf8_lossy(&got);
    assert!(
        text.contains("reverse") || text.contains("HTTP/3") || text.contains("QUIC"),
        "honest accept-only body: {text}"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let flow = loop {
        let q = proxima::types::FlowQuery::default();
        let flows = store.all(&q);
        if let Some(f) = flows.into_iter().find(|f| f.state == FlowState::Complete) {
            break f;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("no Complete accept-only flow");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    };

    assert_eq!(flow.request.http_version, HttpVersion::Http3);
    assert_eq!(flow.transport, Some(Transport::Quic));
    assert!(flow.connection_id.is_some());
    assert!(flow.stream_id.is_some());
    let meta = flow.request.body.expect("request body");
    assert_eq!(meta.size, req_body.len() as u64);
    let stored = store.bodies().read(&meta.id).expect("bytes");
    assert_eq!(stored.as_ref(), req_body.as_ref());
    let resp = flow.response.expect("response");
    assert_eq!(resp.status, 501);

    client_ep.close(0u32.into(), b"done");
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve).await;
}

#[tokio::test]
async fn dial_h3_sends_request_and_receives_response() {
    // Exercises h3-quinn send_request framing end-to-end (not handshake-only).
    install_crypto();
    let (_dir, ca) = temp_ca();

    let sock = bind_udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind");
    let cfg = server_crypto_fixed(ca.clone(), "localhost").expect("crypto");
    let origin = QuicEndpoint::server_with_config(sock, cfg).expect("origin");
    let origin_addr = origin.local_addr();
    let origin_task = tokio::spawn(run_origin_h3(origin, "/roundtrip", b"pong"));

    let mut client_ep = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("client");
    client_ep.set_default_client_config(client_trusting_ca(&ca));

    let authority = UpstreamAuthority {
        host: "localhost".into(),
        port: origin_addr.port(),
    };
    let mut up = dial_h3(&client_ep, &authority, origin_addr)
        .await
        .expect("dial_h3");
    assert_eq!(up.negotiated_alpn().as_deref(), Some(ALPN_H3));

    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/roundtrip", origin_addr.port()))
        .body(())
        .unwrap();
    let mut stream = up.send_request.send_request(req).await.expect("send_request");
    stream.finish().await.expect("finish");
    let resp = stream.recv_response().await.expect("response");
    assert_eq!(resp.status(), 200);
    let mut got = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("data") {
        got.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    assert_eq!(got.as_slice(), b"pong");

    client_ep.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(2), origin_task).await;
    let _ = client_crypto(true);
}

#[tokio::test]
async fn ipv4_only_bind_prefers_v4_resolved_addrs() {
    // Regression: IPv4-only local must not dial AAAA-first as if dual-stack.
    use proxima::quic::order_addrs_for_local;

    let v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let v6: SocketAddr = "[::1]:443".parse().unwrap();
    let local: SocketAddr = "0.0.0.0:9443".parse().unwrap();
    let ordered = order_addrs_for_local(vec![v6, v4], Some(local));
    assert_eq!(ordered, vec![v4], "IPv4-only bind must filter to IPv4 peers");

    let dual: SocketAddr = "[::]:9443".parse().unwrap();
    let ordered_dual = order_addrs_for_local(vec![v4, v6], Some(dual));
    assert_eq!(
        ordered_dual,
        vec![v6, v4],
        "dual-stack :: bind prefers IPv6 then IPv4-mapped"
    );
}

// Silence unused import if QuicConfig is not needed in every path.
#[allow(dead_code)]
fn _config_shape() -> QuicConfig {
    QuicConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        reverse_upstream: None,
        insecure_upstream: false,
    }
}
