//! QUIC stack smoke integration tests.
//!
//! Built only with `--features quic` (see Cargo.toml `[[test]]` required-features).
//! Default `cargo test` never links quinn/h3.
//!
//! ## What runs where
//!
//! - **Localhost UDP** tests always run under `--features quic`. They bind
//!   loopback, mint CA leaves, and exercise a 1-RTT handshake. No external
//!   network is required.
//! - **External network** skeletons are marked `#[ignore]`. Enable them when
//!   the machine has outbound net:
//!   `cargo test --features quic --test quic_smoke -- --ignored`
//!
//! ## Honesty
//!
//! These tests exercise the UDP QUIC path only. They never claim that the
//! classic TCP CONNECT / regular proxy port can see QUIC or invent HTTP/3
//! flows for non-terminated traffic.

#![cfg(feature = "quic")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Once};
use std::time::Duration;

use proxima::ca::CertAuthority;
use proxima::capture::FlowStore;
use proxima::quic::{
    bind_udp, bound_addr, client_crypto, server_crypto, server_crypto_fixed, server_endpoint,
    ALPN_H3, DRAIN_TIMEOUT, MITM_ENABLE_EARLY_DATA, MITM_MAX_EARLY_DATA_SIZE, QuicConfig,
    QuicEndpoint, QuicServer,
};
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::ServerName;
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

/// Client that trusts only the Proxima test CA (not native roots).
fn client_trusting_ca(ca: &CertAuthority) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(ca.cert_der().clone())
        .expect("add Proxima root to test client trust store");
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    tls.enable_early_data = false;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QuicClientConfig");
    ClientConfig::new(Arc::new(quic))
}

/* ------------------------------------------------------------------ */
/* Always-on under --features quic (localhost only)                    */
/* ------------------------------------------------------------------ */

/// Feature gate smoke: this binary only compiles under `quic`.
#[test]
fn quic_feature_is_enabled() {
    assert!(cfg!(feature = "quic"));
}

#[test]
fn early_data_policy_constants_are_disabled() {
    assert_eq!(MITM_MAX_EARLY_DATA_SIZE, 0);
    assert!(!MITM_ENABLE_EARLY_DATA);
    assert_eq!(ALPN_H3, b"h3");
}

#[tokio::test]
async fn bind_udp_ephemeral_localhost() {
    install_crypto();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let sock = bind_udp(addr).await.expect("bind localhost UDP");
    let local = bound_addr(&sock).expect("local_addr after port 0");
    assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(local.port(), 0, "OS must rewrite port 0");
}

#[test]
fn server_and_client_crypto_build() {
    install_crypto();
    let (_dir, ca) = temp_ca();
    let _server = server_crypto(ca.clone(), "localhost").expect("server_crypto");
    let _fixed = server_crypto_fixed(ca, "smoke.local").expect("server_crypto_fixed");
    let _client = client_crypto(true).expect("client_crypto insecure");
}

#[tokio::test]
async fn server_endpoint_on_ephemeral_port() {
    install_crypto();
    let (_dir, ca) = temp_ca();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let sock = bind_udp(addr).await.expect("bind");
    let endpoint = server_endpoint(sock, ca).expect("server_endpoint");
    assert_ne!(endpoint.local_addr().port(), 0);
    assert_eq!(endpoint.config().bind, endpoint.local_addr());
    endpoint.close_and_drain().await;
}

/// Localhost 1-RTT QUIC handshake: server uses CA leaves, ALPN is h3 only.
///
/// Does not speak HTTP/3 framing; that lives in reverse e2e. Proves the UDP
/// MITM TLS path can complete without external network.
#[tokio::test]
async fn localhost_one_rtt_handshake_alpn_h3() {
    install_crypto();
    let (_dir, ca) = temp_ca();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let sock = bind_udp(addr).await.expect("bind");
    let endpoint = QuicEndpoint::server(sock, ca.clone()).expect("server endpoint");
    let local = endpoint.local_addr();

    let accept = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("accept");
        // Full 1-RTT only: never into_0rtt on either leg.
        let conn = incoming.await.expect("server handshake");
        let alpn = conn
            .handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.protocol);
        assert_eq!(alpn.as_deref(), Some(ALPN_H3));
        endpoint.close_and_drain().await;
        conn
    });

    let mut client_ep = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("client endpoint");
    client_ep.set_default_client_config(client_trusting_ca(&ca));

    let connecting = client_ep
        .connect(local, "localhost")
        .expect("start connect");
    let client_conn = connecting.await.expect("client handshake");
    assert_eq!(
        client_conn
            .handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.protocol)
            .as_deref(),
        Some(ALPN_H3)
    );
    let _ = ServerName::try_from("localhost").expect("server name");

    client_conn.close(0u32.into(), b"done");
    let _server_conn = accept.await.expect("accept task");
    client_ep.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, client_ep.wait_idle()).await;
}

#[tokio::test]
async fn quic_server_bind_and_serve_shuts_down() {
    install_crypto();
    let (_dir, ca) = temp_ca();
    let store = Arc::new(FlowStore::new(100, 1024 * 1024, 8 * 1024 * 1024));
    let config = QuicConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        reverse_upstream: None,
        insecure_upstream: true,
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        QuicServer::bind_and_serve(config, ca, store, shutdown_rx).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(true);

    let result = tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .expect("serve should finish within drain window")
        .expect("task join");
    assert!(result.is_ok(), "serve error: {result:?}");
}

/* ------------------------------------------------------------------ */
/* External network: ignored by default                                */
/* ------------------------------------------------------------------ */

/// Skeleton for dialing a public H3 origin. Ignored so default CI / offline
/// runs stay green. Opt in with `-- --ignored` when the host has outbound net.
///
/// Not implemented as a full reverse MITM; see `quic_reverse_e2e` for that.
#[tokio::test]
#[ignore = "requires external network; run with --ignored when online"]
async fn external_h3_upstream_skeleton() {
    install_crypto();
    // Prefer insecure client_crypto only for explicit smoke against known
    // self-signed lab hosts. Public origins should use secure roots.
    let client = match client_crypto(false) {
        Ok(c) => c,
        Err(err) => {
            // No system roots: honest failure, not a flaky skip of an ignore.
            panic!("client_crypto(false) needs system roots for external smoke: {err:#}");
        }
    };

    // Placeholder target: replace with a lab H3 authority when extending this
    // test. Binding a client endpoint and connecting proves outbound UDP +
    // TLS work; full H3 request mapping stays in reverse e2e.
    let mut client_ep = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .expect("client endpoint");
    client_ep.set_default_client_config(client);

    // Resolve a well-known host only when this ignored test is deliberately run.
    // Using a fixed public H3 endpoint is left to the implementer so CI never
    // depends on third-party uptime.
    let target: SocketAddr = "1.1.1.1:443"
        .parse()
        .expect("static Cloudflare QUIC address");
    let connecting = client_ep
        .connect(target, "cloudflare-dns.com")
        .expect("start connect to public H3-capable host");

    match tokio::time::timeout(Duration::from_secs(10), connecting).await {
        Ok(Ok(conn)) => {
            let alpn = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.protocol);
            // Origin may negotiate h3; if not, the test still proves UDP dial.
            eprintln!("external handshake alpn={alpn:?}");
            conn.close(0u32.into(), b"smoke done");
        }
        Ok(Err(err)) => {
            // Network/policy/firewall failures are reported, not soft-skipped:
            // the operator opted in with --ignored.
            panic!("external QUIC handshake failed: {err}");
        }
        Err(_) => panic!("external QUIC handshake timed out after 10s"),
    }

    client_ep.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, client_ep.wait_idle()).await;
}
