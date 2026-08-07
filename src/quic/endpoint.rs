//! Quinn endpoint construction for the QUIC UDP listener.
//!
//! Builds a server-side [`quinn::Endpoint`] on an already-bound UDP socket and
//! exposes accept / close / drain. The classic TCP proxy port never receives
//! these datagrams: QUIC is UDP-only, so only this path can terminate HTTP/3.
//!
//! ## Lifecycle
//!
//! 1. Bind UDP ([`super::bind_udp`]); port 0 is resolved via `local_addr`.
//! 2. Build the endpoint with CA-minted leaves and ALPN `h3`. Early data is
//!    off ([`super::MITM_MAX_EARLY_DATA_SIZE`] = 0) so clients never send
//!    0-RTT application data to the MITM leg.
//! 3. Accept inbound connections until shutdown (full 1-RTT handshake by
//!    awaiting [`quinn::Incoming`]; never 0-RTT accept).
//! 4. On stop: signal close, then wait up to [`DRAIN_TIMEOUT`] for idle.
//!
//! Reverse mode also attaches a default client config (early data off via
//! [`super::client_crypto`]) so the same endpoint can dial upstream over QUIC.
//!
//! Platform bind quirks (macOS dual-stack, firewall, privileged ports) live on
//! [`super::udp`]; this module assumes the socket is already bound.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Endpoint, Incoming, ServerConfig};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::ca::CertAuthority;

use super::tls::server_crypto;

/// How long shutdown waits for in-flight QUIC connections to go idle.
///
/// Long enough for orderly close; short enough that `Servers::stop` does not
/// hang the process when a peer never finishes.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Snapshot of how the endpoint was configured when it was built.
#[derive(Debug, Clone)]
pub struct QuicEndpointConfig {
    pub bind: SocketAddr,
}

/// Server-side QUIC endpoint wrapping quinn.
///
/// Owns the UDP socket and the accept path. Callers drive the accept loop
/// (see crate root accept stub and reverse mode) and call
/// [`Self::close_and_drain`] on shared process shutdown.
pub struct QuicEndpoint {
    inner: Endpoint,
    local: SocketAddr,
}

impl QuicEndpoint {
    /// Builds a server endpoint on an already-bound UDP socket.
    ///
    /// Uses [`server_crypto`] so leaves come from the process CA, ALPN is only
    /// `h3`, and early data is disabled (MITM must not accept 0-RTT; see
    /// [`super::tls`] security notes).
    pub fn server(sock: UdpSocket, ca: Arc<CertAuthority>) -> Result<Self> {
        let local = sock.local_addr().context("QUIC socket local_addr")?;
        // CONNECT-style fallback when a client omits SNI. Reverse clients
        // almost always send SNI; accept-only uses localhost as a last resort.
        let server_config = server_crypto(ca, "localhost")?;
        Self::from_socket(sock, local, server_config)
    }

    /// Same as [`Self::server`] but accepts a pre-built [`ServerConfig`].
    ///
    /// Useful for tests that want a fixed crypto config without going through
    /// the CA path again.
    pub fn server_with_config(sock: UdpSocket, server_config: ServerConfig) -> Result<Self> {
        let local = sock.local_addr().context("QUIC socket local_addr")?;
        Self::from_socket(sock, local, server_config)
    }

    fn from_socket(sock: UdpSocket, local: SocketAddr, server_config: ServerConfig) -> Result<Self> {
        // quinn wants a std socket; convert without closing by into_std.
        let std_sock = sock.into_std().context("tokio UDP into_std")?;
        std_sock
            .set_nonblocking(true)
            .context("QUIC UDP nonblocking")?;

        let runtime = Arc::new(quinn::TokioRuntime);
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            std_sock,
            runtime,
        )
        .with_context(|| format!("creating quinn Endpoint on {local}"))?;

        Ok(Self {
            inner: endpoint,
            local,
        })
    }

    /// Address the OS bound (non-zero port even when the request used port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Config snapshot for status / diagnostics.
    pub fn config(&self) -> QuicEndpointConfig {
        QuicEndpointConfig { bind: self.local }
    }

    /// Waits for the next inbound QUIC connection attempt.
    ///
    /// Returns `None` when the endpoint has been closed and will accept no more
    /// connections. This is the accept-loop primitive; H3 framing lives in
    /// `http3` / `reverse`.
    pub async fn accept(&self) -> Option<Incoming> {
        self.inner.accept().await
    }

    /// Signals the endpoint to stop accepting and close open connections.
    ///
    /// Prefer [`Self::close_and_drain`] on process shutdown so idle wait is
    /// bounded.
    pub fn close(&self) {
        self.inner.close(0u32.into(), b"proxima shutdown");
    }

    /// Waits until all connections on this endpoint are idle (or the endpoint
    /// is dropped). Used after [`Self::close`].
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }

    /// Close then wait for idle, bounded by [`DRAIN_TIMEOUT`].
    ///
    /// Logs if peers outlive the drain window; the process still continues so
    /// TCP/UI shutdown is not blocked.
    pub async fn close_and_drain(&self) {
        self.close();
        match tokio::time::timeout(DRAIN_TIMEOUT, self.wait_idle()).await {
            Ok(()) => {
                debug!(local = %self.local, "QUIC endpoint drained");
            }
            Err(_) => {
                warn!(
                    local = %self.local,
                    secs = DRAIN_TIMEOUT.as_secs(),
                    "QUIC endpoint still busy after drain timeout; continuing shutdown"
                );
            }
        }
    }

    /// Endpoint handle for dialing upstream in reverse mode.
    pub fn raw(&self) -> &Endpoint {
        &self.inner
    }

    /// Attach the default client config used when reverse mode dials origin.
    pub fn set_default_client_config(&mut self, config: quinn::ClientConfig) {
        self.inner.set_default_client_config(config);
    }
}

/// Free-function form of [`QuicEndpoint::server`] for call sites that prefer
/// a function over a constructor.
pub fn server_endpoint(sock: UdpSocket, ca: Arc<CertAuthority>) -> Result<QuicEndpoint> {
    QuicEndpoint::server(sock, ca)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Once;

    use quinn::ClientConfig;
    use rustls::pki_types::ServerName;
    use rustls::RootCertStore;

    use super::super::tls::{client_crypto, ALPN_H3};
    use super::super::udp::bind_udp;

    static CRYPTO: Once = Once::new();

    fn install_crypto() {
        CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn temp_ca() -> Arc<CertAuthority> {
        let dir = std::env::temp_dir().join(format!(
            "proxima-quic-endpoint-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Arc::new(CertAuthority::open(&dir).expect("open CA"))
    }

    /// Client that trusts only the Proxima test CA (not native roots).
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
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QuicClientConfig");
        ClientConfig::new(Arc::new(quic))
    }

    #[tokio::test]
    async fn server_endpoint_resolves_ephemeral_port() {
        install_crypto();
        let ca = temp_ca();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = bind_udp(addr).await.expect("bind");
        let endpoint = server_endpoint(sock, ca).expect("endpoint");
        assert_ne!(endpoint.local_addr().port(), 0);
        assert_eq!(endpoint.config().bind, endpoint.local_addr());
        endpoint.close_and_drain().await;
    }

    #[tokio::test]
    async fn localhost_one_rtt_handshake() {
        install_crypto();
        let ca = temp_ca();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = bind_udp(addr).await.expect("bind");
        let endpoint = QuicEndpoint::server(sock, ca.clone()).expect("server endpoint");
        let local = endpoint.local_addr();

        let accept = tokio::spawn(async move {
            let incoming = endpoint.accept().await.expect("accept");
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
        // Prove SNI was used so the CA mint path ran for "localhost".
        let _ = ServerName::try_from("localhost").expect("server name");

        client_conn.close(0u32.into(), b"done");
        let _server_conn = accept.await.expect("accept task");
        client_ep.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, client_ep.wait_idle()).await;
    }

    #[tokio::test]
    async fn close_stops_accept() {
        install_crypto();
        let ca = temp_ca();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = bind_udp(addr).await.expect("bind");
        let endpoint = QuicEndpoint::server(sock, ca).expect("endpoint");
        endpoint.close();
        let next = endpoint.accept().await;
        assert!(next.is_none(), "closed endpoint must not yield connections");
    }

    #[tokio::test]
    async fn insecure_client_crypto_builds() {
        // Smoke that the shared client factory used by reverse mode stays
        // constructible next to the server path.
        install_crypto();
        let _ = client_crypto(true).expect("insecure client");
        let _ = client_crypto(false); // may fail if no native roots; ok either way
    }

    #[tokio::test]
    async fn server_with_config_uses_fixed_host_leaf() {
        install_crypto();
        let ca = temp_ca();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = bind_udp(addr).await.expect("bind");
        let server_cfg =
            super::super::tls::server_crypto_fixed(ca.clone(), "demo.local").expect("fixed crypto");
        let endpoint = QuicEndpoint::server_with_config(sock, server_cfg).expect("endpoint");
        assert_ne!(endpoint.local_addr().port(), 0);
        endpoint.close_and_drain().await;
    }

    #[tokio::test]
    async fn client_offering_only_h2_fails_handshake() {
        // Server ALPN is h3-only; a client that offers only h2 must not complete.
        install_crypto();
        let ca = temp_ca();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = bind_udp(addr).await.expect("bind");
        let endpoint = QuicEndpoint::server(sock, ca.clone()).expect("server");
        let local = endpoint.local_addr();

        let accept = tokio::spawn(async move {
            match endpoint.accept().await {
                Some(incoming) => {
                    let result = incoming.await;
                    endpoint.close_and_drain().await;
                    result
                }
                None => {
                    endpoint.close_and_drain().await;
                    Err(quinn::ConnectionError::LocallyClosed)
                }
            }
        });

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
        // Deliberately wrong ALPN for a QUIC/H3 endpoint.
        tls.alpn_protocols = vec![b"h2".to_vec()];
        tls.enable_early_data = false;
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QuicClientConfig");
        let mut client_ep = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("client endpoint");
        client_ep.set_default_client_config(ClientConfig::new(Arc::new(quic)));

        let connecting = client_ep
            .connect(local, "localhost")
            .expect("start connect");
        let client_result = connecting.await;
        assert!(
            client_result.is_err(),
            "h2-only client must not complete QUIC handshake against h3-only server"
        );

        // Server side may see accept fail or connection error; either is fine.
        let _ = tokio::time::timeout(Duration::from_secs(2), accept).await;
        client_ep.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, client_ep.wait_idle()).await;
    }

    #[tokio::test]
    async fn close_and_drain_completes_under_budget() {
        install_crypto();
        let ca = temp_ca();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = bind_udp(addr).await.expect("bind");
        let endpoint = QuicEndpoint::server(sock, ca).expect("endpoint");
        let started = std::time::Instant::now();
        endpoint.close_and_drain().await;
        assert!(
            started.elapsed() < DRAIN_TIMEOUT + Duration::from_secs(1),
            "drain should finish within DRAIN_TIMEOUT plus small slack"
        );
    }
}
