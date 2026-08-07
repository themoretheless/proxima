//! QUIC transport and HTTP/3 over UDP.
//!
//! The default Proxima proxy listens on TCP. QUIC never arrives there: it is
//! UDP. This module is the separate path that terminates QUIC, so HTTP/3 can be
//! decrypted with the same certificate authority as HTTPS on TCP.
//!
//! ## Modes (today)
//!
//! - **Accept / inspect skeleton**: bind UDP, terminate QUIC, record HTTP/3
//!   requests into the flow store (responds 501 unless reverse is configured).
//! - **Reverse HTTP/3** ([`reverse`]): speak H3 to clients and forward streams
//!   upstream over H3.
//!
//! Regular "phone HTTP proxy" mode still cannot see device QUIC; that needs a
//! WireGuard or TUN path (see PLANS.md).
//!
//! ## Lifecycle
//!
//! Callers bind UDP first (so port 0 can be resolved and reported), build a
//! [`QuicEndpoint`], then run [`QuicServer::serve`] with shared [`QuicDeps`]
//! until the process shutdown watch fires. Serve closes the endpoint and drains
//! open connections for up to [`DRAIN_TIMEOUT`] before returning.
//!
//! ## Platform: macOS UDP
//!
//! Developer hosts are often Darwin. Bind, dual-stack, firewall, privileged
//! ports, and why reverse (not classic transparent UDP) is the supported path
//! on macOS today are documented on [`udp`] (`udp` module docs, section
//! "macOS notes"). This crate does not implement pf or Network Extension
//! redirect; those remain future ingress options in PLANS.md.
//!
//! ## Security notes
//!
//! - **0-RTT / early data is disabled** on every MITM crypto config:
//!   server `max_early_data_size = 0`, client `enable_early_data = false`, and
//!   no call site uses `Connecting::into_0rtt`. Rationale (replay risk,
//!   incomplete capture, asymmetric client vs origin tickets) lives in
//!   [`tls`] module docs and the [`tls::MITM_MAX_EARLY_DATA_SIZE`] /
//!   [`tls::MITM_ENABLE_EARLY_DATA`] constants.
//! - Chrome may refuse user-installed CAs for QUIC; see the README.
//!
//! Behind `--features quic` only.

mod endpoint;
mod forward_upstream;
mod http3;
mod reverse;
mod stream;
mod tls;
mod udp;

// Public surface for the feature-gated UDP path. Submodules stay private;
// consumers (runtime, integration tests) import through `proxima::quic::*`.
//
// Naming: Config/CLI use `reverse_h3` for the origin authority string;
// this module uses `reverse_upstream` on [`QuicConfig`] / [`QuicDeps`] so
// the UDP layer does not depend on listen-mode vocabulary.

pub use endpoint::{server_endpoint, DRAIN_TIMEOUT, QuicEndpoint, QuicEndpointConfig};
pub use forward_upstream::{
    dial_h3, dial_upstream_h3, host_only, order_addrs_for_local, resolve, resolve_all,
    split_host_port, UpstreamAuthority, UpstreamH3,
};
pub use reverse::{run_reverse_h3, ReverseH3Config};
// H3StreamFlow + stable fail codes for tests and reverse bridge call sites.
// H3RequestMeta and other stream open hooks stay crate-private.
pub use stream::{
    classify_bridge_error_code, classify_client_handshake_error, codes, record_handshake_failure,
    HandshakeClassify, H3StreamFlow,
};
pub use tls::{
    client_crypto, server_crypto, server_crypto_fixed, ALPN_H3, MITM_ENABLE_EARLY_DATA,
    MITM_MAX_EARLY_DATA_SIZE,
};
pub use udp::{bind_error_message, bind_udp, bound_addr, map_bind_error, BindFailureKind};

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info};

use crate::ca::CertAuthority;
use crate::capture::FlowStore;

/* ------------------------------------------------------------------ */
/* Config and deps                                                     */
/* ------------------------------------------------------------------ */

/// Bind and mode knobs for the QUIC/UDP listener.
///
/// Built by runtime/CLI from `Config.quic_*` / reverse flags. Binding itself
/// is not done here so port 0 can be resolved and written back into status
/// before [`QuicServer::serve`] starts.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// UDP address to bind (host may be `0.0.0.0` / `::`; port may be `0`).
    pub bind: SocketAddr,
    /// When set, reverse-proxy HTTP/3 to this authority (`host` or `host:port`).
    pub reverse_upstream: Option<String>,
    /// Accept invalid upstream certificates (mirrors TCP `--insecure`).
    pub insecure_upstream: bool,
}

/// Older name for [`QuicConfig`]. Kept so existing call sites keep compiling.
pub type QuicRuntime = QuicConfig;

/// Shared dependencies for accept and reverse H3 paths.
///
/// Parallel to [`crate::proxy::ProxyDeps`]: certificate authority and flow
/// store live once per process and are shared with the TCP proxy and inspector.
#[derive(Clone)]
pub struct QuicDeps {
    pub ca: Arc<CertAuthority>,
    pub store: Arc<FlowStore>,
    /// When set, reverse-proxy HTTP/3 to this authority instead of the 501
    /// accept-only path.
    pub reverse_upstream: Option<String>,
    pub insecure_upstream: bool,
}

impl QuicDeps {
    /// Process-shared CA, flow store, and reverse knobs.
    pub fn new(
        ca: Arc<CertAuthority>,
        store: Arc<FlowStore>,
        reverse_upstream: Option<String>,
        insecure_upstream: bool,
    ) -> Self {
        Self {
            ca,
            store,
            reverse_upstream,
            insecure_upstream,
        }
    }

    /// Builds deps from a bound-side config (bind address is not needed after
    /// the endpoint exists).
    pub fn from_config(
        ca: Arc<CertAuthority>,
        store: Arc<FlowStore>,
        config: &QuicConfig,
    ) -> Self {
        Self::new(
            ca,
            store,
            config.reverse_upstream.clone(),
            config.insecure_upstream,
        )
    }
}

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

/// UDP QUIC listener, parallel to [`crate::proxy::ProxyServer`].
///
/// The endpoint (and therefore the UDP socket) is built by the caller so
/// `Servers::start` can report the OS-assigned port when `quic_port` was 0.
pub struct QuicServer;

impl QuicServer {
    /// Runs until `shutdown` flips to true.
    ///
    /// On shutdown: stop accepting, close the endpoint with a shutdown reason,
    /// wait for connection tasks (and quinn idle) up to [`DRAIN_TIMEOUT`], then
    /// return. Open connections past the deadline are abandoned so the process
    /// can still exit cleanly.
    pub async fn serve(
        mut endpoint: QuicEndpoint,
        deps: Arc<QuicDeps>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let local = endpoint.local_addr();
        info!(
            %local,
            reverse = ?deps.reverse_upstream,
            "QUIC/UDP endpoint listening"
        );

        if *shutdown.borrow() {
            endpoint.close_and_drain().await;
            return Ok(());
        }

        // Held by every connection task. The receiver completes only after the
        // last clone is dropped, which is the in-process side of "drained".
        let (drain_tx, mut drain_rx) = mpsc::channel::<()>(1);

        let serve_result = if let Some(upstream) = deps.reverse_upstream.clone() {
            let cfg = ReverseH3Config {
                upstream,
                insecure_upstream: deps.insecure_upstream,
            };
            reverse::run_reverse_h3(
                &mut endpoint,
                deps.ca.clone(),
                deps.store.clone(),
                cfg,
                shutdown,
                drain_tx,
            )
            .await
        } else {
            accept_loop(
                &endpoint,
                deps.ca.clone(),
                deps.store.clone(),
                shutdown,
                drain_tx,
            )
            .await
        };

        // Stop accept, close peers, wait up to DRAIN_TIMEOUT for quinn idle.
        endpoint.close_and_drain().await;

        // Wait for connection tasks that still hold drain tokens (flow capture,
        // reverse stream work). Cap so a stuck H3 stream cannot hang stop().
        if tokio::time::timeout(DRAIN_TIMEOUT, drain_rx.recv())
            .await
            .is_err()
        {
            debug!("QUIC connection tasks still open at shutdown, dropping them");
        }

        serve_result
    }

    /// Binds UDP from `config`, builds a server endpoint, and runs [`serve`].
    ///
    /// Prefer binding outside this type when the caller must rewrite port 0
    /// into shared config/status before the accept loop starts.
    pub async fn bind_and_serve(
        config: QuicConfig,
        ca: Arc<CertAuthority>,
        store: Arc<FlowStore>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let sock = bind_udp(config.bind)
            .await
            .with_context(|| format!("starting the QUIC listener on {}", config.bind))?;
        let local = bound_addr(&sock).with_context(|| {
            format!(
                "reading the QUIC listen address after bind on {}",
                config.bind
            )
        })?;
        info!(%local, reverse = ?config.reverse_upstream, "QUIC/UDP endpoint bound");

        let endpoint = QuicEndpoint::server(sock, ca.clone())?;
        let deps = Arc::new(QuicDeps::from_config(ca, store, &config));
        Self::serve(endpoint, deps, shutdown).await
    }
}

/// Binds UDP, builds the endpoint, and spawns [`QuicServer::serve`] on the
/// current Tokio runtime. Returns the join handle for the accept/reverse task.
///
/// [`Servers::start`](crate::runtime::Servers::start) prefers binding itself so
/// it can rewrite `quic_port` when the requested port was 0; this helper remains
/// for tests and simple call sites.
pub async fn spawn(
    config: QuicConfig,
    ca: Arc<CertAuthority>,
    store: Arc<FlowStore>,
    shutdown: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let sock = bind_udp(config.bind)
        .await
        .with_context(|| format!("starting the QUIC listener on {}", config.bind))?;
    let local = bound_addr(&sock).with_context(|| {
        format!(
            "reading the QUIC listen address after bind on {}",
            config.bind
        )
    })?;
    info!(%local, reverse = ?config.reverse_upstream, "QUIC/UDP endpoint bound");

    let endpoint = QuicEndpoint::server(sock, ca.clone())?;
    let deps = Arc::new(QuicDeps::from_config(ca, store, &config));

    Ok(tokio::spawn(async move {
        QuicServer::serve(endpoint, deps, shutdown).await
    }))
}

/* ------------------------------------------------------------------ */
/* Accept-only path                                                    */
/* ------------------------------------------------------------------ */

async fn accept_loop(
    endpoint: &QuicEndpoint,
    ca: Arc<CertAuthority>,
    store: Arc<FlowStore>,
    mut shutdown: watch::Receiver<bool>,
    drain_tx: mpsc::Sender<()>,
) -> Result<()> {
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
                        let ca = ca.clone();
                        let drain = drain_tx.clone();
                        tokio::spawn(async move {
                            let _drain = drain.clone();
                            if let Err(err) =
                                http3::accept_one(connecting, ca, store, drain).await
                            {
                                // Handshake failures already recorded as Error flows + warn.
                                debug!(error = %err, "QUIC connection ended");
                            }
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::capture::FlowStore;

    fn test_ca() -> Arc<CertAuthority> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();
        // Keep the tempdir for the life of the process so the CA files remain.
        std::mem::forget(dir);
        Arc::new(CertAuthority::open(&path).expect("ca"))
    }

    #[tokio::test]
    async fn bind_and_serve_shuts_down_cleanly() {
        let ca = test_ca();
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

        // Give the accept loop a moment to bind and log.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("serve should finish within drain window")
            .expect("task join");
        assert!(result.is_ok(), "serve error: {result:?}");
    }

    #[tokio::test]
    async fn quic_runtime_is_alias_for_quic_config() {
        let config: QuicRuntime = QuicConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9443),
            reverse_upstream: Some("origin.example:443".into()),
            insecure_upstream: false,
        };
        assert_eq!(config.bind.port(), 9443);
        assert!(config.reverse_upstream.is_some());
    }

    #[test]
    fn stable_error_codes_are_reexported() {
        assert_eq!(codes::H3, "h3");
        assert_eq!(codes::QUIC_UPSTREAM, "quic_upstream");
        assert_eq!(codes::H3_ABANDONED, "h3_abandoned");
        assert_eq!(codes::QUIC_CERT_REJECT, "quic_cert_reject");
        assert_eq!(codes::QUIC_ALPN, "quic_alpn");
    }

    #[test]
    fn drain_timeout_is_five_seconds() {
        assert_eq!(DRAIN_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn quic_deps_from_config_copies_fields() {
        let ca = test_ca();
        let store = Arc::new(FlowStore::new(8, 256, 1024));
        let config = QuicConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            reverse_upstream: Some("origin.example:9443".into()),
            insecure_upstream: true,
        };
        let deps = QuicDeps::from_config(ca.clone(), store.clone(), &config);
        assert!(Arc::ptr_eq(&deps.ca, &ca));
        assert!(Arc::ptr_eq(&deps.store, &store));
        assert_eq!(
            deps.reverse_upstream.as_deref(),
            Some("origin.example:9443")
        );
        assert!(deps.insecure_upstream);
    }

    #[tokio::test]
    async fn spawn_shuts_down_cleanly() {
        // spawn/QuicConfig smoke under --features quic.
        let ca = test_ca();
        let store = Arc::new(FlowStore::new(100, 1024 * 1024, 8 * 1024 * 1024));
        let config = QuicConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            reverse_upstream: None,
            insecure_upstream: true,
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = spawn(config, ca, store, shutdown_rx)
            .await
            .expect("spawn bind");

        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("spawn serve should finish within drain window")
            .expect("task join");
        assert!(result.is_ok(), "serve error: {result:?}");
    }

    #[tokio::test]
    async fn already_shutdown_bind_and_serve_returns_quickly() {
        let ca = test_ca();
        let store = Arc::new(FlowStore::new(8, 256, 1024));
        let config = QuicConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            reverse_upstream: None,
            insecure_upstream: true,
        };
        let (_tx, rx) = watch::channel(true); // already requested
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            QuicServer::bind_and_serve(config, ca, store, rx),
        )
        .await
        .expect("must not hang when shutdown is already true");
        assert!(result.is_ok());
    }
}
