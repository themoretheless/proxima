//! WireGuard scaffold bind knobs and the listen task.
//!
//! Binding is separate from serve so port 0 can be rewritten into status before
//! the task is spawned (same pattern as the QUIC listener).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::capture::FlowStore;

use super::demux::{NullUdpIngress, UdpIngress};
use super::tunnel::{NotImplementedTunnel, WireGuardTunnel};

/// Bind address for the WireGuard userspace scaffold.
///
/// Built by runtime/CLI from `Config.wg_*`. Binding itself is not done here so
/// port 0 can be resolved and written back into status before
/// [`WgServer::serve`] starts.
#[derive(Debug, Clone)]
pub struct WgConfig {
    /// UDP address to bind (host may be `0.0.0.0` / `::`; port may be `0`).
    pub bind: SocketAddr,
}

impl WgConfig {
    /// Replace the bind address (after port 0 rewrite).
    pub fn with_bind(mut self, bind: SocketAddr) -> Self {
        self.bind = bind;
        self
    }
}

/// Shared dependencies for the WireGuard scaffold.
///
/// Parallel to proxy/QUIC deps: the flow store is process-shared. The
/// [`UdpIngress`] hook is where a later dual-feature adapter would hand
/// demuxed UDP datagrams to the QUIC/H3 path; P9 defaults to
/// [`NullUdpIngress`].
#[derive(Clone)]
pub struct WgDeps {
    pub store: Arc<FlowStore>,
    pub udp_ingress: Arc<dyn UdpIngress>,
}

impl WgDeps {
    /// Scaffold defaults: shared store, no-op UDP ingress.
    pub fn new(store: Arc<FlowStore>) -> Self {
        Self {
            store,
            udp_ingress: Arc::new(NullUdpIngress),
        }
    }
}

/// UDP WireGuard scaffold listener, parallel to the QUIC accept task.
///
/// Does not run Noise/WG crypto. It binds, waits for shutdown, and drops any
/// unexpected datagrams with a debug log so a real client cannot be mistaken
/// for a working tunnel.
pub struct WgServer;

impl WgServer {
    /// Bind from `config`, then run [`serve`] until shutdown.
    pub async fn serve_bind(
        config: WgConfig,
        deps: WgDeps,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let sock = UdpSocket::bind(config.bind)
            .await
            .with_context(|| format!("binding WireGuard scaffold UDP on {}", config.bind))?;
        let local = sock.local_addr().with_context(|| {
            format!(
                "reading WireGuard listen address after bind on {}",
                config.bind
            )
        })?;
        info!(
            %local,
            "WireGuard UDP scaffold listening (no crypto; not a device tunnel)"
        );
        Self::serve(config.with_bind(local), deps, sock, shutdown).await
    }

    /// Runs until `shutdown` flips to true.
    ///
    /// On each datagram: log at debug that crypto is not implemented and drop
    /// the bytes. Never invents HTTP/3 or CONNECT flows. Never logs payload
    /// bytes (key material must not appear in logs even when crypto is absent).
    pub async fn serve(
        config: WgConfig,
        deps: WgDeps,
        sock: UdpSocket,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let local = sock.local_addr().unwrap_or(config.bind);
        info!(
            %local,
            store_len = deps.store.len(),
            "WireGuard scaffold ready (bind only; Noise/WG not implemented)"
        );

        if *shutdown.borrow() {
            debug!("WireGuard scaffold already shut down before accept");
            return Ok(());
        }

        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        debug!(%local, "WireGuard scaffold shutting down");
                        return Ok(());
                    }
                }
                recv = sock.recv_from(&mut buf) => {
                    match recv {
                        Ok((n, peer)) => {
                            // Length and peer only: never dump bytes (could be
                            // handshake material once crypto exists).
                            warn!(
                                %peer,
                                bytes = n,
                                "WireGuard scaffold received UDP but crypto is not implemented; \
                                 dropping (not a working tunnel)"
                            );
                            // Trait surface is live so a later crypto impl can
                            // replace NotImplementedTunnel without rewiring serve.
                            // Outer frames stay opaque: do not demux or invent flows.
                            let tunnel = NotImplementedTunnel;
                            let _ = tunnel.open_packet(&buf[..n]);
                            let _ = &deps.udp_ingress;
                        }
                        Err(err) => {
                            if *shutdown.borrow() {
                                return Ok(());
                            }
                            return Err(err).context("WireGuard scaffold UDP recv_from failed");
                        }
                    }
                }
            }
        }
    }
}
