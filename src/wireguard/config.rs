//! WireGuard bind knobs and the listen task.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::capture::FlowStore;

use super::crypto::{PeerConfig, WgDevice, WgKeypair};
use super::demux::{demux_ip_packet, DemuxedPacket, NullUdpIngress, UdpIngress};
use super::device::DeviceJoinInfo;
use super::tunnel::{NotImplementedTunnel, WireGuardTunnel};

/// Bind address for the WireGuard UDP listener.
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

/// Shared dependencies for the WireGuard path.
#[derive(Clone)]
pub struct WgDeps {
    pub store: Arc<FlowStore>,
    pub udp_ingress: Arc<dyn UdpIngress>,
    /// Live crypto device when keys were generated. Scaffold builds leave this empty.
    pub device: Option<Arc<WgDevice>>,
    /// Join card for status/setup (keys when device is present).
    pub join_info: Option<DeviceJoinInfo>,
}

impl WgDeps {
    /// Defaults: shared store, no-op UDP ingress, generated one-peer device.
    pub fn new(store: Arc<FlowStore>) -> Self {
        let server = WgKeypair::generate();
        let client = WgKeypair::generate();
        let peer = PeerConfig {
            public: client.public,
            allowed_ips_note: "10.0.0.2/32".into(),
            psk: [0u8; 32],
        };
        let device = Arc::new(WgDevice::new(server.clone(), vec![peer]));
        // Endpoint filled in after bind (port 0 rewrite). Placeholder host.
        let join_info = DeviceJoinInfo::with_keys(
            "0.0.0.0:0",
            server.public_base64(),
            client.secret_base64(),
            client.public_base64(),
        );
        Self {
            store,
            udp_ingress: Arc::new(NullUdpIngress),
            device: Some(device),
            join_info: Some(join_info),
        }
    }

    /// Rewrite join card endpoint after the real listen address is known.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        if let Some(info) = self.join_info.as_mut() {
            info.endpoint = endpoint.into();
        }
        self
    }
}

/// UDP WireGuard listener with Noise_IK crypto.
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
            .with_context(|| format!("binding WireGuard UDP on {}", config.bind))?;
        let local = sock.local_addr().with_context(|| {
            format!(
                "reading WireGuard listen address after bind on {}",
                config.bind
            )
        })?;
        info!(
            %local,
            server_public = deps
                .device
                .as_ref()
                .map(|d| d.server_public_base64())
                .unwrap_or_else(|| "unavailable".into()),
            "WireGuard UDP listening (Noise_IK enabled)"
        );
        Self::serve(config.with_bind(local), deps.with_endpoint(local.to_string()), sock, shutdown)
            .await
    }

    /// Runs until `shutdown` flips to true.
    pub async fn serve(
        config: WgConfig,
        deps: WgDeps,
        sock: UdpSocket,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let local = sock.local_addr().unwrap_or(config.bind);
        if let Some(info) = &deps.join_info {
            info!(
                %local,
                endpoint = %info.endpoint,
                server_public = info.server_public_key.as_deref().unwrap_or("-"),
                client_public = info.client_public_key.as_deref().unwrap_or("-"),
                "WireGuard ready (device-join keys generated; TCP reassembly not shipped)"
            );
        } else {
            info!(
                %local,
                store_len = deps.store.len(),
                "WireGuard listening without device keys"
            );
        }

        if *shutdown.borrow() {
            debug!("WireGuard already shut down before accept");
            return Ok(());
        }

        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        debug!(%local, "WireGuard shutting down");
                        return Ok(());
                    }
                }
                recv = sock.recv_from(&mut buf) => {
                    match recv {
                        Ok((n, peer)) => {
                            let packet = &buf[..n];
                            if let Some(device) = &deps.device {
                                match device.handle_datagram(peer, packet) {
                                    Ok(inner_packets) => {
                                        for outbound in device.take_outbound() {
                                            if let Err(err) = sock.send_to(&outbound.1, outbound.0).await {
                                                warn!(error = %err, "WireGuard reply send failed");
                                            }
                                        }
                                        for ip in inner_packets {
                                            match demux_ip_packet(&ip) {
                                                DemuxedPacket::Udp { src, dst, payload } => {
                                                    if let Err(err) = deps.udp_ingress.push_udp(src, dst, &payload).await {
                                                        debug!(error = %err, "UdpIngress push failed");
                                                    }
                                                }
                                                DemuxedPacket::Tcp { src, dst, .. } => {
                                                    debug!(%src, %dst, "WireGuard inner TCP (reassembly not shipped)");
                                                }
                                                DemuxedPacket::Other { protocol, .. } => {
                                                    debug!(?protocol, "WireGuard inner non-TCP/UDP");
                                                }
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        debug!(%peer, error = %err, "WireGuard datagram rejected");
                                    }
                                }
                            } else {
                                warn!(
                                    %peer,
                                    bytes = n,
                                    "WireGuard received UDP but no device keys; dropping"
                                );
                                let tunnel = NotImplementedTunnel;
                                let _ = tunnel.open_packet(packet);
                            }
                        }
                        Err(err) => {
                            if *shutdown.borrow() {
                                return Ok(());
                            }
                            return Err(err).context("WireGuard UDP recv_from failed");
                        }
                    }
                }
            }
        }
    }
}
