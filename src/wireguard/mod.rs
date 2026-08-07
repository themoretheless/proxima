//! WireGuard userspace device-join path (scaffold).
//!
//! ## Intent
//!
//! Classic phone Wi-Fi HTTP proxy settings only send TCP CONNECT to the proxy
//! port. QUIC/HTTP3 from apps never arrives there. The long-term mobile story
//! (same idea as mitmproxy's WireGuard mode) is: the device joins a WireGuard
//! tunnel that Proxima terminates in userspace, so TCP and UDP both land in
//! this process for inspection.
//!
//! ## What P9 ships
//!
//! - Config/CLI/status knobs (always compiled; see [`crate::config`]).
//! - A feature-gated listen task that binds the WG UDP port and shuts down
//!   cleanly on the shared watch channel.
//! - Trait stubs: [`WireGuardTunnel`], [`UdpIngress`], [`demux_ip_packet`].
//! - Docs-only [`DeviceJoinInfo`] describing what a real join card would show.
//!
//! ## What is not shipped
//!
//! - Noise_IK / WireGuard handshake crypto
//! - Key generation, peer config files, or a working tunnel
//! - Userspace TCP reassembly or a fake userspace network stack
//! - Any claim that Wi-Fi HTTP proxy settings feed this path
//! - Co-enable with reverse-h3 (rejected in config validation)
//!
//! ## Later handoff to QUIC
//!
//! Decrypted inner IP packets that carry UDP can be classified by
//! [`demux_ip_packet`] and passed to a [`UdpIngress`] implementation. A future
//! dual-feature adapter (`quic` + `wireguard`) can feed those datagrams into
//! the H3 path without changing the [`UdpIngress`] trait shape defined here.
//! P9 keeps this trait free of quinn types.
//!
//! Behind `--features wireguard` only. Without that feature the binary has no
//! WG listen task; requesting WG flags fails with rebuild guidance.

mod config;
mod demux;
mod device;
mod tunnel;

pub use config::{WgConfig, WgDeps, WgServer};
pub use demux::{demux_ip_packet, DemuxedPacket, NullUdpIngress, UdpIngress};
pub use device::DeviceJoinInfo;
pub use tunnel::{NotImplementedTunnel, WireGuardTunnel};

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::watch;
use tracing::info;

use crate::capture::FlowStore;

/// Bind UDP for the WireGuard scaffold, rewrite port 0, then run [`WgServer`].
///
/// Prefer binding outside this helper when the caller must write the OS-assigned
/// port into shared config/status before the task starts (see runtime).
pub async fn bind_and_serve(
    config: WgConfig,
    deps: WgDeps,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let sock = tokio::net::UdpSocket::bind(config.bind)
        .await
        .with_context(|| format!("binding WireGuard scaffold UDP on {}", config.bind))?;
    let local = sock
        .local_addr()
        .with_context(|| format!("reading WireGuard bind address after bind on {}", config.bind))?;
    info!(
        %local,
        "WireGuard UDP scaffold bound (crypto not implemented; no device tunnel)"
    );
    WgServer::serve(config.with_bind(local), deps, sock, shutdown).await
}

/// Spawn the scaffold listen task on the current Tokio runtime.
pub async fn spawn(
    config: WgConfig,
    store: Arc<FlowStore>,
    shutdown: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let deps = WgDeps {
        store,
        udp_ingress: Arc::new(NullUdpIngress),
    };
    Ok(tokio::spawn(async move {
        bind_and_serve(config, deps, shutdown).await
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    #[tokio::test]
    async fn already_shutdown_bind_and_serve_returns_quickly() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let config = WgConfig { bind };
        let deps = WgDeps {
            store: Arc::new(FlowStore::new(16, 1024, 64 * 1024)),
            udp_ingress: Arc::new(NullUdpIngress),
        };
        let (tx, rx) = watch::channel(true);
        let done = tokio::time::timeout(
            Duration::from_secs(2),
            WgServer::serve_bind(config, deps, rx),
        )
        .await
        .expect("scaffold must not hang when already shut down");
        done.expect("clean early shutdown");
        drop(tx);
    }

    #[test]
    fn device_join_info_documents_scaffold_limits() {
        let info = DeviceJoinInfo::scaffold_example("203.0.113.10:51820");
        assert!(info.notes.iter().any(|n| n.contains("not") || n.contains("scaffold")));
        // Never invent a "working" public key placeholder that looks real.
        assert!(
            info.server_public_key.is_none()
                || info
                    .server_public_key
                    .as_deref()
                    .is_some_and(|k| k.contains("not") || k.contains("unavailable")),
            "scaffold must not fake key material"
        );
    }

    #[tokio::test]
    async fn scaffold_drops_datagram_without_inventing_flows() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = tokio::net::UdpSocket::bind(bind)
            .await
            .expect("bind scaffold");
        let local = sock.local_addr().expect("local");
        let store = Arc::new(FlowStore::new(16, 1024, 64 * 1024));
        let deps = WgDeps::new(store.clone());
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            WgServer::serve(WgConfig { bind: local }, deps, sock, rx).await
        });

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("client bind");
        client
            .send_to(b"not-a-real-wireguard-handshake", local)
            .await
            .expect("send probe");

        // Give the scaffold a turn to recv and drop without inventing HTTP flows.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            store.len(),
            0,
            "WG scaffold must not invent CONNECT/HTTP flows from outer UDP"
        );

        tx.send(true).expect("shutdown");
        let done = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("serve must exit after shutdown")
            .expect("join");
        done.expect("clean serve after drop");
    }

    #[test]
    fn wg_deps_default_udp_ingress_is_null() {
        let store = Arc::new(FlowStore::new(4, 512, 1024));
        let deps = WgDeps::new(store);
        // Object-safe hook: default construction must not panic and must accept.
        let src: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:443".parse().unwrap();
        let fut = deps.udp_ingress.push_udp(src, dst, b"");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(fut).expect("NullUdpIngress is the default hook");
    }
}
