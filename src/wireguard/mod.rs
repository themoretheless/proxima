//! WireGuard userspace device-join path.
//!
//! ## Intent
//!
//! Classic phone Wi-Fi HTTP proxy settings only send TCP CONNECT to the proxy
//! port. QUIC/HTTP3 from apps never arrives there. The mobile story (same idea
//! as mitmproxy's WireGuard mode) is: the device joins a WireGuard tunnel that
//! Proxima terminates in userspace, so TCP and UDP both land in this process.
//!
//! ## What this feature ships
//!
//! - Config/CLI/status knobs (always compiled; see [`crate::config`]).
//! - Noise_IKpsk2 handshake responder + transport AEAD ([`crypto::WgDevice`]).
//! - Server + one client keypair generation; [`DeviceJoinInfo`] with real keys.
//! - UDP serve loop that decrypts, demuxes IP, and pushes UDP to [`UdpIngress`].
//!
//! ## What is still open
//!
//! - Userspace TCP reassembly / full L4 proxy of inner TCP
//! - Dual-feature adapter into reverse H3 (trait ready: [`UdpIngress`])
//! - Cookie reply under load, roaming peer multi-session polish
//! - Co-enable with reverse-h3 (still rejected in config validation)
//!
//! Behind `--features wireguard` only. Without that feature the binary has no
//! WG listen task; requesting WG flags fails with rebuild guidance.

mod config;
mod crypto;
mod demux;
mod device;
mod tunnel;

pub use config::{WgConfig, WgDeps, WgServer};
pub use crypto::{decode_key, encode_key, PeerConfig, WgDevice, WgKeypair};
pub use demux::{demux_ip_packet, DemuxedPacket, NullUdpIngress, UdpIngress};
pub use device::DeviceJoinInfo;
pub use tunnel::{NotImplementedTunnel, WireGuardTunnel};

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::watch;
use tracing::info;

use crate::capture::FlowStore;

/// Bind UDP for WireGuard, rewrite port 0, then run [`WgServer`].
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
        .with_context(|| format!("binding WireGuard UDP on {}", config.bind))?;
    let local = sock
        .local_addr()
        .with_context(|| format!("reading WireGuard bind address after bind on {}", config.bind))?;
    info!(
        %local,
        "WireGuard UDP bound (Noise_IK crypto enabled)"
    );
    WgServer::serve(
        config.with_bind(local),
        deps.with_endpoint(local.to_string()),
        sock,
        shutdown,
    )
    .await
}

/// Spawn the WireGuard listen task on the current Tokio runtime.
pub async fn spawn(
    config: WgConfig,
    store: Arc<FlowStore>,
    shutdown: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let deps = WgDeps::new(store);
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
        let deps = WgDeps::new(Arc::new(FlowStore::new(16, 1024, 64 * 1024)));
        let (tx, rx) = watch::channel(true);
        let done = tokio::time::timeout(
            Duration::from_secs(2),
            WgServer::serve_bind(config, deps, rx),
        )
        .await
        .expect("serve must not hang when already shut down");
        done.expect("clean early shutdown");
        drop(tx);
    }

    #[test]
    fn device_join_info_with_keys_has_real_public_material() {
        let info = DeviceJoinInfo::with_keys(
            "203.0.113.10:51820",
            "c2VydmVycHVi".into(),
            "Y2xpZW50cHJpdg==".into(),
            "Y2xpZW50cHVi".into(),
        );
        assert!(info.server_public_key.is_some());
        assert!(info.client_private_key.is_some());
        assert!(info.notes.iter().any(|n| n.contains("Noise_IK")));
    }

    #[tokio::test]
    async fn garbage_datagram_does_not_invent_flows() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = tokio::net::UdpSocket::bind(bind)
            .await
            .expect("bind");
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

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            store.len(),
            0,
            "WG must not invent CONNECT/HTTP flows from outer UDP"
        );

        tx.send(true).expect("shutdown");
        let done = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("serve must exit after shutdown")
            .expect("join");
        done.expect("clean serve after drop");
    }

    #[test]
    fn wg_deps_generates_device_and_null_ingress() {
        let store = Arc::new(FlowStore::new(4, 512, 1024));
        let deps = WgDeps::new(store);
        assert!(deps.device.is_some());
        assert!(deps.join_info.as_ref().unwrap().server_public_key.is_some());
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
