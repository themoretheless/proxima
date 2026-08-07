//! Local TUN / packet-capture path (scaffold).
//!
//! ## Intent
//!
//! Classic phone Wi-Fi HTTP proxy settings only send TCP CONNECT to the proxy
//! port. Local host processes (and some VPN-style phone paths) can send UDP and
//! QUIC that never touch that port. A long-term option is to capture or route
//! traffic through a virtual interface that Proxima owns in userspace so
//! inspected packets land in this process.
//!
//! ## Platform limits (honest)
//!
//! - **macOS:** a real path would use `utun` and/or a Network Extension. There
//!   is no Linux-style TPROXY redirect on Darwin. Privileges and entitlements
//!   are non-trivial; this scaffold does not open any interface.
//! - **Linux:** a real path would use `/dev/net/tun` and typically
//!   `CAP_NET_ADMIN` (plus routing/NAT policy). This scaffold does not open
//!   the device and does not require those privileges.
//! - **Windows:** host capture is **not claimed** and is not part of P10.
//!
//! ## What P10 ships
//!
//! - Config/CLI/status knobs (always compiled; see [`crate::config`]).
//! - A feature-gated serve task that logs ready and exits on the shared watch
//!   channel (no device open, no packet loop).
//! - Trait stubs: [`TunDevice`], [`NotImplementedDevice`].
//! - [`platform_support_note`] for status/banner honesty.
//!
//! ## What is not shipped
//!
//! - Opening `utun` or `/dev/net/tun`
//! - Routing, NAT, TPROXY, or Network Extension plumbing
//! - Any packet parse that invents HTTP/CONNECT/H3 flows
//! - Co-enable with reverse-h3, QUIC UDP, or WireGuard (rejected in config)
//! - A working local capture claim in status or banner
//!
//! Behind `--features tun` only. Without that feature the binary has no TUN
//! serve task; requesting TUN flags fails with rebuild guidance.

mod device;
mod platform;
mod server;

pub use device::{NotImplementedDevice, TunDevice};
pub use platform::{platform_support_note, short_status_note};
pub use server::{TunConfig, TunDeps, TunServer};

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::watch;

use crate::capture::FlowStore;

/// Spawn the no-op TUN scaffold on the current Tokio runtime.
pub async fn spawn(
    config: TunConfig,
    store: Arc<FlowStore>,
    shutdown: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let deps = TunDeps::new(store);
    Ok(tokio::spawn(async move {
        TunServer::serve(config, deps, shutdown).await
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn already_shutdown_serve_returns_quickly() {
        let config = TunConfig::default();
        let deps = TunDeps::new(Arc::new(FlowStore::new(16, 1024, 64 * 1024)));
        let (tx, rx) = watch::channel(true);
        let done = tokio::time::timeout(
            Duration::from_secs(2),
            TunServer::serve(config, deps, rx),
        )
        .await
        .expect("scaffold must not hang when already shut down");
        done.expect("clean early shutdown");
        drop(tx);
    }

    #[tokio::test]
    async fn serve_exits_cleanly_on_shutdown_without_flows() {
        let store = Arc::new(FlowStore::new(16, 1024, 64 * 1024));
        let deps = TunDeps::new(store.clone());
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            TunServer::serve(TunConfig::default(), deps, rx).await
        });

        // Give the task a turn to log ready.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(store.len(), 0, "TUN scaffold must not invent flows");

        tx.send(true).expect("shutdown");
        let done = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("serve must exit after shutdown")
            .expect("join");
        done.expect("clean serve after shutdown");
        assert_eq!(store.len(), 0, "shutdown must not invent flows");
    }

    #[tokio::test]
    async fn spawn_helper_exits_cleanly_on_shutdown() {
        let store = Arc::new(FlowStore::new(16, 1024, 64 * 1024));
        let (tx, rx) = watch::channel(false);
        let handle = spawn(TunConfig::default(), store.clone(), rx)
            .await
            .expect("spawn must return a JoinHandle");

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(store.len(), 0, "spawn path must not invent flows");

        tx.send(true).expect("shutdown");
        let done = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("spawned serve must exit after shutdown")
            .expect("join");
        done.expect("clean spawn shutdown");
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn platform_support_note_is_exported() {
        let note = platform_support_note();
        assert!(note.contains("macOS") || note.contains("utun"));
        assert!(note.contains("Linux") || note.contains("/dev/net/tun"));
        assert!(
            note.contains("Windows")
                || note.contains("not supported")
                || note.contains("not claimed"),
            "must not claim Windows capture: {note}"
        );
        assert!(
            note.contains("no device")
                || note.contains("never")
                || note.contains("scaffold")
                || note.contains("not"),
            "must stay scaffold-honest: {note}"
        );
    }

    #[test]
    fn short_status_note_never_claims_live_capture() {
        for active in [true, false] {
            let note = short_status_note(active);
            let lower = note.to_ascii_lowercase();
            assert!(
                !lower.contains("capturing packets") && !lower.contains("live capture"),
                "short_status_note({active}) must not claim capture: {note}"
            );
            assert!(
                note.contains("scaffold")
                    || note.contains("not")
                    || note.contains("no")
                    || note.contains("compiled"),
                "short_status_note({active}) must stay honest: {note}"
            );
        }
    }
}
