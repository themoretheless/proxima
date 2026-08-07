//! TUN scaffold task: ready log, shutdown watch, no device, no flows.
//!
//! Parallel to the WireGuard scaffold serve path, but without a UDP bind:
//! local capture is not a listen port. This task exists so runtime can start
//! and stop a named unit on the shared watch channel.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::capture::FlowStore;

/// Operator knobs for the TUN scaffold (no bind address: not a UDP port).
///
/// Built by runtime/CLI from `Config.tun`. Reserved for future device name /
/// routing hints; P10 carries an empty shell so the type is stable.
#[derive(Debug, Clone, Default)]
pub struct TunConfig {
    /// Reserved: preferred interface name hint (e.g. `utun`, `proxima0`).
    /// Scaffold ignores this; never opens a device from it.
    pub if_name_hint: Option<String>,
}

/// Shared dependencies for the TUN scaffold.
///
/// The flow store is process-shared. P10 never writes flows from this path.
#[derive(Clone)]
pub struct TunDeps {
    pub store: Arc<FlowStore>,
}

impl TunDeps {
    pub fn new(store: Arc<FlowStore>) -> Self {
        Self { store }
    }
}

/// No-op TUN scaffold task (watch shutdown only).
///
/// Does not open utun or `/dev/net/tun`. Does not invent HTTP/CONNECT/H3 flows.
/// Logs ready once, then waits for the shared shutdown watch.
pub struct TunServer;

impl TunServer {
    /// Run until `shutdown` flips to true.
    ///
    /// Logs that the scaffold is ready and that no device is open. Returns
    /// cleanly on shutdown so the runtime JoinSet can join without hanging CI.
    pub async fn serve(
        config: TunConfig,
        deps: TunDeps,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let _ = &config;
        info!(
            store_len = deps.store.len(),
            if_name_hint = ?config.if_name_hint,
            "TUN scaffold ready (no device open; no packet capture; not a working tunnel)"
        );

        if *shutdown.borrow() {
            debug!("TUN scaffold already shut down before watch");
            return Ok(());
        }

        loop {
            shutdown.changed().await?;
            if *shutdown.borrow() {
                debug!(
                    store_len = deps.store.len(),
                    "TUN scaffold shutting down (no device was opened)"
                );
                return Ok(());
            }
        }
    }
}
