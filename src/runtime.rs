//! Bringing the proxy, the inspector, and (when configured) the QUIC or
//! WireGuard UDP listeners up, and taking them down together.
//!
//! Front ends need listeners wired in the same order, and the order matters:
//! sockets are bound before anything else exists, because `--port 0` / UDP port
//! 0 ask the operating system to choose and everything downstream (the setup
//! page, the loop check, the banner, status) has to see the ports that were
//! actually granted. Binding first also means a port clash is reported before a
//! first run has minted a certificate authority it will never use.
//!
//! ## QUIC lifecycle
//!
//! When `Config.quic_port` is set and the binary was built with `--features
//! quic`, [`Servers::start`] binds UDP, rewrites port 0 into config/status,
//! and spawns [`crate::quic::QuicServer::serve`] on the shared [`JoinSet`] as
//! `"the QUIC listener"`. [`Servers::stop`] / [`Servers::shutdown`] flip one
//! watch channel that closes the TCP proxy, inspector, and QUIC accept loop
//! together; the QUIC task drains open connections for up to ~5s before
//! returning.
//!
//! Without `--features quic`, requesting a UDP listener fails hard with rebuild
//! guidance (no silent ignore). Regular TCP proxy mode never opens a UDP
//! socket and does not invent HTTP/3 flows on CONNECT.
//!
//! ## WireGuard lifecycle (scaffold)
//!
//! When `Config.wg_port` is set and the binary was built with `--features
//! wireguard`, [`Servers::start`] binds the WG UDP port, rewrites port 0, and
//! spawns the scaffold listen task on the same shutdown watch. Crypto is not
//! implemented: the task accepts the bind and drops unexpected datagrams.
//! Reverse-h3 and WireGuard co-enable is rejected in config validation.
//!
//! ## TUN lifecycle (scaffold)
//!
//! When `Config.tun` is true and the binary was built with `--features tun`,
//! [`Servers::start`] spawns `"the TUN scaffold"` on the same shutdown watch.
//! No utun or `/dev/net/tun` is opened; the task logs ready and waits for
//! shutdown. Co-enable with reverse-h3, QUIC UDP, and WireGuard is rejected
//! in config validation.

use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::api::{self, ApiState};
use crate::ca::CertAuthority;
use crate::capture::{Archive, FlowStore};
use crate::proxy::forward::Upstream;
use crate::proxy::{ProxyDeps, ProxyServer};
use crate::replay::ReplayEngine;
use crate::types::ServerStatus;
use crate::Config;

/// Running listeners with the handles a front end needs to show what they are
/// doing. Dropping this does not stop them; call [`Servers::stop`].
///
/// Tasks always include the TCP proxy and the inspector. With `--features quic`
/// and a configured `quic_port`, they also include `"the QUIC listener"`. With
/// `--features wireguard` and a configured `wg_port`, they include
/// `"the WireGuard scaffold"`. With `--features tun` and `Config.tun`, they
/// include `"the TUN scaffold"`. One shutdown watch stops every task;
/// [`Servers::shutdown`] joins them all.
pub struct Servers {
    config: Arc<Config>,
    ca: Arc<CertAuthority>,
    store: Arc<FlowStore>,
    state: ApiState,
    shutdown: watch::Sender<bool>,
    tasks: JoinSet<(&'static str, Result<()>)>,
    /// Collected as servers stop rather than returned one at a time, since one
    /// falling over usually explains the other.
    failures: Vec<String>,
}

impl Servers {
    /// Binds, builds and spawns. The returned `config` carries the ports that
    /// were actually bound, which is not what was asked for when either was 0.
    ///
    /// If `config.wants_quic()` is true and this binary was not built with
    /// `--features quic`, returns an error before any socket is opened.
    /// Same hard fail for WireGuard without `--features wireguard` and for
    /// TUN without `--features tun`.
    pub async fn start(mut config: Config) -> Result<Self> {
        install_crypto_provider();

        // Defense in depth: CLI validate_quic already rejects this, but
        // Servers::start is a public API used by the GUI and tests too.
        #[cfg(not(feature = "quic"))]
        if config.wants_quic() {
            return Err(anyhow!(crate::config::quic_feature_required_message()));
        }
        #[cfg(not(feature = "wireguard"))]
        if config.wg_port.is_some() {
            return Err(anyhow!(crate::config::wireguard_feature_required_message()));
        }
        #[cfg(not(feature = "tun"))]
        if config.tun {
            return Err(anyhow!(crate::config::tun_feature_required_message()));
        }

        let proxy_listener =
            bind(&config.proxy_host, config.proxy_port, "the proxy", "--port").await?;
        let ui_listener = bind(
            &config.ui_host,
            config.ui_port,
            "the inspector",
            "--ui-port",
        )
        .await?;
        config.proxy_port = local_port(&proxy_listener)?;
        config.ui_port = local_port(&ui_listener)?;

        // QUIC UDP is bound before Config is shared so port 0 is rewritten into
        // status the same way TCP ports are. Regular mode leaves quic_port None
        // and never opens a UDP socket. Bind failures are classified and traced
        // inside quic::bind_udp (addr, kind, os_error) before we bubble them.
        #[cfg(feature = "quic")]
        let quic_sock = if config.wants_quic() {
            let quic_port = config
                .quic_port
                .expect("wants_quic implies quic_port is Some");
            let host: std::net::IpAddr = config.quic_host.parse().map_err(|err| {
                tracing::error!(
                    host = %config.quic_host,
                    error = %err,
                    "QUIC UDP host is not a valid IP address"
                );
                anyhow!(
                    "quic host {:?} is not a valid IP address to bind \
                     (use 0.0.0.0, 127.0.0.1, or ::): {err}",
                    config.quic_host
                )
            })?;
            let bind_addr = std::net::SocketAddr::new(host, quic_port);
            let sock = crate::quic::bind_udp(bind_addr)
                .await
                .with_context(|| format!("starting the QUIC listener on {bind_addr}"))?;
            let local = crate::quic::bound_addr(&sock).with_context(|| {
                format!("reading the QUIC listen address after bind on {bind_addr}")
            })?;
            config.quic_port = Some(local.port());
            info!(%local, reverse = ?config.reverse_h3, "QUIC/UDP endpoint bound");
            Some(sock)
        } else {
            None
        };

        // WireGuard scaffold UDP: same port-0 rewrite pattern. Co-enable with
        // reverse-h3 is rejected in config validation before we get here.
        #[cfg(feature = "wireguard")]
        let wg_sock = if config.wg_port.is_some() {
            let wg_port = config.wg_port.expect("wg_port is Some");
            let host: std::net::IpAddr = config.wg_host.parse().map_err(|err| {
                tracing::error!(
                    host = %config.wg_host,
                    error = %err,
                    "WireGuard UDP host is not a valid IP address"
                );
                anyhow!(
                    "wireguard host {:?} is not a valid IP address to bind \
                     (use 0.0.0.0, 127.0.0.1, or ::): {err}",
                    config.wg_host
                )
            })?;
            let bind_addr = std::net::SocketAddr::new(host, wg_port);
            let sock = tokio::net::UdpSocket::bind(bind_addr)
                .await
                .with_context(|| format!("starting the WireGuard scaffold on {bind_addr}"))?;
            let local = sock.local_addr().with_context(|| {
                format!("reading the WireGuard listen address after bind on {bind_addr}")
            })?;
            config.wg_port = Some(local.port());
            info!(
                %local,
                "WireGuard UDP scaffold bound (crypto not implemented; no device tunnel)"
            );
            Some(sock)
        } else {
            None
        };

        let config = Arc::new(config);

        let ca = Arc::new(CertAuthority::open(&config.data_dir).with_context(|| {
            format!(
                "opening the certificate authority under {}",
                config.data_dir.display()
            )
        })?);
        info!(
            path = %ca.cert_path().display(),
            fingerprint = %ca.sha256(),
            "certificate authority ready"
        );

        let mut store = FlowStore::new(
            config.max_flows,
            config.max_body_bytes,
            config.max_total_body_bytes,
        )
        .with_max_ws_messages(config.max_ws_messages);
        if let Some(path) = &config.archive_path {
            // A failure here stops the start. Someone who passed --archive and
            // silently got no archive would only find out later, when the
            // traffic they wanted to ask about was already gone.
            let archive = Archive::open(path)
                .with_context(|| format!("opening the traffic archive at {}", path.display()))?;
            store = store.with_archive(archive);
        }
        let store = Arc::new(store);
        let upstream = Upstream::new(&config).context("preparing the upstream TLS settings")?;
        let replay = Arc::new(
            ReplayEngine::new(config.clone(), store.clone())
                .context("starting the replay engine")?,
        );

        let ws_registry = Arc::new(crate::proxy::websocket::WsRegistry::new());
        let pauses = Arc::new(crate::proxy::breakpoint::PauseHub::new());
        let ws_rewrite = crate::proxy::ws_rewrite::WsRewriteHub::compile(&config.ws_rewrite)
            .map_err(|err| anyhow::anyhow!("compiling WebSocket rewrite rules: {err}"))?;
        let rewrite = crate::proxy::rewrite::RewriteHub::new(config.rewrite.clone());
        let state = ApiState {
            config: config.clone(),
            ca: ca.clone(),
            store: store.clone(),
            replay,
            proxy_port: config.proxy_port,
            ui_port: config.ui_port,
            ws_registry: ws_registry.clone(),
            pauses: pauses.clone(),
            ws_rewrite: ws_rewrite.clone(),
            rewrite: rewrite.clone(),
        };
        let deps = Arc::new(ProxyDeps {
            config: config.clone(),
            ca: ca.clone(),
            store: store.clone(),
            upstream,
            // A phone can only reach the proxy port until it trusts us, so the
            // setup page has to be served from there as well as from the UI port.
            setup: Arc::new(api::SetupService {
                state: state.clone(),
            }),
            ws_registry,
            pauses,
            ws_rewrite,
            rewrite,
        });

        let (shutdown, shutdown_rx) = watch::channel(false);
        let mut tasks = JoinSet::new();
        let proxy_shutdown = shutdown_rx.clone();
        tasks.spawn(async move {
            (
                "the proxy",
                ProxyServer::serve(deps, proxy_listener, proxy_shutdown).await,
            )
        });
        let api_state = state.clone();
        let api_shutdown = shutdown_rx.clone();
        tasks.spawn(async move {
            (
                "the inspector",
                api::serve(api_state, ui_listener, api_shutdown).await,
            )
        });

        // Shared shutdown watch: stop() sends true, and QuicServer::serve /
        // ProxyServer / api::serve / WgServer all exit when their receivers flip.
        #[cfg(feature = "quic")]
        if let Some(sock) = quic_sock {
            let endpoint = crate::quic::QuicEndpoint::server(sock, ca.clone())?;
            // Config uses reverse_h3; QuicDeps uses reverse_upstream (UDP-layer name).
            let deps = Arc::new(crate::quic::QuicDeps::new(
                ca.clone(),
                store.clone(),
                config.reverse_h3.clone(),
                config.insecure_upstream,
            ));
            let quic_shutdown = shutdown_rx.clone();
            tasks.spawn(async move {
                (
                    "the QUIC listener",
                    crate::quic::QuicServer::serve(endpoint, deps, quic_shutdown).await,
                )
            });
        }

        #[cfg(feature = "wireguard")]
        if let Some(sock) = wg_sock {
            let local = sock
                .local_addr()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            let wg_config = crate::wireguard::WgConfig { bind: local };
            let deps = crate::wireguard::WgDeps::new(store.clone());
            let wg_shutdown = shutdown_rx.clone();
            tasks.spawn(async move {
                (
                    "the WireGuard scaffold",
                    crate::wireguard::WgServer::serve(wg_config, deps, sock, wg_shutdown).await,
                )
            });
        }

        // TUN scaffold: no socket bind (not a UDP port). Task only watches
        // shutdown; never opens utun or /dev/net/tun.
        #[cfg(feature = "tun")]
        if config.tun {
            let tun_config = crate::tun::TunConfig::default();
            let deps = crate::tun::TunDeps::new(store.clone());
            let tun_shutdown = shutdown_rx.clone();
            tasks.spawn(async move {
                (
                    "the TUN scaffold",
                    crate::tun::TunServer::serve(tun_config, deps, tun_shutdown).await,
                )
            });
            info!(
                "TUN scaffold task started (no device open; not a working capture path)"
            );
        }

        Ok(Self {
            config,
            ca,
            store,
            state,
            shutdown,
            tasks,
            failures: Vec::new(),
        })
    }

    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    pub fn ca(&self) -> &Arc<CertAuthority> {
        &self.ca
    }

    pub fn store(&self) -> &Arc<FlowStore> {
        &self.store
    }

    pub fn status(&self) -> ServerStatus {
        api::status(&self.state)
    }

    /// Asks every listener (proxy, inspector, QUIC, and WireGuard when present)
    /// to finish what it is serving and stop. Shared watch; join happens in
    /// [`Servers::shutdown`].
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Resolves when a server stops on its own, which outside shutdown only
    /// happens on failure. The reason is kept for [`Servers::shutdown`] to
    /// report, so a caller can simply select on this and stop.
    ///
    /// Never resolves once every task has been reaped, so it is safe to select
    /// on repeatedly rather than being a source of spurious wakeups.
    pub async fn stopped_early(&mut self) {
        match self.tasks.join_next().await {
            Some(joined) => {
                if let Some(message) = failure(joined) {
                    self.failures.push(message);
                }
            }
            None => std::future::pending().await,
        }
    }

    /// Stops every listener and waits for the JoinSet (proxy, inspector, QUIC,
    /// WireGuard scaffold) to drain, reporting anything that did not end
    /// cleanly, including whatever [`Servers::stopped_early`] already saw.
    pub async fn shutdown(mut self) -> Result<()> {
        self.stop();
        while let Some(joined) = self.tasks.join_next().await {
            if let Some(message) = failure(joined) {
                self.failures.push(message);
            }
        }
        if self.failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(self.failures.join("; ")))
        }
    }
}

type Joined = std::result::Result<(&'static str, Result<()>), tokio::task::JoinError>;

fn failure(joined: Joined) -> Option<String> {
    match joined {
        Ok((name, Ok(()))) => {
            debug!("{name} stopped");
            None
        }
        Ok((name, Err(err))) => Some(format!("{name} stopped: {err:#}")),
        Err(err) => Some(format!("a server task did not finish cleanly: {err}")),
    }
}

/// rustls needs one process wide provider, and both servers would otherwise
/// race to install it on their first handshake.
pub fn install_crypto_provider() {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        debug!("a TLS crypto provider was already installed");
    }
}

/// Binds, turning the two failures a user actually causes into advice rather
/// than an errno.
async fn bind(host: &str, port: u16, what: &str, flag: &str) -> Result<TcpListener> {
    match TcpListener::bind((host, port)).await {
        Ok(listener) => Ok(listener),
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => Err(anyhow!(
            "port {port} is already in use, so {what} could not start. Another Proxima is the \
             usual reason. Stop it, or start this one with {flag} <n> on a free port."
        )),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Err(anyhow!(
            "binding {host}:{port} for {what} was refused. Ports below 1024 need root, so pick a \
             higher one with {flag} <n>."
        )),
        Err(err) => {
            Err(anyhow::Error::new(err).context(format!("binding {host}:{port} for {what}")))
        }
    }
}

fn local_port(listener: &TcpListener) -> Result<u16> {
    Ok(listener
        .local_addr()
        .context("reading back a listen address")?
        .port())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ephemeral(dir: &std::path::Path) -> Config {
        Config {
            proxy_port: 0,
            ui_port: 0,
            proxy_host: "127.0.0.1".to_string(),
            ui_host: "127.0.0.1".to_string(),
            data_dir: dir.to_path_buf(),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn starting_reports_the_ports_that_were_actually_bound() {
        let dir = tempfile::tempdir().expect("temp dir");
        let servers = Servers::start(ephemeral(dir.path())).await.expect("start");

        let config = servers.config().clone();
        assert_ne!(config.proxy_port, 0, "port 0 was never resolved to a real one");
        assert_ne!(config.ui_port, 0);
        assert_ne!(config.proxy_port, config.ui_port);

        let status = servers.status();
        assert_eq!(status.proxy_port, config.proxy_port);
        assert_eq!(status.ui_port, config.ui_port);
        assert!(!status.ca_fingerprint.is_empty());
        assert_eq!(status.quic_enabled, cfg!(feature = "quic"));
        assert_eq!(status.quic_port, None, "default start binds no UDP listener");
        assert!(
            status
                .quic_note
                .as_deref()
                .is_some_and(|n| n.contains("cannot see QUIC")),
            "status must explain that regular TCP proxy cannot see QUIC"
        );
        assert_eq!(
            status.tun_enabled,
            cfg!(feature = "tun"),
            "default start must always expose tunEnabled for feature detection"
        );
        assert_eq!(
            status.tun_active, None,
            "default start must not mark TUN active without --tun"
        );
        assert!(
            status
                .tun_note
                .as_deref()
                .is_some_and(|n| n.contains("TUN") || n.contains("tun") || n.contains("capture")),
            "default status must carry an honest tun_note: {:?}",
            status.tun_note
        );

        servers.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_taken_port_is_reported_with_the_flag_that_moves_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let first = Servers::start(ephemeral(dir.path())).await.expect("start");
        let taken = first.config().proxy_port;

        let mut clash = ephemeral(dir.path());
        clash.proxy_port = taken;
        let message = match Servers::start(clash).await {
            Ok(_) => panic!("binding a port that is already listening was allowed"),
            Err(err) => format!("{err:#}"),
        };

        assert!(message.contains(&taken.to_string()), "{message}");
        assert!(message.contains("--port"), "the advice must name the flag: {message}");

        first.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn the_store_and_the_certificate_authority_outlive_the_start_call() {
        let dir = tempfile::tempdir().expect("temp dir");
        let servers = Servers::start(ephemeral(dir.path())).await.expect("start");

        assert!(servers.store().is_empty());
        assert!(servers.ca().cert_path().exists(), "the CA was never written");

        servers.shutdown().await.expect("clean shutdown");
    }

    #[cfg(not(feature = "quic"))]
    #[tokio::test]
    async fn quic_port_without_feature_fails_hard() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = ephemeral(dir.path());
        cfg.quic_port = Some(9443);
        cfg.quic_host = "127.0.0.1".to_string();

        let message = match Servers::start(cfg).await {
            Ok(_) => panic!("UDP without --features quic must not start"),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            message.contains("--features quic"),
            "must name rebuild guidance: {message}"
        );
    }

    #[cfg(not(feature = "wireguard"))]
    #[tokio::test]
    async fn wireguard_port_without_feature_fails_hard() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = ephemeral(dir.path());
        cfg.wg_port = Some(51820);
        cfg.wg_host = "127.0.0.1".to_string();
        cfg.mode = crate::config::ListenMode::WireGuard;

        let message = match Servers::start(cfg).await {
            Ok(_) => panic!("WG without --features wireguard must not start"),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            message.contains("--features wireguard"),
            "must name rebuild guidance: {message}"
        );
    }

    #[cfg(feature = "wireguard")]
    #[tokio::test]
    async fn wireguard_port_zero_is_rewritten_and_shuts_down() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = ephemeral(dir.path());
        cfg.wg_port = Some(0);
        cfg.wg_host = "127.0.0.1".to_string();
        cfg.mode = crate::config::ListenMode::WireGuard;

        let servers = Servers::start(cfg).await.expect("start with wireguard");
        let port = servers.config().wg_port.expect("wg_port set");
        assert_ne!(port, 0, "WG port 0 must resolve to a real port");
        let status = servers.status();
        assert!(
            status.wireguard_enabled,
            "feature-on build must report wireguardEnabled"
        );
        assert_eq!(status.wireguard_port, Some(port));
        assert!(
            status
                .wireguard_note
                .as_deref()
                .is_some_and(|n| n.contains(&port.to_string()) || n.contains("scaffold")),
            "wireguard_note should mention scaffold or port: {:?}",
            status.wireguard_note
        );

        let done = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            servers.shutdown(),
        )
        .await
        .expect("WG+TCP shutdown must finish");
        done.expect("clean wireguard shutdown");
    }

    #[cfg(not(feature = "tun"))]
    #[tokio::test]
    async fn tun_without_feature_fails_hard() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = ephemeral(dir.path());
        cfg.tun = true;
        cfg.mode = crate::config::ListenMode::Tun;

        let message = match Servers::start(cfg).await {
            Ok(_) => panic!("TUN without --features tun must not start"),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            message.contains("--features tun"),
            "must name rebuild guidance: {message}"
        );
    }

    #[cfg(feature = "tun")]
    #[tokio::test]
    async fn tun_scaffold_starts_and_shuts_down_cleanly() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = ephemeral(dir.path());
        cfg.tun = true;
        cfg.mode = crate::config::ListenMode::Tun;

        let servers = Servers::start(cfg).await.expect("start with tun");
        assert!(servers.config().tun);
        let store = servers.store().clone();
        assert_eq!(store.len(), 0, "TUN scaffold must not invent flows on start");
        let status = servers.status();
        assert!(
            status.tun_enabled,
            "feature-on build must report tunEnabled"
        );
        assert_eq!(status.tun_active, Some(true));
        assert!(
            status
                .tun_note
                .as_deref()
                .is_some_and(|n| n.contains("scaffold") || n.contains("not") || n.contains("TUN")),
            "tun_note should be honest about scaffold: {:?}",
            status.tun_note
        );
        // Must not claim live capture.
        let note = status.tun_note.as_deref().unwrap_or("");
        assert!(
            !note.to_ascii_lowercase().contains("capturing packets")
                && (note.contains("no") || note.contains("not") || note.contains("scaffold")),
            "tun_note must not claim working capture: {note}"
        );
        assert!(
            note.contains("macOS")
                || note.contains("utun")
                || note.contains("Linux")
                || note.contains("/dev/net/tun"),
            "feature-on active note should mention platform limits: {note}"
        );

        let done = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            servers.shutdown(),
        )
        .await
        .expect("TUN+TCP shutdown must finish");
        done.expect("clean tun shutdown");
        assert_eq!(
            store.len(),
            0,
            "TUN scaffold must not invent flows on shutdown"
        );
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn quic_port_zero_is_rewritten_and_shuts_down() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = ephemeral(dir.path());
        cfg.quic_port = Some(0);
        cfg.quic_host = "127.0.0.1".to_string();

        let servers = Servers::start(cfg).await.expect("start with quic");
        let port = servers.config().quic_port.expect("quic_port set");
        assert_ne!(port, 0, "UDP port 0 must resolve to a real port");
        let status = servers.status();
        assert!(status.quic_enabled, "feature-on build must report quicEnabled");
        assert_eq!(status.quic_port, Some(port));
        assert!(
            status
                .quic_note
                .as_deref()
                .is_some_and(|n| n.contains(&port.to_string())),
            "quic_note should mention the bound UDP port"
        );
        // Accept-only path (no reverse_h3): still binds and reports status.
        assert!(servers.config().reverse_h3.is_none());

        // Shared stop must reap the QUIC task within the drain budget (~5s)
        // plus a small join margin; hanging here means drain is broken.
        let done = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            servers.shutdown(),
        )
        .await
        .expect("QUIC+TCP shutdown must finish within drain window");
        done.expect("clean quic shutdown");
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn reverse_h3_binds_udp_and_shares_shutdown() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = ephemeral(dir.path());
        cfg.quic_port = Some(0);
        cfg.quic_host = "127.0.0.1".to_string();
        cfg.mode = crate::config::ListenMode::ReverseH3;
        cfg.reverse_h3 = Some("127.0.0.1:443".to_string());
        cfg.insecure_upstream = true;

        let servers = Servers::start(cfg).await.expect("start reverse-h3");
        let port = servers.config().quic_port.expect("quic_port set");
        assert_ne!(port, 0);
        let status = servers.status();
        assert_eq!(status.quic_port, Some(port));
        assert_eq!(status.reverse_h3.as_deref(), Some("127.0.0.1:443"));
        assert!(
            status
                .quic_note
                .as_deref()
                .is_some_and(|n| n.contains("reverse") || n.contains(&port.to_string())),
            "reverse note should mention mode or port: {:?}",
            status.quic_note
        );

        let done = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            servers.shutdown(),
        )
        .await
        .expect("reverse-h3 shutdown must finish within drain window");
        done.expect("clean reverse-h3 shutdown");
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn taken_quic_port_names_the_address() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut first_cfg = ephemeral(dir.path());
        first_cfg.quic_port = Some(0);
        first_cfg.quic_host = "127.0.0.1".to_string();
        let first = Servers::start(first_cfg).await.expect("first quic");
        let taken = first.config().quic_port.expect("bound");

        let mut clash = ephemeral(dir.path());
        clash.quic_port = Some(taken);
        clash.quic_host = "127.0.0.1".to_string();
        let message = match Servers::start(clash).await {
            Ok(_) => panic!("second bind on the same UDP port was allowed"),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            message.contains(&taken.to_string()) || message.contains("already in use"),
            "bind failure should name the conflict: {message}"
        );
        assert!(
            message.contains("--quic-port"),
            "advice must name --quic-port: {message}"
        );
        assert!(
            message.contains("QUIC") || message.contains("UDP") || message.contains("quic"),
            "advice should identify the QUIC listener: {message}"
        );
        // Context from Servers::start should wrap the bind advice.
        assert!(
            message.contains("starting the QUIC listener") || message.contains("already in use"),
            "runtime should keep bind advice visible: {message}"
        );

        first.shutdown().await.expect("clean shutdown");
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn invalid_quic_host_fails_before_bind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = ephemeral(dir.path());
        cfg.quic_port = Some(0);
        cfg.quic_host = "not-an-ip".to_string();

        let message = match Servers::start(cfg).await {
            Ok(_) => panic!("invalid quic_host must not start"),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            message.contains("not-an-ip") || message.contains("valid IP"),
            "must name the bad host: {message}"
        );
    }
}
