//! Bringing the proxy and the inspector up, and taking them down together.
//!
//! Both front ends need the same six things wired in the same order, and the
//! order matters: the listeners are bound before anything else exists, because
//! `--port 0` asks the operating system to choose and everything downstream
//! (the setup page, the loop check, the banner) has to see the port that was
//! actually granted. Binding first also means a port clash is reported before a
//! first run has minted a certificate authority it will never use.

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

/// Both servers, running, with the handles a front end needs to show what they
/// are doing. Dropping this does not stop them; call [`Servers::stop`].
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
    pub async fn start(mut config: Config) -> Result<Self> {
        install_crypto_provider();

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
        );
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

        let state = ApiState {
            config: config.clone(),
            ca: ca.clone(),
            store: store.clone(),
            replay,
            proxy_port: config.proxy_port,
            ui_port: config.ui_port,
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
        tasks.spawn(async move {
            (
                "the inspector",
                api::serve(api_state, ui_listener, shutdown_rx).await,
            )
        });

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

    /// Asks both servers to finish what they are serving and stop.
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Resolves when a server stops on its own, which outside shutdown only
    /// happens on failure. The reason is kept for [`Servers::shutdown`] to
    /// report, so a caller can simply select on this and stop.
    ///
    /// Never resolves once both have been reaped, so it is safe to select on
    /// repeatedly rather than being a source of spurious wakeups.
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

    /// Stops both and waits for them, reporting anything that did not end
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
}
