//! The windowed front end.
//!
//! Same proxy, same capture, same certificate authority as the command line
//! binary; the difference is that the traffic list is a native window instead
//! of a page on the UI port. The UI port is still served, so the two views can
//! be open at once and a phone can still reach the setup page.
//!
//! egui owns the main thread because macOS requires the event loop to live on
//! the first thread of the process, so tokio runs the servers underneath it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use proxima::config::{default_data_dir, Config, DecryptMode, DecryptRules, UpstreamHttp2};
use proxima::gui::Inspector;
use proxima::runtime::Servers;
use tracing_subscriber::EnvFilter;

/// Quiet by default for the same reason as the command line binary: at debug
/// level hyper and rustls bury anything about the capture.
const DEFAULT_LOG: &str = "proxima=info,warn";

#[derive(Parser, Debug)]
#[command(
    name = "proxima-gui",
    version,
    about = "See every request your phone makes, in a window.",
    after_help = "PROXIMA_LOG=debug turns on verbose logging."
)]
struct Cli {
    /// proxy port devices point at
    #[arg(short, long, value_name = "n", default_value_t = 9090)]
    port: u16,

    /// UI and API port
    #[arg(short = 'u', long, value_name = "n", default_value_t = 9091)]
    ui_port: u16,

    /// where the CA and settings live (default ~/.proxima)
    #[arg(long, value_name = "dir")]
    data_dir: Option<PathBuf>,

    /// tunnel TLS opaquely, decrypt nothing
    #[arg(long)]
    no_decrypt: bool,

    /// decrypt only these hosts (comma separated, * wildcards ok)
    #[arg(long, value_name = "hosts")]
    only: Vec<String>,

    /// never decrypt these hosts
    #[arg(long, value_name = "hosts")]
    skip: Vec<String>,

    /// ring buffer size
    #[arg(long, value_name = "n", default_value_t = 5000)]
    max_flows: usize,

    /// force HTTP/1.1 upstream
    #[arg(long)]
    no_http2: bool,

    /// accept invalid origin certificates
    #[arg(long)]
    insecure: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("proxima-gui: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Started before the window so a port clash or an unreadable data directory
    // is a message in the terminal rather than an empty window that never fills.
    let servers = runtime.block_on(Servers::start(config_from(&cli)))?;
    let status = servers.status();
    let store = servers.store().clone();
    let handle = runtime.handle().clone();

    eprintln!(
        "proxy on {}:{}, inspector also at http://127.0.0.1:{}",
        status
            .addresses
            .first()
            .map(String::as_str)
            .unwrap_or("127.0.0.1"),
        status.proxy_port,
        status.ui_port
    );

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([720.0, 420.0])
            .with_title("Proxima"),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Proxima",
        options,
        Box::new(move |cc| Ok(Box::new(Inspector::new(cc, store, status, handle)))),
    );

    // Closing the window stops the capture, so the servers come down with it
    // rather than being left listening with nothing watching them.
    runtime.block_on(servers.shutdown())?;

    result.map_err(|err| anyhow::anyhow!("the window could not be opened: {err}"))
}

fn init_tracing() {
    let filter = match std::env::var("PROXIMA_LOG") {
        Ok(value) => EnvFilter::new(value),
        Err(_) => match std::env::var("RUST_LOG") {
            Ok(value) => EnvFilter::new(value),
            Err(_) => EnvFilter::new(DEFAULT_LOG),
        },
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn config_from(cli: &Cli) -> Config {
    let allow = host_list(&cli.only);
    let deny = host_list(&cli.skip);
    let mode = if cli.no_decrypt {
        DecryptMode::None
    } else if allow.is_empty() {
        DecryptMode::All
    } else {
        DecryptMode::Allowlist
    };

    Config {
        proxy_port: cli.port,
        ui_port: cli.ui_port,
        data_dir: cli.data_dir.clone().unwrap_or_else(default_data_dir),
        max_flows: cli.max_flows.max(1),
        decrypt: DecryptRules { mode, allow, deny },
        upstream_http2: if cli.no_http2 {
            UpstreamHttp2::Never
        } else {
            UpstreamHttp2::Auto
        },
        insecure_upstream: cli.insecure,
        ..Config::default()
    }
}

/// Accepts both `--skip a,b` and a repeated `--skip`, because both are what
/// people type and neither is worth an error.
fn host_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}
