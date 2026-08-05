//! The binary: read the flags, bind both ports, build the pieces, tell the user
//! what to do with a phone, and run until ctrl-c.
//!
//! The banner is not decoration. A proxy that is running but that nobody has
//! pointed a device at looks exactly like a proxy that is broken, and the one
//! step people get wrong is the iOS trust switch, so both the address to type
//! and that step are printed where they cannot be missed.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use proxima::config::{default_data_dir, Config, DecryptMode, DecryptRules, UpstreamHttp2};
use proxima::runtime::Servers;
use proxima::types::ServerStatus;
use tracing::warn;
use tracing_subscriber::EnvFilter;

/// Proxima at info, the crates underneath at warn. hyper and rustls at info are
/// a wall of per-connection noise that buries anything about the capture.
const DEFAULT_LOG: &str = "proxima=info,warn";

#[derive(Parser)]
#[command(
    name = "proxima",
    version,
    about = "See every request your phone makes, then edit and replay it.",
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

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(err) = validate(&cli) {
        err.exit();
    }
    init_tracing();

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // The alternate form prints the whole chain. Someone staring at a
            // failed start needs the cause, not the summary of it.
            eprintln!("proxima: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let mut servers = Servers::start(config_from(&cli)).await?;
    print!(
        "{}",
        banner(
            &servers.status(),
            servers.ca().cert_path(),
            servers.config()
        )
    );

    tokio::select! {
        _ = ctrl_c() => {}
        // A server that stops by itself has failed; there is nothing left to
        // wait for, so the other one comes down with it.
        _ = servers.stopped_early() => {}
    }
    servers.shutdown().await
}


/// Resolves on ctrl-c. If the handler cannot be installed there is no clean
/// stop to wait for, so this never resolves and a kill signal ends the process,
/// which beats exiting a second after start.
async fn ctrl_c() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            // The terminal has just echoed ^C onto the current line.
            println!();
            println!("Stopping.");
        }
        Err(err) => {
            warn!(error = %err, "ctrl-c cannot be watched for, so stopping needs a kill signal");
            std::future::pending::<()>().await;
        }
    }
}

/* ------------------------------------------------------------------ */
/* startup                                                             */
/* ------------------------------------------------------------------ */

fn init_tracing() {
    let filter = match std::env::var("PROXIMA_LOG") {
        Ok(value) => EnvFilter::new(value),
        // RUST_LOG is what the README documents and what a Rust user types by
        // reflex, so it keeps working as a second name for the same knob.
        Err(_) => match std::env::var("RUST_LOG") {
            Ok(value) => EnvFilter::new(value),
            Err(_) => EnvFilter::new(DEFAULT_LOG),
        },
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        // Logs go to stderr so the banner on stdout survives being piped or
        // redirected on its own.
        .with_writer(io::stderr)
        .init();
}

/// Rejects flag combinations that contradict each other, with the reason rather
/// than a bare "cannot be used with".
fn validate(cli: &Cli) -> std::result::Result<(), clap::Error> {
    if cli.no_decrypt && !cli.only.is_empty() {
        return Err(Cli::command().error(
            clap::error::ErrorKind::ArgumentConflict,
            "--no-decrypt decrypts nothing at all, so --only would have no hosts left to allow. \
             Pass --only on its own to decrypt just those hosts, or --no-decrypt on its own to \
             decrypt none of them.",
        ));
    }
    if cli.max_flows == 0 {
        return Err(Cli::command().error(
            clap::error::ErrorKind::ValueValidation,
            "--max-flows must be at least 1: a ring buffer of zero would evict every flow the \
             moment it was captured.",
        ));
    }
    Ok(())
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
        max_flows: cli.max_flows,
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

/// Splits the comma separated host lists, dropping the empty entries a trailing
/// comma leaves behind. An empty pattern matches nothing and would be a silent
/// no-op in the rules.
fn host_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_string)
        .collect()
}

/* ------------------------------------------------------------------ */
/* banner                                                              */
/* ------------------------------------------------------------------ */

fn banner(status: &ServerStatus, ca_path: &Path, config: &Config) -> String {
    // Best first, so this is the address a phone on the same Wi-Fi should use.
    let host = status
        .addresses
        .first()
        .map(String::as_str)
        .unwrap_or("127.0.0.1");
    let setup_host = config
        .setup_hosts
        .first()
        .map(String::as_str)
        .unwrap_or("proxima.setup");

    format!(
        "
Proxima is running.

  proxy       {proxy}
  inspector   http://127.0.0.1:{ui_port}
  root CA     {ca}
              SHA-256 {fingerprint}

Point a phone at it. Both devices have to be on the same network.

  1. Phone Wi-Fi settings, configure proxy, manual.
     Server {host}, port {proxy_port}.
  2. Open http://{setup_host} in the phone's browser. The proxy serves that
     page over plain HTTP, so it works before any certificate is trusted.
  3. Install the certificate it offers.
  4. iOS only, and this is the step everyone misses: Settings, General, About,
     Certificate Trust Settings, then switch on the Proxima root. Installing
     the profile is not enough on its own.
{notes}
Ctrl-C to stop.
",
        proxy = authority(host, status.proxy_port),
        ui_port = status.ui_port,
        ca = ca_path.display(),
        fingerprint = status.ca_fingerprint,
        proxy_port = status.proxy_port,
        notes = notes(status, config),
    )
}

/// Everything about this run that differs from the defaults, or that will stop
/// a phone from ever reaching the proxy.
fn notes(status: &ServerStatus, config: &Config) -> String {
    let mut notes: Vec<String> = Vec::new();

    if !status.addresses.is_empty() && status.addresses.iter().all(|a| is_loopback(a)) {
        notes.push(
            "No LAN address was found, so a phone cannot reach this machine.".to_string(),
        );
    } else if status.addresses.len() > 1 {
        notes.push(format!(
            "Also reachable at {}.",
            status.addresses[1..].join(", ")
        ));
    }

    match config.decrypt.mode {
        DecryptMode::None => notes.push(
            "Decryption is off. You will see endpoints and byte counts, not contents."
                .to_string(),
        ),
        DecryptMode::Allowlist => notes.push(format!(
            "Decrypting only {}. Everything else is tunnelled opaquely.",
            config.decrypt.allow.join(", ")
        )),
        DecryptMode::All => {}
    }
    if !config.decrypt.deny.is_empty() {
        notes.push(format!("Not decrypting {}.", config.decrypt.deny.join(", ")));
    }
    if config.upstream_http2 == UpstreamHttp2::Never {
        notes.push("Talking to origins over HTTP/1.1 only.".to_string());
    }
    if config.insecure_upstream {
        notes.push("Not verifying origin certificates.".to_string());
    }

    if notes.is_empty() {
        return String::new();
    }
    let body: String = notes.iter().map(|note| format!("  {note}\n")).collect();
    format!("\n{body}")
}

/// `host:port`, with an IPv6 literal bracketed so the line can be pasted into
/// anything that takes a URL.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn is_loopback(address: &str) -> bool {
    address
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        let mut argv = vec!["proxima"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).expect("these flags should parse")
    }

    fn status(addresses: &[&str]) -> ServerStatus {
        ServerStatus {
            proxy_port: 54321,
            ui_port: 8080,
            addresses: addresses.iter().map(|a| a.to_string()).collect(),
            ca_fingerprint: "AB:CD:EF".to_string(),
            ca_not_after: "2035-08-05T00:00:00Z".to_string(),
            flow_count: 0,
            capturing: true,
        }
    }

    #[test]
    fn only_switches_decryption_to_an_allowlist() {
        let config = config_from(&cli(&["--only", "api.example.com, *.foo.com"]));
        assert_eq!(config.decrypt.mode, DecryptMode::Allowlist);
        assert_eq!(
            config.decrypt.allow,
            vec!["api.example.com", "*.foo.com"],
            "the comma separated list was not split and trimmed"
        );
    }

    #[test]
    fn no_decrypt_turns_decryption_off_entirely() {
        assert_eq!(
            config_from(&cli(&["--no-decrypt"])).decrypt.mode,
            DecryptMode::None
        );
    }

    #[test]
    fn skip_fills_the_deny_list_and_leaves_the_mode_alone() {
        let config = config_from(&cli(&["--skip", "*.bank.com,"]));
        assert_eq!(config.decrypt.mode, DecryptMode::All);
        assert_eq!(
            config.decrypt.deny,
            vec!["*.bank.com"],
            "a trailing comma left an empty pattern, which silently matches nothing"
        );
    }

    #[test]
    fn the_remaining_flags_reach_the_config() {
        let config = config_from(&cli(&[
            "--port",
            "1080",
            "--ui-port",
            "1081",
            "--max-flows",
            "7",
            "--no-http2",
            "--insecure",
            "--data-dir",
            "/tmp/proxima-test",
        ]));
        assert_eq!(config.proxy_port, 1080);
        assert_eq!(config.ui_port, 1081);
        assert_eq!(config.max_flows, 7);
        assert_eq!(config.upstream_http2, UpstreamHttp2::Never);
        assert!(config.insecure_upstream);
        assert_eq!(config.data_dir, PathBuf::from("/tmp/proxima-test"));
    }

    #[test]
    fn no_decrypt_together_with_only_is_refused() {
        let err = validate(&cli(&["--no-decrypt", "--only", "api.example.com"]))
            .expect_err("the two flags contradict each other");
        let text = err.to_string();
        assert!(
            text.contains("--no-decrypt") && text.contains("--only"),
            "the error names neither flag, so nobody can act on it: {text}"
        );
    }

    #[test]
    fn a_ring_buffer_of_zero_is_refused() {
        validate(&cli(&["--max-flows", "0"]))
            .expect_err("zero would evict every flow as it arrived");
    }

    #[test]
    fn the_banner_carries_the_bound_ports_the_lan_address_and_the_fingerprint() {
        let text = banner(
            &status(&["192.168.1.24"]),
            Path::new("/home/me/.proxima/ca/proxima-ca.crt"),
            &Config::default(),
        );
        assert!(
            text.contains("192.168.1.24:54321"),
            "the banner did not print the address a phone has to be given: {text}"
        );
        assert!(text.contains("Server 192.168.1.24, port 54321."));
        assert!(text.contains("http://127.0.0.1:8080"), "no inspector URL");
        assert!(text.contains("AB:CD:EF"), "no certificate fingerprint");
        assert!(text.contains("/home/me/.proxima/ca/proxima-ca.crt"));
    }

    #[test]
    fn the_banner_keeps_the_ios_trust_step() {
        let text = banner(
            &status(&["192.168.1.24"]),
            Path::new("/tmp/proxima-ca.crt"),
            &Config::default(),
        );
        assert!(
            text.contains("Certificate Trust Settings"),
            "the step everybody misses is not in the banner: {text}"
        );
    }

    #[test]
    fn an_ipv6_address_is_bracketed_for_the_proxy_line() {
        let text = banner(
            &status(&["fd00::1"]),
            Path::new("/tmp/proxima-ca.crt"),
            &Config::default(),
        );
        assert!(text.contains("[fd00::1]:54321"), "unbracketed IPv6: {text}");
    }

    #[test]
    fn a_machine_with_no_lan_address_is_told_so() {
        let text = banner(
            &status(&["127.0.0.1"]),
            Path::new("/tmp/proxima-ca.crt"),
            &Config::default(),
        );
        assert!(
            text.contains("No LAN address was found"),
            "loopback only was reported as if a phone could use it: {text}"
        );
    }

    #[test]
    fn the_banner_says_what_is_not_being_decrypted() {
        let config = config_from(&cli(&["--skip", "*.bank.com", "--insecure"]));
        let text = banner(&status(&["192.168.1.24"]), Path::new("/tmp/ca.crt"), &config);
        assert!(text.contains("Not decrypting *.bank.com."));
        assert!(text.contains("Not verifying origin certificates."));

        let quiet = banner(
            &status(&["192.168.1.24"]),
            Path::new("/tmp/ca.crt"),
            &Config::default(),
        );
        assert!(
            !quiet.contains("Not decrypting"),
            "a default run should say nothing about exclusions: {quiet}"
        );
    }

    #[test]
    fn other_addresses_are_offered_as_alternates() {
        let text = banner(
            &status(&["192.168.1.24", "10.0.0.4"]),
            Path::new("/tmp/ca.crt"),
            &Config::default(),
        );
        assert!(text.contains("Also reachable at 10.0.0.4."));
    }
}
