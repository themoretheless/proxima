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
use proxima::config::{
    default_archive_path, default_data_dir, Config, DecryptMode, DecryptRules, DialTarget,
    HeaderEdit, RewriteRule, RewriteRules, UpstreamHttp2,
};
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

    /// record finished flows to <data-dir>/capture.duckdb for later querying
    #[arg(long)]
    archive: bool,

    /// record finished flows to this file instead of the default one
    #[arg(long, value_name = "path")]
    archive_path: Option<PathBuf>,

    /// set a request header on everything (repeatable), e.g. "authorization: Bearer x"
    #[arg(long, value_name = "name: value")]
    set_header: Vec<String>,

    /// remove a request header from everything (repeatable)
    #[arg(long, value_name = "name")]
    remove_header: Vec<String>,

    /// set a response header on everything (repeatable)
    #[arg(long, value_name = "name: value")]
    set_response_header: Vec<String>,

    /// remove a response header from everything (repeatable)
    #[arg(long, value_name = "name")]
    remove_response_header: Vec<String>,

    /// send requests for one host somewhere else (repeatable), e.g.
    /// "api.example.com=127.0.0.1:3000"
    #[arg(long, value_name = "host=target")]
    map_host: Vec<String>,

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
    let config = config_from(&cli).map_err(|message| anyhow::anyhow!(message))?;
    let mut servers = Servers::start(config).await?;
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
        // RUST_LOG is what a Rust user types by reflex, so it keeps working as a
        // second name for the same knob.
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

/* ------------------------------------------------------------------ */
/* rewrite rules                                                       */
/* ------------------------------------------------------------------ */

/// Turns the rewrite flags into rules.
///
/// The header flags apply to every host. That is what they are for: the reason
/// to reach for one is almost always "put my token on everything I am about to
/// send". Scoping a rule to a host, a method or a path is expressible in
/// [`RewriteRule`] and is what the API will offer; the command line stays
/// unambiguous instead of growing a syntax for it.
///
/// Order matters and follows the flags: headers first, then the host mappings,
/// so a later rule overriding an earlier one reads the way the list does.
fn rewrite_from(cli: &Cli) -> std::result::Result<RewriteRules, String> {
    let mut edits = RewriteRule::default();
    for text in &cli.set_header {
        edits.request_headers.push(parse_set("--set-header", text)?);
    }
    for text in &cli.remove_header {
        edits.request_headers.push(parse_remove("--remove-header", text)?);
    }
    for text in &cli.set_response_header {
        edits
            .response_headers
            .push(parse_set("--set-response-header", text)?);
    }
    for text in &cli.remove_response_header {
        edits
            .response_headers
            .push(parse_remove("--remove-response-header", text)?);
    }

    let mut rules = Vec::new();
    if !edits.is_noop() {
        rules.push(edits);
    }
    for text in &cli.map_host {
        rules.push(parse_map_host(text)?);
    }
    Ok(RewriteRules { rules })
}

/// `name: value`, the way the header reads on the wire.
fn parse_set(flag: &str, text: &str) -> std::result::Result<HeaderEdit, String> {
    // Split at the first colon only: values contain them, names cannot.
    let (name, value) = text.split_once(':').ok_or_else(|| {
        format!(
            "{flag} takes \"name: value\", and {text:?} has no colon in it. \
             For example: {flag} \"authorization: Bearer abc123\"."
        )
    })?;
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("{flag} was given a value with no header name: {text:?}"));
    }
    Ok(HeaderEdit::Set {
        name: name.to_string(),
        // Only the space after the colon is punctuation; the rest of the value
        // is the value, trailing spaces included, because a header that is being
        // set deliberately should arrive as it was typed.
        value: value.strip_prefix(' ').unwrap_or(value).to_string(),
    })
}

fn parse_remove(flag: &str, text: &str) -> std::result::Result<HeaderEdit, String> {
    let name = text.trim();
    if name.is_empty() {
        return Err(format!("{flag} needs a header name"));
    }
    if name.contains(':') {
        return Err(format!(
            "{flag} takes a header name on its own, not \"name: value\": {text:?}"
        ));
    }
    Ok(HeaderEdit::Remove {
        name: name.to_string(),
    })
}

/// `host=target`, where the target is `host`, `host:port`, or a bracketed IPv6
/// address with or without a port.
fn parse_map_host(text: &str) -> std::result::Result<RewriteRule, String> {
    let (from, to) = text.split_once('=').ok_or_else(|| {
        format!(
            "--map-host takes \"host=target\", and {text:?} has no = in it. \
             For example: --map-host api.example.com=127.0.0.1:3000."
        )
    })?;
    let from = from.trim();
    if from.is_empty() {
        return Err(format!("--map-host was given no host to match: {text:?}"));
    }
    Ok(RewriteRule {
        hosts: vec![from.to_string()],
        to: Some(parse_target(to.trim())?),
        ..RewriteRule::default()
    })
}

fn parse_target(text: &str) -> std::result::Result<DialTarget, String> {
    if text.is_empty() {
        return Err("--map-host was given nothing to send the traffic to".to_string());
    }

    // A bare IPv6 address is full of colons, so the brackets are what separate
    // the address from a port.
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{text:?} opens a bracket it never closes"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(parse_port(port)?),
            None if tail.is_empty() => None,
            None => return Err(format!("{text:?} has something other than a port after the ]")),
        };
        return Ok(DialTarget {
            host: host.to_string(),
            port,
        });
    }

    match text.rsplit_once(':') {
        // Several colons and no brackets is an unbracketed IPv6 address, which
        // has no port on it.
        Some((head, _)) if head.contains(':') => Ok(DialTarget {
            host: text.to_string(),
            port: None,
        }),
        Some((host, port)) => Ok(DialTarget {
            host: host.to_string(),
            port: Some(parse_port(port)?),
        }),
        None => Ok(DialTarget {
            host: text.to_string(),
            port: None,
        }),
    }
}

fn parse_port(text: &str) -> std::result::Result<u16, String> {
    text.parse::<u16>()
        .map_err(|_| format!("{text:?} is not a port number"))
}

fn config_from(cli: &Cli) -> std::result::Result<Config, String> {
    let allow = host_list(&cli.only);
    let deny = host_list(&cli.skip);
    let mode = if cli.no_decrypt {
        DecryptMode::None
    } else if allow.is_empty() {
        DecryptMode::All
    } else {
        DecryptMode::Allowlist
    };

    let data_dir = cli.data_dir.clone().unwrap_or_else(default_data_dir);
    // Naming a file is asking for an archive, so --archive-path on its own is
    // enough and nobody has to pass both.
    let archive_path = match (&cli.archive_path, cli.archive) {
        (Some(path), _) => Some(path.clone()),
        (None, true) => Some(default_archive_path(&data_dir)),
        (None, false) => None,
    };

    Ok(Config {
        proxy_port: cli.port,
        ui_port: cli.ui_port,
        data_dir,
        max_flows: cli.max_flows,
        archive_path,
        decrypt: DecryptRules { mode, allow, deny },
        rewrite: rewrite_from(cli)?,
        upstream_http2: if cli.no_http2 {
            UpstreamHttp2::Never
        } else {
            UpstreamHttp2::Auto
        },
        insecure_upstream: cli.insecure,
        ..Config::default()
    })
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
    if let Some(path) = &config.archive_path {
        notes.push(format!("Recording finished flows to {}.", path.display()));
    }
    // Traffic being altered on the way through is the one thing here that makes
    // the capture stop describing what the app would have done on its own, so it
    // is never left to be discovered from a config file.
    if !config.rewrite.is_empty() {
        notes.push(format!("Rewriting traffic: {}.", rewrite_summary(config)));
    }

    if notes.is_empty() {
        return String::new();
    }
    let body: String = notes.iter().map(|note| format!("  {note}\n")).collect();
    format!("\n{body}")
}

/// Every change the rules make, named. Header names rather than their values:
/// the values are usually tokens, and a banner is the last place to print one.
fn rewrite_summary(config: &Config) -> String {
    let mut parts: Vec<String> = Vec::new();
    for rule in &config.rewrite.rules {
        if let Some(target) = &rule.to {
            let host = rule.hosts.join(", ");
            let port = match target.port {
                Some(port) => format!(":{port}"),
                None => String::new(),
            };
            parts.push(format!("{host} to {}{port}", target.host));
        }
        for edit in rule.request_headers.iter().chain(&rule.response_headers) {
            let verb = match edit {
                HeaderEdit::Set { .. } => "setting",
                HeaderEdit::Remove { .. } => "removing",
            };
            parts.push(format!("{verb} {}", edit.name()));
        }
    }
    parts.join(", ")
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

    /// The config these flags produce, for the cases where it should build.
    fn config_of(args: &[&str]) -> Config {
        config_from(&cli(args)).expect("these flags should build a config")
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
            archiving: false,
            archive_dropped: 0,
        }
    }

    #[test]
    fn only_switches_decryption_to_an_allowlist() {
        let config = config_of(&["--only", "api.example.com, *.foo.com"]);
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
            config_of(&["--no-decrypt"]).decrypt.mode,
            DecryptMode::None
        );
    }

    #[test]
    fn skip_fills_the_deny_list_and_leaves_the_mode_alone() {
        let config = config_of(&["--skip", "*.bank.com,"]);
        assert_eq!(config.decrypt.mode, DecryptMode::All);
        assert_eq!(
            config.decrypt.deny,
            vec!["*.bank.com"],
            "a trailing comma left an empty pattern, which silently matches nothing"
        );
    }

    #[test]
    fn the_remaining_flags_reach_the_config() {
        let config = config_of(&[
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
        ]);
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
    fn the_archive_is_off_unless_it_is_asked_for() {
        assert_eq!(config_of(&[]).archive_path, None);

        let default_place = config_of(&["--archive", "--data-dir", "/tmp/pd"]);
        assert_eq!(
            default_place.archive_path,
            Some(PathBuf::from("/tmp/pd/capture.duckdb")),
            "the bare flag has to land under the data directory it was given"
        );

        let named = config_of(&["--archive-path", "/tmp/one.duckdb"]);
        assert_eq!(
            named.archive_path,
            Some(PathBuf::from("/tmp/one.duckdb")),
            "naming a file is asking for an archive, so --archive should not also be needed"
        );
    }

    /// The single rule the header flags collapse into, for the tests that only
    /// care what ended up in it.
    fn header_rule(args: &[&str]) -> RewriteRule {
        config_of(args)
            .rewrite
            .rules
            .first()
            .cloned()
            .expect("the header flags should have produced a rule")
    }

    #[test]
    fn header_flags_become_one_rule_that_matches_everything() {
        let rule = header_rule(&[
            "--set-header",
            "authorization: Bearer abc123",
            "--remove-header",
            "cookie",
            "--set-response-header",
            "access-control-allow-origin: *",
            "--remove-response-header",
            "set-cookie",
        ]);

        assert!(
            rule.hosts.is_empty() && rule.methods.is_empty() && rule.path_prefix.is_none(),
            "the header flags are meant to apply to everything"
        );
        assert_eq!(
            rule.request_headers,
            vec![
                HeaderEdit::Set {
                    name: "authorization".into(),
                    value: "Bearer abc123".into(),
                },
                HeaderEdit::Remove {
                    name: "cookie".into()
                },
            ]
        );
        assert_eq!(
            rule.response_headers,
            vec![
                HeaderEdit::Set {
                    name: "access-control-allow-origin".into(),
                    value: "*".into(),
                },
                HeaderEdit::Remove {
                    name: "set-cookie".into()
                },
            ]
        );
    }

    #[test]
    fn only_the_space_after_the_colon_is_punctuation() {
        // A value with colons in it, which is what a header full of URLs or a
        // timestamp looks like, must survive whole.
        let rule = header_rule(&["--set-header", "x-target: https://api.example.com:8443/v1"]);
        assert_eq!(
            rule.request_headers[0],
            HeaderEdit::Set {
                name: "x-target".into(),
                value: "https://api.example.com:8443/v1".into(),
            },
            "the value was split on a colon that belonged to it"
        );

        // No space after the colon is just as legal.
        let tight = header_rule(&["--set-header", "x-a:b"]);
        assert_eq!(
            tight.request_headers[0],
            HeaderEdit::Set {
                name: "x-a".into(),
                value: "b".into()
            }
        );
    }

    #[test]
    fn no_rewrite_flags_means_no_rules_at_all() {
        assert!(
            config_of(&[]).rewrite.is_empty(),
            "a default run must not carry a rule that changes nothing"
        );
    }

    #[test]
    fn map_host_scopes_its_rule_to_the_host_it_names() {
        let config = config_of(&["--map-host", "api.example.com=127.0.0.1:3000"]);
        let rule = &config.rewrite.rules[0];
        assert_eq!(rule.hosts, vec!["api.example.com"]);
        assert_eq!(
            rule.to,
            Some(DialTarget {
                host: "127.0.0.1".into(),
                port: Some(3000),
            })
        );

        // No port keeps whatever port the request was already going to.
        let no_port = config_of(&["--map-host", "api.example.com=staging.internal"]);
        assert_eq!(
            no_port.rewrite.rules[0].to,
            Some(DialTarget {
                host: "staging.internal".into(),
                port: None,
            })
        );
    }

    #[test]
    fn an_ipv6_target_is_read_by_its_brackets() {
        let bracketed = config_of(&["--map-host", "api.example.com=[::1]:3000"]);
        assert_eq!(
            bracketed.rewrite.rules[0].to,
            Some(DialTarget {
                host: "::1".into(),
                port: Some(3000),
            })
        );

        // Unbracketed, the colons are all address and there is no port.
        let bare = config_of(&["--map-host", "api.example.com=fd00::1"]);
        assert_eq!(
            bare.rewrite.rules[0].to,
            Some(DialTarget {
                host: "fd00::1".into(),
                port: None,
            })
        );
    }

    #[test]
    fn a_malformed_rewrite_flag_says_what_it_wanted() {
        let err = config_from(&cli(&["--set-header", "authorization"]))
            .expect_err("a header with no colon cannot be a header");
        assert!(err.contains("--set-header") && err.contains("name: value"), "{err}");

        let err = config_from(&cli(&["--remove-header", "authorization: Bearer x"]))
            .expect_err("removing takes a name, not a pair");
        assert!(err.contains("not \"name: value\""), "{err}");

        let err = config_from(&cli(&["--map-host", "api.example.com"]))
            .expect_err("a mapping with no target is not a mapping");
        assert!(err.contains("host=target"), "{err}");

        let err = config_from(&cli(&["--map-host", "api.example.com=127.0.0.1:notaport"]))
            .expect_err("that is not a port");
        assert!(err.contains("not a port"), "{err}");
    }

    #[test]
    fn the_banner_says_what_is_being_rewritten() {
        let config = config_of(&[
            "--set-header",
            "authorization: Bearer x",
            "--map-host",
            "api.example.com=127.0.0.1:3000",
        ]);
        let text = banner(&status(&["192.168.1.24"]), Path::new("/tmp/ca.crt"), &config);
        assert!(
            text.contains("Rewriting"),
            "traffic is being altered and the banner does not say so: {text}"
        );
        assert!(text.contains("api.example.com"), "{text}");
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
        let config = config_of(&["--skip", "*.bank.com", "--insecure"]);
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
