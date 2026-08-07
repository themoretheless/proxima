//! UDP bind helpers for QUIC endpoints.
//!
//! Quinn needs a datagram socket before an endpoint can accept or dial. This
//! module is the only place that creates that socket for the reverse and
//! accept paths.
//!
//! ## Dual-stack
//!
//! IPv4 and IPv6 bind addresses both work. When the listen address is IPv6,
//! the socket is configured for dual-stack (`IPV6_V6ONLY = 0`) when the OS
//! allows it, so IPv4-mapped clients can reach the same UDP port. On platforms
//! that refuse dual-stack, the bind still succeeds as IPv6-only.
//!
//! ## Reuse
//!
//! `SO_REUSEPORT` is never set: multi-worker fan-out is out of scope for this
//! tool. `SO_REUSEADDR` is also left off so two Proxima processes cannot
//! silently share a unicast QUIC port and split packets. Error messages reuse
//! the same tone as the TCP listener bind advice in `runtime` (name the
//! address, suggest `--quic-port`).
//!
//! ## macOS notes
//!
//! These apply when building and running Proxima on Darwin (the primary
//! developer host for this project). They do not change the bind API; they
//! explain platform behaviour operators hit first.
//!
//! - **Dual-stack on `::`**: setting `IPV6_V6ONLY = 0` is supported on modern
//!   macOS. A successful dual-stack bind means the same UDP port is taken for
//!   IPv4-mapped clients as well; a second bind to `0.0.0.0:port` then fails
//!   with address-in-use (same as Linux). If the option is refused, the
//!   socket stays IPv6-only and IPv4 needs a separate `--quic-host` bind.
//! - **Privileged ports**: ports below 1024 need root (`sudo`). There is no
//!   Linux-style `CAP_NET_BIND_SERVICE` shortcut. Prefer `--quic-port 9443`
//!   (or another high port) for reverse and accept-only listeners.
//! - **Application Firewall**: System Settings → Network → Firewall can block
//!   inbound UDP for an unsigned or freshly built binary. Loopback reverse
//!   tests (`127.0.0.1`) usually work without a prompt; clients on other hosts
//!   that hang while `lsof -iUDP` shows Proxima listening often need an
//!   allow rule for the binary, or the firewall turned off while debugging.
//! - **Local Network privacy (recent macOS)**: when this process *dials*
//!   another host on the LAN over UDP (reverse upstream to a local H3
//!   origin), the OS may show a Local Network permission prompt. Denying it
//!   looks like an upstream connect failure, not a bind failure. Binding the
//!   listener itself does not require that prompt.
//! - **No transparent UDP redirect here**: macOS has no Linux `TPROXY` path.
//!   Getting arbitrary host/app QUIC into Proxima on Darwin needs a future
//!   utun / Network Extension / WireGuard-style ingress (see PLANS.md), not
//!   this reverse bind. Reverse H3 is still real MITM once the client points
//!   at Proxima's UDP port.
//! - **Send path**: Linux UDP GSO / offload knobs are not used. Quinn falls
//!   back to ordinary `sendmsg` on macOS; that is enough for debugging and
//!   localhost reverse e2e. We do not raise `SO_RCVBUF` / `SO_SNDBUF` beyond
//!   OS defaults in this module.
//! - **SO_REUSEPORT semantics**: Darwin implements the option, but with
//!   different multi-socket fan-out rules than Linux. Proxima never sets it,
//!   so only one process owns a given unicast QUIC port.
//!
//! ## Errors and tracing
//!
//! Bind failures are classified ([`BindFailureKind`]) and turned into advice
//! that names the address and the flag that moves it. Every failure is also
//! emitted at `error` level with structured fields (`addr`, `kind`,
//! `os_error`) so operators can see the clash in logs before the process
//! exits. Success is logged at `debug` (runtime / serve log the listen line
//! at `info`).
//!
//! Callers that pass port 0 must read [`UdpSocket::local_addr`] for the
//! OS-assigned port (same contract as the TCP proxy listener).

use std::io;
use std::net::SocketAddr;

use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{debug, error};

/// Why a QUIC UDP bind failed, for logs and tests.
///
/// Maps the OS `ErrorKind` to the advice bucket. Unknown kinds stay under
/// [`Other`] so we never invent a root cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindFailureKind {
    /// Port already taken (`EADDRINUSE`).
    AddrInUse,
    /// Privilege / capability denied (`EACCES` / `EPERM`), often ports < 1024.
    PermissionDenied,
    /// Address not available on this host (`EADDRNOTAVAIL`).
    AddrNotAvailable,
    /// Obviously bad address / port for the socket API.
    InvalidInput,
    /// Anything else (including socket creation failures).
    Other,
}

impl BindFailureKind {
    /// Stable short token for structured logs (`addr_in_use`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddrInUse => "addr_in_use",
            Self::PermissionDenied => "permission_denied",
            Self::AddrNotAvailable => "addr_not_available",
            Self::InvalidInput => "invalid_input",
            Self::Other => "other",
        }
    }

    /// Classifies an I/O error from socket creation or `bind`.
    pub fn from_io(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::AddrInUse => Self::AddrInUse,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
            io::ErrorKind::InvalidInput => Self::InvalidInput,
            // Some platforms report bind-to-missing-iface as Other with a
            // specific errno; keep Other and still name the address in text.
            _ => Self::Other,
        }
    }
}

/// Binds a UDP socket suitable for a quinn endpoint on `addr`.
///
/// On success the socket is non-blocking and ready for
/// [`quinn::Endpoint::new`]. Port 0 is resolved by the OS; use
/// [`UdpSocket::local_addr`] (or [`bound_addr`]) for the real port.
///
/// On failure returns a user-facing [`anyhow::Error`] and emits a structured
/// `error` log (see module docs).
pub async fn bind_udp(addr: SocketAddr) -> Result<UdpSocket> {
    // socket2 bind is synchronous and cheap (one syscall); keep it off the
    // async runtime's poll path via spawn_blocking only if it ever grew cost.
    // Today it is fine inline: same as most tokio examples.
    match bind_udp_sync(addr) {
        Ok(std_sock) => {
            let sock = UdpSocket::from_std(std_sock).with_context(|| {
                format!("wrapping QUIC UDP as tokio socket after bind on {addr}")
            })?;
            match sock.local_addr() {
                Ok(local) => {
                    debug!(%addr, %local, "QUIC UDP socket bound");
                }
                Err(err) => {
                    // Socket is usable for quinn even if local_addr is flaky;
                    // callers that need the port will fail via bound_addr.
                    debug!(%addr, error = %err, "QUIC UDP bound; local_addr not readable yet");
                }
            }
            Ok(sock)
        }
        Err(err) => Err(map_bind_error(addr, err)),
    }
}

/// Classifies `err`, logs it, and builds the advice string for the operator.
///
/// Public so unit tests and call sites that already hold an `io::Error` can
/// reuse the same wording without binding again.
pub fn map_bind_error(addr: SocketAddr, err: io::Error) -> anyhow::Error {
    let kind = BindFailureKind::from_io(&err);
    let os_error = err.raw_os_error();
    error!(
        %addr,
        failure = kind.as_str(),
        ?kind,
        os_error,
        error = %err,
        "QUIC UDP bind failed"
    );
    anyhow!(bind_error_message(addr, kind, &err))
}

/// User-facing message for a classified bind failure (no tracing).
///
/// Separated from [`map_bind_error`] so tests can assert wording without
/// depending on a real OS failure.
pub fn bind_error_message(addr: SocketAddr, kind: BindFailureKind, err: &io::Error) -> String {
    match kind {
        BindFailureKind::AddrInUse => format!(
            "UDP port {} is already in use, so the QUIC listener could not bind {}. \
             Another Proxima or process is the usual reason. Stop it, or pick a free \
             port with --quic-port <n>.",
            addr.port(),
            addr
        ),
        BindFailureKind::PermissionDenied => format!(
            "binding QUIC UDP on {} was refused. Ports below 1024 need elevated \
             privileges; pick a higher port with --quic-port <n>.",
            addr
        ),
        BindFailureKind::AddrNotAvailable => format!(
            "QUIC UDP could not bind {}: that address is not available on this host \
             (wrong interface, or IPv6 disabled). Use 0.0.0.0 / 127.0.0.1 / :: or a \
             local interface IP, and --quic-port <n> for the port.",
            addr
        ),
        BindFailureKind::InvalidInput => format!(
            "QUIC UDP bind address {} is not valid for a datagram socket. Check \
             --quic-host and --quic-port.",
            addr
        ),
        BindFailureKind::Other => format!(
            "binding QUIC UDP socket on {addr} failed: {err}. \
             If the port is taken, pick another with --quic-port <n>."
        ),
    }
}

/// Synchronous dual-stack-aware bind used by [`bind_udp`].
fn bind_udp_sync(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
        // Creation failed before bind; keep the raw Error so map_bind_error
        // still classifies and logs with the requested address.
        io::Error::new(
            err.kind(),
            format!("creating QUIC UDP socket for {addr}: {err}"),
        )
    })?;

    // Prefer dual-stack on IPv6 so a single reverse listener on `::` can take
    // IPv4-mapped traffic. Failure is non-fatal: some OS builds are IPv6-only
    // by policy.
    if addr.is_ipv6() {
        if let Err(err) = socket.set_only_v6(false) {
            debug!(
                error = %err,
                %addr,
                "IPV6_V6ONLY=0 not applied; QUIC bind is IPv6-only"
            );
        }
    }

    socket.bind(&addr.into()).map_err(|err| {
        // Preserve kind/os_error; the outer map_bind_error adds the address.
        err
    })?;
    socket.set_nonblocking(true).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("setting QUIC UDP nonblocking on {addr}: {err}"),
        )
    })?;
    Ok(socket.into())
}

/// Reads the OS-assigned local address after bind (port-0 friendly).
pub fn bound_addr(sock: &UdpSocket) -> Result<SocketAddr> {
    sock.local_addr()
        .context("reading QUIC UDP local_addr after bind")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn binds_ephemeral_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = bind_udp(addr).await.expect("bind");
        let local = bound_addr(&sock).expect("local");
        assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(local.port(), 0, "port 0 must be rewritten by the OS");
    }

    #[tokio::test]
    async fn binds_ipv6_localhost_when_available() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let sock = match bind_udp(addr).await {
            Ok(s) => s,
            Err(err) => {
                // Some CI images ship without IPv6 loopback.
                eprintln!("skipping IPv6 localhost bind: {err:#}");
                return;
            }
        };
        let local = bound_addr(&sock).expect("local");
        assert!(local.is_ipv6());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn addr_in_use_names_address_and_flag() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let first = bind_udp(addr).await.expect("first bind");
        let taken = bound_addr(&first).expect("local");
        // Re-bind the exact assigned address; must fail without SO_REUSEADDR.
        let err = bind_udp(taken).await.expect_err("second bind should fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already in use") || msg.contains("could not bind"),
            "expected AddrInUse advice, got: {msg}"
        );
        assert!(
            msg.contains(&taken.port().to_string()),
            "error should name the port: {msg}"
        );
        assert!(
            msg.contains("--quic-port"),
            "error should suggest --quic-port: {msg}"
        );
        assert!(
            msg.contains(&taken.to_string()) || msg.contains("127.0.0.1"),
            "error should name the listen address: {msg}"
        );
        // Keep first alive until assertions finish.
        drop(first);
    }

    #[tokio::test]
    async fn dual_stack_unspecified_prefers_shared_v4_port() {
        // Bind dual-stack on `::` (unspecified). When dual-stack works, the
        // same UDP port is occupied for IPv4 as well, so a plain IPv4 bind to
        // 0.0.0.0:port fails with AddrInUse. When the OS forces IPv6-only,
        // the IPv4 bind succeeds and we treat that as an acceptable platform
        // limit rather than a test failure.
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let sock = match bind_udp(addr).await {
            Ok(s) => s,
            Err(err) => {
                eprintln!("skipping dual-stack test (no IPv6 bind): {err:#}");
                return;
            }
        };
        let port = bound_addr(&sock).expect("local").port();
        assert_ne!(port, 0);

        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        match std::net::UdpSocket::bind(v4) {
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                // Dual-stack is active: IPv4 port is claimed by the IPv6 socket.
            }
            Ok(_v4_sock) => {
                eprintln!(
                    "platform kept IPv6-only for :: (IPv4 bind on port {port} succeeded); \
                     dual-stack not enforced"
                );
            }
            Err(err) => {
                eprintln!("unexpected IPv4 bind result while holding dual-stack socket: {err}");
            }
        }
        drop(sock);
    }

    #[tokio::test]
    async fn ipv4_unspecified_ephemeral() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let sock = bind_udp(addr).await.expect("bind 0.0.0.0:0");
        let local = bound_addr(&sock).expect("local");
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn bound_addr_matches_socket_local_addr() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sock = bind_udp(addr).await.expect("bind");
        let via_helper = bound_addr(&sock).expect("bound_addr");
        let via_socket = sock.local_addr().expect("local_addr");
        assert_eq!(via_helper, via_socket);
        assert_ne!(via_helper.port(), 0);
    }

    #[tokio::test]
    async fn two_ephemeral_binds_get_distinct_ports() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let a = bind_udp(addr).await.expect("bind a");
        let b = bind_udp(addr).await.expect("bind b");
        let pa = bound_addr(&a).expect("a").port();
        let pb = bound_addr(&b).expect("b").port();
        assert_ne!(pa, 0);
        assert_ne!(pb, 0);
        assert_ne!(pa, pb, "two port-0 binds must not share a port");
    }

    #[test]
    fn classifies_error_kinds() {
        assert_eq!(
            BindFailureKind::from_io(&io::Error::new(io::ErrorKind::AddrInUse, "x")),
            BindFailureKind::AddrInUse
        );
        assert_eq!(
            BindFailureKind::from_io(&io::Error::new(io::ErrorKind::PermissionDenied, "x")),
            BindFailureKind::PermissionDenied
        );
        assert_eq!(
            BindFailureKind::from_io(&io::Error::new(io::ErrorKind::AddrNotAvailable, "x")),
            BindFailureKind::AddrNotAvailable
        );
        assert_eq!(
            BindFailureKind::from_io(&io::Error::new(io::ErrorKind::InvalidInput, "x")),
            BindFailureKind::InvalidInput
        );
        assert_eq!(
            BindFailureKind::from_io(&io::Error::new(io::ErrorKind::Other, "x")),
            BindFailureKind::Other
        );
    }

    #[test]
    fn advice_messages_name_addr_and_flag() {
        let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let err = io::Error::new(io::ErrorKind::AddrInUse, "simulated");

        let in_use = bind_error_message(addr, BindFailureKind::AddrInUse, &err);
        assert!(in_use.contains("9443"), "{in_use}");
        assert!(in_use.contains("127.0.0.1:9443"), "{in_use}");
        assert!(in_use.contains("--quic-port"), "{in_use}");
        assert!(in_use.contains("already in use"), "{in_use}");

        let denied = bind_error_message(addr, BindFailureKind::PermissionDenied, &err);
        assert!(denied.contains("127.0.0.1:9443"), "{denied}");
        assert!(denied.contains("--quic-port"), "{denied}");
        assert!(
            denied.contains("refused") || denied.contains("privileges"),
            "{denied}"
        );

        let not_avail = bind_error_message(addr, BindFailureKind::AddrNotAvailable, &err);
        assert!(not_avail.contains("127.0.0.1:9443"), "{not_avail}");
        assert!(not_avail.contains("not available"), "{not_avail}");
        assert!(not_avail.contains("--quic-port"), "{not_avail}");

        let invalid = bind_error_message(addr, BindFailureKind::InvalidInput, &err);
        assert!(invalid.contains("127.0.0.1:9443"), "{invalid}");
        assert!(
            invalid.contains("--quic-host") || invalid.contains("--quic-port"),
            "{invalid}"
        );

        let other = bind_error_message(addr, BindFailureKind::Other, &err);
        assert!(other.contains("127.0.0.1:9443"), "{other}");
        assert!(other.contains("simulated") || other.contains("failed"), "{other}");
        assert!(other.contains("--quic-port"), "{other}");
    }

    #[test]
    fn map_bind_error_preserves_addr_in_use_advice() {
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let err = io::Error::new(io::ErrorKind::AddrInUse, "os says busy");
        let mapped = map_bind_error(addr, err);
        let msg = format!("{mapped:#}");
        assert!(msg.contains("already in use"), "{msg}");
        assert!(msg.contains("443"), "{msg}");
        assert!(msg.contains("10.0.0.1:443"), "{msg}");
        assert!(msg.contains("--quic-port"), "{msg}");
    }

    #[test]
    fn map_bind_error_permission_denied_advice() {
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "EACCES");
        let mapped = map_bind_error(addr, err);
        let msg = format!("{mapped:#}");
        assert!(msg.contains("0.0.0.0:443"), "{msg}");
        assert!(msg.contains("--quic-port"), "{msg}");
        assert!(
            msg.contains("refused") || msg.contains("privileges"),
            "{msg}"
        );
    }

    #[test]
    fn bind_failure_kind_tokens_are_stable() {
        assert_eq!(BindFailureKind::AddrInUse.as_str(), "addr_in_use");
        assert_eq!(
            BindFailureKind::PermissionDenied.as_str(),
            "permission_denied"
        );
        assert_eq!(
            BindFailureKind::AddrNotAvailable.as_str(),
            "addr_not_available"
        );
        assert_eq!(BindFailureKind::InvalidInput.as_str(), "invalid_input");
        assert_eq!(BindFailureKind::Other.as_str(), "other");
    }
}
