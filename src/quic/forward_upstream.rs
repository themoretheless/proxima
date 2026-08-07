//! Dial origin over QUIC and open an HTTP/3 client session.
//!
//! Reverse H3 MITM terminates the client leg with CA-minted leaves, then uses
//! this module for the **upstream** leg. The regular TCP CONNECT proxy never
//! dials through here and cannot see device QUIC (UDP).
//!
//! ## Policy
//!
//! - **1-RTT only (security)**: never call [`quinn::Connecting::into_0rtt`].
//!   Early data is disabled in [`super::client_crypto`]
//!   ([`super::MITM_ENABLE_EARLY_DATA`] = false). MITM cannot safely forward
//!   client 0-RTT (different tickets/session on each leg, replay risk, incomplete
//!   capture). If you add a dial path, await the full handshake only.
//! - ALPN is whatever was installed on the endpoint's default client config
//!   (Proxima sets `h3` only).
//! - Host / `:authority` rewrite for reverse is the caller's job; this module
//!   only resolves and dials the configured upstream authority.
//! - Failures are plain `anyhow` errors so reverse (or a future error classifier)
//!   can map them onto `quic_upstream` / `quic_alpn` / `h3` flow codes without
//!   inventing a successful response.
//! - DNS resolve returns every address; dial prefers addresses that match the
//!   local endpoint socket family and retries remaining peers on failure.

use std::net::SocketAddr;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use quinn::{Connection, Endpoint};
use tracing::{debug, warn};

use super::codes;

/// Parsed origin authority (`host` or `host:port`, default port 443).
///
/// IPv6 literals without brackets are treated as a bare host (default port),
/// matching the conservative split used by reverse CLI parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAuthority {
    pub host: String,
    pub port: u16,
}

impl UpstreamAuthority {
    /// Parses `host`, `host:port`, or returns host + default port 443.
    pub fn parse(spec: &str) -> Self {
        let (host, port) = split_host_port(spec, 443);
        Self { host, port }
    }

    /// SNI / TLS server name (hostname only, no port).
    pub fn sni_name(&self) -> &str {
        &self.host
    }

    /// `host:port` display form (not bracketed for IPv6).
    pub fn display(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Live upstream HTTP/3 client after a successful QUIC 1-RTT handshake.
///
/// The H3 driver task is spawned internally so the connection stays alive while
/// [`Self::send_request`] is used. Dropping all `SendRequest` clones and the
/// underlying quinn connection ends the session.
pub struct UpstreamH3 {
    pub authority: UpstreamAuthority,
    /// Resolved UDP peer used for this dial.
    pub addr: SocketAddr,
    /// Quinn handle (cloneable) for optional origin TLS facts later.
    pub connection: Connection,
    /// Open new request streams toward the origin.
    pub send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

impl UpstreamH3 {
    /// Client-leg style ALPN on the origin connection, when the handshake
    /// reported one (expected: `h3`).
    pub fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.connection
            .handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.protocol)
    }
}

/// Resolves `authority` via DNS. Returns the first address (compat helper).
///
/// Prefer [`resolve_all`] + [`order_addrs_for_local`] when dialing from a bound
/// server endpoint so IPv4-only binds do not pick AAAA-only peers first.
pub async fn resolve(authority: &UpstreamAuthority) -> Result<SocketAddr> {
    let addrs = resolve_all(authority).await?;
    addrs.into_iter().next().ok_or_else(|| {
        anyhow!(
            "no addresses for upstream {}",
            authority.display()
        )
    })
}

/// Resolves every A/AAAA for the upstream host (order is OS-dependent).
pub async fn resolve_all(authority: &UpstreamAuthority) -> Result<Vec<SocketAddr>> {
    let addrs = tokio::net::lookup_host((authority.host.as_str(), authority.port))
        .await
        .with_context(|| format!("resolving upstream {}", authority.display()))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(anyhow!(
            "no addresses for upstream {}",
            authority.display()
        ));
    }
    Ok(addrs)
}

/// Reorders (and may filter) resolved peers to match the local bind family.
///
/// - **IPv4-only local** (`0.0.0.0` / `127.0.0.1`): only IPv4 peers. An IPv4
///   quinn endpoint cannot dial raw IPv6; calling this avoids AAAA-first hangs.
/// - **IPv6 local** (`::` dual-stack or `::1`): IPv6 first, then IPv4 (mapped
///   peers when the OS dual-stack socket allows them).
///
/// When filtering would drop every address, the original list is returned so
/// the dial path still fails with a real connect error rather than inventing
/// "no addresses".
pub fn order_addrs_for_local(addrs: Vec<SocketAddr>, local: Option<SocketAddr>) -> Vec<SocketAddr> {
    let Some(local) = local else {
        return addrs;
    };
    match local {
        SocketAddr::V4(_) => {
            let v4: Vec<_> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
            if v4.is_empty() {
                // Honest path: keep AAAA so dial fails with connect error rather
                // than a synthetic empty list (operator sees the family mismatch).
                addrs
            } else {
                v4
            }
        }
        SocketAddr::V6(_) => {
            let mut v6 = Vec::new();
            let mut v4 = Vec::new();
            for a in addrs {
                if a.is_ipv6() {
                    v6.push(a);
                } else {
                    v4.push(a);
                }
            }
            v6.extend(v4);
            v6
        }
    }
}

/// Convenience: parse `spec`, resolve, dial QUIC, open H3.
///
/// `endpoint` must already have a default client config (see
/// [`super::client_crypto`] and [`super::QuicEndpoint::set_default_client_config`]).
///
/// Tries every resolved address (family-ordered against `endpoint.local_addr()`)
/// until one handshake + H3 session succeeds.
pub async fn dial_upstream_h3(endpoint: &Endpoint, upstream_spec: &str) -> Result<UpstreamH3> {
    let authority = UpstreamAuthority::parse(upstream_spec);
    let local = endpoint.local_addr().ok();
    let addrs = order_addrs_for_local(resolve_all(&authority).await?, local);
    let mut last_err: Option<anyhow::Error> = None;
    for addr in &addrs {
        match dial_h3(endpoint, &authority, *addr).await {
            Ok(up) => return Ok(up),
            Err(err) => {
                warn!(
                    sni = %authority.sni_name(),
                    %addr,
                    error = %err,
                    "upstream QUIC dial/handshake failed; trying next address if any"
                );
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        anyhow!(
            "no usable addresses for upstream {}",
            authority.display()
        )
    }))
    .with_context(|| format!("dial upstream H3 {}", authority.display()))
}

/// Dials QUIC at `addr` with SNI from `authority`, then opens an H3 client.
///
/// **Security: 1-RTT only.** Does not call `into_0rtt` and does not rely on
/// client early data (disabled in [`super::client_crypto`]). Does not fall
/// back to TCP/H2 (callers that want that must do so explicitly and record
/// origin transport honestly).
pub async fn dial_h3(
    endpoint: &Endpoint,
    authority: &UpstreamAuthority,
    addr: SocketAddr,
) -> Result<UpstreamH3> {
    let sni = authority.sni_name();
    let connecting = endpoint
        .connect(addr, sni)
        .with_context(|| format!("dial upstream QUIC {sni} at {addr}"))?;

    // Security: 1-RTT only. Never into_0rtt: early data is off for MITM
    // (replay + asymmetric tickets; see quic::tls module docs).
    let connection = connecting
        .await
        .with_context(|| format!("upstream QUIC handshake with {sni} at {addr}"))?;

    let alpn = connection
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol.clone());
    match alpn {
        Some(ref proto) if proto.as_slice() == super::ALPN_H3 => {}
        Some(ref proto) => {
            let got = String::from_utf8_lossy(proto);
            return Err(anyhow!(
                "{}: upstream at {addr} negotiated ALPN {got:?}, expected h3 (SNI {sni})",
                codes::QUIC_ALPN
            ));
        }
        None => {
            return Err(anyhow!(
                "{}: upstream at {addr} reported no ALPN (SNI {sni}); expected h3",
                codes::QUIC_ALPN
            ));
        }
    }

    // Keep a handle for origin facts; h3_quinn takes ownership of a clone.
    let conn_for_h3 = connection.clone();
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(conn_for_h3))
        .await
        .with_context(|| format!("h3 upstream session with {sni} at {addr}"))?;

    let sni_owned = sni.to_string();
    tokio::spawn(async move {
        let err = driver.wait_idle().await;
        debug!(sni = %sni_owned, error = %err, "upstream h3 driver finished");
    });

    Ok(UpstreamH3 {
        authority: authority.clone(),
        addr,
        connection,
        send_request,
    })
}

/* ------------------------------------------------------------------ */
/* Parsing helpers (shared with reverse config)                        */
/* ------------------------------------------------------------------ */

/// Split `host`, `host:port`, or `[ipv6]:port` into host and port.
///
/// Bare IPv6 without brackets keeps the whole string as host and uses
/// `default_port` (colon count is ambiguous). Bracketed form is preferred.
pub fn split_host_port(spec: &str, default_port: u16) -> (String, u16) {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            if let Some(port_str) = after.strip_prefix(':') {
                if let Ok(port) = port_str.parse() {
                    return (host.to_string(), port);
                }
            }
            return (host.to_string(), default_port);
        }
    }
    if let Some((h, p)) = spec.rsplit_once(':') {
        // Reject bare IPv6 without brackets (ambiguous colons).
        if !h.is_empty() && !h.contains(':') {
            if let Ok(port) = p.parse() {
                return (h.to_string(), port);
            }
        }
    }
    (spec.to_string(), default_port)
}

/// Hostname only (strip `:port` when present; unwraps `[ipv6]` brackets).
pub fn host_only(spec: &str) -> String {
    split_host_port(spec, 443).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Once;

    use quinn::Endpoint;

    use crate::ca::CertAuthority;

    use super::super::endpoint::QuicEndpoint;
    use super::super::tls::{client_crypto, server_crypto_fixed, ALPN_H3};
    use super::super::udp::bind_udp;

    static CRYPTO: Once = Once::new();

    fn install_crypto() {
        CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn parse_host_default_port() {
        let a = UpstreamAuthority::parse("origin.example");
        assert_eq!(a.host, "origin.example");
        assert_eq!(a.port, 443);
        assert_eq!(a.sni_name(), "origin.example");
        assert_eq!(a.display(), "origin.example:443");
    }

    #[test]
    fn parse_host_with_port() {
        let a = UpstreamAuthority::parse("origin.example:8443");
        assert_eq!(a.host, "origin.example");
        assert_eq!(a.port, 8443);
    }

    #[test]
    fn split_does_not_mangle_ipv6_like_host() {
        // Bare IPv6 without brackets: keep whole string, default port.
        let (h, p) = split_host_port("::1", 443);
        assert_eq!(h, "::1");
        assert_eq!(p, 443);
        assert_eq!(host_only("example.com:9443"), "example.com");
    }

    #[test]
    fn split_bracketed_ipv6() {
        assert_eq!(
            split_host_port("[2001:db8::1]:9443", 443),
            ("2001:db8::1".into(), 9443)
        );
        assert_eq!(split_host_port("[::1]", 443), ("::1".into(), 443));
        let a = UpstreamAuthority::parse("[::1]:8443");
        assert_eq!(a.host, "::1");
        assert_eq!(a.port, 8443);
        assert_eq!(a.sni_name(), "::1");
    }

    #[test]
    fn split_trims_whitespace() {
        let a = UpstreamAuthority::parse("  host.example:443  ");
        assert_eq!(a.host, "host.example");
        assert_eq!(a.port, 443);
    }

    #[test]
    fn host_only_strips_port() {
        assert_eq!(host_only("example.com:9443"), "example.com");
        assert_eq!(host_only("example.com"), "example.com");
        assert_eq!(host_only("[::1]:443"), "::1");
    }

    #[test]
    fn order_addrs_ipv4_local_keeps_only_v4_when_present() {
        let v4: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let local: SocketAddr = "0.0.0.0:9443".parse().unwrap();
        let ordered = order_addrs_for_local(vec![v6, v4], Some(local));
        assert_eq!(ordered, vec![v4]);
    }

    #[test]
    fn order_addrs_ipv4_local_keeps_aaaa_when_no_v4() {
        // Fail honestly at dial rather than inventing empty DNS.
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ordered = order_addrs_for_local(vec![v6], Some(local));
        assert_eq!(ordered, vec![v6]);
    }

    #[test]
    fn order_addrs_ipv6_local_prefers_v6_then_v4() {
        let v4: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let v6: SocketAddr = "[::1]:443".parse().unwrap();
        let local: SocketAddr = "[::]:9443".parse().unwrap();
        let ordered = order_addrs_for_local(vec![v4, v6], Some(local));
        assert_eq!(ordered, vec![v6, v4]);
    }

    #[tokio::test]
    async fn resolve_localhost_returns_loopback() {
        let authority = UpstreamAuthority {
            host: "localhost".into(),
            port: 443,
        };
        let addr = resolve(&authority).await.expect("resolve localhost");
        assert!(addr.ip().is_loopback(), "expected loopback, got {addr}");
        assert_eq!(addr.port(), 443);
    }

    #[tokio::test]
    async fn dial_h3_localhost_roundtrip() {
        install_crypto();
        let dir = std::env::temp_dir().join(format!(
            "proxima-forward-upstream-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = std::sync::Arc::new(CertAuthority::open(&dir).expect("ca"));

        let sock = bind_udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind origin");
        let server_cfg = server_crypto_fixed(ca.clone(), "localhost").expect("server crypto");
        let origin = QuicEndpoint::server_with_config(sock, server_cfg).expect("origin ep");
        let origin_addr = origin.local_addr();

        // Accept one connection and open H3 server (idle until client opens).
        let accept = tokio::spawn(async move {
            let incoming = origin.accept().await.expect("accept");
            let conn = incoming.await.expect("origin handshake");
            let alpn = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.protocol);
            assert_eq!(alpn.as_deref(), Some(ALPN_H3));
            let mut h3: h3::server::Connection<h3_quinn::Connection, Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(conn))
                    .await
                    .expect("h3 server");
            // Wait briefly for a request or shutdown.
            let _ = tokio::time::timeout(std::time::Duration::from_millis(200), h3.accept()).await;
            origin.close_and_drain().await;
        });

        let mut client_ep = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("client endpoint");
        // Trust Proxima CA for the localhost leaf (not --insecure accept-any).
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der().clone()).expect("root");
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN_H3.to_vec()];
        tls.enable_early_data = false;
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client");
        client_ep.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(quic)));

        let authority = UpstreamAuthority {
            host: "localhost".into(),
            port: origin_addr.port(),
        };
        let upstream = dial_h3(&client_ep, &authority, origin_addr)
            .await
            .expect("dial_h3");
        assert_eq!(upstream.addr, origin_addr);
        assert_eq!(upstream.negotiated_alpn().as_deref(), Some(ALPN_H3));

        client_ep.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), accept).await;
        // client_crypto(true) still builds next to this path.
        let _ = client_crypto(true).expect("insecure client_crypto");
    }
}
