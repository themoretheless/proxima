//! rustls crypto configs for quinn, backed by Proxima's certificate authority.
//!
//! ## What this module is for
//!
//! QUIC is UDP. The regular TCP HTTPS proxy never sees it, so this stack lives
//! behind `--features quic` and terminates HTTP/3 with the same
//! [`CertAuthority`] leaves as TCP intercept.
//!
//! ## Policy (deliberate)
//!
//! - ALPN is only `h3` on the QUIC endpoint. TCP intercept still offers `h2` /
//!   `http/1.1` only; do not mix those lists.
//! - **0-RTT / early data is disabled on every MITM config** (see
//!   [`MITM_MAX_EARLY_DATA_SIZE`] and [`MITM_ENABLE_EARLY_DATA`]). Server:
//!   `max_early_data_size = 0`. Client: `enable_early_data = false`. Callers
//!   must never use `quinn::Connecting::into_0rtt`.
//! - Upstream trust never includes the Proxima CA: only system roots, or
//!   accept-any under `--insecure`.
//! - Chrome may still refuse user-installed CAs for QUIC even when the leaf is
//!   correctly minted; that is a client policy limit, not a Proxima bug.
//!
//! ### Why 0-RTT is off for MITM
//!
//! Early data is encrypted with keys derived from a previous session. For a
//! debugging MITM that is the wrong tradeoff:
//!
//! 1. **Replay**: 0-RTT application data can be replayed by an observer. A
//!    proxy that accepted early data would need to either risk replaying
//!    client requests upstream or invent non-replayable semantics it does not
//!    have.
//! 2. **Incomplete capture**: early data can complete before the full
//!    handshake and before Proxima has stable client/server identity facts.
//!    Flows would be partial or ordered wrong relative to the 1-RTT path.
//! 3. **Asymmetric legs**: MITM terminates the client QUIC session and opens a
//!    *new* session to the origin. Client 0-RTT tickets are for Proxima's
//!    leaf, not the origin; origin tickets are not the client's. There is no
//!    safe way to "forward" 0-RTT through the proxy.
//! 4. **Honesty**: debugging tools should not claim performance paths they
//!    cannot implement correctly. 1-RTT only keeps intercepted traffic
//!    inspectable and finishable as normal H3 request streams.
//!
//! Crypto uses the process-wide ring provider already installed by
//! `runtime::install_crypto_provider`. Factories do not install a second
//! provider and do not take the aws-lc path.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig};
use rustls::pki_types::CertificateDer;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
};

use crate::ca::{CertAuthority, SniResolver};

/// ALPN token for HTTP/3 (RFC 9114).
pub const ALPN_H3: &[u8] = b"h3";

/// Server-side early-data budget for every Proxima MITM QUIC config.
///
/// Always `0`: the client-facing endpoint never advertises or accepts QUIC
/// 0-RTT application data. See module docs ("Why 0-RTT is off for MITM").
/// Do not raise this without a full redesign of capture + replay safety.
pub const MITM_MAX_EARLY_DATA_SIZE: u32 = 0;

/// Client-side early-data switch for every Proxima MITM upstream dial.
///
/// Always `false`: origin legs complete a full 1-RTT handshake. Pair with
/// never calling `into_0rtt` on [`quinn::Connecting`] (see
/// [`super::forward_upstream::dial_h3`]).
pub const MITM_ENABLE_EARLY_DATA: bool = false;

/// Builds a quinn [`ServerConfig`] that mints leaves via [`CertAuthority`].
///
/// SNI selects the certificate through [`SniResolver`]. Without SNI the
/// `fallback_host` is used so the handshake can still complete for broken
/// clients (same idea as CONNECT-host fallback on TCP).
///
/// ALPN is only `h3`. Early data is disabled ([`MITM_MAX_EARLY_DATA_SIZE`]).
pub fn server_crypto(
    ca: Arc<CertAuthority>,
    fallback_host: impl Into<String>,
) -> Result<ServerConfig> {
    let tls = rustls_server_sni(ca, fallback_host.into())?;
    wrap_server(tls)
}

/// Same ALPN / 0-RTT policy as [`server_crypto`], but always serves one host's
/// cached leaf regardless of client SNI. Useful for reverse/demo endpoints
/// where the public name is fixed.
///
/// Early data remains disabled; fixed-host reverse is not a reason to accept
/// 0-RTT.
pub fn server_crypto_fixed(ca: Arc<CertAuthority>, host: impl Into<String>) -> Result<ServerConfig> {
    let host = host.into();
    let key = ca
        .certified_key(&host)
        .with_context(|| format!("minting fixed QUIC leaf for {host}"))?;
    let tls = rustls_server_fixed(key)?;
    wrap_server(tls)
}

/// Upstream client config for origin dials.
///
/// When `insecure` is false, system trust roots are required (same honesty as
/// TCP `--insecure` messaging). Proxima's CA is never added to origin roots.
///
/// Early data is disabled ([`MITM_ENABLE_EARLY_DATA`]) even when `insecure` is
/// true: `--insecure` only relaxes certificate verification, not 0-RTT policy.
pub fn client_crypto(insecure: bool) -> Result<ClientConfig> {
    let tls = rustls_client(insecure)?;
    let quic = QuicClientConfig::try_from(tls).context("QuicClientConfig from rustls")?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

/* ------------------------------------------------------------------ */
/* rustls builders (testable before quinn wrap)                        */
/* ------------------------------------------------------------------ */

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn rustls_server_sni(ca: Arc<CertAuthority>, fallback_host: String) -> Result<RustlsServerConfig> {
    let mut tls = RustlsServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .context("rustls server protocol versions")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniResolver::new(ca, fallback_host)));
    apply_server_h3_policy(&mut tls);
    Ok(tls)
}

fn rustls_server_fixed(key: Arc<CertifiedKey>) -> Result<RustlsServerConfig> {
    let mut tls = RustlsServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .context("rustls server protocol versions")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedHostResolver { key }));
    apply_server_h3_policy(&mut tls);
    Ok(tls)
}

/// Applies the shared client-facing H3 + anti-0-RTT policy to a rustls server
/// config. Every MITM server path (SNI resolver and fixed-host) must go through
/// this helper so early-data knobs cannot drift.
fn apply_server_h3_policy(tls: &mut RustlsServerConfig) {
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    // Security: refuse QUIC 0-RTT on the MITM leg. Non-zero would advertise
    // early-data capacity to clients; see MITM_MAX_EARLY_DATA_SIZE docs.
    tls.max_early_data_size = MITM_MAX_EARLY_DATA_SIZE;
    debug_assert_eq!(
        tls.max_early_data_size, 0,
        "MITM server configs must not accept 0-RTT early data"
    );
}

fn rustls_client(insecure: bool) -> Result<RustlsClientConfig> {
    let mut tls = if insecure {
        RustlsClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .context("rustls client protocol versions")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyOrigin))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        for error in &loaded.errors {
            tracing::debug!(error = %error, "a system trust root could not be read");
        }
        for cert in loaded.certs {
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err(anyhow!(
                "no system trust roots could be read, so no origin certificate could be verified. \
                 Run with --insecure to accept origins unverified."
            ));
        }
        RustlsClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .context("rustls client protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    // Security: never send 0-RTT early data to the origin. MITM opens a fresh
    // session; early data would skip inspectable 1-RTT establishment and is
    // not forwardable from the client leg. See MITM_ENABLE_EARLY_DATA.
    tls.enable_early_data = MITM_ENABLE_EARLY_DATA;
    debug_assert!(
        !tls.enable_early_data,
        "MITM client configs must not enable 0-RTT early data"
    );
    Ok(tls)
}

fn wrap_server(tls: RustlsServerConfig) -> Result<ServerConfig> {
    let quic = QuicServerConfig::try_from(tls).context("QuicServerConfig from rustls")?;
    let mut server = ServerConfig::with_crypto(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60)).expect("idle timeout"),
    ));
    server.transport_config(Arc::new(transport));
    Ok(server)
}

/// Always returns one pre-minted leaf, ignoring client SNI.
struct FixedHostResolver {
    key: Arc<CertifiedKey>,
}

impl std::fmt::Debug for FixedHostResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedHostResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for FixedHostResolver {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.key.clone())
    }
}

/// Accepts every certificate. Only used with `--insecure` / reverse upstream.
/// Mirrors TCP `AcceptAnyOrigin` so staging origins with self-signed certs work.
#[derive(Debug)]
struct AcceptAnyOrigin;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyOrigin {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn temp_ca() -> (tempfile::TempDir, Arc<CertAuthority>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = CertAuthority::open(dir.path()).expect("open CA");
        (dir, Arc::new(ca))
    }

    #[test]
    fn mitm_early_data_policy_constants_are_disabled() {
        // Locks the public security knobs: any non-zero/true change is a
        // deliberate policy break and must update module docs + callers.
        assert_eq!(MITM_MAX_EARLY_DATA_SIZE, 0);
        assert!(!MITM_ENABLE_EARLY_DATA);
    }

    #[test]
    fn server_alpn_is_only_h3_and_early_data_disabled() {
        let (_dir, ca) = temp_ca();
        let tls = rustls_server_sni(ca, "fallback.example".into()).expect("server tls");
        assert_eq!(tls.alpn_protocols, vec![ALPN_H3.to_vec()]);
        assert_eq!(tls.max_early_data_size, MITM_MAX_EARLY_DATA_SIZE);
        assert_eq!(tls.max_early_data_size, 0);
    }

    #[test]
    fn fixed_server_same_h3_policy() {
        let (_dir, ca) = temp_ca();
        let key = ca.certified_key("app.example").expect("mint");
        let tls = rustls_server_fixed(key).expect("fixed tls");
        assert_eq!(tls.alpn_protocols, vec![ALPN_H3.to_vec()]);
        assert_eq!(tls.max_early_data_size, MITM_MAX_EARLY_DATA_SIZE);
        assert_eq!(tls.max_early_data_size, 0);
    }

    #[test]
    fn client_alpn_h3_and_early_data_off() {
        // insecure path avoids depending on machine trust stores in CI.
        let tls = rustls_client(true).expect("client tls");
        assert_eq!(tls.alpn_protocols, vec![ALPN_H3.to_vec()]);
        assert_eq!(tls.enable_early_data, MITM_ENABLE_EARLY_DATA);
        assert!(!tls.enable_early_data);
    }

    #[test]
    fn insecure_does_not_relax_zero_rtt_policy() {
        // --insecure only skips origin cert verification; 0-RTT stays off.
        let tls = rustls_client(true).expect("insecure client");
        assert!(!tls.enable_early_data);
        assert_eq!(tls.enable_early_data, MITM_ENABLE_EARLY_DATA);
    }

    #[test]
    fn server_crypto_and_client_crypto_build_without_panic() {
        let (_dir, ca) = temp_ca();
        let _server = server_crypto(ca.clone(), "localhost").expect("server_crypto");
        let _fixed = server_crypto_fixed(ca, "demo.local").expect("server_crypto_fixed");
        let _client = client_crypto(true).expect("client_crypto insecure");
    }

    #[test]
    fn certified_key_chain_includes_root_and_caches() {
        let (_dir, ca) = temp_ca();
        let first = ca.certified_key("cache.quic.example").expect("mint");
        let second = ca.certified_key("cache.quic.example").expect("cache hit");
        assert!(Arc::ptr_eq(&first, &second), "second mint should hit cache");
        assert_eq!(
            first.cert.len(),
            2,
            "leaf + Proxima root must both be present"
        );
        // Root DER matches the CA store.
        assert_eq!(first.cert[1].as_ref(), ca.cert_der().as_ref());
    }

    #[test]
    fn alpn_constant_is_h3() {
        assert_eq!(ALPN_H3, b"h3");
    }

    #[test]
    fn server_alpn_does_not_offer_tcp_protocols() {
        // QUIC endpoint must not advertise h2/http/1.1; those stay on the TCP
        // intercept ServerConfig only (see proxy TLS path).
        let (_dir, ca) = temp_ca();
        let tls = rustls_server_sni(ca, "fallback.example".into()).expect("server tls");
        assert_eq!(tls.alpn_protocols.len(), 1);
        assert!(!tls.alpn_protocols.iter().any(|p| p == b"h2"));
        assert!(!tls.alpn_protocols.iter().any(|p| p == b"http/1.1"));
        assert_eq!(tls.alpn_protocols[0], ALPN_H3);
    }

    #[test]
    fn client_alpn_does_not_offer_tcp_protocols() {
        let tls = rustls_client(true).expect("client tls");
        assert_eq!(tls.alpn_protocols, vec![ALPN_H3.to_vec()]);
        assert!(!tls.alpn_protocols.iter().any(|p| p == b"h2"));
        assert!(!tls.enable_early_data);
    }

    #[test]
    fn secure_client_crypto_builds_or_honest_empty_roots() {
        // On machines with system roots this succeeds; without roots it must
        // fail with the same --insecure guidance as the TCP forward path.
        match client_crypto(false) {
            Ok(_) => {}
            Err(err) => {
                let msg = format!("{err:#}");
                assert!(
                    msg.contains("system trust roots") || msg.contains("--insecure"),
                    "secure client_crypto error should mention roots or --insecure, got: {msg}"
                );
            }
        }
    }

    #[test]
    fn different_hosts_mint_distinct_leaves() {
        let (_dir, ca) = temp_ca();
        let a = ca.certified_key("a.quic.example").expect("mint a");
        let b = ca.certified_key("b.quic.example").expect("mint b");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_ne!(a.cert[0].as_ref(), b.cert[0].as_ref());
        // Both chains still end with the shared Proxima root.
        assert_eq!(a.cert[1].as_ref(), b.cert[1].as_ref());
        assert_eq!(a.cert[1].as_ref(), ca.cert_der().as_ref());
    }
}
