//! The inspector API, the live event socket, the inspector page and the phone
//! setup page.
//!
//! Two servers reach into this module. The UI port runs the full axum
//! [`router`]. The proxy port serves a small synchronous subset through
//! [`SetupService`], because the setup page has to load over plain HTTP before
//! any certificate has been trusted, and at that moment the phone can only talk
//! to the proxy.

mod inspector;
mod routes;
mod setup;

use std::net::{IpAddr, Ipv6Addr};

use anyhow::Result;
use bytes::Bytes;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::ca::CertAuthority;
use crate::capture::FlowStore;
use crate::proxy::breakpoint::PauseHub;
use crate::proxy::rewrite::RewriteHub;
use crate::proxy::websocket::WsRegistry;
use crate::proxy::ws_rewrite::WsRewriteHub;
use crate::replay::ReplayEngine;
use crate::types::ServerStatus;
use crate::Config;

/// Name shown on the iOS profile and in the device certificate list.
const PROFILE_DISPLAY_NAME: &str = "Proxima";

#[derive(Clone)]
pub struct ApiState {
    pub config: std::sync::Arc<Config>,
    pub ca: std::sync::Arc<CertAuthority>,
    pub store: std::sync::Arc<FlowStore>,
    pub replay: std::sync::Arc<ReplayEngine>,
    pub proxy_port: u16,
    pub ui_port: u16,
    /// Live upgraded WebSockets shared with the proxy for frame inject.
    pub ws_registry: std::sync::Arc<WsRegistry>,
    /// Breakpoint rules and held pauses, shared with the proxy pump.
    pub pauses: std::sync::Arc<PauseHub>,
    /// WebSocket rewrite/drop rules, shared with the proxy pump.
    pub ws_rewrite: std::sync::Arc<WsRewriteHub>,
    /// HTTP rewrite / map-host / map-local rules, shared with the proxy.
    pub rewrite: std::sync::Arc<RewriteHub>,
}

/// Every route the inspector serves, including the page itself.
pub fn router(state: ApiState) -> axum::Router {
    routes::build(state)
}

/// Runs the inspector until `shutdown` flips to true or its sender is dropped.
pub async fn serve(
    state: ApiState,
    listener: TcpListener,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let local = listener.local_addr().ok();
    if let Some(addr) = local {
        tracing::info!(%addr, "inspector listening");
    }

    let signal = async move {
        let mut shutdown = shutdown;
        loop {
            if *shutdown.borrow_and_update() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        tracing::debug!("inspector shutting down");
    };

    axum::serve(listener, router(state))
        .with_graceful_shutdown(signal)
        .await?;
    Ok(())
}

/// A snapshot of everything the UI needs to describe the running proxy.
pub fn status(state: &ApiState) -> ServerStatus {
    ServerStatus {
        proxy_port: state.proxy_port,
        ui_port: state.ui_port,
        addresses: lan_addresses(),
        ca_fingerprint: state.ca.sha256().to_string(),
        ca_not_after: rfc3339(state.ca.not_after()),
        flow_count: state.store.len(),
        // Capture has no pause switch today; the field exists so the UI can
        // render one the moment it does.
        capturing: true,
        archiving: state.store.archive().is_some(),
        archive_dropped: state.store.archive().map(|a| a.dropped()).unwrap_or(0),
        quic_enabled: cfg!(feature = "quic"),
        quic_port: state.config.quic_port,
        quic_note: Some(quic_status_note(
            state.config.quic_port,
            state.config.reverse_h3.as_deref(),
        )),
        reverse_h3: state.config.reverse_h3.clone(),
        wireguard_enabled: cfg!(feature = "wireguard"),
        wireguard_port: state.config.wg_port,
        wireguard_note: Some(wireguard_status_note(state.config.wg_port)),
        tun_enabled: cfg!(feature = "tun"),
        tun_active: if state.config.tun {
            Some(true)
        } else {
            None
        },
        tun_note: Some(tun_status_note(state.config.tun)),
    }
}

/// Honest one-liner for the status payload: regular TCP proxy never sees QUIC.
fn quic_status_note(quic_port: Option<u16>, reverse_h3: Option<&str>) -> String {
    if !cfg!(feature = "quic") {
        return "This build has no QUIC support (rebuild with --features quic). \
                Regular TCP proxy mode cannot see QUIC/HTTP3. \
                Phone path for QUIC needs WireGuard/TUN (not shipped)."
            .to_string();
    }
    match (quic_port, reverse_h3) {
        (Some(port), Some(upstream)) => format!(
            "QUIC/HTTP3 reverse proxy on UDP port {port} -> {upstream}. \
             Regular TCP proxy mode cannot see QUIC. \
             Phone path for arbitrary app QUIC needs WireGuard/TUN (not shipped)."
        ),
        (Some(port), None) => format!(
            "QUIC UDP listener on port {port} (accept-only, no reverse upstream / no forward). \
             Regular TCP proxy mode cannot see QUIC. \
             Phone path for QUIC needs WireGuard/TUN (not shipped)."
        ),
        (None, _) => "QUIC support is compiled in but no UDP listener is bound. \
                      Regular TCP proxy mode cannot see QUIC/HTTP3. \
                      Phone path for QUIC needs WireGuard/TUN (not shipped)."
            .to_string(),
    }
}

/// Honest one-liner for WireGuard: scaffold may bind; crypto is not a tunnel.
fn wireguard_status_note(wg_port: Option<u16>) -> String {
    if !cfg!(feature = "wireguard") {
        return "This build has no WireGuard scaffold (rebuild with --features wireguard). \
                Device-join crypto is not shipped either way. \
                Phone Wi-Fi HTTP proxy settings never feed a WireGuard path."
            .to_string();
    }
    match wg_port {
        Some(port) => format!(
            "WireGuard UDP scaffold on port {port} (bind only; Noise/WG crypto not implemented). \
             Not a working device tunnel. Phone Wi-Fi HTTP proxy settings do not feed this path."
        ),
        None => "WireGuard scaffold is compiled in but no WG UDP listener is bound. \
                 Crypto and a working device tunnel are not shipped. \
                 Phone Wi-Fi HTTP proxy settings do not feed a WireGuard path."
            .to_string(),
    }
}

/// Honest one-liner for TUN: scaffold may run; no device open, no capture claim.
fn tun_status_note(tun: bool) -> String {
    if !cfg!(feature = "tun") {
        return "This build has no TUN scaffold (rebuild with --features tun). \
                Local packet capture is not shipped either way. \
                macOS would need utun/Network Extension; Linux /dev/net/tun + CAP_NET_ADMIN; \
                Windows host capture is not claimed."
            .to_string();
    }
    if tun {
        "TUN scaffold task is running (shutdown watch only; no utun//dev/net/tun open; \
         no packet capture). macOS: utun/Network Extension (no TPROXY). \
         Linux: /dev/net/tun + CAP_NET_ADMIN. Not a working capture path."
            .to_string()
    } else {
        "TUN scaffold is compiled in but not requested. \
         No virtual interface is open. macOS/Linux capture is not shipped; \
         no Windows capture claim."
            .to_string()
    }
}

/// Serves the setup page and the certificate downloads over the proxy port,
/// for the hosts listed in [`Config::setup_hosts`].
pub struct SetupService {
    pub state: ApiState,
}

impl crate::proxy::SetupHandler for SetupService {
    fn handle(&self, parts: &http::request::Parts) -> http::Response<Bytes> {
        // The request arrives in absolute form (`GET http://proxima.setup/cert`)
        // because it came through a proxy, but `Uri::path` normalises that away.
        let path = parts.uri.path();
        let user_agent = parts
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok());

        match path {
            // "/setup" is not strictly required here, but it is the path the UI
            // links to and typing it on the phone should not dead end.
            "/" | "/setup" => {
                let html = setup::render(&self.state, user_agent);
                let mut response = http::Response::new(Bytes::from(html));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("text/html; charset=utf-8"),
                );
                response.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-store"),
                );
                response
            }
            "/cert" => download_response(cert_download(&self.state.ca)),
            "/cert.mobileconfig" => download_response(mobileconfig_download(&self.state.ca)),
            _ => {
                let mut response = http::Response::new(Bytes::from_static(
                    b"Not found. Open http://proxima.setup/ to set this device up.\n",
                ));
                *response.status_mut() = http::StatusCode::NOT_FOUND;
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                response
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* certificate downloads, shared by both servers                       */
/* ------------------------------------------------------------------ */

pub(crate) struct Download {
    pub content_type: &'static str,
    pub disposition: Option<&'static str>,
    pub body: Bytes,
}

pub(crate) fn cert_download(ca: &CertAuthority) -> Download {
    Download {
        content_type: "application/x-x509-ca-cert",
        disposition: Some("attachment; filename=\"proxima-ca.crt\""),
        body: Bytes::from(ca.cert_pem().to_owned()),
    }
}

pub(crate) fn mobileconfig_download(ca: &CertAuthority) -> Download {
    Download {
        content_type: "application/x-apple-aspen-config",
        // Deliberately no Content-Disposition. iOS hands a profile to Settings
        // based on the media type; marking it as an attachment makes Safari
        // save it to Files instead, where it cannot be installed.
        disposition: None,
        body: Bytes::from(ca.mobileconfig(PROFILE_DISPLAY_NAME)),
    }
}

fn download_response(download: Download) -> http::Response<Bytes> {
    let mut response = http::Response::new(download.body);
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(download.content_type),
    );
    if let Some(disposition) = download.disposition {
        headers.insert(
            http::header::CONTENT_DISPOSITION,
            http::HeaderValue::from_static(disposition),
        );
    }
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}

/* ------------------------------------------------------------------ */
/* addresses                                                           */
/* ------------------------------------------------------------------ */

/// Addresses a phone on the same network could actually point at, best first.
fn lan_addresses() -> Vec<String> {
    let mut addresses: Vec<IpAddr> = match local_ip_address::list_afinet_netifas() {
        Ok(list) => list.into_iter().map(|(_, ip)| ip).collect(),
        Err(err) => {
            tracing::debug!(error = %err, "could not enumerate network interfaces");
            Vec::new()
        }
    };

    addresses.retain(reachable_from_lan);
    addresses.sort_by_key(|ip| (address_rank(ip), *ip));
    addresses.dedup();

    let mut out: Vec<String> = addresses.iter().map(|ip| ip.to_string()).collect();
    if out.is_empty() {
        // Better to show something usable on the machine itself than nothing.
        out.push("127.0.0.1".to_string());
    }
    out
}

fn reachable_from_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified() && !v4.is_link_local(),
        IpAddr::V6(v6) => {
            !v6.is_loopback() && !v6.is_unspecified() && !v6.is_multicast() && !is_v6_link_local(v6)
        }
    }
}

/// fe80::/10. `Ipv6Addr::is_unicast_link_local` is still unstable.
fn is_v6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// fc00::/7.
fn is_v6_unique_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// A home network hands out RFC 1918 v4, so that is what a user expects to see
/// at the top of the setup page.
fn address_rank(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(v4) if v4.is_private() => 0,
        IpAddr::V4(_) => 1,
        IpAddr::V6(v6) if is_v6_unique_local(v6) => 2,
        IpAddr::V6(_) => 3,
    }
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

/// Human readable date for the setup page, e.g. `5 August 2035`.
pub(crate) fn friendly_date(at: OffsetDateTime) -> String {
    let date = at.date();
    format!("{} {} {}", date.day(), date.month(), date.year())
}

/// Wraps a bare IPv6 address in brackets so it can go into a URL.
pub(crate) fn url_host(address: &str) -> String {
    if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]")
    } else {
        address.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn quic_status_fields_track_feature_and_port() {
        // Feature flag is compile-time; this asserts the status helper's shape.
        let note_off_listener = quic_status_note(None, None);
        assert!(
            note_off_listener.contains("cannot see QUIC"),
            "note must state regular TCP proxy cannot see QUIC: {note_off_listener}"
        );

        let note_bound = quic_status_note(Some(9443), None);
        if cfg!(feature = "quic") {
            assert!(
                note_bound.contains("9443"),
                "bound port should appear when feature is on: {note_bound}"
            );
            assert!(
                note_bound.contains("accept-only"),
                "accept-only path must say accept-only: {note_bound}"
            );
            assert!(
                note_bound.contains("WireGuard") || note_bound.contains("TUN"),
                "note should mention missing phone path: {note_bound}"
            );
        } else {
            assert!(
                note_bound.contains("--features quic"),
                "feature-off note should tell how to rebuild: {note_bound}"
            );
        }

        let note_reverse = quic_status_note(Some(9443), Some("origin.example:443"));
        if cfg!(feature = "quic") {
            assert!(note_reverse.contains("origin.example:443"));
            assert!(note_reverse.contains("reverse"));
        } else {
            assert!(
                note_reverse.contains("--features quic"),
                "feature-off note ignores port/upstream and guides rebuild: {note_reverse}"
            );
        }
    }

    #[test]
    fn server_status_serializes_quic_enabled_and_omits_null_port() {
        let status = ServerStatus {
            proxy_port: 9090,
            ui_port: 9091,
            addresses: vec!["127.0.0.1".into()],
            ca_fingerprint: "AB".into(),
            ca_not_after: "2035-01-01T00:00:00Z".into(),
            flow_count: 0,
            capturing: true,
            archiving: false,
            archive_dropped: 0,
            quic_enabled: cfg!(feature = "quic"),
            quic_port: None,
            quic_note: Some(quic_status_note(None, None)),
            reverse_h3: None,
            wireguard_enabled: cfg!(feature = "wireguard"),
            wireguard_port: None,
            wireguard_note: Some(wireguard_status_note(None)),
            tun_enabled: cfg!(feature = "tun"),
            tun_active: None,
            tun_note: Some(tun_status_note(false)),
        };
        let json = serde_json::to_value(&status).expect("serialize");
        assert_eq!(
            json.get("quicEnabled").and_then(|v| v.as_bool()),
            Some(cfg!(feature = "quic"))
        );
        assert!(
            json.get("quicPort").is_none(),
            "absent quic_port must skip_serializing"
        );
        assert!(
            json
                .get("quicNote")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("cannot see QUIC")),
            "quicNote must be present and honest"
        );
        assert_eq!(
            json.get("wireguardEnabled").and_then(|v| v.as_bool()),
            Some(cfg!(feature = "wireguard"))
        );
        assert!(
            json.get("wireguardPort").is_none(),
            "absent wireguard_port must skip_serializing"
        );
        assert!(
            json
                .get("wireguardNote")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("WireGuard") || s.contains("wireguard")),
            "wireguardNote must be present and honest"
        );
        assert_eq!(
            json.get("tunEnabled").and_then(|v| v.as_bool()),
            Some(cfg!(feature = "tun"))
        );
        assert!(
            json.get("tunActive").is_none(),
            "absent tun_active must skip_serializing"
        );
        assert!(
            json
                .get("tunNote")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("TUN") || s.contains("tun")),
            "tunNote must be present and honest"
        );

        let with_port = ServerStatus {
            quic_port: Some(9443),
            quic_note: Some(quic_status_note(Some(9443), Some("up.example"))),
            reverse_h3: Some("up.example".into()),
            wireguard_port: Some(51820),
            wireguard_note: Some(wireguard_status_note(Some(51820))),
            tun_active: Some(true),
            tun_note: Some(tun_status_note(true)),
            ..status
        };
        let json = serde_json::to_value(&with_port).expect("serialize");
        assert_eq!(json.get("quicPort").and_then(|v| v.as_u64()), Some(9443));
        assert_eq!(
            json.get("reverseH3").and_then(|v| v.as_str()),
            Some("up.example")
        );
        assert_eq!(
            json.get("wireguardPort").and_then(|v| v.as_u64()),
            Some(51820)
        );
        let wg_note = json
            .get("wireguardNote")
            .and_then(|v| v.as_str())
            .expect("wireguardNote present when set");
        if cfg!(feature = "wireguard") {
            assert!(
                wg_note.contains("51820"),
                "feature-on bound note should name the port: {wg_note}"
            );
        } else {
            assert!(
                wg_note.contains("--features wireguard"),
                "feature-off note guides rebuild even if a port is set: {wg_note}"
            );
        }
        assert_eq!(
            json.get("tunActive").and_then(|v| v.as_bool()),
            Some(true),
            "tun_active Some(true) must serialize as tunActive"
        );
        let tun_note = json
            .get("tunNote")
            .and_then(|v| v.as_str())
            .expect("tunNote present when set");
        if cfg!(feature = "tun") {
            assert!(
                tun_note.contains("scaffold")
                    || tun_note.contains("no")
                    || tun_note.contains("not"),
                "feature-on active note must stay scaffold-honest: {tun_note}"
            );
        } else {
            assert!(
                tun_note.contains("--features tun"),
                "feature-off note guides rebuild even if active is set: {tun_note}"
            );
        }
    }

    #[test]
    fn wireguard_status_note_is_honest_about_scaffold() {
        let note_off = wireguard_status_note(None);
        if cfg!(feature = "wireguard") {
            assert!(
                note_off.contains("no WG") || note_off.contains("not shipped"),
                "{note_off}"
            );
        } else {
            assert!(
                note_off.contains("--features wireguard"),
                "feature-off note should guide rebuild: {note_off}"
            );
        }
        let note_bound = wireguard_status_note(Some(51820));
        if cfg!(feature = "wireguard") {
            assert!(note_bound.contains("51820"), "{note_bound}");
            assert!(
                note_bound.contains("scaffold") || note_bound.contains("not implemented"),
                "must not claim a working tunnel: {note_bound}"
            );
        } else {
            assert!(note_bound.contains("--features wireguard"), "{note_bound}");
        }
    }

    #[test]
    fn tun_status_note_is_honest_about_scaffold() {
        let note_off = tun_status_note(false);
        if cfg!(feature = "tun") {
            assert!(
                note_off.contains("not requested") || note_off.contains("not shipped"),
                "{note_off}"
            );
        } else {
            assert!(
                note_off.contains("--features tun"),
                "feature-off note should guide rebuild: {note_off}"
            );
        }
        let note_on = tun_status_note(true);
        if cfg!(feature = "tun") {
            assert!(
                note_on.contains("scaffold")
                    || note_on.contains("no device")
                    || note_on.contains("not a working"),
                "must not claim working capture: {note_on}"
            );
            assert!(
                note_on.contains("macOS")
                    || note_on.contains("utun")
                    || note_on.contains("Linux")
                    || note_on.contains("/dev/net/tun"),
                "should mention platform limits: {note_on}"
            );
        } else {
            assert!(note_on.contains("--features tun"), "{note_on}");
        }
    }

    #[test]
    fn loopback_and_link_local_are_not_offered_to_a_phone() {
        assert!(!reachable_from_lan(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!reachable_from_lan(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 3, 4
        ))));
        assert!(!reachable_from_lan(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(reachable_from_lan(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 5
        ))));

        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(!reachable_from_lan(&IpAddr::V6(link_local)));
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(reachable_from_lan(&IpAddr::V6(global)));
    }

    #[test]
    fn private_v4_sorts_ahead_of_everything_else() {
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let unique_local = IpAddr::V6("fd00::1".parse().unwrap());
        let v6 = IpAddr::V6("2001:db8::1".parse().unwrap());

        assert!(address_rank(&private) < address_rank(&public));
        assert!(address_rank(&public) < address_rank(&unique_local));
        assert!(address_rank(&unique_local) < address_rank(&v6));
    }

    #[test]
    fn ipv6_gets_brackets_in_a_url() {
        assert_eq!(url_host("192.168.1.5"), "192.168.1.5");
        assert_eq!(url_host("fd00::1"), "[fd00::1]");
        assert_eq!(url_host("[fd00::1]"), "[fd00::1]");
    }
}
