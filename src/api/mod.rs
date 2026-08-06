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
