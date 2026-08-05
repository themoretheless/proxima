//! Opaque CONNECT tunnels.
//!
//! Used whenever the bytes inside a tunnel are none of our business: a host
//! excluded by the decrypt rules, or a stream that turned out not to be TLS at
//! all. The connection still becomes a visible flow, because "nothing appeared
//! in the list" and "the app talked to a host you excluded" look identical
//! otherwise. What gets recorded is the endpoint, the reason and the volume in
//! each direction, which is everything an HTTP proxy can honestly claim to know
//! about bytes it never decrypted.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::debug;

use crate::capture::FlowInit;
use crate::types::{
    now_ms, FlowClient, FlowError, FlowKind, FlowRequest, FlowServer, FlowState, HttpVersion,
    Scheme, TunnelInfo,
};

use super::{format_authority, shutdown_requested, ProxyDeps};

/// The flow a tunnel is recorded as, before anything has been copied.
///
/// A CONNECT has no path and no response, so the shape is a little odd on
/// purpose: the method is the CONNECT the client actually sent and the URL is
/// the authority it asked for.
pub(super) fn tunnel_init(host: &str, port: u16, client: FlowClient) -> FlowInit {
    let authority = format_authority(host, port, Scheme::Https);
    FlowInit {
        kind: FlowKind::Tunnel,
        // Nothing was decrypted here, and the UI leans on this flag to explain
        // why there is no request body to look at.
        intercepted: false,
        request: FlowRequest {
            method: "CONNECT".to_string(),
            url: format!("https://{authority}"),
            scheme: Scheme::Https,
            authority,
            host: host.to_string(),
            port,
            path: String::new(),
            http_version: HttpVersion::Http11,
            headers: Vec::new(),
            body: None,
        },
        client,
        server: FlowServer::default(),
        replay_of: None,
    }
}

/// Copies bytes both ways until either side closes or shutdown is requested.
pub(super) async fn run_tunnel<S>(
    mut client_side: S,
    host: String,
    port: u16,
    reason: &str,
    deps: Arc<ProxyDeps>,
    client: FlowClient,
    mut shutdown: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let id = deps.store.create(tunnel_init(&host, port, client));
    let reason = reason.to_string();
    deps.store.update(&id, |flow| {
        flow.state = FlowState::Streaming;
        flow.tunnel = Some(TunnelInfo {
            bytes_sent: 0,
            bytes_received: 0,
            reason: reason.clone(),
        });
    });

    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(stream) => stream,
        Err(err) => {
            debug!(%host, port, error = %err, "could not open the tunnel upstream");
            deps.store.fail(
                &id,
                FlowError {
                    message: format!("could not connect to {host}:{port}: {err}"),
                    code: Some("connect".to_string()),
                    likely_pinning: None,
                },
            );
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    deps.store.update(&id, |flow| {
        flow.timings.connect_end = Some(now_ms());
    });

    let copied = tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client_side, &mut upstream) => Some(result),
        // A tunnel can sit open for hours, so shutdown has to be able to cut it
        // rather than wait for a peer that may never speak again.
        _ = shutdown_requested(&mut shutdown) => None,
    };

    match copied {
        Some(Ok((sent, received))) => {
            record_volume(&deps, &id, sent, received);
            deps.store.finish(&id);
        }
        Some(Err(err)) => {
            debug!(%host, port, error = %err, "tunnel ended with an error");
            // Bytes did move before the failure, and their volume is often the
            // only clue about how far the connection got.
            deps.store.fail(
                &id,
                FlowError {
                    message: format!("tunnel to {host}:{port} failed: {err}"),
                    code: Some("tunnel".to_string()),
                    likely_pinning: None,
                },
            );
        }
        None => {
            debug!(%host, port, "tunnel cut short by shutdown");
            deps.store.update(&id, |flow| {
                flow.state = FlowState::Aborted;
                flow.timings.end = Some(now_ms());
            });
        }
    }
}

fn record_volume(deps: &ProxyDeps, id: &str, sent: u64, received: u64) {
    deps.store.update(id, |flow| {
        let tunnel = flow.tunnel.get_or_insert_with(TunnelInfo::default);
        tunnel.bytes_sent = sent;
        tunnel.bytes_received = received;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::FlowStore;

    fn client() -> FlowClient {
        FlowClient {
            address: "192.168.1.20".to_string(),
            port: 51234,
        }
    }

    #[test]
    fn a_tunnel_flow_names_the_endpoint_and_admits_it_is_opaque() {
        let init = tunnel_init("api.example.com", 443, client());
        assert_eq!(init.request.method, "CONNECT");
        assert_eq!(init.request.url, "https://api.example.com");
        assert_eq!(init.request.authority, "api.example.com");
        assert!(init.request.path.is_empty());
        assert!(!init.intercepted, "a tunnel must not claim to be decrypted");
        assert_eq!(init.kind, FlowKind::Tunnel);
    }

    #[test]
    fn a_non_default_port_stays_in_the_authority() {
        let init = tunnel_init("api.example.com", 8443, client());
        assert_eq!(init.request.authority, "api.example.com:8443");
        assert_eq!(init.request.url, "https://api.example.com:8443");
    }

    #[tokio::test]
    async fn an_unreachable_origin_becomes_a_failed_flow() {
        let store = Arc::new(FlowStore::new(16, 1024, 4096));
        let id = store.create(tunnel_init("example.invalid", 443, client()));
        store.fail(
            &id,
            FlowError {
                message: "could not connect".to_string(),
                code: Some("connect".to_string()),
                likely_pinning: None,
            },
        );

        let flow = store.get(&id).expect("flow");
        assert_eq!(flow.state, FlowState::Error);
        assert!(flow.error.is_some());
    }
}
