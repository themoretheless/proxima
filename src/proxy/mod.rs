//! The port a device points at: CONNECT handling, TLS termination, dispatch.
//!
//! One tokio task per client connection. A plain request arrives in absolute
//! form and is forwarded as it stands. A CONNECT either becomes an opaque
//! tunnel or is terminated with a certificate minted for the host, after which
//! the decrypted stream is served by hyper exactly like any other connection
//! and the requests inside it are rewritten back into absolute form.
//!
//! Nothing here fails a connection on purpose. A request we cannot place gets a
//! readable status code, an origin we cannot reach becomes a failed flow, and a
//! stream that turns out not to be TLS falls back to an opaque tunnel. A
//! debugging proxy that drops connections is indistinguishable from a broken
//! network, which is the one thing it must never look like.

mod tunnel;

pub mod forward;
pub mod headers;
pub mod websocket;

use std::convert::Infallible;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use bytes::Bytes;
use http::request::Parts;
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::ca::{CertAuthority, SniResolver};
use crate::capture::FlowStore;
use crate::config::{host_matches, should_decrypt, strip_port, Config};
use crate::types::{FlowClient, FlowError, FlowServer, Scheme, TunnelInfo};

pub use forward::{ForwardContext, ProxyBody};

/// How long a client may sit silent after CONNECT before we give up on seeing
/// a ClientHello and treat the connection as opaque bytes.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long shutdown waits for connections to finish before giving up on them.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Every TLS record starts with a content type byte; a handshake is 0x16.
const TLS_HANDSHAKE_BYTE: u8 = 0x16;

/* ------------------------------------------------------------------ */
/* Dependencies                                                        */
/* ------------------------------------------------------------------ */

/// Serves the device setup page over plain HTTP.
pub trait SetupHandler: Send + Sync {
    /// Serves the device setup page over plain HTTP for config.setup_hosts.
    fn handle(&self, parts: &Parts) -> Response<Bytes>;
}

pub struct ProxyDeps {
    pub config: Arc<Config>,
    pub ca: Arc<CertAuthority>,
    pub store: Arc<FlowStore>,
    pub upstream: forward::Upstream,
    pub setup: Arc<dyn SetupHandler>,
}

/* ------------------------------------------------------------------ */
/* Capture store glue                                                  */
/* ------------------------------------------------------------------ */

// The capture store owns flow identity: it mints the id, stamps the start time
// and publishes every change. The proxy hands it a FlowInit and then only ever
// refers to the flow by the id it got back.

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

pub struct ProxyServer;

impl ProxyServer {
    /// Runs until `shutdown` flips to true. The listener is bound by the caller
    /// so it can report the port it actually got.
    pub async fn serve(
        deps: Arc<ProxyDeps>,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        install_crypto_provider();

        let local = listener
            .local_addr()
            .context("reading the proxy listen address")?;
        info!(address = %local, "proxy listening");

        if *shutdown.borrow() {
            return Ok(());
        }

        // Held by every task the proxy spawns, including the ones that outlive
        // their parent connection after an upgrade. The receiver only completes
        // once the last clone is dropped, which is what "drained" means here.
        let (drain_tx, mut drain_rx) = mpsc::channel::<()>(1);

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    // A dropped sender means the owner is gone, so stop too.
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let deps = deps.clone();
                            let shutdown = shutdown.clone();
                            let drain = drain_tx.clone();
                            tokio::spawn(async move {
                                let result =
                                    serve_client(stream, peer, deps, shutdown, drain).await;
                                if let Err(err) = result {
                                    debug!(%peer, error = %err, "client connection ended");
                                }
                            });
                        }
                        Err(err) => {
                            // Running out of descriptors is the usual cause and
                            // it clears on its own; spinning on accept does not.
                            warn!(error = %err, "accept failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }

        info!("proxy shutting down");
        drop(drain_tx);
        if tokio::time::timeout(DRAIN_TIMEOUT, drain_rx.recv())
            .await
            .is_err()
        {
            debug!("connections still open at shutdown, dropping them");
        }
        Ok(())
    }
}

fn install_crypto_provider() {
    // ring is the only provider compiled in, but installing it explicitly keeps
    // the first handshake from depending on rustls inferring it.
    if rustls::crypto::CryptoProvider::get_default().is_none()
        && rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
    {
        debug!("a TLS crypto provider was already installed");
    }
}

/// Polls a hyper connection, asking it to shut down gracefully once the
/// shutdown signal arrives. Written as a macro because the three connection
/// types involved share no trait.
macro_rules! drive_connection {
    ($conn:expr, $shutdown:expr) => {{
        let conn = $conn;
        tokio::pin!(conn);
        let mut shutdown = $shutdown;
        let mut asked = false;
        loop {
            tokio::select! {
                result = conn.as_mut() => break result,
                changed = shutdown.changed(), if !asked => {
                    if changed.is_err() || *shutdown.borrow() {
                        asked = true;
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        }
    }};
}

/* ------------------------------------------------------------------ */
/* Connection handling                                                 */
/* ------------------------------------------------------------------ */

/// Everything a request needs to know about the connection it arrived on.
struct ConnCtx {
    deps: Arc<ProxyDeps>,
    client: FlowClient,
    scheme: Scheme,
    intercepted: bool,
    /// Host and port from the CONNECT line, set only inside a terminated tunnel.
    connect_authority: Option<(String, u16)>,
    server: FlowServer,
    shutdown: watch::Receiver<bool>,
    drain: mpsc::Sender<()>,
}

async fn serve_client(
    stream: TcpStream,
    peer: SocketAddr,
    deps: Arc<ProxyDeps>,
    shutdown: watch::Receiver<bool>,
    drain: mpsc::Sender<()>,
) -> Result<()> {
    // Debugging traffic is mostly small and interactive, so Nagle only adds
    // latency to what the user is watching.
    let _ = stream.set_nodelay(true);

    let ctx = Arc::new(ConnCtx {
        deps,
        client: FlowClient {
            address: peer.ip().to_string(),
            port: peer.port(),
        },
        scheme: Scheme::Http,
        intercepted: false,
        connect_authority: None,
        server: FlowServer::default(),
        shutdown: shutdown.clone(),
        drain,
    });

    let service = service_fn(move |req: Request<Incoming>| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(route(req, ctx).await) }
    });

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.keep_alive(true).preserve_header_case(true);
    // with_upgrades covers both CONNECT and a plain WebSocket handshake.
    let conn = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();

    drive_connection!(conn, shutdown).context("serving the client connection")
}

async fn route(req: Request<Incoming>, ctx: Arc<ConnCtx>) -> Response<ProxyBody> {
    if req.method() == Method::CONNECT {
        connect(req, ctx).await
    } else {
        dispatch(req, ctx).await
    }
}

/* ------------------------------------------------------------------ */
/* CONNECT                                                             */
/* ------------------------------------------------------------------ */

async fn connect(mut req: Request<Incoming>, ctx: Arc<ConnCtx>) -> Response<ProxyBody> {
    // A CONNECT target is authority form, so the whole URI is host:port.
    let target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    let Some((host, port)) = split_authority(&target, 443) else {
        return text_response(
            StatusCode::BAD_REQUEST,
            format!("CONNECT target {target:?} is not host:port"),
        );
    };

    if is_self_target(&host, port, &ctx.deps.config) {
        return loop_response(&host, port, &ctx.deps.config);
    }

    let decrypt = should_decrypt(&host, &ctx.deps.config.decrypt);
    let deps = ctx.deps.clone();
    let client = ctx.client.clone();
    let shutdown = ctx.shutdown.clone();
    let drain = ctx.drain.clone();

    // The upgraded stream only exists once this 200 has gone out, so the work
    // happens in its own task and this handler returns immediately.
    tokio::spawn(async move {
        let _drain = drain.clone();
        let upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => TokioIo::new(upgraded),
            Err(err) => {
                debug!(%host, error = %err, "CONNECT upgrade never completed");
                return;
            }
        };

        if !decrypt {
            let reason = "excluded from decryption by the current rules";
            tunnel::run_tunnel(
                Prefixed::new(Bytes::new(), upgraded),
                host,
                port,
                reason,
                deps,
                client,
                shutdown,
            )
            .await;
            return;
        }

        match peek_first_byte(upgraded).await {
            Peeked::Tls(stream) => {
                intercept(stream, host, port, deps, client, shutdown, drain).await;
            }
            Peeked::NotTls(stream, reason) => {
                debug!(%host, %reason, "handing the connection over as an opaque tunnel");
                tunnel::run_tunnel(stream, host, port, reason, deps, client, shutdown).await;
            }
            Peeked::Closed => {
                debug!(%host, "client closed the tunnel before sending anything");
            }
        }
    });

    // No body and no length: hyper reads a 2xx to CONNECT as the upgrade.
    Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap_or_else(|_| Response::new(empty_body()))
}

enum Peeked<S> {
    Tls(Prefixed<S>),
    NotTls(Prefixed<S>, &'static str),
    Closed,
}

/// Reads one byte to tell TLS from anything else. The byte is kept and replayed
/// to whatever handles the stream next; dropping it would corrupt the
/// ClientHello in a way that looks like a network fault.
async fn peek_first_byte<S>(mut stream: S) -> Peeked<S>
where
    S: AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    let read = tokio::time::timeout(FIRST_BYTE_TIMEOUT, stream.read(&mut first)).await;
    match read {
        Ok(Ok(0)) => Peeked::Closed,
        Ok(Ok(_)) => {
            let prefix = Bytes::copy_from_slice(&first);
            if first[0] == TLS_HANDSHAKE_BYTE {
                Peeked::Tls(Prefixed::new(prefix, stream))
            } else {
                Peeked::NotTls(Prefixed::new(prefix, stream), "not TLS")
            }
        }
        Ok(Err(err)) => {
            debug!(error = %err, "reading the first tunnel byte failed");
            Peeked::Closed
        }
        Err(_) => Peeked::NotTls(
            Prefixed::new(Bytes::new(), stream),
            "no data from the client",
        ),
    }
}

/* ------------------------------------------------------------------ */
/* TLS termination                                                     */
/* ------------------------------------------------------------------ */

async fn intercept<S>(
    stream: S,
    host: String,
    port: u16,
    deps: Arc<ProxyDeps>,
    client: FlowClient,
    shutdown: watch::Receiver<bool>,
    drain: mpsc::Sender<()>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        // Clients are allowed to omit SNI, and plenty of them do. The CONNECT
        // host is the only hint left when that happens.
        .with_cert_resolver(Arc::new(SniResolver::new(deps.ca.clone(), host.clone())));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let tls = match acceptor.accept(stream).await {
        Ok(tls) => tls,
        Err(err) => {
            record_handshake_failure(&deps, &client, &host, port, &err);
            return;
        }
    };

    let mut server = FlowServer::default();
    let alpn = {
        let (_, conn) = tls.get_ref();
        server.sni = conn.server_name().map(|name| name.to_string());
        server.tls_version = conn.protocol_version().map(|v| format!("{v:?}"));
        server.cipher = conn
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite()));
        let alpn = conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        server.alpn = alpn.clone();
        alpn
    };
    debug!(%host, port, alpn = ?alpn, sni = ?server.sni, "TLS handshake completed");

    let ctx = Arc::new(ConnCtx {
        deps,
        client,
        scheme: Scheme::Https,
        intercepted: true,
        connect_authority: Some((host.clone(), port)),
        server,
        shutdown: shutdown.clone(),
        drain,
    });
    let service = service_fn(move |req: Request<Incoming>| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(dispatch(req, ctx).await) }
    });

    let io = TokioIo::new(tls);
    let result = if alpn.as_deref() == Some("h2") {
        let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        drive_connection!(builder.serve_connection(io, service), shutdown)
    } else {
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder.keep_alive(true).preserve_header_case(true);
        // WebSockets inside the tunnel need the upgrade to survive; forward()
        // takes it from there.
        drive_connection!(
            builder.serve_connection(io, service).with_upgrades(),
            shutdown
        )
    };
    if let Err(err) = result {
        debug!(%host, port, error = %err, "intercepted connection ended");
    }
}

/// A client that refuses our certificate almost always pins. That is the single
/// most confusing failure this tool produces, so it becomes a visible flow
/// rather than a dropped connection and a silent UI.
fn record_handshake_failure(
    deps: &ProxyDeps,
    client: &FlowClient,
    host: &str,
    port: u16,
    err: &io::Error,
) {
    let pinning = rejected_our_certificate(err);
    if pinning {
        warn!(%host, port, "the client rejected our certificate, this app most likely pins");
    } else {
        debug!(%host, port, error = %err, "TLS handshake with the client failed");
    }

    let id = deps
        .store
        .create(tunnel::tunnel_init(host, port, client.clone()));
    deps.store.update(&id, |flow| {
        flow.tunnel = Some(TunnelInfo {
            bytes_sent: 0,
            bytes_received: 0,
            reason: "the TLS handshake with the client failed".to_string(),
        });
    });
    deps.store.fail(
        &id,
        FlowError {
            message: if pinning {
                format!("{host} rejected the Proxima certificate. This app pins its certificates; add it to the skip list to let it through untouched.")
            } else {
                format!("TLS handshake failed: {err}")
            },
            code: Some("tls_handshake".to_string()),
            likely_pinning: if pinning { Some(true) } else { None },
        },
    );
}

/// True when the peer sent an alert that means "I do not trust this chain".
fn rejected_our_certificate(err: &io::Error) -> bool {
    if let Some(rustls::Error::AlertReceived(alert)) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return matches!(
            alert,
            rustls::AlertDescription::UnknownCA
                | rustls::AlertDescription::BadCertificate
                | rustls::AlertDescription::CertificateUnknown
        );
    }
    // The rustls error is not always reachable through get_ref, for instance
    // once it has been flattened into a message by an intermediate layer.
    let text = err.to_string();
    text.contains("UnknownCA") || text.contains("BadCertificate") || text.contains("CertificateUnknown")
}

/* ------------------------------------------------------------------ */
/* Request dispatch                                                    */
/* ------------------------------------------------------------------ */

async fn dispatch(req: Request<Incoming>, ctx: Arc<ConnCtx>) -> Response<ProxyBody> {
    let (mut parts, body) = req.into_parts();

    let Some((scheme, host, port)) = resolve_target(&parts, &ctx) else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "Proxima could not tell which host this request was for: it had neither an absolute URI nor a Host header.",
        );
    };
    let authority = format_authority(&host, port, scheme);

    // Requests inside a terminated tunnel arrive in origin form, and h2 keeps
    // the authority in a pseudo header. Both become an absolute URL here so
    // everything downstream sees one shape.
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    if let Some(uri) = absolute_uri(scheme, &authority, &path) {
        parts.uri = uri;
    }

    // The setup page has to work before any certificate is trusted, so it is
    // answered here rather than forwarded to a host that does not exist.
    if ctx
        .deps
        .config
        .setup_hosts
        .iter()
        .any(|pattern| host_matches(&host, pattern))
    {
        debug!(%host, path = %parts.uri.path(), "serving the device setup page");
        return ctx.deps.setup.handle(&parts).map(body_from);
    }

    if is_self_target(&host, port, &ctx.deps.config) {
        return loop_response(&host, port, &ctx.deps.config);
    }

    let forward_ctx = ForwardContext {
        scheme,
        host,
        port,
        authority,
        client: ctx.client.clone(),
        server: ctx.server.clone(),
        intercepted: ctx.intercepted,
    };
    forward::forward(Request::from_parts(parts, body), forward_ctx, ctx.deps.clone()).await
}

fn resolve_target(parts: &Parts, ctx: &ConnCtx) -> Option<(Scheme, String, u16)> {
    // Inside a terminated tunnel the CONNECT line is where the client actually
    // opened a socket. Host and :authority are client supplied strings, and
    // trusting them over the CONNECT would send bytes somewhere nobody asked
    // for while the UI claimed otherwise.
    if let Some((host, port)) = &ctx.connect_authority {
        return Some((ctx.scheme, host.clone(), *port));
    }

    if let Some(authority) = parts.uri.authority() {
        // Absolute form. A client may address https through a plain proxy
        // connection, which is unusual but legal and stays undecrypted.
        let scheme = match parts.uri.scheme_str() {
            Some("https") => Scheme::Https,
            _ => ctx.scheme,
        };
        let (host, port) = split_authority(authority.as_str(), default_port(scheme))?;
        return Some((scheme, host, port));
    }

    let header = parts.headers.get(http::header::HOST)?.to_str().ok()?;
    let (host, port) = split_authority(header, default_port(ctx.scheme))?;
    Some((ctx.scheme, host, port))
}

/* ------------------------------------------------------------------ */
/* Loop protection                                                     */
/* ------------------------------------------------------------------ */

/// True when a request points back at our own proxy port on this machine.
fn is_self_target(host: &str, port: u16, config: &Config) -> bool {
    if port != config.proxy_port {
        return false;
    }
    let bare = strip_port(host);
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match bare.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip.is_unspecified() || local_addresses().contains(&ip),
        Err(_) => false,
    }
}

fn loop_response(host: &str, port: u16, config: &Config) -> Response<ProxyBody> {
    warn!(%host, port, "refusing a request that points back at the proxy");
    text_response(
        StatusCode::MISDIRECTED_REQUEST,
        format!(
            "{host}:{port} is Proxima's own proxy port, so forwarding this would loop. \
             Point the client at the host you actually want, or open the inspector on port {}.",
            config.ui_port
        ),
    )
}

/// Interface addresses, read once. They only change when the machine moves
/// network, which is not worth a lookup per request.
fn local_addresses() -> &'static Vec<IpAddr> {
    static ADDRESSES: OnceLock<Vec<IpAddr>> = OnceLock::new();
    ADDRESSES.get_or_init(|| match local_ip_address::list_afinet_netifas() {
        Ok(list) => list.into_iter().map(|(_, ip)| ip).collect(),
        Err(err) => {
            debug!(error = %err, "could not list local addresses, loop detection is weaker");
            Vec::new()
        }
    })
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

fn default_port(scheme: Scheme) -> u16 {
    match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    }
}

/// Splits `host:port`, `host`, `[::1]:port` or a bare IPv6 literal.
fn split_authority(target: &str, default: u16) -> Option<(String, u16)> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    if let Some(rest) = target.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        if host.is_empty() {
            return None;
        }
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(text) => text.parse().ok()?,
            None => default,
        };
        return Some((host.to_string(), port));
    }

    match target.rsplit_once(':') {
        // A bare IPv6 literal has several colons and no port at all.
        Some((host, port)) if !host.contains(':') => {
            if host.is_empty() {
                return None;
            }
            Some((host.to_string(), port.parse().ok()?))
        }
        _ => Some((target.to_string(), default)),
    }
}

/// `host[:port]` with the default port left off and IPv6 bracketed.
fn format_authority(host: &str, port: u16, scheme: Scheme) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port(scheme) {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn absolute_uri(scheme: Scheme, authority: &str, path_and_query: &str) -> Option<Uri> {
    Uri::builder()
        .scheme(scheme.as_str())
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .ok()
}

fn body_from(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

fn empty_body() -> ProxyBody {
    body_from(Bytes::new())
}

fn text_response(status: StatusCode, message: impl Into<String>) -> Response<ProxyBody> {
    let body = Bytes::from(message.into());
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(body_from(body))
        .unwrap_or_else(|_| Response::new(empty_body()))
}

/// Resolves once the shutdown signal is set, or once its sender is gone.
async fn shutdown_requested(rx: &mut watch::Receiver<bool>) {
    loop {
        let stop = *rx.borrow();
        if stop {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Prefixed stream                                                     */
/* ------------------------------------------------------------------ */

/// A stream that replays bytes already read from it before continuing.
///
/// Peeking at the first byte to tell TLS from anything else consumes it. Losing
/// it truncates the ClientHello, which fails much later and looks like anything
/// but the cause, so it is buffered here and handed back on the next read.
pub(crate) struct Prefixed<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let take = this.prefix.len().min(buf.remaining());
            if take > 0 {
                let chunk = this.prefix.split_to(take);
                buf.put_slice(&chunk);
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn authority_splitting_covers_the_shapes_a_client_sends() {
        assert_eq!(
            split_authority("example.com:8443", 443),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(
            split_authority("example.com", 443),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(split_authority("::1", 443), Some(("::1".to_string(), 443)));
        assert_eq!(
            split_authority("[::1]:9090", 443),
            Some(("::1".to_string(), 9090))
        );
        assert_eq!(split_authority("[::1]", 443), Some(("::1".to_string(), 443)));
        assert_eq!(split_authority("", 443), None);
        assert_eq!(split_authority("example.com:http", 443), None);
    }

    #[test]
    fn authority_formatting_hides_default_ports_and_brackets_ipv6() {
        assert_eq!(format_authority("example.com", 443, Scheme::Https), "example.com");
        assert_eq!(
            format_authority("example.com", 8443, Scheme::Https),
            "example.com:8443"
        );
        assert_eq!(format_authority("example.com", 80, Scheme::Http), "example.com");
        assert_eq!(format_authority("::1", 443, Scheme::Https), "[::1]");
        assert_eq!(format_authority("::1", 9090, Scheme::Https), "[::1]:9090");
    }

    #[test]
    fn absolute_urls_are_rebuilt_from_origin_form() {
        let uri = absolute_uri(Scheme::Https, "api.example.com", "/v1/users?id=1").unwrap();
        assert_eq!(uri.to_string(), "https://api.example.com/v1/users?id=1");
    }

    #[test]
    fn our_own_proxy_port_is_recognised() {
        let config = Config {
            proxy_port: 9090,
            ..Config::default()
        };
        assert!(is_self_target("127.0.0.1", 9090, &config));
        assert!(is_self_target("localhost", 9090, &config));
        assert!(is_self_target("::1", 9090, &config));
        assert!(!is_self_target("127.0.0.1", 443, &config));
        assert!(!is_self_target("example.com", 9090, &config));
    }

    #[tokio::test]
    async fn a_peeked_byte_is_replayed_before_the_rest() {
        let source: &[u8] = b"\x01\x02\x03";
        let mut stream = Prefixed::new(Bytes::from_static(b"\x16"), source);

        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"\x16\x01\x02\x03".to_vec());
    }

    #[tokio::test]
    async fn a_prefix_longer_than_the_buffer_still_arrives_in_order() {
        let source: &[u8] = b"cd";
        let mut stream = Prefixed::new(Bytes::from_static(b"ab"), source);

        let mut one = [0u8; 1];
        stream.read_exact(&mut one).await.expect("first");
        assert_eq!(&one, b"a");

        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.expect("rest");
        assert_eq!(rest, b"bcd".to_vec());
    }
}
