//! Sending a request to the origin and recording both halves of it.
//!
//! Bodies are teed rather than buffered: every frame is passed on the moment it
//! arrives and a bounded copy is kept for the inspector. Collecting a whole
//! response before forwarding it would deadlock server-sent events and any
//! other long-lived stream, which are precisely the things people reach for a
//! proxy to debug.
//!
//! Each request opens its own upstream connection. Pooling is the obvious
//! optimisation and is deliberately absent: a reused connection hides which TLS
//! version, cipher and certificate a given flow actually got, and those are
//! among the things this tool exists to show.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::debug;

use crate::capture::{BodyWriter, FlowInit, FlowStore};
use crate::config::{Config, UpstreamHttp2};
use crate::types::{
    now_ms, FlowClient, FlowError, FlowId, FlowKind, FlowRequest, FlowResponse, FlowServer,
    FlowState, HttpVersion, Scheme,
};

use super::{headers, websocket, ProxyDeps};

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Everything the forwarder needs that the request itself does not carry.
pub struct ForwardContext {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub client: FlowClient,
    /// What the client's own handshake looked like, when there was one.
    pub server: FlowServer,
    pub intercepted: bool,
}

/// Reusable TLS settings for talking to origins.
pub struct Upstream {
    /// Offers h2 and http/1.1, so the origin picks.
    negotiating: Arc<rustls::ClientConfig>,
    /// Offers http/1.1 only, for `--no-http2` and for upgrades.
    http1_only: Arc<rustls::ClientConfig>,
}

impl Upstream {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            negotiating: Arc::new(tls_config(config, vec![b"h2".to_vec(), b"http/1.1".to_vec()])?),
            http1_only: Arc::new(tls_config(config, vec![b"http/1.1".to_vec()])?),
        })
    }

    /// The TLS settings to dial an origin with. `allow_h2` decides whether h2 is
    /// offered in ALPN at all, which is how `--no-http2` and upgrades pin the
    /// connection to HTTP/1.1.
    pub fn client_config(&self, allow_h2: bool) -> Arc<rustls::ClientConfig> {
        if allow_h2 {
            self.negotiating.clone()
        } else {
            self.http1_only.clone()
        }
    }
}

/// Forwards one request and records the flow it produced.
///
/// Never returns an error: an origin that cannot be reached becomes a failed
/// flow and a 502 the user can read, because a dropped connection is
/// indistinguishable from a broken network.
pub async fn forward(
    mut req: Request<Incoming>,
    ctx: ForwardContext,
    deps: Arc<ProxyDeps>,
) -> Response<ProxyBody> {
    let upgrading = headers::is_websocket_upgrade(req.headers());
    // Taken while the request is still whole: the upgrade lives in its
    // extensions, and after forwarding there is nothing left to attach the
    // client half of the WebSocket to.
    let client_upgrade = upgrading.then(|| hyper::upgrade::on(&mut req));

    let (parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let id = deps.store.create(FlowInit {
        kind: if upgrading {
            FlowKind::Websocket
        } else {
            FlowKind::Http
        },
        intercepted: ctx.intercepted,
        request: FlowRequest {
            method: parts.method.as_str().to_string(),
            url: format!("{}://{}{}", ctx.scheme.as_str(), ctx.authority, path),
            scheme: ctx.scheme,
            authority: ctx.authority.clone(),
            host: ctx.host.clone(),
            port: ctx.port,
            path,
            http_version: HttpVersion::from_http(parts.version),
            headers: headers::to_pairs(&parts.headers),
            body: None,
        },
        client: ctx.client.clone(),
        server: ctx.server.clone(),
        replay_of: None,
    });

    match exchange(parts, body, &ctx, &deps, &id, upgrading, client_upgrade).await {
        Ok(response) => response,
        Err(err) => {
            debug!(host = %ctx.host, port = ctx.port, error = %err, "forwarding failed");
            deps.store.fail(
                &id,
                FlowError {
                    message: format!("{err:#}"),
                    code: Some("upstream".to_string()),
                    likely_pinning: None,
                },
            );
            bad_gateway(&format!("{err:#}"))
        }
    }
}

type ClientUpgrade = hyper::upgrade::OnUpgrade;

#[allow(clippy::too_many_arguments)]
async fn exchange(
    parts: http::request::Parts,
    body: Incoming,
    ctx: &ForwardContext,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
    upgrading: bool,
    client_upgrade: Option<ClientUpgrade>,
) -> Result<Response<ProxyBody>> {
    // The one and only socket to the origin. An HTTPS flow hands it to the TLS
    // handshake rather than dialling again: a second dial would leave the first
    // socket open and idle for the life of the request, and would double the
    // connection count every origin sees.
    let stream = TcpStream::connect((ctx.host.as_str(), ctx.port))
        .await
        .with_context(|| format!("connecting to {}:{}", ctx.host, ctx.port))?;
    let _ = stream.set_nodelay(true);
    let connect_end = now_ms();

    // An upgrade has no meaning over h2 as we speak it, so a WebSocket pins the
    // upstream connection to HTTP/1.1 regardless of what the origin would
    // otherwise have offered.
    let allow_h2 = !upgrading && deps.config.upstream_http2 == UpstreamHttp2::Auto;

    let (response, facts, upstream_upgrade) = match ctx.scheme {
        Scheme::Http => {
            let (response, upgrade) =
                send_http1(stream, parts, body, ctx, deps, id, upgrading).await?;
            (response, None, upgrade)
        }
        Scheme::Https => {
            let tls = tls_handshake(deps, ctx, stream, allow_h2).await?;
            let facts = tls_facts(&tls, &ctx.host);
            let h2 = facts.alpn.as_deref() == Some("h2");
            let (response, upgrade) = if h2 {
                (send_http2(tls, parts, body, ctx, deps, id).await?, None)
            } else {
                send_http1(tls, parts, body, ctx, deps, id, upgrading).await?
            };
            (response, Some(facts), upgrade)
        }
    };

    let response_start = now_ms();
    let (response_parts, response_body) = response.into_parts();
    let status = response_parts.status;
    let response_headers = headers::to_pairs(&response_parts.headers);
    let encoding = headers::content_encoding(&response_parts.headers);
    let mime = headers::content_type(&response_parts.headers);

    deps.store.update(id, |flow| {
        flow.state = FlowState::Streaming;
        flow.timings.connect_end = Some(connect_end);
        flow.timings.response_start = Some(response_start);
        if let Some(facts) = &facts {
            flow.timings.tls_end = facts.tls_end;
            apply_origin_facts(&mut flow.server, facts);
        }
        flow.response = Some(FlowResponse {
            status: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or_default().to_string(),
            http_version: HttpVersion::from_http(response_parts.version),
            headers: response_headers.clone(),
            body: None,
        });
    });

    let mut out = Response::builder()
        .status(status)
        .version(response_parts.version);
    if let Some(map) = out.headers_mut() {
        *map = headers::for_client(&response_parts.headers, status);
    }

    // A 101 means the protocol changes on both sides. From here the connection
    // is frames, not HTTP, and the websocket module takes it over.
    if status == StatusCode::SWITCHING_PROTOCOLS {
        if let (Some(client_upgrade), Some(upstream_upgrade)) = (client_upgrade, upstream_upgrade) {
            let store = deps.store.clone();
            let flow_id = id.clone();
            deps.store.update(id, |flow| {
                flow.kind = FlowKind::Websocket;
                flow.ws_messages.get_or_insert_with(Vec::new);
            });
            tokio::spawn(async move {
                match tokio::try_join!(client_upgrade, upstream_upgrade) {
                    Ok((client, upstream)) => {
                        websocket::pump(
                            TokioIo::new(client),
                            TokioIo::new(upstream),
                            store,
                            flow_id,
                        )
                        .await;
                    }
                    Err(err) => {
                        debug!(error = %err, "an upgraded connection never completed");
                        store.fail(
                            &flow_id,
                            FlowError {
                                message: format!("the upgrade never completed: {err}"),
                                code: Some("upgrade".to_string()),
                                likely_pinning: None,
                            },
                        );
                    }
                }
            });
            // The response body of a 101 is the upgraded stream itself, so
            // nothing is teed here.
            return out
                .body(empty())
                .map_err(|err| anyhow!("building the 101 response: {err}"));
        }

        // A 101 with nothing to join it to: the client did not ask for an
        // upgrade this proxy can carry, or the upstream half never materialised.
        // Relaying it would hand the client upgrade framing over a connection
        // whose two halves are never wired together and whose flow never ends,
        // so the exchange is refused instead and both sockets close. Dropping
        // `response_body` here is what closes the upstream one.
        debug!(%id, "refusing a 101 that cannot be proxied");
        return Err(anyhow!(
            "the origin switched protocols on a request that was not an upgrade this proxy can carry"
        ));
    }

    let teed = tee(
        response_body,
        deps.store.clone(),
        id.clone(),
        Direction::Response,
        encoding,
        mime,
    );
    out.body(teed)
        .map_err(|err| anyhow!("building the response: {err}"))
}

/* ------------------------------------------------------------------ */
/* transports                                                          */
/* ------------------------------------------------------------------ */

async fn send_http1<I>(
    io: I,
    mut parts: http::request::Parts,
    body: Incoming,
    ctx: &ForwardContext,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
    upgrading: bool,
) -> Result<(Response<Incoming>, Option<hyper::upgrade::OnUpgrade>)>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .context("HTTP/1.1 handshake with the origin")?;
    tokio::spawn(async move {
        // with_upgrades keeps the connection alive past a 101 so the upgraded
        // stream stays usable.
        if let Err(err) = conn.with_upgrades().await {
            debug!(error = %err, "upstream connection ended");
        }
    });

    // A direct connection wants origin form; the absolute URI is only for the
    // proxy hop that just ended.
    if let Some(pq) = parts.uri.path_and_query().cloned() {
        if let Ok(uri) = Uri::builder().path_and_query(pq).build() {
            parts.uri = uri;
        }
    }
    parts.headers = headers::for_upstream(&parts.headers, headers::Wire::Http1);
    headers::set_host(&mut parts.headers, &ctx.authority);

    let teed = tee(
        body,
        deps.store.clone(),
        id.clone(),
        Direction::Request,
        headers::content_encoding(&parts.headers),
        headers::content_type(&parts.headers),
    );

    deps.store.update(id, |flow| {
        flow.timings.request_sent = Some(now_ms());
    });
    let mut response = sender
        .send_request(Request::from_parts(parts, teed))
        .await
        .context("sending the request to the origin")?;

    let upgrade = (upgrading && response.status() == StatusCode::SWITCHING_PROTOCOLS)
        .then(|| hyper::upgrade::on(&mut response));
    Ok((response, upgrade))
}

async fn send_http2<I>(
    io: I,
    mut parts: http::request::Parts,
    body: Incoming,
    ctx: &ForwardContext,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
) -> Result<Response<Incoming>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .context("HTTP/2 handshake with the origin")?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            debug!(error = %err, "upstream connection ended");
        }
    });

    // h2 addresses the origin through the :authority pseudo header, which hyper
    // derives from an absolute URI.
    if let Some(uri) = super::absolute_uri(
        ctx.scheme,
        &ctx.authority,
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/"),
    ) {
        parts.uri = uri;
    }
    parts.version = http::Version::HTTP_2;
    // No set_host counterpart to the HTTP/1.1 path: over h2 the addressing is
    // :authority, derived from the URI above, and `for_upstream` drops the
    // client's Host rather than leave a request that contradicts itself.
    parts.headers = headers::for_upstream(&parts.headers, headers::Wire::Http2);

    let teed = tee(
        body,
        deps.store.clone(),
        id.clone(),
        Direction::Request,
        headers::content_encoding(&parts.headers),
        headers::content_type(&parts.headers),
    );

    deps.store.update(id, |flow| {
        flow.timings.request_sent = Some(now_ms());
    });
    sender
        .send_request(Request::from_parts(parts, teed))
        .await
        .context("sending the request to the origin")
}

/// Wraps an already dialled socket in TLS. Takes the stream rather than a host
/// and port on purpose, so there is exactly one place a connection to the origin
/// is opened.
async fn tls_handshake(
    deps: &Arc<ProxyDeps>,
    ctx: &ForwardContext,
    stream: TcpStream,
    allow_h2: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = deps.upstream.client_config(allow_h2);
    // An IP literal is a valid TLS name of its own kind; anything unusable as a
    // name would fail verification anyway, so it fails here with a clear reason.
    let name = ServerName::try_from(ctx.host.clone())
        .with_context(|| format!("{} is not a usable TLS server name", ctx.host))?;

    tokio_rustls::TlsConnector::from(config)
        .connect(name, stream)
        .await
        .with_context(|| format!("TLS handshake with {}", ctx.host))
}

/// What the origin's handshake revealed. Recorded per flow because it is per
/// connection, and this proxy makes one connection per request.
pub(crate) struct TlsFacts {
    pub(crate) sni: Option<String>,
    pub(crate) alpn: Option<String>,
    pub(crate) tls_version: Option<String>,
    pub(crate) cipher: Option<String>,
    pub(crate) cert_fingerprint: Option<String>,
    pub(crate) tls_end: Option<u64>,
}

/// Folds the origin handshake into a flow's [`FlowServer`] record.
///
/// A [`FlowServer`] deliberately describes two different handshakes, and which
/// field belongs to which is fixed:
///
/// * `sni` and `alpn` describe the *client's* handshake with this proxy. They
///   are set when the connection is intercepted and are never filled in from the
///   origin, because an origin ALPN shown as the client's would misrepresent
///   what the client asked for. On a flow with no client handshake they stay
///   empty, which is the honest answer.
/// * `tls_version`, `cipher` and `cert_fingerprint` describe the *origin's*
///   handshake, which is the certificate and cipher this tool exists to reveal.
///   They always come from the origin, overwriting whatever was there.
///
/// Previously `sni` and `alpn` fell back to the origin values when the client
/// side had none, so a single record could mix the two handshakes with nothing
/// to say which was which.
fn apply_origin_facts(server: &mut FlowServer, facts: &TlsFacts) {
    server.tls_version = facts.tls_version.clone();
    server.cipher = facts.cipher.clone();
    server.cert_fingerprint = facts.cert_fingerprint.clone();
}

pub(crate) fn tls_facts(
    tls: &tokio_rustls::client::TlsStream<TcpStream>,
    host: &str,
) -> TlsFacts {
    let (_, conn) = tls.get_ref();
    TlsFacts {
        sni: Some(host.to_string()),
        alpn: conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
        tls_version: conn.protocol_version().map(|v| format!("{v:?}")),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite())),
        cert_fingerprint: conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|cert| fingerprint(cert.as_ref())),
        tls_end: Some(now_ms()),
    }
}

fn fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn tls_config(config: &Config, alpn: Vec<Vec<u8>>) -> Result<rustls::ClientConfig> {
    let mut client = if config.insecure_upstream {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyOrigin))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        for error in &loaded.errors {
            debug!(error = %error, "a system trust root could not be read");
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
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    client.alpn_protocols = alpn;
    Ok(client)
}

/// Used only under `--insecure`, so a staging server with a self-signed
/// certificate can be debugged without a detour through its trust chain.
#[derive(Debug)]
struct AcceptAnyOrigin;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyOrigin {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/* ------------------------------------------------------------------ */
/* body teeing                                                         */
/* ------------------------------------------------------------------ */

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
}

/// Passes a body straight through while keeping a bounded copy.
struct Tee<B> {
    inner: B,
    /// Taken when the body ends, so the capture is filed exactly once.
    pending: Option<Pending>,
}

struct Pending {
    writer: BodyWriter,
    store: Arc<FlowStore>,
    id: FlowId,
    direction: Direction,
    content_encoding: Option<String>,
    content_type: Option<String>,
}

impl Pending {
    fn commit(self) {
        let empty = self.writer.seen() == 0;
        let meta = (!empty).then(|| self.writer.finish(self.content_encoding, self.content_type));
        let direction = self.direction;
        let store = self.store;

        store.update(&self.id, move |flow| match direction {
            Direction::Request => flow.request.body = meta,
            Direction::Response => {
                if let Some(response) = flow.response.as_mut() {
                    response.body = meta;
                }
            }
        });
        if direction == Direction::Response {
            store.finish(&self.id);
        }
    }
}

impl<B> Body for Tee<B>
where
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin,
{
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, hyper::Error>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(data), Some(pending)) = (frame.data_ref(), this.pending.as_mut()) {
                    pending.writer.write(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                // A body that failed mid-stream still recorded what arrived,
                // and how far it got is usually the interesting part.
                if let Some(pending) = this.pending.take() {
                    pending.commit();
                }
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                if let Some(pending) = this.pending.take() {
                    pending.commit();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for Tee<B> {
    fn drop(&mut self) {
        // A client that hangs up mid-response still gets what did arrive.
        if let Some(pending) = self.pending.take() {
            pending.commit();
        }
    }
}

fn tee<B>(
    body: B,
    store: Arc<FlowStore>,
    id: FlowId,
    direction: Direction,
    content_encoding: Option<String>,
    content_type: Option<String>,
) -> ProxyBody
where
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin + Send + Sync + 'static,
{
    let writer = store.bodies().writer(store.max_body_bytes());
    Tee {
        inner: body,
        pending: Some(Pending {
            writer,
            store,
            id,
            direction,
            content_encoding,
            content_type,
        }),
    }
    .boxed()
}

fn empty() -> ProxyBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn bad_gateway(message: &str) -> Response<ProxyBody> {
    let body = Bytes::from(message.to_string());
    let length = body.len();
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CONTENT_LENGTH, length)
        .body(
            http_body_util::Full::new(body)
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| Response::new(empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::FlowStore;
    use crate::types::{FlowQuery, Scheme};
    use http_body_util::Full;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn store() -> Arc<FlowStore> {
        Arc::new(FlowStore::new(16, 1024, 1024 * 1024))
    }

    fn flow(store: &FlowStore) -> FlowId {
        store.create(FlowInit {
            kind: FlowKind::Http,
            intercepted: true,
            request: FlowRequest {
                method: "POST".to_string(),
                url: "https://api.example.com/v1/things".to_string(),
                scheme: Scheme::Https,
                authority: "api.example.com".to_string(),
                host: "api.example.com".to_string(),
                port: 443,
                path: "/v1/things".to_string(),
                http_version: HttpVersion::Http2,
                headers: Vec::new(),
                body: None,
            },
            client: FlowClient {
                address: "192.168.1.20".to_string(),
                port: 51234,
            },
            server: FlowServer::default(),
            replay_of: None,
        })
    }

    /// Drives a teed body to completion the way hyper would.
    async fn drain(body: ProxyBody) -> Vec<u8> {
        let collected = body.collect().await.expect("collect");
        collected.to_bytes().to_vec()
    }

    fn source(bytes: &'static [u8]) -> impl Body<Data = Bytes, Error = hyper::Error> + Unpin {
        Full::new(Bytes::from_static(bytes)).map_err(|never| match never {})
    }

    #[tokio::test]
    async fn a_teed_request_body_reaches_both_the_origin_and_the_store() {
        let store = store();
        let id = flow(&store);
        let teed = tee(
            source(b"{\"hello\":\"world\"}"),
            store.clone(),
            id.clone(),
            Direction::Request,
            None,
            Some("application/json".to_string()),
        );

        assert_eq!(drain(teed).await, b"{\"hello\":\"world\"}");

        let captured = store.get(&id).expect("flow").request.body.expect("body");
        assert_eq!(captured.size, 17);
        assert!(!captured.truncated);
        assert_eq!(captured.content_type.as_deref(), Some("application/json"));
        assert_eq!(
            store.bodies().read(&captured.id).as_deref(),
            Some(&b"{\"hello\":\"world\"}"[..])
        );
    }

    #[tokio::test]
    async fn an_empty_body_records_nothing() {
        let store = store();
        let id = flow(&store);
        let teed = tee(
            source(b""),
            store.clone(),
            id.clone(),
            Direction::Request,
            None,
            None,
        );

        assert!(drain(teed).await.is_empty());
        assert!(
            store.get(&id).expect("flow").request.body.is_none(),
            "an empty body should not occupy the store"
        );
    }

    #[tokio::test]
    async fn a_response_body_completes_the_flow() {
        let store = store();
        let id = flow(&store);
        store.update(&id, |flow| {
            flow.response = Some(FlowResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: HttpVersion::Http2,
                headers: Vec::new(),
                body: None,
            });
        });

        let teed = tee(
            source(b"body bytes"),
            store.clone(),
            id.clone(),
            Direction::Response,
            None,
            None,
        );
        assert_eq!(drain(teed).await, b"body bytes");

        let flow = store.get(&id).expect("flow");
        assert_eq!(flow.state, FlowState::Complete, "the flow never finished");
        assert!(flow.timings.end.is_some());
        assert_eq!(flow.response.unwrap().body.unwrap().size, 10);
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_truncated_but_still_forwarded() {
        // A two byte ceiling, so the tee has to drop most of what it sees.
        let store = Arc::new(FlowStore::new(16, 2, 1024));
        let id = flow(&store);
        let teed = tee(
            source(b"much longer than two bytes"),
            store.clone(),
            id.clone(),
            Direction::Request,
            None,
            None,
        );

        assert_eq!(
            drain(teed).await,
            b"much longer than two bytes",
            "truncating the capture must not truncate the traffic"
        );
        let captured = store.get(&id).expect("flow").request.body.expect("body");
        assert!(captured.truncated);
        assert_eq!(captured.size, 2, "only the retained bytes are stored");
    }

    /* -------------------------------------------------------------- */
    /* the whole forward path                                          */
    /* -------------------------------------------------------------- */

    /// The proxy only needs something that answers; the real setup page is the
    /// API layer's job.
    struct StubSetup;

    impl crate::proxy::SetupHandler for StubSetup {
        fn handle(&self, _parts: &http::request::Parts) -> Response<Bytes> {
            Response::new(Bytes::from_static(b"setup"))
        }
    }

    fn test_deps(temp: &tempfile::TempDir) -> Arc<ProxyDeps> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = Arc::new(Config {
            data_dir: temp.path().to_path_buf(),
            // The origins in these tests never present a certificate at all, so
            // verifying one is not what is being exercised.
            insecure_upstream: true,
            ..Config::default()
        });
        Arc::new(ProxyDeps {
            upstream: Upstream::new(&config).expect("upstream settings"),
            ca: Arc::new(crate::ca::CertAuthority::open(temp.path()).expect("authority")),
            store: Arc::new(FlowStore::new(16, 1024, 1024 * 1024)),
            setup: Arc::new(StubSetup),
            config,
        })
    }

    /// An origin that counts connections and then hangs up. Nothing it does is a
    /// valid response, which is the point: the count is the assertion.
    async fn counting_origin() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let addr = listener.local_addr().expect("origin address");
        let accepts = Arc::new(AtomicUsize::new(0));

        let counter = accepts.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        (addr, accepts)
    }

    /// An origin that answers every request by switching protocols, without
    /// having been asked to.
    async fn origin_switching_protocols() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let addr = listener.local_addr().expect("origin address");

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\n\
                              Connection: Upgrade\r\n\
                              Upgrade: something-else\r\n\r\n",
                        )
                        .await;
                    // Held open, the way a real upgraded connection would be.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });
        addr
    }

    /// Drives one request through `forward` behind a real hyper server, which is
    /// the only way to get a genuine `Request<Incoming>` to hand it.
    async fn forward_one(
        deps: &Arc<ProxyDeps>,
        scheme: Scheme,
        origin: SocketAddr,
    ) -> Response<Incoming> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let proxy = listener.local_addr().expect("proxy address");

        let served = deps.clone();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let deps = served.clone();
                async move {
                    let ctx = ForwardContext {
                        scheme,
                        host: origin.ip().to_string(),
                        port: origin.port(),
                        authority: format!("{}:{}", origin.ip(), origin.port()),
                        client: FlowClient {
                            address: "127.0.0.1".to_string(),
                            port: 51234,
                        },
                        server: FlowServer::default(),
                        intercepted: true,
                    };
                    Ok::<_, std::convert::Infallible>(forward(req, ctx, deps).await)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
        });

        let stream = TcpStream::connect(proxy).await.expect("connect to the proxy");
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });

        sender
            .send_request(
                Request::builder()
                    .uri("/thing")
                    .header(http::header::HOST, "origin.test")
                    .body(empty())
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn an_https_request_opens_exactly_one_connection_to_the_origin() {
        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        let (origin, accepts) = counting_origin().await;

        let response = forward_one(&deps, Scheme::Https, origin).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "an origin that hangs up mid handshake is a failed flow"
        );

        // The handshake can only have failed after the socket it was speaking
        // over was accepted and dropped, so every dial has been counted by now;
        // the pause is only there to absorb scheduling.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "one request must not open a second, unused connection to the origin"
        );
    }

    #[tokio::test]
    async fn a_101_that_cannot_be_proxied_is_refused_rather_than_left_half_open() {
        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        let origin = origin_switching_protocols().await;

        // The request asked for no upgrade, so there is no client half to join
        // the origin's to.
        let response = forward_one(&deps, Scheme::Http, origin).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "a 101 with nothing to join it to must be refused, not relayed"
        );
        assert!(
            !response.headers().contains_key(http::header::UPGRADE),
            "upgrade framing must not reach a client that cannot use it"
        );

        let flows = deps.store.all(&FlowQuery::default());
        let flow = flows.first().expect("the request was recorded");
        assert_eq!(
            flow.state,
            FlowState::Error,
            "a refused upgrade must not leave the flow unfinished"
        );
        assert!(flow.timings.end.is_some(), "the flow never ended");
    }

    #[test]
    fn origin_facts_do_not_overwrite_the_client_side_of_the_handshake() {
        // What the client's own handshake with the proxy looked like.
        let mut server = FlowServer {
            sni: Some("api.example.com".to_string()),
            alpn: Some("h2".to_string()),
            tls_version: Some("TLSv1_2".to_string()),
            ..FlowServer::default()
        };

        apply_origin_facts(
            &mut server,
            &TlsFacts {
                sni: Some("origin.internal".to_string()),
                alpn: Some("http/1.1".to_string()),
                tls_version: Some("TLSv1_3".to_string()),
                cipher: Some("TLS13_AES_128_GCM_SHA256".to_string()),
                cert_fingerprint: Some("AA:BB".to_string()),
                tls_end: Some(1),
            },
        );

        // The origin owns these three.
        assert_eq!(server.tls_version.as_deref(), Some("TLSv1_3"));
        assert_eq!(server.cipher.as_deref(), Some("TLS13_AES_128_GCM_SHA256"));
        assert_eq!(server.cert_fingerprint.as_deref(), Some("AA:BB"));

        // The client owns these two, and an origin value must never appear in
        // them or the record describes two handshakes at once.
        assert_eq!(server.sni.as_deref(), Some("api.example.com"));
        assert_eq!(server.alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn a_flow_with_no_client_handshake_leaves_the_client_fields_empty() {
        let mut server = FlowServer::default();
        apply_origin_facts(
            &mut server,
            &TlsFacts {
                sni: Some("origin.internal".to_string()),
                alpn: Some("http/1.1".to_string()),
                tls_version: Some("TLSv1_3".to_string()),
                cipher: None,
                cert_fingerprint: None,
                tls_end: None,
            },
        );

        assert_eq!(server.tls_version.as_deref(), Some("TLSv1_3"));
        assert!(
            server.sni.is_none() && server.alpn.is_none(),
            "with no client handshake to describe, the honest answer is nothing"
        );
    }

    #[tokio::test]
    async fn dropping_a_body_early_still_records_what_arrived() {
        let store = store();
        let id = flow(&store);
        let teed = tee(
            source(b"partial"),
            store.clone(),
            id.clone(),
            Direction::Request,
            None,
            None,
        );
        drop(teed);

        // Nothing was polled, so nothing was seen, and the flow must not claim
        // a body it never observed.
        assert!(store.get(&id).expect("flow").request.body.is_none());
    }
}
