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
use crate::config::{Config, MockResponse, UpstreamHttp2};
use crate::types::{
    now_ms, FlowClient, FlowError, FlowId, FlowKind, FlowRequest, FlowResponse, FlowServer,
    FlowState, HttpVersion, Scheme,
};

use super::{headers, rewrite, websocket, ProxyDeps};

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
    /// Client H2 multiplex session id when the intercepted TLS ALPN is h2.
    /// Shared across streams on that TLS session; `None` for HTTP/1.x.
    /// See [`crate::types::Flow::connection_id`].
    pub connection_id: Option<String>,
}

/// Reusable TLS settings for talking to origins.
#[derive(Clone)]
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

    let (mut parts, body) = req.into_parts();
    let mut path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let rules = deps.rewrite.snapshot();
    let method_str = parts.method.as_str().to_string();

    // Before the flow is recorded, so the capture shows what is actually sent.
    // A record that disagrees with the wire is worse than no record at all.
    let mut notes = rewrite::apply(
        &rules,
        rewrite::Half::Request,
        &ctx.host,
        &method_str,
        &path,
        &mut parts.headers,
    );
    // Path and query text rewrites run after header match conditions, still
    // before the flow is opened, so the inspector URL matches the wire.
    notes.extend(rewrite::apply_path(
        &rules,
        &ctx.host,
        &method_str,
        &mut path,
    ));
    notes.extend(rewrite::apply_query(
        &rules,
        &ctx.host,
        &method_str,
        &mut path,
    ));
    if let Err(err) = set_request_path_and_query(&mut parts, &path) {
        debug!(error = %err, "rewritten path was not a legal URI path-and-query");
        notes.push(format!("path rewrite not applied to URI: {err}"));
    }

    let id = deps.store.create(FlowInit {
        kind: if upgrading {
            FlowKind::Websocket
        } else {
            FlowKind::Http
        },
        intercepted: ctx.intercepted,
        request: FlowRequest {
            method: method_str.clone(),
            url: format!("{}://{}{}", ctx.scheme.as_str(), ctx.authority, path),
            scheme: ctx.scheme,
            authority: ctx.authority.clone(),
            host: ctx.host.clone(),
            port: ctx.port,
            path: path.clone(),
            http_version: HttpVersion::from_http(parts.version),
            headers: headers::to_pairs(&parts.headers),
            body: None,
        },
        client: ctx.client.clone(),
        server: ctx.server.clone(),
        replay_of: None,
        // TCP path: omit transport. Multiplex identity is independent of it.
        transport: None,
        connection_id: ctx.connection_id.clone(),
        // Prefer None over fake H2 stream ids until the stack exposes a real one.
        stream_id: None,
        upstream_stream_id: None,
    });
    if !notes.is_empty() {
        deps.store.update(&id, |flow| flow.rewrites = notes);
    }

    // Map local: answer without dialling. Checked after request header rewrites
    // so the capture still shows injected headers on the request half.
    if !upgrading {
        if let Some(mock) = rules
            .mock_response(&ctx.host, parts.method.as_str(), &path)
            .cloned()
        {
            match answer_mock(parts, body, &ctx, &deps, &id, mock).await {
                Ok(response) => return response,
                Err(err) => {
                    debug!(%id, error = %err, "map-local mock failed");
                    deps.store.fail(
                        &id,
                        FlowError {
                            message: format!("map local failed: {err:#}"),
                            code: Some("mock".to_string()),
                            likely_pinning: None,
                        },
                    );
                    return bad_gateway(&format!("map local failed: {err:#}"));
                }
            }
        }
    }

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
    let method = parts.method.as_str().to_string();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    // Where this request actually goes, which is not always where it was
    // addressed. The `Host` header is left alone by the redirect on purpose:
    // pointing a name at a local service is only useful if the service still
    // sees itself being addressed as that name.
    let rules = deps.rewrite.snapshot();

    // Request body text rewrite, then HTTP request breakpoint. Both collect the
    // body; rewrite runs first so a held pause (and the origin) see the edited
    // payload. WebSocket upgrades skip both. After this branch the body is
    // always a boxed stream so pause and non-pause share one send path type.
    let (parts, body): (_, ProxyBody) = if upgrading {
        (parts, body.boxed())
    } else {
        let (parts, body) = if rewrite::needs_body_rewrite(
            &rules,
            rewrite::Half::Request,
            &ctx.host,
            &method,
            &path,
        ) {
            maybe_request_body_rewrite(parts, body, deps, id, &rules, &ctx.host, &method, &path)
                .await?
        } else {
            (parts, body.boxed())
        };
        if deps.pauses.any_http_request_enabled() {
            if let Some(rule) =
                deps.pauses
                    .matching_http_request_rule(&ctx.host, &path, &method)
            {
                maybe_http_request_pause(parts, body, ctx, deps, id, &rule).await?
            } else {
                (parts, body)
            }
        } else {
            (parts, body)
        }
    };

    let (dial_host, dial_port) = match rules.dial_target(&ctx.host, &method, &path) {
        Some(target) => {
            let host = target.host.clone();
            let port = target.port.unwrap_or(ctx.port);
            let note = format!("sent to {host}:{port} instead of {}", ctx.authority);
            deps.store.update(id, |flow| flow.rewrites.push(note.clone()));
            debug!(%id, target = %format!("{host}:{port}"), "rule redirected the request");
            (host, port)
        }
        None => (ctx.host.clone(), ctx.port),
    };

    // The one and only socket to the origin. An HTTPS flow hands it to the TLS
    // handshake rather than dialling again: a second dial would leave the first
    // socket open and idle for the life of the request, and would double the
    // connection count every origin sees.
    let stream = TcpStream::connect((dial_host.as_str(), dial_port))
        .await
        .with_context(|| format!("connecting to {dial_host}:{dial_port}"))?;
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
            // The handshake is with whoever answered, so the name verified is
            // the one dialled. A redirect to a local service therefore needs
            // --insecure, which is honest: that service is not holding a
            // certificate for the origin it is standing in for.
            let tls = tls_handshake(deps, &dial_host, stream, allow_h2).await?;
            let facts = tls_facts(&tls, &dial_host);
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
    let (mut response_parts, response_body) = response.into_parts();
    let status = response_parts.status;

    // Before the response is recorded, so what the inspector shows is what the
    // client receives, the same way round as the request half.
    let response_notes = rewrite::apply(
        &rules,
        rewrite::Half::Response,
        &ctx.host,
        &method,
        &path,
        &mut response_parts.headers,
    );

    let response_headers = headers::to_pairs(&response_parts.headers);

    deps.store.update(id, |flow| {
        flow.rewrites.extend(response_notes.iter().cloned());
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

    // A 101 means the protocol changes on both sides. From here the connection
    // is frames, not HTTP, and the websocket module takes it over. Response
    // breakpoints never hold a 101: the body is the upgraded stream itself.
    if status == StatusCode::SWITCHING_PROTOCOLS {
        let mut out = Response::builder()
            .status(status)
            .version(response_parts.version);
        if let Some(map) = out.headers_mut() {
            *map = headers::for_client(&response_parts.headers, status);
        }
        if let (Some(client_upgrade), Some(upstream_upgrade)) = (client_upgrade, upstream_upgrade) {
            let store = deps.store.clone();
            let registry = deps.ws_registry.clone();
            let pauses = deps.pauses.clone();
            let ws_rewrite = deps.ws_rewrite.clone();
            let flow_id = id.clone();
            let ws_host = ctx.host.clone();
            let ws_path = path.clone();
            // End-to-end negotiation: read what the origin accepted. The proxy
            // does not rewrite Sec-WebSocket-Extensions. Join all values so a
            // split header list still parses.
            let ext_joined = {
                let mut parts = Vec::new();
                for val in response_parts
                    .headers
                    .get_all(http::header::SEC_WEBSOCKET_EXTENSIONS)
                {
                    if let Ok(s) = val.to_str() {
                        parts.push(s);
                    }
                }
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join(", "))
                }
            };
            let deflate =
                super::ws_deflate::parse_sec_websocket_extensions(ext_joined.as_deref());
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
                            registry,
                            pauses,
                            ws_rewrite,
                            ws_host,
                            ws_path,
                            deflate,
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

    // Response body text rewrite, then HTTP response breakpoint. Collect only
    // when a rewrite or pause needs the full payload so SSE and other
    // long-lived streams stay streaming when neither applies.
    let (response_parts, response_body) = if upgrading {
        (response_parts, response_body.boxed())
    } else {
        let (response_parts, response_body) = if rewrite::needs_body_rewrite(
            &rules,
            rewrite::Half::Response,
            &ctx.host,
            &method,
            &path,
        ) {
            maybe_response_body_rewrite(
                response_parts,
                response_body,
                deps,
                id,
                &rules,
                &ctx.host,
                &method,
                &path,
            )
            .await?
        } else {
            (response_parts, response_body.boxed())
        };
        if deps.pauses.any_http_response_enabled() {
            if let Some(rule) =
                deps.pauses
                    .matching_http_response_rule(&ctx.host, &path, &method)
            {
                maybe_http_response_pause(
                    response_parts,
                    response_body,
                    ctx,
                    deps,
                    id,
                    &method,
                    &path,
                    &rule,
                )
                .await?
            } else {
                (response_parts, response_body)
            }
        } else {
            (response_parts, response_body)
        }
    };

    let status = response_parts.status;
    let encoding = headers::content_encoding(&response_parts.headers);
    let mime = headers::content_type(&response_parts.headers);

    let mut out = Response::builder()
        .status(status)
        .version(response_parts.version);
    if let Some(map) = out.headers_mut() {
        *map = headers::for_client(&response_parts.headers, status);
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

async fn send_http1<I, B>(
    io: I,
    mut parts: http::request::Parts,
    body: B,
    ctx: &ForwardContext,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
    upgrading: bool,
) -> Result<(Response<Incoming>, Option<hyper::upgrade::OnUpgrade>)>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin + Send + Sync + 'static,
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

async fn send_http2<I, B>(
    io: I,
    mut parts: http::request::Parts,
    body: B,
    ctx: &ForwardContext,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
) -> Result<Response<Incoming>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin + Send + Sync + 'static,
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
    host: &str,
    stream: TcpStream,
    allow_h2: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = deps.upstream.client_config(allow_h2);
    // An IP literal is a valid TLS name of its own kind; anything unusable as a
    // name would fail verification anyway, so it fails here with a clear reason.
    let name = ServerName::try_from(host.to_string())
        .with_context(|| format!("{host} is not a usable TLS server name"))?;

    tokio_rustls::TlsConnector::from(config)
        .connect(name, stream)
        .await
        .with_context(|| format!("TLS handshake with {host}"))
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
/* HTTP request breakpoint                                             */
/* ------------------------------------------------------------------ */

/// Collects the request body, applies matching request-body text rewrites, and
/// rebuilds a body the upstream send path can stream again. Updates
/// Content-Length when the payload length changes.
#[allow(clippy::too_many_arguments)]
async fn maybe_request_body_rewrite(
    mut parts: http::request::Parts,
    body: impl Body<Data = Bytes, Error = hyper::Error> + Send + 'static,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
    rules: &crate::config::RewriteRules,
    host: &str,
    method: &str,
    path: &str,
) -> Result<(http::request::Parts, ProxyBody)> {
    let collected = body
        .collect()
        .await
        .context("reading the request body for a rewrite")?;
    let mut bytes = collected.to_bytes().to_vec();
    let notes = rewrite::apply_body(
        rules,
        rewrite::Half::Request,
        host,
        method,
        path,
        &mut bytes,
    );
    set_content_length(&mut parts.headers, bytes.len());
    if !notes.is_empty() {
        deps.store.update(id, |flow| {
            flow.rewrites.extend(notes);
            flow.request.headers = headers::to_pairs(&parts.headers);
        });
    }
    Ok((parts, full_body(Bytes::from(bytes))))
}

/// Collects the request, holds it if a rule matched, and rebuilds a body the
/// upstream send path can stream again.
async fn maybe_http_request_pause(
    mut parts: http::request::Parts,
    body: impl Body<Data = Bytes, Error = hyper::Error> + Send + 'static,
    ctx: &ForwardContext,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
    rule: &crate::types::BreakpointRule,
) -> Result<(http::request::Parts, ProxyBody)> {
    let collected = body
        .collect()
        .await
        .context("reading the request body for an HTTP breakpoint")?;
    let mut bytes = collected.to_bytes();
    let max = deps.store.max_body_bytes() as usize;
    let truncated = bytes.len() > max;
    if truncated {
        // Capture ceiling only; the held pause still has the full payload so a
        // release can forward everything the client sent.
    }

    let method = parts.method.as_str().to_string();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let url = format!("{}://{}{}", ctx.scheme.as_str(), ctx.authority, path);
    let headers = headers::to_pairs(&parts.headers);

    let Some((pause_id, rx)) = deps.pauses.hold_http_request(
        &deps.store,
        id.clone(),
        method.clone(),
        url.clone(),
        headers.clone(),
        &bytes,
        truncated,
        rule.timeout_ms,
    ) else {
        return Ok((parts, full_body(bytes)));
    };

    deps.store.update(id, |flow| {
        flow.rewrites
            .push("HTTP request paused for breakpoint".into());
    });

    let decision = super::breakpoint::await_decision(
        &deps.pauses,
        &deps.store,
        &pause_id,
        rule.timeout_ms,
        rx,
    )
    .await;

    match decision {
        super::breakpoint::PauseDecision::Drop => {
            anyhow::bail!("HTTP request dropped at breakpoint");
        }
        super::breakpoint::PauseDecision::HttpRelease {
            method: new_method,
            url: new_url,
            status: _,
            headers: new_headers,
            body: new_body,
        } => {
            if let Ok(m) = new_method.parse::<http::Method>() {
                parts.method = m;
            }
            if let Ok(uri) = new_url.parse::<Uri>() {
                // Keep path for dial matching: when only the body was edited the
                // URL is unchanged; when it changes, absolute form is accepted.
                if let Some(pq) = uri.path_and_query() {
                    if let Ok(path_only) = Uri::builder().path_and_query(pq.clone()).build() {
                        parts.uri = path_only;
                    }
                }
            }
            let mut map = http::HeaderMap::new();
            for (name, value) in &new_headers {
                if let (Ok(n), Ok(v)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::header::HeaderValue::from_str(value),
                ) {
                    map.append(n, v);
                }
            }
            parts.headers = map;
            bytes = Bytes::from(new_body);
            deps.store.update(id, |flow| {
                flow.rewrites
                    .push("HTTP request released from breakpoint".into());
                flow.request.method = parts.method.as_str().to_string();
                flow.request.headers = headers::to_pairs(&parts.headers);
            });
            Ok((parts, full_body(bytes)))
        }
        super::breakpoint::PauseDecision::Release { payload, .. } => {
            // Mis-routed WS decision: treat payload as body, keep headers.
            Ok((parts, full_body(Bytes::from(payload))))
        }
    }
}

/* ------------------------------------------------------------------ */
/* HTTP response breakpoint                                            */
/* ------------------------------------------------------------------ */

/// Collects the origin response body, applies matching response-body text
/// rewrites, and rebuilds a body the client path can stream again.
#[allow(clippy::too_many_arguments)]
async fn maybe_response_body_rewrite(
    mut parts: http::response::Parts,
    body: impl Body<Data = Bytes, Error = hyper::Error> + Send + 'static,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
    rules: &crate::config::RewriteRules,
    host: &str,
    method: &str,
    path: &str,
) -> Result<(http::response::Parts, ProxyBody)> {
    let collected = body
        .collect()
        .await
        .context("reading the response body for a rewrite")?;
    let mut bytes = collected.to_bytes().to_vec();
    let notes = rewrite::apply_body(
        rules,
        rewrite::Half::Response,
        host,
        method,
        path,
        &mut bytes,
    );
    set_content_length(&mut parts.headers, bytes.len());
    if !notes.is_empty() {
        let response_headers = headers::to_pairs(&parts.headers);
        deps.store.update(id, |flow| {
            flow.rewrites.extend(notes);
            if let Some(response) = flow.response.as_mut() {
                response.headers = response_headers;
            }
        });
    }
    Ok((parts, full_body(Bytes::from(bytes))))
}

/// Collects the origin response, holds it if a rule matched, and rebuilds a
/// body the client path can stream again.
#[allow(clippy::too_many_arguments)]
async fn maybe_http_response_pause(
    mut parts: http::response::Parts,
    body: impl Body<Data = Bytes, Error = hyper::Error> + Send + 'static,
    ctx: &ForwardContext,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
    method: &str,
    path: &str,
    rule: &crate::types::BreakpointRule,
) -> Result<(http::response::Parts, ProxyBody)> {
    let collected = body
        .collect()
        .await
        .context("reading the response body for an HTTP breakpoint")?;
    let mut bytes = collected.to_bytes();
    let max = deps.store.max_body_bytes() as usize;
    let truncated = bytes.len() > max;
    if truncated {
        // Capture ceiling only; the held pause still has the full payload so a
        // release can forward everything the origin sent.
    }

    let url = format!("{}://{}{}", ctx.scheme.as_str(), ctx.authority, path);
    let headers = headers::to_pairs(&parts.headers);
    let status = parts.status.as_u16();

    let Some((pause_id, rx)) = deps.pauses.hold_http_response(
        &deps.store,
        id.clone(),
        method.to_string(),
        url,
        status,
        headers,
        &bytes,
        truncated,
        rule.timeout_ms,
    ) else {
        return Ok((parts, full_body(bytes)));
    };

    deps.store.update(id, |flow| {
        flow.rewrites
            .push("HTTP response paused for breakpoint".into());
    });

    let decision = super::breakpoint::await_decision(
        &deps.pauses,
        &deps.store,
        &pause_id,
        rule.timeout_ms,
        rx,
    )
    .await;

    match decision {
        super::breakpoint::PauseDecision::Drop => {
            anyhow::bail!("HTTP response dropped at breakpoint");
        }
        super::breakpoint::PauseDecision::HttpRelease {
            method: _method,
            url: _url,
            status: new_status,
            headers: new_headers,
            body: new_body,
        } => {
            if new_status != 0 {
                if let Ok(s) = StatusCode::from_u16(new_status) {
                    parts.status = s;
                }
            }
            let mut map = http::HeaderMap::new();
            for (name, value) in &new_headers {
                if let (Ok(n), Ok(v)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::header::HeaderValue::from_str(value),
                ) {
                    map.append(n, v);
                }
            }
            parts.headers = map;
            bytes = Bytes::from(new_body);
            let response_headers = headers::to_pairs(&parts.headers);
            deps.store.update(id, |flow| {
                flow.rewrites
                    .push("HTTP response released from breakpoint".into());
                if let Some(response) = flow.response.as_mut() {
                    response.status = parts.status.as_u16();
                    response.status_text = parts
                        .status
                        .canonical_reason()
                        .unwrap_or_default()
                        .to_string();
                    response.headers = response_headers;
                }
            });
            Ok((parts, full_body(bytes)))
        }
        super::breakpoint::PauseDecision::Release { payload, .. } => {
            // Mis-routed WS decision: treat payload as body, keep status/headers.
            Ok((parts, full_body(Bytes::from(payload))))
        }
    }
}

/* ------------------------------------------------------------------ */
/* map local / mock                                                    */
/* ------------------------------------------------------------------ */

/// Serves a configured mock without dialling the origin.
///
/// The client body is still drained and captured so the request half is
/// complete; the response is built from the mock rule and marked on the flow.
async fn answer_mock(
    parts: http::request::Parts,
    body: Incoming,
    _ctx: &ForwardContext,
    deps: &Arc<ProxyDeps>,
    id: &FlowId,
    mock: MockResponse,
) -> Result<Response<ProxyBody>> {
    // Drain and capture the request body the same way a real forward would.
    let encoding = headers::content_encoding(&parts.headers);
    let mime = headers::content_type(&parts.headers);
    let collected = body
        .collect()
        .await
        .context("reading the request body for map local")?;
    let req_bytes = collected.to_bytes();
    if !req_bytes.is_empty() {
        let mut writer = deps.store.bodies().writer(deps.store.max_body_bytes());
        writer.write(&req_bytes);
        let meta = writer.finish(encoding, mime);
        deps.store.update(id, |flow| {
            flow.request.body = Some(meta);
            flow.timings.request_sent = Some(now_ms());
        });
    } else {
        deps.store.update(id, |flow| {
            flow.timings.request_sent = Some(now_ms());
        });
    }

    let status_code = if mock.status == 0 {
        StatusCode::OK
    } else {
        StatusCode::from_u16(mock.status).unwrap_or(StatusCode::OK)
    };
    let body_bytes = mock_body_bytes(&mock)?;
    let mut header_pairs: Vec<(String, String)> = mock.headers.clone();
    if !header_pairs
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-type"))
        && !body_bytes.is_empty()
    {
        header_pairs.push(("content-type".into(), "application/octet-stream".into()));
    }
    if !header_pairs
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
    {
        header_pairs.push(("content-length".into(), body_bytes.len().to_string()));
    }

    let mut note = format!("mocked response {status_code} (map local)");
    if let Some(path) = mock.body_file.as_deref() {
        note.push_str(&format!(" from file {path}"));
    }

    let response_start = now_ms();
    let mut resp_meta = None;
    if !body_bytes.is_empty() {
        let mut writer = deps.store.bodies().writer(deps.store.max_body_bytes());
        writer.write(&body_bytes);
        let ct = header_pairs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());
        resp_meta = Some(writer.finish(None, ct));
    }

    deps.store.update(id, |flow| {
        flow.mocked = true;
        flow.rewrites.push(note);
        flow.state = FlowState::Complete;
        flow.timings.response_start = Some(response_start);
        flow.timings.end = Some(now_ms());
        flow.response = Some(FlowResponse {
            status: status_code.as_u16(),
            status_text: status_code
                .canonical_reason()
                .unwrap_or("Mocked")
                .to_string(),
            http_version: HttpVersion::Http11,
            headers: header_pairs.clone(),
            body: resp_meta,
        });
    });
    deps.store.finish(id);

    let mut builder = Response::builder().status(status_code);
    for (name, value) in &header_pairs {
        if let (Ok(n), Ok(v)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            builder = builder.header(n, v);
        }
    }
    let response = builder
        .body(full_body(body_bytes))
        .context("building the mocked response")?;
    Ok(response)
}

fn mock_body_bytes(mock: &MockResponse) -> Result<Bytes> {
    if let Some(path) = mock.body_file.as_deref() {
        match std::fs::read(path) {
            Ok(bytes) => return Ok(Bytes::from(bytes)),
            Err(err) => {
                if mock.body.is_none() {
                    return Err(anyhow!("could not read mock body file {path}: {err}"));
                }
                debug!(path, error = %err, "mock body_file unreadable; falling back to body");
            }
        }
    }
    Ok(Bytes::from(
        mock.body.clone().unwrap_or_default().into_bytes(),
    ))
}

fn full_body(bytes: Bytes) -> ProxyBody {
    use http_body_util::Full;
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed()
}

/// Rebuild `parts.uri` path-and-query after a path/query text rewrite, keeping
/// scheme and authority when the request used absolute-form.
fn set_request_path_and_query(
    parts: &mut http::request::Parts,
    path_and_query: &str,
) -> Result<()> {
    let mut builder = Uri::builder();
    if let Some(scheme) = parts.uri.scheme() {
        builder = builder.scheme(scheme.clone());
    }
    if let Some(authority) = parts.uri.authority() {
        builder = builder.authority(authority.clone());
    }
    let uri = builder
        .path_and_query(path_and_query)
        .build()
        .map_err(|err| anyhow!("illegal path-and-query after rewrite: {err}"))?;
    parts.uri = uri;
    Ok(())
}

/// After a body length change, drop Transfer-Encoding and set Content-Length so
/// the next hop does not hang waiting for a framed body of the old size.
fn set_content_length(headers: &mut http::HeaderMap, len: usize) {
    headers.remove(http::header::TRANSFER_ENCODING);
    if let Ok(value) = http::HeaderValue::from_str(&len.to_string()) {
        headers.insert(http::header::CONTENT_LENGTH, value);
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
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
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
            ws_registry: Arc::new(websocket::WsRegistry::new()),
            pauses: Arc::new(crate::proxy::breakpoint::PauseHub::new()),
            ws_rewrite: crate::proxy::ws_rewrite::WsRewriteHub::empty(),
            rewrite: crate::proxy::rewrite::RewriteHub::empty(),
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
                        connection_id: None,
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

    /* -------------------------------------------------------------- */
    /* HTTP response breakpoints                                       */
    /* -------------------------------------------------------------- */

    /// Origin that answers every request with a fixed status, headers and body.
    async fn origin_http_response(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static [u8],
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let addr = listener.local_addr().expect("origin address");

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let body = body;
                let headers = headers;
                tokio::spawn(async move {
                    // Drain the request so the origin can answer.
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let mut msg = format!("HTTP/1.1 {status} OK\r\n");
                    for (name, value) in headers {
                        msg.push_str(&format!("{name}: {value}\r\n"));
                    }
                    msg.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
                    let mut wire = msg.into_bytes();
                    wire.extend_from_slice(body);
                    let _ = stream.write_all(&wire).await;
                });
            }
        });
        addr
    }

    fn response_rule(timeout_ms: u64) -> crate::types::BreakpointRule {
        crate::types::BreakpointRule {
            id: "resp".into(),
            enabled: true,
            kind: crate::types::PauseKind::Http,
            hosts: vec![],
            path_prefix: None,
            directions: vec![],
            opcodes: vec![],
            timeout_ms,
            http_half: Some(crate::types::HttpPauseHalf::Response),
            methods: vec![],
        }
    }

    #[tokio::test]
    async fn response_breakpoint_timeout_releases_original_body() {
        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        deps.pauses.set_rules(crate::types::BreakpointRulesBody {
            rules: vec![response_rule(1_000)],
        });
        let origin =
            origin_http_response(200, &[("Content-Type", "text/plain")], b"origin-body").await;

        let response = forward_one(&deps, Scheme::Http, origin).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(&body[..], b"origin-body");

        let flows = deps.store.all(&FlowQuery::default());
        let flow = flows.first().expect("recorded flow");
        assert!(
            flow.rewrites
                .iter()
                .any(|n| n.contains("HTTP response paused")),
            "expected pause note, got {:?}",
            flow.rewrites
        );
        assert!(
            flow.rewrites
                .iter()
                .any(|n| n.contains("HTTP response released")),
            "expected release note, got {:?}",
            flow.rewrites
        );
        assert_eq!(
            flow.response.as_ref().map(|r| r.status),
            Some(200)
        );
    }

    #[tokio::test]
    async fn response_breakpoint_release_can_edit_status_and_body() {
        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        deps.pauses.set_rules(crate::types::BreakpointRulesBody {
            // Long timeout; the test resolves from the event stream.
            rules: vec![response_rule(60_000)],
        });
        let origin =
            origin_http_response(200, &[("Content-Type", "text/plain")], b"origin-body").await;

        let pauses = deps.pauses.clone();
        let store = deps.store.clone();
        let mut events = store.subscribe();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(crate::types::ProxyEvent::PauseHit { pause }) => {
                        let _ = pauses.resolve(
                            &store,
                            &pause.pause_id,
                            crate::proxy::breakpoint::PauseDecision::HttpRelease {
                                method: "GET".into(),
                                url: pause
                                    .http
                                    .as_ref()
                                    .map(|h| h.url.clone())
                                    .unwrap_or_default(),
                                status: 418,
                                headers: vec![("content-type".into(), "text/plain".into())],
                                body: b"edited-body".to_vec(),
                            },
                            crate::types::PauseResolveReason::User,
                        );
                        return;
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });

        let response = forward_one(&deps, Scheme::Http, origin).await;
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(&body[..], b"edited-body");

        let flows = deps.store.all(&FlowQuery::default());
        let flow = flows.first().expect("recorded flow");
        assert_eq!(
            flow.response.as_ref().map(|r| r.status),
            Some(418)
        );
    }

    #[tokio::test]
    async fn response_breakpoint_drop_fails_the_flow() {
        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        deps.pauses.set_rules(crate::types::BreakpointRulesBody {
            rules: vec![response_rule(60_000)],
        });
        let origin =
            origin_http_response(200, &[("Content-Type", "text/plain")], b"origin-body").await;

        let pauses = deps.pauses.clone();
        let store = deps.store.clone();
        let mut events = store.subscribe();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(crate::types::ProxyEvent::PauseHit { pause }) => {
                        let _ = pauses.resolve(
                            &store,
                            &pause.pause_id,
                            crate::proxy::breakpoint::PauseDecision::Drop,
                            crate::types::PauseResolveReason::User,
                        );
                        return;
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });

        let response = forward_one(&deps, Scheme::Http, origin).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let flows = deps.store.all(&FlowQuery::default());
        let flow = flows.first().expect("recorded flow");
        assert_eq!(flow.state, FlowState::Error);
        assert!(
            flow.error
                .as_ref()
                .map(|e| e.message.contains("dropped at breakpoint"))
                .unwrap_or(false),
            "expected drop error, got {:?}",
            flow.error
        );
    }

    #[tokio::test]
    async fn without_response_rule_no_pause_notes_are_written() {
        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        // No response-half rules: streaming path, no pause notes.
        deps.pauses.set_rules(crate::types::BreakpointRulesBody {
            rules: vec![],
        });
        let origin =
            origin_http_response(200, &[("Content-Type", "text/plain")], b"plain").await;

        let response = forward_one(&deps, Scheme::Http, origin).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(&body[..], b"plain");

        let flows = deps.store.all(&FlowQuery::default());
        let flow = flows.first().expect("recorded flow");
        assert!(
            !flow
                .rewrites
                .iter()
                .any(|n| n.contains("HTTP response paused")),
            "response half must not pause without a response rule: {:?}",
            flow.rewrites
        );
    }

    /* -------------------------------------------------------------- */
    /* path / query / body text rewrites                               */
    /* -------------------------------------------------------------- */

    /// Origin that records the request path and body of the first request,
    /// then answers 200 with a fixed body so the client can finish.
    async fn origin_capture_request() -> (SocketAddr, Arc<parking_lot::Mutex<(String, Vec<u8>)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let addr = listener.local_addr().expect("origin address");
        let captured = Arc::new(parking_lot::Mutex::new((String::new(), Vec::new())));
        let slot = captured.clone();

        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 16 * 1024];
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await
                .unwrap_or(0);
            buf.truncate(n);
            // Split headers / body on the first blank line.
            let (head, body) = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = &buf[..pos];
                let body = buf[pos + 4..].to_vec();
                (head, body)
            } else {
                (buf.as_slice(), Vec::new())
            };
            let head_str = String::from_utf8_lossy(head);
            let path = head_str
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            *slot.lock() = (path, body);

            let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            let _ = stream.write_all(reply).await;
        });
        (addr, captured)
    }

    /// POST a body through `forward` the same way `forward_one` does for GET.
    async fn forward_post(
        deps: &Arc<ProxyDeps>,
        scheme: Scheme,
        origin: SocketAddr,
        path: &str,
        body: &'static [u8],
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
                        connection_id: None,
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
                    .method("POST")
                    .uri(path)
                    .header(http::header::HOST, "origin.test")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header(http::header::CONTENT_LENGTH, body.len())
                    .body(full_body(Bytes::from_static(body)))
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn a_request_body_text_replace_reaches_the_origin_and_leaves_a_note() {
        use crate::config::{BodyRewrite, RewriteRule, RewriteRulesBody, TextReplace};

        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        deps.rewrite.set_rules(RewriteRulesBody {
            rules: vec![RewriteRule {
                request_body: Some(BodyRewrite {
                    replacements: vec![TextReplace {
                        find: "secret".into(),
                        replace: "redacted".into(),
                    }],
                    max_bytes: 0,
                }),
                ..RewriteRule::default()
            }],
        });

        let (origin, captured) = origin_capture_request().await;
        let response = forward_post(
            &deps,
            Scheme::Http,
            origin,
            "/api/submit",
            br#"{"token":"secret"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let (path, body) = captured.lock().clone();
        assert_eq!(path, "/api/submit");
        assert_eq!(
            body.as_slice(),
            br#"{"token":"redacted"}"#,
            "origin must see the rewritten body, not the client original"
        );

        let flows = deps.store.all(&FlowQuery::default());
        let flow = flows.first().expect("recorded flow");
        assert!(
            flow.rewrites
                .iter()
                .any(|n| n.contains("request body") && n.contains("secret")),
            "expected a request body rewrite note, got {:?}",
            flow.rewrites
        );
        // Capture shows wire bytes (post-rewrite), same honesty as headers.
        let meta = flow.request.body.as_ref().expect("request body meta");
        assert_eq!(
            deps.store.bodies().read(&meta.id).as_deref(),
            Some(&br#"{"token":"redacted"}"#[..])
        );
    }

    #[tokio::test]
    async fn a_path_rewrite_is_what_the_origin_sees() {
        use crate::config::{RewriteRule, RewriteRulesBody, TextReplace};

        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        deps.rewrite.set_rules(RewriteRulesBody {
            rules: vec![RewriteRule {
                path_replacements: vec![TextReplace {
                    find: "/v1/".into(),
                    replace: "/v2/".into(),
                }],
                ..RewriteRule::default()
            }],
        });

        let (origin, captured) = origin_capture_request().await;
        let response = forward_post(&deps, Scheme::Http, origin, "/v1/users", b"{}").await;
        assert_eq!(response.status(), StatusCode::OK);

        let (path, _) = captured.lock().clone();
        assert_eq!(path, "/v2/users", "origin must see the rewritten path");

        let flows = deps.store.all(&FlowQuery::default());
        let flow = flows.first().expect("recorded flow");
        assert_eq!(flow.request.path, "/v2/users");
        assert!(
            flow.rewrites.iter().any(|n| n.contains("path replaced")),
            "expected a path rewrite note, got {:?}",
            flow.rewrites
        );
    }

    #[tokio::test]
    async fn without_body_rewrite_rules_the_body_is_not_force_collected() {
        // Smoke: a POST with no body rewrite still reaches the origin unchanged
        // and leaves no body-rewrite notes (streaming tee path).
        let temp = tempfile::tempdir().expect("temp dir");
        let deps = test_deps(&temp);
        let (origin, captured) = origin_capture_request().await;
        let response = forward_post(
            &deps,
            Scheme::Http,
            origin,
            "/plain",
            br#"{"keep":"me"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let (_, body) = captured.lock().clone();
        assert_eq!(body.as_slice(), br#"{"keep":"me"}"#);

        let flows = deps.store.all(&FlowQuery::default());
        let flow = flows.first().expect("recorded flow");
        assert!(
            !flow.rewrites.iter().any(|n| n.contains("body")),
            "no body rewrite rules must leave no body notes: {:?}",
            flow.rewrites
        );
    }
}
