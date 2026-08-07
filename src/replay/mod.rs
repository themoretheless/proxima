//! Re-sending captured requests, and composing new ones from scratch.
//!
//! Replay is deliberately not a second proxy. It builds one request, opens one
//! connection, reads the whole answer and records it as an ordinary [`Flow`]
//! with [`Flow::replay_of`] pointing at whatever it came from. Nothing streams,
//! because the caller is an inspector waiting on a JSON reply rather than a
//! phone waiting on bytes, and a bounded read is what keeps a composed request
//! against a firehose endpoint from eating the process.
//!
//! Both entry points take the same shape. [`SendSpec`] is a set of overrides:
//! [`ReplayEngine::send`] needs a URL because there is nothing underneath it,
//! and [`ReplayEngine::from_flow`] takes anything omitted from the captured
//! request instead.
//!
//! WebSocket frame replay lives in [`ws`]: it reuses the live inject path
//! rather than opening a second HTTP connection.

pub mod collections;
pub mod curl;
pub mod vars;
pub mod ws;

use std::sync::Arc;

use anyhow::{anyhow, bail, Context as _, Result};
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::debug;

use crate::capture::{FlowInit, FlowStore};
use crate::config::{strip_port, Config, UpstreamHttp2};
use crate::proxy::forward::{self, Upstream};
use crate::proxy::headers;
use crate::types::{
    now_ms, Flow, FlowClient, FlowError, FlowId, FlowKind, FlowRequest, FlowResponse, FlowServer,
    FlowState, FlowTimings, HeaderPair, HttpVersion, Scheme,
};

pub use collections::{
    Collection, CollectionStore, Environment, RequestRevision, SavedRequest, SendHistoryEntry,
};
pub use curl::to_curl;
pub use ws::{
    execute_live, inject_error_message, is_injectable_opcode, plan_frames, parse_directions,
    replay_compose, replay_live, resolve_payload, ComposeDeps, ComposeError, PlanError,
    PlannedFrame, WsReplayRequest, WsReplayResult, DEFAULT_MAX_FRAMES,
};

/// True for a header that describes one connection rather than the request, and
/// so must never be carried onto a new one.
pub fn is_hop_by_hop(name: &str) -> bool {
    headers::is_hop_by_hop_str(name)
}

/// True for an HTTP/2 pseudo header. They are captured because the UI shows the
/// request as it arrived, but they are part of the framing and are rebuilt from
/// the method and URL on the way back out.
pub fn is_pseudo_header(name: &str) -> bool {
    name.starts_with(':')
}

/* ------------------------------------------------------------------ */
/* wire types                                                          */
/* ------------------------------------------------------------------ */

/// The body of `POST /api/send` and `POST /api/flows/{id}/replay`.
///
/// Every field is optional so that replay can express "leave this as captured".
/// `bodyBase64` distinguishes three cases and needs all three: absent means
/// keep the captured body, `null` means send an empty one, and a string is the
/// raw bytes to send.
/// Unknown keys are refused rather than dropped. Serde's default is to ignore
/// them, which turns a field nothing implements into a request that quietly
/// does something other than what the caller asked for.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendSpec {
    pub method: Option<String>,
    pub url: Option<String>,
    pub headers: Option<Vec<HeaderPair>>,
    #[serde(default, deserialize_with = "present_or_absent")]
    pub body_base64: Option<Option<String>>,
    /// Environment whose variables are applied as `{{name}}` before send.
    /// When omitted, the store's active environment is used if one is set.
    #[serde(default)]
    pub environment_id: Option<String>,
}

/// Replay overrides are the same shape as a composed request; the difference is
/// only where the unset fields come from.
pub type SendEdits = SendSpec;

/// Deserialises into `Some(_)` whenever the field appeared at all, so an
/// explicit `null` stays distinguishable from an omitted key.
fn present_or_absent<'de, D>(de: D) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(de).map(Some)
}

/// The reply to both endpoints.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResult {
    /// The flow this send was recorded as, so the UI can open it in the list.
    pub flow_id: FlowId,
    pub status: u16,
    pub status_text: String,
    /// What the origin answered with, which is not necessarily what was asked
    /// for: an HTTP/1.1 request can come back as HTTP/1.0.
    pub http_version: HttpVersion,
    pub headers: Vec<HeaderPair>,
    /// Base64 of the response bytes as received, subject to the same capture
    /// ceiling as any other body.
    pub body_base64: String,
    pub timings: FlowTimings,
}

/* ------------------------------------------------------------------ */
/* engine                                                              */
/* ------------------------------------------------------------------ */

pub struct ReplayEngine {
    config: Arc<Config>,
    store: Arc<FlowStore>,
    collections: CollectionStore,
    upstream: Upstream,
}

impl ReplayEngine {
    pub fn new(config: Arc<Config>, store: Arc<FlowStore>) -> Result<Self> {
        let collections = CollectionStore::open(&config.data_dir)?;
        let upstream = Upstream::new(&config)?;
        Ok(Self {
            config,
            store,
            collections,
            upstream,
        })
    }

    pub fn collections(&self) -> &CollectionStore {
        &self.collections
    }

    /// Upstream TLS settings used for compose WebSocket dials (HTTP/1.1 only).
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// Composes and sends a request that was never captured.
    pub async fn send(&self, spec: SendSpec) -> Result<SendResult> {
        let vars = self
            .collections
            .variables_for(spec.environment_id.as_deref());
        let url = spec
            .url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| anyhow!("a composed request needs a url"))?;
        let url = vars::interpolate(url, &vars);

        let headers = vars::interpolate_headers(&spec.headers.unwrap_or_default(), &vars);
        let body = match spec.body_base64 {
            Some(Some(encoded)) => {
                let raw = decode_base64(&encoded)?;
                interpolate_body_bytes(&raw, &vars)
            }
            Some(None) | None => Bytes::new(),
        };

        let outgoing = Outgoing {
            method: method_of(spec.method.as_deref(), "GET")?,
            target: Target::parse(&url)?,
            headers,
            body,
        };
        self.execute(outgoing, None).await
    }

    /// Re-sends a captured request. Anything `edits` leaves out is taken from
    /// the flow as it was recorded.
    pub async fn from_flow(&self, id: &str, edits: SendEdits) -> Result<SendResult> {
        let flow = self
            .store
            .get(id)
            .ok_or_else(|| anyhow!("no flow with that id"))?;

        let vars = self
            .collections
            .variables_for(edits.environment_id.as_deref());

        let url = edits
            .url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .unwrap_or(flow.request.url.as_str());
        let url = vars::interpolate(url, &vars);

        let headers = vars::interpolate_headers(
            &edits
                .headers
                .unwrap_or_else(|| flow.request.headers.clone()),
            &vars,
        );
        let body = match edits.body_base64 {
            Some(Some(encoded)) => {
                let raw = decode_base64(&encoded)?;
                interpolate_body_bytes(&raw, &vars)
            }
            Some(None) => Bytes::new(),
            None => self.captured_body(&flow),
        };

        let outgoing = Outgoing {
            method: method_of(edits.method.as_deref(), &flow.request.method)?,
            target: Target::parse(&url)?,
            headers,
            body,
        };
        self.execute(outgoing, Some(flow.id)).await
    }

    /// The request body exactly as it went past the first time. It is not
    /// decoded: the captured `Content-Encoding` is replayed alongside it, so
    /// decoding here would contradict the header.
    fn captured_body(&self, flow: &Flow) -> Bytes {
        let Some(meta) = flow.request.body.as_ref() else {
            return Bytes::new();
        };
        if meta.truncated {
            debug!(
                flow = %flow.id,
                "replaying a request whose captured body was truncated at the capture limit"
            );
        }
        self.store.bodies().read(&meta.id).unwrap_or_default()
    }

    async fn execute(&self, outgoing: Outgoing, replay_of: Option<FlowId>) -> Result<SendResult> {
        let sanitised = outgoing.header_map();
        let target = &outgoing.target;

        let id = self.store.create(FlowInit {
            kind: FlowKind::Http,
            // We built this request ourselves, so there is nothing opaque about
            // it whatever the scheme turns out to be.
            intercepted: true,
            request: FlowRequest {
                method: outgoing.method.as_str().to_string(),
                url: target.url.clone(),
                scheme: target.scheme,
                authority: target.authority.clone(),
                host: target.host.clone(),
                port: target.port,
                path: target.path.clone(),
                // Overwritten below with whatever was actually negotiated.
                http_version: HttpVersion::Http11,
                headers: headers::to_pairs(&sanitised),
                body: None,
            },
            client: FlowClient {
                address: "127.0.0.1".to_string(),
                port: 0,
            },
            server: FlowServer::default(),
            replay_of,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });

        match self.exchange(&id, outgoing, sanitised).await {
            Ok(result) => Ok(result),
            Err(err) => {
                self.store.fail(
                    &id,
                    FlowError {
                        message: format!("{err:#}"),
                        code: Some("replay".to_string()),
                        likely_pinning: None,
                    },
                );
                Err(err)
            }
        }
    }

    async fn exchange(
        &self,
        id: &FlowId,
        outgoing: Outgoing,
        sanitised: HeaderMap,
    ) -> Result<SendResult> {
        let target = &outgoing.target;
        let limit = self.store.max_body_bytes();

        // The request body is known in full before anything is sent, so it is
        // filed straight away rather than teed.
        let mut writer = self.store.bodies().writer(limit);
        writer.write(&outgoing.body);
        let request_meta = (writer.seen() > 0).then(|| {
            writer.finish(
                headers::content_encoding(&sanitised),
                headers::content_type(&sanitised),
            )
        });
        self.store.update(id, |flow| {
            flow.request.body = request_meta;
        });

        let allow_h2 = self.config.upstream_http2 == UpstreamHttp2::Auto;
        let connect_host = strip_port(&target.host).to_string();

        let stream = TcpStream::connect((connect_host.as_str(), target.port))
            .await
            .with_context(|| format!("connecting to {}:{}", connect_host, target.port))?;
        let _ = stream.set_nodelay(true);
        let connect_end = now_ms();

        // `request_sent` is taken on the way in, not on the way out: the send
        // and the wait for a reply are one await, and stamping it afterwards
        // would fold the whole server think time into it and leave every replay
        // reporting a response that arrived before it was asked for.
        let (response, facts, sent_version, request_sent) = match target.scheme {
            Scheme::Http => {
                let request_sent = now_ms();
                let response = send_http1(stream, &outgoing, sanitised).await?;
                (response, None, HttpVersion::Http11, request_sent)
            }
            Scheme::Https => {
                let name = ServerName::try_from(connect_host.clone())
                    .with_context(|| format!("{connect_host} is not a usable TLS server name"))?;
                let tls = tokio_rustls::TlsConnector::from(self.upstream.client_config(allow_h2))
                    .connect(name, stream)
                    .await
                    .with_context(|| format!("TLS handshake with {connect_host}"))?;
                let facts = forward::tls_facts(&tls, &connect_host);
                let request_sent = now_ms();
                if facts.alpn.as_deref() == Some("h2") {
                    let response = send_http2(tls, &outgoing, sanitised).await?;
                    (response, Some(facts), HttpVersion::Http2, request_sent)
                } else {
                    let response = send_http1(tls, &outgoing, sanitised).await?;
                    (response, Some(facts), HttpVersion::Http11, request_sent)
                }
            }
        };

        let response_start = now_ms();
        let (parts, body) = response.into_parts();
        let status = parts.status;
        let version = HttpVersion::from_http(parts.version);
        let response_headers = headers::to_pairs(&parts.headers);
        let encoding = headers::content_encoding(&parts.headers);
        let mime = headers::content_type(&parts.headers);

        self.store.update(id, |flow| {
            flow.state = FlowState::Streaming;
            // What we actually spoke, which is not necessarily what the origin
            // answered with: an HTTP/1.1 request can come back as HTTP/1.0.
            flow.request.http_version = sent_version;
            flow.timings.connect_end = Some(connect_end);
            flow.timings.request_sent = Some(request_sent);
            flow.timings.response_start = Some(response_start);
            if let Some(facts) = &facts {
                flow.timings.tls_end = facts.tls_end;
                flow.server.sni = facts.sni.clone();
                flow.server.alpn = facts.alpn.clone();
                flow.server.tls_version = facts.tls_version.clone();
                flow.server.cipher = facts.cipher.clone();
                flow.server.cert_fingerprint = facts.cert_fingerprint.clone();
            }
            flow.response = Some(FlowResponse {
                status: status.as_u16(),
                status_text: status.canonical_reason().unwrap_or_default().to_string(),
                http_version: version,
                headers: response_headers.clone(),
                body: None,
            });
        });

        let (retained, meta) = read_body(body, self.store.bodies(), limit, encoding, mime).await?;
        self.store.update(id, |flow| {
            if let Some(response) = flow.response.as_mut() {
                response.body = meta;
            }
        });
        self.store.finish(id);

        let timings = self
            .store
            .get(id)
            .map(|flow| flow.timings)
            .unwrap_or_default();

        Ok(SendResult {
            flow_id: id.clone(),
            status: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or_default().to_string(),
            http_version: version,
            headers: response_headers,
            body_base64: base64::engine::general_purpose::STANDARD.encode(&retained),
            timings,
        })
    }
}

/* ------------------------------------------------------------------ */
/* the request being sent                                              */
/* ------------------------------------------------------------------ */

struct Outgoing {
    method: Method,
    target: Target,
    headers: Vec<HeaderPair>,
    body: Bytes,
}

impl Outgoing {
    /// The headers as they will actually go out. Hop-by-hop headers and h2
    /// pseudo headers are dropped because they describe framing this request no
    /// longer has, and `Content-Length` is dropped because hyper measures the
    /// body it is given and an edited body would contradict a captured length.
    ///
    /// A name or value that will not parse is skipped rather than failing the
    /// send: captured headers are read lossily, so an unrepresentable one is
    /// the capture's fault and not something the user can fix from the UI.
    fn header_map(&self) -> HeaderMap {
        let mut map = HeaderMap::with_capacity(self.headers.len());
        for (name, value) in &self.headers {
            if is_hop_by_hop(name)
                || is_pseudo_header(name)
                || name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                debug!(header = %name, "dropping a header that cannot be sent");
                continue;
            };
            map.append(name, value);
        }
        map
    }
}

/// Applies `{{var}}` when the body is valid UTF-8; binary bodies pass through.
fn interpolate_body_bytes(raw: &Bytes, vars: &std::collections::HashMap<String, String>) -> Bytes {
    match std::str::from_utf8(raw) {
        Ok(text) if text.contains("{{") => Bytes::from(vars::interpolate(text, vars)),
        _ => raw.clone(),
    }
}

/// Where a request is going, decomposed the way [`FlowRequest`] wants it.
struct Target {
    scheme: Scheme,
    /// Hostname as written, so an IPv6 literal keeps its brackets.
    host: String,
    port: u16,
    authority: String,
    path: String,
    url: String,
}

impl Target {
    fn parse(input: &str) -> Result<Self> {
        let uri: Uri = input
            .trim()
            .parse()
            .with_context(|| format!("\"{input}\" is not a URL"))?;

        let scheme = match uri.scheme_str() {
            Some("http") => Scheme::Http,
            Some("https") => Scheme::Https,
            Some(other) => bail!("{other} is not a scheme this can send"),
            None => bail!("the url needs a scheme, for example https://api.example.com/"),
        };
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| anyhow!("the url needs a host"))?
            .to_string();

        let default_port = match scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        let port = uri.port_u16().unwrap_or(default_port);
        let authority = if port == default_port {
            host.clone()
        } else {
            format!("{host}:{port}")
        };

        let path = match uri.path_and_query() {
            Some(pq) if !pq.as_str().is_empty() => pq.as_str().to_string(),
            _ => "/".to_string(),
        };

        let url = format!("{}://{}{}", scheme.as_str(), authority, path);
        Ok(Self {
            scheme,
            host,
            port,
            authority,
            path,
            url,
        })
    }
}

fn method_of(candidate: Option<&str>, fallback: &str) -> Result<Method> {
    let raw = candidate
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback);
    Method::from_bytes(raw.as_bytes()).with_context(|| format!("\"{raw}\" is not an HTTP method"))
}

fn decode_base64(encoded: &str) -> Result<Bytes> {
    // The UI encodes with the standard alphabet, but a hand-written request or
    // a value copied out of a JWT may well be URL-safe, and rejecting that
    // would look like the body silently going missing.
    let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let engine = if cleaned.contains('-') || cleaned.contains('_') {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        base64::engine::general_purpose::STANDARD_NO_PAD
    };
    let trimmed = cleaned.trim_end_matches('=');
    engine
        .decode(trimmed)
        .map(Bytes::from)
        .context("the request body was not valid base64")
}

/* ------------------------------------------------------------------ */
/* transports                                                          */
/* ------------------------------------------------------------------ */

async fn send_http1<I>(io: I, outgoing: &Outgoing, mut sent: HeaderMap) -> Result<Response<Incoming>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .context("HTTP/1.1 handshake with the origin")?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            debug!(error = %err, "replay connection ended");
        }
    });

    // A direct connection wants origin form.
    let uri: Uri = outgoing
        .target
        .path
        .parse()
        .with_context(|| format!("{} is not a usable request path", outgoing.target.path))?;
    headers::set_host(&mut sent, &outgoing.target.authority);

    let mut request = Request::new(Full::new(outgoing.body.clone()));
    *request.method_mut() = outgoing.method.clone();
    *request.uri_mut() = uri;
    *request.headers_mut() = sent;

    sender
        .send_request(request)
        .await
        .context("sending the request to the origin")
}

async fn send_http2<I>(io: I, outgoing: &Outgoing, mut sent: HeaderMap) -> Result<Response<Incoming>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // h2 carries the destination in `:authority`, which is built below from the
    // target URL and so already reflects any edit. A captured `Host` alongside
    // it would name a different origin in the same request, and which of the two
    // the far end believes is not ours to decide.
    sent.remove(http::header::HOST);

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .context("HTTP/2 handshake with the origin")?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            debug!(error = %err, "replay connection ended");
        }
    });

    // h2 addresses the origin through :authority, which hyper derives from an
    // absolute URI.
    let uri: Uri = outgoing
        .target
        .url
        .parse()
        .with_context(|| format!("{} is not a usable request URL", outgoing.target.url))?;

    let mut request = Request::new(Full::new(outgoing.body.clone()));
    *request.method_mut() = outgoing.method.clone();
    *request.uri_mut() = uri;
    *request.version_mut() = http::Version::HTTP_2;
    *request.headers_mut() = sent;

    sender
        .send_request(request)
        .await
        .context("sending the request to the origin")
}

/// Reads a response body into the body store, keeping at most `limit` bytes and
/// handing the same bytes back for the JSON reply.
async fn read_body(
    mut body: Incoming,
    bodies: &crate::capture::BodyStore,
    limit: u64,
    content_encoding: Option<String>,
    content_type: Option<String>,
) -> Result<(Vec<u8>, Option<crate::types::BodyMeta>)> {
    let mut writer = bodies.writer(limit);
    let mut retained: Vec<u8> = Vec::new();

    while let Some(frame) = body.frame().await {
        let frame = frame.context("reading the response from the origin")?;
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        writer.write(chunk);
        let room = limit.saturating_sub(retained.len() as u64) as usize;
        if room > 0 {
            retained.extend_from_slice(&chunk[..room.min(chunk.len())]);
        }
    }

    let meta = (writer.seen() > 0).then(|| writer.finish(content_encoding, content_type));
    Ok((retained, meta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_keeps_its_default_port_out_of_the_authority() {
        let target = Target::parse("https://api.example.com/v1/users?page=2").unwrap();
        assert_eq!(target.scheme, Scheme::Https);
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.authority, "api.example.com");
        assert_eq!(target.path, "/v1/users?page=2");
        assert_eq!(target.url, "https://api.example.com/v1/users?page=2");

        let plain = Target::parse("http://api.example.com/").unwrap();
        assert_eq!(plain.port, 80);
        assert_eq!(plain.authority, "api.example.com");
    }

    #[test]
    fn a_non_default_port_stays_visible() {
        let target = Target::parse("https://api.example.com:8443/x").unwrap();
        assert_eq!(target.port, 8443);
        assert_eq!(target.authority, "api.example.com:8443");
        assert_eq!(target.url, "https://api.example.com:8443/x");
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_but_not_for_connecting() {
        let target = Target::parse("https://[::1]:9443/health").unwrap();
        assert_eq!(target.host, "[::1]");
        assert_eq!(target.authority, "[::1]:9443");
        assert_eq!(strip_port(&target.host), "::1");
    }

    #[test]
    fn a_missing_path_becomes_a_slash() {
        let target = Target::parse("https://api.example.com").unwrap();
        assert_eq!(target.path, "/");
        assert_eq!(target.url, "https://api.example.com/");
    }

    #[test]
    fn unusable_urls_are_rejected_with_a_reason() {
        for bad in ["", "   ", "api.example.com/x", "ftp://files.example.com/x", "https://"] {
            assert!(Target::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn framing_headers_never_travel_onto_a_replay() {
        let outgoing = Outgoing {
            method: Method::POST,
            target: Target::parse("https://api.example.com/x").unwrap(),
            headers: vec![
                (":method".to_string(), "POST".to_string()),
                (":authority".to_string(), "api.example.com".to_string()),
                ("connection".to_string(), "keep-alive".to_string()),
                ("transfer-encoding".to_string(), "chunked".to_string()),
                ("Content-Length".to_string(), "999".to_string()),
                ("accept".to_string(), "application/json".to_string()),
                ("set-cookie".to_string(), "a=1".to_string()),
                ("set-cookie".to_string(), "b=2".to_string()),
            ],
            body: Bytes::new(),
        };

        let map = outgoing.header_map();
        for absent in [":method", ":authority", "connection", "transfer-encoding", "content-length"] {
            assert!(!map.contains_key(absent), "{absent} was sent");
        }
        assert_eq!(map.get("accept").unwrap(), "application/json");
        assert_eq!(
            map.get_all("set-cookie").iter().count(),
            2,
            "repeated headers must survive"
        );
    }

    #[test]
    fn a_method_falls_back_only_when_it_is_missing() {
        assert_eq!(method_of(None, "PATCH").unwrap(), Method::PATCH);
        assert_eq!(method_of(Some("  "), "PATCH").unwrap(), Method::PATCH);
        assert_eq!(method_of(Some("delete"), "GET").unwrap(), "delete");
        assert!(method_of(Some("bad method"), "GET").is_err());
    }

    #[test]
    fn bodies_decode_from_either_base64_alphabet() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), Bytes::from_static(b"hello"));
        assert_eq!(decode_base64("aGVsbG8").unwrap(), Bytes::from_static(b"hello"));
        // 0xfb 0xff encodes as "+/8" in the standard alphabet and "-_8" URL-safe.
        assert_eq!(decode_base64("+/8=").unwrap(), Bytes::from_static(&[0xfb, 0xff]));
        assert_eq!(decode_base64("-_8=").unwrap(), Bytes::from_static(&[0xfb, 0xff]));
        assert_eq!(decode_base64("").unwrap(), Bytes::new());
        assert!(decode_base64("not base64!").is_err());
    }

    #[test]
    fn an_absent_body_is_not_the_same_as_a_null_one() {
        let absent: SendSpec = serde_json::from_str(r#"{"method":"GET"}"#).unwrap();
        assert!(absent.body_base64.is_none(), "an omitted body must stay omitted");

        let cleared: SendSpec = serde_json::from_str(r#"{"bodyBase64":null}"#).unwrap();
        assert_eq!(cleared.body_base64, Some(None), "null must mean an empty body");

        let given: SendSpec = serde_json::from_str(r#"{"bodyBase64":"aGk="}"#).unwrap();
        assert_eq!(given.body_base64, Some(Some("aGk=".to_string())));
    }

    #[test]
    fn a_spec_deserialises_from_the_shape_the_ui_sends() {
        let spec: SendSpec = serde_json::from_str(
            r#"{"method":"POST","url":"https://api.example.com/x","headers":[["accept","*/*"]],"bodyBase64":"aGk="}"#,
        )
        .unwrap();
        assert_eq!(spec.method.as_deref(), Some("POST"));
        assert_eq!(spec.url.as_deref(), Some("https://api.example.com/x"));
        assert_eq!(
            spec.headers.as_deref(),
            Some(&[("accept".to_string(), "*/*".to_string())][..])
        );
    }

    /* -------------------------------------------------------------- */
    /* exchanges against a local origin                                */
    /* -------------------------------------------------------------- */

    use std::net::SocketAddr;

    use parking_lot::Mutex;
    use tokio::net::TcpListener;

    const STANDARD: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    /// One request as the origin received it, so a test can assert on the bytes
    /// that actually left rather than on the struct that described them.
    struct Seen {
        method: String,
        path: String,
        /// Only h2 fills this in: an HTTP/1.1 request arrives in origin form and
        /// names its destination in `Host` instead.
        authority: Option<String>,
        headers: Vec<HeaderPair>,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    /// An origin on the loopback interface that answers everything with
    /// `reply`. Port zero and 127.0.0.1, so these tests never touch the network
    /// and never collide with something already listening.
    async fn origin(reply: &'static [u8]) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a local origin");
        let address = listener.local_addr().expect("the local address");
        let seen = Arc::new(Mutex::new(Vec::new()));

        let recorder = seen.clone();
        tokio::spawn(async move {
            // Replay opens a fresh connection per send, so the accept loop has
            // to outlive the first one.
            while let Ok((stream, _)) = listener.accept().await {
                let recorder = recorder.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        let recorder = recorder.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let collected = body
                                .collect()
                                .await
                                .map(|body| body.to_bytes())
                                .unwrap_or_default();
                            recorder.lock().push(Seen {
                                method: parts.method.as_str().to_string(),
                                path: parts.uri.path().to_string(),
                                authority: parts.uri.authority().map(ToString::to_string),
                                headers: headers::to_pairs(&parts.headers),
                                body: collected.to_vec(),
                            });
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("content-type", "application/octet-stream")
                                    .body(Full::new(Bytes::from_static(reply)))
                                    .expect("a response the test controls"),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        (address, seen)
    }

    /// The same origin speaking h2c, which is HTTP/2 over plain TCP with prior
    /// knowledge. It is what lets a test see the frames [`send_http2`] builds
    /// without standing up a TLS handshake and an ALPN negotiation first.
    async fn origin_http2(reply: &'static [u8]) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a local origin");
        let address = listener.local_addr().expect("the local address");
        let seen = Arc::new(Mutex::new(Vec::new()));

        let recorder = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let recorder = recorder.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        let recorder = recorder.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let collected = body
                                .collect()
                                .await
                                .map(|body| body.to_bytes())
                                .unwrap_or_default();
                            recorder.lock().push(Seen {
                                method: parts.method.as_str().to_string(),
                                path: parts.uri.path().to_string(),
                                authority: parts.uri.authority().map(ToString::to_string),
                                headers: headers::to_pairs(&parts.headers),
                                body: collected.to_vec(),
                            });
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from_static(reply)))
                                    .expect("a response the test controls"),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        (address, seen)
    }

    fn engine(store: Arc<FlowStore>, data_dir: &std::path::Path) -> ReplayEngine {
        let config = Config {
            data_dir: data_dir.to_path_buf(),
            // Nothing here speaks TLS, and skipping the system trust store
            // keeps the suite from failing on a machine whose roots are
            // unreadable rather than on anything this module does.
            insecure_upstream: true,
            ..Config::default()
        };
        ReplayEngine::new(Arc::new(config), store).expect("a replay engine")
    }

    /// A flow in the store shaped like something the proxy captured, pointed at
    /// the local origin so it can actually be replayed.
    fn captured(
        store: &FlowStore,
        address: SocketAddr,
        headers: Vec<HeaderPair>,
        body: &[u8],
    ) -> FlowId {
        let id = store.create(FlowInit {
            kind: FlowKind::Http,
            intercepted: true,
            request: FlowRequest {
                method: "POST".to_string(),
                url: format!("http://{address}/captured"),
                scheme: Scheme::Http,
                authority: address.to_string(),
                host: address.ip().to_string(),
                port: address.port(),
                path: "/captured".to_string(),
                http_version: HttpVersion::Http11,
                headers,
                body: None,
            },
            client: FlowClient {
                address: "192.168.1.20".to_string(),
                port: 51314,
            },
            server: FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });

        if !body.is_empty() {
            let mut writer = store.bodies().writer(store.max_body_bytes());
            writer.write(body);
            let meta = writer.finish(None, Some("application/json".to_string()));
            store.update(&id, |flow| flow.request.body = Some(meta));
        }
        id
    }

    fn store() -> Arc<FlowStore> {
        Arc::new(FlowStore::new(16, 64 * 1024, 1024 * 1024))
    }

    #[tokio::test]
    async fn a_composed_send_carries_bytes_both_ways_through_base64() {
        // Neither payload is valid UTF-8, which is the case base64 is here for.
        const REPLY: &[u8] = &[0x00, 0xff, 0xfe, b'o', b'k'];
        let request_body: &[u8] = &[0x01, 0x02, 0xfe];

        let (address, seen) = origin(REPLY).await;
        let dir = tempfile::tempdir().unwrap();
        let store = store();
        let engine = engine(store.clone(), dir.path());

        let result = engine
            .send(SendSpec {
                method: Some("POST".to_string()),
                url: Some(format!("http://{address}/compose")),
                headers: Some(vec![("x-note".to_string(), "hello".to_string())]),
                body_base64: Some(Some(STANDARD.encode(request_body))),
                environment_id: None,
            })
            .await
            .expect("the send should have reached the local origin");

        let seen = seen.lock();
        assert_eq!(seen.len(), 1, "the origin saw {} requests", seen.len());
        assert_eq!(
            seen[0].body.as_slice(),
            request_body,
            "the request body did not survive base64 decoding"
        );
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, "/compose");
        assert_eq!(seen[0].header("x-note"), Some("hello"));

        assert_eq!(result.status, 200);
        assert_eq!(result.status_text, "OK");
        let decoded = STANDARD
            .decode(&result.body_base64)
            .expect("the reply body should be standard base64");
        assert_eq!(
            decoded.as_slice(),
            REPLY,
            "the response body did not survive base64 encoding"
        );
    }

    #[tokio::test]
    async fn a_composed_send_without_a_url_is_refused_before_any_connection() {
        let dir = tempfile::tempdir().unwrap();
        let store = store();
        let engine = engine(store.clone(), dir.path());

        for spec in [
            SendSpec::default(),
            SendSpec {
                url: Some("   ".to_string()),
                ..SendSpec::default()
            },
        ] {
            let err = engine
                .send(spec)
                .await
                .expect_err("a send with no url should not be attempted");
            assert!(
                err.to_string().contains("url"),
                "the error does not say what is missing: {err:#}"
            );
        }

        assert!(
            store.is_empty(),
            "a request that was never sent must not appear in the traffic list"
        );
    }

    #[tokio::test]
    async fn edits_replace_only_what_they_name_and_the_rest_comes_from_the_capture() {
        const REPLY: &[u8] = b"ok";
        let (address, seen) = origin(REPLY).await;
        let dir = tempfile::tempdir().unwrap();
        let store = store();
        let engine = engine(store.clone(), dir.path());

        let original = captured(
            &store,
            address,
            vec![
                ("x-captured".to_string(), "kept".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            br#"{"from":"the capture"}"#,
        );

        engine
            .from_flow(&original, SendEdits::default())
            .await
            .expect("replaying the capture unchanged");

        engine
            .from_flow(
                &original,
                SendEdits {
                    method: Some("PUT".to_string()),
                    body_base64: Some(Some(STANDARD.encode(b"edited"))),
                    ..SendEdits::default()
                },
            )
            .await
            .expect("replaying the capture with edits");

        let seen = seen.lock();
        assert_eq!(seen.len(), 2, "the origin saw {} requests", seen.len());

        assert_eq!(
            seen[0].method, "POST",
            "an omitted method must come from the capture"
        );
        assert_eq!(
            seen[0].path, "/captured",
            "an omitted url must come from the capture"
        );
        assert_eq!(
            seen[0].header("x-captured"),
            Some("kept"),
            "omitted headers must come from the capture"
        );
        assert_eq!(
            seen[0].body.as_slice(),
            &br#"{"from":"the capture"}"#[..],
            "an omitted body must be read back out of the body store"
        );

        assert_eq!(seen[1].method, "PUT", "the method edit did not take");
        assert_eq!(
            seen[1].body.as_slice(),
            &b"edited"[..],
            "the body edit did not take"
        );
        assert_eq!(
            seen[1].path, "/captured",
            "an unedited url must still come from the capture"
        );
        assert_eq!(
            seen[1].header("x-captured"),
            Some("kept"),
            "unedited headers must still come from the capture"
        );
    }

    #[tokio::test]
    async fn a_replay_points_back_at_its_capture_and_a_composed_send_does_not() {
        const REPLY: &[u8] = b"ok";
        let (address, _seen) = origin(REPLY).await;
        let dir = tempfile::tempdir().unwrap();
        let store = store();
        let engine = engine(store.clone(), dir.path());

        let original = captured(&store, address, Vec::new(), b"payload");
        let replayed = engine
            .from_flow(&original, SendEdits::default())
            .await
            .expect("replaying the capture");

        assert_ne!(
            replayed.flow_id, original,
            "a replay is its own flow, not an edit of the one it came from"
        );
        let recorded = store
            .get(&replayed.flow_id)
            .expect("the replay should be in the traffic list");
        assert_eq!(
            recorded.replay_of.as_deref(),
            Some(original.as_str()),
            "the replay does not say what it came from"
        );
        assert_eq!(recorded.state, FlowState::Complete);
        assert_eq!(
            recorded.response.expect("a recorded response").status,
            200,
            "the replay was recorded without the answer it got"
        );

        let composed = engine
            .send(SendSpec {
                url: Some(format!("http://{address}/composed")),
                ..SendSpec::default()
            })
            .await
            .expect("composing a request");
        let recorded = store
            .get(&composed.flow_id)
            .expect("the composed send should be in the traffic list");
        assert!(
            recorded.replay_of.is_none(),
            "a composed request came from nothing and must not claim a parent"
        );
        assert_eq!(
            recorded.request.method, "GET",
            "a composed request with no method should default to GET"
        );
    }

    #[tokio::test]
    async fn hop_by_hop_headers_from_a_capture_never_reach_the_origin() {
        const REPLY: &[u8] = b"ok";
        let (address, seen) = origin(REPLY).await;
        let dir = tempfile::tempdir().unwrap();
        let store = store();
        let engine = engine(store.clone(), dir.path());

        let original = captured(
            &store,
            address,
            vec![
                (":authority".to_string(), "somewhere.else".to_string()),
                ("proxy-connection".to_string(), "keep-alive".to_string()),
                ("keep-alive".to_string(), "timeout=5".to_string()),
                ("transfer-encoding".to_string(), "chunked".to_string()),
                ("te".to_string(), "trailers".to_string()),
                ("content-length".to_string(), "999".to_string()),
                ("accept".to_string(), "application/json".to_string()),
            ],
            b"four",
        );

        engine
            .from_flow(&original, SendEdits::default())
            .await
            .expect("replaying the capture");

        let authority = address.to_string();
        let seen = seen.lock();
        for absent in [
            ":authority",
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "te",
        ] {
            assert!(
                seen[0].header(absent).is_none(),
                "{absent} was carried onto the replay"
            );
        }
        assert_eq!(
            seen[0].header("accept"),
            Some("application/json"),
            "an ordinary header was dropped along with the framing"
        );
        assert_eq!(
            seen[0].header("content-length"),
            Some("4"),
            "the captured length outlived the body it described"
        );
        assert_eq!(
            seen[0].header("host"),
            Some(authority.as_str()),
            "the replay must address the host it actually dialled"
        );
    }

    #[tokio::test]
    async fn an_http2_replay_names_one_destination_and_it_is_the_target() {
        const REPLY: &[u8] = b"ok";
        let (address, seen) = origin_http2(REPLY).await;

        // The capture carried a Host from wherever it was recorded. The target
        // is the local origin, which is what the user pointed the replay at, and
        // it is the only destination the request may claim.
        let outgoing = Outgoing {
            method: Method::GET,
            target: Target::parse(&format!("http://{address}/edited")).expect("a usable target"),
            headers: vec![("host".to_string(), "captured.example.com".to_string())],
            body: Bytes::new(),
        };
        let sanitised = outgoing.header_map();

        let stream = TcpStream::connect(address)
            .await
            .expect("connecting to the local origin");
        let response = send_http2(stream, &outgoing, sanitised)
            .await
            .expect("sending over h2");
        assert_eq!(response.status(), 200);

        let authority = address.to_string();
        let seen = seen.lock();
        assert_eq!(seen.len(), 1, "the origin saw {} requests", seen.len());
        assert_eq!(
            seen[0].authority.as_deref(),
            Some(authority.as_str()),
            ":authority must come from the target"
        );
        assert!(
            seen[0].header("host").is_none(),
            "a captured Host contradicted :authority: {:?}",
            seen[0].header("host")
        );
        assert_eq!(seen[0].path, "/edited");
    }

    #[tokio::test]
    async fn a_response_past_the_ceiling_is_cut_rather_than_buffered_whole() {
        const REPLY: &[u8] = &[b'x'; 4096];
        let (address, _seen) = origin(REPLY).await;
        let dir = tempfile::tempdir().unwrap();
        // An eight byte ceiling, so the reply cannot possibly fit under it.
        let store = Arc::new(FlowStore::new(16, 8, 1024 * 1024));
        let engine = engine(store.clone(), dir.path());

        let result = engine
            .send(SendSpec {
                url: Some(format!("http://{address}/big")),
                ..SendSpec::default()
            })
            .await
            .expect("the send should have reached the local origin");

        let decoded = STANDARD
            .decode(&result.body_base64)
            .expect("the reply body should be standard base64");
        assert_eq!(
            decoded.len(),
            8,
            "the JSON reply carried {} bytes past an eight byte ceiling",
            decoded.len()
        );

        let recorded = store
            .get(&result.flow_id)
            .expect("the send should be in the traffic list");
        let body = recorded
            .response
            .expect("a recorded response")
            .body
            .expect("a recorded response body");
        assert!(body.truncated, "a body cut at the ceiling must say so");
        assert_eq!(
            body.size, 8,
            "only the retained bytes belong in the body store"
        );
    }
}
