//! End to end: a real client, a real CONNECT, real TLS in both directions.
//!
//! The unit tests cover the pieces in isolation, which says nothing about
//! whether a phone pointed at this proxy actually reaches the internet. These
//! tests run the whole path: an HTTPS origin with its own certificate, a client
//! configured to use the proxy and to trust the Proxima root, and assertions on
//! both what the client received and what the capture store recorded.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use proxima::ca::CertAuthority;
use proxima::capture::FlowStore;
use proxima::config::{Config, DecryptMode, DecryptRules};
use proxima::proxy::{ProxyDeps, ProxyServer, SetupHandler};
use proxima::types::{FlowKind, FlowState};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// The setup page is the API layer's job; the proxy only needs something that
/// answers, so these tests supply the smallest thing that satisfies the trait.
struct StubSetup;

impl SetupHandler for StubSetup {
    fn handle(&self, _parts: &http::request::Parts) -> Response<Bytes> {
        Response::new(Bytes::from_static(b"setup"))
    }
}

struct Harness {
    proxy_addr: SocketAddr,
    origin_addr: SocketAddr,
    store: Arc<FlowStore>,
    config: Arc<Config>,
    ca_pem: String,
    origin_pem: String,
    _shutdown: watch::Sender<bool>,
    _temp: tempfile::TempDir,
}

impl Harness {
    fn origin_url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.origin_addr.port())
    }
}

async fn start(deny: Vec<String>) -> Harness {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (origin_addr, origin_pem) = start_origin().await;

    let temp = tempfile::tempdir().expect("temp dir");
    let ca = Arc::new(CertAuthority::open(temp.path()).expect("certificate authority"));
    let ca_pem = ca.cert_pem().to_string();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy address");

    let config = Arc::new(Config {
        proxy_port: proxy_addr.port(),
        proxy_host: "127.0.0.1".to_string(),
        data_dir: temp.path().to_path_buf(),
        // The origin signs its own certificate, which no system root vouches
        // for. Verifying it is not what these tests are about.
        insecure_upstream: true,
        decrypt: DecryptRules {
            mode: DecryptMode::All,
            allow: Vec::new(),
            deny,
        },
        ..Config::default()
    });

    let store = Arc::new(FlowStore::new(
        config.max_flows,
        config.max_body_bytes,
        config.max_total_body_bytes,
    ));
    let deps = Arc::new(ProxyDeps {
        upstream: proxima::proxy::forward::Upstream::new(&config).expect("upstream"),
        config: config.clone(),
        ca,
        store: store.clone(),
        setup: Arc::new(StubSetup),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = ProxyServer::serve(deps, listener, shutdown_rx).await;
    });

    Harness {
        proxy_addr,
        origin_addr,
        store,
        config,
        ca_pem,
        origin_pem,
        _shutdown: shutdown_tx,
        _temp: temp,
    }
}

/// An HTTPS origin that echoes enough to prove what reached it.
async fn start_origin() -> (SocketAddr, String) {
    let key = rcgen::KeyPair::generate().expect("origin key");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("origin certificate parameters");
    let cert = params.self_signed(&key).expect("origin certificate");
    let pem = cert.pem();

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der())
                .expect("origin private key"),
        )
        .expect("origin TLS configuration");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin address");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(handle_origin);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    (addr, pem)
}

async fn handle_origin(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let body = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();

    let response = match (method.as_str(), path.as_str()) {
        ("POST", "/echo") => Response::builder()
            .status(StatusCode::CREATED)
            .header("content-type", "application/json")
            .body(Full::new(body))
            .expect("echo response"),
        (_, "/hello") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from_static(b"hello from the origin")))
            .expect("hello response"),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found")))
            .expect("not found response"),
    };
    Ok(response)
}

/// A client that trusts the Proxima root and the origin's own certificate, and
/// sends everything through the proxy. Trusting the origin directly is what
/// makes the tunnelled case testable.
fn client(harness: &Harness) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{}", harness.proxy_addr.port()))
                .expect("proxy setting"),
        )
        .add_root_certificate(
            reqwest::Certificate::from_pem(harness.ca_pem.as_bytes()).expect("Proxima root"),
        )
        .add_root_certificate(
            reqwest::Certificate::from_pem(harness.origin_pem.as_bytes()).expect("origin root"),
        )
        .build()
        .expect("client")
}

/// Flows are recorded from the body stream, which finishes a moment after the
/// client has its response.
async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
}

#[tokio::test]
async fn https_through_the_proxy_is_decrypted_and_recorded() {
    let harness = start(Vec::new()).await;
    let response = client(&harness)
        .get(harness.origin_url("/hello"))
        .send()
        .await
        .expect("request through the proxy");

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.text().await.expect("body"),
        "hello from the origin",
        "the client did not get the origin's response intact"
    );

    settle().await;
    let flows = harness.store.all(&Default::default());
    let flow = flows
        .iter()
        .find(|f| f.request.path == "/hello")
        .expect("the request was never captured");

    assert!(flow.intercepted, "the flow was not decrypted");
    assert_eq!(flow.kind, FlowKind::Http);
    assert_eq!(flow.state, FlowState::Complete);
    assert_eq!(flow.request.method, "GET");
    assert_eq!(flow.request.host, "localhost");
    assert_eq!(flow.request.url, harness.origin_url("/hello"));

    let response = flow.response.as_ref().expect("no response was recorded");
    assert_eq!(response.status, 200);

    let body = response.body.as_ref().expect("no response body was captured");
    assert_eq!(
        harness.store.bodies().read(&body.id).as_deref(),
        Some(&b"hello from the origin"[..]),
        "the captured body is not what the origin sent"
    );

    // The point of terminating TLS ourselves is seeing these.
    assert!(flow.server.tls_version.is_some(), "no upstream TLS version recorded");
    assert!(flow.server.cert_fingerprint.is_some(), "no origin fingerprint recorded");
}

#[tokio::test]
async fn a_request_body_is_captured_without_altering_it() {
    let harness = start(Vec::new()).await;
    let payload = r#"{"question":"does the body survive?"}"#;

    let response = client(&harness)
        .post(harness.origin_url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .expect("post through the proxy");

    assert_eq!(response.status(), 201);
    assert_eq!(
        response.text().await.expect("body"),
        payload,
        "the origin did not receive the body unchanged"
    );

    settle().await;
    let flows = harness.store.all(&Default::default());
    let flow = flows
        .iter()
        .find(|f| f.request.path == "/echo")
        .expect("the POST was never captured");

    let request_body = flow.request.body.as_ref().expect("no request body captured");
    assert_eq!(request_body.size, payload.len() as u64);
    assert_eq!(
        harness.store.bodies().read(&request_body.id).as_deref(),
        Some(payload.as_bytes()),
        "the captured request body differs from what was sent"
    );
    assert_eq!(
        request_body.content_type.as_deref(),
        Some("application/json")
    );
}

#[tokio::test]
async fn a_skipped_host_is_tunnelled_and_stays_opaque() {
    let harness = start(vec!["localhost".to_string()]).await;
    let response = client(&harness)
        .get(harness.origin_url("/hello"))
        .send()
        .await
        .expect("request through the tunnel");

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.text().await.expect("body"),
        "hello from the origin",
        "excluding a host must not break it"
    );

    settle().await;
    let flows = harness.store.all(&Default::default());
    let flow = flows.first().expect("the tunnel was never recorded");

    assert_eq!(flow.kind, FlowKind::Tunnel);
    assert!(!flow.intercepted, "an excluded host must not be decrypted");
    assert_eq!(flow.request.method, "CONNECT");
    assert!(flow.response.is_none(), "a tunnel has no response to show");

    let tunnel = flow.tunnel.as_ref().expect("no tunnel information recorded");
    assert!(
        tunnel.bytes_sent > 0 && tunnel.bytes_received > 0,
        "a tunnel that carried a request and a response reported {tunnel:?}"
    );
    assert!(
        !tunnel.reason.is_empty(),
        "the UI needs a reason to explain why this was not decrypted"
    );
}

#[tokio::test]
async fn a_plain_request_to_a_tls_origin_fails_visibly() {
    let harness = start(Vec::new()).await;

    // No CONNECT here: a plain proxy request arrives in absolute form. The
    // origin only speaks TLS, so this asserts the failure is recorded rather
    // than swallowed, which is the behaviour that matters on this path.
    let response = client(&harness)
        .get(format!("http://localhost:{}/hello", harness.origin_addr.port()))
        .send()
        .await
        .expect("plain request through the proxy");

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "an origin that cannot answer must produce a readable status, not a dropped connection"
    );

    settle().await;
    let flows = harness.store.all(&Default::default());
    let flow = flows
        .iter()
        .find(|f| f.request.scheme == proxima::types::Scheme::Http)
        .expect("the plain request was never captured");

    assert_eq!(flow.state, FlowState::Error);
    assert!(flow.error.is_some(), "a failed flow must carry its error");
}

/// The replay engine talks to origins on its own rather than through the proxy,
/// so nothing above covers it. This drives a captured flow back out at the same
/// origin and checks both what came back and what was recorded.
#[tokio::test]
async fn a_captured_request_can_be_replayed_and_edited() {
    use proxima::replay::{ReplayEngine, SendSpec};

    let harness = start(Vec::new()).await;
    let payload = r#"{"attempt":"first"}"#;

    client(&harness)
        .post(harness.origin_url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .expect("post through the proxy")
        .bytes()
        .await
        .expect("body");

    settle().await;
    let captured = harness
        .store
        .all(&Default::default())
        .into_iter()
        .find(|f| f.request.path == "/echo")
        .expect("the POST was never captured");

    let engine =
        ReplayEngine::new(harness.config.clone(), harness.store.clone()).expect("replay engine");

    // Nothing overridden: the method, url, headers and body all come from the
    // captured flow, so the origin should echo the original payload back.
    let verbatim = engine
        .from_flow(&captured.id, SendSpec::default())
        .await
        .expect("replaying the captured request");

    assert_eq!(verbatim.status, 201);
    assert_eq!(
        base64_decode(&verbatim.body_base64),
        payload.as_bytes(),
        "an unedited replay did not send the captured body"
    );

    let replayed = harness
        .store
        .get(&verbatim.flow_id)
        .expect("the replay was not recorded");
    assert_eq!(replayed.replay_of.as_deref(), Some(captured.id.as_str()));
    assert_eq!(replayed.state, FlowState::Complete);
    assert_eq!(replayed.request.method, "POST");
    assert_eq!(replayed.request.path, "/echo");
    assert!(
        replayed.server.tls_version.is_some(),
        "a replayed HTTPS request should record what it negotiated"
    );
    assert!(
        replayed.timings.request_sent <= replayed.timings.response_start,
        "a request cannot be answered before it was sent: {:?}",
        replayed.timings
    );

    let request_body = replayed.request.body.as_ref().expect("no request body");
    assert_eq!(
        harness.store.bodies().read(&request_body.id).as_deref(),
        Some(payload.as_bytes())
    );

    // An edited body replaces the captured one; everything else still carries.
    let edited_payload = r#"{"attempt":"second"}"#;
    let edited = engine
        .from_flow(
            &captured.id,
            SendSpec {
                body_base64: Some(Some(base64_encode(edited_payload.as_bytes()))),
                ..SendSpec::default()
            },
        )
        .await
        .expect("replaying with an edited body");

    assert_eq!(
        base64_decode(&edited.body_base64),
        edited_payload.as_bytes(),
        "the edited body never reached the origin"
    );
}

/// A composed request needs no capture behind it at all.
#[tokio::test]
async fn a_composed_request_is_sent_and_recorded() {
    use proxima::replay::{ReplayEngine, SendSpec};

    let harness = start(Vec::new()).await;
    let engine =
        ReplayEngine::new(harness.config.clone(), harness.store.clone()).expect("replay engine");

    let result = engine
        .send(SendSpec {
            url: Some(harness.origin_url("/hello")),
            headers: Some(vec![("accept".to_string(), "text/plain".to_string())]),
            ..SendSpec::default()
        })
        .await
        .expect("sending a composed request");

    assert_eq!(result.status, 200);
    assert_eq!(result.status_text, "OK");
    assert_eq!(base64_decode(&result.body_base64), b"hello from the origin");

    let flow = harness
        .store
        .get(&result.flow_id)
        .expect("the composed request was not recorded");
    assert_eq!(flow.request.method, "GET", "a composed request defaults to GET");
    assert!(flow.replay_of.is_none(), "nothing was replayed here");
    assert_eq!(flow.state, FlowState::Complete);
    assert_eq!(
        flow.response.as_ref().expect("no response recorded").status,
        200
    );

    // A url that cannot be sent must say so rather than record a broken flow.
    assert!(engine.send(SendSpec::default()).await.is_err());
    assert!(engine
        .send(SendSpec {
            url: Some("not a url".to_string()),
            ..SendSpec::default()
        })
        .await
        .is_err());
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("the reply was not base64")
}
