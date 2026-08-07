//! Header handling on the way through the proxy.
//!
//! Two rules drive everything here. Hop-by-hop headers describe one connection
//! and must not be copied onto the next one, and HTTP/2 forbids the
//! connection-specific ones outright: forwarding a `Connection` header onto an
//! h2 stream is a protocol error that the origin answers by resetting the
//! stream, which looks to the user like the origin hating their request.
//!
//! The exception is an upgrade. A WebSocket handshake is carried *by*
//! `Connection: Upgrade` and `Upgrade: websocket`, so on that one path the
//! framing headers are the payload and have to survive.

use http::header::{HeaderMap, HeaderName, HeaderValue};

use crate::types::HeaderPair;

/// Headers scoped to a single hop, per RFC 9110. `Transfer-Encoding` is in the
/// list because the framing is decided per connection: hyper sets it when it
/// needs it, and a copied one contradicts what is actually on the wire.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// How the sanitised headers will be framed, which decides what may survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// HTTP/1.x, where an upgrade is possible.
    Http1,
    /// HTTP/2, which rejects connection-specific headers entirely.
    Http2,
    /// HTTP/3 over QUIC. Same hop rules as HTTP/2 (`Host` dropped, `te:
    /// trailers` kept). Used by reverse H3 only; the TCP proxy never speaks h3.
    Http3,
}

pub fn is_hop_by_hop(name: &HeaderName) -> bool {
    is_hop_by_hop_str(name.as_str())
}

/// The same test against a header name that has not been parsed, which is how
/// the replay side sees them: a captured [`HeaderPair`] is a plain string and
/// may not even be a legal `HeaderName`.
pub fn is_hop_by_hop_str(name: &str) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// True when these headers are asking to become a WebSocket.
///
/// `Connection` is a comma separated list and the token is case insensitive,
/// so `Connection: keep-alive, Upgrade` counts. Clients really do send that.
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrading = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));

    upgrading
        && headers
            .get(http::header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
}

/// True for the one `TE` value HTTP/2 still allows. gRPC sends exactly this and
/// reads its absence as "this hop cannot carry trailers", so it has to survive.
fn is_te_trailers(value: &HeaderValue) -> bool {
    value
        .to_str()
        .map(|value| value.trim().eq_ignore_ascii_case("trailers"))
        .unwrap_or(false)
}

/// Copies headers for the next hop, dropping the ones that described this one.
///
/// Over HTTP/1.1 an upgrade keeps its `Connection` and `Upgrade` headers,
/// because without them the origin has no idea a WebSocket was requested.
///
/// Over HTTP/2 and HTTP/3 two more things differ. `te: trailers` is explicitly
/// permitted and is kept, because stripping it makes this proxy look like one
/// that cannot carry trailers and breaks gRPC through it. `Host` is dropped,
/// because h2/h3 address the origin through `:authority` and a `Host` copied
/// from the client only ever contradicts it.
pub fn for_upstream(from: &HeaderMap, wire: Wire) -> HeaderMap {
    let keep_upgrade = wire == Wire::Http1 && is_websocket_upgrade(from);
    let multiplexed = matches!(wire, Wire::Http2 | Wire::Http3);
    let mut out = HeaderMap::with_capacity(from.len());
    for (name, value) in from {
        if multiplexed && name == http::header::HOST {
            continue;
        }
        if is_hop_by_hop(name) {
            let is_upgrade_framing =
                name == http::header::CONNECTION || name == http::header::UPGRADE;
            let keep_te = multiplexed && name == http::header::TE && is_te_trailers(value);
            if !(keep_upgrade && is_upgrade_framing) && !keep_te {
                continue;
            }
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// The same filter applied to a response on its way back to the client.
pub fn for_client(from: &HeaderMap, status: http::StatusCode) -> HeaderMap {
    // A 101 is the one response whose upgrade framing has to reach the client,
    // otherwise the WebSocket the origin just agreed to never opens.
    let keep_upgrade = status == http::StatusCode::SWITCHING_PROTOCOLS;
    let mut out = HeaderMap::with_capacity(from.len());
    for (name, value) in from {
        if is_hop_by_hop(name) {
            let is_upgrade_framing =
                name == http::header::CONNECTION || name == http::header::UPGRADE;
            if !(keep_upgrade && is_upgrade_framing) {
                continue;
            }
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Replaces `Host` with the authority the request is actually being sent to.
/// A stale `Host` from the client is a common source of confusing 404s.
pub fn set_host(headers: &mut HeaderMap, authority: &str) {
    if let Ok(value) = HeaderValue::from_str(authority) {
        headers.insert(http::header::HOST, value);
    }
}

/// Headers as the UI shows them: order and duplicates preserved, because a
/// server that treats repeated headers oddly is exactly what gets debugged.
///
/// A value that is not UTF-8 is shown lossily rather than dropped: seeing the
/// header with replacement characters is more useful than not seeing it.
pub fn to_pairs(headers: &HeaderMap) -> Vec<HeaderPair> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

pub fn content_type(headers: &HeaderMap) -> Option<String> {
    text_header(headers, http::header::CONTENT_TYPE)
}

pub fn content_encoding(headers: &HeaderMap) -> Option<String> {
    text_header(headers, http::header::CONTENT_ENCODING)
}

fn text_header(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn hop_by_hop_headers_do_not_travel() {
        let from = headers(&[
            ("connection", "keep-alive"),
            ("proxy-connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("accept", "application/json"),
            ("authorization", "Bearer x"),
        ]);
        let out = for_upstream(&from, Wire::Http1);

        assert!(out.contains_key("accept"));
        assert!(out.contains_key("authorization"));
        for dropped in ["connection", "proxy-connection", "keep-alive", "transfer-encoding"] {
            assert!(!out.contains_key(dropped), "{dropped} was forwarded");
        }
    }

    #[test]
    fn a_websocket_handshake_keeps_its_framing_over_http1() {
        let from = headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("te", "trailers"),
        ]);

        let out = for_upstream(&from, Wire::Http1);
        assert!(out.contains_key("connection"), "the upgrade lost Connection");
        assert!(out.contains_key("upgrade"));
        assert!(out.contains_key("sec-websocket-key"));
        assert!(!out.contains_key("te"), "unrelated hop headers still go");
    }

    #[test]
    fn http2_never_carries_connection_headers() {
        let from = headers(&[("connection", "Upgrade"), ("upgrade", "websocket")]);
        let out = for_upstream(&from, Wire::Http2);
        assert!(out.is_empty(), "h2 rejects connection specific headers");
    }

    #[test]
    fn h2_keeps_te_trailers_because_grpc_needs_it() {
        let out = for_upstream(&headers(&[("te", "trailers")]), Wire::Http2);
        assert_eq!(
            out.get("te").map(|value| value.as_bytes()),
            Some(&b"trailers"[..]),
            "h2 permits te: trailers and gRPC requires it"
        );

        // Capitalisation and surrounding space are the peer's business.
        let out = for_upstream(&headers(&[("te", " Trailers ")]), Wire::Http2);
        assert!(out.contains_key("te"));

        // Any other te value describes this hop only and still goes.
        for other in ["gzip", "deflate", "trailers, deflate"] {
            let out = for_upstream(&headers(&[("te", other)]), Wire::Http2);
            assert!(!out.contains_key("te"), "te: {other} was forwarded over h2");
        }

        // HTTP/1.1 has no such exception: te is hop by hop there, full stop.
        let out = for_upstream(&headers(&[("te", "trailers")]), Wire::Http1);
        assert!(!out.contains_key("te"), "http/1.1 must not carry te");
    }

    #[test]
    fn h2_drops_host_in_favour_of_the_authority() {
        let from = headers(&[("host", "stale.example.com"), ("accept", "*/*")]);

        let out = for_upstream(&from, Wire::Http2);
        assert!(
            !out.contains_key("host"),
            "a Host next to :authority contradicts it"
        );
        assert!(out.contains_key("accept"), "only Host is special here");

        // Over HTTP/1.1 Host is the addressing, so it stays and is rewritten
        // by set_host afterwards.
        let out = for_upstream(&from, Wire::Http1);
        assert!(out.contains_key("host"));
    }

    #[test]
    fn h3_matches_h2_hop_rules() {
        let from = headers(&[
            ("host", "stale.example.com"),
            ("connection", "keep-alive"),
            ("te", "trailers"),
            ("accept", "*/*"),
        ]);
        let out = for_upstream(&from, Wire::Http3);
        assert!(!out.contains_key("host"));
        assert!(!out.contains_key("connection"));
        assert!(out.contains_key("te"), "h3 keeps te: trailers like h2");
        assert!(out.contains_key("accept"));
    }

    #[test]
    fn an_upgrade_token_in_a_list_still_counts() {
        assert!(is_websocket_upgrade(&headers(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket"),
        ])));
        assert!(is_websocket_upgrade(&headers(&[
            ("connection", "upgrade"),
            ("upgrade", "WebSocket"),
        ])));
        assert!(!is_websocket_upgrade(&headers(&[
            ("connection", "keep-alive"),
            ("upgrade", "websocket"),
        ])));
        assert!(!is_websocket_upgrade(&headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "h2c"),
        ])));
    }

    #[test]
    fn a_101_keeps_its_framing_on_the_way_back() {
        let from = headers(&[("connection", "Upgrade"), ("upgrade", "websocket")]);
        let switching = for_client(&from, http::StatusCode::SWITCHING_PROTOCOLS);
        assert!(switching.contains_key("upgrade"));

        let ordinary = for_client(&from, http::StatusCode::OK);
        assert!(!ordinary.contains_key("upgrade"));
    }

    #[test]
    fn repeated_headers_survive_in_order() {
        let from = headers(&[("set-cookie", "a=1"), ("set-cookie", "b=2")]);
        let pairs = to_pairs(&from);
        assert_eq!(
            pairs,
            vec![
                ("set-cookie".to_string(), "a=1".to_string()),
                ("set-cookie".to_string(), "b=2".to_string()),
            ]
        );
    }

    #[test]
    fn host_is_replaced_not_appended() {
        let mut map = headers(&[("host", "stale.example.com")]);
        set_host(&mut map, "api.example.com:8443");
        assert_eq!(map.get_all("host").iter().count(), 1);
        assert_eq!(map.get("host").unwrap(), "api.example.com:8443");
    }

    #[test]
    fn content_headers_are_read_as_sent() {
        let map = headers(&[
            ("content-type", "application/json; charset=utf-8"),
            ("content-encoding", "gzip"),
        ]);
        assert_eq!(
            content_type(&map).as_deref(),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(content_encoding(&map).as_deref(), Some("gzip"));
        assert!(content_type(&HeaderMap::new()).is_none());
    }
}
