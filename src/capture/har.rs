//! HAR 1.2 export.
//!
//! The output is what other tools eat: Chrome DevTools, Charles, Postman and
//! every HAR viewer on the web. That constrains the shape more than it looks.
//! `cache` and `timings` are required even when empty or unknown, unknown
//! numbers are `-1` rather than absent, and anything we invent has to sit
//! behind an underscore prefix, which the spec reserves for custom fields.
//!
//! Bodies are decoded before they are embedded, because a HAR holding gzip
//! bytes labelled as JSON is useless to every consumer.

use base64::Engine as _;
use serde_json::{json, Value};
use tracing::debug;

use crate::types::{
    BodyMeta, Flow, FlowKind, FlowRequest, FlowResponse, FlowTimings, HeaderPair, HttpVersion,
    WsDirection,
};

use super::bodies::BodyStore;
use super::decode::{decode_body, is_textual};
use super::{header_value, is_ws_drop_marker};

/// Renders flows as a HAR 1.2 log. Tunnels are skipped: an opaque CONNECT has
/// no request or response to describe. WebSocket flows appear as their
/// handshake, with the frames attached as a custom field.
pub fn flows_to_har(flows: &[Flow], bodies: &BodyStore) -> Value {
    let entries: Vec<Value> = flows
        .iter()
        .filter(|flow| flow.kind != FlowKind::Tunnel)
        .map(|flow| entry(flow, bodies))
        .collect();

    json!({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "Proxima",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "entries": entries,
        }
    })
}

fn entry(flow: &Flow, bodies: &BodyStore) -> Value {
    let mut entry = json!({
        "startedDateTime": iso8601(flow.timings.start),
        "time": total_time(&flow.timings),
        "request": request_json(&flow.request, bodies),
        "response": response_json(flow.response.as_ref(), bodies),
        "cache": {},
        "timings": timings_json(&flow.timings),
    });

    if let Some(address) = &flow.server.address {
        entry["serverIPAddress"] = json!(address);
    }
    if let Some(comment) = &flow.comment {
        entry["comment"] = json!(comment);
    }
    if let Some(error) = &flow.error {
        entry["_error"] = json!(error.message);
    }
    if let Some(replay_of) = &flow.replay_of {
        entry["_replayOf"] = json!(replay_of);
    }
    if let Some(messages) = &flow.ws_messages {
        // A capped socket kept only its most recent frames. An export that did
        // not say so would read as a complete history of the connection.
        if let Some(marker) = messages.iter().find(|message| is_ws_drop_marker(message)) {
            entry["_webSocketMessagesDropped"] = json!(marker.size);
        }
        entry["_webSocketMessages"] = ws_messages_json(messages);
    }
    entry["_flowId"] = json!(flow.id);
    entry
}

fn request_json(request: &FlowRequest, bodies: &BodyStore) -> Value {
    let mut value = json!({
        "method": request.method,
        "url": request.url,
        "httpVersion": http_version(request.http_version),
        "cookies": request_cookies(&request.headers),
        "headers": headers_json(&request.headers),
        "queryString": query_string(&request.path),
        "headersSize": -1,
        "bodySize": declared_body_size(request.body.as_ref()),
    });

    if let Some(meta) = &request.body {
        let mime = mime_of(meta, &request.headers);
        let payload = read_payload(meta, bodies, &mime);

        let mut post = json!({ "mimeType": mime, "params": [] });
        match &payload.text {
            Some(text) => post["text"] = json!(text),
            None => {
                post["text"] = json!("");
                post["comment"] = json!("body no longer retained");
            }
        }
        if payload.base64 {
            // Not in HAR 1.2 for postData, but every importer that handles
            // binary uploads reads it, and the alternative is lossy text.
            post["encoding"] = json!("base64");
        }
        if let Some(text) = payload.text.as_ref().filter(|_| !payload.base64) {
            if mime.starts_with("application/x-www-form-urlencoded") {
                post["params"] = pairs_json(text);
            }
        }
        if meta.truncated {
            post["_truncated"] = json!(true);
        }
        if payload.decode_failed {
            post["_decodeFailed"] = json!(true);
        }
        value["postData"] = post;
    }

    value
}

fn response_json(response: Option<&FlowResponse>, bodies: &BodyStore) -> Value {
    let Some(response) = response else {
        // The schema requires a response object, so a flow that never got one
        // is described as status 0, which is what browsers write too.
        return json!({
            "status": 0,
            "statusText": "",
            "httpVersion": "",
            "cookies": [],
            "headers": [],
            "content": { "size": 0, "mimeType": "" },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        });
    };

    json!({
        "status": response.status,
        "statusText": response.status_text,
        "httpVersion": http_version(response.http_version),
        "cookies": response_cookies(&response.headers),
        "headers": headers_json(&response.headers),
        "content": content_json(response, bodies),
        "redirectURL": header_value(&response.headers, "location").unwrap_or_default(),
        "headersSize": -1,
        "bodySize": declared_body_size(response.body.as_ref()),
    })
}

fn content_json(response: &FlowResponse, bodies: &BodyStore) -> Value {
    let Some(meta) = &response.body else {
        let mime = header_value(&response.headers, "content-type").unwrap_or_default();
        return json!({ "size": 0, "mimeType": mime });
    };

    let mime = mime_of(meta, &response.headers);
    let payload = read_payload(meta, bodies, &mime);

    let mut content = json!({
        "size": payload.size,
        "mimeType": mime,
    });
    match &payload.text {
        Some(text) => content["text"] = json!(text),
        None => content["comment"] = json!("body no longer retained"),
    }
    if payload.base64 {
        content["encoding"] = json!("base64");
    }
    // The spec defines compression as the bytes saved by the transfer encoding.
    let on_the_wire = meta.size as i64;
    if payload.retained && !meta.truncated && payload.size > on_the_wire {
        content["compression"] = json!(payload.size - on_the_wire);
    }
    if meta.truncated {
        content["_truncated"] = json!(true);
    }
    if payload.decode_failed {
        content["_decodeFailed"] = json!(true);
    }
    content
}

struct Payload {
    /// Already base64 encoded when `base64` is set.
    text: Option<String>,
    base64: bool,
    /// Decoded length, or the retained length when the body is gone.
    size: i64,
    retained: bool,
    decode_failed: bool,
}

fn read_payload(meta: &BodyMeta, bodies: &BodyStore, mime: &str) -> Payload {
    let Some(raw) = bodies.read(&meta.id) else {
        return Payload {
            text: None,
            base64: false,
            size: meta.size as i64,
            retained: false,
            decode_failed: false,
        };
    };

    let (bytes, decode_failed) = match decode_body(&raw, meta.content_encoding.as_deref()) {
        Ok(decoded) => (decoded, false),
        Err(error) => {
            // Truncated bodies land here constantly: half a gzip stream cannot
            // be decoded. Embedding the raw bytes keeps the export lossless.
            debug!(id = %meta.id, %error, "har export embedding an undecodable body raw");
            (raw.to_vec(), true)
        }
    };

    let size = bytes.len() as i64;
    if is_textual(Some(mime)) && !decode_failed {
        match String::from_utf8(bytes) {
            Ok(text) => {
                return Payload {
                    text: Some(text),
                    base64: false,
                    size,
                    retained: true,
                    decode_failed,
                }
            }
            Err(err) => {
                let bytes = err.into_bytes();
                return Payload {
                    text: Some(base64_of(&bytes)),
                    base64: true,
                    size,
                    retained: true,
                    decode_failed,
                };
            }
        }
    }

    Payload {
        text: Some(base64_of(&bytes)),
        base64: true,
        size,
        retained: true,
        decode_failed,
    }
}

fn base64_of(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn mime_of(meta: &BodyMeta, headers: &[HeaderPair]) -> String {
    meta.content_type
        .clone()
        .or_else(|| header_value(headers, "content-type"))
        .unwrap_or_default()
}

/// Bytes as they arrived. A truncated capture means we never learned the real
/// length, and HAR spells that `-1` rather than a lie.
fn declared_body_size(meta: Option<&BodyMeta>) -> i64 {
    match meta {
        None => 0,
        Some(meta) if meta.truncated => -1,
        Some(meta) => meta.size as i64,
    }
}

fn headers_json(headers: &[HeaderPair]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect(),
    )
}

fn request_cookies(headers: &[HeaderPair]) -> Value {
    let mut cookies = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in value.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (key, val) = split_once_or_empty(pair, '=');
            cookies.push(json!({ "name": key, "value": val }));
        }
    }
    Value::Array(cookies)
}

fn response_cookies(headers: &[HeaderPair]) -> Value {
    let mut cookies = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let mut parts = value.split(';');
        let Some(first) = parts.next() else {
            continue;
        };
        let (key, val) = split_once_or_empty(first.trim(), '=');
        if key.is_empty() {
            continue;
        }
        let mut cookie = json!({ "name": key, "value": val });
        for attribute in parts {
            let attribute = attribute.trim();
            let (attr_name, attr_value) = split_once_or_empty(attribute, '=');
            match attr_name.to_ascii_lowercase().as_str() {
                "path" => cookie["path"] = json!(attr_value),
                "domain" => cookie["domain"] = json!(attr_value),
                "expires" => cookie["expires"] = json!(cookie_expires(&attr_value)),
                "secure" => cookie["secure"] = json!(true),
                "httponly" => cookie["httpOnly"] = json!(true),
                _ => {}
            }
        }
        cookies.push(cookie);
    }
    Value::Array(cookies)
}

/// HAR 1.2 specifies ISO 8601 for a cookie's `expires`, but Set-Cookie carries
/// an HTTP-date. A value we cannot read is passed through untouched: a date a
/// reader has to work at is better than a field that quietly disappeared.
fn cookie_expires(value: &str) -> String {
    http_date_to_iso8601(value).unwrap_or_else(|| value.to_string())
}

/// Converts the two dated formats RFC 6265 requires a client to understand,
/// `Wed, 21 Oct 2015 07:28:00 GMT` and `Wednesday, 21-Oct-15 07:28:00 GMT`.
/// Anything else, including the asctime form, returns `None`.
fn http_date_to_iso8601(value: &str) -> Option<String> {
    // Both formats open with the weekday, which ends at the comma and tells us
    // nothing the date does not.
    let (_, rest) = value.trim().split_once(',')?;
    let mut fields = rest.split_whitespace();

    let date = fields.next()?;
    let (day, month, year, clock) = if date.contains('-') {
        // RFC 850 packs the date into one hyphenated token.
        let mut parts = date.split('-');
        let day = parts.next()?;
        let month = parts.next()?;
        let year = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        (day, month, year, fields.next()?)
    } else {
        (date, fields.next()?, fields.next()?, fields.next()?)
    };

    // Cookie dates are always UTC. A zone we do not recognise means we have
    // misread the value, not that we may assume UTC anyway.
    match fields.next() {
        None => {}
        Some(zone)
            if matches!(
                zone.to_ascii_uppercase().as_str(),
                "GMT" | "UTC" | "UT" | "Z" | "+0000" | "-0000"
            ) => {}
        Some(_) => return None,
    }
    if fields.next().is_some() {
        return None;
    }

    let day: u8 = day.parse().ok()?;
    let month = time::Month::try_from(month_number(month)?).ok()?;
    let year = calendar_year(year)?;

    let mut clock = clock.split(':');
    let hour: u8 = clock.next()?.parse().ok()?;
    let minute: u8 = clock.next()?.parse().ok()?;
    let second: u8 = clock.next()?.parse().ok()?;
    if clock.next().is_some() {
        return None;
    }

    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let clock = time::Time::from_hms(hour, minute, second).ok()?;
    time::PrimitiveDateTime::new(date, clock)
        .assume_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn month_number(name: &str) -> Option<u8> {
    match name.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

/// Four digit years are taken as written. Two digit years follow RFC 6265: 70
/// and up belong to the twentieth century, everything below it to the current
/// one.
fn calendar_year(text: &str) -> Option<i32> {
    let year: i32 = text.parse().ok()?;
    match text.len() {
        4 => Some(year),
        2 if year >= 70 => Some(1900 + year),
        2 => Some(2000 + year),
        _ => None,
    }
}

fn split_once_or_empty(text: &str, separator: char) -> (String, String) {
    match text.split_once(separator) {
        Some((left, right)) => (left.trim().to_string(), right.trim().to_string()),
        None => (text.trim().to_string(), String::new()),
    }
}

/// Name and value pairs from the query portion of a path.
fn query_string(path: &str) -> Value {
    let Some((_, query)) = path.split_once('?') else {
        return Value::Array(Vec::new());
    };
    // A fragment never travels on the wire, but a composed request might carry
    // one, and it is not part of the query.
    let query = query.split('#').next().unwrap_or(query);
    pairs_json(query)
}

fn pairs_json(encoded: &str) -> Value {
    Value::Array(
        encoded
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, value) = match pair.split_once('=') {
                    Some((name, value)) => (name, value),
                    None => (pair, ""),
                };
                json!({
                    "name": percent_decode(name),
                    "value": percent_decode(value),
                })
            })
            .collect(),
    )
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                match (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push((high << 4) | low);
                        index += 3;
                    }
                    // Not a valid escape, so it is a literal percent sign.
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn http_version(version: HttpVersion) -> &'static str {
    match version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
        HttpVersion::Http2 => "HTTP/2",
    }
}

fn timings_json(timings: &FlowTimings) -> Value {
    let connect_start = timings.dns_end.unwrap_or(timings.start);
    // HAR 1.2 keeps `ssl` inside `connect` rather than after it, for backward
    // compatibility with 1.1 readers that only knew about `connect`. So the
    // handshake ends the connect phase; it does not follow it.
    let connect_end = timings.tls_end.or(timings.connect_end);
    let send_start = timings
        .tls_end
        .or(timings.connect_end)
        .unwrap_or(timings.start);

    json!({
        "blocked": -1,
        "dns": delta(Some(timings.start), timings.dns_end),
        "connect": delta(Some(connect_start), connect_end),
        "ssl": delta(timings.connect_end, timings.tls_end),
        "send": delta(Some(send_start), timings.request_sent),
        "wait": delta(timings.request_sent, timings.response_start),
        "receive": delta(timings.response_start, timings.end),
    })
}

/// Elapsed milliseconds between two marks, or `-1` when either is missing or
/// the clock moved backwards under us.
fn delta(from: Option<u64>, to: Option<u64>) -> i64 {
    match (from, to) {
        (Some(from), Some(to)) if to >= from => (to - from) as i64,
        _ => -1,
    }
}

fn total_time(timings: &FlowTimings) -> i64 {
    delta(Some(timings.start), timings.end)
}

/// Only frames that actually crossed the wire. The marker the store leaves
/// behind for discarded frames is reported on the entry instead, so nothing in
/// this array is something the peer did not send.
fn ws_messages_json(messages: &[crate::types::WsMessage]) -> Value {
    Value::Array(
        messages
            .iter()
            .filter(|message| !is_ws_drop_marker(message))
            .map(|message| {
                let mut value = json!({
                    "type": match message.direction {
                        WsDirection::Send => "send",
                        WsDirection::Recv => "receive",
                    },
                    // Chrome writes this field in seconds.
                    "time": message.at as f64 / 1000.0,
                    "opcode": message.opcode,
                    "_size": message.size,
                });
                if let Some(text) = &message.text {
                    value["data"] = json!(text);
                }
                if message.truncated {
                    value["_truncated"] = json!(true);
                }
                value
            })
            .collect(),
    )
}

/// ISO 8601 in UTC. HAR readers parse this field, so a bad clock must not
/// produce a string that fails to parse.
fn iso8601(epoch_ms: u64) -> String {
    let nanos = i128::from(epoch_ms) * 1_000_000;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        FlowClient, FlowError, FlowServer, FlowState, Scheme, TunnelInfo, WsMessage,
    };
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn store_body(
        bodies: &BodyStore,
        payload: &[u8],
        encoding: Option<&str>,
        mime: &str,
    ) -> BodyMeta {
        let mut writer = bodies.writer(1024 * 1024);
        writer.write(payload);
        writer.finish(encoding.map(str::to_string), Some(mime.to_string()))
    }

    fn sample_flow() -> Flow {
        Flow {
            id: "flow-1".into(),
            kind: FlowKind::Http,
            state: FlowState::Complete,
            intercepted: true,
            request: FlowRequest {
                method: "GET".into(),
                url: "https://api.example.com/v1/users?limit=10&q=hello+world".into(),
                scheme: Scheme::Https,
                authority: "api.example.com".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/v1/users?limit=10&q=hello+world".into(),
                http_version: HttpVersion::Http2,
                headers: vec![
                    ("accept".into(), "application/json".into()),
                    ("cookie".into(), "session=abc123; theme=dark".into()),
                ],
                body: None,
            },
            response: None,
            error: None,
            timings: FlowTimings {
                start: 1_700_000_000_000,
                dns_end: Some(1_700_000_000_010),
                connect_end: Some(1_700_000_000_030),
                tls_end: Some(1_700_000_000_070),
                request_sent: Some(1_700_000_000_075),
                response_start: Some(1_700_000_000_200),
                end: Some(1_700_000_000_250),
            },
            client: FlowClient {
                address: "192.168.1.20".into(),
                port: 51314,
            },
            server: FlowServer {
                address: Some("93.184.216.34".into()),
                port: Some(443),
                ..FlowServer::default()
            },
            replay_of: None,
            comment: None,
            ws_messages: None,
            tunnel: None,
        }
    }

    #[test]
    fn one_structurally_valid_entry() {
        let bodies = BodyStore::new(1024 * 1024);
        // Repetitive enough that gzip actually shrinks it, which is what makes
        // the `compression` field meaningful.
        let body_text = format!(
            "{{\"users\":[{}{{\"id\":0,\"name\":\"Ada\"}}]}}",
            "{\"id\":1,\"name\":\"Ada\"},".repeat(50)
        );
        let body = body_text.as_bytes();
        let meta = store_body(&bodies, &gzip(body), Some("gzip"), "application/json");

        let mut flow = sample_flow();
        flow.response = Some(FlowResponse {
            status: 200,
            status_text: "OK".into(),
            http_version: HttpVersion::Http2,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("content-encoding".into(), "gzip".into()),
                (
                    "set-cookie".into(),
                    "session=xyz; Path=/; HttpOnly; Secure".into(),
                ),
            ],
            body: Some(meta),
        });

        let har = flows_to_har(&[flow], &bodies);
        let log = &har["log"];
        assert_eq!(log["version"], "1.2");
        assert_eq!(log["creator"]["name"], "Proxima");

        let entries = log["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];

        assert_eq!(entry["startedDateTime"], "2023-11-14T22:13:20Z");
        assert_eq!(entry["time"], 250);
        assert!(entry["cache"].is_object());
        assert_eq!(entry["serverIPAddress"], "93.184.216.34");

        let request = &entry["request"];
        assert_eq!(request["method"], "GET");
        assert_eq!(request["httpVersion"], "HTTP/2");
        assert_eq!(request["headersSize"], -1);
        assert_eq!(request["bodySize"], 0);
        assert!(request["postData"].is_null(), "no body means no postData");

        let query = request["queryString"]
            .as_array()
            .expect("queryString array");
        assert_eq!(query.len(), 2);
        assert_eq!(query[0]["name"], "limit");
        assert_eq!(query[0]["value"], "10");
        assert_eq!(query[1]["name"], "q");
        assert_eq!(query[1]["value"], "hello world");

        let cookies = request["cookies"].as_array().expect("cookies array");
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0]["name"], "session");
        assert_eq!(cookies[0]["value"], "abc123");

        let response = &entry["response"];
        assert_eq!(response["status"], 200);
        assert_eq!(response["statusText"], "OK");
        assert_eq!(response["redirectURL"], "");
        assert_eq!(response["headersSize"], -1);

        // The gzip must be gone by the time it lands in the HAR.
        let content = &response["content"];
        assert_eq!(content["mimeType"], "application/json");
        assert_eq!(content["size"], body.len() as i64);
        assert_eq!(content["text"], body_text);
        assert!(content["encoding"].is_null(), "text must not be base64");
        assert!(content["compression"].as_i64().unwrap_or(0) > 0);

        let set_cookie = response["cookies"].as_array().expect("cookies array");
        assert_eq!(set_cookie.len(), 1);
        assert_eq!(set_cookie[0]["name"], "session");
        assert_eq!(set_cookie[0]["path"], "/");
        assert_eq!(set_cookie[0]["httpOnly"], true);
        assert_eq!(set_cookie[0]["secure"], true);

        let timings = &entry["timings"];
        assert_eq!(timings["blocked"], -1);
        assert_eq!(timings["dns"], 10);
        // dns_end to tls_end, because the handshake is part of connect.
        assert_eq!(timings["connect"], 60);
        assert_eq!(timings["ssl"], 40);
        assert_eq!(timings["send"], 5);
        assert_eq!(timings["wait"], 125);
        assert_eq!(timings["receive"], 50);

        // The whole thing has to survive a serialisation round trip.
        let text = serde_json::to_string(&har).expect("serialisable");
        let parsed: Value = serde_json::from_str(&text).expect("parsable");
        assert_eq!(
            parsed["log"]["entries"].as_array().map(|e| e.len()),
            Some(1)
        );
    }

    #[test]
    fn binary_bodies_are_base64() {
        let bodies = BodyStore::new(1024 * 1024);
        let png = [0x89u8, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00];
        let meta = store_body(&bodies, &png, None, "image/png");

        let mut flow = sample_flow();
        flow.response = Some(FlowResponse {
            status: 200,
            status_text: "OK".into(),
            http_version: HttpVersion::Http11,
            headers: vec![("content-type".into(), "image/png".into())],
            body: Some(meta),
        });

        let har = flows_to_har(&[flow], &bodies);
        let content = &har["log"]["entries"][0]["response"]["content"];
        assert_eq!(content["encoding"], "base64");
        assert_eq!(content["size"], png.len() as i64);
        let text = content["text"].as_str().expect("base64 text");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(text)
            .expect("valid base64");
        assert_eq!(decoded, png);
    }

    #[test]
    fn request_bodies_become_post_data() {
        let bodies = BodyStore::new(1024 * 1024);
        let meta = store_body(
            &bodies,
            b"name=Ada+Lovelace&role=engineer",
            None,
            "application/x-www-form-urlencoded",
        );

        let mut flow = sample_flow();
        flow.request.method = "POST".into();
        flow.request.body = Some(meta);
        flow.response = Some(FlowResponse {
            status: 204,
            status_text: "No Content".into(),
            http_version: HttpVersion::Http11,
            headers: vec![],
            body: None,
        });

        let har = flows_to_har(&[flow], &bodies);
        let request = &har["log"]["entries"][0]["request"];
        assert_eq!(request["bodySize"], 31);
        let post = &request["postData"];
        assert_eq!(post["mimeType"], "application/x-www-form-urlencoded");
        assert_eq!(post["text"], "name=Ada+Lovelace&role=engineer");
        let params = post["params"].as_array().expect("params array");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0]["name"], "name");
        assert_eq!(params[0]["value"], "Ada Lovelace");

        assert_eq!(har["log"]["entries"][0]["response"]["content"]["size"], 0);
    }

    #[test]
    fn failed_flows_still_produce_a_response_object() {
        let bodies = BodyStore::new(1024);
        let mut flow = sample_flow();
        flow.state = FlowState::Error;
        flow.timings.response_start = None;
        flow.timings.end = None;
        flow.error = Some(FlowError {
            message: "upstream connection reset".into(),
            code: Some("ECONNRESET".into()),
            likely_pinning: None,
        });

        let har = flows_to_har(&[flow], &bodies);
        let entry = &har["log"]["entries"][0];
        assert_eq!(entry["time"], -1);
        assert_eq!(entry["response"]["status"], 0);
        assert_eq!(entry["response"]["bodySize"], -1);
        assert!(entry["response"]["content"].is_object());
        assert_eq!(entry["timings"]["wait"], -1);
        assert_eq!(entry["timings"]["receive"], -1);
        assert_eq!(entry["_error"], "upstream connection reset");
    }

    #[test]
    fn tunnels_are_skipped_and_websockets_are_kept() {
        let bodies = BodyStore::new(1024);

        let mut tunnel = sample_flow();
        tunnel.kind = FlowKind::Tunnel;
        tunnel.tunnel = Some(TunnelInfo {
            bytes_sent: 10,
            bytes_received: 20,
            reason: "host is on the deny list".into(),
        });

        let mut socket = sample_flow();
        socket.kind = FlowKind::Websocket;
        socket.response = Some(FlowResponse {
            status: 101,
            status_text: "Switching Protocols".into(),
            http_version: HttpVersion::Http11,
            headers: vec![("upgrade".into(), "websocket".into())],
            body: None,
        });
        socket.ws_messages = Some(vec![WsMessage {
            at: 1_700_000_000_300,
            direction: WsDirection::Send,
            opcode: 1,
            size: 5,
            truncated: false,
            text: Some("hello".into()),
            body_id: None,
        }]);

        let har = flows_to_har(&[tunnel, socket], &bodies);
        let entries = har["log"]["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 1, "the tunnel must not be exported");
        assert_eq!(entries[0]["response"]["status"], 101);

        let messages = entries[0]["_webSocketMessages"]
            .as_array()
            .expect("websocket frames");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["type"], "send");
        assert_eq!(messages[0]["data"], "hello");
        assert!(
            entries[0]["_webSocketMessagesDropped"].is_null(),
            "nothing was dropped from this socket"
        );
    }

    #[test]
    fn discarded_websocket_frames_are_reported_not_hidden() {
        let bodies = BodyStore::new(1024);
        let mut socket = sample_flow();
        socket.kind = FlowKind::Websocket;
        socket.ws_messages = Some(vec![
            // What the store leaves at the head of a capped flow.
            WsMessage {
                at: 1_700_000_000_290,
                direction: WsDirection::Recv,
                opcode: crate::capture::WS_DROPPED_OPCODE,
                size: 9000,
                truncated: true,
                text: Some("9000 earlier messages discarded".into()),
                body_id: None,
            },
            WsMessage {
                at: 1_700_000_000_300,
                direction: WsDirection::Send,
                opcode: 1,
                size: 5,
                truncated: false,
                text: Some("hello".into()),
                body_id: None,
            },
        ]);

        let har = flows_to_har(&[socket], &bodies);
        let entry = &har["log"]["entries"][0];
        assert_eq!(
            entry["_webSocketMessagesDropped"], 9000,
            "an export must not pass a trimmed history off as the whole one"
        );

        let messages = entry["_webSocketMessages"]
            .as_array()
            .expect("websocket frames");
        assert_eq!(
            messages.len(),
            1,
            "the marker is not a frame the peer ever sent"
        );
        assert_eq!(messages[0]["data"], "hello");
    }

    #[test]
    fn evicted_bodies_degrade_instead_of_lying() {
        let bodies = BodyStore::new(1024 * 1024);
        let meta = store_body(&bodies, b"{\"gone\":true}", None, "application/json");
        bodies.remove(&meta.id);

        let mut flow = sample_flow();
        flow.response = Some(FlowResponse {
            status: 200,
            status_text: "OK".into(),
            http_version: HttpVersion::Http11,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Some(meta),
        });

        let har = flows_to_har(&[flow], &bodies);
        let content = &har["log"]["entries"][0]["response"]["content"];
        assert!(content["text"].is_null());
        assert_eq!(content["size"], 13);
        assert!(content["comment"].is_string());
    }

    #[test]
    fn ssl_is_contained_within_connect() {
        let bodies = BodyStore::new(1024);
        let flow = sample_flow();
        let har = flows_to_har(&[flow], &bodies);
        let timings = &har["log"]["entries"][0]["timings"];

        let connect = timings["connect"].as_i64().expect("connect");
        let ssl = timings["ssl"].as_i64().expect("ssl");
        assert!(
            ssl <= connect,
            "HAR 1.2 counts the ssl period inside connect, got ssl {ssl} against connect {connect}"
        );
        // The two phases together, not the handshake hanging off the end.
        assert_eq!(connect, 60);
        assert_eq!(ssl, 40);

        // A plain HTTP flow has no handshake to fold in.
        let mut plain = sample_flow();
        plain.timings.tls_end = None;
        let har = flows_to_har(&[plain], &bodies);
        let timings = &har["log"]["entries"][0]["timings"];
        assert_eq!(timings["connect"], 20);
        assert_eq!(timings["ssl"], -1);
    }

    #[test]
    fn cookie_expiry_is_iso8601() {
        let bodies = BodyStore::new(1024);
        let mut flow = sample_flow();
        flow.response = Some(FlowResponse {
            status: 200,
            status_text: "OK".into(),
            http_version: HttpVersion::Http11,
            headers: vec![(
                "set-cookie".into(),
                "session=xyz; Path=/; Expires=Wed, 21 Oct 2015 07:28:00 GMT".into(),
            )],
            body: None,
        });

        let har = flows_to_har(&[flow], &bodies);
        let cookie = &har["log"]["entries"][0]["response"]["cookies"][0];
        assert_eq!(
            cookie["expires"], "2015-10-21T07:28:00Z",
            "HAR 1.2 wants ISO 8601 here, not the raw HTTP-date"
        );
    }

    #[test]
    fn http_dates_convert_or_are_left_alone() {
        assert_eq!(
            http_date_to_iso8601("Wed, 21 Oct 2015 07:28:00 GMT").as_deref(),
            Some("2015-10-21T07:28:00Z")
        );
        // RFC 850, which RFC 6265 still requires a client to read.
        assert_eq!(
            http_date_to_iso8601("Sunday, 06-Nov-94 08:49:37 GMT").as_deref(),
            Some("1994-11-06T08:49:37Z")
        );
        assert_eq!(
            http_date_to_iso8601("Fri, 01-Jan-38 00:00:00 GMT").as_deref(),
            Some("2038-01-01T00:00:00Z"),
            "a two digit year below 70 is this century"
        );
        // Session cookies and deletions both show up as absurd dates.
        assert_eq!(
            http_date_to_iso8601("Thu, 01 Jan 1970 00:00:00 GMT").as_deref(),
            Some("1970-01-01T00:00:00Z")
        );

        // Anything we cannot read keeps its original text rather than vanishing.
        assert_eq!(http_date_to_iso8601("Sun Nov  6 08:49:37 1994"), None);
        assert_eq!(http_date_to_iso8601("not a date at all"), None);
        assert_eq!(http_date_to_iso8601("Wed, 32 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(http_date_to_iso8601("Wed, 21 Foo 2015 07:28:00 GMT"), None);
        assert_eq!(http_date_to_iso8601("Wed, 21 Oct 2015 07:28:00 PST"), None);
        assert_eq!(http_date_to_iso8601(""), None);
        assert_eq!(cookie_expires("whenever"), "whenever");
    }

    #[test]
    fn percent_decoding_survives_bad_input() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("100%2"), "100%2");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("caf%C3%A9"), "café");
    }

    #[test]
    fn empty_input_produces_an_empty_log() {
        let bodies = BodyStore::new(1024);
        let har = flows_to_har(&[], &bodies);
        assert_eq!(har["log"]["entries"].as_array().map(|e| e.len()), Some(0));
    }
}
