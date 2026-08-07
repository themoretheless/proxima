//! cURL export.
//!
//! The output has one job: survive a copy and paste into a shell without being
//! edited first. That rules out double quotes (the shell would expand `$`,
//! backticks and `\`) and it rules out printing raw bytes, so every value is
//! wrapped in single quotes and binary bodies are rebuilt by `printf`.

use crate::types::{Flow, HttpVersion};

/// Renders `flow` as a `curl` invocation. `body` is the request body bytes as
/// they should go out, already decoded by the caller; pass `None` to emit the
/// request without one.
///
/// `--insecure` is never emitted. Whether a certificate should be trusted is a
/// decision for whoever runs the command, and quietly disabling verification in
/// a snippet that then gets pasted into a script is how that gets lost.
pub fn to_curl(flow: &Flow, body: Option<&[u8]>) -> String {
    let request = &flow.request;
    let mut args: Vec<String> = Vec::new();

    args.push(format!("--request {}", quote(&request.method)));
    args.push(format!("--url {}", quote(&request.url)));
    if request.http_version == HttpVersion::Http2 {
        args.push("--http2".to_string());
    }
    if request.http_version == HttpVersion::Http3 {
        args.push("--http3".to_string());
    }

    for (name, value) in &request.headers {
        // Hop-by-hop headers describe the connection we captured, not the
        // request; replaying them either confuses curl or corrupts framing.
        if super::is_hop_by_hop(name) || super::is_pseudo_header(name) {
            continue;
        }
        // curl measures whatever body it is actually given. Echoing a captured
        // length only creates a mismatch the moment the body is edited.
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        // The body handed in has already been decoded, so repeating the
        // captured encoding would label plaintext as gzip and curl would send
        // it exactly as labelled.
        if name.eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        args.push(format!("--header {}", quote(&format!("{name}: {value}"))));
    }

    let mut prefix = String::new();
    if let Some(bytes) = body.filter(|b| !b.is_empty()) {
        match std::str::from_utf8(bytes) {
            // A single quoted string carries newlines and non-ASCII text
            // unchanged, so text bodies go inline. A leading `@` is the one
            // exception: curl reads it as a filename after the shell has
            // removed the quoting, so no amount of quoting saves it.
            Ok(text) if !text.contains('\0') && !text.starts_with('@') => {
                args.push(format!("--data-binary {}", quote(text)));
            }
            // Anything else cannot be an argument without loss, so it is
            // reconstructed byte for byte and piped in, where `@-` means
            // standard input and nothing is reinterpreted.
            _ => {
                prefix = format!("printf {} | ", quote(&printf_format(bytes)));
                args.push("--data-binary @-".to_string());
            }
        }
    }

    let mut out = String::with_capacity(prefix.len() + 8 + args.len() * 32);
    out.push_str(&prefix);
    out.push_str("curl");
    for arg in args {
        out.push_str(" \\\n  ");
        out.push_str(&arg);
    }
    out
}

/// Wraps `value` in single quotes. Inside single quotes a POSIX shell expands
/// nothing at all, so the only character needing care is the quote itself: end
/// the string, emit an escaped quote, start a new string. Newlines, `$`,
/// backticks and backslashes all pass through untouched.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Builds a POSIX `printf` format string that reproduces `bytes` exactly.
/// Printable ASCII goes through literally; everything else becomes a
/// three-digit octal escape, which `printf` expands back to the original byte.
/// `%` and `\` are doubled because `printf` reads them as syntax.
fn printf_format(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        match byte {
            b'%' => out.push_str("%%"),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(byte)),
            other => out.push_str(&format!("\\{other:03o}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        FlowClient, FlowKind, FlowRequest, FlowServer, FlowState, FlowTimings, HeaderPair, Scheme,
    };

    fn flow_with(headers: Vec<HeaderPair>, version: HttpVersion) -> Flow {
        Flow {
            id: "test".to_string(),
            kind: FlowKind::Http,
            state: FlowState::Complete,
            intercepted: true,
            request: FlowRequest {
                method: "POST".to_string(),
                url: "https://api.example.com/v1/users?page=2".to_string(),
                scheme: Scheme::Https,
                authority: "api.example.com".to_string(),
                host: "api.example.com".to_string(),
                port: 443,
                path: "/v1/users?page=2".to_string(),
                http_version: version,
                headers,
                body: None,
            },
            response: None,
            error: None,
            timings: FlowTimings::default(),
            client: FlowClient {
                address: "127.0.0.1".to_string(),
                port: 0,
            },
            server: FlowServer::default(),
            replay_of: None,
            comment: None,
            ws_messages: None,
            tunnel: None,
            rewrites: Vec::new(),
            mocked: false,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        }
    }

    #[test]
    fn single_quotes_inside_a_value_survive() {
        let flow = flow_with(
            vec![("X-Note".to_string(), "it's fine".to_string())],
            HttpVersion::Http11,
        );
        let out = to_curl(&flow, None);
        assert!(
            out.contains(r"--header 'X-Note: it'\''s fine'"),
            "unexpected output:\n{out}"
        );
    }

    #[test]
    fn newlines_stay_inside_the_quoted_body() {
        let flow = flow_with(vec![], HttpVersion::Http11);
        let out = to_curl(&flow, Some(b"line one\nline 'two'\n"));
        assert!(
            out.contains("--data-binary 'line one\nline '\\''two'\\''\n'"),
            "unexpected output:\n{out}"
        );
    }

    #[test]
    fn quoting_round_trips_through_a_shell() {
        // A crude model of what `sh` does with a single quoted word.
        fn unquote(input: &str) -> String {
            let mut out = String::new();
            let mut chars = input.chars().peekable();
            let mut inside = false;
            while let Some(ch) = chars.next() {
                match ch {
                    '\'' => inside = !inside,
                    '\\' if !inside => {
                        if let Some(next) = chars.next() {
                            out.push(next);
                        }
                    }
                    other => out.push(other),
                }
            }
            out
        }

        for value in [
            "plain",
            "it's",
            "'''",
            "line\nbreak",
            "$HOME `whoami` \\ \"quoted\"",
            "",
        ] {
            assert_eq!(unquote(&quote(value)), value, "failed for {value:?}");
        }
    }

    #[test]
    fn hop_by_hop_and_pseudo_headers_are_left_out() {
        let flow = flow_with(
            vec![
                (":method".to_string(), "POST".to_string()),
                (":authority".to_string(), "api.example.com".to_string()),
                ("Connection".to_string(), "keep-alive".to_string()),
                ("keep-alive".to_string(), "timeout=5".to_string()),
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
                ("Proxy-Connection".to_string(), "keep-alive".to_string()),
                ("Upgrade".to_string(), "h2c".to_string()),
                ("TE".to_string(), "trailers".to_string()),
                ("Content-Length".to_string(), "999".to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            HttpVersion::Http11,
        );
        let out = to_curl(&flow, None);

        for absent in [
            ":method",
            ":authority",
            "Connection:",
            "keep-alive:",
            "Transfer-Encoding",
            "Proxy-Connection",
            "Upgrade",
            "TE:",
            "Content-Length",
        ] {
            assert!(!out.contains(absent), "{absent} should not appear in:\n{out}");
        }
        assert!(out.contains("--header 'Accept: application/json'"));
    }

    #[test]
    fn binary_bodies_go_through_printf() {
        let flow = flow_with(vec![], HttpVersion::Http11);
        let out = to_curl(&flow, Some(&[0x00, 0xff, b'A', b'%', b'\\', 0x0a]));
        assert!(out.starts_with("printf '"), "unexpected output:\n{out}");
        assert!(out.contains(r"\000"), "unexpected output:\n{out}");
        assert!(out.contains(r"\377"), "unexpected output:\n{out}");
        assert!(out.contains("A%%"), "unexpected output:\n{out}");
        assert!(out.contains(r"\\"), "unexpected output:\n{out}");
        assert!(out.contains("--data-binary @-"), "unexpected output:\n{out}");
        assert!(!out.contains("--data-binary '"), "unexpected output:\n{out}");
    }

    #[test]
    fn http2_is_flagged_and_insecure_never_is() {
        let two = to_curl(&flow_with(vec![], HttpVersion::Http2), None);
        assert!(two.contains("--http2"));
        assert!(!two.contains("--insecure"));
        assert!(!two.contains(" -k"));

        let one = to_curl(&flow_with(vec![], HttpVersion::Http11), None);
        assert!(!one.contains("--http2"));
    }

    #[test]
    fn the_url_and_method_are_always_present() {
        let out = to_curl(&flow_with(vec![], HttpVersion::Http11), None);
        assert!(out.contains("--request 'POST'"));
        assert!(out.contains("--url 'https://api.example.com/v1/users?page=2'"));
        assert!(out.starts_with("curl \\\n  "));
    }

    #[test]
    fn the_captured_content_encoding_never_labels_a_decoded_body() {
        let flow = flow_with(
            vec![
                ("Content-Encoding".to_string(), "gzip".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            HttpVersion::Http11,
        );
        // What the caller hands in is the plaintext, so claiming gzip would
        // make curl send plaintext that the origin then tries to inflate.
        let out = to_curl(&flow, Some(br#"{"plain":"text"}"#));
        assert!(
            !out.to_ascii_lowercase().contains("content-encoding"),
            "unexpected output:\n{out}"
        );
        assert!(
            out.contains("--header 'Content-Type: application/json'"),
            "an ordinary header was dropped along with the encoding:\n{out}"
        );
    }

    #[test]
    fn a_body_starting_with_an_at_sign_is_not_read_as_a_filename() {
        let flow = flow_with(vec![], HttpVersion::Http11);
        let out = to_curl(&flow, Some(b"@/etc/passwd"));
        assert!(
            !out.contains("--data-binary '@"),
            "curl would read that as a filename:\n{out}"
        );
        assert!(out.starts_with("printf '"), "unexpected output:\n{out}");
        assert!(out.contains("--data-binary @-"), "unexpected output:\n{out}");
        assert!(
            out.contains("@/etc/passwd"),
            "the body itself went missing:\n{out}"
        );
    }

    #[test]
    fn an_empty_body_adds_no_data_flag() {
        let out = to_curl(&flow_with(vec![], HttpVersion::Http11), Some(&[]));
        assert!(!out.contains("--data-binary"));
    }
}
