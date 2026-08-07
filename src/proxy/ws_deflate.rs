//! Observe-side permessage-deflate (RFC 7692) for WebSocket capture.
//!
//! The proxy never rewrites `Sec-WebSocket-Extensions`. When the 101 response
//! negotiates `permessage-deflate`, this module parses the accepted parameters
//! and inflates a **copy** of each compressed message for the inspector.
//!
//! The on-wire path stays an exact byte copy. Decompress never feeds the peer
//! write path, so RSV1 and the compressed payload stay intact end-to-end.
//!
//! # Passthrough limits under deflate
//!
//! When deflate is negotiated, parse-before-forward (structured rewrite,
//! text_regex, breakpoints that re-encode) is disabled. Re-encoding with
//! [`super::websocket::encode_frame`] would clear RSV1 and corrupt the peers.
//! Inject still works: injected frames are uncompressed (legal) and recorded
//! as usual.

use flate2::{Decompress, FlushDecompress, Status};

/// RFC 7692 empty DEFLATE block. Stripped from each compressed message on the
/// wire; the receiver must append it before inflate.
const DEFLATE_TRAILER: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// Parsed from `Sec-WebSocket-Extensions` on the 101 (end-to-end; the proxy
/// does not rewrite the header).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PermessageDeflateParams {
    pub enabled: bool,
    pub client_no_context_takeover: bool,
    pub server_no_context_takeover: bool,
    /// 8..=15, default 15 when the parameter is absent.
    pub client_max_window_bits: u8,
    /// 8..=15, default 15 when the parameter is absent.
    pub server_max_window_bits: u8,
}

/// Result of feeding one data frame into the capture inflater.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateFrameResult {
    /// Uncompressed message (no RSV1 path) or deflate off; keep wire payload.
    Passthrough,
    /// Display bytes for this frame/message. Wire size stays separate.
    Decoded(Vec<u8>),
    /// Keep wire payload for display; inflater left consistent if possible.
    Failed,
}

/// Per-direction capture inflater (not on the wire path).
///
/// One instance per half. Client-to-server uses the client window bits and
/// `client_no_context_takeover`; server-to-client uses the server pair.
///
/// Inflate always uses flate2's default raw window (15). A receiver window of
/// 15 can inflate any stream whose compressor used 8..=15, so negotiated
/// `*_max_window_bits` need not reconfigure miniz (that API is behind flate2's
/// optional zlib backend).
pub struct MessageInflater {
    no_context_takeover: bool,
    decompress: Decompress,
    /// True while a compressed data message is in progress (RSV1 saw start,
    /// FIN not yet seen). Control frames never touch this.
    in_compressed: bool,
    /// Concatenated wire payloads for the current compressed message.
    message_buf: Vec<u8>,
}

impl MessageInflater {
    pub fn new(_max_window_bits: u8, no_context_takeover: bool) -> Self {
        Self {
            no_context_takeover,
            // Raw DEFLATE: no zlib wrapper (RFC 7692). Window 15 default.
            decompress: Decompress::new(false),
            in_compressed: false,
            message_buf: Vec::new(),
        }
    }

    /// Feed one data frame. `rsv1` marks message start; `fin` ends it and may
    /// reset the inflater when no-context-takeover is set.
    ///
    /// Intermediate frames of a compressed message return [`InflateFrameResult::Passthrough`]
    /// (display stays the wire bytes); the full decoded message is attached on FIN.
    /// Truncated captures should not call this with a partial prefix: use
    /// [`Self::abandon_message`] instead so the dictionary is not poisoned
    /// with half a frame.
    pub fn feed_frame(
        &mut self,
        rsv1: bool,
        fin: bool,
        wire_payload: &[u8],
        max_out: usize,
    ) -> InflateFrameResult {
        if !self.in_compressed {
            if !rsv1 {
                // Uncompressed data message (or we lost sync). Do not touch
                // the inflater: an uncompressed message must not reset context.
                return InflateFrameResult::Passthrough;
            }
            self.in_compressed = true;
            self.message_buf.clear();
        } else if rsv1 {
            // RSV1 mid-message is illegal; abandon and fail this frame.
            self.abandon_message();
            return InflateFrameResult::Failed;
        }

        self.message_buf.extend_from_slice(wire_payload);

        if !fin {
            // Keep continuity; display path uses wire bytes until FIN.
            return InflateFrameResult::Passthrough;
        }

        // End of compressed message: append the stripped empty block and inflate.
        let mut input = std::mem::take(&mut self.message_buf);
        input.extend_from_slice(&DEFLATE_TRAILER);
        self.in_compressed = false;

        // Decompress into a buffer capped at max_out + 1 so oversize is visible.
        let ceiling = max_out.saturating_add(1);
        let mut out = Vec::new();
        let mut input_offset = 0usize;
        loop {
            let before_in = self.decompress.total_in();
            let before_out = self.decompress.total_out();
            if out.len() >= ceiling {
                self.reset_decompress();
                return InflateFrameResult::Failed;
            }
            let chunk = (ceiling - out.len()).min(64 * 1024);
            let old_len = out.len();
            out.resize(old_len + chunk, 0);
            let status = self.decompress.decompress(
                &input[input_offset..],
                &mut out[old_len..],
                FlushDecompress::Sync,
            );
            let wrote = (self.decompress.total_out() - before_out) as usize;
            let read = (self.decompress.total_in() - before_in) as usize;
            out.truncate(old_len + wrote);
            input_offset += read;

            match status {
                Ok(Status::StreamEnd) => break,
                Ok(Status::Ok) | Ok(Status::BufError) => {
                    // Output buffer full (or nearly): more pending if we filled
                    // the spare or input remains / inflater still has state.
                    if out.len() >= ceiling {
                        self.reset_decompress();
                        return InflateFrameResult::Failed;
                    }
                    if wrote == 0 && read == 0 {
                        // No progress. If input remains, the stream is corrupt.
                        if input_offset < input.len() {
                            self.reset_decompress();
                            return InflateFrameResult::Failed;
                        }
                        break;
                    }
                    // Filled this chunk with input still producing: grow again.
                    // Done when input is exhausted and the last write did not
                    // fill the whole spare (no more pending output).
                    if input_offset >= input.len() && wrote < chunk {
                        break;
                    }
                }
                Err(_) => {
                    self.reset_decompress();
                    return InflateFrameResult::Failed;
                }
            }
        }

        if out.len() > max_out {
            self.reset_decompress();
            return InflateFrameResult::Failed;
        }

        if self.no_context_takeover {
            self.reset_decompress();
        }

        InflateFrameResult::Decoded(out)
    }

    /// True while a compressed message has started and FIN has not been seen.
    pub fn in_compressed_message(&self) -> bool {
        self.in_compressed
    }

    /// Drop an in-flight compressed message without feeding truncated bytes.
    /// Resets the inflater so later messages are not decoded against a broken
    /// dictionary (context takeover cannot survive a skipped message).
    pub fn abandon_message(&mut self) {
        self.in_compressed = false;
        self.message_buf.clear();
        self.reset_decompress();
    }

    fn reset_decompress(&mut self) {
        self.decompress = Decompress::new(false);
    }
}

fn clamp_window_bits(bits: u8) -> u8 {
    bits.clamp(8, 15)
}

/// Parse `Sec-WebSocket-Extensions` from the 101 response.
///
/// Only `permessage-deflate` is recognised. Unknown extensions are ignored.
/// When the parameter is absent, window bits default to 15.
pub fn parse_sec_websocket_extensions(header: Option<&str>) -> PermessageDeflateParams {
    let Some(header) = header else {
        return PermessageDeflateParams::default();
    };

    let mut params = PermessageDeflateParams {
        client_max_window_bits: 15,
        server_max_window_bits: 15,
        ..PermessageDeflateParams::default()
    };

    // Multiple extensions: comma-separated. Each extension is name + ';' params.
    for ext in header.split(',') {
        let ext = ext.trim();
        if ext.is_empty() {
            continue;
        }
        let mut parts = ext.split(';');
        let name = parts.next().unwrap_or("").trim();
        if !name.eq_ignore_ascii_case("permessage-deflate") {
            continue;
        }
        params.enabled = true;
        for param in parts {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            let (key, value) = match param.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim().trim_matches('"'))),
                None => (param, None),
            };
            if key.eq_ignore_ascii_case("client_no_context_takeover") {
                params.client_no_context_takeover = true;
            } else if key.eq_ignore_ascii_case("server_no_context_takeover") {
                params.server_no_context_takeover = true;
            } else if key.eq_ignore_ascii_case("client_max_window_bits") {
                if let Some(v) = value {
                    if let Ok(n) = v.parse::<u8>() {
                        params.client_max_window_bits = clamp_window_bits(n);
                    }
                }
                // Bare flag without value: keep default 15 (server accepted offer).
            } else if key.eq_ignore_ascii_case("server_max_window_bits") {
                if let Some(v) = value {
                    if let Ok(n) = v.parse::<u8>() {
                        params.server_max_window_bits = clamp_window_bits(n);
                    }
                }
            }
        }
        // First permessage-deflate wins; further identical offers are rare.
        break;
    }

    params
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;

    fn compress_message(data: &[u8]) -> Vec<u8> {
        // Raw deflate + SYNC_FLUSH empty block, then strip the trailer peers omit.
        // compress_vec does not grow the vec; reserve spare capacity first.
        use flate2::{Compress, FlushCompress};
        let mut c = Compress::new(Compression::default(), false);
        let mut out = Vec::with_capacity(data.len() + 64);
        c.compress_vec(data, &mut out, FlushCompress::Sync)
            .expect("compress");
        assert!(
            out.ends_with(&DEFLATE_TRAILER),
            "SYNC_FLUSH should end with empty block, got {out:02x?}"
        );
        out.truncate(out.len() - 4);
        out
    }

    #[test]
    fn parse_absent_is_disabled() {
        assert!(!parse_sec_websocket_extensions(None).enabled);
        assert!(!parse_sec_websocket_extensions(Some("")).enabled);
        assert!(!parse_sec_websocket_extensions(Some("x-foo")).enabled);
    }

    #[test]
    fn parse_basic_permessage_deflate() {
        let p = parse_sec_websocket_extensions(Some("permessage-deflate"));
        assert!(p.enabled);
        assert!(!p.client_no_context_takeover);
        assert!(!p.server_no_context_takeover);
        assert_eq!(p.client_max_window_bits, 15);
        assert_eq!(p.server_max_window_bits, 15);
    }

    #[test]
    fn parse_params_case_insensitive() {
        let p = parse_sec_websocket_extensions(Some(
            "PerMessage-Deflate; Server_No_Context_Takeover; client_max_window_bits=12",
        ));
        assert!(p.enabled);
        assert!(p.server_no_context_takeover);
        assert!(!p.client_no_context_takeover);
        assert_eq!(p.client_max_window_bits, 12);
    }

    #[test]
    fn parse_among_other_extensions() {
        let p = parse_sec_websocket_extensions(Some(
            "x-webkit-deflate-frame, permessage-deflate; client_no_context_takeover",
        ));
        assert!(p.enabled);
        assert!(p.client_no_context_takeover);
    }

    #[test]
    fn inflate_unfragmented_text() {
        let plain = b"Hello";
        let wire = compress_message(plain);
        let mut inf = MessageInflater::new(15, true);
        match inf.feed_frame(true, true, &wire, 1024 * 1024) {
            InflateFrameResult::Decoded(out) => assert_eq!(out, plain),
            other => panic!("expected Decoded, got {other:?}"),
        }
    }

    #[test]
    fn inflate_without_rsv1_is_passthrough() {
        let mut inf = MessageInflater::new(15, true);
        assert_eq!(
            inf.feed_frame(false, true, b"plain", 1024),
            InflateFrameResult::Passthrough
        );
    }

    #[test]
    fn no_context_takeover_resets_between_messages() {
        let a = compress_message(b"aaaaaaaaaa");
        let b = compress_message(b"bbbbbbbbbb");
        let mut inf = MessageInflater::new(15, true);
        assert!(matches!(
            inf.feed_frame(true, true, &a, 1024),
            InflateFrameResult::Decoded(_)
        ));
        // Independent messages still decode after reset.
        match inf.feed_frame(true, true, &b, 1024) {
            InflateFrameResult::Decoded(out) => assert_eq!(out, b"bbbbbbbbbb"),
            other => panic!("expected Decoded, got {other:?}"),
        }
    }

    #[test]
    fn context_takeover_reuses_dictionary() {
        // Two messages from one compressor (context takeover on).
        use flate2::{Compress, FlushCompress};
        let mut c = Compress::new(Compression::default(), false);
        let mut w1 = Vec::with_capacity(128);
        c.compress_vec(b"Hello Hello Hello", &mut w1, FlushCompress::Sync)
            .unwrap();
        w1.truncate(w1.len() - 4);
        let mut w2 = Vec::with_capacity(128);
        c.compress_vec(b"Hello Hello World", &mut w2, FlushCompress::Sync)
            .unwrap();
        w2.truncate(w2.len() - 4);

        let mut inf = MessageInflater::new(15, false);
        match inf.feed_frame(true, true, &w1, 1024) {
            InflateFrameResult::Decoded(out) => assert_eq!(out, b"Hello Hello Hello"),
            other => panic!("{other:?}"),
        }
        match inf.feed_frame(true, true, &w2, 1024) {
            InflateFrameResult::Decoded(out) => assert_eq!(out, b"Hello Hello World"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn fragmented_message_decodes_on_fin() {
        let wire = compress_message(b"fragmented payload here");
        let mid = wire.len() / 2;
        let mut inf = MessageInflater::new(15, true);
        assert_eq!(
            inf.feed_frame(true, false, &wire[..mid], 1024),
            InflateFrameResult::Passthrough
        );
        match inf.feed_frame(false, true, &wire[mid..], 1024) {
            InflateFrameResult::Decoded(out) => assert_eq!(out, b"fragmented payload here"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn oversize_output_fails_without_panic() {
        let wire = compress_message(&vec![b'x'; 1000]);
        let mut inf = MessageInflater::new(15, true);
        // Tiny ceiling forces failure.
        assert_eq!(
            inf.feed_frame(true, true, &wire, 16),
            InflateFrameResult::Failed
        );
        // Inflater is usable again after failure (reset).
        let small = compress_message(b"ok");
        assert!(matches!(
            inf.feed_frame(true, true, &small, 1024),
            InflateFrameResult::Decoded(_)
        ));
    }

    #[test]
    fn garbage_payload_fails() {
        let mut inf = MessageInflater::new(15, true);
        assert_eq!(
            inf.feed_frame(true, true, b"\xff\xff\xff not deflate", 1024),
            InflateFrameResult::Failed
        );
    }

    #[test]
    fn parse_clamps_window_bits_to_8_15() {
        let low = parse_sec_websocket_extensions(Some(
            "permessage-deflate; client_max_window_bits=3; server_max_window_bits=99",
        ));
        assert_eq!(low.client_max_window_bits, 8);
        assert_eq!(low.server_max_window_bits, 15);

        let bare = parse_sec_websocket_extensions(Some(
            "permessage-deflate; client_max_window_bits; server_max_window_bits",
        ));
        assert!(bare.enabled);
        assert_eq!(bare.client_max_window_bits, 15);
        assert_eq!(bare.server_max_window_bits, 15);
    }

    #[test]
    fn parse_both_no_context_takeover_flags() {
        let p = parse_sec_websocket_extensions(Some(
            "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
        ));
        assert!(p.enabled);
        assert!(p.client_no_context_takeover);
        assert!(p.server_no_context_takeover);
    }

    #[test]
    fn rsv1_mid_message_fails_and_recovers() {
        let wire = compress_message(b"split me");
        let mid = wire.len() / 2;
        let mut inf = MessageInflater::new(15, true);
        assert_eq!(
            inf.feed_frame(true, false, &wire[..mid], 1024),
            InflateFrameResult::Passthrough
        );
        // Illegal second RSV1 while a compressed message is open.
        assert_eq!(
            inf.feed_frame(true, true, &wire[mid..], 1024),
            InflateFrameResult::Failed
        );
        assert!(!inf.in_compressed_message());
        // Fresh message after abandon.
        let next = compress_message(b"after");
        match inf.feed_frame(true, true, &next, 1024) {
            InflateFrameResult::Decoded(out) => assert_eq!(out, b"after"),
            other => panic!("expected Decoded after recover, got {other:?}"),
        }
    }

    #[test]
    fn abandon_message_clears_partial_without_poisoning() {
        let wire = compress_message(b"never finished");
        let mut inf = MessageInflater::new(15, false);
        assert_eq!(
            inf.feed_frame(true, false, &wire[..wire.len() / 2], 1024),
            InflateFrameResult::Passthrough
        );
        assert!(inf.in_compressed_message());
        inf.abandon_message();
        assert!(!inf.in_compressed_message());
        // Context takeover cannot survive abandon; dictionary was reset.
        let next = compress_message(b"clean start");
        match inf.feed_frame(true, true, &next, 1024) {
            InflateFrameResult::Decoded(out) => assert_eq!(out, b"clean start"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn first_permessage_deflate_wins_among_duplicates() {
        let p = parse_sec_websocket_extensions(Some(
            "permessage-deflate; client_no_context_takeover, \
             permessage-deflate; server_no_context_takeover",
        ));
        assert!(p.enabled);
        assert!(p.client_no_context_takeover);
        assert!(
            !p.server_no_context_takeover,
            "second extension offer must not override the first"
        );
    }
}
