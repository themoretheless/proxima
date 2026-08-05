//! Watching an upgraded WebSocket without getting in its way.
//!
//! Once a 101 goes through, the connection stops being HTTP and becomes a
//! stream of RFC 6455 frames. The proxy copies those bytes in both directions
//! unchanged and parses a copy of them purely to describe what went past.
//!
//! Parsing is deliberately forgiving. If a frame header does not make sense,
//! observation stops for that direction and the bytes keep flowing: an
//! extension that negotiated a framing we do not understand (compression, for
//! one) must not turn into a broken connection. A debugging tool that corrupts
//! the thing it is watching is worse than one that admits it cannot read it.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::capture::FlowStore;
use crate::types::{now_ms, FlowId, WsDirection, WsMessage};

/// Read size for the copy loop. Frames are usually small and interactive.
const READ_BUF: usize = 16 * 1024;
/// Text payloads up to this size are inlined in the event; larger ones and all
/// binary frames go to the body store.
const INLINE_TEXT_LIMIT: usize = 4 * 1024;
/// Frames beyond this are recorded by size only. A parser that trusted the
/// declared length would otherwise let a peer name a 2 GiB frame and be handed
/// the allocation for free.
const MAX_CAPTURED_PAYLOAD: u64 = 1024 * 1024;

/// Copies both directions of an upgraded connection, recording frames as they
/// pass. Returns when either side closes.
pub async fn pump<C, U>(client: C, upstream: U, store: Arc<FlowStore>, id: FlowId)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);

    let to_upstream = observe(
        client_read,
        upstream_write,
        store.clone(),
        id.clone(),
        WsDirection::Send,
    );
    let to_client = observe(
        upstream_read,
        client_write,
        store.clone(),
        id.clone(),
        WsDirection::Recv,
    );

    // Either half finishing means the socket is done; the other half is dropped
    // with it rather than left waiting on a peer that has gone.
    tokio::select! {
        _ = to_upstream => {}
        _ = to_client => {}
    }
    store.finish(&id);
}

/// One direction: read, record, write on unchanged.
async fn observe<R, W>(
    mut from: R,
    mut to: W,
    store: Arc<FlowStore>,
    id: FlowId,
    direction: WsDirection,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut parser = FrameParser::default();
    let mut buf = vec![0u8; READ_BUF];

    loop {
        let read = match from.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => {
                debug!(%id, error = %err, "websocket read failed");
                break;
            }
        };

        // Forwarding happens before parsing so that observation can never add
        // latency to the connection being observed.
        if let Err(err) = to.write_all(&buf[..read]).await {
            debug!(%id, error = %err, "websocket write failed");
            break;
        }

        for frame in parser.feed(&buf[..read]) {
            record(&store, &id, direction, frame);
        }
    }
    let _ = to.shutdown().await;
}

fn record(store: &FlowStore, id: &FlowId, direction: WsDirection, frame: Observed) {
    let mut message = WsMessage {
        at: now_ms(),
        direction,
        opcode: frame.opcode,
        size: frame.size,
        truncated: frame.truncated,
        text: None,
        body_id: None,
    };

    if !frame.payload.is_empty() {
        // Opcode 1 is text; a continuation frame carries no opcode of its own,
        // so its payload is stored rather than guessed at.
        let as_text = (frame.opcode == 1 && frame.payload.len() <= INLINE_TEXT_LIMIT)
            .then(|| String::from_utf8(frame.payload.clone()).ok())
            .flatten();
        match as_text {
            Some(text) => message.text = Some(text),
            None => {
                let mut writer = store.bodies().writer(store.max_body_bytes());
                writer.write(&frame.payload);
                message.body_id = Some(writer.finish(None, None).id);
            }
        }
    }

    store.add_ws_message(id, message);
}

/* ------------------------------------------------------------------ */
/* frame parsing                                                       */
/* ------------------------------------------------------------------ */

/// What one frame looked like, as far as we could tell.
struct Observed {
    opcode: u8,
    /// Declared payload length, which is what the peer actually sent.
    size: u64,
    /// Set when the payload was longer than we were willing to keep.
    truncated: bool,
    payload: Vec<u8>,
}

/// A frame whose header has been read and whose payload is still arriving.
///
/// The payload is consumed as it comes rather than waited for in full: the
/// declared length is the peer's claim, and buffering it would let a peer name a
/// gigabyte and be handed the allocation. Only the first
/// [`MAX_CAPTURED_PAYLOAD`] bytes are retained; the rest is counted and dropped.
struct Partial {
    opcode: u8,
    /// Declared payload length, recorded whether or not it is all kept.
    size: u64,
    mask: Option<[u8; 4]>,
    /// Payload bytes still to come before this frame ends.
    remaining: u64,
    /// The retained prefix, never longer than [`MAX_CAPTURED_PAYLOAD`].
    payload: Vec<u8>,
    truncated: bool,
}

/// Incremental RFC 6455 reader over a byte stream.
///
/// Frames arrive split across reads and several per read, so the parser holds
/// its own buffer and yields whatever became complete. Once `broken` is set it
/// yields nothing further: the stream is still copied, we just stop claiming to
/// understand it.
///
/// Memory is bounded by the read size plus [`MAX_CAPTURED_PAYLOAD`], regardless
/// of what lengths the peer declares.
#[derive(Default)]
struct FrameParser {
    buf: Vec<u8>,
    partial: Option<Partial>,
    broken: bool,
}

impl FrameParser {
    fn feed(&mut self, chunk: &[u8]) -> Vec<Observed> {
        let mut out = Vec::new();
        if self.broken {
            return out;
        }
        self.buf.extend_from_slice(chunk);

        loop {
            match self.next_frame() {
                Step::Frame(frame) => out.push(frame),
                Step::NeedMore => break,
                Step::Broken => {
                    debug!("websocket framing was not understood, only copying from here on");
                    self.broken = true;
                    self.buf = Vec::new();
                    self.partial = None;
                    break;
                }
            }
        }
        out
    }

    /// Takes as much of the frame in flight as has arrived, keeping only the
    /// prefix that fits under the capture limit and dropping the rest.
    fn consume_payload(&mut self) -> Step {
        let Some(partial) = self.partial.as_mut() else {
            return Step::NeedMore;
        };

        let take = partial.remaining.min(self.buf.len() as u64);
        // Where this chunk starts within the payload, which is what the mask
        // key is indexed by.
        let offset = partial.size - partial.remaining;
        if offset < MAX_CAPTURED_PAYLOAD {
            let keep = (MAX_CAPTURED_PAYLOAD - offset).min(take) as usize;
            let from = partial.payload.len();
            partial.payload.extend_from_slice(&self.buf[..keep]);
            if let Some(key) = partial.mask {
                for (i, byte) in partial.payload[from..].iter_mut().enumerate() {
                    *byte ^= key[(from + i) % 4];
                }
            }
        }
        partial.remaining -= take;
        self.buf.drain(..take as usize);

        if partial.remaining > 0 {
            return Step::NeedMore;
        }
        let done = self.partial.take().expect("checked just above");
        Step::Frame(Observed {
            opcode: done.opcode,
            size: done.size,
            truncated: done.truncated,
            payload: done.payload,
        })
    }

    fn next_frame(&mut self) -> Step {
        if self.partial.is_some() {
            return self.consume_payload();
        }
        if self.buf.len() < 2 {
            return Step::NeedMore;
        }
        let first = self.buf[0];
        let second = self.buf[1];
        let opcode = first & 0x0f;
        let masked = second & 0x80 != 0;
        let short_len = second & 0x7f;

        // Reserved opcodes mean an extension is in play that we do not know how
        // to frame, and guessing past it would desynchronise everything after.
        if !matches!(opcode, 0x0..=0x2 | 0x8..=0xa) {
            return Step::Broken;
        }

        let mut offset = 2usize;
        let payload_len: u64 = match short_len {
            126 => {
                if self.buf.len() < offset + 2 {
                    return Step::NeedMore;
                }
                let len = u16::from_be_bytes([self.buf[offset], self.buf[offset + 1]]) as u64;
                offset += 2;
                len
            }
            127 => {
                if self.buf.len() < offset + 8 {
                    return Step::NeedMore;
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&self.buf[offset..offset + 8]);
                offset += 8;
                let len = u64::from_be_bytes(bytes);
                // The high bit must be zero per the spec, and a length that
                // large is a framing error rather than a real message.
                if len > i64::MAX as u64 {
                    return Step::Broken;
                }
                len
            }
            other => other as u64,
        };

        // A control frame carries at most 125 bytes and is never fragmented.
        if opcode >= 0x8 && (payload_len > 125 || first & 0x80 == 0) {
            return Step::Broken;
        }

        let mask = if masked {
            if self.buf.len() < offset + 4 {
                return Step::NeedMore;
            }
            let key = [
                self.buf[offset],
                self.buf[offset + 1],
                self.buf[offset + 2],
                self.buf[offset + 3],
            ];
            offset += 4;
            Some(key)
        } else {
            None
        };

        // The header is complete, so it goes and the payload becomes the frame
        // in flight. Nothing waits for the declared length to arrive: a frame
        // that never completes must not cost more than the prefix we keep.
        self.buf.drain(..offset);
        self.partial = Some(Partial {
            opcode,
            size: payload_len,
            mask,
            remaining: payload_len,
            payload: Vec::new(),
            truncated: payload_len > MAX_CAPTURED_PAYLOAD,
        });
        self.consume_payload()
    }
}

enum Step {
    Frame(Observed),
    NeedMore,
    Broken,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a frame the way a client would: FIN set, masked.
    fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let key = [0x37u8, 0xfa, 0x21, 0x3d];
        let mut out = vec![0x80 | opcode];
        let len = payload.len();
        if len < 126 {
            out.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        out.extend_from_slice(&key);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        out
    }

    /// Builds a frame the way a server would: FIN set, unmasked.
    fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80 | opcode];
        let len = payload.len();
        if len < 126 {
            out.push(len as u8);
        } else {
            out.push(126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn a_masked_text_frame_is_unmasked() {
        let mut parser = FrameParser::default();
        let frames = parser.feed(&masked_frame(1, b"Hello"));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].opcode, 1);
        assert_eq!(frames[0].size, 5);
        assert_eq!(frames[0].payload, b"Hello");
        assert!(!frames[0].truncated);
    }

    #[test]
    fn an_unmasked_server_frame_reads_straight_through() {
        let mut parser = FrameParser::default();
        let frames = parser.feed(&server_frame(1, b"pong from the server"));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"pong from the server");
    }

    #[test]
    fn several_frames_in_one_read_all_arrive() {
        let mut bytes = masked_frame(1, b"one");
        bytes.extend(masked_frame(1, b"two"));
        bytes.extend(masked_frame(2, &[0xff, 0x00]));

        let mut parser = FrameParser::default();
        let frames = parser.feed(&bytes);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].payload, b"one");
        assert_eq!(frames[1].payload, b"two");
        assert_eq!(frames[2].opcode, 2);
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let bytes = masked_frame(1, b"split across reads");
        let mut parser = FrameParser::default();

        for cut in [1usize, 2, 5, 9] {
            let mut parser = FrameParser::default();
            assert!(parser.feed(&bytes[..cut]).is_empty(), "cut at {cut} yielded early");
            let frames = parser.feed(&bytes[cut..]);
            assert_eq!(frames.len(), 1, "cut at {cut} lost the frame");
            assert_eq!(frames[0].payload, b"split across reads");
        }

        // And one byte at a time, which is the pathological case.
        let mut collected = Vec::new();
        for byte in &bytes {
            collected.extend(parser.feed(&[*byte]));
        }
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].payload, b"split across reads");
    }

    #[test]
    fn extended_lengths_are_read() {
        let payload = vec![b'x'; 1000];
        let mut parser = FrameParser::default();
        let frames = parser.feed(&masked_frame(1, &payload));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].size, 1000);
        assert_eq!(frames[0].payload.len(), 1000);
    }

    #[test]
    fn control_frames_are_recognised() {
        let mut parser = FrameParser::default();
        let frames = parser.feed(&masked_frame(9, b"ping"));
        assert_eq!(frames[0].opcode, 9);

        let close = parser.feed(&masked_frame(8, &[0x03, 0xe8]));
        assert_eq!(close[0].opcode, 8);
        assert_eq!(close[0].size, 2);
    }

    #[test]
    fn an_oversized_payload_is_counted_but_not_kept() {
        let payload = vec![b'z'; MAX_CAPTURED_PAYLOAD as usize + 64];
        let mut parser = FrameParser::default();
        let frames = parser.feed(&masked_frame(2, &payload));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].size, payload.len() as u64);
        assert_eq!(frames[0].payload.len(), MAX_CAPTURED_PAYLOAD as usize);
        assert!(frames[0].truncated);
    }

    #[test]
    fn a_huge_declared_length_never_grows_the_parser() {
        // Three gigabytes, declared and then dribbled in. Nothing about this is
        // illegal framing, so the parser has to keep observing without ever
        // holding more than one read plus the capture limit.
        let declared: u64 = 3 * 1024 * 1024 * 1024;
        let mut header = vec![0x82u8, 127];
        header.extend_from_slice(&declared.to_be_bytes());

        let mut parser = FrameParser::default();
        assert!(parser.feed(&header).is_empty(), "the frame is not over yet");

        let chunk = vec![b'q'; READ_BUF];
        let mut sent = 0usize;
        while sent < 8 * READ_BUF + MAX_CAPTURED_PAYLOAD as usize {
            assert!(parser.feed(&chunk).is_empty());
            sent += chunk.len();

            assert!(
                parser.buf.len() <= chunk.len(),
                "the parser is buffering the declared length, {} bytes held after {sent} sent",
                parser.buf.len()
            );
            let retained = parser.partial.as_ref().map(|p| p.payload.len()).unwrap_or(0);
            assert!(
                retained <= MAX_CAPTURED_PAYLOAD as usize,
                "retained {retained} bytes, past the capture limit"
            );
        }

        // Still parsing, still counting, just no longer keeping.
        assert!(!parser.broken);
        let partial = parser.partial.as_ref().expect("the frame is still in flight");
        assert_eq!(partial.size, declared);
        assert!(partial.truncated);
        assert_eq!(partial.remaining, declared - sent as u64);
    }

    #[test]
    fn a_truncated_frame_still_completes_with_its_full_size() {
        let payload = vec![b'y'; MAX_CAPTURED_PAYLOAD as usize * 2];
        let bytes = masked_frame(2, &payload);

        // Split so the capture limit is crossed mid-chunk rather than on a
        // convenient boundary, which is where a mask offset goes wrong.
        let mut parser = FrameParser::default();
        let mut frames = Vec::new();
        for piece in bytes.chunks(7919) {
            frames.extend(parser.feed(piece));
        }

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].size, payload.len() as u64);
        assert!(frames[0].truncated);
        assert_eq!(frames[0].payload.len(), MAX_CAPTURED_PAYLOAD as usize);
        assert_eq!(
            frames[0].payload.as_slice(),
            &payload[..MAX_CAPTURED_PAYLOAD as usize],
            "the retained prefix was unmasked with the wrong key offset"
        );
        assert!(parser.partial.is_none(), "the frame was not released");
    }

    #[test]
    fn a_reserved_opcode_stops_observation_without_panicking() {
        let mut parser = FrameParser::default();
        // Opcode 3 is reserved, so the framing after it cannot be trusted.
        let frames = parser.feed(&masked_frame(3, b"unknown extension"));
        assert!(frames.is_empty());
        assert!(parser.broken);

        // Everything after is copied but no longer parsed.
        assert!(parser.feed(&masked_frame(1, b"later")).is_empty());
    }

    #[test]
    fn a_fragmented_control_frame_is_rejected() {
        // FIN clear on a close frame: illegal, and a sign the framing is off.
        let bytes = vec![0x08, 0x00];
        let mut parser = FrameParser::default();
        assert!(parser.feed(&bytes).is_empty());
        assert!(parser.broken);
    }

    #[test]
    fn an_absurd_declared_length_is_rejected_before_allocating() {
        let mut bytes = vec![0x81, 127];
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        let mut parser = FrameParser::default();
        assert!(parser.feed(&bytes).is_empty());
        assert!(parser.broken, "a length with the high bit set is a framing error");
    }

    #[test]
    fn a_continuation_frame_keeps_its_opcode() {
        let mut parser = FrameParser::default();
        let frames = parser.feed(&masked_frame(0, b"rest of the message"));
        assert_eq!(frames[0].opcode, 0, "continuation frames are recorded as such");
    }
}
