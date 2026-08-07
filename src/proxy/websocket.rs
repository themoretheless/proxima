//! Watching an upgraded WebSocket without getting in its way.
//!
//! Once a 101 goes through, the connection stops being HTTP and becomes a
//! stream of RFC 6455 frames. With no breakpoint rules and no WS rewrite
//! rules, the proxy copies those bytes in both directions unchanged and
//! parses a copy of them purely to describe what went past (zero extra
//! latency on the wire path).
//!
//! When any WebSocket breakpoint is enabled or any WS rewrite rule is active,
//! that half switches to parse-before-forward. Config rewrite/drop runs first
//! (see [`super::ws_rewrite`]); breakpoints then see the post-rewrite opcode
//! and payload. Non-matching frames are re-encoded and written; the mask key
//! may change. Broken framing falls back to opaque byte-copy and never pauses
//! or rewrites: an extension we cannot parse must not turn into a hung
//! connection, and structured rules have no match opportunity on opaque bytes.
//!
//! When the 101 negotiates `permessage-deflate` (see [`super::ws_deflate`]),
//! the pump stays on the raw-copy observe path for the life of the socket even
//! if rewrite or breakpoint rules are present. Re-encoding would strip RSV1
//! and break the peers. Capture still parses a copy and inflates compressed
//! messages for display (`WsMessage.compressed`); `size` remains the on-wire
//! length. Structured rewrite / text_regex / pause do not apply usefully under
//! deflate. Injected frames stay uncompressed (legal) and are still recorded.
//!
//! Injection is unpaused and unre-written: a frame composed through the API
//! (`ws/send` or multi-frame `ws/replay`) is encoded and written immediately,
//! then recorded with the same path as a real frame so the inspector cannot
//! tell the two histories apart except by the optional `injected` flag.
//! Replay never re-enters rewrite or breakpoint logic; it only queues inject
//! commands on the live halves.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use crate::capture::FlowStore;
use crate::types::{now_ms, FlowId, WsDirection, WsMessage};

use super::breakpoint::{
    await_decision, PauseDecision, PauseHub, WsPauseContext,
};
use super::ws_deflate::{
    InflateFrameResult, MessageInflater, PermessageDeflateParams,
};
use super::ws_rewrite::{WsRewriteHub, WsRewriteOutcome};

/// Read size for the copy loop. Frames are usually small and interactive.
const READ_BUF: usize = 16 * 1024;
/// Text payloads up to this size are inlined in the event; larger ones and all
/// binary frames go to the body store.
const INLINE_TEXT_LIMIT: usize = 4 * 1024;
/// Frames beyond this are recorded by size only. A parser that trusted the
/// declared length would otherwise let a peer name a 2 GiB frame and be handed
/// the allocation for free.
const MAX_CAPTURED_PAYLOAD: u64 = 1024 * 1024;
/// How many inject commands may queue on one half before further injects are
/// rejected rather than waiting silently on a stalled peer write.
const INJECT_CHANNEL: usize = 32;

/* ------------------------------------------------------------------ */
/* frame encoding                                                      */
/* ------------------------------------------------------------------ */

/// Builds one FIN frame. When `mask` is set, a random 4-byte mask is applied
/// (client-to-server wire format). Unmasked frames are the server-to-client form.
pub fn encode_frame(opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.push(0x80 | (opcode & 0x0f));
    let len = payload.len();
    let mask_bit = if mask { 0x80 } else { 0 };
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if mask {
        let mut key = [0u8; 4];
        rand::rng().fill_bytes(&mut key);
        out.extend_from_slice(&key);
        out.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % 4]),
        );
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/* ------------------------------------------------------------------ */
/* live connection registry                                            */
/* ------------------------------------------------------------------ */

/// One frame to write on a live half, with a reply once it has been recorded.
pub struct InjectCmd {
    pub opcode: u8,
    pub payload: Vec<u8>,
    /// Filled with the recorded message after a successful write, or dropped if
    /// the half closes before the frame can go out.
    pub reply: oneshot::Sender<WsMessage>,
}

/// Why an inject could not be handed to a live half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectError {
    /// No upgraded WebSocket is currently registered for this flow.
    NotLive,
    /// The half's inject queue is full; the peer write is likely stalled.
    Full,
    /// The half closed between lookup and send.
    Closed,
}

struct LiveHalf {
    /// Client to origin (masked on the wire).
    to_upstream: mpsc::Sender<InjectCmd>,
    /// Origin to client (unmasked on the wire).
    to_client: mpsc::Sender<InjectCmd>,
}

/// Maps live upgraded flows to the inject senders for each direction.
///
/// Register on pump entry, unregister on exit (before finish). Lookups never
/// hold the mutex across an await.
#[derive(Default)]
pub struct WsRegistry {
    inner: Mutex<HashMap<FlowId, LiveHalf>>,
}

impl WsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers inject senders for a live upgraded flow. Called by the pump
    /// (and any future compose dialer) on entry; pair with [`Self::unregister`]
    /// before finish so concurrent injects see [`InjectError::NotLive`].
    pub fn register(
        &self,
        id: FlowId,
        to_upstream: mpsc::Sender<InjectCmd>,
        to_client: mpsc::Sender<InjectCmd>,
    ) {
        self.inner.lock().insert(
            id,
            LiveHalf {
                to_upstream,
                to_client,
            },
        );
    }

    /// Drops inject senders for a flow. Safe to call when already absent.
    pub fn unregister(&self, id: &str) {
        self.inner.lock().remove(id);
    }

    /// True while a pump for this flow is registered.
    pub fn is_live(&self, id: &str) -> bool {
        self.inner.lock().contains_key(id)
    }

    /// Queues one frame on the half matching `direction`. Returns a receiver
    /// that yields the recorded message once the half has written and stored it.
    pub fn inject(
        &self,
        id: &str,
        direction: WsDirection,
        opcode: u8,
        payload: Vec<u8>,
    ) -> Result<oneshot::Receiver<WsMessage>, InjectError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = InjectCmd {
            opcode,
            payload,
            reply: reply_tx,
        };
        let sender = {
            let inner = self.inner.lock();
            let half = inner.get(id).ok_or(InjectError::NotLive)?;
            match direction {
                WsDirection::Send => half.to_upstream.clone(),
                WsDirection::Recv => half.to_client.clone(),
            }
        };
        match sender.try_send(cmd) {
            Ok(()) => Ok(reply_rx),
            Err(mpsc::error::TrySendError::Full(_)) => Err(InjectError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(InjectError::Closed),
        }
    }
}

/* ------------------------------------------------------------------ */
/* pump                                                                */
/* ------------------------------------------------------------------ */

/// Copies both directions of an upgraded connection, recording frames as they
/// pass and accepting injects from the registry. When `pauses` has enabled WS
/// rules or `ws_rewrite` is non-empty **and** permessage-deflate was not
/// negotiated, frames are parsed before forward so they can be rewritten, held,
/// or dropped. With deflate, the path stays raw-copy + observe-side inflate.
/// Returns when either side closes.
pub async fn pump<C, U>(
    client: C,
    upstream: U,
    store: Arc<FlowStore>,
    id: FlowId,
    registry: Arc<WsRegistry>,
    pauses: Arc<PauseHub>,
    ws_rewrite: Arc<WsRewriteHub>,
    host: String,
    path: String,
    deflate: PermessageDeflateParams,
) where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);

    let (tx_up, rx_up) = mpsc::channel(INJECT_CHANNEL);
    let (tx_client, rx_client) = mpsc::channel(INJECT_CHANNEL);
    registry.register(id.clone(), tx_up, tx_client);

    let pause_ctx = WsPauseContext {
        hub: pauses.clone(),
        host,
        path,
    };

    let to_upstream = observe(
        client_read,
        upstream_write,
        store.clone(),
        id.clone(),
        WsDirection::Send,
        rx_up,
        pause_ctx.clone(),
        ws_rewrite.clone(),
        deflate,
    );
    let to_client = observe(
        upstream_read,
        client_write,
        store.clone(),
        id.clone(),
        WsDirection::Recv,
        rx_client,
        pause_ctx,
        ws_rewrite,
        deflate,
    );

    // Either half finishing means the socket is done; the other half is dropped
    // with it rather than left waiting on a peer that has gone.
    tokio::select! {
        _ = to_upstream => {}
        _ = to_client => {}
    }
    // Unregister before finish so a concurrent inject sees not-live rather than
    // racing a half that is already shutting down.
    registry.unregister(&id);
    // Drop any held pauses so the UI does not keep offering release on a dead
    // socket, and so awaiters unblock.
    pauses.cancel_flow(&store, &id);
    store.finish(&id);
}

/// One direction: peer bytes are either copied then parsed (no rules / deflate)
/// or parsed then forwarded (breakpoints or WS rewrites active, no deflate).
/// Injects are never paused and never rewritten.
async fn observe<R, W>(
    mut from: R,
    mut to: W,
    store: Arc<FlowStore>,
    id: FlowId,
    direction: WsDirection,
    mut inject: mpsc::Receiver<InjectCmd>,
    pause_ctx: WsPauseContext,
    ws_rewrite: Arc<WsRewriteHub>,
    deflate: PermessageDeflateParams,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut parser = FrameParser::default();
    let mut buf = vec![0u8; READ_BUF];
    // Once the registry drops its senders, recv yields None forever. Stop
    // polling that branch so the half still drains peer traffic cleanly.
    let mut inject_open = true;
    // Deflate: never re-encode. RSV1 must reach the peer; encode_frame would
    // clear it. Sticky for the life of the half.
    let deflate_on = deflate.enabled;
    // Sticky: once any breakpoint is enabled or rewrites are present we stay
    // in parse-before-forward for the life of the half so a rule added
    // mid-stream still has a complete frame. Deflate overrides this permanently.
    // A half that saw broken framing drops back to opaque copy permanently.
    let mut parse_before_forward = !deflate_on
        && (pause_ctx.hub.any_ws_enabled() || !ws_rewrite.is_empty());
    let mut opaque_only = false;

    // Observe-side inflater only. Direction maps to the compressor that peer
    // uses: client->server uses client_* params, server->client uses server_*.
    let mut inflater = if deflate_on {
        let (bits, no_takeover) = match direction {
            WsDirection::Send => (
                deflate.client_max_window_bits,
                deflate.client_no_context_takeover,
            ),
            WsDirection::Recv => (
                deflate.server_max_window_bits,
                deflate.server_no_context_takeover,
            ),
        };
        Some(MessageInflater::new(bits, no_takeover))
    } else {
        None
    };

    loop {
        tokio::select! {
            read = from.read(&mut buf) => {
                let n = match read {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) => {
                        debug!(%id, error = %err, "websocket read failed");
                        break;
                    }
                };

                if opaque_only {
                    if let Err(err) = to.write_all(&buf[..n]).await {
                        debug!(%id, error = %err, "websocket write failed");
                        break;
                    }
                    continue;
                }

                // Re-check breakpoints and rewrite rules so enabling either
                // mid-connection takes effect on the next read without
                // restarting the pump. Sticky once true for this half. Never
                // when deflate is negotiated (re-encode would strip RSV1).
                if !deflate_on
                    && !parse_before_forward
                    && (pause_ctx.hub.any_ws_enabled() || !ws_rewrite.is_empty())
                {
                    parse_before_forward = true;
                }

                if !parse_before_forward {
                    // Zero-latency path: forward first, then describe a copy.
                    if let Err(err) = to.write_all(&buf[..n]).await {
                        debug!(%id, error = %err, "websocket write failed");
                        break;
                    }
                    for frame in parser.feed(&buf[..n]) {
                        let _ = record(
                            &store,
                            &id,
                            direction,
                            frame,
                            false,
                            inflater.as_mut(),
                        );
                    }
                    if parser.broken {
                        opaque_only = true;
                    }
                    continue;
                }

                // Parse-before-forward: complete frames may be rewritten/held.
                // (Unreachable when deflate_on; inflater is unused here.)
                let frames = parser.feed(&buf[..n]);
                for frame in frames {
                    // Once framing is broken we still forward frames that were
                    // already complete, but never pause on them: a half that is
                    // about to go opaque must not wait on the user. Rewrites
                    // still apply to those complete frames (they were parsed).
                    let allow_pause = !parser.broken;
                    if let Err(err) = handle_parsed_frame(
                        &mut to,
                        &store,
                        &id,
                        direction,
                        frame,
                        &pause_ctx,
                        &ws_rewrite,
                        allow_pause,
                    )
                    .await
                    {
                        debug!(%id, error = %err, "websocket write failed");
                        // End this half; the other select branch will die too.
                        let _ = to.shutdown().await;
                        return;
                    }
                }
                if parser.broken {
                    // Residual unparsed bytes (including the bad header) stay
                    // in the parser buffer; flush them as opaque and copy only
                    // from here on. Never pause on residual.
                    debug!(%id, "websocket framing broken; opaque copy only");
                    let residual = parser.take_residual();
                    if !residual.is_empty() {
                        if let Err(err) = to.write_all(&residual).await {
                            debug!(%id, error = %err, "websocket write failed");
                            break;
                        }
                    }
                    opaque_only = true;
                }
            }
            cmd = inject.recv(), if inject_open => {
                let Some(cmd) = cmd else {
                    inject_open = false;
                    continue;
                };
                // Inject is never paused: write immediately, then record.
                // Injected frames are uncompressed (no RSV1); legal under deflate.
                let mask = matches!(direction, WsDirection::Send);
                let wire = encode_frame(cmd.opcode, &cmd.payload, mask);
                if let Err(err) = to.write_all(&wire).await {
                    debug!(%id, error = %err, "websocket inject write failed");
                    // Reply is dropped; the API treats a closed receiver as failure.
                    break;
                }
                let size = cmd.payload.len() as u64;
                let truncated = size > MAX_CAPTURED_PAYLOAD;
                let mut payload = cmd.payload;
                if truncated {
                    payload.truncate(MAX_CAPTURED_PAYLOAD as usize);
                }
                let message = record(
                    &store,
                    &id,
                    direction,
                    Observed {
                        opcode: cmd.opcode,
                        size,
                        truncated,
                        payload,
                        fin: true,
                        rsv1: false,
                    },
                    true,
                    // Injected payloads are plain; do not run them through inflate.
                    None,
                );
                let _ = cmd.reply.send(message);
            }
        }
    }
    let _ = to.shutdown().await;
}

/// Rewrites, then forwards, holds, or drops one fully parsed frame.
async fn handle_parsed_frame<W>(
    to: &mut W,
    store: &FlowStore,
    id: &FlowId,
    direction: WsDirection,
    frame: Observed,
    pause_ctx: &WsPauseContext,
    ws_rewrite: &WsRewriteHub,
    allow_pause: bool,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mask = matches!(direction, WsDirection::Send);

    // Rewrite/drop first so breakpoints and capture see the post-rewrite body.
    // Inject never reaches this path.
    let outcome = ws_rewrite.apply(
        &pause_ctx.host,
        &pause_ctx.path,
        direction,
        frame.opcode,
        &frame.payload,
    );
    let (opcode, payload, rewrite_notes) = match outcome {
        WsRewriteOutcome::Drop { notes } => {
            if !notes.is_empty() {
                store.update(id, |flow| flow.rewrites.extend(notes));
            }
            // No write, no ws_message. Honest capture: a dropped frame never
            // left the proxy, so it must not appear as on-the-wire history.
            return Ok(());
        }
        WsRewriteOutcome::Forward {
            opcode,
            payload,
            notes,
        } => (opcode, payload, notes),
    };
    if !rewrite_notes.is_empty() {
        store.update(id, |flow| flow.rewrites.extend(rewrite_notes));
    }

    let size = payload.len() as u64;
    let truncated = size > MAX_CAPTURED_PAYLOAD;
    let mut kept = payload;
    if truncated {
        kept.truncate(MAX_CAPTURED_PAYLOAD as usize);
    }
    // Parse-before-forward re-encodes without RSV1; only used when deflate is off.
    let frame = Observed {
        opcode,
        size,
        truncated,
        payload: kept,
        fin: frame.fin,
        rsv1: false,
    };

    let rule = if allow_pause {
        pause_ctx.hub.matching_ws_rule(
            &pause_ctx.host,
            &pause_ctx.path,
            direction,
            frame.opcode,
        )
    } else {
        None
    };

    let Some(rule) = rule else {
        // No pause match: re-encode and forward; record what went on the wire.
        let wire = encode_frame(frame.opcode, &frame.payload, mask);
        to.write_all(&wire).await?;
        let _ = record(store, id, direction, frame, false, None);
        return Ok(());
    };

    let timeout_ms = rule.timeout_ms;
    let Some((pause_id, rx)) = pause_ctx.hub.hold_ws(
        store,
        id.clone(),
        direction,
        frame.opcode,
        frame.size,
        frame.truncated,
        &frame.payload,
        timeout_ms,
    ) else {
        // Cap full: forward post-rewrite body without pausing.
        let wire = encode_frame(frame.opcode, &frame.payload, mask);
        to.write_all(&wire).await?;
        let _ = record(store, id, direction, frame, false, None);
        return Ok(());
    };

    let decision = await_decision(&pause_ctx.hub, store, &pause_id, timeout_ms, rx).await;
    match decision {
        PauseDecision::Drop => {
            // Not forwarded; nothing recorded as on the wire.
            Ok(())
        }
        PauseDecision::Release { opcode, payload } => {
            let wire = encode_frame(opcode, &payload, mask);
            to.write_all(&wire).await?;
            let size = payload.len() as u64;
            let truncated = size > MAX_CAPTURED_PAYLOAD;
            let mut kept = payload;
            if truncated {
                kept.truncate(MAX_CAPTURED_PAYLOAD as usize);
            }
            let _ = record(
                store,
                id,
                direction,
                Observed {
                    opcode,
                    size,
                    truncated,
                    payload: kept,
                    fin: true,
                    rsv1: false,
                },
                false,
                None,
            );
            Ok(())
        }
        // HTTP decisions never come from the WS pump.
        PauseDecision::HttpRelease { .. } => Ok(()),
    }
}

fn record(
    store: &FlowStore,
    id: &FlowId,
    direction: WsDirection,
    frame: Observed,
    injected: bool,
    inflater: Option<&mut MessageInflater>,
) -> WsMessage {
    // Wire size is always the on-wire payload length, even when display is inflated.
    let wire_size = frame.size;
    let mut display = frame.payload;
    let mut compressed = false;

    if let Some(inf) = inflater {
        if matches!(frame.opcode, 0x0 | 0x1 | 0x2) {
            if frame.truncated {
                // Cannot inflate a truncated capture prefix; abandon so the
                // dictionary is not half-fed, then keep wire bytes for display.
                if frame.rsv1 || inf.in_compressed_message() {
                    inf.abandon_message();
                }
            } else {
                match inf.feed_frame(
                    frame.rsv1,
                    frame.fin,
                    &display,
                    MAX_CAPTURED_PAYLOAD as usize,
                ) {
                    InflateFrameResult::Decoded(bytes) => {
                        display = bytes;
                        compressed = true;
                    }
                    InflateFrameResult::Passthrough | InflateFrameResult::Failed => {}
                }
            }
        }
    }

    let mut message = WsMessage {
        at: now_ms(),
        direction,
        opcode: frame.opcode,
        size: wire_size,
        truncated: frame.truncated,
        text: None,
        body_id: None,
        injected,
        compressed,
    };

    if !display.is_empty() {
        // Opcode 1 is text; a continuation frame carries no opcode of its own,
        // so its payload is stored rather than guessed at. Inflated text from a
        // compressed text message uses the original opcode (1) on the first
        // frame; FIN continuation still has opcode 0.
        let as_text = (frame.opcode == 1 && display.len() <= INLINE_TEXT_LIMIT)
            .then(|| String::from_utf8(display.clone()).ok())
            .flatten();
        match as_text {
            Some(text) => message.text = Some(text),
            None => {
                let mut writer = store.bodies().writer(store.max_body_bytes());
                writer.write(&display);
                message.body_id = Some(writer.finish(None, None).id);
            }
        }
    }

    store.add_ws_message(id, message.clone());
    message
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
    /// FIN bit from the frame header.
    fin: bool,
    /// RSV1 bit (permessage-deflate message start when negotiated).
    rsv1: bool,
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
    fin: bool,
    rsv1: bool,
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
    /// Takes any unparsed residual after framing breaks. Used by the
    /// parse-before-forward path to flush bytes that never became a frame.
    fn take_residual(&mut self) -> Vec<u8> {
        self.partial = None;
        std::mem::take(&mut self.buf)
    }

    fn feed(&mut self, chunk: &[u8]) -> Vec<Observed> {
        let mut out = Vec::new();
        if self.broken {
            // Opaque mode: do not accumulate; the pump copies the raw chunk.
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
                    // Leave `buf` in place so the pump can flush residual bytes
                    // as opaque when parse-before-forward was holding them.
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
            fin: done.fin,
            rsv1: done.rsv1,
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
        let fin = first & 0x80 != 0;
        let rsv1 = first & 0x40 != 0;
        let opcode = first & 0x0f;
        let masked = second & 0x80 != 0;
        let short_len = second & 0x7f;

        // Reserved opcodes mean an extension is in play that we do not know how
        // to frame, and guessing past it would desynchronise everything after.
        // RSV1 alone is not broken: permessage-deflate uses it on data frames.
        if !matches!(opcode, 0x0..=0x2 | 0x8..=0xa) {
            return Step::Broken;
        }
        // RSV1 on a control frame is illegal and would desync inflate state.
        if rsv1 && opcode >= 0x8 {
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
        if opcode >= 0x8 && (payload_len > 125 || !fin) {
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
            fin,
            rsv1,
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
    use tokio::io::duplex;

    /// Builds a frame the way a client would: FIN set, fixed mask for tests.
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
        encode_frame(opcode, payload, false)
    }

    fn ws_flow(store: &FlowStore) -> FlowId {
        let id = store.create(crate::capture::FlowInit {
            kind: crate::types::FlowKind::Websocket,
            intercepted: true,
            request: crate::types::FlowRequest {
                method: "GET".into(),
                url: "http://ws.test/".into(),
                scheme: crate::types::Scheme::Http,
                authority: "ws.test".into(),
                host: "ws.test".into(),
                port: 80,
                path: "/".into(),
                http_version: crate::types::HttpVersion::Http11,
                headers: vec![],
                body: None,
            },
            client: crate::types::FlowClient {
                address: "127.0.0.1".into(),
                port: 1,
            },
            server: crate::types::FlowServer::default(),
            replay_of: None,
            transport: None,
            connection_id: None,
            stream_id: None,
            upstream_stream_id: None,
        });
        store.update(&id, |flow| {
            flow.ws_messages = Some(Vec::new());
        });
        id
    }

    /// Spins a pump on duplex pairs and waits until the registry has the flow.
    async fn start_pump(
        store: Arc<FlowStore>,
        id: FlowId,
        registry: Arc<WsRegistry>,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        start_pump_with(
            store,
            id,
            registry,
            Arc::new(PauseHub::new()),
            WsRewriteHub::empty(),
        )
        .await
    }

    async fn start_pump_with_pauses(
        store: Arc<FlowStore>,
        id: FlowId,
        registry: Arc<WsRegistry>,
        pauses: Arc<PauseHub>,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        start_pump_with(
            store,
            id,
            registry,
            pauses,
            WsRewriteHub::empty(),
        )
        .await
    }

    async fn start_pump_with(
        store: Arc<FlowStore>,
        id: FlowId,
        registry: Arc<WsRegistry>,
        pauses: Arc<PauseHub>,
        ws_rewrite: Arc<WsRewriteHub>,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (client_side, peer_client) = duplex(4096);
        let (upstream_side, peer_upstream) = duplex(4096);
        let pump_store = store.clone();
        let pump_id = id.clone();
        let pump_reg = registry.clone();
        let handle = tokio::spawn(async move {
            pump(
                client_side,
                upstream_side,
                pump_store,
                pump_id,
                pump_reg,
                pauses,
                ws_rewrite,
                "ws.test".into(),
                "/".into(),
                PermessageDeflateParams::default(),
            )
            .await;
        });
        for _ in 0..50 {
            if registry.is_live(&id) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(registry.is_live(&id), "pump never registered");
        (handle, peer_client, peer_upstream)
    }

    #[test]
    fn encode_frame_sets_fin_and_masks_when_asked() {
        let wire = encode_frame(1, b"Hello", true);
        assert_eq!(wire[0], 0x81, "FIN | text");
        assert_eq!(wire[1] & 0x80, 0x80, "mask bit set");
        assert_eq!(wire[1] & 0x7f, 5);

        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"Hello");
        assert_eq!(frames[0].opcode, 1);
    }

    #[test]
    fn encode_frame_unmasked_parses_as_server_frame() {
        let wire = encode_frame(2, &[0xde, 0xad], false);
        assert_eq!(wire[0], 0x82);
        assert_eq!(wire[1] & 0x80, 0, "no mask bit");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire);
        assert_eq!(frames[0].payload, &[0xde, 0xad]);
    }

    #[test]
    fn encode_frame_extended_length() {
        let payload = vec![b'x'; 200];
        let wire = encode_frame(1, &payload, false);
        assert_eq!(wire[1] & 0x7f, 126);
        let mut parser = FrameParser::default();
        assert_eq!(parser.feed(&wire)[0].payload, payload);
    }

    #[test]
    fn encode_frame_control_opcodes_keep_fin() {
        for opcode in [8u8, 9, 10] {
            let payload: &[u8] = if opcode == 8 { &[0x03, 0xe8] } else { b"hi" };
            let wire = encode_frame(opcode, payload, false);
            assert_eq!(wire[0], 0x80 | opcode, "FIN | opcode {opcode}");
            let mut parser = FrameParser::default();
            let frames = parser.feed(&wire);
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].opcode, opcode);
            assert_eq!(frames[0].payload, payload);
        }
    }

    #[test]
    fn registry_reports_not_live_when_empty() {
        let registry = WsRegistry::new();
        assert!(!registry.is_live("missing"));
        assert!(matches!(
            registry.inject("missing", WsDirection::Send, 1, b"x".to_vec()),
            Err(InjectError::NotLive)
        ));
    }

    #[test]
    fn registry_reports_full_when_inject_queue_is_saturated() {
        let registry = WsRegistry::new();
        // Capacity 1: one queued command fills the half; the next try_send fails.
        let (tx_up, _rx_up) = mpsc::channel(1);
        let (tx_client, _rx_client) = mpsc::channel(1);
        registry.register("flow-full".into(), tx_up, tx_client);

        registry
            .inject("flow-full", WsDirection::Send, 1, b"first".to_vec())
            .expect("first inject fits");
        assert!(matches!(
            registry.inject("flow-full", WsDirection::Send, 1, b"second".to_vec()),
            Err(InjectError::Full)
        ));
    }

    #[test]
    fn registry_reports_closed_when_half_senders_are_dropped() {
        let registry = WsRegistry::new();
        let (tx_up, rx_up) = mpsc::channel(4);
        let (tx_client, rx_client) = mpsc::channel(4);
        registry.register("flow-closed".into(), tx_up, tx_client);
        drop(rx_up);
        drop(rx_client);
        assert!(matches!(
            registry.inject("flow-closed", WsDirection::Send, 1, b"x".to_vec()),
            Err(InjectError::Closed)
        ));
    }

    #[tokio::test]
    async fn registry_inject_reaches_a_registered_half() {
        let registry = Arc::new(WsRegistry::new());
        let (tx_up, mut rx_up) = mpsc::channel(4);
        let (tx_client, _rx_client) = mpsc::channel(4);
        registry.register("flow-1".into(), tx_up, tx_client);

        let reply = registry
            .inject("flow-1", WsDirection::Send, 1, b"hi".to_vec())
            .expect("live");
        let cmd = rx_up.recv().await.expect("queued");
        assert_eq!(cmd.opcode, 1);
        assert_eq!(cmd.payload, b"hi");
        let _ = cmd.reply.send(WsMessage {
            at: 1,
            direction: WsDirection::Send,
            opcode: 1,
            size: 2,
            truncated: false,
            text: Some("hi".into()),
            body_id: None,
            injected: true,
            compressed: false,
        });
        let recorded = reply.await.expect("reply");
        assert!(recorded.injected);
        assert_eq!(recorded.text.as_deref(), Some("hi"));

        registry.unregister("flow-1");
        assert!(matches!(
            registry.inject("flow-1", WsDirection::Send, 1, vec![]),
            Err(InjectError::NotLive)
        ));
    }

    #[tokio::test]
    async fn injected_frame_is_written_masked_toward_origin_and_recorded() {
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let (pump, peer_client, mut peer_upstream) =
            start_pump(store.clone(), id.clone(), registry.clone()).await;

        let reply = registry
            .inject(&id, WsDirection::Send, 1, b"inject".to_vec())
            .expect("inject accepted");
        let message = tokio::time::timeout(std::time::Duration::from_secs(2), reply)
            .await
            .expect("reply timed out")
            .expect("reply channel closed");
        assert!(message.injected);
        assert_eq!(message.opcode, 1);
        assert_eq!(message.text.as_deref(), Some("inject"));
        assert_eq!(message.direction, WsDirection::Send);

        // The origin half should see a masked FIN text frame.
        let mut wire = vec![0u8; 32];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("origin read timed out")
        .expect("origin read");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire[..n]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"inject");
        assert_eq!(wire[1] & 0x80, 0x80, "client-to-server must be masked");

        // Stored on the flow with the same path as real traffic.
        let flow = store.get(&id).expect("flow");
        let msgs = flow.ws_messages.as_ref().expect("messages");
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].injected);
        assert_eq!(msgs[0].text.as_deref(), Some("inject"));

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
        assert!(!registry.is_live(&id), "pump must unregister on exit");
    }

    #[tokio::test]
    async fn injected_recv_frame_is_unmasked_toward_client_and_recorded() {
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let (pump, mut peer_client, peer_upstream) =
            start_pump(store.clone(), id.clone(), registry.clone()).await;

        let reply = registry
            .inject(&id, WsDirection::Recv, 2, vec![0xde, 0xad, 0xbe])
            .expect("inject accepted");
        let message = tokio::time::timeout(std::time::Duration::from_secs(2), reply)
            .await
            .expect("reply timed out")
            .expect("reply channel closed");
        assert!(message.injected);
        assert_eq!(message.opcode, 2);
        assert_eq!(message.direction, WsDirection::Recv);
        assert!(message.body_id.is_some(), "binary frames go to the body store");
        assert!(message.text.is_none());

        let mut wire = vec![0u8; 32];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_client.read(&mut wire),
        )
        .await
        .expect("client read timed out")
        .expect("client read");
        assert_eq!(wire[0], 0x82, "FIN | binary");
        assert_eq!(wire[1] & 0x80, 0, "server-to-client must not be masked");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire[..n]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, &[0xde, 0xad, 0xbe]);

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
        assert!(!registry.is_live(&id));
    }

    #[tokio::test]
    async fn peer_traffic_is_forwarded_before_parse_and_not_marked_injected() {
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let (pump, mut peer_client, mut peer_upstream) =
            start_pump(store.clone(), id.clone(), registry.clone()).await;

        // Client sends a real masked text frame; the origin must see the same
        // bytes, and the store must record it without the injected flag.
        let frame = masked_frame(1, b"from-peer");
        peer_client
            .write_all(&frame)
            .await
            .expect("write client frame");

        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("origin read timed out")
        .expect("origin read");
        assert_eq!(&wire[..n], frame.as_slice(), "bytes must be copied unchanged");

        // Give the parse/record path a moment after the write.
        for _ in 0..50 {
            let count = store
                .get(&id)
                .and_then(|f| f.ws_messages)
                .map(|m| m.len())
                .unwrap_or(0);
            if count >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let flow = store.get(&id).expect("flow");
        let msgs = flow.ws_messages.as_ref().expect("messages");
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].injected, "real traffic is not marked injected");
        assert_eq!(msgs[0].text.as_deref(), Some("from-peer"));
        assert_eq!(msgs[0].direction, WsDirection::Send);

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
        assert!(!registry.is_live(&id));
        // finish() marks the flow complete once either half ends.
        let finished = store.get(&id).expect("flow after finish");
        assert!(finished.timings.end.is_some());
    }

    #[tokio::test]
    async fn matching_frame_is_held_until_release() {
        use crate::types::{BreakpointRule, BreakpointRulesBody, PauseKind, PauseResolveReason};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let pauses = Arc::new(PauseHub::new());
        pauses.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "hold-text".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 30_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with_pauses(
            store.clone(),
            id.clone(),
            registry.clone(),
            pauses.clone(),
        )
        .await;

        let frame = masked_frame(1, b"paused");
        peer_client
            .write_all(&frame)
            .await
            .expect("write client frame");

        // Must not arrive at the origin while held.
        let early = tokio::time::timeout(
            std::time::Duration::from_millis(80),
            peer_upstream.read(&mut [0u8; 32]),
        )
        .await;
        assert!(early.is_err(), "frame must not forward before release");

        // Wait until the hub lists the pause.
        let pause_id = {
            let mut found = None;
            for _ in 0..50 {
                if let Some(p) = pauses.list().into_iter().next() {
                    found = Some(p.pause_id);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            found.expect("pause never registered")
        };

        pauses
            .resolve(
                &store,
                &pause_id,
                PauseDecision::Release {
                    opcode: 1,
                    payload: b"edited".to_vec(),
                },
                PauseResolveReason::User,
            )
            .expect("release");

        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("origin read timed out")
        .expect("origin read");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire[..n]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"edited");

        let flow = store.get(&id).expect("flow");
        let msgs = flow.ws_messages.as_ref().expect("messages");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text.as_deref(), Some("edited"));
        assert!(!msgs[0].injected);

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn drop_skips_forward_and_record() {
        use crate::types::{BreakpointRule, BreakpointRulesBody, PauseKind, PauseResolveReason};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let pauses = Arc::new(PauseHub::new());
        pauses.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "drop-text".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 30_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with_pauses(
            store.clone(),
            id.clone(),
            registry.clone(),
            pauses.clone(),
        )
        .await;

        peer_client
            .write_all(&masked_frame(1, b"nope"))
            .await
            .expect("write");

        let pause_id = {
            let mut found = None;
            for _ in 0..50 {
                if let Some(p) = pauses.list().into_iter().next() {
                    found = Some(p.pause_id);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            found.expect("pause")
        };
        pauses
            .resolve(
                &store,
                &pause_id,
                PauseDecision::Drop,
                PauseResolveReason::User,
            )
            .expect("drop");

        let early = tokio::time::timeout(
            std::time::Duration::from_millis(80),
            peer_upstream.read(&mut [0u8; 32]),
        )
        .await;
        assert!(early.is_err(), "dropped frame must not reach origin");

        let flow = store.get(&id).expect("flow");
        assert!(
            flow.ws_messages.as_ref().map(|m| m.is_empty()).unwrap_or(true),
            "dropped frame is not recorded as on the wire"
        );

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn control_frames_are_not_paused_by_default_rules() {
        use crate::types::{BreakpointRule, BreakpointRulesBody, PauseKind};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let pauses = Arc::new(PauseHub::new());
        // Empty opcodes => text+binary only.
        pauses.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "data-only".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![],
                timeout_ms: 30_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with_pauses(
            store.clone(),
            id.clone(),
            registry.clone(),
            pauses.clone(),
        )
        .await;

        peer_client
            .write_all(&masked_frame(9, b"ping"))
            .await
            .expect("write ping");

        let mut wire = vec![0u8; 32];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("origin read timed out")
        .expect("origin read");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire[..n]);
        assert_eq!(frames[0].opcode, 9);
        assert_eq!(frames[0].payload, b"ping");
        assert_eq!(pauses.pending_count(), 0, "ping must not be held");

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn broken_framing_forwards_without_pausing() {
        use crate::types::{BreakpointRule, BreakpointRulesBody, PauseKind};

        // A reserved opcode breaks the parser. With rules enabled the half must
        // still flush residual bytes and never register a pause.
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let pauses = Arc::new(PauseHub::new());
        pauses.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "all-text".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 30_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with_pauses(
            store.clone(),
            id.clone(),
            registry.clone(),
            pauses.clone(),
        )
        .await;

        let bad = masked_frame(3, b"unknown extension");
        peer_client
            .write_all(&bad)
            .await
            .expect("write reserved opcode");

        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("origin must still receive residual bytes")
        .expect("read");
        assert_eq!(&wire[..n], bad.as_slice());
        assert_eq!(pauses.pending_count(), 0, "broken framing must not hold");

        // After broken, further bytes are opaque-copied and also not paused.
        let later = masked_frame(1, b"later");
        peer_client.write_all(&later).await.expect("write later");
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("opaque forward timed out")
        .expect("read");
        assert_eq!(&wire[..n], later.as_slice());
        assert_eq!(pauses.pending_count(), 0);

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn pump_exit_cancels_held_pauses() {
        use crate::types::{BreakpointRule, BreakpointRulesBody, PauseKind};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let pauses = Arc::new(PauseHub::new());
        pauses.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "hold".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 30_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        let (pump, mut peer_client, peer_upstream) = start_pump_with_pauses(
            store.clone(),
            id.clone(),
            registry.clone(),
            pauses.clone(),
        )
        .await;

        peer_client
            .write_all(&masked_frame(1, b"held"))
            .await
            .expect("write");

        for _ in 0..50 {
            if pauses.pending_count() > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(pauses.pending_count(), 1, "frame should be held");

        // Tear down the connection; the pump must cancel, not leave a zombie.
        drop(peer_client);
        drop(peer_upstream);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pump)
            .await
            .expect("pump should exit after peers close");

        for _ in 0..50 {
            if pauses.pending_count() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            pauses.pending_count(),
            0,
            "held pauses must clear on pump exit"
        );
    }

    #[tokio::test]
    async fn inject_is_not_paused_when_rules_are_enabled() {
        use crate::types::{BreakpointRule, BreakpointRulesBody, PauseKind};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let pauses = Arc::new(PauseHub::new());
        pauses.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "hold-text".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 30_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        let (pump, peer_client, mut peer_upstream) = start_pump_with_pauses(
            store.clone(),
            id.clone(),
            registry.clone(),
            pauses.clone(),
        )
        .await;

        let reply = registry
            .inject(&id, WsDirection::Send, 1, b"inject-now".to_vec())
            .expect("inject accepted");
        let message = tokio::time::timeout(std::time::Duration::from_secs(2), reply)
            .await
            .expect("inject must not wait on a pause")
            .expect("reply");
        assert!(message.injected);
        assert_eq!(message.text.as_deref(), Some("inject-now"));
        assert_eq!(pauses.pending_count(), 0, "inject path is unpaused");

        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("origin read timed out")
        .expect("origin read");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire[..n]);
        assert_eq!(frames[0].payload, b"inject-now");

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn injected_close_and_ping_are_recorded_with_opcodes() {
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let (pump, peer_client, mut peer_upstream) =
            start_pump(store.clone(), id.clone(), registry.clone()).await;

        let close_payload = {
            let mut p = 1000u16.to_be_bytes().to_vec();
            p.extend_from_slice(b"bye");
            p
        };
        let close_reply = registry
            .inject(&id, WsDirection::Send, 8, close_payload.clone())
            .expect("close inject");
        let close_msg = tokio::time::timeout(std::time::Duration::from_secs(2), close_reply)
            .await
            .expect("timeout")
            .expect("reply");
        assert!(close_msg.injected);
        assert_eq!(close_msg.opcode, 8);
        assert_eq!(close_msg.size, close_payload.len() as u64);

        let ping_reply = registry
            .inject(&id, WsDirection::Send, 9, b"ping".to_vec())
            .expect("ping inject");
        let ping_msg = tokio::time::timeout(std::time::Duration::from_secs(2), ping_reply)
            .await
            .expect("timeout")
            .expect("reply");
        assert_eq!(ping_msg.opcode, 9);
        assert!(ping_msg.injected);

        // Drain both frames from the origin so the write path is exercised.
        let mut wire = vec![0u8; 64];
        let mut got = Vec::new();
        while got.len() < 2 {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                peer_upstream.read(&mut wire),
            )
            .await
            .expect("read timeout")
            .expect("read");
            let mut parser = FrameParser::default();
            got.extend(parser.feed(&wire[..n]));
        }
        assert_eq!(got[0].opcode, 8);
        assert_eq!(got[0].payload, close_payload);
        assert_eq!(got[1].opcode, 9);
        assert_eq!(got[1].payload, b"ping");

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
        assert!(matches!(
            registry.inject(&id, WsDirection::Send, 1, b"late".to_vec()),
            Err(InjectError::NotLive)
        ));
    }

    #[tokio::test]
    async fn empty_rewrite_hub_keeps_byte_copy_and_no_notes() {
        // Empty rules + no breakpoints: wire bytes identical, no rewrite notes.
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with(
            store.clone(),
            id.clone(),
            registry.clone(),
            Arc::new(PauseHub::new()),
            WsRewriteHub::empty(),
        )
        .await;

        let frame = masked_frame(1, b"byte-copy");
        peer_client
            .write_all(&frame)
            .await
            .expect("write");

        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        assert_eq!(&wire[..n], frame.as_slice(), "empty rules must not re-encode");

        for _ in 0..50 {
            if store
                .get(&id)
                .and_then(|f| f.ws_messages)
                .map(|m| !m.is_empty())
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let flow = store.get(&id).expect("flow");
        assert!(
            flow.rewrites.is_empty(),
            "empty rewrite path must leave Flow.rewrites empty: {:?}",
            flow.rewrites
        );
        let msgs = flow.ws_messages.as_ref().expect("messages");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text.as_deref(), Some("byte-copy"));

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn mid_connection_rewrite_enable_switches_to_parse_before_forward() {
        use crate::config::{WsRewriteRule, WsRewriteRulesBody};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        // Shared empty hub; rules are installed after the first frame.
        let hub = WsRewriteHub::empty();
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with(
            store.clone(),
            id.clone(),
            registry.clone(),
            Arc::new(PauseHub::new()),
            hub.clone(),
        )
        .await;

        // First frame: empty rules, byte-copy path (wire identity).
        let first = masked_frame(1, b"before-rules");
        peer_client
            .write_all(&first)
            .await
            .expect("write first");
        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        assert_eq!(&wire[..n], first.as_slice());

        hub.set_rules(WsRewriteRulesBody {
            rules: vec![WsRewriteRule {
                replace_text: Some("after-rules".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("enable rewrite");

        // Second frame: parse-before-forward must pick up the new rule.
        peer_client
            .write_all(&masked_frame(1, b"to-rewrite"))
            .await
            .expect("write second");
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire[..n]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"after-rules");

        for _ in 0..50 {
            if store
                .get(&id)
                .map(|f| f.rewrites.iter().any(|n| n.contains("replaced")))
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let flow = store.get(&id).expect("flow");
        assert!(
            flow.rewrites.iter().any(|n| n.contains("replaced")),
            "mid-connection enable must record a rewrite note: {:?}",
            flow.rewrites
        );

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn replace_rule_changes_wire_payload_and_records_note() {
        use crate::config::{WsRewriteRule, WsRewriteRules};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let hub = WsRewriteHub::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                replace_text: Some("rewritten".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("compile");
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with(
            store.clone(),
            id.clone(),
            registry.clone(),
            Arc::new(PauseHub::new()),
            hub,
        )
        .await;

        peer_client
            .write_all(&masked_frame(1, b"original"))
            .await
            .expect("write");

        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire[..n]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"rewritten");

        for _ in 0..50 {
            if store
                .get(&id)
                .and_then(|f| f.ws_messages)
                .map(|m| !m.is_empty())
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let flow = store.get(&id).expect("flow");
        let msgs = flow.ws_messages.as_ref().expect("messages");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text.as_deref(), Some("rewritten"));
        assert!(
            flow.rewrites.iter().any(|n| n.contains("replaced")),
            "rewrite note missing: {:?}",
            flow.rewrites
        );

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn drop_rule_skips_write_and_ws_message_but_notes() {
        use crate::config::{WsRewriteRule, WsRewriteRules};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let hub = WsRewriteHub::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                drop: true,
                text_regex: Some("secret".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("compile");
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with(
            store.clone(),
            id.clone(),
            registry.clone(),
            Arc::new(PauseHub::new()),
            hub,
        )
        .await;

        peer_client
            .write_all(&masked_frame(1, b"has secret here"))
            .await
            .expect("write");

        let early = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            peer_upstream.read(&mut [0u8; 32]),
        )
        .await;
        assert!(
            early.is_err(),
            "dropped frame must not reach the peer"
        );

        for _ in 0..50 {
            if store
                .get(&id)
                .map(|f| !f.rewrites.is_empty())
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let flow = store.get(&id).expect("flow");
        assert!(
            flow.ws_messages
                .as_ref()
                .map(|m| m.is_empty())
                .unwrap_or(true),
            "drop must not add a ws_message"
        );
        assert!(
            flow.rewrites.iter().any(|n| n.contains("dropped")),
            "drop note missing: {:?}",
            flow.rewrites
        );

        // Non-matching frame still goes through.
        peer_client
            .write_all(&masked_frame(1, b"clean"))
            .await
            .expect("write clean");
        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        let mut parser = FrameParser::default();
        assert_eq!(parser.feed(&wire[..n])[0].payload, b"clean");

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn inject_skips_rewrite_rules() {
        use crate::config::{WsRewriteRule, WsRewriteRules};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let hub = WsRewriteHub::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                replace_text: Some("should-not-apply".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("compile");
        let (pump, peer_client, mut peer_upstream) = start_pump_with(
            store.clone(),
            id.clone(),
            registry.clone(),
            Arc::new(PauseHub::new()),
            hub,
        )
        .await;

        let reply = registry
            .inject(&id, WsDirection::Send, 1, b"inject-body".to_vec())
            .expect("inject");
        let message = tokio::time::timeout(std::time::Duration::from_secs(2), reply)
            .await
            .expect("timeout")
            .expect("reply");
        assert_eq!(message.text.as_deref(), Some("inject-body"));
        assert!(message.injected);

        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        let mut parser = FrameParser::default();
        assert_eq!(parser.feed(&wire[..n])[0].payload, b"inject-body");

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn breakpoint_sees_post_rewrite_payload() {
        use crate::config::{WsRewriteRule, WsRewriteRules};
        use crate::types::{BreakpointRule, BreakpointRulesBody, PauseKind, PauseResolveReason};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let pauses = Arc::new(PauseHub::new());
        pauses.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "after-rewrite".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 30_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        let hub = WsRewriteHub::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                replace_text: Some("after-rewrite".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("compile");
        let (pump, mut peer_client, mut peer_upstream) = start_pump_with(
            store.clone(),
            id.clone(),
            registry.clone(),
            pauses.clone(),
            hub,
        )
        .await;

        peer_client
            .write_all(&masked_frame(1, b"before"))
            .await
            .expect("write");

        let pause_id = {
            let mut found = None;
            for _ in 0..50 {
                if let Some(p) = pauses.list().into_iter().next() {
                    let ws = p.ws.as_ref().expect("ws body");
                    assert_eq!(
                        ws.text.as_deref(),
                        Some("after-rewrite"),
                        "breakpoint must see post-rewrite payload"
                    );
                    found = Some(p.pause_id);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            found.expect("pause never registered")
        };
        pauses
            .resolve(
                &store,
                &pause_id,
                PauseDecision::Release {
                    opcode: 1,
                    payload: b"after-rewrite".to_vec(),
                },
                PauseResolveReason::User,
            )
            .expect("release");

        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        let mut parser = FrameParser::default();
        assert_eq!(parser.feed(&wire[..n])[0].payload, b"after-rewrite");

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
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

    #[test]
    fn rsv1_text_frame_is_parsed_not_broken() {
        // FIN | RSV1 | text, unmasked server frame with empty payload for header check.
        let mut bytes = server_frame(1, b"x");
        bytes[0] |= 0x40; // set RSV1
        let mut parser = FrameParser::default();
        let frames = parser.feed(&bytes);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].rsv1);
        assert!(frames[0].fin);
        assert_eq!(frames[0].opcode, 1);
        assert!(!parser.broken);
    }

    #[test]
    fn rsv1_on_control_frame_is_broken() {
        let mut bytes = server_frame(9, b"ping");
        bytes[0] |= 0x40;
        let mut parser = FrameParser::default();
        assert!(parser.feed(&bytes).is_empty());
        assert!(parser.broken);
    }

    /// Raw-deflate compress + strip RFC 7692 trailer (SYNC_FLUSH empty block).
    fn compress_ws_payload(data: &[u8]) -> Vec<u8> {
        use flate2::{Compress, Compression, FlushCompress};
        let mut c = Compress::new(Compression::default(), false);
        let mut out = Vec::with_capacity(data.len() + 64);
        c.compress_vec(data, &mut out, FlushCompress::Sync)
            .expect("compress");
        assert!(
            out.ends_with(&[0x00, 0x00, 0xff, 0xff]),
            "SYNC_FLUSH trailer missing: {out:02x?}"
        );
        out.truncate(out.len() - 4);
        out
    }

    /// Server FIN|RSV1|text frame with compressed payload.
    fn compressed_server_text(plain: &[u8]) -> Vec<u8> {
        let wire_payload = compress_ws_payload(plain);
        let mut frame = encode_frame(1, &wire_payload, false);
        frame[0] |= 0x40; // RSV1
        frame
    }

    async fn start_pump_with_deflate(
        store: Arc<FlowStore>,
        id: FlowId,
        registry: Arc<WsRegistry>,
        deflate: PermessageDeflateParams,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (client_side, peer_client) = duplex(4096);
        let (upstream_side, peer_upstream) = duplex(4096);
        let pump_store = store.clone();
        let pump_id = id.clone();
        let pump_reg = registry.clone();
        let handle = tokio::spawn(async move {
            pump(
                client_side,
                upstream_side,
                pump_store,
                pump_id,
                pump_reg,
                Arc::new(PauseHub::new()),
                WsRewriteHub::empty(),
                "ws.test".into(),
                "/".into(),
                deflate,
            )
            .await;
        });
        for _ in 0..50 {
            if registry.is_live(&id) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(registry.is_live(&id), "pump never registered");
        (handle, peer_client, peer_upstream)
    }

    #[tokio::test]
    async fn deflate_unfragmented_text_is_inflated_for_capture() {
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let deflate = PermessageDeflateParams {
            enabled: true,
            client_no_context_takeover: true,
            server_no_context_takeover: true,
            client_max_window_bits: 15,
            server_max_window_bits: 15,
        };
        let (pump, mut peer_client, mut peer_upstream) =
            start_pump_with_deflate(store.clone(), id.clone(), registry, deflate).await;

        let plain = b"Hello deflate world";
        let frame = compressed_server_text(plain);
        let wire_payload_len = {
            let mut p = FrameParser::default();
            let f = p.feed(&frame);
            f[0].size
        };

        peer_upstream
            .write_all(&frame)
            .await
            .expect("write compressed frame toward client");

        // On-wire bytes must be an exact copy.
        let mut got = vec![0u8; frame.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_client.read_exact(&mut got),
        )
        .await
        .expect("client read timed out")
        .expect("client read");
        assert_eq!(got, frame, "on-wire must be exact copy, not re-encoded");

        // Capture should show inflated text with compressed flag and wire size.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let message = loop {
            if let Some(msgs) = store.get(&id).and_then(|f| f.ws_messages.clone()) {
                if let Some(m) = msgs.iter().find(|m| m.opcode == 1) {
                    break m.clone();
                }
            }
            if tokio::time::Instant::now() > deadline {
                panic!("no ws message recorded");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        assert!(message.compressed);
        assert_eq!(message.size, wire_payload_len);
        assert_eq!(message.text.as_deref(), Some("Hello deflate world"));
        assert!(!message.injected);

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn deflate_with_rewrite_rules_still_copies_wire_bytes() {
        // Rewrite rules would normally force parse-before-forward; with deflate
        // they must not re-encode (RSV1 must survive).
        use crate::config::{WsRewriteRule, WsRewriteRules};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let ws_rewrite = WsRewriteHub::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                replace_text: Some("rewritten".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("compile rewrite rules");
        let deflate = PermessageDeflateParams {
            enabled: true,
            client_no_context_takeover: true,
            server_no_context_takeover: true,
            client_max_window_bits: 15,
            server_max_window_bits: 15,
        };
        let (client_side, mut peer_client) = duplex(4096);
        let (upstream_side, mut peer_upstream) = duplex(4096);
        let pump_store = store.clone();
        let pump_id = id.clone();
        let pump_reg = registry.clone();
        let pump = tokio::spawn(async move {
            pump(
                client_side,
                upstream_side,
                pump_store,
                pump_id,
                pump_reg,
                Arc::new(PauseHub::new()),
                ws_rewrite,
                "ws.test".into(),
                "/".into(),
                deflate,
            )
            .await;
        });
        for _ in 0..50 {
            if registry.is_live(&id) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let frame = compressed_server_text(b"keep me compressed");
        peer_upstream.write_all(&frame).await.expect("write");
        let mut got = vec![0u8; frame.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_client.read_exact(&mut got),
        )
        .await
        .expect("timeout")
        .expect("read");
        assert_eq!(got, frame, "rewrite must not strip RSV1 under deflate");
        assert_eq!(got[0] & 0x40, 0x40, "RSV1 still set on the wire");

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn inject_under_deflate_is_uncompressed_and_recorded() {
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let deflate = PermessageDeflateParams {
            enabled: true,
            ..PermessageDeflateParams::default()
        };
        let (pump, _peer_client, mut peer_upstream) =
            start_pump_with_deflate(store.clone(), id.clone(), registry.clone(), deflate).await;

        let reply = registry
            .inject(&id, WsDirection::Send, 1, b"inject".to_vec())
            .expect("inject");
        let message = tokio::time::timeout(std::time::Duration::from_secs(2), reply)
            .await
            .expect("timeout")
            .expect("reply");
        assert!(message.injected);
        assert!(!message.compressed);
        assert_eq!(message.text.as_deref(), Some("inject"));

        let mut wire = vec![0u8; 32];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        // Injected frames must not set RSV1.
        assert_eq!(wire[0] & 0x40, 0, "inject is uncompressed");
        let mut parser = FrameParser::default();
        assert_eq!(parser.feed(&wire[..n])[0].payload, b"inject");

        drop(peer_upstream);
        let _ = pump.await;
    }

    /// Client FIN|RSV1|text with compressed payload and a fixed mask.
    fn compressed_client_text(plain: &[u8]) -> Vec<u8> {
        let wire_payload = compress_ws_payload(plain);
        let mut frame = masked_frame(1, &wire_payload);
        frame[0] |= 0x40; // RSV1
        frame
    }

    async fn wait_ws_opcode(store: &FlowStore, id: &FlowId, opcode: u8) -> WsMessage {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Some(msgs) = store.get(id).and_then(|f| f.ws_messages.clone()) {
                if let Some(m) = msgs.iter().find(|m| m.opcode == opcode) {
                    return m.clone();
                }
            }
            if tokio::time::Instant::now() > deadline {
                panic!("no ws message with opcode {opcode}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn deflate_inflate_failure_falls_back_to_wire_and_keeps_framing() {
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let deflate = PermessageDeflateParams {
            enabled: true,
            client_no_context_takeover: true,
            server_no_context_takeover: true,
            client_max_window_bits: 15,
            server_max_window_bits: 15,
        };
        let (pump, mut peer_client, mut peer_upstream) =
            start_pump_with_deflate(store.clone(), id.clone(), registry, deflate).await;

        // Garbage RSV1 payload: inflate fails; on-wire copy must still complete.
        let mut bad = encode_frame(1, b"\xff\xff not deflate", false);
        bad[0] |= 0x40;
        peer_upstream.write_all(&bad).await.expect("write bad");
        let mut got = vec![0u8; bad.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_client.read_exact(&mut got),
        )
        .await
        .expect("client read timed out")
        .expect("client read");
        assert_eq!(got, bad, "failed inflate must not rewrite the pipe");

        let bad_msg = wait_ws_opcode(&store, &id, 1).await;
        assert!(
            !bad_msg.compressed,
            "inflate failure keeps wire bytes, not compressed display"
        );
        assert_eq!(bad_msg.size, (bad.len() - 2) as u64);

        // A later good compressed message must still decode (inflater recovered).
        let plain = b"recovered after fail";
        let good = compressed_server_text(plain);
        peer_upstream.write_all(&good).await.expect("write good");
        let mut got_good = vec![0u8; good.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_client.read_exact(&mut got_good),
        )
        .await
        .expect("good read timed out")
        .expect("good read");
        assert_eq!(got_good, good);

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let good_msg = loop {
            if let Some(msgs) = store.get(&id).and_then(|f| f.ws_messages.clone()) {
                if let Some(m) = msgs
                    .iter()
                    .find(|m| m.opcode == 1 && m.text.as_deref() == Some("recovered after fail"))
                {
                    break m.clone();
                }
            }
            if tokio::time::Instant::now() > deadline {
                panic!("good compressed message never recorded as inflated text");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        assert!(good_msg.compressed);

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn deflate_with_breakpoint_rules_still_copies_wire_bytes() {
        // Breakpoints would force parse-before-forward without deflate; with
        // deflate the path stays raw-copy so RSV1 survives and frames are not held.
        use crate::types::{BreakpointRule, BreakpointRulesBody, PauseKind};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let pauses = Arc::new(PauseHub::new());
        pauses.set_rules(BreakpointRulesBody {
            rules: vec![BreakpointRule {
                id: "hold-all-text".into(),
                enabled: true,
                kind: PauseKind::Ws,
                hosts: vec![],
                path_prefix: None,
                directions: vec![],
                opcodes: vec![1],
                timeout_ms: 30_000,
                        http_half: None,
            methods: vec![],
        }],
        });
        let deflate = PermessageDeflateParams {
            enabled: true,
            client_no_context_takeover: true,
            server_no_context_takeover: true,
            client_max_window_bits: 15,
            server_max_window_bits: 15,
        };
        let (client_side, mut peer_client) = duplex(4096);
        let (upstream_side, mut peer_upstream) = duplex(4096);
        let pump_store = store.clone();
        let pump_id = id.clone();
        let pump_reg = registry.clone();
        let pauses_clone = pauses.clone();
        let pump = tokio::spawn(async move {
            pump(
                client_side,
                upstream_side,
                pump_store,
                pump_id,
                pump_reg,
                pauses_clone,
                WsRewriteHub::empty(),
                "ws.test".into(),
                "/".into(),
                deflate,
            )
            .await;
        });
        for _ in 0..50 {
            if registry.is_live(&id) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let frame = compressed_server_text(b"do not hold me");
        peer_upstream.write_all(&frame).await.expect("write");
        let mut got = vec![0u8; frame.len()];
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            peer_client.read_exact(&mut got),
        )
        .await
        .expect("frame must forward without waiting for pause release")
        .expect("read");
        assert_eq!(got, frame);
        assert_eq!(got[0] & 0x40, 0x40, "RSV1 intact under breakpoint+deflate");
        assert!(
            pauses.list().is_empty(),
            "deflate path must not register WS pauses"
        );

        let message = wait_ws_opcode(&store, &id, 1).await;
        assert!(message.compressed);
        assert_eq!(message.text.as_deref(), Some("do not hold me"));

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn deflate_negotiated_uncompressed_text_is_not_marked_compressed() {
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let deflate = PermessageDeflateParams {
            enabled: true,
            ..PermessageDeflateParams::default()
        };
        let (pump, mut peer_client, mut peer_upstream) =
            start_pump_with_deflate(store.clone(), id.clone(), registry, deflate).await;

        let frame = server_frame(1, b"plain while deflate on");
        peer_upstream.write_all(&frame).await.expect("write");
        let mut got = vec![0u8; frame.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_client.read_exact(&mut got),
        )
        .await
        .expect("timeout")
        .expect("read");
        assert_eq!(got, frame);

        let message = wait_ws_opcode(&store, &id, 1).await;
        assert!(!message.compressed);
        assert_eq!(message.text.as_deref(), Some("plain while deflate on"));
        assert_eq!(message.size, b"plain while deflate on".len() as u64);

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn deflate_client_to_server_text_is_inflated_for_capture() {
        // Client->server uses client_* inflater params and masked wire frames.
        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let deflate = PermessageDeflateParams {
            enabled: true,
            client_no_context_takeover: true,
            server_no_context_takeover: false,
            client_max_window_bits: 15,
            server_max_window_bits: 15,
        };
        let (pump, mut peer_client, mut peer_upstream) =
            start_pump_with_deflate(store.clone(), id.clone(), registry, deflate).await;

        let plain = b"client compressed hello";
        let frame = compressed_client_text(plain);
        let wire_payload_len = {
            let mut p = FrameParser::default();
            p.feed(&frame)[0].size
        };
        peer_client.write_all(&frame).await.expect("write client");
        let mut got = vec![0u8; frame.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_upstream.read_exact(&mut got),
        )
        .await
        .expect("upstream read timed out")
        .expect("upstream read");
        assert_eq!(got, frame, "masked client frame must pass through byte-exact");
        assert_eq!(got[0] & 0x40, 0x40);

        let message = wait_ws_opcode(&store, &id, 1).await;
        assert_eq!(message.direction, WsDirection::Send);
        assert!(message.compressed);
        assert_eq!(message.size, wire_payload_len);
        assert_eq!(message.text.as_deref(), Some("client compressed hello"));

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }

    #[tokio::test]
    async fn without_deflate_rewrite_still_reencodes() {
        // Regression: deflate-off path keeps parse-before-forward rewrite.
        use crate::config::{WsRewriteRule, WsRewriteRules};

        let store = Arc::new(FlowStore::new(8, 1024, 64 * 1024));
        let id = ws_flow(&store);
        let registry = Arc::new(WsRegistry::new());
        let ws_rewrite = WsRewriteHub::compile(&WsRewriteRules {
            rules: vec![WsRewriteRule {
                replace_text: Some("rewritten".into()),
                ..WsRewriteRule::default()
            }],
        })
        .expect("compile");
        let (client_side, mut peer_client) = duplex(4096);
        let (upstream_side, mut peer_upstream) = duplex(4096);
        let pump_store = store.clone();
        let pump_id = id.clone();
        let pump_reg = registry.clone();
        let pump = tokio::spawn(async move {
            pump(
                client_side,
                upstream_side,
                pump_store,
                pump_id,
                pump_reg,
                Arc::new(PauseHub::new()),
                ws_rewrite,
                "ws.test".into(),
                "/".into(),
                PermessageDeflateParams::default(),
            )
            .await;
        });
        for _ in 0..50 {
            if registry.is_live(&id) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let frame = server_frame(1, b"original");
        peer_upstream.write_all(&frame).await.expect("write");
        let mut wire = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_client.read(&mut wire),
        )
        .await
        .expect("timeout")
        .expect("read");
        let mut parser = FrameParser::default();
        let frames = parser.feed(&wire[..n]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"rewritten");
        assert!(!frames[0].rsv1);

        let message = wait_ws_opcode(&store, &id, 1).await;
        assert!(!message.compressed);
        assert_eq!(message.text.as_deref(), Some("rewritten"));

        drop(peer_client);
        drop(peer_upstream);
        let _ = pump.await;
    }
}
