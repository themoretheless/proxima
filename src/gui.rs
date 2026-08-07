//! The native inspector window.
//!
//! This is the same view as the page on the UI port, except it reads the
//! capture store directly instead of going out through HTTP and back. Nothing
//! is serialised, nothing is polled: the window subscribes to the same
//! broadcast the web socket does, applies events to a list it keeps itself, and
//! only asks the store for anything again when it has fallen behind.
//!
//! The proxy runs in the same process, on a tokio runtime in the background,
//! while egui owns the main thread. That is not a stylistic choice: macOS
//! requires the event loop to be on the first thread of the process.

use std::collections::HashMap;
use std::sync::Arc;

use eframe::egui;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::sync::broadcast::Receiver;

use crate::capture::{decode_body, is_textual, FlowStore};
use crate::types::{
    Flow, FlowId, FlowQuery, FlowState, FlowSummary, ProxyEvent, ServerStatus,
};

/// Rows kept in the window. The store's own ring buffer is the real limit; this
/// only stops a long session from making the list widget the slow part.
const MAX_ROWS: usize = 5_000;
/// Rows are evicted in batches, because the index has to be rebuilt each time.
const EVICT_SLACK: usize = 512;
/// Body bytes rendered as text. Past this the preview is cut: a 10 MB response
/// pasted into a label costs more than it tells anyone.
const PREVIEW_LIMIT: usize = 256 * 1024;
/// Detail copy when `likely_pinning` is set. Cert-reject signal only: Chrome
/// user-CA refusal for QUIC is the same class, so this is not pure app-pinning
/// proof (see README force-TCP / Chrome user-CA notes).
const LIKELY_PINNING_NOTE: &str = "Client rejected the Proxima certificate (pinning or user-CA \
policy, not pure pinning proof). Exclude the host with --skip to let it through untouched, or \
force the client onto TCP/HTTP2.";

pub struct Inspector {
    store: Arc<FlowStore>,
    events: Receiver<ProxyEvent>,
    status: ServerStatus,
    /// Oldest first, so a new flow is a push rather than a shift of everything.
    /// The list is drawn in reverse.
    rows: Vec<FlowSummary>,
    index: HashMap<FlowId, usize>,
    filter: String,
    only_errors: bool,
    selected: Option<FlowId>,
    detail: Option<Detail>,
    /// Cleared when the store's sender is gone, which means the servers stopped.
    live: bool,
    /// A window that fails to appear looks exactly like one that opened behind
    /// everything else, so the first frame says so in the log.
    drawn: bool,
}

struct Detail {
    flow: Flow,
    request: Preview,
    response: Preview,
}

/// What can be shown of a captured body.
enum Preview {
    Absent,
    Text {
        text: String,
        /// Set when the preview was cut, or the capture itself was.
        clipped: bool,
    },
    Binary {
        size: u64,
    },
    /// The body was evicted from the store to stay under the memory ceiling.
    Reclaimed {
        size: u64,
    },
}

impl Inspector {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        store: Arc<FlowStore>,
        status: ServerStatus,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        // A second receiver exists only to wake the window. Without it egui
        // sleeps until the mouse moves, and traffic would appear only when the
        // user happened to touch the machine.
        let mut waker = store.subscribe();
        let ctx = cc.egui_ctx.clone();
        runtime.spawn(async move {
            while waker.recv().await.is_ok() {
                ctx.request_repaint();
                // Under load the store publishes thousands of events a second.
                // A frame cannot show more than one of them anyway, so the wake
                // ups are collapsed rather than each one costing a wake.
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            }
        });

        let mut inspector = Self {
            events: store.subscribe(),
            store,
            status,
            rows: Vec::new(),
            index: HashMap::new(),
            filter: String::new(),
            only_errors: false,
            selected: None,
            detail: None,
            live: true,
            drawn: false,
        };
        inspector.resync();
        inspector
    }

    /// Re-reads the list from the store. Used at startup and whenever the
    /// broadcast reports that events were dropped, since from that point the
    /// list this window keeps is no longer what the store holds.
    fn resync(&mut self) {
        let (mut flows, _) = self.store.query(&FlowQuery {
            limit: Some(MAX_ROWS),
            ..FlowQuery::default()
        });
        // query answers newest first; the list is kept the other way round.
        flows.reverse();
        self.rows = flows;
        self.reindex();
    }

    fn reindex(&mut self) {
        self.index = self
            .rows
            .iter()
            .enumerate()
            .map(|(at, flow)| (flow.id.clone(), at))
            .collect();
    }

    fn drain_events(&mut self) {
        loop {
            match self.events.try_recv() {
                Ok(ProxyEvent::FlowNew { flow })
                | Ok(ProxyEvent::FlowUpdate { flow })
                | Ok(ProxyEvent::FlowDone { flow }) => self.upsert(*flow),
                Ok(ProxyEvent::WsMessageEvent { id, .. }) => {
                    // Frames are held on the flow, so the open detail view is
                    // simply reloaded rather than patched in two places.
                    if self.selected.as_ref() == Some(&id) {
                        self.load_detail(&id);
                    }
                }
                // Native GUI does not surface breakpoints yet; ignore so the
                // exhaustive match stays complete when pause events land.
                Ok(ProxyEvent::PauseHit { .. }) | Ok(ProxyEvent::PauseResolved { .. }) => {}
                Ok(ProxyEvent::Clear) => {
                    self.rows.clear();
                    self.index.clear();
                    self.selected = None;
                    self.detail = None;
                }
                Ok(ProxyEvent::Status { status }) => self.status = *status,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Lagged(_)) => self.resync(),
                Err(TryRecvError::Closed) => {
                    self.live = false;
                    break;
                }
            }
        }
        self.status.flow_count = self.store.len();
    }

    fn upsert(&mut self, flow: FlowSummary) {
        if let Some(at) = self.index.get(&flow.id).copied() {
            // The detail view holds a snapshot, so a flow that finishes while
            // it is open has to be re-read rather than left showing "pending".
            if self.selected.as_ref() == Some(&flow.id) {
                let id = flow.id.clone();
                self.load_detail(&id);
            }
            self.rows[at] = flow;
            return;
        }
        self.index.insert(flow.id.clone(), self.rows.len());
        self.rows.push(flow);

        if self.rows.len() > MAX_ROWS + EVICT_SLACK {
            self.rows.drain(..self.rows.len() - MAX_ROWS);
            self.reindex();
        }
    }

    fn load_detail(&mut self, id: &str) {
        let Some(flow) = self.store.get(id) else {
            self.detail = None;
            return;
        };
        let request = self.preview(flow.request.body.as_ref());
        let response = self.preview(flow.response.as_ref().and_then(|r| r.body.as_ref()));
        self.detail = Some(Detail {
            flow,
            request,
            response,
        });
    }

    fn preview(&self, meta: Option<&crate::types::BodyMeta>) -> Preview {
        let Some(meta) = meta else {
            return Preview::Absent;
        };
        let Some(bytes) = self.store.bodies().read(&meta.id) else {
            return Preview::Reclaimed { size: meta.size };
        };

        // A body that lies about its encoding is shown as it arrived: seeing
        // the raw bytes is more useful than refusing to show anything.
        let decoded =
            decode_body(&bytes, meta.content_encoding.as_deref()).unwrap_or_else(|_| bytes.to_vec());

        // A type we do not recognise is still shown when the bytes happen to be
        // text, since plenty of APIs send JSON under a private content type.
        if !is_textual(meta.content_type.as_deref()) && std::str::from_utf8(&decoded).is_err() {
            return Preview::Binary { size: meta.size };
        }

        let clipped = decoded.len() > PREVIEW_LIMIT || meta.truncated;
        let shown = &decoded[..decoded.len().min(PREVIEW_LIMIT)];
        match std::str::from_utf8(shown) {
            Ok(text) => Preview::Text {
                text: text.to_string(),
                clipped,
            },
            // Cutting at a byte offset can land inside a character, which is a
            // property of the cut and not of the body.
            Err(err) => Preview::Text {
                text: String::from_utf8_lossy(&shown[..err.valid_up_to()]).into_owned(),
                clipped: true,
            },
        }
    }

    fn visible(&self) -> Vec<&FlowSummary> {
        let needle = self.filter.trim().to_ascii_lowercase();
        self.rows
            .iter()
            .rev()
            .filter(|flow| !self.only_errors || is_failure(flow))
            .filter(|flow| needle.is_empty() || haystack(flow).contains(&needle))
            .collect()
    }
}

impl eframe::App for Inspector {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.drawn {
            self.drawn = true;
            let size = ctx.screen_rect().size();
            tracing::info!(
                width = size.x,
                height = size.y,
                "inspector window drew its first frame"
            );
        }
        self.drain_events();

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("PROXIMA").strong().color(ACCENT));
                let (dot, tip) = if self.live {
                    ("live", "capturing")
                } else {
                    ("stopped", "the servers are no longer running")
                };
                ui.label(egui::RichText::new(dot).color(if self.live { OK } else { ERROR }))
                    .on_hover_text(tip);

                // QUIC/UDP listener facts from ServerStatus (never the TCP proxy port).
                if let Some(label) = quic_status_label(&self.status) {
                    ui.separator();
                    let tip = self
                        .status
                        .quic_note
                        .clone()
                        .unwrap_or_else(|| {
                            "QUIC/HTTP3 over UDP. Regular TCP proxy mode cannot see QUIC."
                                .to_string()
                        });
                    ui.label(egui::RichText::new(label).monospace().weak())
                        .on_hover_text(tip);
                }

                // WireGuard scaffold bind facts (never claim device-join crypto).
                if let Some(label) = wireguard_status_label(&self.status) {
                    ui.separator();
                    let tip = self
                        .status
                        .wireguard_note
                        .clone()
                        .unwrap_or_else(|| {
                            "WireGuard UDP scaffold only. Noise/WG crypto is not shipped."
                                .to_string()
                        });
                    ui.label(egui::RichText::new(label).monospace().weak())
                        .on_hover_text(tip);
                }

                // TUN scaffold task (never claim host packet capture).
                if let Some(label) = tun_status_label(&self.status) {
                    ui.separator();
                    let tip = self.status.tun_note.clone().unwrap_or_else(|| {
                        "TUN scaffold only. No utun//dev/net/tun open; not working host capture."
                            .to_string()
                    });
                    ui.label(egui::RichText::new(label).monospace().weak())
                        .on_hover_text(tip);
                }

                ui.separator();
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("Filter by method, host, path, status or connection")
                        .desired_width(320.0),
                );
                ui.checkbox(&mut self.only_errors, "Errors only");

                ui.separator();
                ui.label(format!("{} flows", self.status.flow_count));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Clear").clicked() {
                        self.store.clear();
                    }
                    ui.label(
                        egui::RichText::new(format!(
                            "proxy {}:{}",
                            self.status
                                .addresses
                                .first()
                                .map(String::as_str)
                                .unwrap_or("127.0.0.1"),
                            self.status.proxy_port
                        ))
                        .monospace()
                        .weak(),
                    )
                    .on_hover_text(format!(
                        "Inspector also on http://127.0.0.1:{}\nRoot CA SHA-256 {}",
                        self.status.ui_port, self.status.ca_fingerprint
                    ));
                });
            });
            ui.add_space(4.0);
        });

        if self.detail.is_some() {
            egui::SidePanel::right("detail")
                .resizable(true)
                .default_width(460.0)
                .min_width(320.0)
                .show(ctx, |ui| self.draw_detail(ui));
        }

        egui::CentralPanel::default().show(ctx, |ui| self.draw_list(ui));
    }
}

impl Inspector {
    fn draw_list(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(header_row()).monospace().weak());
        });
        ui.separator();

        let visible: Vec<FlowSummary> = self.visible().into_iter().cloned().collect();
        if visible.is_empty() {
            ui.add_space(12.0);
            ui.label(
                egui::RichText::new(if self.rows.is_empty() {
                    "Nothing captured yet. Point a device at the proxy, or send a request through it."
                } else {
                    "No flow matches that filter."
                })
                .weak(),
            );
            return;
        }

        let mut clicked = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for flow in &visible {
                    let selected = self.selected.as_ref() == Some(&flow.id);
                    let response = ui.selectable_label(
                        selected,
                        egui::RichText::new(row_text(flow))
                            .monospace()
                            .color(row_color(flow)),
                    );
                    if response.clicked() {
                        clicked = Some(flow.id.clone());
                    }
                }
            });

        if let Some(id) = clicked {
            self.selected = Some(id.clone());
            self.load_detail(&id);
        }
    }

    fn draw_detail(&mut self, ui: &mut egui::Ui) {
        // Taken out of `self` for the duration of the draw. The buttons below
        // change the selection, and holding a borrow of `self.detail` across
        // that is what would otherwise force this into flags and a second pass.
        let Some(detail) = self.detail.take() else {
            return;
        };
        let mut close = false;
        let mut copy = false;

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(&detail.flow.request.method)
                    .monospace()
                    .strong()
                    .color(ACCENT),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                close = ui.button("Close").clicked();
                copy = ui.button("Copy as cURL").clicked();
            });
        });

        if copy {
            let body = detail
                .flow
                .request
                .body
                .as_ref()
                .and_then(|meta| self.store.bodies().read(&meta.id))
                .map(|bytes| bytes.to_vec());
            let command = crate::replay::to_curl(&detail.flow, body.as_deref());
            ui.ctx().copy_text(command);
        }

        ui.label(egui::RichText::new(&detail.flow.request.url).monospace());
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                let flow = &detail.flow;
                egui::Grid::new("facts")
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        fact(ui, "Status", &status_line(flow));
                        fact(
                            ui,
                            "Kind",
                            &format!(
                                "{:?}, {}",
                                flow.kind,
                                if flow.intercepted {
                                    "decrypted"
                                } else {
                                    "opaque"
                                }
                            ),
                        );
                        fact(ui, "HTTP", flow.request.http_version.as_label());
                        // transport is orthogonal: omit on TCP (including H2);
                        // "quic" only for H3. connectionId/streamId group H2+H3.
                        if let Some(transport) = flow.transport {
                            fact(ui, "Transport", transport.as_str());
                        }
                        if let Some(conn) = &flow.connection_id {
                            fact(ui, "Connection", conn);
                        }
                        if let Some(stream) = flow.stream_id {
                            fact(ui, "Stream id", &stream.to_string());
                        }
                        if let Some(upstream) = flow.upstream_stream_id {
                            fact(ui, "Upstream stream id", &upstream.to_string());
                        }
                        if let Some(end) = flow.timings.end {
                            fact(
                                ui,
                                "Duration",
                                &format!("{} ms", end.saturating_sub(flow.timings.start)),
                            );
                        }
                        fact(
                            ui,
                            "Client",
                            &format!("{}:{}", flow.client.address, flow.client.port),
                        );
                        if let Some(version) = &flow.server.tls_version {
                            fact(ui, "TLS", version);
                        }
                        if let Some(cipher) = &flow.server.cipher {
                            fact(ui, "Cipher", cipher);
                        }
                        if let Some(alpn) = &flow.server.alpn {
                            fact(ui, "ALPN", alpn);
                        }
                    });

                if let Some(error) = &flow.error {
                    ui.add_space(6.0);
                    ui.colored_label(ERROR, &error.message);
                    if error.likely_pinning == Some(true) {
                        ui.colored_label(WARN, LIKELY_PINNING_NOTE);
                    }
                }

                if let Some(tunnel) = &flow.tunnel {
                    ui.add_space(6.0);
                    ui.label(format!(
                        "Tunnelled, {}: {} sent, {} received",
                        tunnel.reason, tunnel.bytes_sent, tunnel.bytes_received
                    ));
                }

                section(ui, "Request headers", &flow.request.headers);
                body_section(ui, "Request body", &detail.request);
                if let Some(response) = &flow.response {
                    section(ui, "Response headers", &response.headers);
                }
                body_section(ui, "Response body", &detail.response);

                if let Some(messages) = &flow.ws_messages {
                    ui.add_space(8.0);
                    ui.heading("WebSocket");
                    for message in messages.iter().take(500) {
                        let arrow = match message.direction {
                            crate::types::WsDirection::Send => "->",
                            crate::types::WsDirection::Recv => "<-",
                        };
                        let mut mark = String::new();
                        if message.injected {
                            mark.push_str(" [injected]");
                        }
                        // Observe-side inflate: text is readable; size stays wire length.
                        if message.compressed {
                            mark.push_str(" [compressed]");
                        }
                        let text = message
                            .text
                            .clone()
                            .unwrap_or_else(|| format!("{} bytes", message.size));
                        ui.label(
                            egui::RichText::new(format!("{arrow}{mark} {text}")).monospace(),
                        );
                    }
                }
            });

        if close {
            self.selected = None;
        } else {
            self.detail = Some(detail);
        }
    }
}

/* ------------------------------------------------------------------ */
/* drawing helpers                                                     */
/* ------------------------------------------------------------------ */

const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x7d, 0xb9, 0xff);
const OK: egui::Color32 = egui::Color32::from_rgb(0x6f, 0xcf, 0x97);
const WARN: egui::Color32 = egui::Color32::from_rgb(0xe8, 0xc4, 0x6a);
const ERROR: egui::Color32 = egui::Color32::from_rgb(0xef, 0x76, 0x76);
const PLAIN: egui::Color32 = egui::Color32::from_rgb(0xd8, 0xdc, 0xe4);

fn fact(ui: &mut egui::Ui, name: &str, value: &str) {
    ui.label(egui::RichText::new(name).weak());
    ui.label(egui::RichText::new(value).monospace());
    ui.end_row();
}

fn section(ui: &mut egui::Ui, title: &str, headers: &[(String, String)]) {
    if headers.is_empty() {
        return;
    }
    ui.add_space(8.0);
    egui::CollapsingHeader::new(format!("{title} ({})", headers.len()))
        .default_open(false)
        .show(ui, |ui| {
            egui::Grid::new(title)
                .num_columns(2)
                .spacing([12.0, 2.0])
                .striped(true)
                .show(ui, |ui| {
                    for (name, value) in headers {
                        ui.label(egui::RichText::new(name).monospace().weak());
                        ui.label(egui::RichText::new(value).monospace());
                        ui.end_row();
                    }
                });
        });
}

fn body_section(ui: &mut egui::Ui, title: &str, preview: &Preview) {
    match preview {
        Preview::Absent => {}
        Preview::Text { text, clipped } => {
            ui.add_space(8.0);
            egui::CollapsingHeader::new(title)
                .default_open(true)
                .show(ui, |ui| {
                    if *clipped {
                        ui.label(egui::RichText::new("Shown in part.").weak());
                    }
                    ui.add(
                        egui::TextEdit::multiline(&mut text.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
        }
        Preview::Binary { size } => {
            ui.add_space(8.0);
            ui.label(egui::RichText::new(format!("{title}: {size} bytes, binary")).weak());
        }
        Preview::Reclaimed { size } => {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!(
                    "{title}: {size} bytes, no longer held. The body store dropped it to stay \
                     under its ceiling."
                ))
                .weak(),
            );
        }
    }
}

fn header_row() -> String {
    format!(
        "{:<7} {:<28} {:<38} {:>6} {:>9} {:>8}",
        "METHOD", "HOST", "PATH", "STATUS", "SIZE", "TIME"
    )
}

fn row_text(flow: &FlowSummary) -> String {
    format!(
        "{:<7} {:<28} {:<38} {:>6} {:>9} {:>8}",
        clip(&flow.method, 7),
        clip(&flow.authority, 28),
        clip(&flow.path, 38),
        flow.status
            .map(|status| status.to_string())
            .unwrap_or_else(|| if flow.error.is_some() { "err".into() } else { "…".into() }),
        bytes(flow.response_size),
        flow.duration
            .map(|ms| format!("{ms} ms"))
            .unwrap_or_default(),
    )
}

/// Cuts on a character boundary, since a header or a path can be any UTF-8.
fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let kept: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn bytes(size: u64) -> String {
    if size < 1024 {
        format!("{size} B")
    } else if size < 1024 * 1024 {
        format!("{:.1} kB", size as f64 / 1024.0)
    } else {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    }
}

fn row_color(flow: &FlowSummary) -> egui::Color32 {
    if flow.likely_pinning {
        return WARN;
    }
    if is_failure(flow) {
        return ERROR;
    }
    match flow.status {
        Some(200..=299) => OK,
        Some(300..=399) => ACCENT,
        _ => PLAIN,
    }
}

fn is_failure(flow: &FlowSummary) -> bool {
    matches!(flow.state, FlowState::Error | FlowState::Aborted)
        || flow.error.is_some()
        || flow.status.map(|status| status >= 400).unwrap_or(false)
}

fn status_line(flow: &Flow) -> String {
    match &flow.response {
        Some(response) => format!("{} {}", response.status, response.status_text),
        None => format!("{:?}", flow.state),
    }
}

fn haystack(flow: &FlowSummary) -> String {
    // Include multiplex session keys so typing a connection/stream id groups
    // sibling H2 TLS or H3 QUIC streams the same way the web inspector does.
    // "mock" is a synthetic token so filtering mocked map-local rows matches
    // the web inspector needle.
    format!(
        "{} {}{} {} {} {} {} {} {} {}",
        flow.method,
        flow.authority,
        flow.path,
        flow.status.map(|s| s.to_string()).unwrap_or_default(),
        flow.content_type.clone().unwrap_or_default(),
        flow.http_version.as_label(),
        flow.transport.map(|t| t.as_str()).unwrap_or(""),
        flow.connection_id.as_deref().unwrap_or(""),
        flow.stream_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        if flow.mocked { "mock" } else { "" },
    )
    .to_ascii_lowercase()
}

/// Compact toolbar label for a bound QUIC/UDP listener. `None` when no UDP
/// socket is listening so the classic TCP proxy status line stays quiet.
fn quic_status_label(status: &ServerStatus) -> Option<String> {
    let port = status.quic_port?;
    let label = match status.reverse_h3.as_deref() {
        Some(upstream) => format!("quic :{port} reverse {upstream}"),
        None => format!("quic :{port} accept-only"),
    };
    Some(label)
}

/// Compact toolbar label for a bound WireGuard scaffold UDP port. `None` when
/// no WG socket is listening. Always says "scaffold" so the UI never looks like
/// a working device tunnel.
fn wireguard_status_label(status: &ServerStatus) -> Option<String> {
    let port = status.wireguard_port?;
    Some(format!("wg :{port} scaffold"))
}

/// Compact toolbar label when the TUN scaffold task was requested. `None` when
/// TUN was never started. Always says "scaffold" so the UI never looks like
/// working host packet capture.
fn tun_status_label(status: &ServerStatus) -> Option<String> {
    if status.tun_active == Some(true) {
        Some("tun scaffold".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HttpVersion, Scheme};

    fn summary(method: &str, host: &str, path: &str, status: Option<u16>) -> FlowSummary {
        FlowSummary {
            id: format!("{method}-{host}-{path}"),
            kind: crate::types::FlowKind::Http,
            state: if status.is_some() {
                FlowState::Complete
            } else {
                FlowState::Pending
            },
            intercepted: true,
            method: method.to_string(),
            scheme: Scheme::Https,
            authority: host.to_string(),
            path: path.to_string(),
            http_version: HttpVersion::Http2,
            status,
            content_type: Some("application/json".to_string()),
            request_size: 0,
            response_size: 1536,
            start: 1_700_000_000_000,
            duration: Some(42),
            error: None,
            likely_pinning: false,
            client: "127.0.0.1".to_string(),
            transport: None,
            connection_id: None,
            stream_id: None,
            mocked: false,
        }
    }

    #[test]
    fn a_row_lines_up_with_its_header() {
        let row = row_text(&summary("GET", "api.example.com", "/v1/things", Some(200)));
        let header = header_row();
        assert_eq!(
            row.chars().count(),
            header.chars().count(),
            "the columns drift apart:\n{header}\n{row}"
        );
    }

    #[test]
    fn a_long_path_is_cut_on_a_character_boundary() {
        let long = "/".to_string() + &"путь".repeat(40);
        let row = row_text(&summary("GET", "api.example.com", &long, Some(200)));
        // The assertion is that this does not panic and stays inside its column.
        assert_eq!(row.chars().count(), header_row().chars().count());
        assert!(row.contains('…'), "a cut path must say it was cut: {row}");
    }

    #[test]
    fn clipping_never_splits_a_character() {
        assert_eq!(clip("héllo", 10), "héllo");
        assert_eq!(clip("héllo", 3), "hé…");
        assert_eq!(clip("日本語のテキスト", 4), "日本語…");
    }

    #[test]
    fn pinning_outranks_the_status_colour() {
        let mut flow = summary("GET", "api.bank.com", "/", None);
        flow.likely_pinning = true;
        flow.state = FlowState::Error;
        assert_eq!(row_color(&flow), WARN, "a pinned host must be told apart from a plain failure");
    }

    /// P11 honesty: the native pane must not treat likely_pinning as pure
    /// app-pinning proof (Chrome user-CA refusal for QUIC is the same class).
    #[test]
    fn likely_pinning_copy_is_not_pure_pinning_proof() {
        assert!(
            LIKELY_PINNING_NOTE.contains("not pure pinning proof"),
            "gui detail must not claim pure app pinning for likely_pinning"
        );
        assert!(
            LIKELY_PINNING_NOTE.contains("user-CA"),
            "gui detail must name user-CA policy as an alternate cause"
        );
        assert!(
            LIKELY_PINNING_NOTE.contains("TCP/HTTP2"),
            "gui detail should point operators at force-TCP when cert reject fires"
        );
    }

    #[test]
    fn a_four_hundred_counts_as_a_failure() {
        assert!(is_failure(&summary("GET", "api.example.com", "/", Some(404))));
        assert!(is_failure(&summary("GET", "api.example.com", "/", Some(500))));
        assert!(!is_failure(&summary("GET", "api.example.com", "/", Some(204))));
        assert!(!is_failure(&summary("GET", "api.example.com", "/", Some(302))));
    }

    #[test]
    fn the_filter_matches_case_insensitively_across_the_row() {
        let flow = summary("POST", "API.Example.com", "/v1/Users", Some(201));
        let hay = haystack(&flow);
        for needle in ["post", "api.example.com", "/v1/users", "201", "json"] {
            assert!(hay.contains(needle), "{needle} did not match {hay}");
        }
    }

    #[test]
    fn haystack_matches_multiplex_and_quic_fields() {
        use crate::types::Transport;
        let mut flow = summary("GET", "h3.example", "/x", Some(200));
        flow.http_version = HttpVersion::Http3;
        flow.transport = Some(Transport::Quic);
        flow.connection_id = Some("quic-conn-uuid".into());
        flow.stream_id = Some(0);
        let hay = haystack(&flow);
        for needle in ["3.0", "quic", "quic-conn-uuid", "0"] {
            assert!(hay.contains(needle), "{needle} did not match {hay}");
        }
    }

    #[test]
    fn quic_status_label_names_port_and_mode() {
        let mut status = ServerStatus {
            proxy_port: 9090,
            ui_port: 9091,
            addresses: vec!["127.0.0.1".into()],
            ca_fingerprint: "ab".into(),
            ca_not_after: "2035-01-01T00:00:00Z".into(),
            flow_count: 0,
            capturing: true,
            archiving: false,
            archive_dropped: 0,
            quic_enabled: true,
            quic_port: None,
            quic_note: None,
            reverse_h3: None,
            wireguard_enabled: false,
            wireguard_port: None,
            wireguard_note: None,
            tun_enabled: false,
            tun_active: None,
            tun_note: None,
        };
        assert!(quic_status_label(&status).is_none());

        status.quic_port = Some(9443);
        assert_eq!(
            quic_status_label(&status).as_deref(),
            Some("quic :9443 accept-only")
        );

        status.reverse_h3 = Some("origin.example:443".into());
        assert_eq!(
            quic_status_label(&status).as_deref(),
            Some("quic :9443 reverse origin.example:443")
        );
    }

    #[test]
    fn wireguard_status_label_names_scaffold_port() {
        let mut status = ServerStatus {
            proxy_port: 9090,
            ui_port: 9091,
            addresses: vec!["127.0.0.1".into()],
            ca_fingerprint: "ab".into(),
            ca_not_after: "2035-01-01T00:00:00Z".into(),
            flow_count: 0,
            capturing: true,
            archiving: false,
            archive_dropped: 0,
            quic_enabled: false,
            quic_port: None,
            quic_note: None,
            reverse_h3: None,
            wireguard_enabled: true,
            wireguard_port: None,
            wireguard_note: None,
            tun_enabled: false,
            tun_active: None,
            tun_note: None,
        };
        assert!(wireguard_status_label(&status).is_none());

        status.wireguard_port = Some(51820);
        assert_eq!(
            wireguard_status_label(&status).as_deref(),
            Some("wg :51820 scaffold")
        );
        // Never looks like a working tunnel.
        let label = wireguard_status_label(&status).expect("label");
        assert!(label.contains("scaffold"), "{label}");
        assert!(!label.contains("tunnel"), "{label}");
    }

    #[test]
    fn tun_status_label_names_scaffold_when_active() {
        let mut status = ServerStatus {
            proxy_port: 9090,
            ui_port: 9091,
            addresses: vec!["127.0.0.1".into()],
            ca_fingerprint: "ab".into(),
            ca_not_after: "2035-01-01T00:00:00Z".into(),
            flow_count: 0,
            capturing: true,
            archiving: false,
            archive_dropped: 0,
            quic_enabled: false,
            quic_port: None,
            quic_note: None,
            reverse_h3: None,
            wireguard_enabled: false,
            wireguard_port: None,
            wireguard_note: None,
            tun_enabled: true,
            tun_active: None,
            tun_note: None,
        };
        assert!(tun_status_label(&status).is_none());

        status.tun_active = Some(true);
        assert_eq!(
            tun_status_label(&status).as_deref(),
            Some("tun scaffold")
        );
        let label = tun_status_label(&status).expect("label");
        assert!(label.contains("scaffold"), "{label}");
        assert!(
            !label.contains("capture") && !label.contains("tunnel"),
            "must not look like working capture: {label}"
        );
    }

    #[test]
    fn sizes_are_readable_at_every_scale() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1536), "1.5 kB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn a_pending_flow_shows_that_it_has_no_status_yet() {
        let row = row_text(&summary("GET", "api.example.com", "/slow", None));
        assert!(row.contains('…'), "a flow in flight needs a placeholder: {row}");

        let mut failed = summary("GET", "api.example.com", "/gone", None);
        failed.error = Some("connection refused".to_string());
        assert!(row_text(&failed).contains("err"));
    }
}
