# Plans

What is next, and why in this order. Kept here so the list stops living in
chat logs.

## Done

- **Traffic archive.** Finished flows recorded to DuckDB, `POST
  /api/archive/query` and `GET /api/archive/stats` over them. Behind the
  off-by-default `archive` feature.
- **Rewrite rules.** Request and response headers set, replaced and removed;
  `--map-host` sends a host's traffic elsewhere. Edits land before the flow is
  recorded, and each change leaves a note on the flow.

## Done (recent)

- **Map local / mock.** `RewriteRule.mock` (status, headers, body / body_file);
  last matching mock wins; no upstream dial; `Flow.mocked` + rewrite notes;
  live rules via `RewriteHub` and `GET|PUT /api/rewrite`.
- **HTTP request breakpoints.** Same PauseHub as WS; `kind: http` +
  `http_half: request`; hold before dial; release with optional method/url/
  headers/body overrides; response-half still open.
- **`{{var}}` environments.** Active env on the store; `environmentId` on
  `SendSpec`; interpolate URL/headers/UTF-8 body on send/replay; composer env
  select + `GET|PUT /api/environments/active`.

## Next

1. **HTTP response breakpoints.** Pause after origin response (collect or
   size-gated), share release API with request half.
2. **The UI pass.** Filters over `FlowQuery`, archive stats panel, rewrite /
   map-local editor (API exists: `/api/rewrite`, `/api/archive/*`).
3. **Body rewrite** (match-replace on path/query/body with size gates).

## Protocol coverage (product requirement)

WebSocket, QUIC and HTTP/3 are all in scope. The README still describes what
the **default TCP HTTP proxy** can and cannot see today; that honesty stays.
The plan is to close the gaps with explicit modes, not by pretending CONNECT
on TCP can carry QUIC.

### WebSocket (partial today → full)

Shipped: RFC 6455 upgrade, bidirectional byte-copy, best-effort frame parse
into `Flow.ws_messages`, HAR handshake + frames, inspector/GUI lists frames.
Observation never blocks the pipe (parse failures fall back to opaque copy).
`POST /api/flows/{id}/ws/send` injects text/binary/ping/pong/close either way
on a live upgrade (masked toward origin); the Frames tab has the form, and
injected frames are marked in the list and on the event socket. Inject skips
rewrite and breakpoints, writes immediately, records like wire traffic.

Shipped for Frames filter / search / pretty UI: direction and opcode filters plus
substring search on raw frame text, shared across live `ws:message` appends and
filter changes via a retained `MAX_FRAMES` window; text frames that parse as
JSON pretty-print on display only. Opcode 15 drop markers label as retention
gaps. Larger retention controls and bodyId load-on-demand are still open.

Shipped for frame breakpoints: runtime rules via `GET|PUT /api/breakpoints`,
hold/release/drop via `/api/pauses`, `pause:hit` / `pause:resolved` on the
event socket, parse-before-forward only when a WS rule is enabled, timeout
auto-release, inspector Breakpoints panel and held-frame strip. Control frames
are not paused by default. Protocol is kind-tagged for future HTTP pauses.

Shipped for WS rewrite/drop: config + runtime hub (`WsRewriteRule` /
`WsRewriteEngine` / `WsRewriteHub`), match host/path/direction/opcode/
text_regex, replace payload or drop frame before forward, rewrite-before-pause,
capture notes on `Flow.rewrites`, inject skips rewrite. Empty rules keep the
zero-latency byte-copy path. `GET|PUT /api/ws-rewrite` and the inspector
**WS rewrite** panel replace the rule list live (invalid regex/base64 is 400).
CLI flags for seeding rules from the command line are still optional.

Shipped for inject/replay API docs (README): `POST .../ws/send` and
`.../ws/replay` camelCase bodies, payload priority, 200/400/404/409 shapes,
fail-closed limits (drop markers, continuations, truncated/missing body,
deflate uncompressed replay), compose not implemented. Implementation lives in
`api/routes.rs` (`WsSendRequest`) and `replay/ws.rs` (`WsReplayRequest`).

Still missing for parity with Proxyman / Burp / mitmproxy:

1. **HTTP request/response breakpoints** (same pause protocol, new kind body).
2. **permessage-deflate (MVP landed):** parse `Sec-WebSocket-Extensions` on the
   101, raw-copy the pipe, inflate a copy for capture (`WsMessage.compressed`).
   Under deflate, rewrite/breakpoint re-encode is disabled so RSV1 is not
   stripped. Inject stays uncompressed. Multi-frame messages keep inflater
   continuity; full decoded display attaches on FIN. Inspector Frames and the
   egui GUI mark compressed frames (size labeled as wire length); REST and
   `ws:message` events expose `compressed` when true; HAR uses `_compressed`.
   Remaining: optional rewrite after inflate (explicit out of scope).
3. **Larger WS frame retention and bodyId load-on-demand** (filter/search/pretty
   on the Frames tab is shipped; caps and on-demand body fetch still open).
4. **Replay of a single frame or recorded sequence:** live mode shipped
   (`POST /api/flows/{id}/ws/replay` onto the same or another live upgrade;
   Frames tab has history replay plus per-frame ↻). Compose mode (dial a new
   socket with `replay_of`) still open.
5. **CLI flags** to seed WS rewrite rules at startup (API/inspector already live).

Natural home for remaining WS work: `proxy/websocket.rs` + event socket +
inspector Frames / Breakpoints panels.

### QUIC and HTTP/3 (not reachable via regular proxy mode)

**Why the default TCP proxy cannot see them:** QUIC is UDP. A phone pointed at
`host:9090` as an HTTP proxy only sends TCP CONNECT (and plain HTTP). UDP
never arrives on that listener. Clients that insist on HTTP/3 stay invisible;
many fall back to HTTP/2 when a proxy is set, which is luck, not support.

**What competitors actually do:** mitmproxy 11 decrypts HTTP/3 in transparent,
WireGuard and reverse modes, not in classic regular proxy mode. Chrome also
often refuses user CAs for QUIC, so even a working MITM needs a documented
fallback story.

#### Scaffold status (as of reverse H3 path)

Feature gate: `--features quic` (`quinn` rustls-ring + `h3` + `h3-quinn`),
off by default like `gui` and `archive`. Default binary does not link quinn.

| Surface | Status |
| --- | --- |
| UDP bind + port-0 rewrite + shared shutdown drain | **Landed** (`src/quic/udp.rs`, `endpoint.rs`, `runtime.rs`) |
| QUIC TLS MITM (CA leaves, ALPN `h3` only, 0-RTT off, ring) | **Landed** (`src/quic/tls.rs` via `CertAuthority::certified_key` / SniResolver) |
| Accept-only skeleton (record request, answer 501) | **Landed** (`src/quic/http3.rs`) |
| Reverse H3 MITM (authority rewrite, body tee, hop sanitize, one stream = one Flow) | **Landed** (`src/quic/reverse.rs`, `forward_upstream.rs`) |
| Flow model: `HttpVersion::Http3`, `Transport::Quic`, `connection_id` / `stream_id` / `upstream_stream_id` | **Landed** (always-on types; TCP leaves them `None`) |
| CLI: `--quic` / `--quic-port` / `--quic-host` / `--reverse-h3` / `--mode reverse-h3`; hard fail without feature | **Landed** (`config.rs`, `main.rs`) |
| Status honesty: `quicEnabled` / `quicPort` / `quicNote` (accept-only + WireGuard/TUN note) | **Landed** (`ServerStatus`; regular mode never claims QUIC on TCP port) |
| HAR `HTTP/3` + `connection` / `_transport` / `_streamId` / `_upstreamStreamId` | **Landed** |
| README reverse usage + Chrome user-CA note | **Landed** |
| Full localhost reverse e2e (client POST matches origin + Complete Http3 flow) | **Landed** (`tests/quic_reverse_e2e.rs`; accept-only 501 path too) |
| Typed error taxonomy (`quic_cert_reject` / `quic_alpn` / `quic_upstream` / `h3` / `h3_abandoned`) | **Landed** (handshake fail Flow + classifiers; shared tls_alert still open) |
| TCP H2 origin fallback when upstream has no h3 | **Open** |
| WireGuard / TUN / transparent UDP (phone path) | **Scaffold (P9 WG / P10 TUN)** / capture open |
| qlog, 0-RTT, DATAGRAM, QPACK wire capture, SO_REUSEPORT multi-worker | **Non-goals** for this ship |

Modules live under `src/quic/` (not under `src/proxy/`). Regular CONNECT proxy
unchanged; no invented H3 flows on TCP.

#### WireGuard userspace scaffold (P9)

Feature gate: `--features wireguard` (empty feature; no crypto crate). Config
fields `wg_port` / `wg_host`, CLI `--wireguard` / `--wg-port` / `--wg-host` /
`--mode wireguard`, and status `wireguardEnabled` / `wireguardPort` /
`wireguardNote` are always compiled (mirrors quic). Without the feature,
requesting a WG listener fails with rebuild guidance.

| Surface | Status |
| --- | --- |
| ListenMode::WireGuard + Config apply/validate | **Landed** (`config.rs`) |
| Feature-gated `src/wireguard/` (bind scaffold, demux, tunnel trait, DeviceJoinInfo) | **Landed** (crypto **not** shipped) |
| Runtime spawn on shared shutdown; port-0 rewrite | **Landed** (`runtime.rs`) |
| Status honesty (scaffold only; Wi-Fi proxy does not feed WG) | **Landed** |
| Reject reverse-h3 + wireguard co-enable | **Landed** |
| Noise_IK / real device join / key material | **Open** |
| Dual-feature `UdpIngress` adapter into H3 | **Open** (trait + NullUdpIngress ready) |

Device-join intent: phone joins a WG tunnel Proxima terminates in userspace so
TCP and UDP (including app QUIC) land here. P9 is bind + API surface only; do
not claim a working phone tunnel.

#### Local TUN / packet-capture scaffold (P10)

Feature gate: `--features tun` (empty feature; no tun/pcap crate). Config field
`tun: bool`, CLI `--tun` / `--mode tun`, and status `tunEnabled` / `tunActive` /
`tunNote` are always compiled. Without the feature, requesting TUN fails with
rebuild guidance. The serve task is shutdown-watch only: it does **not** open
`utun` or `/dev/net/tun` and never invents HTTP/CONNECT/H3 flows.

| Surface | Status |
| --- | --- |
| ListenMode::Tun + Config apply/validate | **Landed** (`config.rs`) |
| Feature-gated `src/tun/` (device trait, platform notes, TunServer) | **Landed** (device open **not** shipped) |
| Runtime spawn on shared shutdown (no socket bind) | **Landed** (`runtime.rs`) |
| Status honesty (scaffold only; no working-capture claim) | **Landed** |
| Reject co-enable with reverse-h3, QUIC UDP, WireGuard | **Landed** |
| Platform docs: macOS utun/NE (no TPROXY); Linux /dev/net/tun + CAP_NET_ADMIN | **Landed** (docs/notes only) |
| Real device open, routing, TPROXY, Network Extension | **Open** |
| Windows host capture | **Not claimed** |

P10 is scaffold-only. Do not treat `tunActive` or `tunEnabled` as live host
packet capture.

#### Architecture checklist (product path remaining)

1. **Path into the process for UDP**
   - **Reverse H3** (shipped scaffold above): clients point at Proxima as an H3
     origin; useful for servers and tests, not "phone system proxy".
   - **WireGuard userspace mode** (mitmproxy pattern): device joins a WG tunnel
     Proxima terminates; TCP and UDP both land here. Best mobile story.
   - **Local TUN / packet filter** (macOS/Linux): capture host process traffic
     including UDP 443.
2. **QUIC TLS MITM** (client leg + upstream H3): **landed** for reverse; H2-TCP
   origin fallback still open.
3. **HTTP/3 session ↔ flow model**: **landed** for reverse/accept (one request
   stream = one `FlowKind::Http`); inspector polish for multiplex grouping
   remains light.
4. **datagrams / QPACK / 0-RTT** policy: request/response streams only; QPACK
   only via h3 decoded headers; 0-RTT never. Documented in module docs.
5. **Browser/client constraints**: README documents Chrome user-CA + QUIC,
   force-TCP operator tips, and that Proxima has **no** Alt-Svc strip or
   client force-TCP helper. `--no-http2` is upstream-only. Keep it that way
   unless a real helper ships; do not invent product flags in docs.

Order relative to map-local / breakpoints: protocol work can proceed in
parallel (mostly new modules). Shared flow/event fields for H3 are in place;
keep new stream UI from forking the existing inspector event protocol.

### Interim honesty (phone path still open)

- Keep labeling QUIC/HTTP3 as **invisible on the default TCP proxy port**.
  The TCP `--port` listener never invents H3 flows on CONNECT.
- Accept-only (`--quic` / `--quic-port`) and reverse H3 (`--reverse-h3`) are
  real UDP paths when built with `--features quic`; do not claim that phone
  system-proxy CONNECT settings feed either. Phone QUIC needs WG/TUN (not
  shipped as a working tunnel).
- `quic_cert_reject` / `likely_pinning` is not pure app-pinning proof (Chrome
  user-CA policy too). Documented in README.
- Do not invent "client likely using QUIC elsewhere" detection; it is not
  reliable.
- Force-TCP tips (browser flags/policies, TCP-only clients, proxy fallback
  luck) are documented in README. No Alt-Svc helper is built. Prefer those
  operator tips for day-to-day mobile work until WireGuard or TUN capture
  exists.

Independent of the above, in no particular order:

- **Throttling.** Emulate 3G, EDGE and packet loss. Touches nothing else.
- **Body decoders.** protobuf and gRPC, msgpack, and JWT in an `Authorization`
  header. protobuf is common in iOS traffic and is unreadable in the inspector
  today.
- **HAR import.** Export exists; the other direction does not.
- **Reloading the archive into the inspector.** A restart currently starts with
  an empty list. Metadata survives in the archive but bodies do not, so a
  reloaded flow can never be complete, and the UI has to say which is which
  rather than pretend.

## Debts

Taken on deliberately, worth clearing.

- The archive file has no rotation and no size ceiling.
- Rewrite rules scoped to a host, method or path exist in `RewriteRule` but can
  only be built from code. The command line sets global rules only, on purpose;
  the API should expose the scoped ones.
- `config_from` returns a `Result`, so a malformed rewrite flag prints as
  `proxima: ...` rather than in clap's style. The message names the flag, but
  the formatting differs from the `--no-decrypt`/`--only` conflict.
