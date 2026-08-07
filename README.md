# Proxima

See every request your phone makes, then edit and replay it.

Proxima is two tools in one binary: an HTTPS interception proxy for watching
live traffic, and a request composer for replaying and hand-crafting calls
against the same API.

Written in Rust, on tokio and hyper, with rustls for TLS in both directions and
rcgen for minting certificates on the fly. The inspector is a page the binary
serves itself, so cargo is the whole build and a release build is one file with
no runtime to install.

## Quick start

```bash
cargo run
```

That prints the proxy address, the inspector URL and the setup steps. Use
`cargo run --release` for anything past a first look: every captured byte goes
through TLS, decompression and hashing, and an unoptimised build shows it.

For a native window instead of a browser tab:

```bash
cargo run --release --features gui --bin proxima-gui
```

Same proxy, same capture, same certificate authority, and the inspector port is
still served, so both views can be open at once. The window reads the capture
store directly rather than going out over HTTP and back.

`gui` is off by default because it pulls in winit and a GL stack, which is a
minute of build time that someone running only the proxy should not pay.

## Changing traffic on the way through

Headers can be added, replaced or removed in both directions, and a host can be
pointed somewhere else entirely:

```bash
cargo run -- \
  --set-header 'authorization: Bearer abc123' \
  --remove-header cookie \
  --set-response-header 'access-control-allow-origin: *' \
  --map-host api.example.com=127.0.0.1:3000
```

All four flags repeat. The header flags apply to every host, because the reason
to reach for one is almost always "put my token on everything I am about to
send"; rules scoped to a host, method or path exist in the configuration and are
what the API will expose, but the command line stays unambiguous rather than
growing a syntax for them. Setting a header replaces every copy of it rather
than appending, since an override sitting next to the original has overridden
nothing.

`--map-host` changes where the request is sent, not what it is addressed as. The
`Host` header still carries the original authority, because pointing a name at a
local service is only useful if that service sees itself being addressed as the
name. TLS, though, is negotiated with whoever answers, so an HTTPS mapping to a
local server usually wants `--insecure` alongside it: that server is not holding
a certificate for the origin it is standing in for.

**The capture shows what went on the wire, not what the app handed over.** Edits
are applied before the flow is recorded, in both directions, so the inspector
never disagrees with the traffic. That makes an injected header indistinguishable
from a real one, so each flow also carries a note per change under `rewrites`,
and the startup banner lists every rule in force. A debugging tool that quietly
alters the thing being debugged is worse than one that cannot alter it at all.

## Searching and counting what you captured

The inspector holds the last few thousand flows in memory and forgets them on
exit, which answers "what just happened" and nothing else. For "which hosts
served the most 5xx this afternoon", build with the archive and point it at a
file:

```bash
cargo run --release --features archive -- --archive
```

Every flow that finishes is copied into `~/.proxima/capture.duckdb`, which
outlives the process, and `POST /api/archive/query` runs SQL against it:

```bash
curl -s localhost:9091/api/archive/query -H 'content-type: application/json' \
  -d '{"sql":"SELECT host, count(*) AS n, CAST(quantile_cont(duration_ms, 0.95) AS BIGINT) AS p95 FROM flows GROUP BY host ORDER BY n DESC LIMIT 10"}'
```

`GET /api/archive/stats` answers the same questions without writing any SQL:
totals, busiest hosts, status classes, slowest paths, heaviest responses.

Query the `flows` view rather than the `flows_raw` table underneath it. The view
adds the three derived columns every question wants and nobody wants to retype:
`started` as a timestamp, `status_class` as 200/400/500, and `bytes` as the two
byte counts added up. Headers are a JSON array of `[name, value]` pairs, so
`json_extract` reaches them without a join. Each run tags its rows with a
`session`, so one afternoon can be told from another in a file that outlives
both.

Two things it deliberately does not do. **Bodies are not archived**, only their
sizes and content types: bodies are the one part of a capture with no ceiling on
size, and a file that grows without bound is a feature that ends up deleted.
**Submitted SQL is read only and cannot touch the filesystem**: the UI port has
no authentication and listens on every interface, so anything else would be a
file browser for whoever is on the network. Queries run on a connection opened
read only, with external access off and the configuration locked, so it is the
engine that decides what counts as a write. The leading-keyword check in front
of it is only there for the error message: `WITH x AS (SELECT 1) DELETE FROM
flows_raw` starts with an allowed word, and DuckDB will happily run it.

That read-only connection is opened per query rather than kept, because DuckDB
freezes one at the snapshot it opened with; a long-lived reader would answer
every question with the state of the file at startup.

`archive` is off by default for the same reason as `gui`: it compiles DuckDB's
C++ amalgamation, which is minutes of cold build and tens of megabytes of
binary.

## Pointing a phone at it

Both devices must be on the same network, and the phone must be able to reach
the computer's LAN address.

1. **Phone Wi-Fi settings, configure proxy, manual**: host is the computer's
   LAN IP, port 9090.
2. Open **http://proxima.setup** in the phone browser. That page is served by
   the proxy itself over plain HTTP, so it works before any certificate is
   trusted.
3. Install the certificate it offers.
4. **iOS only, and this is the step everyone misses:** Settings, General,
   About, Certificate Trust Settings, then enable full trust for the Proxima
   root. Installing the profile is not enough on its own.

Traffic appears at http://127.0.0.1:9091 as it happens.

### If the computer is on the phone's hotspot, this cannot work

A phone sharing its connection routes its own traffic over cellular, and iOS
only offers proxy settings for a Wi-Fi network the phone has joined. Either put
both devices on the same Wi-Fi network, or share Wi-Fi from the computer and
join it from the phone, then set the proxy there.

## What you will and will not see

Being precise about this matters, because "all traffic" is a claim an HTTP
proxy cannot honestly make.

**Captured and decrypted:** HTTP and HTTPS over TCP from any app that honours
the system proxy setting, including HTTP/2 and WebSockets. That covers the
large majority of iOS app traffic, since `URLSession` respects the proxy.
On a live upgraded WebSocket you can inject and replay frames (API below; the
Frames tab has the same forms). The Frames tab also filters by direction and
opcode, searches raw frame text, and pretty-prints JSON text payloads for
display (search still uses the raw capture).

### WebSocket inject and replay API

Both routes write through the live inject path: the frame is encoded and
written **immediately**, skips rewrite rules and breakpoints, is recorded like
wire traffic, and is marked `injected: true` on the message (ordinary capture
omits the field when false). Direction is relative to the client: `send` goes
toward the origin (masked), `recv` goes toward the client (unmasked).

#### `POST /api/flows/{id}/ws/send`

Body fields are camelCase:

| Field | Type | Notes |
| --- | --- | --- |
| `direction` | `"send"` \| `"recv"` | required |
| `opcode` | `1` \| `2` \| `8` \| `9` \| `10` | text, binary, close, ping, pong |
| `text` | string | UTF-8 payload |
| `dataBase64` | string | binary payload |
| `closeCode` | u16 | close frame status (big-endian on the wire) |
| `closeReason` | string | optional UTF-8 after `closeCode` |

Payload priority: `text` > `dataBase64` > `closeCode` (+ reason) > empty.
Control payloads (opcodes 8/9/10) may not exceed 125 bytes.

```bash
# Text toward the origin
curl -s localhost:9091/api/flows/$ID/ws/send -H 'content-type: application/json' \
  -d '{"direction":"send","opcode":1,"text":"hello"}'

# Binary toward the client
curl -s localhost:9091/api/flows/$ID/ws/send -H 'content-type: application/json' \
  -d '{"direction":"recv","opcode":2,"dataBase64":"AQID"}'

# Close with code + reason
curl -s localhost:9091/api/flows/$ID/ws/send -H 'content-type: application/json' \
  -d '{"direction":"send","opcode":8,"closeCode":1000,"closeReason":"bye"}'
```

Responses:

- **200** `{ "message": <WsMessage> }` with `injected: true` when set
- **400** invalid `direction`, opcode outside 1/2/8/9/10, bad `dataBase64`, or control payload longer than 125 bytes
- **404** unknown flow id
- **409** not a live upgraded socket, inject queue full, or the socket closed before the write finished

#### `POST /api/flows/{id}/ws/replay`

Replays captured frames from the source flow onto a live upgrade (same path as
`/ws/send`). Body is camelCase and **rejects unknown fields**. Empty body uses
defaults: `mode: "live"`, target = source id, auto-select injectable frames.

| Field | Type | Default |
| --- | --- | --- |
| `targetFlowId` | string | source id |
| `mode` | `"live"` only | `"live"` (`"compose"` is refused) |
| `indices` | number[] | auto-select all eligible frames |
| `directions` | `("send"\|"recv")[]` | both |
| `delayMs` | u64 | `0` |
| `stopOnError` | bool | `true` |
| `maxFrames` | usize | `4096` |

```bash
# Auto-select injectable frames onto the same live flow
curl -s localhost:9091/api/flows/$ID/ws/replay -H 'content-type: application/json' -d '{}'

# Explicit indices onto another live upgrade, pause between frames
curl -s localhost:9091/api/flows/$SOURCE/ws/replay -H 'content-type: application/json' \
  -d '{"targetFlowId":"'$TARGET'","indices":[0,2],"delayMs":50}'
```

Responses:

- **200** `{ sourceFlowId, targetFlowId, mode, planned, sent, skipped, messages, error? }`
  - `messages` are the injected `WsMessage` records (with `injected: true`)
  - partial progress is possible when `stopOnError` is false; `error` names the first failure
- **400** bad plan: unsupported `mode` (including compose), bad directions, out-of-range indices, explicit drop-marker or continuation index, non-injectable opcode, control payload over 125 bytes, `maxFrames` less than 1, or unknown JSON fields
- **404** unknown source or `targetFlowId`
- **409** not live / inject queue full / closed before write; also missing body-store bytes or truncated capture when nothing has been sent yet

**Fail-closed limits (inject and replay share these):**

- Opcodes **1, 2, 8, 9, 10** only. Opcode **0** (continuation) and **15** (retention drop marker) are never injected. Auto-selection skips them; an explicit index fails with 400.
- Truncated captures and missing non-empty body-store bytes fail closed (409 when nothing was sent).
- Under permessage-deflate, capture stores inflated display bytes; replay injects those bytes **uncompressed** (legal frames, not wire-identical RSV1).
- Compose mode (dial a new socket with `replay_of`) is **not implemented**.

**WebSocket frame breakpoints:** matching frames can be held before forward,
edited, released, or dropped. Rules live only in memory (lost on restart) and
are managed over the API or the inspector Breakpoints panel:

```bash
# Hold text and binary frames on example.com (default opcodes; not ping/pong/close)
curl -s localhost:9091/api/breakpoints -H 'content-type: application/json' -X PUT -d '{
  "rules": [{
    "id": "ws-1",
    "enabled": true,
    "kind": "ws",
    "hosts": ["example.com"],
    "pathPrefix": null,
    "directions": [],
    "opcodes": [],
    "timeoutMs": 30000
  }]
}'

# List held frames; release original or edited; drop without forwarding
curl -s localhost:9091/api/pauses
curl -s localhost:9091/api/pauses/$PAUSE_ID/release -X POST
curl -s localhost:9091/api/pauses/$PAUSE_ID/release -H 'content-type: application/json' \
  -d '{"text":"edited payload"}' -X POST
curl -s localhost:9091/api/pauses/$PAUSE_ID/drop -X POST
```

`GET|PUT /api/breakpoints` replaces the whole rule list. Empty `hosts` matches
any host; empty `directions` matches both; empty `opcodes` defaults to text and
binary only so keepalive and the close handshake are never stalled by a rule.
Each rule has a `timeoutMs`: if nobody releases or drops in time, the original
frame is auto-forwarded. The live event socket emits `pause:hit` and
`pause:resolved` (kind-tagged body: `ws` now, `http` later). Injected frames
are never paused. With no enabled rules the proxy keeps its zero-latency
byte-copy path.

**WebSocket rewrite and drop:** matching frames can have their full payload
replaced, or be dropped, before they are written. Rules apply per frame (not
reassembled messages), before breakpoints, and are runtime-replaceable via
`GET|PUT /api/ws-rewrite` or the inspector **WS rewrite** panel:

```bash
# Drop client-to-server text frames whose payload matches a regex
curl -s localhost:9091/api/ws-rewrite -H 'content-type: application/json' -X PUT -d '{
  "rules": [{
    "hosts": ["chat.example.com"],
    "pathPrefix": "/ws",
    "directions": ["send"],
    "opcodes": [],
    "textRegex": "secret",
    "drop": true
  }]
}'

# Replace every matching text payload on the wire
curl -s localhost:9091/api/ws-rewrite -H 'content-type: application/json' -X PUT -d '{
  "rules": [{
    "hosts": [],
    "directions": [],
    "opcodes": [1],
    "replaceText": "rewritten"
  }]
}'
```

Empty `hosts` / `directions` match any; empty `opcodes` means text and binary
only (never ping/pong/close by default). Capture records what went on the wire:
a replace shows the new payload and a note under the flow's `rewrites`; a drop
leaves only the note (no `ws_message`). Invalid `textRegex` or `replaceBase64`
is rejected with 400 and the previous list stays in force. Injected frames skip
rewrite rules. Opaque/broken framing has no structured match opportunity. When
the 101 negotiates permessage-deflate, the proxy keeps an exact on-wire copy
(no re-encode: RSV1 must survive) and inflates a copy for capture display
(`compressed: true` on the message; `size` is still the wire length). REST
flows, `ws:message` events, the inspector Frames tab, the GUI, and HAR
(`_compressed`) all surface that flag when display bytes were inflated.
Structured rewrite, text_regex, and breakpoints that re-encode do not apply
under deflate; inject still sends uncompressed frames. With an empty rule list
(and no breakpoints) and no deflate, the proxy keeps the zero-latency
byte-copy path.

**Captured but opaque:** anything excluded with `--skip`, plus non-HTTP
protocols tunnelled through CONNECT. You get the endpoint, timing and byte
counts, not the contents.

**Not captured on the default TCP proxy port:**

- **QUIC and HTTP/3 from a phone using only the HTTP proxy setting.** QUIC is
  UDP; a classic CONNECT proxy never sees it. The TCP `--port` listener does
  not invent HTTP/3 flows for CONNECT tunnels. Many clients fall back to TCP
  when a proxy is configured, but a client that insists on QUIC is invisible on
  `--port` alone.
- **Apps that ignore the system proxy**, which some SDKs do deliberately.
- **Traffic inside a VPN** the phone has already established.

### QUIC / HTTP/3 (optional feature)

The default binary does **not** link quinn or h3. QUIC is opt-in, like `gui`
and `archive`, so a plain `cargo run` stays a TCP HTTPS proxy.

**Enable the feature:**

```bash
cargo build --release --features quic
cargo run --release --features quic -- --help
```

Requesting `--quic`, `--quic-port`, `--reverse-h3`, or `--mode reverse-h3`
without that feature fails at startup with rebuild guidance
(`cargo build --features quic` / `cargo run --features quic -- ...`).

**0-RTT / early data is disabled** on both MITM legs (server
`max_early_data_size = 0`, client `enable_early_data = false`, no
`into_0rtt`). Handshakes are 1-RTT only: early data is replayable, tickets are
not shared across client vs origin legs, and a debugging MITM needs a full
handshake before capture is honest.

**Accept-only UDP (inspect skeleton):** bind QUIC, terminate with the same CA
as HTTPS, record each client H3 request stream as one flow, then answer `501`
(no origin yet):

```bash
cargo run --release --features quic -- --quic-port 9443
# or: --quic  (default UDP port 9443)
```

**Reverse HTTP/3:** speak H3 to clients on UDP, forward each stream to a fixed
upstream authority over H3, and capture request/response bodies in the
inspector:

```bash
cargo run --release --features quic -- \
  --quic-port 9443 \
  --reverse-h3 cloudflare-quic.com:443 \
  --insecure
```

`--reverse-h3 host[:port]` alone implies reverse-h3 mode and defaults the UDP
port to 9443. `--mode reverse-h3` is the same mode; it still needs
`--reverse-h3`. Use `--quic-port 0` to let the OS assign an ephemeral UDP port
(reported in the banner and status). `--insecure` is the same honesty as on
TCP: upstream TLS may not match the name you are standing in for.

What reverse records: one flow per client H3 request stream
(`httpVersion` 3.0, transport quic, `server.alpn` from the negotiated client
handshake when present), with optional connection/stream ids for multiplex.
Control streams, QPACK table traffic, and datagrams are not turned into fake
HTTP flows. 0-RTT early data is disabled on both legs.

**Shared multiplex identity (HTTP/2 and HTTP/3):** list rows, full flows, the
event socket (`flow:new` / `flow:update` / `flow:done`), and HAR all use the
same optional camelCase keys: `connectionId` (Proxima UUID for the client
multiplex session, not a wire QUIC CID), `streamId` (client-leg stream key when
known), and on full flows only `upstreamStreamId` when MITM reopens a
multiplexed origin leg. TCP HTTP/2 may set `connectionId` without `transport`;
HTTP/3 sets `transport: "quic"`. HTTP/1.x and opaque tunnels omit the keys.
Filter the inspector or `GET /api/flows?search=` by `connectionId` to group
sibling streams on one session.

**Still not a phone system-proxy path for QUIC.** Setting the phone's HTTP
proxy to Proxima only sends TCP CONNECT to `--port`. Getting arbitrary app
HTTP/3 into this process needs WireGuard or TUN (see PLANS.md). A
`--features wireguard` scaffold can bind a UDP listen port (`--wireguard` /
`--wg-port`, default 51820) and exposes status fields, but Noise/WG crypto and
a working device tunnel are **not** shipped. Do not treat that bind as a phone
VPN. A `--features tun` scaffold (`--tun` / `--mode tun`) starts a no-op task
only: it does **not** open `utun` or `/dev/net/tun`, and is not working host
capture. macOS would need utun/Network Extension (no TPROXY); Linux
`/dev/net/tun` + `CAP_NET_ADMIN`; Windows host capture is not claimed. Reverse
mode is for servers, tests, and clients you can point at Proxima as an H3
origin on the UDP port. WireGuard, TUN, and reverse-h3 cannot be co-enabled
in these scaffolds.

**Chrome and user-installed CAs:** Chrome often refuses user CAs for QUIC even
when the leaf is otherwise valid. If the client handshake fails with a cert
reject, Proxima records an Error flow with code `quic_cert_reject` and may set
`likely_pinning` with the same honesty caveats as TCP (that alert also covers
Chrome user-CA policy, not only app pinning). Force the browser onto TCP/HTTP2
(or a client that trusts the Proxima root for H3). That is a client policy
limit, not something the TCP proxy can fix by pretending to see QUIC.

**Visible, but as a failure:** apps that pin their certificates reject the
Proxima leaf and their connections fail. On TCP Proxima recognises the TLS
alert and labels the flow as likely pinning. On QUIC the same alert class maps
to `quic_cert_reject` (do not treat that as proof of app pinning vs Chrome's
user-CA policy). Other stable codes on the UDP path: `quic_upstream`, `quic_alpn`,
`h3`, `h3_abandoned`. Exclude pinned hosts with `--skip api.example.com` on the
TCP path to let them through untouched.

### Force-TCP operator tips (no product helper)

Phone Wi-Fi "HTTP proxy" is **TCP CONNECT only**. UDP/QUIC never arrives on
`--port`. Many mobile clients luckily fall back to HTTP/2 over that CONNECT
tunnel; that is client behaviour, not Proxima "supporting" H3 on the proxy
port. Clients that insist on QUIC stay invisible on the TCP listener.

Practical ways to keep traffic on TCP where you control the client:

- **Chrome / Chromium:** disable QUIC in flags or enterprise policy (names vary
  by version; look for "Experimental QUIC protocol" / `QuicAllowed`), or point
  only TCP-capable tools at the proxy.
- **Prefer TCP-only clients** (curl without HTTP/3, many SDKs when a system
  proxy is set) for day-to-day mobile work.
- **Do not treat `quic_cert_reject` / `likely_pinning` as pure app pinning
  proof.** Chrome's refusal of user CAs for QUIC produces the same class of
  handshake failure on the optional UDP path.

**What Proxima does not ship today:**

- No built-in Alt-Svc strip, QUIC kill-switch, or client force-TCP flag.
- No endpoint that rewrites origin headers to push browsers off H3.
- `--no-http2` forces HTTP/1.1 on the **upstream** (origin) leg only; it does
  not disable client QUIC, does not change the phone proxy path, and does not
  invent H3 visibility on CONNECT.

Status stays honest either way: `GET /api/status` exposes `quicEnabled`,
`quicPort`, `quicNote`, and `reverseH3` when relevant, and never claims QUIC
on the TCP `proxyPort`. Rebuild guidance appears when the feature is off.

Capturing genuinely everything means putting the machine in the network path,
as a transparent gateway or a VPN profile, rather than asking the device to
cooperate. That is a larger change and is not what this does today.

## Android note

Android 7 and later only trust user-installed CAs for apps whose network
security config opts in. System browsers will decrypt; a stock third-party app
usually will not, unless it is a debug build with a permissive config.

## Options

```
-p, --port <n>        proxy port devices point at      (default 9090)
-u, --ui-port <n>     UI and API port                  (default 9091)
    --data-dir <dir>  where the CA and settings live   (default ~/.proxima)
    --archive         record finished flows for later querying
                      (needs --features archive)
    --archive-path <path>  put that file somewhere other than
                      <data-dir>/capture.duckdb
    --no-decrypt      tunnel TLS opaquely, decrypt nothing
    --only <hosts>    decrypt only these hosts (comma separated, * wildcards ok)
    --skip <hosts>    never decrypt these hosts
    --max-flows <n>   ring buffer size                 (default 5000)
    --set-header <name: value>           set a request header on everything
    --remove-header <name>               remove a request header from everything
    --set-response-header <name: value>  set a response header on everything
    --remove-response-header <name>      remove a response header from everything
    --map-host <host=target>             send one host's requests elsewhere
    --no-http2        force HTTP/1.1 upstream
    --insecure        accept invalid origin certificates
    --mode <mode>     regular (TCP proxy) or reverse-h3
                      (UDP HTTP/3 reverse; needs --features quic)
    --quic            open a QUIC/UDP listener (accept-only on
                      port 9443 unless --quic-port / --reverse-h3)
    --quic-port <n>   UDP port for QUIC/HTTP3 (0 = ephemeral;
                      default 9443 with --quic or reverse-h3)
    --quic-host <ip>  bind address for QUIC UDP (default 0.0.0.0;
                      use :: for dual-stack when the OS allows)
    --reverse-h3 <host[:port]>
                      reverse-proxy HTTP/3 on the QUIC UDP port
                      (implies reverse-h3; needs --features quic)
```

`PROXIMA_LOG=debug` turns on verbose logging. `RUST_LOG` is read as a second
name for the same knob, so the reflex works too.

The QUIC flags always parse; without `--features quic` they exit with rebuild
guidance rather than silently ignoring UDP. Regular mode never opens a UDP
socket unless you pass `--quic` / `--quic-port`.

## The certificate authority

On first run Proxima generates a root CA in `~/.proxima/ca/` and mints a leaf
per hostname signed by that root, reusing one key pair so a new host costs a
signature rather than a key generation. The root private key never leaves the
machine and is written with owner-only permissions.

The leaf constraints are not cosmetic. iOS 13 and later reject server
certificates that live longer than 398 days or that identify the host only by
common name, so leaves carry a subject alternative name, a 397 day lifetime,
`serverAuth` extended key usage and a unique serial. Getting any of these wrong
produces a proxy that silently intercepts nothing.

Anyone who trusts this root and can intercept your network can read your TLS
traffic. Install it only on devices you control, and remove it when you are
done: iOS removes it with the profile, macOS from Keychain Access.

## Layout

```
src/
  main.rs             flags and the startup banner
  bin/gui.rs          the same, for the native window
  lib.rs              the module map
  runtime.rs          binding, building and stopping both servers
  gui.rs              the native inspector window (behind the gui feature)
  types.rs            the domain model every module implements against
  config.rs           configuration and the rules deciding what gets decrypted
  ca.rs               root CA, per-host leaf minting, iOS profile, SNI resolver
  proxy/
    mod.rs            CONNECT handling, TLS termination, dispatch
    forward.rs        sending a request upstream and recording both halves
    tunnel.rs         opaque tunnels for hosts that are not decrypted
    websocket.rs      upgraded socket copy, frame parse, and inject
    headers.rs        hop-by-hop stripping and the rest of the forwarding rules
    rewrite.rs        applying the configured edits to headers in flight
  quic/               QUIC/UDP + HTTP/3 (behind --features quic only)
    mod.rs            QuicServer, runtime knobs, accept loop
    udp.rs            UDP bind and port-0 resolution
    tls.rs            quinn ServerConfig/ClientConfig (ALPN h3, 0-RTT off)
    endpoint.rs       quinn Endpoint accept/connect/drain
    http3.rs          h3 session glue into FlowStore
    reverse.rs        reverse HTTP/3 MITM and Host rewrite
    forward_upstream.rs  dial origin over QUIC+H3
  capture/
    mod.rs            the flow ring buffer and the live event feed
    archive.rs        finished flows on disk, and the SQL over them
    bodies.rs         bounded in-memory body storage
    decode.rs         undoing Content-Encoding on captured bodies
    har.rs            HAR 1.2 export
  api/
    mod.rs            server state, status, shared helpers
    routes.rs         REST endpoints, live event socket, certificate downloads
    inspector.rs      the inspector page, served straight from the binary
    setup.rs          the page a phone sees first, over plain HTTP
  replay/
    mod.rs            replaying captured requests, composing new ones
    collections.rs    saved requests, folders of them, reusable variable sets
    curl.rs           cURL export
tests/
  e2e.rs              a real client, a real CONNECT, real TLS both ways
  quic_reverse_e2e.rs reverse H3 MITM (required-features = ["quic"])
```

## Development

```bash
cargo test                              # default features: no quinn/h3
cargo test --features quic              # unit tests in src/quic + quic_reverse_e2e
cargo test --all-features               # unit tests, e2e, gui, archive, quic
cargo clippy --all-targets --all-features -- -D warnings
```

Default `cargo test` stays free of the UDP stack so the common CLI path stays
fast to build. `--features quic` is required for `src/quic/*` module tests and
for `tests/quic_reverse_e2e.rs` (Cargo.toml gates that target with
`required-features = ["quic"]`). `--all-features` is a superset: without it
`src/gui.rs`, `src/capture/archive.rs`, and `src/quic/` are neither fully
tested nor linted. Drop the flag to check what someone building only the CLI
gets, which is a case worth checking, since `archive.rs` and the Http3 domain
types compile either way and have to keep the same shape.

`tests/e2e.rs` is the TCP path worth reading: an HTTPS origin with its own
certificate, a real client through CONNECT, and asserts on both what the client
received and what the capture store recorded. It does not claim QUIC visibility
on the TCP proxy. The optional `quic_reverse_e2e` target exercises localhost
UDP reverse MITM under `--features quic`.
