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

**Captured but opaque:** anything excluded with `--skip`, plus non-HTTP
protocols tunnelled through CONNECT. You get the endpoint, timing and byte
counts, not the contents.

**Not captured at all:**

- **QUIC and HTTP/3.** They run over UDP and do not traverse an HTTP proxy, so
  those packets never reach Proxima. In practice, configuring a proxy makes most
  clients fall back to TCP, but a client that insists on QUIC is invisible here.
- **Apps that ignore the system proxy**, which some SDKs do deliberately.
- **Traffic inside a VPN** the phone has already established.

**Visible, but as a failure:** apps that pin their certificates reject the
Proxima leaf and their connections fail. Proxima recognises that specific TLS
alert and labels the flow as likely pinning, so you can tell it apart from a
network problem. Exclude those hosts with `--skip api.example.com` to let them
through untouched.

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
```

`PROXIMA_LOG=debug` turns on verbose logging. `RUST_LOG` is read as a second
name for the same knob, so the reflex works too.

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
    websocket.rs      watching an upgraded socket without altering it
    headers.rs        hop-by-hop stripping and the rest of the forwarding rules
    rewrite.rs        applying the configured edits to headers in flight
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
```

## Development

```bash
cargo test --all-features               # unit tests, tests/e2e.rs, the window, the archive
cargo clippy --all-targets --all-features -- -D warnings
```

Both take every feature on purpose: the optional ones are a superset of the
default build, and without them `src/gui.rs` and `src/capture/archive.rs` are
neither tested nor linted. Drop the flag to check what someone building only the
CLI gets, which is a case worth checking, since `archive.rs` compiles either way
and the two halves have to keep the same shape.

`tests/e2e.rs` is the one worth reading. The unit tests cover the pieces in
isolation, which says nothing about whether a phone pointed at this proxy
reaches the internet, so that file stands up an HTTPS origin with its own
certificate, sends a real client through the proxy, and asserts on both what the
client received and what the capture store recorded.
