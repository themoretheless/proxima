//! The traffic inspector: one page, assembled here from constants.
//!
//! It is the whole front end. Markup, stylesheet and script are string
//! constants in this file for the same reason the setup page is: the only thing
//! that has to be running for it to work is this process.
//!
//! Nothing captured is interpolated into any of it. Header names, URLs, bodies
//! and error text arrive afterwards over `fetch` and the event socket, and they
//! reach the document only as `textContent` on nodes made with `createElement`.
//! That is the whole cross-site-scripting story: a captured response body
//! carrying markup never touches the HTML parser, so it renders as the text it
//! is. The policy header below is a second line of defence, not the first.

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use base64::Engine as _;
use rand::RngCore;

/// Serves the inspector, which lives at the root and nowhere else.
///
/// Anything else reaching the fallback is a mistake worth naming: a stray
/// `/api/` path answered with HTML only turns into a parse error in a console.
pub(super) fn serve(path: &str) -> Response {
    if path != "/" && path != "/index.html" {
        return not_found();
    }

    let nonce = nonce();
    let mut response = Response::new(Body::from(page(&nonce)));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(value) = HeaderValue::from_str(&policy(&nonce)) {
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

fn not_found() -> Response {
    let mut response = Response::new(Body::from(
        "Not found. The inspector is at /, the API under /api/.\n",
    ));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Names this page's own script and style so the policy never has to say
/// `unsafe-inline`. `ws:` is spelled out because browsers disagree about
/// whether `'self'` covers a socket back to the origin that served the page.
fn policy(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
         img-src data:; connect-src 'self' ws: wss:; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'"
    )
}

/// URL-safe base64, so the value is safe both in a header and in an attribute
/// without any escaping.
fn nonce() -> String {
    let mut raw = [0u8; 16];
    rand::rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// The nonce is the only thing this function substitutes, and it is generated
/// here rather than derived from anything a request carries.
fn page(nonce: &str) -> String {
    let mut page = String::with_capacity(40 * 1024);
    page.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    page.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    page.push_str("<meta name=\"color-scheme\" content=\"light dark\">\n<title>Proxima</title>\n");
    page.push_str(ICON);
    page.push_str("<style nonce=\"");
    page.push_str(nonce);
    page.push_str("\">");
    page.push_str(CSS);
    page.push_str("</style>\n</head>\n<body>\n");
    page.push_str(BODY);
    page.push_str("<script nonce=\"");
    page.push_str(nonce);
    page.push_str("\">");
    page.push_str(SCRIPT);
    page.push_str("</script>\n</body>\n</html>\n");
    page
}

/* ------------------------------------------------------------------ */
/* the page                                                            */
/* ------------------------------------------------------------------ */

/// Inline, so a tab does not spend a request on /favicon.ico it will only get a
/// 404 for.
const ICON: &str = "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' rx='4' fill='%230c0e12'/%3E%3Ccircle cx='8' cy='8' r='3.2' fill='%235ea9ff'/%3E%3C/svg%3E\">\n";

const BODY: &str = r#"<header>
  <span class="mark">PROXIMA</span>
  <span id="dot" class="dot"></span><span id="state" class="state">connecting</span>
  <input id="filter" type="search" placeholder="Filter by method, host, path, status or connection" autocomplete="off" spellcheck="false" aria-label="Filter">
  <span id="count" class="count"></span>
  <button id="theme" class="btn" type="button" title="Light, dark, or whatever this machine is set to">Theme: system</button>
  <button id="view" class="btn on" type="button">Hide tree</button>
  <button id="break" class="btn" type="button" title="Hold WebSocket frames or HTTP messages before they are forwarded">Breakpoints</button>
  <button id="rewrite" class="btn" type="button" title="Replace or drop matching WebSocket frames on the wire">WS rewrite</button>
  <button id="httprewrite" class="btn" type="button" title="Answer matching HTTP requests from a mock status, headers and body without dialling the origin">HTTP rewrite</button>
  <button id="compose" class="btn" type="button">Compose</button>
  <button id="archive" class="btn" type="button" title="Totals, busiest hosts, status classes, slowest paths and heaviest responses from the on-disk archive">Archive</button>
  <button id="clear" class="btn" type="button">Clear</button>
  <a class="btn" href="/setup">Set up a device</a>
</header>
<div id="pauses" class="pauses" hidden></div>
<main>
  <section id="tree">
    <div id="live" class="part">
      <div class="shelf" data-part="live">
        <span class="twist">▾</span><span class="shelf-name">Requests</span>
        <button id="hunt-live" class="icon" type="button" title="Search hosts and paths" aria-label="Search hosts and paths">⌕</button>
        <span class="sift"><button id="sift-live" class="icon" type="button"
              title="Grouping and filters" aria-label="Grouping and filters"
              aria-haspopup="menu" aria-expanded="false">▽</button></span>
      </div>
      <input id="live-hunt" class="hunt" type="search" autocomplete="off" spellcheck="false"
             placeholder="Host or path" aria-label="Search hosts and paths" hidden>
      <div id="devices" role="group" aria-label="Devices"></div>
      <div class="tree-scroll">
        <div id="hosts" role="tree" aria-label="Hosts and paths"></div>
      </div>
    </div>
    <div id="saved" class="part">
      <div class="shelf" data-part="saved">
        <span class="twist">▾</span><span class="shelf-name">Saved requests</span>
        <button id="hunt-saved" class="icon" type="button" title="Search saved requests" aria-label="Search saved requests">⌕</button>
        <span class="sift"><button id="sift-saved" class="icon" type="button"
              title="Grouping" aria-label="Grouping"
              aria-haspopup="menu" aria-expanded="false">▽</button></span>
        <button id="new-book" class="icon" type="button" title="New collection" aria-label="New collection">+</button>
      </div>
      <input id="saved-hunt" class="hunt" type="search" autocomplete="off" spellcheck="false"
             placeholder="Name or URL" aria-label="Search saved requests" hidden>
      <div class="tree-scroll">
        <div id="books" role="tree" aria-label="Saved requests"></div>
      </div>
      <p id="no-books" class="pad hint">Nothing saved yet. Drag a live request here, copy one into a collection, or compose and save.</p>
    </div>
    <div id="recent" class="part">
      <div class="shelf" data-part="recent">
        <span class="twist">▾</span><span class="shelf-name">Recent</span>
        <button id="clear-recent" class="icon" type="button" title="Clear send history" aria-label="Clear send history">×</button>
      </div>
      <div class="tree-scroll">
        <div id="recent-list" role="list" aria-label="Recent sends"></div>
      </div>
      <p id="no-recent" class="pad hint">Nothing sent yet. Compose and Send to fill this list.</p>
    </div>
    <div id="tree-grip" role="separator" aria-orientation="vertical" aria-label="Resize tree" title="Drag to resize"></div>
  </section>
  <section id="list">
    <div id="scope" class="idle">
      <span id="scope-name" class="mono"></span>
      <button id="scope-clear" type="button">Show everything</button>
    </div>
    <div class="head">
      <span>Method</span><span>Host</span><span>Path</span><span>Status</span><span>Size</span><span>Time</span>
    </div>
    <div id="rows" role="list"></div>
    <p id="empty">Nothing captured yet. Point a device at the proxy, trust the certificate, then load something.</p>
  </section>
  <section id="detail"><p class="hint">Pick a request to see its headers and body.</p></section>
  <section id="composer" hidden>
    <div class="c-line">
      <input id="c-name" type="text" autocomplete="off" placeholder="Name to save it under" aria-label="Name">
      <select id="c-book" aria-label="Collection"></select>
      <select id="c-env" aria-label="Environment" title="{{var}} environment for send">
        <option value="">No environment</option>
      </select>
      <button id="c-save" class="btn" type="button">Save</button>
      <button id="c-history" class="btn" type="button"
              title="Previous versions of this saved request">History</button>
    </div>
    <div class="c-line">
      <select id="c-method" aria-label="Method">
        <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option>
        <option>DELETE</option><option>HEAD</option><option>OPTIONS</option>
      </select>
      <div class="url-field">
        <div id="c-url-mirror" class="url-mirror mono" aria-hidden="true"></div>
        <input id="c-url" type="text" spellcheck="false" autocomplete="off"
               placeholder="https://api.example.com/v1/thing" aria-label="URL">
      </div>
      <button id="c-send" class="btn" type="button">Send</button>
    </div>
    <section class="c-fold" id="c-params-wrap">
      <button type="button" class="c-fold-bar" id="c-params-toggle"
              aria-expanded="true" aria-controls="c-params-panel">
        <span class="twist">▾</span>
        <span class="c-fold-name">Query parameters</span>
        <span class="c-fold-meta" id="c-params-meta"></span>
      </button>
      <div class="c-fold-body" id="c-params-panel">
        <p class="c-params-hint hint" id="c-params-hint">Key/value rows rewrite the query string on the URL above. Uncheck a row to drop it from the URL without deleting it.</p>
        <table class="c-params" id="c-params" aria-label="Query parameters">
          <thead>
            <tr>
              <th class="c-params-on" title="Include in URL">On</th>
              <th>Key</th>
              <th>Value</th>
              <th class="c-params-drop"></th>
            </tr>
          </thead>
          <tbody id="c-params-body"></tbody>
        </table>
      </div>
    </section>
    <section class="c-fold" id="c-headers-wrap">
      <button type="button" class="c-fold-bar" id="c-headers-toggle"
              aria-expanded="true" aria-controls="c-headers-panel">
        <span class="twist">▾</span>
        <span class="c-fold-name">Headers</span>
        <span class="c-fold-meta" id="c-headers-meta"></span>
      </button>
      <div class="c-fold-body" id="c-headers-panel">
        <label class="c-label" for="c-headers">One per line, as Name: value</label>
        <textarea id="c-headers" spellcheck="false" placeholder="content-type: application/json"></textarea>
      </div>
    </section>
    <section class="c-fold" id="c-body-wrap">
      <button type="button" class="c-fold-bar" id="c-body-toggle"
              aria-expanded="true" aria-controls="c-body-panel">
        <span class="twist">▾</span>
        <span class="c-fold-name">Body</span>
        <span class="c-fold-meta" id="c-body-meta"></span>
      </button>
      <div class="c-fold-body" id="c-body-panel">
        <textarea id="c-body" spellcheck="false" aria-label="Body"></textarea>
      </div>
    </section>
    <section class="c-fold" id="c-versions-wrap">
      <button type="button" class="c-fold-bar" id="c-versions-toggle"
              aria-expanded="true" aria-controls="c-versions">
        <span class="twist">▾</span>
        <span class="c-fold-name">History</span>
        <span class="c-fold-meta" id="c-versions-meta"></span>
      </button>
      <div class="c-fold-body" id="c-versions">
        <p class="hint">Open a saved request and Save a change to keep versions here.</p>
      </div>
    </section>
    <section class="c-fold" id="c-out-wrap">
      <button type="button" class="c-fold-bar" id="c-out-toggle"
              aria-expanded="true" aria-controls="c-out">
        <span class="twist">▾</span>
        <span class="c-fold-name">Response</span>
        <span class="c-fold-meta" id="c-out-meta"></span>
      </button>
      <div class="c-fold-body" id="c-out">
        <p class="hint">Send a request to see the response here.</p>
      </div>
    </section>
  </section>
  <section id="breaker" hidden>
    <p class="hint">Hold matching WebSocket frames or HTTP messages before they are forwarded. Rules are runtime-only and lost on restart. Empty hosts matches any host. For WebSocket, by default only text and binary frames pause; ping, pong and close keep flowing so keepalive and the close handshake do not stall. For HTTP, empty methods matches any method. Injected frames skip breakpoints.</p>
    <div class="c-line">
      <select id="b-kind" aria-label="Kind">
        <option value="ws">WebSocket</option>
        <option value="http">HTTP</option>
      </select>
      <select id="b-http-half" aria-label="HTTP half" title="Which half of the exchange to hold" hidden>
        <option value="request">request</option>
        <option value="response">response</option>
      </select>
      <input id="b-methods" type="text" spellcheck="false" autocomplete="off"
             placeholder="Methods, comma-separated (empty = any)" aria-label="HTTP methods"
             title="Comma-separated methods for HTTP rules; empty matches any" hidden>
      <input id="b-hosts" type="text" spellcheck="false" autocomplete="off"
             placeholder="Hosts, comma-separated (empty = any)" aria-label="Hosts">
      <input id="b-path" type="text" spellcheck="false" autocomplete="off"
             placeholder="Path prefix (empty = any)" aria-label="Path prefix">
      <input id="b-timeout" type="number" min="1000" max="300000" step="1000" value="30000"
             aria-label="Timeout in milliseconds" title="Auto-release original after this many ms">
    </div>
    <div class="c-line">
      <label class="b-check"><input id="b-enabled" type="checkbox" checked> Enabled</label>
      <select id="b-dir" aria-label="Direction">
        <option value="">both directions</option>
        <option value="send">client to server</option>
        <option value="recv">server to client</option>
      </select>
      <button id="b-save" class="btn" type="button">Save rules</button>
      <button id="b-clear" class="btn" type="button">Clear all rules</button>
    </div>
    <p id="b-status" class="hint"></p>
    <div id="b-list"></div>
  </section>
  <section id="rewriter" hidden>
    <p class="hint">Replace or drop matching WebSocket frames before they are forwarded. Applied per frame (not reassembled messages), before breakpoints, and lost on restart unless you save again. Empty hosts matches any host. Empty opcodes mean text and binary only; ping, pong and close are never rewritten by default. Injected frames skip these rules. Drops leave a note on the flow and no frame in the list; replaces record the rewritten payload.</p>
    <div class="c-line">
      <input id="w-hosts" type="text" spellcheck="false" autocomplete="off"
             placeholder="Hosts, comma-separated (empty = any)" aria-label="Hosts">
      <input id="w-path" type="text" spellcheck="false" autocomplete="off"
             placeholder="Path prefix (empty = any)" aria-label="Path prefix">
      <input id="w-regex" type="text" spellcheck="false" autocomplete="off"
             placeholder="Text regex (optional, UTF-8 only)" aria-label="Text regex">
    </div>
    <div class="c-line">
      <select id="w-dir" aria-label="Direction">
        <option value="">both directions</option>
        <option value="send">client to server</option>
        <option value="recv">server to client</option>
      </select>
      <select id="w-action" aria-label="Action">
        <option value="drop">drop frame</option>
        <option value="replace">replace payload</option>
      </select>
      <input id="w-replace" type="text" spellcheck="false" autocomplete="off"
             placeholder="Replacement text (when replace)" aria-label="Replacement text">
      <button id="w-save" class="btn" type="button">Save rules</button>
      <button id="w-clear" class="btn" type="button">Clear all rules</button>
    </div>
    <p id="w-status" class="hint"></p>
    <div id="w-list"></div>
  </section>
  <section id="httprewriter" hidden>
    <p class="hint">Rewrite matching HTTP traffic in flight, or answer it from a mock without dialling the origin (map local). Path and query replacements use one find=&gt;replace per line. Request and response body rewrites are find/replace with an optional maxBytes cap. Rules are runtime-only and lost on restart unless you save again. Empty hosts matches any host. Empty methods matches any method. Empty path prefix matches any path. The last matching mock wins. This form saves one rule; save again to replace the list.</p>
    <div class="c-line">
      <input id="hr-hosts" type="text" spellcheck="false" autocomplete="off"
             placeholder="Hosts, comma-separated (empty = any)" aria-label="Hosts">
      <input id="hr-methods" type="text" spellcheck="false" autocomplete="off"
             placeholder="Methods, comma-separated (empty = any)" aria-label="Methods">
      <input id="hr-path" type="text" spellcheck="false" autocomplete="off"
             placeholder="Path prefix (empty = any)" aria-label="Path prefix">
      <input id="hr-mock-status" type="number" min="100" max="599" step="1" value="200"
             aria-label="Mock status" title="HTTP status for the mock response">
    </div>
    <label class="c-label" for="hr-headers">Mock response headers, one per line, as Name: value</label>
    <textarea id="hr-headers" spellcheck="false" placeholder="content-type: application/json"></textarea>
    <label class="c-label" for="hr-body">Mock body</label>
    <textarea id="hr-body" spellcheck="false" placeholder="{&quot;ok&quot;: true}"></textarea>
    <div class="c-line">
      <input id="hr-body-file" type="text" spellcheck="false" autocomplete="off"
             placeholder="Optional body file path (wins over body when readable)" aria-label="Body file path">
    </div>
    <label class="c-label" for="hr-path-repl">Path replacements, one find=&gt;replace per line</label>
    <textarea id="hr-path-repl" spellcheck="false" placeholder="/v1/=&gt;/v2/"></textarea>
    <label class="c-label" for="hr-query-repl">Query replacements, one find=&gt;replace per line</label>
    <textarea id="hr-query-repl" spellcheck="false" placeholder="debug=1=&gt;debug=0"></textarea>
    <label class="c-label" for="hr-req-body-find">Request body find / replace</label>
    <div class="c-line">
      <input id="hr-req-body-find" type="text" spellcheck="false" autocomplete="off"
             placeholder="Find" aria-label="Request body find">
      <input id="hr-req-body-replace" type="text" spellcheck="false" autocomplete="off"
             placeholder="Replace" aria-label="Request body replace">
      <input id="hr-req-body-max" type="number" min="1" step="1"
             placeholder="maxBytes" aria-label="Request body max bytes"
             title="Optional: only rewrite request bodies up to this many bytes">
    </div>
    <label class="c-label" for="hr-res-body-find">Response body find / replace</label>
    <div class="c-line">
      <input id="hr-res-body-find" type="text" spellcheck="false" autocomplete="off"
             placeholder="Find" aria-label="Response body find">
      <input id="hr-res-body-replace" type="text" spellcheck="false" autocomplete="off"
             placeholder="Replace" aria-label="Response body replace">
      <input id="hr-res-body-max" type="number" min="1" step="1"
             placeholder="maxBytes" aria-label="Response body max bytes"
             title="Optional: only rewrite response bodies up to this many bytes">
    </div>
    <div class="c-line">
      <button id="hr-save" class="btn" type="button">Save rules</button>
      <button id="hr-clear" class="btn" type="button">Clear all rules</button>
    </div>
    <p id="hr-status" class="hint"></p>
    <div id="hr-list"></div>
  </section>
  <section id="archiver" hidden>
    <div class="c-line">
      <button id="a-refresh" class="btn" type="button">Refresh</button>
      <span id="a-dropped" class="hint" hidden></span>
    </div>
    <p id="a-status" class="hint"></p>
    <div id="a-body"></div>
  </section>
</main>
"#;

const CSS: &str = r#"
*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }
/* Anything meant to be clicked rather than read: clicking a fold open and shut
   a few times otherwise selects its label, and the selection sits there
   looking like state the page is keeping. Captured text is left selectable,
   because copying it out is the whole point of the page. */
.shelf, .gline, .sitem, .chip, .tab, .icon, .star, .kill, .twist {
  user-select: none; -webkit-user-select: none;
}
/* Every colour on this page is named here and nowhere else, and each name
   carries both schemes at once. Writing them as one pair per line is what keeps
   the two in step: a colour added to one of them cannot be forgotten in the
   other, because there is nowhere else to put it. Which half is used follows
   the machine, until the switch in the header says otherwise. */
:root {
  color-scheme: light dark;
  --bg: light-dark(#faf9f5, #262624);
  --card: light-dark(#f0eee6, #30302e);
  --line: light-dark(#e2dfd4, #3d3d3a);
  --hover: light-dark(#eeece3, #333331);
  --ink: light-dark(#1f1e1d, #f0eee6);
  /* Strongest text: pure white on dark (base URL host/path). Dark near-black on light. */
  --bright: light-dark(#141413, #ffffff);
  --dim: light-dark(#73716a, #a09d94);
  --accent: light-dark(#c96442, #d97757);
  --good: light-dark(#3d7f56, #7bc08d);
  --warn: light-dark(#a06c11, #e0b054);
  --bad: light-dark(#b3392c, #e58a7a);
  --info: light-dark(#2f6f8f, #86bcd8);
  --field: light-dark(#ffffff, #1f1f1e);
  --rule: light-dark(#edeae0, #302f2d);
  --pick: light-dark(#f7e8e2, #3b2f2a);
  --btn: light-dark(#ffffff, #3a3a37);
  --btn-line: light-dark(#ddd9cd, #4b4b47);
  --btn-hover: light-dark(#f2f0e8, #454541);
  --err-line: light-dark(#e6c3bb, #6b3a30);
  --err-bg: light-dark(#fbeeea, #2a1c18);
  --err-ink: light-dark(#7a2f24, #f0c9c0);
  --pin-ink: light-dark(#33260a, #2a1d05);
  --mock-ink: light-dark(#0e2a38, #0a2030);
  --mock-line: light-dark(#b8d4e4, #2f4d5e);
  --mock-bg: light-dark(#eaf4f9, #1a2830);
  --mock-title: light-dark(#1f5a75, #86bcd8);
}
:root[data-theme="light"] { color-scheme: light; }
:root[data-theme="dark"] { color-scheme: dark; }
html, body { height: 100%; }
body {
  margin: 0; display: flex; flex-direction: column;
  background: var(--bg); color: var(--ink);
  font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  -webkit-font-smoothing: antialiased;
}
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
header {
  flex: none; display: flex; align-items: center; gap: 10px;
  padding: 7px 12px; background: var(--card); border-bottom: 1px solid var(--line);
}
.mark { font-size: 11px; letter-spacing: .18em; font-weight: 700; color: var(--accent); }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--dim); }
.dot.live { background: var(--good); }
.dot.gone { background: var(--bad); }
.state { color: var(--dim); font-size: 12px; min-width: 6.5rem; }
#filter {
  flex: 1; min-width: 0; height: 28px; padding: 0 9px;
  background: var(--field); color: var(--ink);
  border: 1px solid var(--line); border-radius: 7px; font: inherit;
}
#filter:focus { outline: none; border-color: var(--accent); }
.count { color: var(--dim); font-size: 12px; white-space: nowrap; }
.btn {
  height: 28px; padding: 0 11px; display: inline-flex; align-items: center;
  background: var(--btn); color: var(--ink); border: 1px solid var(--btn-line);
  border-radius: 7px; font: inherit; text-decoration: none; cursor: default;
  white-space: nowrap;
}
.btn:hover { background: var(--btn-hover); }
/* The tree stands beside both panes, and the request sits under the list it
   was picked from rather than off to one side of it: header lines and bodies
   are wide things, and a column beside the list is not. Width is a choice,
   not a constant: the edge can be dragged, and --tree-w is what remembers. */
main {
  flex: 1; min-height: 0; display: grid;
  --tree-w: 15rem;
  grid-template-columns: var(--tree-w) minmax(0, 1fr);
  grid-template-rows: minmax(0, 1.1fr) minmax(0, 1fr);
}
#tree { grid-column: 1; grid-row: 1 / span 2; }
#list { grid-column: 2; grid-row: 1; }
#detail { grid-column: 2; grid-row: 2; }
/* The tree is a filter, not a view: hiding it gives its width back to the two
   panes that were always here. */
main.flat { grid-template-columns: minmax(0, 1fr); }
main.flat > #tree { display: none; }
main.flat > #list, main.flat > #detail { grid-column: 1; }
#list { display: flex; flex-direction: column; min-height: 0; border-bottom: 1px solid var(--line); }
#rows { flex: 1; overflow: auto; }
#detail { overflow: auto; padding: 12px 14px 40px; min-height: 0; }
/* Composing takes the list and the pane under it, and leaves the tree alone: a
   saved request is opened from that tree, and covering it would put away the
   thing being picked from. Breakpoints, WS rewrite, HTTP rewrite and archive
   stats use the same seat. */
main.composing, main.breaking, main.rewriting, main.httprewriting, main.archiving {
  grid-template-rows: minmax(0, 1fr);
}
main.composing > #list, main.composing > #detail,
main.breaking > #list, main.breaking > #detail,
main.rewriting > #list, main.rewriting > #detail,
main.httprewriting > #list, main.httprewriting > #detail,
main.archiving > #list, main.archiving > #detail { display: none; }
main.composing > #composer { grid-column: 2; grid-row: 1; }
main.composing.flat > #composer { grid-column: 1; }
main.breaking > #breaker { grid-column: 2; grid-row: 1; }
main.breaking.flat > #breaker { grid-column: 1; }
main.rewriting > #rewriter { grid-column: 2; grid-row: 1; }
main.rewriting.flat > #rewriter { grid-column: 1; }
main.httprewriting > #httprewriter { grid-column: 2; grid-row: 1; }
main.httprewriting.flat > #httprewriter { grid-column: 1; }
main.archiving > #archiver { grid-column: 2; grid-row: 1; }
main.archiving.flat > #archiver { grid-column: 1; }
#composer, #breaker, #rewriter, #httprewriter, #archiver {
  overflow: auto; min-height: 0; padding: 12px 14px 40px;
  display: flex; flex-direction: column; gap: 8px;
}
/* Composer: method/url keep a little inset; folds go edge-to-edge so headers
   and body use the full pane width instead of a default-sized textarea island. */
#composer {
  padding: 8px 0 20px; gap: 0;
}
#composer > .c-line {
  padding: 4px 10px 6px; gap: 8px;
}
.c-line { display: flex; gap: 8px; flex-wrap: wrap; }
/* Coloured URL: a mirror of spans sits under a transparent input so the caret
   and edits stay on a real field while scheme/host/path/query paint in colour. */
.url-field {
  flex: 1; min-width: 0; display: grid; position: relative;
  background: var(--field); border: 1px solid var(--line); border-radius: 7px;
}
.url-field:focus-within {
  outline: 1px solid var(--accent); border-color: var(--accent);
}
.url-field > .url-mirror,
.url-field > #c-url {
  grid-area: 1 / 1; min-width: 0; width: 100%; box-sizing: border-box;
  margin: 0; padding: 5px 9px; border: none; border-radius: 7px;
  font: inherit; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  line-height: 1.45; white-space: pre; overflow: hidden;
}
.url-field > .url-mirror {
  pointer-events: none; color: var(--ink); background: transparent;
  /* Keep one line; scrollLeft is synced from the input. */
  overflow-x: hidden; overflow-y: hidden;
}
.url-field > #c-url {
  position: relative; z-index: 1;
  color: transparent; -webkit-text-fill-color: transparent;
  caret-color: var(--ink); background: transparent; outline: none;
}
.url-field > #c-url::placeholder {
  color: var(--dim); -webkit-text-fill-color: var(--dim); opacity: 1;
}
/* Token colours for coloured URLs: composer mirror, detail head, list path.
   Base URL (host + path) is the whitest; query keys/values keep colour. */
.url-mirror .u-scheme, .durl .u-scheme, .row .path .u-scheme { color: var(--dim); }
.url-mirror .u-sep, .durl .u-sep, .row .path .u-sep { color: var(--dim); }
.url-mirror .u-user, .durl .u-user, .row .path .u-user { color: var(--warn); }
.url-mirror .u-host, .durl .u-host, .row .path .u-host {
  color: var(--bright); font-weight: 600;
}
.url-mirror .u-port, .durl .u-port, .row .path .u-port { color: var(--dim); }
.url-mirror .u-path, .durl .u-path, .row .path .u-path { color: var(--bright); }
.url-mirror .u-key, .durl .u-key, .row .path .u-key { color: var(--info); }
.url-mirror .u-val, .durl .u-val, .row .path .u-val { color: var(--good); }
.url-mirror .u-frag, .durl .u-frag, .row .path .u-frag { color: var(--warn); }
.url-mirror .u-var, .durl .u-var, .row .path .u-var { color: var(--warn); }
/* Query key+value pair: hover or click selects both ends together. */
.u-pair {
  border-radius: 3px; cursor: default;
  padding: 0 1px; margin: 0 -1px;
}
.u-pair:hover { background: var(--hover); }
.u-pair.on {
  background: var(--pick);
  box-shadow: inset 0 -1px 0 var(--accent);
}
/* Composer folds: full-bleed under the URL row. Bar on --card with accent
   titles; editor body on --field so header and inputs are two clear layers. */
.c-fold {
  display: flex; flex-direction: column; gap: 0;
  margin: 0; background: var(--field);
  border: none; border-top: 1px solid var(--line); border-radius: 0;
  overflow: hidden;
}
.c-fold-bar {
  display: flex; align-items: center; gap: 8px; width: 100%;
  margin: 0; padding: 7px 12px; cursor: default; text-align: left;
  background: var(--card); border: none; border-bottom: 1px solid var(--line);
  color: var(--ink); font: inherit;
}
.c-fold-bar:hover { background: var(--hover); }
/* Same language as .shelf-name / .shelf > .twist in the tree column. */
.c-fold-bar .twist { flex: none; font-size: 10px; color: var(--dim); width: 0.9rem; }
.c-fold-name {
  flex: none; color: var(--dim); font-size: 11px; font-weight: 600;
  letter-spacing: .06em; text-transform: uppercase;
}
.c-fold-meta {
  flex: 1; min-width: 0; color: var(--dim); font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: right;
}
.c-fold-body {
  display: flex; flex-direction: column; gap: 0; padding: 0; min-width: 0;
  background: var(--field);
}
.c-fold.shut > .c-fold-body { display: none; }
.c-fold.shut > .c-fold-bar { border-bottom: none; }
/* Query params table: Postman-style key/value rows that rewrite the URL query. */
.c-params-hint { margin: 0; padding: 6px 12px; font-size: 12px; color: var(--dim); background: var(--field); }
.c-params {
  width: 100%; border-collapse: collapse; font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  background: var(--field); border: none; border-top: 1px solid var(--line);
  border-radius: 0; table-layout: fixed;
}
.c-params th, .c-params td {
  text-align: left; padding: 0; border-bottom: 1px solid var(--rule);
  vertical-align: middle;
}
.c-params tr:last-child td { border-bottom: none; }
.c-params th {
  color: var(--info); font-size: 11px; font-weight: 700;
  letter-spacing: .04em; text-transform: uppercase; white-space: nowrap;
  padding: 6px 10px; background: var(--bg);
}
.c-params th.c-params-on, .c-params td.c-params-on { width: 2.6rem; text-align: center; padding: 0 4px; }
.c-params th.c-params-drop, .c-params td.c-params-drop { width: 2.2rem; text-align: center; padding: 0 4px; }
.c-params td input[type="text"] {
  width: 100%; box-sizing: border-box; margin: 0; min-height: 32px;
  background: var(--field); color: var(--ink); border: none; border-radius: 0;
  padding: 7px 10px; font: inherit;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.c-params td input[type="text"]:focus {
  outline: none; background: var(--bg); box-shadow: inset 0 0 0 1px var(--accent);
}
.c-params td input[type="text"]::placeholder { color: var(--dim); opacity: 1; }
.c-params td input[type="checkbox"] { margin: 0; width: 14px; height: 14px; cursor: default; accent-color: var(--accent); }
.c-params .c-params-x {
  height: 26px; width: 26px; padding: 0; border: none; border-radius: 6px;
  background: none; color: var(--dim); font: inherit; font-size: 16px; line-height: 1; cursor: default;
}
.c-params .c-params-x:hover { color: var(--bad); background: var(--hover); }
.c-params tr.off td input[type="text"] { color: var(--dim); background: var(--bg); }
/* Hover or focus on a param row lights key and value together. */
.c-params tbody tr:hover td { background: var(--hover); }
.c-params tbody tr:hover td input[type="text"] { background: var(--hover); }
.c-params tbody tr:focus-within td,
.c-params tbody tr.on td { background: var(--pick); }
.c-params tbody tr:focus-within td input[type="text"],
.c-params tbody tr.on td input[type="text"] { background: var(--pick); }
.c-params tbody tr:focus-within td input[type="text"]:focus {
  background: var(--bg); box-shadow: inset 0 0 0 1px var(--accent);
}
.c-params tbody tr.off:hover td input[type="text"],
.c-params tbody tr.off:focus-within td input[type="text"],
.c-params tbody tr.off.on td input[type="text"] { color: var(--dim); }
/* Read-only query breakdown on a captured request (Request tab). */
.qparams { margin: 0 0 12px; }
.qparams .headers {
  margin-top: 4px;
  display: flex; flex-direction: column; gap: 1px;
}
/* Real rows (not display:contents) so hover/select can paint key+value as one. */
.qparams .hrow {
  display: grid;
  grid-template-columns: minmax(0, auto) minmax(0, 1fr);
  gap: 1px 10px;
  padding: 3px 6px; margin: 0 -6px; border-radius: 5px;
  cursor: default;
}
.qparams .hrow:hover { background: var(--hover); }
.qparams .hrow.on {
  background: var(--pick);
  box-shadow: inset 2px 0 0 var(--accent);
}
.qparams .hname { color: var(--info); }
.qparams .hval { color: var(--good); }
#composer select, #composer input, #composer textarea,
#breaker select, #breaker input, #breaker textarea,
#rewriter select, #rewriter input, #rewriter textarea,
#httprewriter select, #httprewriter input, #httprewriter textarea {
  background: var(--field); color: var(--ink); border: 1px solid var(--line);
  border-radius: 7px; padding: 5px 9px; font: inherit;
}
/* Method / name / book row: sit on the page bg so the field chips read clearly. */
#composer > .c-line select, #composer > .c-line input {
  background: var(--field); color: var(--ink); border-color: var(--line);
}
/* Fold editors span the pane: no default textarea island, no double chrome. */
#composer .c-fold textarea {
  display: block; width: 100%; min-width: 0; box-sizing: border-box;
  margin: 0; border: none; border-top: 1px solid var(--line); border-radius: 0;
  min-height: 7.5rem; resize: vertical;
  background: var(--field); color: var(--ink);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
#composer .c-fold textarea::placeholder { color: var(--dim); opacity: 1; }
#composer .c-fold .c-label {
  padding: 6px 12px 2px; margin: 0; color: var(--info);
  background: var(--field);
}
#composer .c-fold #c-out {
  padding: 10px 12px 14px; min-width: 0;
  background: var(--field); color: var(--ink);
}
/* The URL field owns its own chrome (see .url-field); skip the shared input chrome. */
#composer .url-field > #c-url {
  background: transparent; color: transparent; border: none; border-radius: 7px;
  padding: 5px 9px;
}
#composer select:focus, #composer input:focus, #composer textarea:focus,
#breaker select:focus, #breaker input:focus, #breaker textarea:focus,
#rewriter select:focus, #rewriter input:focus, #rewriter textarea:focus,
#httprewriter select:focus, #httprewriter input:focus, #httprewriter textarea:focus {
  outline: 1px solid var(--accent); border-color: var(--accent);
}
#composer .c-fold textarea:focus {
  outline: none; background: var(--bg);
  box-shadow: inset 0 0 0 1px var(--accent);
}
#composer .url-field > #c-url:focus {
  outline: none; border: none;
}
/* Param cells skip the shared composer input chrome (border/padding). */
#composer .c-params td input[type="text"] {
  background: var(--field); border: none; border-radius: 0; padding: 7px 10px;
}
#composer .c-params td input[type="text"]:focus {
  outline: none; border: none; background: var(--bg);
  box-shadow: inset 0 0 0 1px var(--accent);
}
/* Archive stats: canned report tables from GET /api/archive/stats. */
.a-section { margin-bottom: 14px; }
.a-section h2 {
  margin: 0 0 6px; color: var(--dim); font-size: 11px; font-weight: 600;
  letter-spacing: .06em; text-transform: uppercase;
}
.a-table {
  width: 100%; border-collapse: collapse; font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.a-table th, .a-table td {
  text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--rule);
  vertical-align: top; word-break: break-all;
}
.a-table th {
  color: var(--dim); font-size: 11px; font-weight: 600;
  letter-spacing: .04em; text-transform: uppercase; white-space: nowrap;
}
.a-table tr:hover td { background: var(--hover); }
.a-totals {
  display: flex; flex-wrap: wrap; gap: 8px 16px; margin: 0 0 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
}
.a-totals .a-metric { display: flex; flex-direction: column; gap: 2px; min-width: 5.5rem; }
.a-totals .a-label { color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
.a-totals .a-value { color: var(--ink); }
#composer textarea, #httprewriter textarea { min-height: 92px; resize: vertical; }
#httprewriter #hr-path-repl, #httprewriter #hr-query-repl { min-height: 56px; }
#b-hosts, #b-path, #b-methods, #w-hosts, #w-path, #w-regex, #w-replace,
#hr-hosts, #hr-methods, #hr-path, #hr-body-file,
#hr-req-body-find, #hr-req-body-replace, #hr-res-body-find, #hr-res-body-replace {
  flex: 1; min-width: 8rem;
}
#b-timeout { width: 7.5rem; }
#hr-mock-status { width: 5.5rem; }
#hr-req-body-max, #hr-res-body-max { width: 7rem; }
#b-kind, #b-http-half { min-width: 7rem; }
.b-check { display: inline-flex; align-items: center; gap: 6px; color: var(--ink); white-space: nowrap; }
.c-label {
  color: var(--dim); font-size: 11px; letter-spacing: .06em; text-transform: uppercase;
}
.btn.on { border-color: var(--accent); color: var(--accent); }
/* Held frames sit under the header so a timeout cannot hide behind a tab. */
.pauses {
  flex: none; max-height: 42%; overflow: auto;
  display: flex; flex-direction: column; gap: 8px;
  padding: 8px 12px; background: var(--err-bg); border-bottom: 1px solid var(--err-line);
}
.pause {
  display: flex; flex-direction: column; gap: 8px;
  padding: 10px 11px; background: var(--field); border: 1px solid var(--err-line); border-radius: 8px;
}
.pause .p-head {
  display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: baseline;
}
.pause .p-meta { color: var(--dim); font-size: 12px; }
.pause .p-flow {
  background: none; border: none; padding: 0; color: var(--accent);
  font: inherit; cursor: default; text-decoration: underline;
}
.pause .p-flow:hover { color: var(--ink); }
.pause .p-payload, .pause .p-headers {
  width: 100%; min-height: 56px; resize: vertical;
  background: var(--bg); color: var(--ink); border: 1px solid var(--line);
  border-radius: 7px; padding: 5px 9px; font: inherit;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.pause .p-headers { min-height: 48px; }
.pause .p-payload:focus, .pause .p-headers:focus {
  outline: 1px solid var(--accent); border-color: var(--accent);
}
.pause .p-line {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
}
.pause .p-field {
  background: var(--bg); color: var(--ink); border: 1px solid var(--line);
  border-radius: 7px; padding: 5px 9px; font: inherit;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.pause .p-field:focus { outline: 1px solid var(--accent); border-color: var(--accent); }
.pause .p-method { width: 6.5rem; }
.pause .p-url { flex: 1; min-width: 10rem; }
.pause .p-code { width: 5rem; }
.pause .p-actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.pause .p-status { margin: 0; color: var(--dim); font-size: 12px; }
.rule {
  display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: baseline;
  padding: 8px 10px; background: var(--field); border: 1px solid var(--line); border-radius: 8px;
  font-size: 12px;
}
.rule .off { color: var(--dim); }
.rule .on { color: var(--good); }
.head, .row {
  display: grid; align-items: baseline; gap: 10px; padding: 3px 12px;
  grid-template-columns: 4rem minmax(4rem, 11rem) minmax(0, 1fr) 4rem 4.6rem 4.4rem;
}
.head {
  flex: none; color: var(--dim); font-size: 11px; letter-spacing: .06em;
  text-transform: uppercase; border-bottom: 1px solid var(--line); padding-block: 6px;
}
/* The tree takes a column off the list, so the headings have to give way the
   same way the cells under them already do. */
.head span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.row {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px; cursor: default; border-bottom: 1px solid var(--rule);
}
.row:hover { background: var(--hover); }
.row.on { background: var(--pick); }
.row.pinned { box-shadow: inset 3px 0 0 var(--warn); }
/* Clip at the cell, not each nested token (path is painted as u-* spans). */
.row > span, .row .hostname, .row .status {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row .path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.row .path > span { overflow: visible; text-overflow: clip; }
.row .method { font-weight: 700; color: var(--accent); }
.row .method.m-GET, .row .method.m-HEAD, .row .method.m-OPTIONS { color: var(--good); }
.row .method.m-POST { color: var(--info); }
.row .method.m-PUT, .row .method.m-PATCH { color: var(--warn); }
.row .method.m-DELETE { color: var(--bad); }
.row .host { display: flex; gap: 6px; align-items: baseline; min-width: 0; }
.row .hostname { min-width: 0; color: var(--bright); font-weight: 600; }
.pin {
  flex: none; display: inline-block; padding: 0 4px; border-radius: 3px;
  background: var(--warn); color: var(--pin-ink); font-size: 10px; font-weight: 700;
}
/* Status column holds the code and, when map-local, a short mock badge. */
.row .st { display: flex; gap: 4px; align-items: baseline; min-width: 0; }
.row .st .status { min-width: 0; }
.mock {
  flex: none; display: inline-block; padding: 0 3px; border-radius: 3px;
  background: var(--info); color: var(--mock-ink); font-size: 9px; font-weight: 700;
  letter-spacing: .03em; text-transform: lowercase;
}
.size, .dur { color: var(--dim); text-align: right; }
.s2 .status { color: var(--good); }
.s3 .status { color: var(--info); }
.s4 .status { color: var(--warn); }
.s5 .status, .serr .status { color: var(--bad); }
.swait .status { color: var(--dim); }
/* The tree: hosts and the paths under them, as somewhere to click rather than
   as a second list. Picking a branch narrows the list beside it. */
/* Two trees, one column. What came in is above, what was kept is below: they
   are read the same way and neither is worth a pane of its own. */
#tree {
  position: relative;
  min-height: 0; display: flex; flex-direction: column; overflow: hidden;
  border-right: 1px solid var(--line);
}
/* The right edge of the tree is a grip, not a second border: drag it and the
   column grows or shrinks, and the list takes whatever is left. */
#tree-grip {
  position: absolute; top: 0; right: -3px; width: 6px; height: 100%;
  cursor: default; z-index: 3; touch-action: none;
}
#tree-grip:hover, body.tree-sizing #tree-grip {
  background: var(--accent); opacity: 0.35;
}
body.tree-sizing { cursor: default; user-select: none; -webkit-user-select: none; }
/* Both halves carry the same bar and fold away the same way. A folded one
   keeps only its bar, and the space it was using goes to the other. */
.part { display: flex; flex-direction: column; min-height: 0; }
.part.shut > *:not(.shelf) { display: none; }
/* Vertical scroll on the half. The tree is always the panel width: long names
   ellipsis rather than a sticky count rail that painted over the shelf buttons. */
#live {
  flex: 0 1 auto; max-height: 50%; min-height: 0;
  overflow-x: hidden; overflow-y: auto;
}
#saved {
  flex: 1 1 0%; min-height: 0;
  overflow-x: hidden; overflow-y: auto;
  border-top: 1px solid var(--line);
}
#recent {
  flex: 0 1 auto; max-height: 33%; min-height: 0;
  overflow-x: hidden; overflow-y: auto;
  border-top: 1px solid var(--line);
}
/* Folded live is only its shelf (border-bottom). Drop the next part's top edge
   or the two rules stack into a double line under REQUESTS. */
#live.shut + #saved,
#saved.shut + #recent {
  border-top: none;
}
.tree-scroll {
  flex: none;
  width: 100%; max-width: 100%;
  overflow-x: hidden; overflow-y: hidden;
  box-sizing: border-box;
}
/* Written against the ids on purpose: the shares above are set that way too,
   and a class alone loses to them, which leaves a folded half still holding
   the room it was given. Folded halves stack at the top instead. */
#live.shut, #saved.shut, #recent.shut { flex: none; max-height: none; overflow: hidden; }
/* When live is folded, saved may use the rest of the column. Do not expand live
   when saved is folded: that pushed the SAVED REQUESTS bar to the bottom with
   a void under a short host list. */
#tree:has(> #live.shut) > #saved:not(.shut) { flex: 1 1 0%; }
/* Status badge on a Recent row (after the name, before the kill control). */
.smeta {
  flex: none; color: var(--dim); font-size: 11px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
/* Version rows inside the composer fold. */
.vitem {
  display: flex; gap: 8px; align-items: baseline;
  padding: 4px 2px; cursor: default; font-size: 12px;
  border-radius: 5px;
}
.vitem:hover { background: var(--hover); }
.vwhen {
  flex: none; width: 3.2rem; color: var(--dim);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px;
}
.vname {
  flex: 1 1 auto; min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
/* Panel-wide content. --d tracks nest depth so indented rows still span the
   full right edge (count column stays put while the name indents). */
#hosts {
  --d: 0px;
  padding: 4px 0 12px;
  width: 100%;
  box-sizing: border-box;
}
/* Devices sit above the hosts because they are the coarser cut: which machine,
   then which of its hosts. One device is the usual case, and one chip that
   says so is small enough to leave alone. */
#devices {
  flex: none; display: flex; flex-wrap: wrap; gap: 4px; padding: 6px 8px;
  border-bottom: 1px solid var(--rule);
}
#devices:empty { display: none; }
.chip {
  padding: 2px 8px; cursor: default; white-space: nowrap;
  background: none; border: 1px solid var(--btn-line); border-radius: 20px;
  color: var(--dim); font: inherit; font-size: 11px;
}
.chip:hover { background: var(--hover); color: var(--ink); }
.chip.on { background: var(--pick); border-color: var(--accent); color: var(--accent); }
/* Keep-pin in the count rail. Star only on digit hover (or kept); replaces the
   number. Colours as before: dim until kept, then accent — not yellow. */
.gpin {
  position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
  z-index: 1;
  box-sizing: border-box;
  min-width: 2.25rem; min-height: 1.2em;
  display: flex; align-items: center; justify-content: flex-end;
}
.gpin > .gcount {
  position: static; right: auto; top: auto; transform: none;
}
.star {
  position: absolute; right: 0; top: 50%; transform: translateY(-50%);
  box-sizing: border-box;
  min-width: 2.25rem;
  visibility: hidden; padding: 0; margin: 0; cursor: default;
  background: none; border: none; color: var(--dim); font: inherit; font-size: 12px;
  line-height: 1.2; text-align: right;
}
.gpin:hover > .star { visibility: visible; color: var(--dim); }
.star.on { visibility: visible; color: var(--accent); }
.gpin:hover > .gcount,
.gpin:has(> .star.on) > .gcount { visibility: hidden; }
#books {
  --d: 0px;
  padding: 2px 0 12px;
  width: 100%;
  box-sizing: border-box;
}
/* Above row chrome: a scrolled host must not cover hunt/sift.
   Fixed height so REQUESTS and SAVED REQUESTS bars match (2 vs 3 icons used to
   look uneven when line-box metrics differed). */
.shelf {
  position: sticky; top: 0; left: 0; z-index: 5;
  flex: none; display: flex; align-items: center; gap: 6px; cursor: default;
  box-sizing: border-box;
  height: 32px; min-height: 32px; max-height: 32px;
  padding: 0 6px 0 8px;
  border-bottom: 1px solid var(--rule);
  background: var(--bg);
  width: 100%;
  min-width: 100%;
}
.shelf:hover { background: var(--hover); }
.shelf > .twist {
  flex: none; width: 1.15rem; font-size: 10px; line-height: 1;
  display: inline-flex; align-items: center; justify-content: center;
}
.shelf .icon {
  flex: none; box-sizing: border-box;
  width: 22px; height: 22px; min-width: 22px; min-height: 22px;
  font-size: 13px; line-height: 1; padding: 0;
}
.hunt {
  flex: none; margin: 5px 8px 3px; height: 24px; padding: 0 8px;
  background: var(--field); color: var(--ink);
  border: 1px solid var(--line); border-radius: 7px; font: inherit; font-size: 12px;
}
.hunt:focus { outline: none; border-color: var(--accent); }
.shelf-name {
  flex: 1; min-width: 0; color: var(--dim); font-size: 11px; line-height: 1;
  letter-spacing: .06em; text-transform: uppercase;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.pad { margin: 0; padding: 10px 12px; font-size: 12px; }
.sitem {
  position: relative; display: flex; gap: 6px; align-items: baseline;
  padding: 3px 8px 3px 12px; cursor: default; font-size: 12px;
  width: 100%; box-sizing: border-box; min-width: 0;
}
.sitem:hover { background: var(--hover); }
.smethod {
  flex: none; width: 3.2rem; color: var(--dim);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px;
}
.sname {
  flex: 1 1 auto; min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
/* Delete sits on top of the trailing text so rows do not reserve a kill column.
   Hidden with opacity (not visibility) so the layout never pays for the control. */
.kill {
  position: absolute; right: 2px; top: 50%; transform: translateY(-50%);
  z-index: 2; width: 1.35rem; height: 1.35rem; padding: 0;
  display: inline-flex; align-items: center; justify-content: center;
  opacity: 0; pointer-events: none; cursor: default;
  background: var(--hover); border: none; border-radius: 5px;
  color: var(--dim); font: inherit; font-size: 13px; line-height: 1;
  /* Soft edge so text under the mark still reads until hover. */
  box-shadow: -8px 0 8px var(--hover);
}
.kill:hover { color: var(--bad); background: var(--card); }
.sitem:hover .kill, .gline:hover .kill {
  opacity: 1; pointer-events: auto;
}
/* Collection rows also use .kill; gline is position:relative below. */
/* Live rows drag into a collection via pointer drag (not HTML5 DnD: that
   forces a system grab hand we cannot style away). Arrow cursor throughout. */
.row.dragging, .durl.dragging { opacity: .55; pointer-events: none; }
body.row-dragging, body.row-dragging * { cursor: default !important; }
body.row-dragging { user-select: none; -webkit-user-select: none; }
.group.drop-over > .gline,
#saved.drop-over > .shelf,
.live-drop.drop-over > .gline,
.live-drop.drop-over.shelf {
  background: var(--pick);
  box-shadow: inset 2px 0 0 var(--accent);
}
/* Full panel width at every depth (--d undoes gbody indent). Count is absolute
   against that shared right edge so 1, 26 and 380 end on one vertical line. */
.gline {
  position: relative;
  display: flex;
  align-items: baseline;
  gap: 4px;
  box-sizing: border-box;
  width: calc(100% + var(--d));
  margin-left: calc(0px - var(--d));
  padding: 3px 2.5rem 3px calc(4px + var(--d));
  cursor: default; border-radius: 0 6px 6px 0;
}
.gline:hover { background: var(--hover); }
.gline.picked { background: var(--pick); box-shadow: inset 2px 0 0 var(--accent); }
.twist {
  flex: none; width: 1.15rem; color: var(--dim); text-align: center;
  cursor: default; line-height: 1.4;
}
.gname {
  flex: 1 1 auto; min-width: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
  color: var(--dim);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.group.host > .gline > .gname { color: var(--ink); }
/* Absolute rail on the row's right edge. Monospace + tabular-nums. */
.gcount {
  position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
  box-sizing: border-box;
  min-width: 2.25rem;
  padding: 0;
  color: var(--dim); font-size: 11px; line-height: 1.2;
  white-space: nowrap; text-align: right;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-variant-numeric: tabular-nums;
  font-feature-settings: "tnum";
}
.gline.picked > .gname, .gline.picked > .gcount { color: var(--accent); }
/* Indent the branch; --d grows so child .gline can span back to the full edge. */
.gbody {
  --d: calc(var(--d) + 11px);
  margin-left: 11px; border-left: 1px solid var(--rule);
}
.group.shut > .gbody { display: none; }
#scope {
  display: flex; gap: 6px; align-items: baseline; padding: 5px 10px;
  color: var(--dim); font-size: 12px; border-bottom: 1px solid var(--line);
}
#scope button {
  background: none; border: none; padding: 0; margin: 0; cursor: default;
  color: var(--accent); font: inherit;
}
#scope.idle { display: none; }
#empty { flex: none; margin: 0; padding: 22px 14px; color: var(--dim); }
.hint { color: var(--dim); }
.dhead { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.icon {
  flex: none; width: 26px; height: 26px; padding: 0; cursor: default;
  display: inline-flex; align-items: center; justify-content: center;
  background: var(--btn); color: var(--dim); border: 1px solid var(--btn-line);
  border-radius: 7px; font: inherit; font-size: 14px; line-height: 1;
}
.icon:hover { background: var(--btn-hover); color: var(--ink); }
.icon.caret { width: 18px; font-size: 10px; }
.icon.on { border-color: var(--accent); color: var(--accent); }
/* Not the same thing as an open menu: this one says the menu was used. */
.icon.set { border-color: var(--accent); color: var(--accent); }
/* Subtle active structured-filter count on the live sift control. */
#sift-live[data-count] { position: relative; }
#sift-live[data-count]::after {
  content: attr(data-count);
  position: absolute; top: -4px; right: -5px; min-width: 12px; height: 12px;
  padding: 0 3px; border-radius: 6px; background: var(--accent); color: var(--card);
  font-size: 9px; font-weight: 700; line-height: 12px; text-align: center;
}
/* The menu hangs off the pair of buttons, so they are what it is measured
   from. No shadow: nothing else on this page is raised, and a border against
   the card colour is enough to read as in front. */
/* One control with a seam down it rather than two buttons side by side: the
   arrow belongs to the mark it stands next to. The halves overlap by the width
   of a border so the seam is one line, and whichever half is under the pointer
   comes forward so its own border is the one that shows. */
.copybar { position: relative; display: inline-flex; }
.copybar > .icon { position: relative; border-radius: 0; }
.copybar > .icon:first-child { border-radius: 7px 0 0 7px; }
.copybar > .caret { border-radius: 0 7px 7px 0; margin-left: -1px; }
.copybar > .icon:hover, .copybar > .icon.on { z-index: 1; }
.menu {
  position: absolute; top: calc(100% + 4px); left: 0; z-index: 5;
  display: flex; flex-direction: column; min-width: 13rem; padding: 4px;
  background: var(--card); border: 1px solid var(--line); border-radius: 9px;
}
.mitem {
  padding: 5px 9px; text-align: left; white-space: nowrap; cursor: default;
  background: none; border: none; border-radius: 6px; color: var(--ink); font: inherit;
}
.mitem:hover { background: var(--hover); }
/* The same menu, hung off a button that sits at the right edge of a narrow
   column: measured from that edge instead, or most of it would be off the
   side of the tree it belongs to. */
.sift {
  position: relative; display: inline-flex; align-items: center;
  flex: none; line-height: 0;
}
.sift > .menu { left: auto; right: 0; }
.mhead {
  padding: 5px 9px 2px; color: var(--dim); font-size: 11px;
  letter-spacing: .06em; text-transform: uppercase;
}
.mband { display: flex; flex-direction: column; }
.mitem .tick { display: inline-block; width: 1.1rem; color: var(--accent); }
.dmethod { font-weight: 700; color: var(--accent); }
.durl { word-break: break-all; font-size: 12px; }
.facts { display: grid; grid-template-columns: 7.5rem minmax(0, 1fr); gap: 2px 10px; margin-bottom: 14px; }
.fkey { color: var(--dim); }
.fval { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; word-break: break-all; }
/* Clickable connection id: filter the list to sibling streams on the same
   multiplex session (H2 TLS or H3 QUIC). Same shape for both protocols. */
button.flink {
  display: inline; margin: 0; padding: 0; border: 0; background: transparent;
  color: var(--accent); cursor: default; text-align: left;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px; word-break: break-all;
}
button.flink:hover { text-decoration: underline; }
.block { margin-bottom: 16px; }
.block h2 {
  font-size: 11px; letter-spacing: .08em; text-transform: uppercase;
  color: var(--dim); margin: 0 0 6px; font-weight: 600;
}
.headers { display: grid; grid-template-columns: minmax(0, auto) minmax(0, 1fr); gap: 1px 10px; font-size: 12px; }
.hrow { display: contents; }
.hname { color: var(--accent); word-break: break-all; }
.hval { word-break: break-all; }
.none { color: var(--dim); margin: 0; }
.note { color: var(--dim); margin: 0 0 6px; }
pre.body, pre.copy {
  margin: 8px 0 0; padding: 9px 11px; max-height: 26rem; overflow: auto;
  background: var(--field); border: 1px solid var(--line); border-radius: 8px;
  font-size: 12px; white-space: pre-wrap; word-break: break-word;
}
.error {
  margin: 0 0 14px; padding: 10px 12px; border-radius: 9px;
  border: 1px solid var(--err-line); background: var(--err-bg);
}
.etitle { color: var(--bad); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.error p { margin: 8px 0 0; color: var(--err-ink); }
/* Map-local mock: not an error, but must not be buried under rewrite notes. */
.mock-banner {
  margin: 0 0 14px; padding: 10px 12px; border-radius: 9px;
  border: 1px solid var(--mock-line); background: var(--mock-bg);
}
.mtitle {
  color: var(--mock-title);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px; font-weight: 600;
}
.mock-banner p { margin: 6px 0 0; color: var(--dim); }
/* The switch over the bottom pane. Request and response are the same shape and
   are usually read against each other, so both fitting on one screen is worth
   a mode of its own rather than a second click every time. */
.tabs { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.tab {
  height: 26px; padding: 0 10px; background: none; cursor: default;
  border: 1px solid transparent; border-radius: 7px; color: var(--dim); font: inherit;
}
.tab:hover { background: var(--hover); color: var(--ink); }
.tab.on { background: var(--pick); border-color: var(--accent); color: var(--accent); }
.tabs .gap { flex: 1; min-width: 12px; }
.panes.both { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 0 20px; }
.panes.both > .wide { grid-column: 1 / -1; }
.frame { display: grid; grid-template-columns: 9rem 9rem minmax(0, 1fr) auto; gap: 8px; font-size: 12px; padding: 2px 0; align-items: start; }
.frame .dir { color: var(--dim); }
.frame.up .dir { color: var(--accent); }
.frame .text { word-break: break-all; white-space: pre-wrap; }
.frame .frame-replay {
  height: 22px; width: 22px; padding: 0; flex: none;
  color: var(--dim); border-color: transparent;
}
.frame .frame-replay:hover { color: var(--accent); border-color: var(--line); }
/* Injected frames are real wire traffic, but they did not come from either peer,
   so the list has to say so rather than looking like something the app did. */
.frame.injected .dir::after { content: ' · injected'; color: var(--warn); }
/* Display text/body is inflated (permessage-deflate); size is still the wire length. */
.frame.compressed .dir::after { content: ' · compressed'; color: var(--info); }
.inject {
  display: flex; flex-direction: column; gap: 8px;
  margin: 0 0 12px; padding: 10px 11px;
  background: var(--field); border: 1px solid var(--line); border-radius: 8px;
}
.inject .c-line { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.inject select, .inject input, .inject textarea {
  background: var(--bg); color: var(--ink); border: 1px solid var(--line);
  border-radius: 7px; padding: 5px 9px; font: inherit;
}
.inject select:focus, .inject input:focus, .inject textarea:focus {
  outline: 1px solid var(--accent); border-color: var(--accent);
}
.inject textarea { min-height: 56px; resize: vertical; width: 100%; }
.inject .c-label {
  color: var(--dim); font-size: 11px; letter-spacing: .06em; text-transform: uppercase;
}
.inject .hint { margin: 0; }
/* Frame filters share the inject control language so the Frames tab stays one strip. */
.inject.filters { margin-top: 0; }
.inject.filters input[type="search"], .inject.filters input[type="text"] {
  flex: 1; min-width: 8rem;
}
.inject.replay input[type="text"] { flex: 1; min-width: 10rem; }
.inject.replay input[type="number"] { width: 6.5rem; }
.frame.gap .dir { color: var(--dim); font-style: italic; }
.frame.gap .meta { color: var(--dim); }
/* JSON syntax paint from /api/json/view (themoretheless-tokenizer). Spans only. */
.json .j-property { color: var(--info); }
.json .j-string { color: var(--good); }
.json .j-number { color: var(--accent); }
.json .j-boolean { color: var(--warn); }
.json .j-null { color: var(--dim); }
.json .j-punctuation { color: var(--dim); }
.json .j-comment { color: var(--dim); font-style: italic; }
.json .j-whitespace { }
.json .j-invalid { color: var(--bad); }
pre.json, .text.json {
  white-space: pre-wrap; word-break: break-word;
}
@media (max-width: 1000px) {
  /* The tree is the pane you can do without: the filter box narrows the same
     list without taking a column to do it. */
  main, main.flat { grid-template-columns: minmax(0, 1fr); }
  main > #tree { display: none; }
  main > #list, main > #detail,
  main.composing > #composer, main.breaking > #breaker,
  main.rewriting > #rewriter, main.httprewriting > #httprewriter,
  main.archiving > #archiver { grid-column: 1; }
  .head, .row { grid-template-columns: 3.6rem minmax(4rem, 8rem) minmax(0, 1fr) 3.4rem 4.2rem; }
  .head span:last-child, .row .dur { display: none; }
  /* Two columns of headers at this width are two columns of ellipsis. */
  .panes.both { grid-template-columns: minmax(0, 1fr); }
}
"#;

const SCRIPT: &str = r#"
(function () {
  'use strict';

  var COPY_MARK = '⧉';
  var MAX_ROWS = 2000;
  var MAX_BODY_CHARS = 200000;
  var MAX_FRAMES = 200;
  var RETRY_MIN = 400;
  var RETRY_MAX = 4000;
  // Drag payload and clipboard envelope for live → saved request.
  // Live → collection drag uses pointer events (see wireLiveDragSource), not
  // HTML5 dataTransfer: the system grab cursor cannot be restyled.
  var SAVED_CLIP_TYPE = 'application/x-proxima-saved-request+json';
  var SAVED_CLIP_PREFIX = 'proxima-saved-request:';

  var rowsEl = document.getElementById('rows');
  var treeEl = document.getElementById('hosts');
  var devicesEl = document.getElementById('devices');
  var booksEl = document.getElementById('books');
  var noBooksEl = document.getElementById('no-books');
  var mainEl = document.querySelector('main');
  var viewBtn = document.getElementById('view');
  var scopeEl = document.getElementById('scope');
  var scopeNameEl = document.getElementById('scope-name');
  var detailEl = document.getElementById('detail');
  var filterEl = document.getElementById('filter');
  var countEl = document.getElementById('count');
  var emptyEl = document.getElementById('empty');
  var dotEl = document.getElementById('dot');
  var stateEl = document.getElementById('state');

  var rows = new Map();
  var needles = new Map();
  // The most recent summary for every row, so an arriving event can be compared
  // against what the pane below was actually built from.
  var summaries = new Map();
  var rendered = '';
  var groups = new Map();
  var branches = new Map();
  var homes = new Map();
  var spots = new Map();
  var bads = new Map();
  var seen = new Map();
  var visible = 0;
  var needle = '';
  var scope = '';
  var device = '';
  // What the menus on the two bars are set to. Read back from storage further
  // down, once the functions that act on them exist.
  var liveGroup = 'host';
  // Structured list filters map to FlowQuery (method/status/kind/onlyErrors/
  // onlyMocked). Free-text #filter stays as search: client-side as you type,
  // and on the next server fetch. Live socket rows use the same client predicates.
  var listMethod = '';
  var listStatus = '';
  var listKind = '';
  var onlyErrors = false;
  var onlyMocked = false;
  var bookGroup = 'book';
  var selectedId = null;
  var detailToken = 0;
  var queue = null;
  var greeted = false;
  var backoff = RETRY_MIN;
  var frameList = null;
  var frameOwner = null;
  // Retained window for the selected socket. Filters re-render from this, not
  // from the DOM, so live appends and filter changes stay consistent.
  var frameMessages = [];
  // Absolute index of frameMessages[0] in the source flow ws_messages vector.
  // Live retain shifts the front and bumps this so per-frame replay stays honest.
  var frameIndexBase = 0;
  // Status line under the replay form; per-row replay reuses it when present.
  var replayStatusEl = null;
  // direction: '' | 'send' | 'recv'; opcodes: null | { [code]: true }; query: lowercased needle.
  var frameFilters = { direction: '', opcodes: null, query: '' };
  var side = 'info';
  var paired = false;
  // Held frames keyed by pauseId. The strip under the header is drawn from this
  // map so a reconnect can refill it from GET /api/pauses without inventing state.
  var pauses = new Map();
  var pauseTimer = 0;
  var breakRules = [];

  // Every string that came off the wire enters the document through here, and
  // textContent is why a captured body full of markup stays a captured body
  // full of markup.
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function str(value) {
    if (typeof value === 'string') { return value; }
    if (value === undefined || value === null) { return ''; }
    return String(value);
  }

  function strip(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  function size(bytes) {
    var n = typeof bytes === 'number' && isFinite(bytes) && bytes > 0 ? bytes : 0;
    if (n < 1024) { return n + ' B'; }
    if (n < 1048576) { return (n / 1024).toFixed(1) + ' KB'; }
    return (n / 1048576).toFixed(1) + ' MB';
  }

  function millis(ms) {
    if (typeof ms !== 'number' || !isFinite(ms)) { return '...'; }
    if (ms < 1000) { return Math.round(ms) + ' ms'; }
    return (ms / 1000).toFixed(2) + ' s';
  }

  function clock(epochMs) {
    if (typeof epochMs !== 'number' || !epochMs) { return ''; }
    return new Date(epochMs).toLocaleTimeString();
  }

  function statusLabel(flow) {
    if (typeof flow.status === 'number' && flow.status > 0) { return String(flow.status); }
    if (flow.state === 'error') { return 'failed'; }
    if (flow.state === 'aborted') { return 'gone'; }
    if (flow.kind === 'tunnel') { return 'opaque'; }
    return '...';
  }

  function statusClass(flow) {
    if (typeof flow.status === 'number' && flow.status >= 100) {
      return 's' + Math.floor(flow.status / 100);
    }
    if (flow.error || flow.state === 'error' || flow.state === 'aborted') { return 'serr'; }
    return 'swait';
  }

  /* ---------------------------------------------------------------- */
  /* the list                                                          */
  /* ---------------------------------------------------------------- */

  function makeRow(flow) {
    var row = el('div', 'row');
    row.setAttribute('role', 'listitem');
    // The id lives on the element object, not in an attribute, so no captured
    // value ever needs quoting.
    row.flowId = flow.id;
    row.hidden = true;
    // Drag onto a collection to save (pointer drag; not HTML5, no grab hand).
    wireLiveDragSource(row, function () { return row.flowId; });
    row.addEventListener('click', function () {
      if (liveDragSuppressClick) { return; }
      select(row.flowId);
    });
    row.appendChild(el('span', 'method'));
    var host = el('span', 'host');
    host.appendChild(el('span', 'hostname'));
    var pin = el('span', 'pin', 'PINNED');
    // Cert-reject signal only; not pure app-pinning proof (Chrome user-CA too).
    pin.title = 'Client rejected the Proxima certificate (pinning or user-CA policy). Not pure pinning proof.';
    host.appendChild(pin);
    row.appendChild(host);
    row.appendChild(el('span', 'path'));
    var st = el('span', 'st');
    var mock = el('span', 'mock', 'mock');
    mock.hidden = true;
    mock.title = 'Map-local mock; origin was not dialed';
    st.appendChild(mock);
    st.appendChild(el('span', 'status'));
    row.appendChild(st);
    row.appendChild(el('span', 'size'));
    row.appendChild(el('span', 'dur'));
    return row;
  }

  function paint(row, flow) {
    var methodEl = row.querySelector('.method');
    var method = str(flow.method);
    methodEl.textContent = method;
    // Method colour class (m-GET, m-POST, …); unknown verbs keep .method accent.
    methodEl.className = 'method' + (method
      ? (' m-' + method.toUpperCase().replace(/[^A-Z0-9+-]/g, ''))
      : '');
    row.querySelector('.hostname').textContent = str(flow.authority);
    row.querySelector('.pin').hidden = !flow.likelyPinning;
    // Same path/query token colours as the detail URL and composer field.
    fillUrlTokens(row.querySelector('.path'), str(flow.path));
    row.querySelector('.mock').hidden = !flow.mocked;
    row.querySelector('.status').textContent = statusLabel(flow);
    row.querySelector('.size').textContent = size(flow.responseSize);
    row.querySelector('.dur').textContent =
      typeof flow.duration === 'number' ? millis(flow.duration) : '...';

    // Hover shows shared multiplex identity (H2 and H3 use the same keys).
    // List columns stay quiet so ordinary HTTP/1 rows do not grow chrome.
    var tips = [];
    if (flow.httpVersion) { tips.push('HTTP/' + str(flow.httpVersion)); }
    if (flow.transport) { tips.push(str(flow.transport)); }
    if (flow.connectionId) { tips.push('conn ' + str(flow.connectionId)); }
    if (flow.streamId != null && flow.streamId !== undefined) {
      tips.push('stream ' + String(flow.streamId));
    }
    if (flow.mocked) { tips.push('mocked (map local)'); }
    row.title = tips.join(' · ');

    var mark = statusClass(flow);
    var cls = 'row ' + mark;
    if (flow.likelyPinning) { cls += ' pinned'; }
    if (flow.id === selectedId) { cls += ' on'; }
    row.className = cls;
    // What "went wrong" means to the menu below: a status the server refused
    // with, or a flow that never got one at all.
    bads.set(flow.id, mark === 's4' || mark === 's5' || mark === 'serr');

    // Synthetic "mock" token so typing mock in the filter finds map-local rows
    // even when the path/host never mention it.
    needles.set(flow.id, [
      str(flow.method), str(flow.authority), str(flow.path),
      statusLabel(flow), str(flow.error), str(flow.client),
      str(flow.httpVersion), str(flow.transport),
      str(flow.connectionId), str(flow.streamId),
      flow.mocked ? 'mock mocked' : ''
    ].join(' ').toLowerCase());
    summaries.set(flow.id, flow);
    settle(flow);
    filterRow(row, flow.id);
  }

  // Everything about a flow that the pane below spells out and that can still
  // change after the row first appears. A response that lands while its flow is
  // open changes this string, and that is the signal to rebuild the pane.
  function signature(flow) {
    if (!flow) { return ''; }
    return [
      str(flow.state), str(flow.status), str(flow.responseSize),
      str(flow.duration), str(flow.error)
    ].join(' ');
  }

  /* ---------------------------------------------------------------- */
  /* devices                                                           */
  /* ---------------------------------------------------------------- */

  /* Two phones and a laptop through one proxy is three streams in one list.
     The address is the only thing that tells them apart here, so it is what
     the chips above the tree are: a coarser cut than the host, taken first. */

  function settle(flow) {
    var was = homes.get(flow.id);
    var now = str(flow.client) || 'unknown';
    if (was === now) { return; }
    if (was) { note(was, -1); }
    homes.set(flow.id, now);
    note(now, 1);
    paintDevices();
  }

  function forget(id) {
    var was = homes.get(id);
    if (!was) { return; }
    homes.delete(id);
    note(was, -1);
    paintDevices();
  }

  function note(address, by) {
    var count = (seen.get(address) || 0) + by;
    if (count > 0) { seen.set(address, count); } else { seen.delete(address); }
  }

  function paintDevices() {
    strip(devicesEl);
    // One device is the ordinary case and needs no choosing between.
    if (seen.size < 2) {
      if (device) { pickDevice(device); }
      return;
    }
    var addresses = Array.from(seen.keys()).sort();
    for (var i = 0; i < addresses.length; i++) {
      devicesEl.appendChild(chip(addresses[i]));
    }
    if (device && !seen.has(device)) { pickDevice(device); }
  }

  function chip(address) {
    var button = el('button', device === address ? 'chip on' : 'chip',
      address + '  ' + seen.get(address));
    button.type = 'button';
    button.addEventListener('click', function () { pickDevice(address); });
    return button;
  }

  function pickDevice(address) {
    device = device === address ? '' : address;
    paintDevices();
    rows.forEach(function (row, id) { filterRow(row, id); });
    restack();
    tally();
  }

  // Status filter: same shapes parse_status_range accepts (2xx, exact code).
  function statusInFilter(flow) {
    if (!listStatus) { return true; }
    var code = typeof flow.status === 'number' ? flow.status : 0;
    if (!(code >= 100 && code <= 599)) { return false; }
    var token = listStatus.toLowerCase();
    if (token.length === 3 && token.charAt(1) === 'x' && token.charAt(2) === 'x') {
      var band = parseInt(token.charAt(0), 10);
      if (!isFinite(band)) { return false; }
      return code >= band * 100 && code <= band * 100 + 99;
    }
    var exact = parseInt(token, 10);
    return isFinite(exact) && code === exact;
  }

  // FlowQuery-shaped cuts shared by the list and the branch counts. Server
  // reload applies the same cuts; this keeps live ws rows honest between
  // fetches.
  function matchesListFilters(id) {
    if (onlyErrors && !bads.get(id)) { return false; }
    var flow = summaries.get(id);
    if (!flow) { return true; }
    if (onlyMocked && !flow.mocked) { return false; }
    if (listMethod && str(flow.method).toUpperCase() !== listMethod) { return false; }
    if (listKind && str(flow.kind).toLowerCase() !== listKind) { return false; }
    if (listStatus && !statusInFilter(flow)) { return false; }
    return true;
  }

  // GET /api/flows query string from the current structured filters + search.
  function flowsQueryUrl() {
    var parts = ['limit=' + MAX_ROWS];
    var search = filterEl.value.trim();
    if (search) { parts.push('search=' + encodeURIComponent(search)); }
    if (listMethod) { parts.push('method=' + encodeURIComponent(listMethod)); }
    if (listStatus) { parts.push('status=' + encodeURIComponent(listStatus)); }
    if (listKind) { parts.push('kind=' + encodeURIComponent(listKind)); }
    if (onlyErrors) { parts.push('onlyErrors=1'); }
    if (onlyMocked) { parts.push('onlyMocked=1'); }
    return '/api/flows?' + parts.join('&');
  }

  function structuredFilterCount() {
    var n = 0;
    if (listMethod) { n += 1; }
    if (listStatus) { n += 1; }
    if (listKind) { n += 1; }
    if (onlyErrors) { n += 1; }
    if (onlyMocked) { n += 1; }
    return n;
  }

  // The narrowings are one decision: a row survives the typed needle, the
  // device the chips picked, the structured FlowQuery filters, and the
  // branch that was clicked, or it is not on screen.
  function filterRow(row, id) {
    var text = needles.get(id) || '';
    var hide = (needle !== '' && text.indexOf(needle) < 0)
      || (device !== '' && homes.get(id) !== device)
      || !matchesListFilters(id)
      || !inScope(id);
    if (row.hidden !== hide) {
      row.hidden = hide;
      visible += hide ? -1 : 1;
    }
  }

  function upsert(flow, atTop) {
    if (!flow || typeof flow.id !== 'string') { return; }
    var row = rows.get(flow.id);
    if (!row) {
      row = makeRow(flow);
      rows.set(flow.id, row);
      if (atTop) { rowsEl.insertBefore(row, rowsEl.firstChild); } else { rowsEl.appendChild(row); }
    }
    paint(row, flow);
    place(flow);
    trim();
  }

  function trim() {
    while (rows.size > MAX_ROWS) {
      var last = rowsEl.lastElementChild;
      if (!last) { return; }
      rowsEl.removeChild(last);
      rows.delete(last.flowId);
      unplace(last.flowId);
      forget(last.flowId);
      needles.delete(last.flowId);
      summaries.delete(last.flowId);
      spots.delete(last.flowId);
      bads.delete(last.flowId);
      if (!last.hidden) { visible -= 1; }
    }
  }

  function wipe() {
    strip(rowsEl);
    strip(treeEl);
    rows.clear();
    needles.clear();
    summaries.clear();
    rendered = '';
    groups.clear();
    branches.clear();
    homes.clear();
    spots.clear();
    bads.clear();
    seen.clear();
    device = '';
    strip(devicesEl);
    // The branch that was picked no longer exists, so neither does the scope.
    scope = '';
    scopeEl.classList.add('idle');
    visible = 0;
    selectedId = null;
    frameList = null;
    frameOwner = null;
    frameMessages = [];
    frameIndexBase = 0;
    replayStatusEl = null;
    detailToken += 1;
    hint('Pick a request to see its headers and body.');
    tally();
  }

  function tally() {
    var total = rows.size;
    emptyEl.hidden = total > 0;
    if (!total) { countEl.textContent = ''; return; }
    var base = visible === total
      ? total + ' flows'
      : visible + ' of ' + total + ' flows';
    var n = structuredFilterCount();
    countEl.textContent = n
      ? base + ' · ' + n + ' filter' + (n === 1 ? '' : 's')
      : base;
  }

  filterEl.addEventListener('input', function () {
    needle = filterEl.value.trim().toLowerCase();
    rows.forEach(function (row, id) { filterRow(row, id); });
    restack();
    tally();
  });

  // What the filter box did to the list, it also did to the branch counts.
  function restack() {
    branches.forEach(function (held, id) {
      var now = visibleIn(id);
      if (now !== held.shown) { count(held, 0, now - held.shown); }
    });
  }

  /* ---------------------------------------------------------------- */
  /* the tree                                                          */
  /* ---------------------------------------------------------------- */

  /* Hosts, and the paths under them, as a place to click. It is not a second
     list: picking a branch narrows the one list there is, the same way typing
     in the filter box does, and the two narrow together. */

  function groupFor(key, label, parent) {
    var rec = groups.get(key);
    if (rec) { return rec; }

    var box = el('div', parent ? 'group' : 'group host');
    var line = el('div', 'gline');
    var twist = el('span', 'twist', '▾');
    line.appendChild(twist);
    line.appendChild(el('span', 'gname', label));
    // Host rows wrap star + count in .gpin so the star only appears when the
    // digit rail is hovered and replaces the number there (same slot).
    var count = el('span', 'gcount', '0');
    if (!parent && liveGroup === 'host') {
      var pin = el('span', 'gpin');
      pin.appendChild(starFor(box, label));
      pin.appendChild(count);
      line.appendChild(pin);
    } else {
      line.appendChild(count);
    }
    var body = el('div', 'gbody');
    box.appendChild(line);
    box.appendChild(body);
    // The twisty folds the branch away, the rest of the line narrows the list.
    // Two jobs on one row, so the first has to keep the click to itself.
    twist.addEventListener('click', function (event) {
      event.stopPropagation();
      event.preventDefault();
      var closed = box.classList.toggle('shut');
      twist.textContent = closed ? '▸' : '▾';
    });
    line.addEventListener('click', function () { scopeTo(key); });

    rec = { key: key, el: box, line: line, body: body, count: count, parent: parent, total: 0, shown: 0 };
    groups.set(key, rec);
    if (parent) { parent.body.appendChild(box); } else { seat(box, label); }
    // A host that turns up while a search is on has to answer it too, rather
    // than arriving on screen past a filter it was never shown.
    if (hostHunt !== '') { huntHosts(hostHunt); }
    return rec;
  }

  /* Hosts arrive in whatever order the device asks for them, which is to say
     the one you care about is somewhere in the middle by the time you look.
     A kept host sits at the top of the tree instead, and stays kept across
     restarts of the tab, since the interesting hosts do not change nearly as
     often as the traffic does. */

  var kept = readKept();

  function isKept(host) { return kept.indexOf(host) >= 0; }

  function readKept() {
    try {
      var held = JSON.parse(localStorage.getItem('proxima.kept') || '[]');
      return Array.isArray(held) ? held.filter(function (h) { return typeof h === 'string'; }) : [];
    } catch (error) {
      return [];
    }
  }

  function writeKept() {
    try { localStorage.setItem('proxima.kept', JSON.stringify(kept)); } catch (error) { /* not fatal */ }
  }

  function starFor(box, host) {
    var star = el('button', isKept(host) ? 'star on' : 'star', '★');
    star.type = 'button';
    star.title = 'Keep this host at the top';
    star.setAttribute('aria-label', 'Keep this host at the top');
    box.kept = isKept(host);
    star.addEventListener('click', function (event) {
      // The line under it narrows the list, which is not what was asked for.
      event.stopPropagation();
      var at = kept.indexOf(host);
      if (at < 0) { kept.push(host); } else { kept.splice(at, 1); }
      writeKept();
      box.kept = at < 0;
      star.className = box.kept ? 'star on' : 'star';
      seat(box, host);
    });
    return star;
  }

  // Kept hosts first, in the order they were kept; everything else after them,
  // in the order it arrived.
  function seat(box, host) {
    box.kept = isKept(host);
    if (box.parentNode) { box.parentNode.removeChild(box); }
    var others = treeEl.children;
    for (var i = 0; i < others.length; i++) {
      if (box.kept ? !others[i].kept : false) {
        treeEl.insertBefore(box, others[i]);
        return;
      }
    }
    treeEl.appendChild(box);
  }

  // Where a flow sits: the host, then one branch per directory segment of its
  // path. The last segment is the request itself rather than a branch, and the
  // query string goes with it, because two calls that differ only by query are
  // two requests and not two places.
  function branch(flow) {
    var raw = str(flow.path);
    var cut = raw.indexOf('?');
    var parts = (cut < 0 ? raw : raw.slice(0, cut)).split('/');
    var dirs = [];
    for (var i = 0; i < parts.length; i++) {
      if (parts[i]) { dirs.push(parts[i]); }
    }
    if (dirs.length) { dirs.pop(); }
    return { host: str(flow.authority) || 'unknown host', dirs: dirs };
  }

  /* Where a flow belongs is worked out from the flow, but the tree is built
     again whenever the grouping changes, and by then the flow itself is long
     gone. What the tree needs of it is kept instead. */

  function place(flow) {
    spots.set(flow.id, branch(flow));
    perch(flow.id);
  }

  function perch(id) {
    var spot = spots.get(id);
    if (!spot) { return; }
    var key;
    var rec;
    // Grouped by device the address is the first branch and the host the
    // second, which is the same cut the chips take, made once and kept.
    if (liveGroup === 'device') {
      key = homes.get(id) || 'unknown';
      rec = groupFor(key, key, null);
      key += '/' + spot.host;
      rec = groupFor(key, spot.host, rec);
    } else {
      key = spot.host;
      rec = groupFor(key, spot.host, null);
    }
    for (var i = 0; i < spot.dirs.length; i++) {
      key += '/' + spot.dirs[i];
      rec = groupFor(key, spot.dirs[i], rec);
    }

    // A flow that arrives as a bare CONNECT and only later reports its path
    // moves, so a stale placement is undone rather than left where it was.
    var held = branches.get(id);
    if (held && held.key === key) {
      count(held, 0, visibleIn(id) - held.shown);
      return;
    }
    if (held) { unplace(id); }
    var held2 = { key: key, rec: rec, shown: 0 };
    branches.set(id, held2);
    count(held2, 1, visibleIn(id));
  }

  // Nothing is recounted branch by branch: the tree is thrown away and every
  // flow still in the list is seated again under the new grouping.
  function regroup() {
    strip(treeEl);
    groups.clear();
    branches.clear();
    if (scope) { scopeTo(scope, false); }
    // One pass: what a row is seated under and whether it shows are decisions
    // about that row alone, so neither waits on the rest of them.
    rows.forEach(function (row, id) {
      perch(id);
      filterRow(row, id);
    });
    if (hostHunt !== '') { huntHosts(hostHunt); }
    tally();
  }

  function unplace(id) {
    var held = branches.get(id);
    if (!held) { return; }
    branches.delete(id);
    count(held, -1, -held.shown);
    prune(held.rec);
  }

  // Whether the needle alone would show this flow. The scope is left out on
  // purpose: a count that shrank because you clicked a branch would say the
  // other branches had emptied, when all that happened is you looked away.
  function visibleIn(id) {
    var text = needles.get(id) || '';
    if (needle !== '' && text.indexOf(needle) < 0) { return 0; }
    if (device !== '' && homes.get(id) !== device) { return 0; }
    if (!matchesListFilters(id)) { return 0; }
    return 1;
  }

  // Counts ride up the chain rather than being recounted: a branch only ever
  // changes by the one flow that arrived, left, or fell out of the filter.
  function count(held, total, shown) {
    held.shown += shown;
    var rec = held.rec;
    while (rec) {
      rec.total += total;
      rec.shown += shown;
      rec.count.textContent = rec.shown === rec.total
        ? String(rec.total)
        : rec.shown + ' of ' + rec.total;
      dress(rec);
      rec = rec.parent;
    }
  }

  // Two reasons to hide a branch, and one place that decides: nothing under it
  // survived the filter box, or nothing under it answers the search in the bar.
  function dress(rec) {
    rec.el.hidden = (rec.total > 0 && rec.shown === 0) || rec.astray === true;
  }

  /* The search in each bar is a search of that tree, not of the capture: it
     hides branches rather than flows, and the counts on the ones left standing
     go on saying how much traffic they hold. */

  var hostHunt = '';

  function huntHosts(text) {
    var want = text.trim().toLowerCase();
    hostHunt = want;
    groups.forEach(function (rec) { rec.astray = want !== ''; });
    if (want !== '') {
      groups.forEach(function (rec) {
        if (rec.key.toLowerCase().indexOf(want) < 0) { return; }
        // A branch that answers brings the ones above it along, or it would be
        // hidden inside a parent that does not answer itself.
        for (var up = rec; up; up = up.parent) { up.astray = false; }
      });
    }
    groups.forEach(dress);
  }

  // A branch nothing hangs off is noise, and leaving it would let the tree grow
  // without bound while the list it stands beside stays capped.
  function prune(rec) {
    while (rec && rec.total === 0) {
      if (rec.el.parentNode) { rec.el.parentNode.removeChild(rec.el); }
      groups.delete(rec.key);
      // The list cannot stay narrowed to a branch that is no longer there.
      if (rec.key === scope) { scopeTo(scope, false); }
      rec = rec.parent;
    }
  }

  // A flow is in scope when it sits on the chosen branch or below it. Comparing
  // whole segments is what keeps `example.com/v1` from claiming `/v10`.
  function inScope(id) {
    if (!scope) { return true; }
    var held = branches.get(id);
    if (!held) { return false; }
    return held.key === scope || held.key.indexOf(scope + '/') === 0;
  }

  // `fromUser` (default true): leave the composer seat so #list is visible.
  // Internal callers (prune / regroup) pass false; they only fix scope state.
  function scopeTo(key, fromUser) {
    if (fromUser !== false) {
      // Picking a host/path is going back to live traffic. Composer / breaker /
      // rewrite / archive hide #list; without leaving them the tree looks
      // broken: scope changes and nothing appears beside it.
      composing(false);
      breaking(false);
      rewriting(false);
      httpRewriting(false);
      archiveView(false);
    }

    scope = scope === key ? '' : key;
    groups.forEach(function (rec) {
      rec.line.classList.toggle('picked', rec.key === scope);
      // A branch that is the scope should be open so its children are visible.
      if (rec.key === scope) {
        rec.el.classList.remove('shut');
        var tw = rec.line.querySelector('.twist');
        if (tw) { tw.textContent = '▾'; }
      }
    });
    scopeEl.classList.toggle('idle', scope === '');
    scopeNameEl.textContent = scope;
    rows.forEach(function (row, id) { filterRow(row, id); });
    tally();
  }

  function highlight(id, on) {
    var row = rows.get(id);
    if (row) { row.classList.toggle('on', on); }
  }

  document.getElementById('scope-clear').addEventListener('click', function () {
    if (scope) { scopeTo(scope); }
  });

  /* The scheme follows the machine unless it is told not to. The choice
     outlives the tab, because a tool you leave open all day should not go back
     to arguing with you after every restart. */

  var THEMES = ['system', 'light', 'dark'];
  var themeBtn = document.getElementById('theme');

  function wearTheme(name) {
    if (name === 'system') { document.documentElement.removeAttribute('data-theme'); }
    else { document.documentElement.setAttribute('data-theme', name); }
    themeBtn.textContent = 'Theme: ' + name;
    themeBtn.classList.toggle('on', name !== 'system');
  }

  function rememberedTheme() {
    // Private browsing refuses storage outright, and a stored value from an
    // older build is not one of ours.
    try {
      var held = localStorage.getItem('proxima.theme');
      return THEMES.indexOf(held) < 0 ? 'system' : held;
    } catch (error) {
      return 'system';
    }
  }

  var theme = rememberedTheme();
  themeBtn.addEventListener('click', function () {
    // Storage that refuses to be written must still leave the button working
    // for as long as the tab is open, so the choice is held here as well.
    theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
    try { localStorage.setItem('proxima.theme', theme); } catch (error) { /* not fatal */ }
    wearTheme(theme);
  });
  wearTheme(theme);

  viewBtn.addEventListener('click', function () {
    var off = mainEl.classList.toggle('flat');
    viewBtn.classList.toggle('on', !off);
    viewBtn.textContent = off ? 'Tree' : 'Hide tree';
  });

  /* How wide the tree is is a habit, not a one-shot: drag the edge, and the
     next visit starts where this one left off. Bounds keep the list usable. */

  var TREE_W_MIN = 160;
  var TREE_W_MAX = 640;
  var TREE_W_DEFAULT = 240;

  function readTreeWidth() {
    try {
      var held = parseFloat(localStorage.getItem('proxima.tree-w'));
      if (!isFinite(held) || held < TREE_W_MIN || held > TREE_W_MAX) {
        return TREE_W_DEFAULT;
      }
      return held;
    } catch (error) {
      return TREE_W_DEFAULT;
    }
  }

  function wearTreeWidth(px) {
    var w = Math.max(TREE_W_MIN, Math.min(TREE_W_MAX, px));
    // Half the main pane is as far as the tree may go: past that the list is
    // no longer a list you can read.
    var room = mainEl.clientWidth;
    if (room > 0) {
      w = Math.min(w, Math.max(TREE_W_MIN, Math.floor(room * 0.55)));
    }
    mainEl.style.setProperty('--tree-w', w + 'px');
    return w;
  }

  var treeWidth = wearTreeWidth(readTreeWidth());
  var treeGrip = document.getElementById('tree-grip');
  var treeDrag = null;

  treeGrip.addEventListener('pointerdown', function (event) {
    if (event.button !== 0) { return; }
    event.preventDefault();
    treeDrag = { x: event.clientX, w: treeWidth };
    document.body.classList.add('tree-sizing');
    treeGrip.setPointerCapture(event.pointerId);
  });
  treeGrip.addEventListener('pointermove', function (event) {
    if (!treeDrag) { return; }
    treeWidth = wearTreeWidth(treeDrag.w + (event.clientX - treeDrag.x));
  });
  function endTreeDrag() {
    if (!treeDrag) { return; }
    treeDrag = null;
    document.body.classList.remove('tree-sizing');
    try { localStorage.setItem('proxima.tree-w', String(treeWidth)); } catch (error) { /* not fatal */ }
  }
  treeGrip.addEventListener('pointerup', endTreeDrag);
  treeGrip.addEventListener('pointercancel', endTreeDrag);

  /* ---------------------------------------------------------------- */
  /* the detail view                                                   */
  /* ---------------------------------------------------------------- */

  // Every path that replaces the detail pane with a sentence comes through
  // here, so this is where the frame list stops being live. Without it a socket
  // whose detail view failed to reload keeps appending frames to a node that
  // was detached from the document several selections ago.
  function hint(text) {
    strip(detailEl);
    frameList = null;
    frameOwner = null;
    frameMessages = [];
    frameIndexBase = 0;
    replayStatusEl = null;
    detailEl.appendChild(el('p', 'hint', text));
  }

  // `showLive` (default true): leave the composer / breakpoints / rewrite /
  // archive seats so #list and #detail are visible again. Automatic redraws
  // of the open flow pass false, so a background update does not yank the
  // composer closed under someone who just opened a saved request.
  async function select(id, showLive) {
    if (showLive !== false) {
      // Live traffic uses #list/#detail. Those are display:none while composer
      // (or breaker/rewriter/archiver) owns the seat; without this a click on
      // a capture after opening a saved request looks like it does nothing.
      composing(false);
      breaking(false);
      rewriting(false);
      httpRewriting(false);
      archiveView(false);
    }

    // Both views carry the selection, so switching between them keeps it.
    if (selectedId) { highlight(selectedId, false); }
    selectedId = id;
    rendered = signature(summaries.get(id));
    highlight(id, true);

    var token = ++detailToken;
    hint('Loading...');
    try {
      var flow = await getJson('/api/flows/' + encodeURIComponent(id));
      if (token === detailToken) { renderFlow(flow); }
    } catch (error) {
      if (token === detailToken) { hint('Could not load that flow: ' + error.message); }
    }
  }

  function renderFlow(flow) {
    strip(detailEl);
    frameList = null;
    frameOwner = null;
    frameMessages = [];
    frameIndexBase = 0;
    replayStatusEl = null;
    var request = flow.request || {};
    var response = flow.response || null;

    var head = el('div', 'dhead');
    // One line, and the copy sits at the head of it: it acts on the URL beside
    // it, and a row of its own for a single control was a row of mostly nothing.
    head.appendChild(copyBar(flow, request, response));
    // Method only in the head: HTTP version lives under Info (and in the list
    // tooltip), not glued to GET as "GET 2.0".
    head.appendChild(el('span', 'dmethod', str(request.method)));
    // Same token colours as the composer URL field (scheme/host/path/query).
    var durl = el('span', 'durl mono');
    fillUrlTokens(durl, str(request.url));
    // Same drag source as list rows: pull the detail URL onto a collection.
    if (flow.id && request.url) {
      durl.title = 'Drag onto a collection to save';
      wireLiveDragSource(durl, function () { return flow.id; });
    }
    head.appendChild(durl);
    detailEl.appendChild(head);

    // Banner, not only a rewrite note: map-local must be obvious at a glance.
    if (flow.mocked) {
      var banner = el('div', 'mock-banner');
      banner.appendChild(el('div', 'mtitle', 'Mocked response (map local)'));
      banner.appendChild(el('p', null,
        'This response was produced by a map-local mock rule; the origin was not dialed.'));
      detailEl.appendChild(banner);
    }

    sides(flow, request, response);
  }

  /* The bottom pane holds two halves of one exchange. Which of them is on
     screen is a preference rather than a property of the flow, so it is kept
     across selections: picking the next request does not put you back on a
     tab you had just moved away from. */

  function sides(flow, request, response) {
    // A live upgrade may still have an empty list. The Frames tab still has to
    // exist so a frame can be injected before either peer has said anything.
    var frames = Array.isArray(flow.wsMessages)
      ? flow.wsMessages
      : (flow.kind === 'websocket' ? [] : null);
    var tabs = el('div', 'tabs');
    var panes = el('div', 'panes');
    var buttons = [];

    function draw() {
      strip(panes);
      // Whatever the frame list was pointing at is about to leave the document.
      frameList = null;
      frameOwner = null;
      frameMessages = [];
      frameIndexBase = 0;
      replayStatusEl = null;
      panes.className = paired ? 'panes both' : 'panes';

      for (var i = 0; i < buttons.length; i++) {
        buttons[i].hidden = paired;
        buttons[i].classList.toggle('on', !paired && buttons[i].side === side);
      }
      if (paired) {
        panes.appendChild(pane('info', flow, request, response, frames));
        panes.appendChild(pane('request', flow, request, response, frames));
        if (response) { panes.appendChild(pane('response', flow, request, response, frames)); }
        if (frames) { panes.appendChild(pane('frames', flow, request, response, frames)); }
        return;
      }
      panes.appendChild(pane(side, flow, request, response, frames));
    }

    function offer(name, label) {
      var button = el('button', 'tab', label);
      button.type = 'button';
      button.side = name;
      button.addEventListener('click', function () { side = name; draw(); });
      buttons.push(button);
      tabs.appendChild(button);
    }

    offer('info', 'Info');
    offer('request', 'Request');
    if (response) { offer('response', 'Response'); }
    if (frames) { offer('frames', 'Frames'); }
    // A flow still in flight has no response half, and most have no frames.
    // What every flow does have is the account of itself.
    if (side === 'response' && !response) { side = 'info'; }
    if (side === 'frames' && !frames) { side = 'info'; }

    tabs.appendChild(el('span', 'gap'));
    var mode = el('button', 'tab', paired ? 'One at a time' : 'Both at once');
    mode.type = 'button';
    mode.addEventListener('click', function () {
      paired = !paired;
      mode.textContent = paired ? 'One at a time' : 'Both at once';
      mode.classList.toggle('on', paired);
      draw();
    });
    mode.classList.toggle('on', paired);
    tabs.appendChild(mode);

    detailEl.appendChild(tabs);
    detailEl.appendChild(panes);
    draw();
  }

  function pane(which, flow, request, response, frames) {
    // Info and the frames are about the exchange rather than one end of it, so
    // side by side they take the full width instead of a column each.
    var box = el('div', which === 'request' || which === 'response' ? 'pane' : 'pane wide');
    if (which === 'frames') {
      box.appendChild(frameBlock(flow.id, frames, flow));
      return box;
    }
    if (which === 'info') {
      box.appendChild(facts(flow, request, response));
      if (Array.isArray(flow.rewrites) && flow.rewrites.length) {
        var rw = el('section', 'block');
        rw.appendChild(el('h2', null, 'Rewrites'));
        for (var ri = 0; ri < flow.rewrites.length; ri++) {
          rw.appendChild(el('p', 'mono', str(flow.rewrites[ri])));
        }
        box.appendChild(rw);
      }
      if (flow.error) {
        var trouble = el('div', 'error');
        var etitle = str(flow.error.message);
        if (flow.error.code) {
          etitle = '[' + str(flow.error.code) + '] ' + etitle;
        }
        trouble.appendChild(el('div', 'etitle', etitle));
        if (flow.error.likelyPinning) {
          // likelyPinning is a cert-reject signal, not pure app-pinning proof:
          // Chrome often refuses user CAs for QUIC, and TCP UnknownCA alerts
          // cover the same class. See README force-TCP / Chrome user-CA notes.
          trouble.appendChild(el('p', null, 'The client rejected the Proxima certificate. That often means the app pins its own CA, but it is not pure pinning proof: on QUIC especially, Chrome may refuse a user-installed CA even when the leaf is otherwise valid. Nothing here decrypts it; build the app against a permissive network security config, put Proxima in the system trust store, or force the client onto TCP/HTTP2. Exclude the host with --skip to let traffic through untouched.'));
        }
        box.appendChild(trouble);
      }
      return box;
    }
    var half = which === 'response' ? response : request;
    if (which === 'request') {
      // Postman-style key/value breakdown of the request URL query string.
      box.appendChild(queryParamsBlock(request.url));
    }
    box.appendChild(headerBlock(
      which === 'response' ? 'Response headers' : 'Request headers', half.headers));
    box.appendChild(bodyBlock(flow.id, which, half.body));
    return box;
  }

  // Read-only table of query parameters for a captured request URL. Same
  // header-grid language as Request headers so the two stacks match.
  function queryParamsBlock(url) {
    var block = el('section', 'block qparams');
    block.appendChild(el('h2', null, 'Query parameters'));
    var parts = splitUrlParts(str(url));
    var rows = parseQueryString(parts.query);
    if (!rows.length) {
      block.appendChild(el('p', 'none', 'none'));
      return block;
    }
    var grid = el('div', 'headers mono');
    for (var i = 0; i < rows.length; i++) {
      var line = el('div', 'hrow');
      line.appendChild(el('span', 'hname', str(rows[i].key)));
      line.appendChild(el('span', 'hval', str(rows[i].value)));
      line.title = 'Highlight this parameter';
      line.addEventListener('click', function (event) {
        var row = event.currentTarget;
        var was = row.classList.contains('on');
        var sibs = grid.querySelectorAll('.hrow.on');
        for (var s = 0; s < sibs.length; s++) { sibs[s].classList.remove('on'); }
        if (!was) { row.classList.add('on'); }
      });
      grid.appendChild(line);
    }
    block.appendChild(grid);
    return block;
  }

  function facts(flow, request, response) {
    var server = flow.server || {};
    var client = flow.client || {};
    var timings = flow.timings || {};
    var pairs = [];

    pairs.push(['Status', response
      ? str(response.status) + ' ' + str(response.statusText)
      : statusLabel({ state: flow.state, kind: flow.kind, error: flow.error })]);
    pairs.push(['Kind', str(flow.kind) + (flow.intercepted ? ', decrypted' : ', not decrypted')]);
    if (flow.mocked) { pairs.push(['Mocked', 'map local (no origin dial)']); }
    pairs.push(['HTTP', str(request.httpVersion)]);
    // transport is orthogonal to multiplex: omit for TCP (including H2);
    // "quic" only for H3. connectionId/streamId are the shared H2+H3 session
    // identity (Proxima UUID per client multiplex session, not a wire CID).
    if (flow.transport) { pairs.push(['Transport', str(flow.transport)]); }
    if (flow.connectionId) { pairs.push(['Connection', str(flow.connectionId)]); }
    if (flow.streamId != null && flow.streamId !== undefined) {
      pairs.push(['Stream id', String(flow.streamId)]);
    }
    if (flow.upstreamStreamId != null && flow.upstreamStreamId !== undefined) {
      pairs.push(['Upstream stream id', String(flow.upstreamStreamId)]);
    }
    pairs.push(['Started', clock(timings.start)]);
    pairs.push(['Duration', typeof timings.end === 'number' && typeof timings.start === 'number'
      ? millis(timings.end - timings.start)
      : 'in flight']);
    pairs.push(['Client', str(client.address) + ':' + str(client.port)]);
    if (server.address) { pairs.push(['Server', str(server.address) + ':' + str(server.port)]); }
    if (server.sni) { pairs.push(['SNI', server.sni]); }
    if (server.alpn) { pairs.push(['ALPN', server.alpn]); }
    if (server.tlsVersion) {
      pairs.push(['TLS', str(server.tlsVersion) + (server.cipher ? ', ' + str(server.cipher) : '')]);
    }
    if (server.certFingerprint) { pairs.push(['Origin cert', server.certFingerprint]); }
    if (flow.tunnel) {
      pairs.push(['Tunnelled', size(flow.tunnel.bytesSent) + ' up, ' +
        size(flow.tunnel.bytesReceived) + ' down, ' + str(flow.tunnel.reason)]);
    }
    if (flow.replayOf) { pairs.push(['Replay of', flow.replayOf]); }

    var grid = el('div', 'facts');
    for (var i = 0; i < pairs.length; i++) {
      grid.appendChild(el('span', 'fkey', pairs[i][0]));
      // Connection is a Proxima multiplex session key. Clicking it filters the
      // list so sibling streams on the same H2 TLS or H3 QUIC session group.
      if (pairs[i][0] === 'Connection' && flow.connectionId) {
        var link = el('button', 'flink', shortId(flow.connectionId));
        link.type = 'button';
        link.title = 'Filter list to this multiplex session\n' + str(flow.connectionId);
        link.addEventListener('click', function () {
          filterByConnection(str(flow.connectionId));
        });
        grid.appendChild(link);
      } else {
        grid.appendChild(el('span', 'fval', pairs[i][1]));
      }
    }
    return grid;
  }

  // Shorten a UUID-like connection id for the facts grid; full value stays in
  // title and is what filter-by-connection uses.
  function shortId(id) {
    var s = str(id);
    if (s.length <= 12) { return s; }
    return s.slice(0, 8) + '...';
  }

  function filterByConnection(connectionId) {
    if (!connectionId) { return; }
    filterEl.value = connectionId;
    needle = connectionId.trim().toLowerCase();
    rows.forEach(function (row, id) { filterRow(row, id); });
  }

  function headerBlock(title, headers) {
    var block = el('section', 'block');
    block.appendChild(el('h2', null, title));
    var list = Array.isArray(headers) ? headers : [];
    if (!list.length) {
      block.appendChild(el('p', 'none', 'none'));
      return block;
    }
    var grid = el('div', 'headers mono');
    for (var i = 0; i < list.length; i++) {
      var pair = list[i];
      if (!Array.isArray(pair)) { continue; }
      var line = el('div', 'hrow');
      line.appendChild(el('span', 'hname', str(pair[0])));
      line.appendChild(el('span', 'hval', str(pair[1])));
      grid.appendChild(line);
    }
    block.appendChild(grid);
    return block;
  }

  function bodyBlock(id, which, meta) {
    var block = el('section', 'block');
    block.appendChild(el('h2', null, which === 'request' ? 'Request body' : 'Response body'));
    if (!meta) {
      block.appendChild(el('p', 'none', 'none'));
      return block;
    }

    var note = size(meta.size);
    if (meta.truncated) { note += ', cut short at the capture limit'; }
    if (meta.contentEncoding) { note += ', ' + str(meta.contentEncoding); }
    if (meta.contentType) { note += ', ' + str(meta.contentType); }
    block.appendChild(el('p', 'note', note));

    var save = el('a', 'btn', 'Download');
    // The store mints these ids, and encoding keeps whatever it minted inside
    // one path segment.
    save.href = '/api/flows/' + encodeURIComponent(id) + '/body/' + which + '?download=1';
    block.appendChild(save);

    var pre = el('pre', 'body mono');
    block.appendChild(pre);
    if (!textual(meta.contentType)) {
      pre.textContent = 'Binary. Download it rather than reading it here.';
      return block;
    }
    pre.textContent = 'Loading...';
    loadBody(id, which, meta.contentType, pre);
    return block;
  }

  function textual(contentType) {
    if (!contentType) { return true; }
    var ct = String(contentType).toLowerCase();
    if (ct.indexOf('text/') === 0) { return true; }
    var kinds = ['json', 'xml', 'javascript', 'ecmascript', 'html', 'csv', 'graphql', 'x-www-form-urlencoded'];
    for (var i = 0; i < kinds.length; i++) {
      if (ct.indexOf(kinds[i]) >= 0) { return true; }
    }
    return false;
  }

  // Whole, decoded, and not cut down: the pane below trims it to what it can
  // show, and copying wants the thing itself.
  async function bodyText(id, which) {
    var url = '/api/flows/' + encodeURIComponent(id) + '/body/' + which + '?decode=1';
    var response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('it is no longer available (' + response.status + ')');
    }
    return response.text();
  }

  async function loadBody(id, which, contentType, into) {
    var text;
    try {
      text = await bodyText(id, which);
    } catch (error) {
      into.textContent = 'Could not read the body: ' + error.message;
      return;
    }
    var cut = text.length > MAX_BODY_CHARS;
    if (cut) { text = text.slice(0, MAX_BODY_CHARS); }
    var suffix = cut ? '\n\n[stopped after ' + MAX_BODY_CHARS + ' characters]' : '';
    // JSON goes through the tokenizer (pretty + colour); other types stay plain.
    if (wantsJsonView(text, contentType)) {
      var view = await fetchJsonView(text);
      if (view) {
        paintJson(into, view);
        if (suffix) { into.appendChild(document.createTextNode(suffix)); }
        return;
      }
    }
    into.textContent = text + suffix;
  }

  // True when the body is worth sending to /api/json/view.
  function wantsJsonView(text, contentType) {
    if (contentType && String(contentType).toLowerCase().indexOf('json') >= 0) {
      return true;
    }
    var t = String(text || '').replace(/^\uFEFF/, '').replace(/^\s+/, '');
    return t.charAt(0) === '{' || t.charAt(0) === '[';
  }

  // Cache short payloads so a list of similar frames does not hammer the API.
  var jsonViewCache = new Map();
  var JSON_VIEW_CACHE_MAX = 64;

  async function fetchJsonView(text) {
    var key = text.length <= 4096 ? text : null;
    if (key && jsonViewCache.has(key)) { return jsonViewCache.get(key); }
    try {
      var response = await fetch('/api/json/view', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text: text }),
        cache: 'no-store'
      });
      if (!response.ok) { return null; }
      var view = await response.json();
      if (key) {
        if (jsonViewCache.size >= JSON_VIEW_CACHE_MAX) {
          jsonViewCache.delete(jsonViewCache.keys().next().value);
        }
        jsonViewCache.set(key, view);
      }
      return view;
    } catch (error) {
      return null;
    }
  }

  // Paint tokenizer tokens as spans. Never HTML: each run is textContent.
  function paintJson(into, view) {
    strip(into);
    into.classList.add('json');
    var tokens = view && Array.isArray(view.tokens) ? view.tokens : null;
    if (!tokens || !tokens.length) {
      into.textContent = view && view.text != null ? String(view.text) : '';
      return;
    }
    for (var i = 0; i < tokens.length; i++) {
      var tok = tokens[i];
      var kind = str(tok && tok.kind).toLowerCase() || 'invalid';
      into.appendChild(el('span', 'j-' + kind, tok && tok.text != null ? String(tok.text) : ''));
    }
  }

  // Soft-view JSON from ?pretty=1 (tokens optional) or plain text fallback.
  function paintSoftOrText(into, view, fallback) {
    if (view && view.kind === 'json' && view.tokens) {
      paintJson(into, view);
      return;
    }
    if (view && view.text != null) {
      into.textContent = String(view.text);
      return;
    }
    into.textContent = fallback || '';
  }

  function frameBlock(id, messages, flow) {
    var block = el('section', 'block');
    block.appendChild(el('h2', null, 'WebSocket frames'));
    block.appendChild(injectForm(id, flow));
    block.appendChild(replayForm(id, flow));
    block.appendChild(frameFilterBar());
    frameList = el('div', 'frames mono');
    frameOwner = id;
    // Keep a retained window, then paint only the rows that match the filters.
    var all = Array.isArray(messages) ? messages : [];
    frameMessages = all.slice(-MAX_FRAMES);
    frameIndexBase = Math.max(0, all.length - frameMessages.length);
    renderFrames();
    block.appendChild(frameList);
    return block;
  }

  /* Filters apply to the retained window (not the DOM alone). Search uses the
     raw captured text; display can pretty-print JSON without changing matches. */
  function matchesFrame(message) {
    if (!message) { return false; }
    if (frameFilters.direction && message.direction !== frameFilters.direction) {
      return false;
    }
    if (frameFilters.opcodes && !frameFilters.opcodes[message.opcode]) {
      return false;
    }
    var needle = frameFilters.query;
    if (needle) {
      var raw = typeof message.text === 'string' ? message.text : '';
      if (raw.toLowerCase().indexOf(needle) < 0) { return false; }
    }
    return true;
  }

  // Synchronous fallback when /api/json/view is not yet back. Search still
  // uses raw message.text; only display goes through this.
  function displayText(message) {
    var raw = typeof message.text === 'string' ? message.text : null;
    if (raw === null) { return null; }
    if (message.opcode === 1 && wantsJsonView(raw, null)) {
      // Prefer a cached server pretty; else leave raw until paintJson fills in.
      if (jsonViewCache.has(raw)) {
        var held = jsonViewCache.get(raw);
        return held && held.text != null ? String(held.text) : raw;
      }
      return raw;
    }
    return raw;
  }

  function paintFramePayload(textEl, message) {
    var raw = typeof message.text === 'string' ? message.text : null;
    if (raw === null) { return; }
    if (message.opcode === 1 && wantsJsonView(raw, null)) {
      if (jsonViewCache.has(raw)) {
        paintJson(textEl, jsonViewCache.get(raw));
        return;
      }
      textEl.textContent = raw;
      fetchJsonView(raw).then(function (view) {
        if (view) { paintJson(textEl, view); }
      });
      return;
    }
    textEl.textContent = raw;
  }

  function renderFrames() {
    if (!frameList) { return; }
    strip(frameList);
    for (var i = 0; i < frameMessages.length; i++) {
      if (matchesFrame(frameMessages[i])) {
        frameList.appendChild(frameLine(frameMessages[i], frameIndexBase + i));
      }
    }
  }

  function retainFrame(message) {
    frameMessages.push(message || {});
    while (frameMessages.length > MAX_FRAMES) {
      frameMessages.shift();
      frameIndexBase += 1;
    }
  }

  function isInjectableOpcode(code) {
    return code === 1 || code === 2 || code === 8 || code === 9 || code === 10;
  }

  function frameFilterBar() {
    var bar = el('div', 'inject filters');
    bar.appendChild(el('p', 'hint',
      'Filter the list. Search matches raw frame text; JSON is pretty-printed below.'));

    var line = el('div', 'c-line');
    var dir = document.createElement('select');
    dir.setAttribute('aria-label', 'Frame direction filter');
    addOption(dir, '', 'any direction');
    addOption(dir, 'send', 'client to server');
    addOption(dir, 'recv', 'server to client');
    dir.value = frameFilters.direction || '';
    line.appendChild(dir);

    var op = document.createElement('select');
    op.setAttribute('aria-label', 'Frame opcode filter');
    addOption(op, '', 'any opcode');
    addOption(op, '1', 'text');
    addOption(op, '2', 'binary');
    addOption(op, '8', 'close');
    addOption(op, '9', 'ping');
    addOption(op, '10', 'pong');
    // Reflect a single-code set as the select value; multi is unused in this UI.
    op.value = frameFilters.opcodes
      ? String(Object.keys(frameFilters.opcodes)[0] || '')
      : '';
    line.appendChild(op);

    var query = document.createElement('input');
    query.type = 'search';
    query.placeholder = 'search frame text';
    query.spellcheck = false;
    query.setAttribute('aria-label', 'Search frame text');
    query.value = frameFilters.query || '';
    line.appendChild(query);
    bar.appendChild(line);

    function applyFilters() {
      frameFilters.direction = dir.value || '';
      if (op.value === '') {
        frameFilters.opcodes = null;
      } else {
        var set = {};
        set[Number(op.value)] = true;
        frameFilters.opcodes = set;
      }
      frameFilters.query = query.value.trim().toLowerCase();
      renderFrames();
    }
    dir.addEventListener('change', applyFilters);
    op.addEventListener('change', applyFilters);
    query.addEventListener('input', applyFilters);
    return bar;
  }

  function addOption(select, value, label) {
    var option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    select.appendChild(option);
  }

  /* The form posts to /api/flows/{id}/ws/send. The event socket appends the
     recorded frame afterwards, so a successful inject must not also draw the
     response here or the list would double every frame. */
  function injectForm(id, flow) {
    var form = el('div', 'inject');
    var closed = flow && (flow.state === 'complete' || flow.state === 'error' ||
      flow.state === 'aborted');
    form.appendChild(el('p', 'hint', closed
      ? 'This socket is closed. Inject only works on a live upgraded flow.'
      : 'Inject a frame into the live connection. Written immediately; skips rewrite rules and breakpoints; recorded like wire traffic and marked injected. Client to server is masked; server to client is not. Opcodes text, binary, ping, pong, close only (no continuations or drop markers).'));

    var line = el('div', 'c-line');
    var dir = document.createElement('select');
    dir.setAttribute('aria-label', 'Direction');
    addOption(dir, 'send', 'client to server');
    addOption(dir, 'recv', 'server to client');
    line.appendChild(dir);

    var op = document.createElement('select');
    op.setAttribute('aria-label', 'Opcode');
    addOption(op, '1', 'text');
    addOption(op, '2', 'binary');
    addOption(op, '9', 'ping');
    addOption(op, '10', 'pong');
    addOption(op, '8', 'close');
    line.appendChild(op);

    var go = el('button', 'btn', 'Inject');
    go.type = 'button';
    line.appendChild(go);
    form.appendChild(line);

    var closeLine = el('div', 'c-line');
    closeLine.hidden = true;
    var code = document.createElement('input');
    code.type = 'number';
    code.value = '1000';
    code.min = '0';
    code.max = '65535';
    code.setAttribute('aria-label', 'Close code');
    closeLine.appendChild(code);
    var reason = document.createElement('input');
    reason.type = 'text';
    reason.placeholder = 'close reason';
    reason.setAttribute('aria-label', 'Close reason');
    reason.spellcheck = false;
    closeLine.appendChild(reason);
    form.appendChild(closeLine);

    var payloadLabel = el('label', 'c-label', 'Payload');
    form.appendChild(payloadLabel);
    var payload = document.createElement('textarea');
    payload.spellcheck = false;
    payload.setAttribute('aria-label', 'Payload');
    form.appendChild(payload);

    var status = el('p', 'hint');
    form.appendChild(status);

    function showClose(on) {
      closeLine.hidden = !on;
      payload.hidden = on;
      payloadLabel.hidden = on;
      if (!on) {
        payloadLabel.textContent = op.value === '2'
          ? 'Payload (sent as UTF-8 bytes)'
          : 'Payload';
      }
    }
    op.addEventListener('change', function () { showClose(op.value === '8'); });

    go.addEventListener('click', function () {
      injectFrame(id, dir.value, Number(op.value), payload.value, code.value,
        reason.value, go, status);
    });
    return form;
  }

  async function injectFrame(id, direction, opcode, text, closeCode, closeReason, button, status) {
    var body = { direction: direction, opcode: opcode };
    if (opcode === 8) {
      var code = parseInt(closeCode, 10);
      if (!isFinite(code) || code < 0 || code > 65535) {
        status.textContent = 'Close code must be between 0 and 65535.';
        return;
      }
      body.closeCode = code;
      if (closeReason) { body.closeReason = closeReason; }
    } else if (opcode === 2) {
      body.dataBase64 = toBase64(text);
    } else if (text) {
      body.text = text;
    }

    button.disabled = true;
    status.textContent = 'Injecting...';
    try {
      var response = await fetch('/api/flows/' + encodeURIComponent(id) + '/ws/send', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        cache: 'no-store'
      });
      var raw = await response.text();
      var parsed = null;
      try { parsed = JSON.parse(raw); } catch (error) { /* body may not be JSON */ }
      if (!response.ok) {
        status.textContent = (parsed && parsed.error)
          ? String(parsed.error)
          : ('Inject failed (' + response.status + ')');
        return;
      }
      status.textContent = 'Injected.';
    } catch (error) {
      status.textContent = 'Could not inject: ' + error.message;
    } finally {
      button.disabled = false;
    }
  }

  /* Replay posts to /api/flows/{id}/ws/replay. Like inject, the event socket
     owns list rows: a successful replay must not paint response.messages here
     or same-flow injects would double every frame. */
  function replayForm(id, flow) {
    var form = el('div', 'inject replay');
    var closed = flow && (flow.state === 'complete' || flow.state === 'error' ||
      flow.state === 'aborted');
    form.appendChild(el('p', 'hint', closed
      ? 'This socket is closed. Replay only works onto a live upgraded flow (use another targetFlowId if needed).'
      : 'Replay captured frames onto this live socket (or another live target). Drop markers and continuations are skipped; compressed frames re-inject inflated bytes uncompressed.'));

    var line = el('div', 'c-line');
    var dir = document.createElement('select');
    dir.setAttribute('aria-label', 'Replay direction filter');
    addOption(dir, '', 'both directions');
    addOption(dir, 'send', 'client to server only');
    addOption(dir, 'recv', 'server to client only');
    line.appendChild(dir);

    var delay = document.createElement('input');
    delay.type = 'number';
    delay.min = '0';
    delay.max = '60000';
    delay.step = '10';
    delay.value = '0';
    delay.placeholder = 'delay ms';
    delay.setAttribute('aria-label', 'Delay between frames in milliseconds');
    delay.title = 'Milliseconds to wait between successful injects';
    line.appendChild(delay);

    var go = el('button', 'btn', 'Replay history');
    go.type = 'button';
    line.appendChild(go);
    form.appendChild(line);

    var targetLine = el('div', 'c-line');
    var target = document.createElement('input');
    target.type = 'text';
    target.spellcheck = false;
    target.autocomplete = 'off';
    target.placeholder = 'target flow id (empty = this flow)';
    target.setAttribute('aria-label', 'Target flow id');
    targetLine.appendChild(target);
    form.appendChild(targetLine);

    var status = el('p', 'hint');
    form.appendChild(status);
    replayStatusEl = status;

    go.addEventListener('click', function () {
      var directions = dir.value ? [dir.value] : null;
      var delayMs = parseInt(delay.value, 10);
      if (!isFinite(delayMs) || delayMs < 0) { delayMs = 0; }
      var targetId = target.value.trim() || null;
      replayFrames(id, null, directions, delayMs, targetId, go, status);
    });
    return form;
  }

  async function replayFrames(sourceId, indices, directions, delayMs, targetFlowId, button, status) {
    var body = {};
    body.mode = 'live';
    if (indices && indices.length) { body.indices = indices; }
    if (directions && directions.length) { body.directions = directions; }
    if (delayMs > 0) { body.delayMs = delayMs; }
    if (targetFlowId) { body.targetFlowId = targetFlowId; }
    body.stopOnError = true;

    button.disabled = true;
    status.textContent = 'Replaying...';
    try {
      var response = await fetch('/api/flows/' + encodeURIComponent(sourceId) + '/ws/replay', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        cache: 'no-store'
      });
      var raw = await response.text();
      var parsed = null;
      try { parsed = JSON.parse(raw); } catch (error) { /* body may not be JSON */ }
      if (!response.ok) {
        status.textContent = (parsed && parsed.error)
          ? String(parsed.error)
          : ('Replay failed (' + response.status + ')');
        return;
      }
      var sent = parsed && typeof parsed.sent === 'number' ? parsed.sent : 0;
      var planned = parsed && typeof parsed.planned === 'number' ? parsed.planned : 0;
      var skipped = parsed && typeof parsed.skipped === 'number' ? parsed.skipped : 0;
      var note = 'Replayed ' + sent + ' of ' + planned + ' frame' + (planned === 1 ? '' : 's');
      if (skipped) { note += ' (' + skipped + ' skipped)'; }
      note += '.';
      if (parsed && parsed.error) { note += ' ' + String(parsed.error); }
      status.textContent = note;
    } catch (error) {
      status.textContent = 'Could not replay: ' + error.message;
    } finally {
      button.disabled = false;
    }
  }

  function frameLine(message, absoluteIndex) {
    var out = message.direction === 'send';
    var gap = message.opcode === 15;
    var line = el('div', gap ? 'frame gap' : (out ? 'frame up' : 'frame down'));
    if (message.injected) { line.className += ' injected'; }
    // Capture-side inflate only: on-wire bytes stayed compressed (RSV1 intact).
    if (message.compressed) { line.className += ' compressed'; }
    line.appendChild(el('span', 'dir', gap
      ? 'retention gap'
      : (out ? 'client to server' : 'server to client')));
    var meta = opcode(message.opcode) + ', ' + size(message.size);
    // size is wire length; text/body_id may already be inflated when compressed.
    if (message.compressed) { meta += ' wire'; }
    if (message.truncated && !gap) { meta += ', cut short'; }
    line.appendChild(el('span', 'meta', meta));
    // Search raw text via matchesFrame; paint pretty/coloured JSON when it applies.
    if (typeof message.text === 'string') {
      var textEl = el('span', 'text');
      line.appendChild(textEl);
      paintFramePayload(textEl, message);
    } else if (message.bodyId && !gap) {
      // Large/binary frames store payload under bodyId; load on demand.
      var bodyEl = el('span', 'text body-pending', 'loading body…');
      line.appendChild(bodyEl);
      fetch('/api/bodies/' + encodeURIComponent(message.bodyId) + '?pretty=1')
        .then(function (res) {
          if (!res.ok) { throw new Error(res.status === 404 ? 'body gone' : res.statusText); }
          return res.json();
        })
        .then(function (view) {
          bodyEl.className = 'text';
          paintSoftOrText(bodyEl, view, '(empty)');
          if (view && view.kind) {
            bodyEl.title = 'soft view: ' + view.kind + (view.note ? ' — ' + view.note : '');
          }
        })
        .catch(function (err) {
          bodyEl.className = 'text muted';
          bodyEl.textContent = 'body unavailable (' + (err && err.message ? err.message : 'error') + ')';
        });
    }
    // Single-frame replay onto the same live flow. Gaps and non-injectable
    // opcodes stay off the button: the server would refuse them closed.
    if (!gap && isInjectableOpcode(message.opcode) && typeof absoluteIndex === 'number') {
      var again = el('button', 'icon frame-replay', '↻');
      again.type = 'button';
      again.title = 'Replay this frame onto the live socket';
      again.setAttribute('aria-label', 'Replay this frame');
      again.addEventListener('click', function () {
        var status = replayStatusEl || el('p', 'hint');
        replayFrames(frameOwner, [absoluteIndex], null, 0, null, again, status);
      });
      line.appendChild(again);
    }
    return line;
  }

  function opcode(code) {
    if (code === 1) { return 'text'; }
    if (code === 2) { return 'binary'; }
    if (code === 8) { return 'close'; }
    if (code === 9) { return 'ping'; }
    if (code === 10) { return 'pong'; }
    // Capture ring-buffer marker (WS_DROPPED_OPCODE = 0xf), not a real frame.
    if (code === 15) { return 'gap'; }
    return 'opcode ' + str(code);
  }

  // A mark rather than a word, so it can sit at the head of the URL line. What
  // it did has to show somewhere all the same, and for one character that is
  // the mark itself and the tooltip behind it.
  function says(button, mark, why) {
    button.textContent = mark;
    button.title = why;
  }

  /* The mark copies the command, which is what it is wanted for nine times in
     ten. The arrow beside it is where the tenth lives, so the other things
     worth lifting out of a flow do not each need a button of their own. */

  function copyBar(flow, request, response) {
    var bar = el('div', 'copybar');
    var mark = el('button', 'icon', COPY_MARK);
    mark.type = 'button';
    mark.title = 'Copy as cURL';
    mark.setAttribute('aria-label', 'Copy as cURL');
    mark.addEventListener('click', function () {
      shut();
      copyWhat(mark, function () { return curlOf(flow.id); });
    });

    var caret = el('button', 'icon caret', '▾');
    caret.type = 'button';
    caret.title = 'Other things to copy';
    caret.setAttribute('aria-label', 'Other things to copy');
    caret.setAttribute('aria-haspopup', 'menu');
    caret.setAttribute('aria-expanded', 'false');

    var menu = el('div', 'menu');
    menu.setAttribute('role', 'menu');
    menu.hidden = true;

    function item(label, make) {
      var entry = el('button', 'mitem', label);
      entry.type = 'button';
      entry.setAttribute('role', 'menuitem');
      entry.addEventListener('click', function () {
        shut();
        copyWhat(mark, make);
      });
      menu.appendChild(entry);
    }

    item('cURL command', function () { return curlOf(flow.id); });
    item('URL', function () { return str(request.url); });
    item('Request headers', function () { return headerLines(request.headers); });
    if (request.body) {
      item('Request body', function () { return bodyText(flow.id, 'request'); });
    }
    if (response) {
      item('Response headers', function () { return headerLines(response.headers); });
      if (response.body) {
        item('Response body', function () { return bodyText(flow.id, 'response'); });
      }
    }
    // Live → saved: clipboard copy of a SavedRequest, and a direct save that
    // does not require opening the composer first.
    item('Copy as saved request', function () {
      return flowToSavedJson(flow.id);
    });
    var saveItem = el('button', 'mitem', 'Save to collection');
    saveItem.type = 'button';
    saveItem.setAttribute('role', 'menuitem');
    saveItem.addEventListener('click', function () {
      shut();
      saveFlowToCollection(flow.id, null).then(function (name) {
        says(mark, '✓', 'Saved as ' + name);
        setTimeout(function () { says(mark, COPY_MARK, 'Copy as cURL'); }, 2000);
      }).catch(function (error) {
        says(mark, '!', error.message || 'Could not save');
        setTimeout(function () { says(mark, COPY_MARK, 'Copy as cURL'); }, 3000);
      });
    });
    menu.appendChild(saveItem);

    caret.addEventListener('click', function (event) {
      // Without this the document listener below would close the menu in the
      // same click that opened it.
      event.stopPropagation();
      var open = menu.hidden;
      shut();
      menu.hidden = !open;
      caret.classList.toggle('on', open);
      caret.setAttribute('aria-expanded', open ? 'true' : 'false');
      // Which menu is the open one is settled here rather than where it was
      // built: the page holds more than one, and the last one built is not
      // the one a click elsewhere has to close.
      if (open) {
        openMenu = menu;
        openCaret = caret;
      }
    });

    bar.appendChild(mark);
    bar.appendChild(caret);
    bar.appendChild(menu);
    return bar;
  }

  var openMenu = null;
  var openCaret = null;

  function shut() {
    if (openMenu) { openMenu.hidden = true; }
    if (openCaret) {
      openCaret.classList.remove('on');
      openCaret.setAttribute('aria-expanded', 'false');
    }
  }

  document.addEventListener('click', shut);
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { shut(); }
  });

  async function curlOf(id) {
    var data = await getJson('/api/flows/' + encodeURIComponent(id) + '/curl');
    return data && typeof data.curl === 'string' ? data.curl : '';
  }

  function headerLines(headers) {
    var list = Array.isArray(headers) ? headers : [];
    var lines = [];
    for (var i = 0; i < list.length; i++) {
      if (Array.isArray(list[i])) { lines.push(str(list[i][0]) + ': ' + str(list[i][1])); }
    }
    return lines.join('\n');
  }

  async function copyWhat(button, make) {
    var text;
    try {
      text = await make();
    } catch (error) {
      says(button, '!', 'Could not copy that: ' + error.message);
      setTimeout(function () { says(button, COPY_MARK, 'Copy as cURL'); }, 3000);
      return;
    }

    try {
      if (!navigator.clipboard) { throw new Error('there is no clipboard here'); }
      await navigator.clipboard.writeText(text);
      says(button, '✓', 'Copied');
      setTimeout(function () { says(button, COPY_MARK, 'Copy as cURL'); }, 1500);
    } catch (error) {
      // Served over plain HTTP to a LAN address there is no clipboard API at
      // all, and even on localhost the write is refused unless the document
      // holds focus. What was asked for is the point, so put it on screen.
      offer(button, text);
    }
  }

  function offer(button, text) {
    var head = button.parentNode;
    var stale = head.parentNode.querySelector('pre.copy');
    if (stale) { stale.parentNode.removeChild(stale); }
    head.parentNode.insertBefore(el('pre', 'copy mono', text), head.nextSibling);
    says(button, COPY_MARK, 'There is no clipboard here, so the command is below to copy by hand');
  }

  /* ---------------------------------------------------------------- */
  /* the wire                                                          */
  /* ---------------------------------------------------------------- */

  async function getJson(url) {
    var response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) { throw new Error('the server answered ' + response.status); }
    return response.json();
  }

  function apply(event) {
    if (!event || typeof event.type !== 'string') { return; }
    if (event.type === 'flow:new' || event.type === 'flow:update' || event.type === 'flow:done') {
      upsert(event.flow, true);
      tally();
      // The pane below is a snapshot taken when the row was clicked. A flow
      // opened while it is still in flight has no response yet, and without
      // this it would keep saying so for as long as it stays open: the body
      // only appeared if you happened to click away and back.
      if (event.flow && event.flow.id === selectedId &&
          signature(event.flow) !== rendered) {
        select(selectedId, false);
      }
      return;
    }
    if (event.type === 'clear') { wipe(); return; }
    if (event.type === 'status') {
      // Surface QUIC / WireGuard / TUN facts on the chrome status strip when
      // present. Never invent a working tunnel or host capture: WG and TUN
      // are scaffold-only.
      var st = event.status || {};
      var stripBits = [];
      var titleBits = [];
      if (st.quicEnabled || st.quicPort || st.quicNote || st.reverseH3) {
        if (st.quicPort) { stripBits.push('QUIC :' + st.quicPort); }
        if (st.reverseH3) { stripBits.push('reverse ' + st.reverseH3); }
        else if (st.quicPort) { stripBits.push('accept-only'); }
        if (st.quicNote) { titleBits.push(String(st.quicNote)); }
      }
      if (st.wireguardEnabled || st.wireguardPort || st.wireguardNote) {
        if (st.wireguardPort) {
          stripBits.push('WG :' + st.wireguardPort + ' scaffold');
        }
        if (st.wireguardNote) { titleBits.push(String(st.wireguardNote)); }
      }
      if (st.tunEnabled || st.tunActive || st.tunNote) {
        if (st.tunActive) {
          stripBits.push('TUN scaffold');
        }
        if (st.tunNote) { titleBits.push(String(st.tunNote)); }
      }
      if (titleBits.length) {
        stateEl.title = titleBits.join(' ');
      }
      if (stripBits.length && (stateEl.textContent === 'live' ||
          (stateEl.textContent.indexOf('QUIC') < 0 &&
           stateEl.textContent.indexOf('WG') < 0 &&
           stateEl.textContent.indexOf('TUN') < 0))) {
        link('live', 'live · ' + stripBits.slice(0, 3).join(' · '));
      }
      // Archive button only when this run is recording finished flows to disk.
      // Without --archive (or a build without the feature) there is nothing
      // for GET /api/archive/stats to answer.
      setArchiveEnabled(!!st.archiving, st.archiveDropped);
      // The first one is the handshake. A later one means the socket dropped
      // events on the floor and this list has holes in it.
      if (greeted) { reload(); } else { greeted = true; }
      return;
    }
    if (event.type === 'ws:message' && event.id === frameOwner && frameList) {
      // Trim the retained window, then re-render so active filters apply to live
      // rows the same way they do after a filter change (including injects).
      retainFrame(event.message || {});
      renderFrames();
      return;
    }
    if (event.type === 'pause:hit' && event.pause) {
      notePause(event.pause);
      return;
    }
    if (event.type === 'pause:resolved' && event.pauseId) {
      clearPause(event.pauseId);
    }
  }

  async function reload() {
    // Events that land mid-fetch would otherwise be overwritten by the older
    // snapshot they raced.
    queue = [];
    // Resynchronising is about the list having holes in it, not about the pane
    // someone is reading. Whatever was open stays open as long as the flow
    // survived the round trip.
    var reopen = selectedId;
    try {
      var page = await getJson(flowsQueryUrl());
      wipe();
      var list = page && Array.isArray(page.flows) ? page.flows : [];
      for (var i = 0; i < list.length; i++) { upsert(list[i], false); }
    } catch (error) {
      stateEl.textContent = 'cannot read flows';
    }
    // Pauses outlive a list rebuild: refill from the hub so a lagged socket
    // cannot leave a held frame invisible until it times out.
    await loadPauses();
    var pending = queue;
    queue = null;
    for (var j = 0; j < pending.length; j++) { apply(pending[j]); }
    tally();
    if (reopen && rows.has(reopen)) { select(reopen, false); }
  }

  /* ---------------------------------------------------------------- */
  /* breakpoints and held pauses                                       */
  /* ---------------------------------------------------------------- */

  var pausesEl = document.getElementById('pauses');
  var breakBtn = document.getElementById('break');
  var breakerEl = document.getElementById('breaker');
  var breakStatusEl = document.getElementById('b-status');
  var breakListEl = document.getElementById('b-list');

  function notePause(pause) {
    if (!pause || !pause.pauseId) { return; }
    pauses.set(pause.pauseId, pause);
    paintPauses();
  }

  function clearPause(pauseId) {
    if (!pauses.delete(pauseId)) { return; }
    paintPauses();
  }

  function pausePayloadText(pause) {
    var body = null;
    if (pause && pause.kind === 'http' && pause.http) { body = pause.http; }
    else if (pause && pause.ws) { body = pause.ws; }
    if (!body) { return ''; }
    if (typeof body.text === 'string') { return body.text; }
    if (body.dataBase64) {
      try { return fromBase64(body.dataBase64); }
      catch (error) { return ''; }
    }
    return '';
  }

  function pauseOpcodeLabel(code) {
    return opcode(code);
  }

  function pauseIsHttp(pause) {
    return !!(pause && (pause.kind === 'http' || pause.http));
  }

  function headerSummary(headers) {
    var list = Array.isArray(headers) ? headers : [];
    if (!list.length) { return '0 headers'; }
    var names = [];
    for (var i = 0; i < list.length && names.length < 4; i++) {
      if (Array.isArray(list[i]) && list[i][0]) { names.push(str(list[i][0])); }
    }
    var more = list.length > names.length ? ' +' + (list.length - names.length) : '';
    return list.length + ' header' + (list.length === 1 ? '' : 's') +
      (names.length ? ' (' + names.join(', ') + more + ')' : '');
  }

  function secondsLeft(expiresAt) {
    if (typeof expiresAt !== 'number' || !isFinite(expiresAt)) { return 0; }
    return Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  }

  function paintPauses() {
    strip(pausesEl);
    pausesEl.hidden = pauses.size === 0;
    if (pauseTimer) {
      clearInterval(pauseTimer);
      pauseTimer = 0;
    }
    if (pauses.size === 0) {
      dressBreak();
      return;
    }
    var list = [];
    pauses.forEach(function (pause) { list.push(pause); });
    list.sort(function (a, b) { return (b.createdAt || 0) - (a.createdAt || 0); });
    for (var i = 0; i < list.length; i++) {
      pausesEl.appendChild(pauseCard(list[i]));
    }
    pauseTimer = setInterval(tickPauses, 1000);
    dressBreak();
  }

  function tickPauses() {
    var clocks = pausesEl.querySelectorAll('[data-expires]');
    for (var i = 0; i < clocks.length; i++) {
      var node = clocks[i];
      var left = secondsLeft(Number(node.getAttribute('data-expires')));
      node.textContent = left + 's left';
    }
  }

  function pauseCard(pause) {
    if (pauseIsHttp(pause)) { return pauseCardHttp(pause); }
    return pauseCardWs(pause);
  }

  function pauseCardHead(pause, titleText, metaText) {
    var head = el('div', 'p-head');
    head.appendChild(el('span', 'mono', titleText));
    var flowBtn = el('button', 'p-flow mono', str(pause.flowId));
    flowBtn.type = 'button';
    flowBtn.title = 'Open this flow';
    flowBtn.addEventListener('click', function () {
      if (rows.has(pause.flowId)) { select(pause.flowId); }
    });
    head.appendChild(flowBtn);
    if (metaText) { head.appendChild(el('span', 'p-meta mono', metaText)); }
    var clock = el('span', 'p-meta mono', secondsLeft(pause.expiresAt) + 's left');
    clock.setAttribute('data-expires', String(pause.expiresAt || 0));
    head.appendChild(clock);
    return head;
  }

  function pauseActions(releaseTitle, editTitle, dropTitle) {
    var actions = el('div', 'p-actions');
    var releaseBtn = el('button', 'btn', 'Release');
    releaseBtn.type = 'button';
    releaseBtn.title = releaseTitle;
    var releaseEditBtn = el('button', 'btn', 'Release edited');
    releaseEditBtn.type = 'button';
    releaseEditBtn.title = editTitle;
    var dropBtn = el('button', 'btn', 'Drop');
    dropBtn.type = 'button';
    dropBtn.title = dropTitle;
    var status = el('p', 'p-status');
    actions.appendChild(releaseBtn);
    actions.appendChild(releaseEditBtn);
    actions.appendChild(dropBtn);
    actions.appendChild(status);
    return {
      el: actions,
      releaseBtn: releaseBtn,
      releaseEditBtn: releaseEditBtn,
      dropBtn: dropBtn,
      status: status
    };
  }

  function pauseCardWs(pause) {
    var ws = pause.ws || {};
    var card = el('div', 'pause');
    card.setAttribute('data-pause-id', pause.pauseId);

    var dir = ws.direction === 'send' ? 'client to server' : 'server to client';
    var meta = dir + ' · ' + pauseOpcodeLabel(ws.opcode) + ' · ' + size(ws.size) +
      (ws.truncated ? ' · cut short' : '');
    card.appendChild(pauseCardHead(pause, 'Held WebSocket frame', meta));

    var payload = document.createElement('textarea');
    payload.className = 'p-payload';
    payload.spellcheck = false;
    payload.setAttribute('aria-label', 'Frame payload');
    payload.value = pausePayloadText(pause);
    card.appendChild(payload);

    var actions = pauseActions(
      'Forward the original frame unchanged',
      'Forward the payload in the box',
      'Do not forward this frame'
    );
    card.appendChild(actions.el);

    actions.releaseBtn.addEventListener('click', function () {
      resolvePause(pause.pauseId, 'release', null, actions.releaseBtn, actions.status);
    });
    actions.releaseEditBtn.addEventListener('click', function () {
      var body = { opcode: typeof ws.opcode === 'number' ? ws.opcode : 1 };
      if (body.opcode === 2) { body.dataBase64 = toBase64(payload.value); }
      else { body.text = payload.value; }
      resolvePause(pause.pauseId, 'release', body, actions.releaseEditBtn, actions.status);
    });
    actions.dropBtn.addEventListener('click', function () {
      resolvePause(pause.pauseId, 'drop', null, actions.dropBtn, actions.status);
    });
    return card;
  }

  function pauseCardHttp(pause) {
    var http = pause.http || {};
    var half = str(http.half || 'request');
    var isResponse = half === 'response';
    var card = el('div', 'pause');
    card.setAttribute('data-pause-id', pause.pauseId);

    var meta = half + ' · ' + str(http.method || '') + ' · ' + size(http.size) +
      (typeof http.status === 'number' ? ' · ' + http.status : '') +
      (http.truncated ? ' · cut short' : '') +
      ' · ' + headerSummary(http.headers);
    var title = isResponse ? 'Held HTTP response' : 'Held HTTP request';
    card.appendChild(pauseCardHead(pause, title, meta));
    if (http.url) {
      card.appendChild(el('div', 'p-meta mono', str(http.url)));
    }

    var line = el('div', 'p-line');
    var methodIn = document.createElement('input');
    methodIn.type = 'text';
    methodIn.className = 'p-field p-method';
    methodIn.spellcheck = false;
    methodIn.setAttribute('aria-label', 'Method');
    methodIn.value = str(http.method || 'GET');
    line.appendChild(methodIn);

    var urlIn = document.createElement('input');
    urlIn.type = 'text';
    urlIn.className = 'p-field p-url';
    urlIn.spellcheck = false;
    urlIn.setAttribute('aria-label', 'URL');
    urlIn.value = str(http.url || '');
    line.appendChild(urlIn);

    var statusIn = null;
    if (isResponse) {
      statusIn = document.createElement('input');
      statusIn.type = 'number';
      statusIn.className = 'p-field p-code';
      statusIn.min = '100';
      statusIn.max = '599';
      statusIn.setAttribute('aria-label', 'Status');
      statusIn.title = 'HTTP status code';
      statusIn.value = typeof http.status === 'number' ? String(http.status) : '200';
      line.appendChild(statusIn);
    }
    card.appendChild(line);

    var headersArea = document.createElement('textarea');
    headersArea.className = 'p-headers';
    headersArea.spellcheck = false;
    headersArea.setAttribute('aria-label', 'Headers, one per line, as Name: value');
    headersArea.placeholder = 'Headers, one per line, as Name: value';
    headersArea.value = headerLines(http.headers);
    card.appendChild(headersArea);

    var payload = document.createElement('textarea');
    payload.className = 'p-payload';
    payload.spellcheck = false;
    payload.setAttribute('aria-label', 'Body');
    payload.value = pausePayloadText(pause);
    card.appendChild(payload);

    var actions = pauseActions(
      'Forward the original message unchanged',
      'Forward with the edits in the fields',
      'Do not forward this message'
    );
    card.appendChild(actions.el);

    actions.releaseBtn.addEventListener('click', function () {
      resolvePause(pause.pauseId, 'release', null, actions.releaseBtn, actions.status);
    });
    actions.releaseEditBtn.addEventListener('click', function () {
      var body = {
        method: methodIn.value.trim() || str(http.method || 'GET'),
        url: urlIn.value.trim() || str(http.url || ''),
        headers: readHeaders(headersArea.value),
        text: payload.value
      };
      if (isResponse && statusIn) {
        var code = parseInt(statusIn.value, 10);
        if (isFinite(code)) { body.status = code; }
      }
      resolvePause(pause.pauseId, 'release', body, actions.releaseEditBtn, actions.status);
    });
    actions.dropBtn.addEventListener('click', function () {
      resolvePause(pause.pauseId, 'drop', null, actions.dropBtn, actions.status);
    });
    return card;
  }

  async function resolvePause(pauseId, action, body, button, status) {
    button.disabled = true;
    status.textContent = action === 'drop' ? 'Dropping...' : 'Releasing...';
    var url = action === 'drop'
      ? '/api/pauses/' + encodeURIComponent(pauseId) + '/drop'
      : '/api/pauses/' + encodeURIComponent(pauseId) + '/release';
    try {
      var response = await fetch(url, {
        method: 'POST',
        headers: body ? { 'content-type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        cache: 'no-store'
      });
      var raw = await response.text();
      var parsed = null;
      try { parsed = JSON.parse(raw); } catch (error) { /* may not be JSON */ }
      if (!response.ok) {
        status.textContent = (parsed && parsed.error)
          ? String(parsed.error)
          : (action + ' failed (' + response.status + ')');
        // Already gone: clear the card rather than leaving a dead hold on screen.
        if (response.status === 404 || response.status === 410) {
          clearPause(pauseId);
        }
        return;
      }
      clearPause(pauseId);
    } catch (error) {
      status.textContent = 'Could not ' + action + ': ' + error.message;
    } finally {
      button.disabled = false;
    }
  }

  async function loadPauses() {
    try {
      var page = await getJson('/api/pauses');
      pauses.clear();
      var list = page && Array.isArray(page.pauses) ? page.pauses : [];
      for (var i = 0; i < list.length; i++) {
        if (list[i] && list[i].pauseId) { pauses.set(list[i].pauseId, list[i]); }
      }
    } catch (error) {
      // Leave whatever the event socket already delivered.
    }
    paintPauses();
  }

  function breaking(on) {
    if (on) { composing(false); rewriting(false); httpRewriting(false); archiveView(false); }
    mainEl.classList.toggle('breaking', on);
    breakerEl.hidden = !on;
    if (on) { loadRules(); }
    else { dressBreak(); }
  }

  function dressBreak() {
    var armed = breakRules.some(function (r) { return r.enabled; });
    var held = pauses.size;
    breakBtn.classList.toggle('on', !breakerEl.hidden || armed || held > 0);
    if (held > 0) {
      breakBtn.textContent = 'Breakpoints (' + held + ')';
    } else if (armed) {
      breakBtn.textContent = 'Breakpoints · on';
    } else {
      breakBtn.textContent = 'Breakpoints';
    }
  }

  function breakKindIsHttp() {
    var kindEl = document.getElementById('b-kind');
    return !!(kindEl && kindEl.value === 'http');
  }

  function dressBreakKind() {
    var http = breakKindIsHttp();
    var halfEl = document.getElementById('b-http-half');
    var methodsEl = document.getElementById('b-methods');
    var dirEl = document.getElementById('b-dir');
    if (halfEl) { halfEl.hidden = !http; }
    if (methodsEl) { methodsEl.hidden = !http; }
    if (dirEl) { dirEl.hidden = http; }
  }

  function paintRules() {
    strip(breakListEl);
    if (!breakRules.length) {
      breakListEl.appendChild(el('p', 'hint',
        'No rules. Save one above to start holding WebSocket frames or HTTP messages.'));
      dressBreak();
      return;
    }
    for (var i = 0; i < breakRules.length; i++) {
      var rule = breakRules[i];
      var row = el('div', 'rule');
      row.appendChild(el('span', rule.enabled ? 'on' : 'off',
        rule.enabled ? 'enabled' : 'disabled'));
      var kind = str(rule.kind || 'ws');
      row.appendChild(el('span', 'mono', kind));
      var hosts = Array.isArray(rule.hosts) && rule.hosts.length
        ? rule.hosts.join(', ')
        : 'any host';
      row.appendChild(el('span', 'mono', hosts));
      var path = rule.pathPrefix ? str(rule.pathPrefix) : 'any path';
      row.appendChild(el('span', 'mono', path));
      if (kind === 'http') {
        var half = rule.httpHalf ? str(rule.httpHalf) : 'request';
        row.appendChild(el('span', 'mono', half));
        var methods = Array.isArray(rule.methods) && rule.methods.length
          ? rule.methods.join(', ')
          : 'any method';
        row.appendChild(el('span', 'mono', methods));
      } else {
        var dirs = Array.isArray(rule.directions) && rule.directions.length
          ? rule.directions.join(', ')
          : 'both';
        row.appendChild(el('span', 'mono', dirs));
        var ops = Array.isArray(rule.opcodes) && rule.opcodes.length
          ? rule.opcodes.map(pauseOpcodeLabel).join(', ')
          : 'text, binary';
        row.appendChild(el('span', 'mono', ops));
      }
      row.appendChild(el('span', 'mono', str(rule.timeoutMs) + ' ms'));
      breakListEl.appendChild(row);
    }
    dressBreak();
  }

  async function loadRules() {
    try {
      var page = await getJson('/api/breakpoints');
      breakRules = page && Array.isArray(page.rules) ? page.rules : [];
      if (breakRules.length) {
        var rule = breakRules[0];
        document.getElementById('b-enabled').checked = rule.enabled !== false;
        document.getElementById('b-hosts').value =
          Array.isArray(rule.hosts) ? rule.hosts.join(', ') : '';
        document.getElementById('b-path').value = rule.pathPrefix || '';
        document.getElementById('b-timeout').value =
          typeof rule.timeoutMs === 'number' ? rule.timeoutMs : 30000;
        var kindEl = document.getElementById('b-kind');
        kindEl.value = rule.kind === 'http' ? 'http' : 'ws';
        var halfEl = document.getElementById('b-http-half');
        halfEl.value = rule.httpHalf === 'response' ? 'response' : 'request';
        document.getElementById('b-methods').value =
          Array.isArray(rule.methods) ? rule.methods.join(', ') : '';
        var dir = document.getElementById('b-dir');
        if (Array.isArray(rule.directions) && rule.directions.length === 1) {
          dir.value = rule.directions[0];
        } else {
          dir.value = '';
        }
        dressBreakKind();
      }
      breakStatusEl.textContent = breakRules.length
        ? (breakRules.length + ' rule' + (breakRules.length === 1 ? '' : 's') + ' loaded')
        : 'No rules yet';
    } catch (error) {
      breakStatusEl.textContent = 'Could not load rules: ' + error.message;
      breakRules = [];
    }
    paintRules();
  }

  async function saveRules() {
    var hostsRaw = document.getElementById('b-hosts').value;
    var hosts = [];
    var parts = hostsRaw.split(',');
    for (var i = 0; i < parts.length; i++) {
      var h = parts[i].trim();
      if (h) { hosts.push(h); }
    }
    var path = document.getElementById('b-path').value.trim();
    var timeout = parseInt(document.getElementById('b-timeout').value, 10);
    if (!isFinite(timeout) || timeout < 1000) { timeout = 30000; }
    if (timeout > 300000) { timeout = 300000; }
    var kind = document.getElementById('b-kind').value === 'http' ? 'http' : 'ws';
    var dir = document.getElementById('b-dir').value;
    var rule = {
      id: kind === 'http' ? 'http-1' : 'ws-1',
      enabled: document.getElementById('b-enabled').checked,
      kind: kind,
      hosts: hosts,
      pathPrefix: path || null,
      directions: kind === 'ws' && dir ? [dir] : [],
      opcodes: [],
      timeoutMs: timeout,
      methods: [],
      httpHalf: null
    };
    if (kind === 'http') {
      var half = document.getElementById('b-http-half').value;
      rule.httpHalf = half === 'response' ? 'response' : 'request';
      var methodsRaw = document.getElementById('b-methods').value;
      var methods = [];
      var mparts = methodsRaw.split(',');
      for (var mi = 0; mi < mparts.length; mi++) {
        var m = mparts[mi].trim();
        if (m) { methods.push(m.toUpperCase()); }
      }
      rule.methods = methods;
    }
    breakStatusEl.textContent = 'Saving...';
    try {
      var response = await fetch('/api/breakpoints', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rules: [rule] }),
        cache: 'no-store'
      });
      var raw = await response.text();
      var parsed = null;
      try { parsed = JSON.parse(raw); } catch (error) { /* may not be JSON */ }
      if (!response.ok) {
        breakStatusEl.textContent = (parsed && parsed.error)
          ? String(parsed.error)
          : ('Save failed (' + response.status + ')');
        return;
      }
      breakRules = parsed && Array.isArray(parsed.rules) ? parsed.rules : [rule];
      if (!rule.enabled) {
        breakStatusEl.textContent = 'Saved. Rule is disabled; traffic is not held.';
      } else if (kind === 'http') {
        breakStatusEl.textContent =
          'Saved. Matching HTTP ' + str(rule.httpHalf || 'request') +
          's will pause until release, drop, or timeout.';
      } else {
        breakStatusEl.textContent =
          'Saved. Matching WebSocket frames will pause until release, drop, or timeout.';
      }
      paintRules();
    } catch (error) {
      breakStatusEl.textContent = 'Could not save: ' + error.message;
    }
  }

  async function clearRules() {
    breakStatusEl.textContent = 'Clearing...';
    try {
      var response = await fetch('/api/breakpoints', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rules: [] }),
        cache: 'no-store'
      });
      if (!response.ok) {
        breakStatusEl.textContent = 'Clear failed (' + response.status + ')';
        return;
      }
      breakRules = [];
      document.getElementById('b-hosts').value = '';
      document.getElementById('b-path').value = '';
      document.getElementById('b-timeout').value = '30000';
      document.getElementById('b-enabled').checked = true;
      document.getElementById('b-dir').value = '';
      document.getElementById('b-kind').value = 'ws';
      document.getElementById('b-http-half').value = 'request';
      document.getElementById('b-methods').value = '';
      dressBreakKind();
      breakStatusEl.textContent = 'All rules cleared. Traffic is no longer held.';
      paintRules();
    } catch (error) {
      breakStatusEl.textContent = 'Could not clear: ' + error.message;
    }
  }

  /* ---------------------------------------------------------------- */
  /* WebSocket rewrite / drop rules                                    */
  /* ---------------------------------------------------------------- */

  var rewriteBtn = document.getElementById('rewrite');
  var rewriterEl = document.getElementById('rewriter');
  var rewriteStatusEl = document.getElementById('w-status');
  var rewriteListEl = document.getElementById('w-list');
  var rewriteRules = [];

  function rewriting(on) {
    if (on) { composing(false); breaking(false); httpRewriting(false); archiveView(false); }
    mainEl.classList.toggle('rewriting', on);
    rewriterEl.hidden = !on;
    if (on) { loadRewriteRules(); }
    else { dressRewrite(); }
  }

  function dressRewrite() {
    var armed = rewriteRules.some(function (r) {
      return r && (r.drop || r.replaceText || r.replaceBase64);
    });
    rewriteBtn.classList.toggle('on', !rewriterEl.hidden || armed);
    if (armed) {
      rewriteBtn.textContent = 'WS rewrite · on';
    } else {
      rewriteBtn.textContent = 'WS rewrite';
    }
  }

  function paintRewriteRules() {
    strip(rewriteListEl);
    if (!rewriteRules.length) {
      rewriteListEl.appendChild(el('p', 'hint',
        'No rules. Save one above to replace or drop matching frames.'));
      dressRewrite();
      return;
    }
    for (var i = 0; i < rewriteRules.length; i++) {
      var rule = rewriteRules[i];
      var row = el('div', 'rule');
      var action = rule.drop
        ? 'drop'
        : (rule.replaceText != null
          ? 'replace text'
          : (rule.replaceBase64 ? 'replace base64' : 'noop'));
      row.appendChild(el('span', rule.drop || rule.replaceText || rule.replaceBase64 ? 'on' : 'off',
        action));
      var hosts = Array.isArray(rule.hosts) && rule.hosts.length
        ? rule.hosts.join(', ')
        : 'any host';
      row.appendChild(el('span', 'mono', hosts));
      var path = rule.pathPrefix ? str(rule.pathPrefix) : 'any path';
      row.appendChild(el('span', 'mono', path));
      var dirs = Array.isArray(rule.directions) && rule.directions.length
        ? rule.directions.join(', ')
        : 'both';
      row.appendChild(el('span', 'mono', dirs));
      var ops = Array.isArray(rule.opcodes) && rule.opcodes.length
        ? rule.opcodes.map(pauseOpcodeLabel).join(', ')
        : 'text, binary';
      row.appendChild(el('span', 'mono', ops));
      if (rule.textRegex) {
        row.appendChild(el('span', 'mono', '/' + str(rule.textRegex) + '/'));
      }
      if (rule.replaceText != null && !rule.drop) {
        row.appendChild(el('span', 'mono', '-> ' + str(rule.replaceText).slice(0, 40)));
      }
      rewriteListEl.appendChild(row);
    }
    dressRewrite();
  }

  async function loadRewriteRules() {
    try {
      var page = await getJson('/api/ws-rewrite');
      rewriteRules = page && Array.isArray(page.rules) ? page.rules : [];
      if (rewriteRules.length) {
        var rule = rewriteRules[0];
        document.getElementById('w-hosts').value =
          Array.isArray(rule.hosts) ? rule.hosts.join(', ') : '';
        document.getElementById('w-path').value = rule.pathPrefix || '';
        document.getElementById('w-regex').value = rule.textRegex || '';
        var dir = document.getElementById('w-dir');
        if (Array.isArray(rule.directions) && rule.directions.length === 1) {
          dir.value = rule.directions[0];
        } else {
          dir.value = '';
        }
        var action = document.getElementById('w-action');
        action.value = rule.drop ? 'drop' : 'replace';
        document.getElementById('w-replace').value = rule.replaceText || '';
      }
      rewriteStatusEl.textContent = rewriteRules.length
        ? (rewriteRules.length + ' rule' + (rewriteRules.length === 1 ? '' : 's') + ' loaded')
        : 'No rules yet';
    } catch (error) {
      rewriteStatusEl.textContent = 'Could not load rules: ' + error.message;
      rewriteRules = [];
    }
    paintRewriteRules();
  }

  async function saveRewriteRules() {
    var hostsRaw = document.getElementById('w-hosts').value;
    var hosts = [];
    var parts = hostsRaw.split(',');
    for (var i = 0; i < parts.length; i++) {
      var h = parts[i].trim();
      if (h) { hosts.push(h); }
    }
    var path = document.getElementById('w-path').value.trim();
    var regex = document.getElementById('w-regex').value.trim();
    var dir = document.getElementById('w-dir').value;
    var action = document.getElementById('w-action').value;
    var replaceText = document.getElementById('w-replace').value;
    if (action === 'replace' && replaceText === '') {
      rewriteStatusEl.textContent = 'Replacement text is required when the action is replace.';
      return;
    }
    var rule = {
      hosts: hosts,
      pathPrefix: path || null,
      directions: dir ? [dir] : [],
      opcodes: [],
      textRegex: regex || null,
      drop: action === 'drop',
      replaceText: action === 'replace' ? replaceText : null,
      replaceBase64: null
    };
    rewriteStatusEl.textContent = 'Saving...';
    try {
      var response = await fetch('/api/ws-rewrite', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rules: [rule] }),
        cache: 'no-store'
      });
      var raw = await response.text();
      var parsed = null;
      try { parsed = JSON.parse(raw); } catch (error) { /* may not be JSON */ }
      if (!response.ok) {
        rewriteStatusEl.textContent = (parsed && parsed.error)
          ? String(parsed.error)
          : ('Save failed (' + response.status + ')');
        return;
      }
      rewriteRules = parsed && Array.isArray(parsed.rules) ? parsed.rules : [rule];
      rewriteStatusEl.textContent = action === 'drop'
        ? 'Saved. Matching frames will be dropped (notes only on the flow).'
        : 'Saved. Matching frames will have their payload replaced on the wire.';
      paintRewriteRules();
    } catch (error) {
      rewriteStatusEl.textContent = 'Could not save: ' + error.message;
    }
  }

  async function clearRewriteRules() {
    rewriteStatusEl.textContent = 'Clearing...';
    try {
      var response = await fetch('/api/ws-rewrite', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rules: [] }),
        cache: 'no-store'
      });
      if (!response.ok) {
        rewriteStatusEl.textContent = 'Clear failed (' + response.status + ')';
        return;
      }
      rewriteRules = [];
      document.getElementById('w-hosts').value = '';
      document.getElementById('w-path').value = '';
      document.getElementById('w-regex').value = '';
      document.getElementById('w-dir').value = '';
      document.getElementById('w-action').value = 'drop';
      document.getElementById('w-replace').value = '';
      rewriteStatusEl.textContent = 'All rewrite rules cleared. Frames pass through unchanged.';
      paintRewriteRules();
    } catch (error) {
      rewriteStatusEl.textContent = 'Could not clear: ' + error.message;
    }
  }

  /* ---------------------------------------------------------------- */
  /* HTTP rewrite / map-local mock rules                               */
  /* ---------------------------------------------------------------- */

  var httpRewriteBtn = document.getElementById('httprewrite');
  var httpRewriterEl = document.getElementById('httprewriter');
  var httpRewriteStatusEl = document.getElementById('hr-status');
  var httpRewriteListEl = document.getElementById('hr-list');
  var httpRewriteRules = [];

  function httpRewriting(on) {
    if (on) { composing(false); breaking(false); rewriting(false); archiveView(false); }
    mainEl.classList.toggle('httprewriting', on);
    httpRewriterEl.hidden = !on;
    if (on) { loadHttpRewriteRules(); }
    else { dressHttpRewrite(); }
  }

  function parseFindReplaceLines(text) {
    var out = [];
    var lines = String(text || '').split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!line || !line.trim()) { continue; }
      var idx = line.indexOf('=>');
      if (idx < 0) { continue; }
      out.push({
        find: line.slice(0, idx),
        replace: line.slice(idx + 2)
      });
    }
    return out;
  }

  function formatFindReplaceLines(list) {
    if (!Array.isArray(list) || !list.length) { return ''; }
    var lines = [];
    for (var i = 0; i < list.length; i++) {
      var item = list[i];
      if (!item || item.find == null) { continue; }
      lines.push(str(item.find) + '=>' + str(item.replace != null ? item.replace : ''));
    }
    return lines.join('\n');
  }

  function readBodyRewrite(findId, replaceId, maxId) {
    var find = document.getElementById(findId).value;
    var replace = document.getElementById(replaceId).value;
    var maxRaw = document.getElementById(maxId).value.trim();
    // Backend BodyRewrite.maxBytes is u64; 0 means the server default (1 MiB).
    var maxBytes = 0;
    if (maxRaw !== '') {
      var n = parseInt(maxRaw, 10);
      if (isFinite(n) && n > 0) { maxBytes = n; }
    }
    var replacements = [];
    if (find !== '') {
      replacements.push({ find: find, replace: replace });
    }
    if (!replacements.length) { return null; }
    return { replacements: replacements, maxBytes: maxBytes };
  }

  function fillBodyRewrite(body, findId, replaceId, maxId) {
    var findEl = document.getElementById(findId);
    var replaceEl = document.getElementById(replaceId);
    var maxEl = document.getElementById(maxId);
    findEl.value = '';
    replaceEl.value = '';
    maxEl.value = '';
    if (!body) { return; }
    var list = Array.isArray(body.replacements) ? body.replacements : [];
    if (list.length && list[0]) {
      findEl.value = list[0].find != null ? str(list[0].find) : '';
      replaceEl.value = list[0].replace != null ? str(list[0].replace) : '';
    }
    if (typeof body.maxBytes === 'number' && body.maxBytes > 0) {
      maxEl.value = String(body.maxBytes);
    }
  }

  function ruleHasPathBodyRewrites(rule) {
    if (!rule) { return false; }
    if (Array.isArray(rule.pathReplacements) && rule.pathReplacements.length) { return true; }
    if (Array.isArray(rule.queryReplacements) && rule.queryReplacements.length) { return true; }
    if (rule.requestBody && Array.isArray(rule.requestBody.replacements) &&
        rule.requestBody.replacements.length) { return true; }
    if (rule.responseBody && Array.isArray(rule.responseBody.replacements) &&
        rule.responseBody.replacements.length) { return true; }
    return false;
  }

  function dressHttpRewrite() {
    var armed = httpRewriteRules.some(function (r) {
      return r && (r.mock || r.to || ruleHasPathBodyRewrites(r) ||
        (Array.isArray(r.requestHeaders) && r.requestHeaders.length) ||
        (Array.isArray(r.responseHeaders) && r.responseHeaders.length));
    });
    httpRewriteBtn.classList.toggle('on', !httpRewriterEl.hidden || armed);
    if (armed) {
      httpRewriteBtn.textContent = 'HTTP rewrite · on';
    } else {
      httpRewriteBtn.textContent = 'HTTP rewrite';
    }
  }

  function paintHttpRewriteRules() {
    strip(httpRewriteListEl);
    if (!httpRewriteRules.length) {
      httpRewriteListEl.appendChild(el('p', 'hint',
        'No rules. Save one above to mock or rewrite matching HTTP traffic.'));
      dressHttpRewrite();
      return;
    }
    for (var i = 0; i < httpRewriteRules.length; i++) {
      var rule = httpRewriteRules[i];
      var row = el('div', 'rule');
      if (rule.mock) {
        row.appendChild(el('span', 'on', 'mock ' + str(rule.mock.status || 200)));
      } else if (rule.to) {
        row.appendChild(el('span', 'on', 'map-host'));
      } else if (ruleHasPathBodyRewrites(rule)) {
        row.appendChild(el('span', 'on', 'rewrite'));
      } else {
        row.appendChild(el('span', 'on', 'headers'));
      }
      var hosts = Array.isArray(rule.hosts) && rule.hosts.length
        ? rule.hosts.join(', ')
        : 'any host';
      row.appendChild(el('span', 'mono', hosts));
      var methods = Array.isArray(rule.methods) && rule.methods.length
        ? rule.methods.join(', ')
        : 'any method';
      row.appendChild(el('span', 'mono', methods));
      var path = rule.pathPrefix ? str(rule.pathPrefix) : 'any path';
      row.appendChild(el('span', 'mono', path));
      if (rule.mock) {
        if (rule.mock.bodyFile) {
          row.appendChild(el('span', 'mono', 'file: ' + str(rule.mock.bodyFile)));
        } else if (rule.mock.body != null && str(rule.mock.body) !== '') {
          row.appendChild(el('span', 'mono', 'body: ' + str(rule.mock.body).slice(0, 40)));
        }
      }
      if (Array.isArray(rule.pathReplacements) && rule.pathReplacements.length) {
        row.appendChild(el('span', 'mono',
          'path×' + rule.pathReplacements.length));
      }
      if (Array.isArray(rule.queryReplacements) && rule.queryReplacements.length) {
        row.appendChild(el('span', 'mono',
          'query×' + rule.queryReplacements.length));
      }
      if (rule.requestBody && Array.isArray(rule.requestBody.replacements) &&
          rule.requestBody.replacements.length) {
        row.appendChild(el('span', 'mono', 'req-body'));
      }
      if (rule.responseBody && Array.isArray(rule.responseBody.replacements) &&
          rule.responseBody.replacements.length) {
        row.appendChild(el('span', 'mono', 'res-body'));
      }
      if (rule.to && rule.to.host) {
        var target = str(rule.to.host);
        if (rule.to.port) { target += ':' + str(rule.to.port); }
        row.appendChild(el('span', 'mono', '-> ' + target));
      }
      httpRewriteListEl.appendChild(row);
    }
    dressHttpRewrite();
  }

  function fillHttpRewriteForm(rule) {
    document.getElementById('hr-hosts').value =
      Array.isArray(rule.hosts) ? rule.hosts.join(', ') : '';
    document.getElementById('hr-methods').value =
      Array.isArray(rule.methods) ? rule.methods.join(', ') : '';
    document.getElementById('hr-path').value = rule.pathPrefix || '';
    var mock = rule.mock || {};
    document.getElementById('hr-mock-status').value =
      typeof mock.status === 'number' && mock.status > 0 ? mock.status : 200;
    var headerLines = [];
    var headers = Array.isArray(mock.headers) ? mock.headers : [];
    for (var hi = 0; hi < headers.length; hi++) {
      var pair = headers[hi];
      if (Array.isArray(pair) && pair.length >= 2) {
        headerLines.push(str(pair[0]) + ': ' + str(pair[1]));
      }
    }
    document.getElementById('hr-headers').value = headerLines.join('\n');
    document.getElementById('hr-body').value = mock.body != null ? str(mock.body) : '';
    document.getElementById('hr-body-file').value = mock.bodyFile || '';
    document.getElementById('hr-path-repl').value =
      formatFindReplaceLines(rule.pathReplacements);
    document.getElementById('hr-query-repl').value =
      formatFindReplaceLines(rule.queryReplacements);
    fillBodyRewrite(rule.requestBody, 'hr-req-body-find', 'hr-req-body-replace', 'hr-req-body-max');
    fillBodyRewrite(rule.responseBody, 'hr-res-body-find', 'hr-res-body-replace', 'hr-res-body-max');
  }

  async function loadHttpRewriteRules() {
    try {
      var page = await getJson('/api/rewrite');
      httpRewriteRules = page && Array.isArray(page.rules) ? page.rules : [];
      if (httpRewriteRules.length) {
        var pick = httpRewriteRules[0];
        for (var i = 0; i < httpRewriteRules.length; i++) {
          if (httpRewriteRules[i] && (httpRewriteRules[i].mock ||
              ruleHasPathBodyRewrites(httpRewriteRules[i]))) {
            pick = httpRewriteRules[i];
            break;
          }
        }
        fillHttpRewriteForm(pick);
      }
      httpRewriteStatusEl.textContent = httpRewriteRules.length
        ? (httpRewriteRules.length + ' rule' + (httpRewriteRules.length === 1 ? '' : 's') + ' loaded')
        : 'No rules yet';
    } catch (error) {
      httpRewriteStatusEl.textContent = 'Could not load rules: ' + error.message;
      httpRewriteRules = [];
    }
    paintHttpRewriteRules();
  }

  async function saveHttpRewriteRules() {
    var hostsRaw = document.getElementById('hr-hosts').value;
    var hosts = [];
    var parts = hostsRaw.split(',');
    for (var i = 0; i < parts.length; i++) {
      var h = parts[i].trim();
      if (h) { hosts.push(h); }
    }
    var methodsRaw = document.getElementById('hr-methods').value;
    var methods = [];
    var mparts = methodsRaw.split(',');
    for (var mi = 0; mi < mparts.length; mi++) {
      var m = mparts[mi].trim();
      if (m) { methods.push(m.toUpperCase()); }
    }
    var path = document.getElementById('hr-path').value.trim();
    var status = parseInt(document.getElementById('hr-mock-status').value, 10);
    if (!isFinite(status) || status < 100 || status > 599) { status = 200; }
    var bodyText = document.getElementById('hr-body').value;
    var bodyFile = document.getElementById('hr-body-file').value.trim();
    var mockHeaders = readHeaders(document.getElementById('hr-headers').value);
    var pathReplacements = parseFindReplaceLines(
      document.getElementById('hr-path-repl').value);
    var queryReplacements = parseFindReplaceLines(
      document.getElementById('hr-query-repl').value);
    var requestBody = readBodyRewrite(
      'hr-req-body-find', 'hr-req-body-replace', 'hr-req-body-max');
    var responseBody = readBodyRewrite(
      'hr-res-body-find', 'hr-res-body-replace', 'hr-res-body-max');
    var hasMockContent = bodyText !== '' || bodyFile || mockHeaders.length ||
      status !== 200;
    var hasRewrites = pathReplacements.length || queryReplacements.length ||
      requestBody || responseBody;
    // Keep mock when the form has mock content, or when there is nothing else
    // (map-local default). Pure path/query/body rewrite rules omit mock so the
    // origin is still dialled.
    var mock = null;
    if (hasMockContent || !hasRewrites) {
      mock = {
        status: status,
        headers: mockHeaders,
        body: bodyText !== '' ? bodyText : null,
        bodyFile: bodyFile || null
      };
    }
    var rule = {
      hosts: hosts,
      methods: methods,
      pathPrefix: path || null,
      requestHeaders: [],
      responseHeaders: [],
      to: null,
      pathReplacements: pathReplacements,
      queryReplacements: queryReplacements,
      requestBody: requestBody,
      responseBody: responseBody,
      mock: mock
    };
    httpRewriteStatusEl.textContent = 'Saving...';
    try {
      var response = await fetch('/api/rewrite', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rules: [rule] }),
        cache: 'no-store'
      });
      var raw = await response.text();
      var parsed = null;
      try { parsed = JSON.parse(raw); } catch (error) { /* may not be JSON */ }
      if (!response.ok) {
        httpRewriteStatusEl.textContent = (parsed && parsed.error)
          ? String(parsed.error)
          : ('Save failed (' + response.status + ')');
        return;
      }
      httpRewriteRules = parsed && Array.isArray(parsed.rules) ? parsed.rules : [rule];
      if (mock) {
        httpRewriteStatusEl.textContent =
          'Saved. Matching requests get a mock ' + status + ' without dialling the origin.';
      } else {
        httpRewriteStatusEl.textContent =
          'Saved. Matching requests get path, query and body rewrites on the wire.';
      }
      paintHttpRewriteRules();
    } catch (error) {
      httpRewriteStatusEl.textContent = 'Could not save: ' + error.message;
    }
  }

  async function clearHttpRewriteRules() {
    httpRewriteStatusEl.textContent = 'Clearing...';
    try {
      var response = await fetch('/api/rewrite', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rules: [] }),
        cache: 'no-store'
      });
      if (!response.ok) {
        httpRewriteStatusEl.textContent = 'Clear failed (' + response.status + ')';
        return;
      }
      httpRewriteRules = [];
      document.getElementById('hr-hosts').value = '';
      document.getElementById('hr-methods').value = '';
      document.getElementById('hr-path').value = '';
      document.getElementById('hr-mock-status').value = '200';
      document.getElementById('hr-headers').value = '';
      document.getElementById('hr-body').value = '';
      document.getElementById('hr-body-file').value = '';
      document.getElementById('hr-path-repl').value = '';
      document.getElementById('hr-query-repl').value = '';
      document.getElementById('hr-req-body-find').value = '';
      document.getElementById('hr-req-body-replace').value = '';
      document.getElementById('hr-req-body-max').value = '';
      document.getElementById('hr-res-body-find').value = '';
      document.getElementById('hr-res-body-replace').value = '';
      document.getElementById('hr-res-body-max').value = '';
      httpRewriteStatusEl.textContent = 'All HTTP rewrite rules cleared. Requests go upstream again.';
      paintHttpRewriteRules();
    } catch (error) {
      httpRewriteStatusEl.textContent = 'Could not clear: ' + error.message;
    }
  }

  function link(kind, text) {
    dotEl.className = 'dot ' + kind;
    stateEl.textContent = text;
  }

  function connect() {
    var socket;
    try {
      var scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
      socket = new WebSocket(scheme + '//' + location.host + '/api/stream');
    } catch (error) {
      retry();
      return;
    }

    socket.addEventListener('open', function () {
      backoff = RETRY_MIN;
      greeted = false;
      link('live', 'live');
      reload();
    });
    socket.addEventListener('message', function (event) {
      var data;
      try { data = JSON.parse(event.data); } catch (error) { return; }
      if (queue) { queue.push(data); } else { apply(data); }
    });
    socket.addEventListener('close', retry);
  }

  // The server is restarted constantly while it is being worked on, so this
  // reconnects on its own rather than waiting for a reload.
  function retry() {
    link('gone', 'reconnecting');
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, RETRY_MAX);
  }

  /* ---- the composer: the half of this tool that sends rather than watches ---- */

  var composerEl = document.getElementById('composer');
  var composeBtn = document.getElementById('compose');
  var outEl = document.getElementById('c-out');
  var urlIn = document.getElementById('c-url');
  var urlMirror = document.getElementById('c-url-mirror');

  /* Paint scheme, host, path and query as coloured spans. Used by the
     composer mirror, detail head and list path. Spans only: text never
     reaches the HTML parser. Query key[=value] groups into .u-pair so
     hover/click lights the parameter and its value together. */
  function fillUrlTokens(into, text) {
    if (!into) { return; }
    strip(into);
    if (!text) { return; }
    var parts = tokenizeUrl(text);
    var i = 0;
    while (i < parts.length) {
      if (parts[i].cls === 'u-key') {
        var pair = el('span', 'u-pair');
        pair.appendChild(el('span', parts[i].cls, parts[i].text));
        i += 1;
        // Optional =value right after the key.
        if (i < parts.length && parts[i].cls === 'u-sep' && parts[i].text === '=') {
          pair.appendChild(el('span', parts[i].cls, parts[i].text));
          i += 1;
          if (i < parts.length && parts[i].cls === 'u-val') {
            pair.appendChild(el('span', parts[i].cls, parts[i].text));
            i += 1;
          }
        }
        wireUrlPair(pair, into);
        into.appendChild(pair);
        continue;
      }
      into.appendChild(el('span', parts[i].cls, parts[i].text));
      i += 1;
    }
  }

  // Click selects one pair at a time inside its URL cell; second click clears.
  function wireUrlPair(pair, root) {
    pair.title = 'Highlight this parameter';
    pair.addEventListener('click', function (event) {
      // Keep the list row from changing selection when picking a query param.
      event.stopPropagation();
      var was = pair.classList.contains('on');
      var all = root.querySelectorAll('.u-pair.on');
      for (var j = 0; j < all.length; j++) { all[j].classList.remove('on'); }
      if (!was) { pair.classList.add('on'); }
    });
  }

  /* Paint scheme, host, path and query parameters under the transparent URL
     input. Spans only: captured or typed text never reaches the HTML parser. */
  function paintUrlMirror() {
    if (!urlMirror || !urlIn) { return; }
    fillUrlTokens(urlMirror, urlIn.value);
    urlMirror.scrollLeft = urlIn.scrollLeft;
  }

  // Break a typed URL into coloured runs without requiring a complete URL.
  // `{{var}}` wins over every other class so environment placeholders stay
  // obvious while the rest of the string still tokenises around them.
  function tokenizeUrl(raw) {
    var text = String(raw || '');
    var n = text.length;
    var out = [];

    function push(cls, from, to) {
      if (to <= from) { return; }
      var j = from;
      while (j < to) {
        if (j + 1 < to && text.charAt(j) === '{' && text.charAt(j + 1) === '{') {
          var close = text.indexOf('}}', j + 2);
          if (close < 0 || close + 2 > to) {
            // Unclosed {{... : still mark the rest of this range as a var so
            // half-typed placeholders do not look like path text mid-edit.
            if (j > from) { out.push({ cls: cls, text: text.slice(from, j) }); }
            out.push({ cls: 'u-var', text: text.slice(j, to) });
            return;
          }
          if (j > from) { out.push({ cls: cls, text: text.slice(from, j) }); }
          out.push({ cls: 'u-var', text: text.slice(j, close + 2) });
          from = close + 2;
          j = from;
          continue;
        }
        j += 1;
      }
      if (to > from) { out.push({ cls: cls, text: text.slice(from, to) }); }
    }

    function isSchemeChar(ch) {
      return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || ch === '+' || ch === '.' || ch === '-';
    }

    var i = 0;
    // scheme://  when present; otherwise the first segment is the host.
    var schemeAt = -1;
    if (n > 0 && ((text.charAt(0) >= 'a' && text.charAt(0) <= 'z') ||
        (text.charAt(0) >= 'A' && text.charAt(0) <= 'Z'))) {
      var s = 1;
      while (s < n && isSchemeChar(text.charAt(s))) { s += 1; }
      if (s < n && text.charAt(s) === ':') { schemeAt = s; }
    }
    if (schemeAt >= 0) {
      push('u-scheme', 0, schemeAt + 1);
      i = schemeAt + 1;
      if (i + 1 < n && text.charAt(i) === '/' && text.charAt(i + 1) === '/') {
        push('u-sep', i, i + 2);
        i += 2;
      }
    }

    // Authority: [userinfo@]host[:port] until / ? # or end.
    if (schemeAt >= 0 || i === 0) {
      var authEnd = i;
      while (authEnd < n) {
        var ac = text.charAt(authEnd);
        if (ac === '/' || ac === '?' || ac === '#') { break; }
        authEnd += 1;
      }
      if (authEnd > i) {
        var at = text.lastIndexOf('@', authEnd - 1);
        var hostStart = i;
        if (at >= i) {
          push('u-user', i, at);
          push('u-sep', at, at + 1);
          hostStart = at + 1;
        }
        // Host vs port: last bare colon (ignore IPv6 brackets by only taking
        // a trailing :digits port after the last ']').
        var colon = text.lastIndexOf(':', authEnd - 1);
        if (colon >= hostStart) {
          // Port is a trailing :digits only; IPv6 brackets put other colons
          // before ']', so a colon after ']' (or none) is the port marker.
          var bracket = text.lastIndexOf(']', authEnd - 1);
          var digits = colon + 1 < authEnd;
          var d = colon + 1;
          while (digits && d < authEnd) {
            var dc = text.charAt(d);
            if (dc < '0' || dc > '9') { digits = false; break; }
            d += 1;
          }
          // Empty ":port" (just a trailing colon) still counts as a port slot.
          if (bracket < colon && (colon + 1 === authEnd || digits)) {
            push('u-host', hostStart, colon);
            push('u-sep', colon, colon + 1);
            push('u-port', colon + 1, authEnd);
          } else {
            push('u-host', hostStart, authEnd);
          }
        } else {
          push('u-host', hostStart, authEnd);
        }
        i = authEnd;
      }
    }

    // Path segments until ? or #.
    if (i < n && text.charAt(i) !== '?' && text.charAt(i) !== '#') {
      var pathEnd = i;
      while (pathEnd < n) {
        var pc = text.charAt(pathEnd);
        if (pc === '?' || pc === '#') { break; }
        pathEnd += 1;
      }
      var p = i;
      while (p < pathEnd) {
        if (text.charAt(p) === '/') {
          push('u-sep', p, p + 1);
          p += 1;
          continue;
        }
        var seg = p;
        while (seg < pathEnd && text.charAt(seg) !== '/') { seg += 1; }
        push('u-path', p, seg);
        p = seg;
      }
      i = pathEnd;
    }

    // Query: ?key=value&key=value
    if (i < n && text.charAt(i) === '?') {
      push('u-sep', i, i + 1);
      i += 1;
      while (i < n && text.charAt(i) !== '#') {
        if (text.charAt(i) === '&') {
          push('u-sep', i, i + 1);
          i += 1;
          continue;
        }
        var keyEnd = i;
        while (keyEnd < n) {
          var kc = text.charAt(keyEnd);
          if (kc === '=' || kc === '&' || kc === '#') { break; }
          keyEnd += 1;
        }
        push('u-key', i, keyEnd);
        i = keyEnd;
        if (i < n && text.charAt(i) === '=') {
          push('u-sep', i, i + 1);
          i += 1;
          var valEnd = i;
          while (valEnd < n) {
            var vc = text.charAt(valEnd);
            if (vc === '&' || vc === '#') { break; }
            valEnd += 1;
          }
          push('u-val', i, valEnd);
          i = valEnd;
        }
      }
    }

    // Fragment.
    if (i < n && text.charAt(i) === '#') {
      push('u-sep', i, i + 1);
      i += 1;
      push('u-frag', i, n);
      i = n;
    }

    // Anything left (malformed remainder) as plain path colour.
    if (i < n) { push('u-path', i, n); }
    return out;
  }

  /* Query-parameter table (Postman-style). Rows drive the URL query when the
     table is edited; typing in the URL bar re-parses into rows. Disabled rows
     stay in the table but drop out of the URL until re-checked. */
  var paramsBody = document.getElementById('c-params-body');
  // true while the table is rewriting the URL, so the URL→table pass is skipped.
  var paramsFromTable = false;
  // Disabled (unchecked) rows live only in the table. URL edits would drop
  // them; keep a copy keyed by position until the next full table rebuild that
  // still has room for them — simpler: hold extra off-rows and re-append after
  // a URL-driven rebuild when the query text itself did not change from us.
  var paramsOff = [];

  function decodeParam(raw) {
    try { return decodeURIComponent(String(raw || '').replace(/\+/g, ' ')); }
    catch (error) { return String(raw || ''); }
  }

  // encodeURIComponent turns {{var}} into %7B%7Bvar%7D%7D; restore braces so
  // environment placeholders survive a round-trip through the table.
  function encodeParam(raw) {
    return encodeURIComponent(String(raw || ''))
      .replace(/%7B/gi, '{')
      .replace(/%7D/gi, '}');
  }

  // Split into base (before ?), query (between ? and #), hash (from #).
  function splitUrlParts(url) {
    var text = String(url || '');
    var hash = '';
    var hashAt = text.indexOf('#');
    if (hashAt >= 0) {
      hash = text.slice(hashAt);
      text = text.slice(0, hashAt);
    }
    var query = '';
    var qAt = text.indexOf('?');
    var base = text;
    if (qAt >= 0) {
      base = text.slice(0, qAt);
      query = text.slice(qAt + 1);
    }
    return { base: base, query: query, hash: hash };
  }

  function parseQueryString(query) {
    var rows = [];
    if (!query) { return rows; }
    var parts = String(query).split('&');
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      // A trailing & leaves an empty segment; skip so the blank add-row is alone.
      if (part === '' && i === parts.length - 1) { continue; }
      var eq = part.indexOf('=');
      var key = eq < 0 ? part : part.slice(0, eq);
      var val = eq < 0 ? '' : part.slice(eq + 1);
      rows.push({ on: true, key: decodeParam(key), value: decodeParam(val) });
    }
    return rows;
  }

  function buildQueryString(rows) {
    var bits = [];
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      if (!row.on) { continue; }
      var key = str(row.key);
      var val = str(row.value);
      // Empty trailing add-row must not become "?=" on the wire.
      if (!key && !val) { continue; }
      if (!key) { continue; }
      bits.push(encodeParam(key) + '=' + encodeParam(val));
    }
    return bits.join('&');
  }

  function readParamRows() {
    var rows = [];
    if (!paramsBody) { return rows; }
    var trs = paramsBody.querySelectorAll('tr');
    for (var i = 0; i < trs.length; i++) {
      var tr = trs[i];
      var onEl = tr.querySelector('input[type="checkbox"]');
      var keyEl = tr.querySelector('input.c-params-key');
      var valEl = tr.querySelector('input.c-params-val');
      if (!keyEl || !valEl) { continue; }
      rows.push({
        on: onEl ? !!onEl.checked : true,
        key: keyEl.value,
        value: valEl.value
      });
    }
    return rows;
  }

  function writeUrlFromParams() {
    if (!urlIn) { return; }
    var rows = readParamRows();
    var parts = splitUrlParts(urlIn.value);
    var query = buildQueryString(rows);
    var next = parts.base;
    if (query) { next += '?' + query; }
    next += parts.hash;
    if (next !== urlIn.value) {
      paramsFromTable = true;
      urlIn.value = next;
      paintUrlMirror();
      paramsFromTable = false;
    }
    // Meta counts on/off rows even when the query string did not change.
    dressParamsMeta();
  }

  function paramRow(data, isBlank) {
    var row = data || { on: true, key: '', value: '' };
    var tr = document.createElement('tr');
    if (!row.on) { tr.className = 'off'; }

    var tdOn = document.createElement('td');
    tdOn.className = 'c-params-on';
    var check = document.createElement('input');
    check.type = 'checkbox';
    check.checked = row.on !== false;
    check.title = 'Include in URL';
    check.setAttribute('aria-label', 'Include parameter in URL');
    tdOn.appendChild(check);
    tr.appendChild(tdOn);

    var tdKey = document.createElement('td');
    var keyIn = document.createElement('input');
    keyIn.type = 'text';
    keyIn.className = 'c-params-key';
    keyIn.spellcheck = false;
    keyIn.autocomplete = 'off';
    keyIn.placeholder = isBlank ? 'Key' : '';
    keyIn.setAttribute('aria-label', 'Parameter key');
    keyIn.value = str(row.key);
    tdKey.appendChild(keyIn);
    tr.appendChild(tdKey);

    var tdVal = document.createElement('td');
    var valIn = document.createElement('input');
    valIn.type = 'text';
    valIn.className = 'c-params-val';
    valIn.spellcheck = false;
    valIn.autocomplete = 'off';
    valIn.placeholder = isBlank ? 'Value' : '';
    valIn.setAttribute('aria-label', 'Parameter value');
    valIn.value = str(row.value);
    tdVal.appendChild(valIn);
    tr.appendChild(tdVal);

    var tdDrop = document.createElement('td');
    tdDrop.className = 'c-params-drop';
    if (!isBlank) {
      var drop = document.createElement('button');
      drop.type = 'button';
      drop.className = 'c-params-x';
      drop.title = 'Remove parameter';
      drop.setAttribute('aria-label', 'Remove parameter');
      drop.textContent = '×';
      drop.addEventListener('click', function () {
        tr.parentNode.removeChild(tr);
        ensureBlankParamRow();
        writeUrlFromParams();
      });
      tdDrop.appendChild(drop);
    }
    tr.appendChild(tdDrop);

    function onEdit() {
      tr.classList.toggle('off', !check.checked);
      // Typing into the blank row turns it into a real one and seeds a new blank.
      if (isBlank && (keyIn.value || valIn.value)) {
        isBlank = false;
        dropBtnFor(tr);
        ensureBlankParamRow();
      }
      writeUrlFromParams();
    }

    // Clicking the row (not only an input) marks it so key and value stay lit.
    tr.addEventListener('click', function (event) {
      if (event.target === drop || (event.target && event.target.classList
          && event.target.classList.contains('c-params-x'))) {
        return;
      }
      var was = tr.classList.contains('on');
      if (paramsBody) {
        var lit = paramsBody.querySelectorAll('tr.on');
        for (var s = 0; s < lit.length; s++) { lit[s].classList.remove('on'); }
      }
      if (!was) { tr.classList.add('on'); }
    });

    function dropBtnFor(node) {
      if (node.querySelector('.c-params-x')) { return; }
      var cell = node.querySelector('td.c-params-drop');
      if (!cell) { return; }
      var drop = document.createElement('button');
      drop.type = 'button';
      drop.className = 'c-params-x';
      drop.title = 'Remove parameter';
      drop.setAttribute('aria-label', 'Remove parameter');
      drop.textContent = '×';
      drop.addEventListener('click', function () {
        node.parentNode.removeChild(node);
        ensureBlankParamRow();
        writeUrlFromParams();
      });
      cell.appendChild(drop);
      keyIn.placeholder = '';
      valIn.placeholder = '';
    }

    check.addEventListener('change', onEdit);
    keyIn.addEventListener('input', onEdit);
    valIn.addEventListener('input', onEdit);
    return tr;
  }

  function ensureBlankParamRow() {
    if (!paramsBody) { return; }
    var trs = paramsBody.querySelectorAll('tr');
    var last = trs.length ? trs[trs.length - 1] : null;
    if (last) {
      var keyEl = last.querySelector('input.c-params-key');
      var valEl = last.querySelector('input.c-params-val');
      if (keyEl && valEl && !keyEl.value && !valEl.value) { return; }
    }
    paramsBody.appendChild(paramRow({ on: true, key: '', value: '' }, true));
  }

  function fillParamsTable(rows) {
    if (!paramsBody) { return; }
    strip(paramsBody);
    var list = Array.isArray(rows) ? rows : [];
    for (var i = 0; i < list.length; i++) {
      paramsBody.appendChild(paramRow(list[i], false));
    }
    // Re-attach disabled rows that were only in the table (not on the URL).
    for (var j = 0; j < paramsOff.length; j++) {
      paramsBody.appendChild(paramRow(paramsOff[j], false));
    }
    paramsOff = [];
    ensureBlankParamRow();
    dressParamsMeta();
  }

  function syncParamsFromUrl() {
    if (paramsFromTable || !urlIn) { return; }
    // Preserve unchecked rows across a URL-driven rebuild when the operator is
    // only editing the path/host, not the query — actually any URL edit that
    // re-parses query replaces on-rows; stash current off-rows first.
    var current = readParamRows();
    paramsOff = [];
    for (var i = 0; i < current.length; i++) {
      if (!current[i].on && (current[i].key || current[i].value)) {
        paramsOff.push(current[i]);
      }
    }
    var parts = splitUrlParts(urlIn.value);
    fillParamsTable(parseQueryString(parts.query));
  }

  function wireUrlField() {
    // Params table must fill even if the colour mirror is missing; the two
    // are independent surfaces that share the same input value.
    if (urlIn) {
      urlIn.addEventListener('input', function () {
        paintUrlMirror();
        syncParamsFromUrl();
      });
      if (urlMirror) {
        urlIn.addEventListener('scroll', function () {
          urlMirror.scrollLeft = urlIn.scrollLeft;
        });
      }
      // Programmatic .value writes do not fire input; openSaved calls paint+sync.
      paintUrlMirror();
      syncParamsFromUrl();
    } else if (paramsBody) {
      ensureBlankParamRow();
    }
  }
  wireUrlField();

  /* Fold bars for params and response. Same twist language as the tree shelves;
     preference survives the tab via localStorage. */
  var paramsMetaEl = document.getElementById('c-params-meta');
  var headersMetaEl = document.getElementById('c-headers-meta');
  var bodyMetaEl = document.getElementById('c-body-meta');
  var outMetaEl = document.getElementById('c-out-meta');
  var headersIn = document.getElementById('c-headers');
  var bodyIn = document.getElementById('c-body');
  var paramsFold = null;
  var headersFold = null;
  var bodyFold = null;
  var versionsFold = null;
  var outFold = null;

  function wireFold(wrapId, storageKey) {
    var wrap = document.getElementById(wrapId);
    if (!wrap) { return null; }
    var bar = wrap.querySelector('.c-fold-bar');
    var twist = bar ? bar.querySelector('.twist') : null;
    if (!bar || !twist) { return null; }

    function apply(shut) {
      wrap.classList.toggle('shut', shut);
      twist.textContent = shut ? '▸' : '▾';
      bar.setAttribute('aria-expanded', shut ? 'false' : 'true');
      try { localStorage.setItem(storageKey, shut ? '1' : '0'); } catch (error) { /* not fatal */ }
    }

    bar.addEventListener('click', function () {
      apply(!wrap.classList.contains('shut'));
    });
    try {
      if (localStorage.getItem(storageKey) === '1') { apply(true); }
    } catch (error) { /* not fatal */ }

    return {
      open: function () { apply(false); },
      close: function () { apply(true); },
      isShut: function () { return wrap.classList.contains('shut'); }
    };
  }

  function dressParamsMeta() {
    if (!paramsMetaEl) { return; }
    var rows = readParamRows();
    var on = 0;
    var total = 0;
    for (var i = 0; i < rows.length; i++) {
      if (!rows[i].key && !rows[i].value) { continue; }
      total += 1;
      if (rows[i].on) { on += 1; }
    }
    if (!total) {
      paramsMetaEl.textContent = '';
      return;
    }
    paramsMetaEl.textContent = on === total
      ? (total + (total === 1 ? ' param' : ' params'))
      : (on + ' of ' + total);
  }

  function dressHeadersMeta() {
    if (!headersMetaEl || !headersIn) { return; }
    var list = readHeaders(headersIn.value);
    headersMetaEl.textContent = list.length
      ? (list.length + (list.length === 1 ? ' header' : ' headers'))
      : '';
  }

  function dressBodyMeta() {
    if (!bodyMetaEl || !bodyIn) { return; }
    var text = bodyIn.value;
    if (!text) {
      bodyMetaEl.textContent = '';
      return;
    }
    // Character count is what the operator typed; bytes may differ after encode.
    var n = text.length;
    bodyMetaEl.textContent = n < 1024
      ? (n + (n === 1 ? ' char' : ' chars'))
      : ((n / 1024).toFixed(1) + ' KB');
  }

  function dressOutMeta(text) {
    if (outMetaEl) { outMetaEl.textContent = text ? str(text) : ''; }
  }

  paramsFold = wireFold('c-params-wrap', 'proxima.compose.params-shut');
  headersFold = wireFold('c-headers-wrap', 'proxima.compose.headers-shut');
  bodyFold = wireFold('c-body-wrap', 'proxima.compose.body-shut');
  versionsFold = wireFold('c-versions-wrap', 'proxima.compose.versions-shut');
  outFold = wireFold('c-out-wrap', 'proxima.compose.out-shut');
  dressParamsMeta();
  dressHeadersMeta();
  dressBodyMeta();
  if (headersIn) {
    headersIn.addEventListener('input', dressHeadersMeta);
  }
  if (bodyIn) {
    bodyIn.addEventListener('input', dressBodyMeta);
  }

  function composing(on) {
    if (on) { breaking(false); rewriting(false); httpRewriting(false); archiveView(false); }
    mainEl.classList.toggle('composing', on);
    composerEl.hidden = !on;
    composeBtn.classList.toggle('on', on);
    if (on) {
      urlIn.focus();
      paintUrlMirror();
      syncParamsFromUrl();
    }
  }

  /* ---------------------------------------------------------------- */
  /* archive stats (canned report when --archive is on)                */
  /* ---------------------------------------------------------------- */

  var archiveBtn = document.getElementById('archive');
  var archiverEl = document.getElementById('archiver');
  var archiveStatusEl = document.getElementById('a-status');
  var archiveBodyEl = document.getElementById('a-body');
  var archiveDroppedEl = document.getElementById('a-dropped');
  var archiveEnabled = false;
  var archiveDroppedCount = 0;

  function setArchiveEnabled(on, dropped) {
    archiveEnabled = !!on;
    archiveDroppedCount = typeof dropped === 'number' && isFinite(dropped) ? dropped : 0;
    // Button stays visible either way: when off, opening the panel explains
    // that this run (or build) is not recording, instead of a silent missing
    // control.
    archiveBtn.classList.toggle('on', !archiverEl.hidden && archiveEnabled);
    if (!archiverEl.hidden) {
      // Status can flip mid-session (reconnect). Refresh the open panel so the
      // hint or the live report matches the new flag.
      if (archiveEnabled) {
        dressArchiveDropped();
        loadArchiveStats();
      } else {
        strip(archiveBodyEl);
        archiveStatusEl.textContent =
          'Archive is not enabled. Start Proxima with --archive (and a build that includes the archive feature) to record finished flows to disk.';
        dressArchiveDropped();
      }
    } else {
      dressArchiveDropped();
    }
  }

  function dressArchiveDropped() {
    if (!archiveDroppedEl) { return; }
    if (archiveEnabled && archiveDroppedCount > 0) {
      archiveDroppedEl.hidden = false;
      archiveDroppedEl.textContent =
        archiveDroppedCount + ' flow' + (archiveDroppedCount === 1 ? '' : 's') +
        ' dropped when the archive writer was full';
    } else {
      archiveDroppedEl.hidden = true;
      archiveDroppedEl.textContent = '';
    }
  }

  function archiveView(on) {
    if (on) { composing(false); breaking(false); rewriting(false); httpRewriting(false); }
    mainEl.classList.toggle('archiving', on);
    archiverEl.hidden = !on;
    archiveBtn.classList.toggle('on', on && archiveEnabled);
    if (on) {
      dressArchiveDropped();
      if (!archiveEnabled) {
        strip(archiveBodyEl);
        archiveStatusEl.textContent =
          'Archive is not enabled. Start Proxima with --archive (and a build that includes the archive feature) to record finished flows to disk.';
        return;
      }
      loadArchiveStats();
    }
  }

  function cellText(column, value) {
    if (value === null || value === undefined) { return ''; }
    var name = str(column).toLowerCase();
    if (typeof value === 'number' && isFinite(value)) {
      if (name.indexOf('byte') >= 0) { return size(value); }
      if (name === 'p95_ms' || name === 'median_ms' || name.slice(-3) === '_ms') {
        return millis(value);
      }
      if (name === 'flows' || name === 'failures' || name === 'hosts' ||
          name === 'class' || name.indexOf('count') >= 0) {
        return String(value);
      }
      // Plain counts and other numbers: keep them compact and readable.
      if (Math.abs(value) >= 1000 && value % 1 === 0) {
        return String(value);
      }
      return String(value);
    }
    return str(value);
  }

  function paintQueryTable(title, result) {
    var section = el('section', 'a-section block');
    section.appendChild(el('h2', null, title));
    if (!result || !Array.isArray(result.columns) || !Array.isArray(result.rows)) {
      section.appendChild(el('p', 'hint', 'No data in this section.'));
      return section;
    }
    if (!result.rows.length) {
      section.appendChild(el('p', 'hint', 'No rows yet.'));
      return section;
    }
    var table = el('table', 'a-table');
    var thead = document.createElement('thead');
    var headRow = document.createElement('tr');
    for (var c = 0; c < result.columns.length; c++) {
      headRow.appendChild(el('th', null, str(result.columns[c])));
    }
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = document.createElement('tbody');
    for (var r = 0; r < result.rows.length; r++) {
      var row = result.rows[r];
      var tr = document.createElement('tr');
      var cells = Array.isArray(row) ? row : [];
      for (var i = 0; i < result.columns.length; i++) {
        tr.appendChild(el('td', null, cellText(result.columns[i], cells[i])));
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    section.appendChild(table);
    if (result.truncated) {
      section.appendChild(el('p', 'hint', 'Result was truncated at the server limit.'));
    }
    return section;
  }

  function paintTotals(result) {
    var section = el('section', 'a-section block');
    section.appendChild(el('h2', null, 'Totals'));
    if (!result || !Array.isArray(result.columns) || !Array.isArray(result.rows) ||
        !result.rows.length) {
      section.appendChild(el('p', 'hint', 'No totals yet. Capture some traffic.'));
      return section;
    }
    var cols = result.columns;
    var vals = Array.isArray(result.rows[0]) ? result.rows[0] : [];
    var metrics = el('div', 'a-totals');
    for (var i = 0; i < cols.length; i++) {
      var metric = el('div', 'a-metric');
      metric.appendChild(el('span', 'a-label', str(cols[i]).replace(/_/g, ' ')));
      metric.appendChild(el('span', 'a-value', cellText(cols[i], vals[i])));
      metrics.appendChild(metric);
    }
    section.appendChild(metrics);
    return section;
  }

  function paintArchiveStats(stats) {
    strip(archiveBodyEl);
    if (!stats || typeof stats !== 'object') {
      archiveBodyEl.appendChild(el('p', 'hint', 'The archive answered with nothing useful.'));
      return;
    }
    var totals = stats.totals;
    var flowCount = 0;
    if (totals && Array.isArray(totals.rows) && totals.rows.length &&
        Array.isArray(totals.rows[0])) {
      flowCount = Number(totals.rows[0][0]) || 0;
    }
    if (flowCount === 0 &&
        (!totals || !Array.isArray(totals.rows) || !totals.rows.length)) {
      archiveBodyEl.appendChild(el('p', 'hint',
        'Archive is empty. Capture some traffic while recording is on.'));
      return;
    }
    archiveBodyEl.appendChild(paintTotals(stats.totals));
    archiveBodyEl.appendChild(paintQueryTable('Busiest hosts', stats.hosts));
    archiveBodyEl.appendChild(paintQueryTable('Status classes', stats.statuses));
    archiveBodyEl.appendChild(paintQueryTable('Slowest paths', stats.slowest));
    archiveBodyEl.appendChild(paintQueryTable('Heaviest responses', stats.heaviest));
    if (flowCount === 0) {
      archiveBodyEl.appendChild(el('p', 'hint',
        'No flows archived yet. Traffic that finishes while --archive is on will appear here.'));
    }
  }

  async function loadArchiveStats() {
    strip(archiveBodyEl);
    archiveStatusEl.textContent = 'Loading archive stats...';
    dressArchiveDropped();
    try {
      var response = await fetch('/api/archive/stats', { cache: 'no-store' });
      var text = await response.text();
      if (!response.ok) {
        var message = 'the server answered ' + response.status;
        try {
          var parsed = JSON.parse(text);
          if (parsed && parsed.error) { message = str(parsed.error); }
        } catch (ignore) {
          if (text) { message = text.slice(0, 400); }
        }
        throw new Error(message);
      }
      var stats = JSON.parse(text);
      archiveStatusEl.textContent = '';
      paintArchiveStats(stats);
    } catch (error) {
      archiveStatusEl.textContent = 'Could not load archive stats: ' + error.message;
      archiveBodyEl.appendChild(el('p', 'hint',
        'Nothing to show. The archive may be busy, missing, or this build may not record flows.'));
    }
  }

  function readHeaders(text) {
    var out = [];
    var lines = str(text).split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) { continue; }
      var at = line.indexOf(':');
      // A name has to be there, so a leading colon is a typo rather than a header.
      if (at < 1) { continue; }
      out.push([line.slice(0, at).trim(), line.slice(at + 1).trim()]);
    }
    return out;
  }

  // The wire carries bodies as base64, so anything non-ASCII survives the trip.
  function toBase64(text) {
    var bytes = new TextEncoder().encode(text);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) { binary += String.fromCharCode(bytes[i]); }
    return btoa(binary);
  }

  function fromBase64(value) {
    var binary = atob(str(value));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
    return new TextDecoder().decode(bytes);
  }

  function contentTypeOf(headers) {
    var list = Array.isArray(headers) ? headers : [];
    for (var i = 0; i < list.length; i++) {
      if (Array.isArray(list[i]) && str(list[i][0]).toLowerCase() === 'content-type') {
        return str(list[i][1]);
      }
    }
    return '';
  }

  async function fire() {
    var button = document.getElementById('c-send');
    var url = document.getElementById('c-url').value.trim();
    strip(outEl);
    // A folded response would hide the answer the operator just asked for.
    if (outFold) { outFold.open(); }
    if (!url) {
      dressOutMeta('');
      outEl.appendChild(el('p', 'hint', 'Give it a URL first.'));
      return;
    }

    var bodyText = document.getElementById('c-body').value;
    var envId = document.getElementById('c-env').value;
    var spec = {
      method: document.getElementById('c-method').value,
      url: url,
      headers: readHeaders(document.getElementById('c-headers').value),
      bodyBase64: bodyText ? toBase64(bodyText) : null,
      environmentId: envId || null
    };

    button.disabled = true;
    dressOutMeta('Sending...');
    outEl.appendChild(el('p', 'hint', 'Sending...'));
    try {
      var response = await fetch('/api/send', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(spec),
        cache: 'no-store'
      });
      var text = await response.text();
      strip(outEl);
      if (!response.ok) {
        dressOutMeta('failed');
        outEl.appendChild(el('p', 'hint', 'The request failed.'));
        outEl.appendChild(el('pre', 'mono', text));
        return;
      }

      var result = JSON.parse(text);
      var took = result.timings && result.timings.end
        ? result.timings.end - result.timings.start
        : null;
      var statusLine = str(result.status) + ' ' + str(result.statusText) + '   ' +
        str(result.httpVersion) + (took === null ? '' : '   ' + millis(took));
      // Status also sits on the fold bar so a collapsed response still names it.
      dressOutMeta(str(result.status) + (took === null ? '' : ' · ' + millis(took)));
      var summary = el('section', 'block');
      summary.appendChild(el('p', 'mono', statusLine));
      outEl.appendChild(summary);
      outEl.appendChild(headerBlock('Response headers', result.headers));

      var shown;
      try { shown = fromBase64(result.bodyBase64); }
      catch (error) { shown = '[the body is not text]'; }
      var body = el('section', 'block');
      body.appendChild(el('h2', null, 'Response body'));
      var pre = el('pre', 'mono');
      body.appendChild(pre);
      outEl.appendChild(body);
      var ct = contentTypeOf(result.headers);
      if (wantsJsonView(shown, ct)) {
        fetchJsonView(shown).then(function (view) {
          if (view) { paintJson(pre, view); }
          else { pre.textContent = shown; }
        });
      } else {
        pre.textContent = shown;
      }
      // Successful send is recorded server-side; refresh the Recent shelf.
      loadRecent();
    } catch (error) {
      strip(outEl);
      dressOutMeta('error');
      outEl.appendChild(el('p', 'hint', 'Could not send: ' + error.message));
    } finally {
      button.disabled = false;
    }
  }

  composeBtn.addEventListener('click', function () { composing(composerEl.hidden); });
  breakBtn.addEventListener('click', function () { breaking(breakerEl.hidden); });
  rewriteBtn.addEventListener('click', function () { rewriting(rewriterEl.hidden); });
  httpRewriteBtn.addEventListener('click', function () { httpRewriting(httpRewriterEl.hidden); });
  archiveBtn.addEventListener('click', function () { archiveView(archiverEl.hidden); });
  document.getElementById('a-refresh').addEventListener('click', function () {
    if (!archiverEl.hidden) { loadArchiveStats(); }
  });
  document.getElementById('b-save').addEventListener('click', saveRules);
  document.getElementById('b-clear').addEventListener('click', clearRules);
  document.getElementById('b-kind').addEventListener('change', dressBreakKind);
  dressBreakKind();
  document.getElementById('w-save').addEventListener('click', saveRewriteRules);
  document.getElementById('w-clear').addEventListener('click', clearRewriteRules);
  document.getElementById('hr-save').addEventListener('click', saveHttpRewriteRules);
  document.getElementById('hr-clear').addEventListener('click', clearHttpRewriteRules);
  document.getElementById('c-send').addEventListener('click', fire);
  document.addEventListener('keydown', function (event) {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter' && !composerEl.hidden) {
      event.preventDefault();
      fire();
    }
  });

  /* ---------------------------------------------------------------- */
  /* saved requests                                                    */
  /* ---------------------------------------------------------------- */

  /* The other half of this tool: requests kept on purpose rather than caught
     in passing. They live in the same column as the hosts because they are read
     the same way, and they open in the composer, which is the only thing here
     that sends anything. */

  var books = [];
  // Id of the saved request currently open in the composer. Empty means the
  // next Save is a new entry; non-empty means overwrite that one in place.
  var editingSavedId = '';

  async function loadBooks() {
    try {
      var got = await getJson('/api/collections');
      books = Array.isArray(got) ? got : [];
    } catch (error) {
      books = [];
    }
    paintBooks();
    loadEnvironments();
    paintVersions();
  }

  var environments = [];

  async function loadEnvironments() {
    try {
      var got = await getJson('/api/environments');
      environments = Array.isArray(got) ? got : [];
    } catch (error) {
      environments = [];
    }
    var activeId = null;
    try {
      var active = await getJson('/api/environments/active');
      activeId = active && active.id ? str(active.id) : null;
    } catch (error) { /* no active */ }
    fillEnvChoices(activeId);
  }

  function fillEnvChoices(activeId) {
    var choose = document.getElementById('c-env');
    if (!choose) { return; }
    var held = activeId || choose.value;
    strip(choose);
    var none = el('option', null, 'No environment');
    none.value = '';
    choose.appendChild(none);
    for (var i = 0; i < environments.length; i++) {
      var option = el('option', null, str(environments[i].name));
      option.value = environments[i].id;
      choose.appendChild(option);
    }
    choose.value = held;
    if (!choose.value) { choose.value = ''; }
  }

  var envSelect = document.getElementById('c-env');
  if (envSelect) {
    envSelect.addEventListener('change', async function () {
      var id = envSelect.value || null;
      try {
        await fetch('/api/environments/active', {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id: id }),
          cache: 'no-store'
        });
      } catch (error) { /* not fatal */ }
    });
  }

  var bookHunt = '';

  // A collection whose own name answers keeps all of it: asking for the name of
  // a folder is asking for the folder, not for the requests that repeat it.
  function keptFor(book) {
    var all = book.requests || [];
    if (bookHunt === '') { return all; }
    if (str(book.name).toLowerCase().indexOf(bookHunt) >= 0) { return all; }
    var out = [];
    for (var i = 0; i < all.length; i++) {
      var spec = all[i].spec || {};
      var hay = (str(all[i].name) + ' ' + str(spec.method) + ' ' + str(spec.url)).toLowerCase();
      if (hay.indexOf(bookHunt) >= 0) { out.push(all[i]); }
    }
    return out;
  }

  function paintBooks() {
    strip(booksEl);
    var count = 0;
    for (var i = 0; i < books.length; i++) {
      count += (books[i].requests || []).length;
    }
    var showing = bookGroup === 'book' ? byBook() : byField(bookGroup);
    noBooksEl.hidden = showing > 0;
    if (books.length && !showing) {
      noBooksEl.textContent = 'Nothing saved here answers that.';
    } else if (!books.length) {
      noBooksEl.textContent =
        'Nothing saved yet. Drag a live request here, copy one into a collection, or compose and save.';
    }
    fillBookChoices();
    return count;
  }

  // The collections as they were saved: one branch per collection, holding
  // whatever in it answers the search.
  function byBook() {
    var showing = 0;
    for (var i = 0; i < books.length; i++) {
      var found = keptFor(books[i]);
      // While searching, a collection with nothing to show is not shown.
      if (bookHunt !== '' && !found.length) { continue; }
      showing += 1;
      booksEl.appendChild(bookNode(books[i], found));
    }
    return showing;
  }

  /* Cut across the collections instead: by what the request does, or by what it
     does it to. A collection is how requests were filed, which is not always
     how they are looked for. */

  function byField(field) {
    var piles = new Map();
    for (var i = 0; i < books.length; i++) {
      var found = keptFor(books[i]);
      for (var j = 0; j < found.length; j++) {
        var spec = found[j].spec || {};
        var label = field === 'method'
          ? (str(spec.method) || 'GET').toUpperCase()
          : hostOf(str(spec.url));
        if (!piles.has(label)) { piles.set(label, []); }
        piles.get(label).push({ book: books[i], saved: found[j] });
      }
    }
    var labels = Array.from(piles.keys()).sort();
    for (var k = 0; k < labels.length; k++) {
      booksEl.appendChild(pileNode(labels[k], piles.get(labels[k])));
    }
    return labels.length;
  }

  /* A saved request holds whatever was typed into the URL box, which is not
     always a URL yet. `api.example.com/v1` is a host to anyone reading it and
     nothing at all to the parser, so the scheme it was saved without is
     supplied before giving up on it. What is left after that is a line that
     names no host, and it is filed under saying so rather than under a host
     invented for it. */

  function hostOf(url) {
    var text = url.trim();
    if (text === '') { return 'no host'; }
    try { return new URL(text).host || 'no host'; }
    catch (error) { /* try it as the host it looks like */ }
    // Only where a scheme is missing rather than wrong: `ftp://x/y` parses,
    // and `https://ftp://x/y` would be a second guess at an answered question.
    if (text.indexOf('://') >= 0) { return 'no host'; }
    try { return new URL('https://' + text).host || 'no host'; }
    catch (error) { return 'no host'; }
  }

  function pileNode(label, held) {
    var box = el('div', 'group host');
    var line = el('div', 'gline');
    var twist = el('span', 'twist', '▾');
    line.appendChild(twist);
    line.appendChild(el('span', 'gname', label));
    line.appendChild(el('span', 'gcount', String(held.length)));
    // Same split as the live tree: twist folds, the rest of the line does not
    // also have to; a full-line toggle made the chevron feel broken next to
    // other click targets on the row.
    twist.addEventListener('click', function (event) {
      event.stopPropagation();
      event.preventDefault();
      twist.textContent = box.classList.toggle('shut') ? '▸' : '▾';
    });
    line.addEventListener('click', function () {
      twist.textContent = box.classList.toggle('shut') ? '▸' : '▾';
    });
    var body = el('div', 'gbody');
    for (var i = 0; i < held.length; i++) {
      body.appendChild(keptNode(held[i].book, held[i].saved));
    }
    box.appendChild(line);
    box.appendChild(body);
    return box;
  }

  function bookNode(book, showing) {
    var box = el('div', 'group host');
    var line = el('div', 'gline');
    var twist = el('span', 'twist', '▾');
    var all = book.requests || [];
    var kept = showing || all;
    line.appendChild(twist);
    line.appendChild(el('span', 'gname', str(book.name)));
    line.appendChild(el('span', 'gcount', kept.length === all.length
      ? String(all.length)
      : kept.length + ' of ' + all.length));

    var kill = el('button', 'kill', '×');
    kill.type = 'button';
    kill.title = 'Delete this collection';
    kill.setAttribute('aria-label', 'Delete this collection');
    kill.addEventListener('click', function (event) {
      event.stopPropagation();
      dropBook(book);
    });
    line.appendChild(kill);

    twist.addEventListener('click', function (event) {
      event.stopPropagation();
      event.preventDefault();
      twist.textContent = box.classList.toggle('shut') ? '▸' : '▾';
    });
    line.addEventListener('click', function (event) {
      // Kill has its own handler; other clicks on the bar fold the collection.
      if (event.target && event.target.classList && event.target.classList.contains('kill')) {
        return;
      }
      twist.textContent = box.classList.toggle('shut') ? '▸' : '▾';
    });

    // Drop a live flow here to append it as a saved request in this collection.
    acceptLiveDrop(box, function () { return book; });

    var body = el('div', 'gbody');
    for (var i = 0; i < kept.length; i++) {
      body.appendChild(keptNode(book, kept[i]));
    }
    box.appendChild(line);
    box.appendChild(body);
    return box;
  }

  function keptNode(book, saved) {
    var spec = saved.spec || {};
    var item = el('div', 'sitem');
    item.appendChild(el('span', 'smethod', str(spec.method) || 'GET'));
    item.appendChild(el('span', 'sname', str(saved.name) || str(spec.url)));

    var kill = el('button', 'kill', '×');
    kill.type = 'button';
    kill.title = 'Delete this request';
    kill.setAttribute('aria-label', 'Delete this request');
    kill.addEventListener('click', function (event) {
      event.stopPropagation();
      dropSaved(book, saved);
    });
    item.appendChild(kill);

    item.addEventListener('click', function () { openSaved(book, saved); });
    return item;
  }

  // Fill composer fields from a name + SendSpec-shaped object.
  // `opts.savedId` (string|''): set editingSavedId; omit to leave it alone.
  // `opts.bookId`: select that collection in #c-book.
  // `opts.clearOut` (default true): wipe the response pane.
  function fillComposer(name, spec, opts) {
    opts = opts || {};
    spec = spec || {};
    if (opts.savedId !== undefined) { editingSavedId = str(opts.savedId); }
    if (opts.bookId) {
      document.getElementById('c-book').value = opts.bookId;
    }
    document.getElementById('c-method').value = str(spec.method) || 'GET';
    // urlIn is #c-url; paint + params table after so both match the value.
    urlIn.value = str(spec.url);
    paintUrlMirror();
    syncParamsFromUrl();
    if (headersIn) { headersIn.value = headerLines(spec.headers); }
    else { document.getElementById('c-headers').value = headerLines(spec.headers); }
    var body = '';
    if (spec.bodyBase64) {
      try { body = fromBase64(spec.bodyBase64); } catch (error) { body = ''; }
    }
    if (bodyIn) { bodyIn.value = body; }
    else { document.getElementById('c-body').value = body; }
    document.getElementById('c-name').value = str(name);
    if (spec.environmentId != null && document.getElementById('c-env')) {
      document.getElementById('c-env').value = str(spec.environmentId);
    }
    dressHeadersMeta();
    dressBodyMeta();
    if (opts.clearOut !== false) {
      // The answer on screen belongs to the request that was open a moment ago.
      // Left up, it reads as the answer to this one, and it is convincing: same
      // shape, same pane, only the URL above it has changed.
      strip(outEl);
      dressOutMeta('');
      outEl.appendChild(el('p', 'hint', 'Send a request to see the response here.'));
    }
    paintVersions();
    composing(true);
  }

  // Straight into the composer, which is where a saved request is of any use.
  function openSaved(book, saved) {
    fillComposer(str(saved.name), saved.spec || {}, {
      savedId: str(saved.id),
      bookId: book && book.id ? book.id : ''
    });
  }

  function findEditingSaved() {
    if (!editingSavedId) { return null; }
    for (var i = 0; i < books.length; i++) {
      var reqs = books[i].requests || [];
      for (var r = 0; r < reqs.length; r++) {
        if (reqs[r].id === editingSavedId) { return reqs[r]; }
      }
    }
    return null;
  }

  function formatVersionWhen(ms) {
    var n = Number(ms);
    if (!isFinite(n) || n <= 0) { return '--:--'; }
    var d = new Date(n);
    var hh = d.getHours();
    var mm = d.getMinutes();
    return (hh < 10 ? '0' : '') + hh + ':' + (mm < 10 ? '0' : '') + mm;
  }

  function paintVersions() {
    var box = document.getElementById('c-versions');
    var meta = document.getElementById('c-versions-meta');
    var histBtn = document.getElementById('c-history');
    if (!box) { return; }
    strip(box);
    var saved = findEditingSaved();
    var history = saved && Array.isArray(saved.history) ? saved.history : [];
    var n = history.length;
    if (meta) {
      meta.textContent = n
        ? (n + (n === 1 ? ' version' : ' versions'))
        : '';
    }
    // History button next to Save: same count, always clickable (opens the fold).
    if (histBtn) {
      histBtn.textContent = n ? ('History (' + n + ')') : 'History';
      if (!editingSavedId) {
        histBtn.title = 'Open a saved request to see its history';
      } else if (!n) {
        histBtn.title = 'No previous versions yet; Save a change to keep one';
      } else {
        histBtn.title = n + ' previous version' + (n === 1 ? '' : 's');
      }
    }
    if (!editingSavedId) {
      box.appendChild(el('p', 'hint',
        'Open a saved request and Save a change to keep versions here.'));
      return;
    }
    if (!history.length) {
      box.appendChild(el('p', 'hint',
        'No versions yet. Save a change to keep the previous one here.'));
      return;
    }
    for (var i = 0; i < history.length; i++) {
      (function (rev) {
        var spec = rev.spec || {};
        var item = el('div', 'vitem');
        item.appendChild(el('span', 'vwhen', formatVersionWhen(rev.atMs)));
        var label = str(rev.name) || (str(spec.method) + ' ' + str(spec.url));
        item.appendChild(el('span', 'vname', label));
        item.title = 'Load this version into the composer';
        item.addEventListener('click', function () {
          // Keep editingSavedId so the next Save overwrites current and the
          // store pushes that current into history.
          fillComposer(str(rev.name), spec, { savedId: editingSavedId });
        });
        box.appendChild(item);
      })(history[i]);
    }
  }

  // History button: open the versions fold and bring it into view.
  function showHistory() {
    paintVersions();
    if (versionsFold) { versionsFold.open(); }
    var wrap = document.getElementById('c-versions-wrap');
    if (wrap && wrap.scrollIntoView) {
      wrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function fillBookChoices() {
    var choose = document.getElementById('c-book');
    var held = choose.value;
    strip(choose);
    for (var i = 0; i < books.length; i++) {
      var option = el('option', null, str(books[i].name));
      option.value = books[i].id;
      choose.appendChild(option);
    }
    var fresh = el('option', null, 'New collection...');
    fresh.value = '';
    choose.appendChild(fresh);
    choose.value = held;
    // A collection that was deleted while its name sat in the box leaves the
    // select on nothing at all.
    if (!choose.value) { choose.value = books.length ? books[0].id : ''; }
  }

  // History is owned by the store. Only id/name/spec go on the wire so a
  // client-side empty history array cannot wipe revisions on the server.
  function bookForPut(book) {
    var requests = [];
    var all = book.requests || [];
    for (var i = 0; i < all.length; i++) {
      requests.push({
        id: all[i].id || '',
        name: all[i].name || '',
        spec: all[i].spec || {}
      });
    }
    return {
      id: book.id || '',
      name: book.name || '',
      requests: requests
    };
  }

  async function putBook(book) {
    var payload = bookForPut(book);
    var url = payload.id
      ? '/api/collections/' + encodeURIComponent(payload.id)
      : '/api/collections';
    var response = await fetch(url, {
      method: payload.id ? 'PUT' : 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      cache: 'no-store'
    });
    if (!response.ok) { throw new Error('the server answered ' + response.status); }
    return response.json();
  }

  async function saveComposed() {
    var out = document.getElementById('c-out');
    var url = document.getElementById('c-url').value.trim();
    if (!url) {
      strip(out);
      out.appendChild(el('p', 'hint', 'Give it a URL before saving it.'));
      return;
    }

    var bodyText = document.getElementById('c-body').value;
    var saved = {
      // Empty id = new; a known id replaces that request instead of appending.
      id: editingSavedId || '',
      name: document.getElementById('c-name').value.trim() || url,
      spec: {
        method: document.getElementById('c-method').value,
        url: url,
        headers: readHeaders(document.getElementById('c-headers').value),
        bodyBase64: bodyText ? toBase64(bodyText) : null
      }
    };

    var chosen = document.getElementById('c-book').value;
    var book = null;
    for (var i = 0; i < books.length; i++) {
      if (books[i].id === chosen) { book = books[i]; }
    }
    if (!book) { book = { id: '', name: 'Saved requests', requests: [] }; }

    var requests = (book.requests || []).slice();
    var replaced = false;
    if (saved.id) {
      for (var r = 0; r < requests.length; r++) {
        if (requests[r].id === saved.id) {
          requests[r] = saved;
          replaced = true;
          break;
        }
      }
      // Id known but not in this collection: drop it from every other book so
      // Save with a different collection selected moves rather than clones.
      if (!replaced) {
        for (var b = 0; b < books.length; b++) {
          if (books[b].id === book.id) { continue; }
          var others = books[b].requests || [];
          var kept = [];
          var moved = false;
          for (var o = 0; o < others.length; o++) {
            if (others[o].id === saved.id) { moved = true; }
            else { kept.push(others[o]); }
          }
          if (moved) {
            books[b].requests = kept;
            try { await putBook(books[b]); } catch (error) { /* best effort */ }
          }
        }
        requests.push(saved);
        replaced = true;
      }
    }
    if (!replaced) { requests.push(saved); }
    book.requests = requests;

    strip(out);
    try {
      var result = await putBook(book);
      await loadBooks();
      // Keep editing the same request so a second Save overwrites, not clones.
      editingSavedId = saved.id;
      if (!editingSavedId && result && Array.isArray(result.requests)) {
        for (var j = result.requests.length - 1; j >= 0; j--) {
          if (result.requests[j].name === saved.name) {
            editingSavedId = str(result.requests[j].id);
            break;
          }
        }
      }
      paintVersions();
      out.appendChild(el('p', 'hint', replaced && saved.id
        ? ('Updated ' + saved.name + '.')
        : ('Saved as ' + saved.name + '.')));
    } catch (error) {
      out.appendChild(el('p', 'hint', 'Could not save it: ' + error.message));
    }
  }

  async function dropSaved(book, saved) {
    var kept = [];
    var all = book.requests || [];
    for (var i = 0; i < all.length; i++) {
      if (all[i].id !== saved.id) { kept.push(all[i]); }
    }
    book.requests = kept;
    try {
      await putBook(book);
      await loadBooks();
    } catch (error) {
      noBooksEl.hidden = false;
      noBooksEl.textContent = 'Could not delete that: ' + error.message;
    }
  }

  async function dropBook(book) {
    if (!book.id) { return; }
    try {
      var response = await fetch('/api/collections/' + encodeURIComponent(book.id), {
        method: 'DELETE',
        cache: 'no-store'
      });
      if (!response.ok) { throw new Error('the server answered ' + response.status); }
      await loadBooks();
    } catch (error) {
      noBooksEl.hidden = false;
      noBooksEl.textContent = 'Could not delete that: ' + error.message;
    }
  }

  /* ---------------------------------------------------------------- */
  /* live request → saved request (drag, copy, paste)                  */
  /* ---------------------------------------------------------------- */

  // Headers that describe a hop or are implied by the URL/body. Replaying them
  // confuses the next send the same way it confuses curl.
  function isSavedHop(name) {
    var n = str(name).toLowerCase();
    return n === 'host' || n === 'content-length' || n === 'transfer-encoding'
      || n === 'connection' || n === 'keep-alive' || n === 'proxy-connection'
      || n === 'proxy-authenticate' || n === 'proxy-authorization'
      || n === 'te' || n === 'trailers' || n === 'upgrade';
  }

  function filterSavedHeaders(headers) {
    var list = Array.isArray(headers) ? headers : [];
    var out = [];
    for (var i = 0; i < list.length; i++) {
      if (!Array.isArray(list[i])) { continue; }
      if (isSavedHop(list[i][0])) { continue; }
      out.push([str(list[i][0]), str(list[i][1])]);
    }
    return out;
  }

  async function bodyAsBase64(id, which) {
    var response = await fetch(
      '/api/flows/' + encodeURIComponent(id) + '/body/' + which + '?decode=1',
      { cache: 'no-store' }
    );
    if (!response.ok) {
      throw new Error('the body is no longer available (' + response.status + ')');
    }
    var buffer = await response.arrayBuffer();
    var bytes = new Uint8Array(buffer);
    var binary = '';
    // Chunked: apply on huge bodies would blow the stack with one huge join.
    var chunk = 0x8000;
    for (var i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function defaultSavedName(request) {
    var method = str(request.method) || 'GET';
    var path = str(request.path) || str(request.url) || 'request';
    if (path.length > 80) { path = path.slice(0, 77) + '...'; }
    return method + ' ' + path;
  }

  // Build a SavedRequest (SendSpec under a name) from a live flow id.
  async function flowToSaved(id) {
    var flow = await getJson('/api/flows/' + encodeURIComponent(id));
    var request = flow.request || {};
    var url = str(request.url);
    if (!url) {
      throw new Error('that flow has no request URL to save');
    }
    var bodyBase64 = null;
    if (request.body) {
      try {
        bodyBase64 = await bodyAsBase64(id, 'request');
      } catch (error) {
        // Headers and URL are still worth keeping when the body was evicted.
        bodyBase64 = null;
      }
    }
    return {
      id: '',
      name: defaultSavedName(request),
      spec: {
        method: str(request.method) || 'GET',
        url: url,
        headers: filterSavedHeaders(request.headers),
        bodyBase64: bodyBase64
      }
    };
  }

  async function flowToSavedJson(id) {
    var saved = await flowToSaved(id);
    return SAVED_CLIP_PREFIX + JSON.stringify(saved);
  }

  function parseSavedClipboard(text) {
    var raw = str(text).trim();
    if (raw.indexOf(SAVED_CLIP_PREFIX) === 0) {
      raw = raw.slice(SAVED_CLIP_PREFIX.length);
    }
    var value = JSON.parse(raw);
    if (!value || typeof value !== 'object') {
      throw new Error('clipboard is not a saved request');
    }
    var spec = value.spec || value;
    if (!str(spec.url)) {
      throw new Error('clipboard has no URL');
    }
    return {
      id: '',
      name: str(value.name) || str(spec.url),
      spec: {
        method: str(spec.method) || 'GET',
        url: str(spec.url),
        headers: Array.isArray(spec.headers) ? spec.headers : [],
        bodyBase64: spec.bodyBase64 == null ? null : str(spec.bodyBase64)
      }
    };
  }

  async function ensureBook(book) {
    if (book && book.id) { return book; }
    if (books.length) { return books[0]; }
    return putBook({ id: '', name: 'From capture', requests: [] });
  }

  async function appendSaved(book, saved) {
    var target = await ensureBook(book);
    // Refresh from the in-memory list so concurrent saves do not drop siblings.
    for (var i = 0; i < books.length; i++) {
      if (books[i].id === target.id) { target = books[i]; break; }
    }
    target.requests = (target.requests || []).concat([saved]);
    await putBook(target);
    await loadBooks();
    return { book: target, saved: saved };
  }

  async function saveFlowToCollection(flowId, book) {
    var saved = await flowToSaved(flowId);
    await appendSaved(book, saved);
    return saved.name;
  }

  function clearDropMarks() {
    var marks = document.querySelectorAll('.drop-over');
    for (var i = 0; i < marks.length; i++) {
      marks[i].classList.remove('drop-over');
    }
  }

  /* Pointer-based live → collection drag.
     HTML5 draggable forces a system grab hand; CSS cannot override it. */
  var liveDrag = null;
  var liveDragSuppressClick = false;
  var LIVE_DRAG_THRESHOLD = 6;

  function clearLiveDrag() {
    if (liveDrag && liveDrag.source) {
      liveDrag.source.classList.remove('dragging');
    }
    liveDrag = null;
    document.body.classList.remove('row-dragging');
    clearDropMarks();
  }

  function liveDropAt(x, y) {
    var el = document.elementFromPoint(x, y);
    while (el) {
      if (el.classList && el.classList.contains('live-drop')) {
        return el;
      }
      el = el.parentElement;
    }
    return null;
  }

  function markLiveDrop(target) {
    clearDropMarks();
    if (target) { target.classList.add('drop-over'); }
  }

  function finishLiveDrop(flowId, target) {
    if (!flowId || !target || typeof target._bookOf !== 'function') { return; }
    var book = target._bookOf();
    saveFlowToCollection(flowId, book).catch(function (error) {
      noBooksEl.hidden = false;
      noBooksEl.textContent = 'Could not save that: ' + error.message;
    });
  }

  function wireLiveDragSource(el, getFlowId) {
    el.addEventListener('pointerdown', function (event) {
      if (event.button !== 0) { return; }
      // Kill / star / other controls keep their own clicks.
      if (event.target && event.target !== el) {
        var t = event.target;
        if (t.closest && (t.closest('.kill') || t.closest('.star') || t.closest('button'))) {
          return;
        }
      }
      var flowId = getFlowId();
      if (!flowId) { return; }
      liveDrag = {
        flowId: flowId,
        source: el,
        x: event.clientX,
        y: event.clientY,
        active: false,
        pointerId: event.pointerId
      };
      function onMove(move) {
        if (!liveDrag || liveDrag.pointerId !== move.pointerId) { return; }
        var dx = move.clientX - liveDrag.x;
        var dy = move.clientY - liveDrag.y;
        if (!liveDrag.active) {
          if ((dx * dx + dy * dy) < LIVE_DRAG_THRESHOLD * LIVE_DRAG_THRESHOLD) {
            return;
          }
          liveDrag.active = true;
          liveDragSuppressClick = true;
          liveDrag.source.classList.add('dragging');
          document.body.classList.add('row-dragging');
          try { liveDrag.source.setPointerCapture(move.pointerId); } catch (err) { /* ok */ }
        }
        move.preventDefault();
        markLiveDrop(liveDropAt(move.clientX, move.clientY));
      }
      function onUp(up) {
        if (!liveDrag || liveDrag.pointerId !== up.pointerId) { return; }
        document.removeEventListener('pointermove', onMove, true);
        document.removeEventListener('pointerup', onUp, true);
        document.removeEventListener('pointercancel', onUp, true);
        var wasActive = liveDrag.active;
        var id = liveDrag.flowId;
        var drop = wasActive ? liveDropAt(up.clientX, up.clientY) : null;
        try { liveDrag.source.releasePointerCapture(up.pointerId); } catch (err) { /* ok */ }
        clearLiveDrag();
        if (wasActive && drop) {
          finishLiveDrop(id, drop);
        }
        // Suppress the click that follows a completed drag.
        if (wasActive) {
          setTimeout(function () { liveDragSuppressClick = false; }, 0);
        }
      }
      document.addEventListener('pointermove', onMove, true);
      document.addEventListener('pointerup', onUp, true);
      document.addEventListener('pointercancel', onUp, true);
    });
  }

  function acceptLiveDrop(node, bookOf) {
    node.classList.add('live-drop');
    node._bookOf = bookOf;
  }

  // The whole Saved panel accepts a drop when there is no specific collection
  // under the pointer (empty list, or between groups).
  (function wireSavedPanelDrop() {
    var panel = document.getElementById('saved');
    if (!panel) { return; }
    acceptLiveDrop(panel, function () { return null; });
  })();

  function typingTarget(node) {
    if (!node || !node.tagName) { return false; }
    var tag = node.tagName.toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select' || node.isContentEditable;
  }

  // Cmd/Ctrl+C on a selected live flow copies a saved-request envelope.
  // Cmd/Ctrl+V over the saved column pastes it into a collection.
  document.addEventListener('keydown', function (event) {
    if (typingTarget(event.target)) { return; }
    var mod = event.metaKey || event.ctrlKey;
    if (!mod) { return; }
    if (event.key === 'c' || event.key === 'C') {
      if (!selectedId) { return; }
      // Do not steal a real text selection on the page.
      var sel = window.getSelection && window.getSelection();
      if (sel && str(sel.toString())) { return; }
      event.preventDefault();
      copyFlowAsSaved(selectedId);
      return;
    }
    if (event.key === 'v' || event.key === 'V') {
      // Paste is handled on the paste event so the clipboard can be read.
      return;
    }
  });

  async function copyFlowAsSaved(id) {
    try {
      var text = await flowToSavedJson(id);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        throw new Error('no clipboard');
      }
      flashSavedHint('Copied live request as a saved request. Paste into Saved requests.');
    } catch (error) {
      try {
        var again = await flowToSavedJson(id);
        offerSavedText(again);
      } catch (err) {
        flashSavedHint('Could not copy: ' + err.message);
      }
    }
  }

  function offerSavedText(text) {
    var head = detailEl.querySelector('.dhead') || detailEl;
    var stale = detailEl.querySelector('pre.copy-saved');
    if (stale) { stale.parentNode.removeChild(stale); }
    var pre = el('pre', 'copy copy-saved mono', text);
    if (head.nextSibling) {
      detailEl.insertBefore(pre, head.nextSibling);
    } else {
      detailEl.appendChild(pre);
    }
    flashSavedHint('Clipboard blocked; saved request is below to copy by hand.');
  }

  function flashSavedHint(message) {
    noBooksEl.hidden = false;
    noBooksEl.textContent = message;
  }

  document.addEventListener('paste', function (event) {
    if (typingTarget(event.target)) { return; }
    var panel = document.getElementById('saved');
    // Only when focus is on the saved side or nothing particular, so we do not
    // hijack paste meant for the filter box (already excluded) or composer.
    var inSaved = panel && (panel.contains(event.target) || document.activeElement === document.body);
    if (!inSaved && event.target !== booksEl && event.target !== noBooksEl) {
      // Still allow paste when the selection is a flow and user is on the list:
      // the intent "I copied a live request, paste into saved" is global enough
      // when the clipboard carries our prefix.
    }
    var text = '';
    try {
      text = (event.clipboardData && event.clipboardData.getData('text/plain')) || '';
    } catch (error) { return; }
    if (text.indexOf(SAVED_CLIP_PREFIX) !== 0 && text.indexOf('"spec"') < 0) {
      return;
    }
    try {
      var saved = parseSavedClipboard(text);
      event.preventDefault();
      appendSaved(null, saved).then(function () {
        flashSavedHint('Pasted into saved requests as ' + saved.name + '.');
      }).catch(function (error) {
        flashSavedHint('Could not paste: ' + error.message);
      });
    } catch (error) {
      // Not our payload; leave paste alone.
    }
  });

  /* Either half of the column folds to its bar. Which of them is folded is
     remembered, because it is a decision about how you work rather than about
     what is on screen at the moment. */

  var shutParts = readShut();

  function readShut() {
    try {
      var held = JSON.parse(localStorage.getItem('proxima.shut') || '[]');
      return Array.isArray(held) ? held.filter(function (p) { return typeof p === 'string'; }) : [];
    } catch (error) {
      return [];
    }
  }

  function foldPart(name, shut) {
    var part = document.getElementById(name);
    if (!part) { return; }
    part.classList.toggle('shut', shut);
    part.querySelector('.twist').textContent = shut ? '▸' : '▾';
  }

  /* One search box per bar, folded away until it is asked for: two boxes always
     on screen would take a line each from the trees they search. */

  function huntBox(buttonId, inputId, run) {
    var button = document.getElementById(buttonId);
    var box = document.getElementById(inputId);
    button.addEventListener('click', function (event) {
      // The bar it sits on folds the section, which is not what was asked for.
      event.stopPropagation();
      box.hidden = !box.hidden;
      button.classList.toggle('on', !box.hidden);
      if (box.hidden) {
        box.value = '';
        run('');
      } else {
        box.focus();
      }
    });
    box.addEventListener('input', function () { run(box.value); });
    box.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') { return; }
      box.value = '';
      box.hidden = true;
      button.classList.remove('on');
      run('');
    });
  }

  /* The button beside each search: what the tree under it is cut by, and what
     it leaves out. Both bars carry one, because both are trees that could be
     read more than one way, and neither question is worth a row of controls
     standing there all day to ask it. */

  function siftBox(buttonId, build) {
    var button = document.getElementById(buttonId);
    var menu = el('div', 'menu');
    menu.setAttribute('role', 'menu');
    menu.hidden = true;
    button.parentNode.appendChild(menu);

    // The headings group the choices for the eye; the same grouping is spelled
    // out for anything not reading with one.
    var band = null;

    function head(text) {
      band = el('div', 'mband');
      band.setAttribute('role', 'group');
      band.setAttribute('aria-label', text);
      band.appendChild(el('span', 'mhead', text));
      menu.appendChild(band);
    }

    // One of a set rather than a switch of its own: what the tick says to the
    // eye, the state says to a reader.
    function pick(label, on, take) {
      var entry = el('button', 'mitem');
      entry.type = 'button';
      entry.setAttribute('role', 'menuitemradio');
      entry.setAttribute('aria-checked', on ? 'true' : 'false');
      entry.appendChild(el('span', 'tick', on ? '✓' : ''));
      entry.appendChild(el('span', null, label));
      entry.addEventListener('click', function (event) {
        // The bar it hangs off folds the section, which is not what was asked
        // for, and the document listener would close the menu twice over.
        event.stopPropagation();
        shut();
        take();
        rememberSift();
      });
      (band || menu).appendChild(entry);
    }

    button.addEventListener('click', function (event) {
      event.stopPropagation();
      var open = menu.hidden;
      shut();
      if (!open) { return; }
      // Built at every opening, so the ticks describe the state as it is now
      // rather than as it was when the page loaded.
      strip(menu);
      band = null;
      build(head, pick);
      menu.hidden = false;
      button.classList.add('on');
      button.setAttribute('aria-expanded', 'true');
      openMenu = menu;
      openCaret = button;
    });
  }

  siftBox('sift-live', function (head, pick) {
    head('Group by');
    pick('Host', liveGroup === 'host', function () { regroupLive('host'); });
    pick('Device, then host', liveGroup === 'device', function () { regroupLive('device'); });
    head('Method');
    pick('Any', listMethod === '', function () { setListMethod(''); });
    pick('GET', listMethod === 'GET', function () { setListMethod('GET'); });
    pick('POST', listMethod === 'POST', function () { setListMethod('POST'); });
    pick('PUT', listMethod === 'PUT', function () { setListMethod('PUT'); });
    pick('PATCH', listMethod === 'PATCH', function () { setListMethod('PATCH'); });
    pick('DELETE', listMethod === 'DELETE', function () { setListMethod('DELETE'); });
    pick('HEAD', listMethod === 'HEAD', function () { setListMethod('HEAD'); });
    pick('OPTIONS', listMethod === 'OPTIONS', function () { setListMethod('OPTIONS'); });
    head('Status');
    pick('Any', listStatus === '', function () { setListStatus(''); });
    pick('2xx', listStatus === '2xx', function () { setListStatus('2xx'); });
    pick('3xx', listStatus === '3xx', function () { setListStatus('3xx'); });
    pick('4xx', listStatus === '4xx', function () { setListStatus('4xx'); });
    pick('5xx', listStatus === '5xx', function () { setListStatus('5xx'); });
    head('Kind');
    pick('Any', listKind === '', function () { setListKind(''); });
    pick('HTTP', listKind === 'http', function () { setListKind('http'); });
    pick('WebSocket', listKind === 'websocket', function () { setListKind('websocket'); });
    pick('Tunnel', listKind === 'tunnel', function () { setListKind('tunnel'); });
    head('Show');
    pick('Everything', !onlyErrors && !onlyMocked, function () {
      setOnlyErrors(false);
      setOnlyMocked(false);
    });
    pick('Failures only', onlyErrors, function () { setOnlyErrors(true); });
    pick('Mocks only', onlyMocked, function () { setOnlyMocked(true); });
  });

  function regroupLive(how) {
    if (liveGroup === how) { return; }
    liveGroup = how;
    dressSift();
    regroup();
  }

  // Structured cuts re-fetch so the retained window matches the store, then
  // live socket rows keep the same predicates via matchesListFilters.
  function setListMethod(method) {
    if (listMethod === method) { return; }
    listMethod = method;
    dressSift();
    reload();
  }

  function setListStatus(status) {
    if (listStatus === status) { return; }
    listStatus = status;
    dressSift();
    reload();
  }

  function setListKind(kind) {
    if (listKind === kind) { return; }
    listKind = kind;
    dressSift();
    reload();
  }

  function setOnlyErrors(only) {
    if (onlyErrors === only) { return; }
    onlyErrors = only;
    dressSift();
    reload();
  }

  function setOnlyMocked(only) {
    if (onlyMocked === only) { return; }
    onlyMocked = only;
    dressSift();
    reload();
  }

  siftBox('sift-saved', function (head, pick) {
    head('Group by');
    pick('Collection', bookGroup === 'book', function () { regroupBooks('book'); });
    pick('Method', bookGroup === 'method', function () { regroupBooks('method'); });
    pick('Host', bookGroup === 'host', function () { regroupBooks('host'); });
  });

  function regroupBooks(how) {
    if (bookGroup === how) { return; }
    bookGroup = how;
    dressSift();
    paintBooks();
  }

  /* A cut through the traffic is a decision about how it is being read, and it
     outlives the tab for the same reason the folds and the theme do. */

  function rememberSift() {
    try {
      localStorage.setItem('proxima.sift', JSON.stringify({
        live: liveGroup, bad: onlyErrors, mock: onlyMocked, saved: bookGroup,
        method: listMethod, status: listStatus, kind: listKind
      }));
    } catch (error) { /* not fatal */ }
  }

  function recallSift() {
    var held;
    try { held = JSON.parse(localStorage.getItem('proxima.sift') || '{}'); }
    catch (error) { return; }
    if (!held || typeof held !== 'object') { return; }
    // Anything not one of ours is left at the default rather than trusted.
    if (held.live === 'device') { liveGroup = 'device'; }
    if (held.saved === 'method' || held.saved === 'host') { bookGroup = held.saved; }
    onlyErrors = held.bad === true;
    onlyMocked = held.mock === true;
    var methods = {
      GET: 1, POST: 1, PUT: 1, PATCH: 1, DELETE: 1, HEAD: 1, OPTIONS: 1
    };
    if (typeof held.method === 'string' && methods[held.method]) {
      listMethod = held.method;
    }
    if (held.status === '2xx' || held.status === '3xx' ||
        held.status === '4xx' || held.status === '5xx') {
      listStatus = held.status;
    }
    if (held.kind === 'http' || held.kind === 'websocket' || held.kind === 'tunnel') {
      listKind = held.kind;
    }
    dressSift();
  }

  /* Two things a button can be saying at once: that its menu is open, and that
     something in that menu is set to other than the default. The first is the
     class every menu here uses and is taken back the moment the menu closes,
     so the second needs one of its own or it would close with it. */

  function dressSift() {
    var n = structuredFilterCount();
    var liveBtn = document.getElementById('sift-live');
    liveBtn.classList.toggle('set', n > 0 || liveGroup !== 'host');
    var label = n
      ? ('Grouping and filters, ' + n + ' active')
      : 'Grouping and filters';
    liveBtn.title = label;
    liveBtn.setAttribute('aria-label', label);
    if (n > 0) { liveBtn.setAttribute('data-count', String(n)); }
    else { liveBtn.removeAttribute('data-count'); }
    document.getElementById('sift-saved').classList.toggle('set', bookGroup !== 'book');
  }

  recallSift();

  huntBox('hunt-live', 'live-hunt', huntHosts);
  huntBox('hunt-saved', 'saved-hunt', function (text) {
    bookHunt = text.trim().toLowerCase();
    paintBooks();
  });

  var shelves = document.querySelectorAll('.shelf');
  for (var s = 0; s < shelves.length; s++) {
    (function (shelf) {
      var name = shelf.getAttribute('data-part');
      foldPart(name, shutParts.indexOf(name) >= 0);
      shelf.addEventListener('click', function () {
        var at = shutParts.indexOf(name);
        if (at < 0) { shutParts.push(name); } else { shutParts.splice(at, 1); }
        try { localStorage.setItem('proxima.shut', JSON.stringify(shutParts)); }
        catch (error) { /* not fatal */ }
        foldPart(name, at < 0);
      });
    }(shelves[s]));
  }

  document.getElementById('c-save').addEventListener('click', saveComposed);
  var historyBtn = document.getElementById('c-history');
  if (historyBtn) {
    historyBtn.addEventListener('click', showHistory);
  }
  document.getElementById('new-book').addEventListener('click', async function (event) {
    // The bar it sits on folds the section, which is not what was asked for.
    event.stopPropagation();
    try {
      await putBook({ id: '', name: 'New collection', requests: [] });
      await loadBooks();
    } catch (error) {
      noBooksEl.hidden = false;
      noBooksEl.textContent = 'Could not add a collection: ' + error.message;
    }
  });

  /* ---------------------------------------------------------------- */
  /* recent sends (composer history)                                   */
  /* ---------------------------------------------------------------- */

  var recentSends = [];
  var recentListEl = document.getElementById('recent-list');
  var noRecentEl = document.getElementById('no-recent');

  async function loadRecent() {
    try {
      var got = await getJson('/api/send-history');
      recentSends = Array.isArray(got) ? got : [];
    } catch (error) {
      recentSends = [];
    }
    paintRecent();
  }

  function paintRecent() {
    if (!recentListEl) { return; }
    strip(recentListEl);
    if (noRecentEl) { noRecentEl.hidden = recentSends.length > 0; }
    for (var i = 0; i < recentSends.length; i++) {
      recentListEl.appendChild(recentNode(recentSends[i]));
    }
  }

  function recentNode(entry) {
    var spec = entry.spec || {};
    var item = el('div', 'sitem');
    item.appendChild(el('span', 'smethod', str(spec.method) || 'GET'));
    item.appendChild(el('span', 'sname', str(entry.name) || str(spec.url)));
    if (entry.status != null && entry.status !== '') {
      item.appendChild(el('span', 'smeta', str(entry.status)));
    }
    var kill = el('button', 'kill', '×');
    kill.type = 'button';
    kill.title = 'Remove from recent';
    kill.setAttribute('aria-label', 'Remove from recent');
    kill.addEventListener('click', function (event) {
      event.stopPropagation();
      dropRecent(entry);
    });
    item.appendChild(kill);
    item.addEventListener('click', function () { openRecent(entry); });
    return item;
  }

  function openRecent(entry) {
    // A past send is a draft, not an overwrite of whatever saved request was open.
    fillComposer(str(entry.name), entry.spec || {}, { savedId: '' });
  }

  async function dropRecent(entry) {
    if (!entry || !entry.id) { return; }
    try {
      var response = await fetch('/api/send-history/' + encodeURIComponent(entry.id), {
        method: 'DELETE',
        cache: 'no-store'
      });
      if (!response.ok) { throw new Error('the server answered ' + response.status); }
      await loadRecent();
    } catch (error) {
      if (noRecentEl) {
        noRecentEl.hidden = false;
        noRecentEl.textContent = 'Could not remove that: ' + error.message;
      }
    }
  }

  async function clearRecent() {
    try {
      var response = await fetch('/api/send-history', {
        method: 'DELETE',
        cache: 'no-store'
      });
      if (!response.ok) { throw new Error('the server answered ' + response.status); }
      await loadRecent();
    } catch (error) {
      if (noRecentEl) {
        noRecentEl.hidden = false;
        noRecentEl.textContent = 'Could not clear recent: ' + error.message;
      }
    }
  }

  var clearRecentBtn = document.getElementById('clear-recent');
  if (clearRecentBtn) {
    clearRecentBtn.addEventListener('click', function (event) {
      event.stopPropagation();
      clearRecent();
    });
  }

  loadBooks();
  loadRecent();
  paintVersions();
  loadRules();
  loadPauses();

  document.getElementById('clear').addEventListener('click', async function () {
    try {
      var response = await fetch('/api/flows', { method: 'DELETE', cache: 'no-store' });
      if (!response.ok) { throw new Error('the server answered ' + response.status); }
      wipe();
    } catch (error) {
      hint('Could not clear the capture: ' + error.message);
    }
  });

  connect();
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FlowKind, FlowState, FlowSummary, HttpVersion, Scheme};

    /// Every JavaScript string literal in the script, on the assumption that
    /// single quotes always delimit one. Nothing in the script escapes a quote,
    /// and a test that breaks the day something does is the point.
    fn literals() -> Vec<&'static str> {
        SCRIPT.split('\'').skip(1).step_by(2).collect()
    }

    #[test]
    fn captured_data_has_no_route_into_the_html_parser() {
        for sink in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "createContextualFragment",
            "setHTMLUnsafe",
            "srcdoc",
            "eval(",
            "new Function",
            "javascript:",
        ] {
            assert!(
                !SCRIPT.contains(sink),
                "the inspector must not use {sink}: captured bodies reach the document \
                 as text or not at all"
            );
        }
        assert!(
            SCRIPT.contains("node.textContent = String(text)"),
            "the single node builder must still be the one that sets textContent"
        );
    }

    #[test]
    fn a_response_body_holding_a_script_tag_renders_as_text() {
        // A body is written with textContent on a node that is already in the
        // tree, so its bytes are never handed to the HTML parser. There is no
        // second path: the sink check above covers the rest of the file.
        assert!(
            SCRIPT.contains("function paintJson(into, view)")
                && SCRIPT.contains("into.appendChild(el('span', 'j-' + kind"),
            "JSON bodies paint as textContent spans, never markup strings"
        );
        assert!(
            SCRIPT.contains("into.textContent = text + suffix")
                || SCRIPT.contains("into.textContent = 'Could not read the body:"),
            "non-JSON bodies still land as plain textContent"
        );
        assert!(
            SCRIPT.contains("pre.textContent = 'Binary. Download it"),
            "an undisplayable body must still be replaced rather than rendered"
        );
    }

    #[test]
    fn captured_header_names_and_values_are_built_as_nodes_not_markup() {
        for line in [
            "line.appendChild(el('span', 'hname', str(pair[0])));",
            "line.appendChild(el('span', 'hval', str(pair[1])));",
        ] {
            assert!(
                SCRIPT.contains(line),
                "header rendering must go through the node builder: {line}"
            );
        }
    }

    #[test]
    fn the_page_shell_carries_exactly_one_script_of_its_own() {
        let rendered = page("Zm9ydHl0d28");
        assert_eq!(
            rendered.matches("<script").count(),
            1,
            "the page has one script element, the one this file wrote"
        );
        assert_eq!(
            rendered.matches("<style").count(),
            1,
            "the page has one style element, the one this file wrote"
        );
    }

    #[test]
    fn the_page_substitutes_nothing_but_its_own_nonce() {
        let one = page("aaaaaaaaaaaa").replace("aaaaaaaaaaaa", "N");
        let two = page("bbbbbbbbbbbb").replace("bbbbbbbbbbbb", "N");
        assert_eq!(
            one, two,
            "the only value the page interpolates must be the nonce"
        );
    }

    #[test]
    fn the_inline_script_and_style_cannot_end_themselves_early() {
        for (name, source) in [("script", SCRIPT), ("style", CSS)] {
            assert!(
                !source.contains("</"),
                "a closing tag inside the inline {name} would end it early"
            );
            assert!(
                !source.contains("<!--"),
                "a comment opener inside the inline {name} confuses the parser"
            );
        }
    }

    #[test]
    fn the_inspector_loads_nothing_from_the_network() {
        let rendered = page("nonce");
        for fragment in ["src=\"http", "href=\"http", "@import", "//cdn", "fonts."] {
            assert!(
                !rendered.contains(fragment),
                "the inspector must be self contained, found {fragment}"
            );
        }
    }

    /// Every path-shaped literal in the script, whether it opens an endpoint or
    /// is concatenated onto the middle of one. The suffixes matter as much as
    /// the prefixes: `/curl` and `/body/` are the halves that decide which route
    /// a request lands on, and checking only the `/api` prefix would let a
    /// rename of either go unnoticed.
    const KNOWN_PATHS: [&str; 25] = [
        "/api/flows",
        "/api/flows?",
        "/api/flows/",
        "/api/bodies/",
        "/api/json/view",
        "/api/stream",
        "/api/send",
        "/api/send-history",
        "/api/send-history/",
        "/api/collections",
        "/api/collections/",
        "/api/environments",
        "/api/environments/active",
        "/api/breakpoints",
        "/api/ws-rewrite",
        "/api/rewrite",
        "/api/archive/stats",
        "/api/pauses",
        "/api/pauses/",
        "/body/",
        "/curl",
        "/ws/send",
        "/ws/replay",
        "/drop",
        "/release",
    ];

    #[test]
    fn the_page_only_calls_endpoints_the_router_serves() {
        for literal in literals() {
            // Two leading slashes in the script name nothing on the router:
            // the scheme separator the socket URL is built from, and the
            // separator the tree splits a path on.
            if literal.starts_with('/') && literal != "//" && literal != "/" {
                assert!(
                    KNOWN_PATHS.contains(&literal),
                    "{literal} is not an endpoint the router serves"
                );
            }
        }
        for path in KNOWN_PATHS {
            assert!(
                literals().contains(&path),
                "{path} is listed as used but no longer appears in the script"
            );
        }
    }

    #[test]
    fn the_endpoints_the_script_assembles_are_the_ones_the_router_spells_out() {
        // These two are only ever built by concatenation, so the literal scan
        // above sees the halves and never the whole.
        for (expression, route) in [
            (
                "'/api/flows/' + encodeURIComponent(id) + '/body/' + which",
                "/api/flows/{id}/body/{which}",
            ),
            (
                "'/api/bodies/' + encodeURIComponent(message.bodyId) + '?pretty=1'",
                "/api/bodies/{id}",
            ),
            (
                "'/api/flows/' + encodeURIComponent(id) + '/curl'",
                "/api/flows/{id}/curl",
            ),
            (
                "'/api/flows/' + encodeURIComponent(id) + '/ws/send'",
                "/api/flows/{id}/ws/send",
            ),
            (
                "'/api/flows/' + encodeURIComponent(sourceId) + '/ws/replay'",
                "/api/flows/{id}/ws/replay",
            ),
            (
                "'/api/pauses/' + encodeURIComponent(pauseId) + '/drop'",
                "/api/pauses/{pauseId}/drop",
            ),
            (
                "'/api/pauses/' + encodeURIComponent(pauseId) + '/release'",
                "/api/pauses/{pauseId}/release",
            ),
        ] {
            assert!(
                SCRIPT.contains(expression),
                "{route} is a route, but nothing in the script assembles it any more"
            );
        }

        assert!(
            BODY.contains("href=\"/setup\""),
            "the setup link is the one endpoint the markup reaches on its own"
        );
        assert_eq!(
            BODY.matches("href=").count(),
            1,
            "a second href in the markup would be a second endpoint nothing checks"
        );
    }

    #[test]
    fn the_filter_matches_by_substring_so_a_regex_metacharacter_is_just_text() {
        // Typing `.*` or `a(b` into the filter has to narrow the list, not throw
        // and not match everything, which is what building a RegExp out of it
        // would do.
        assert!(
            SCRIPT.contains("text.indexOf(needle) < 0"),
            "the filter must stay a substring search"
        );
        for builder in ["new RegExp", ".match(", ".test(", ".search("] {
            assert!(
                !SCRIPT.contains(builder),
                "the filter needle must never reach {builder}: a metacharacter typed \
                 into the box would change what matches, or throw"
            );
        }
        assert!(
            SCRIPT.contains("filterEl.value.trim().toLowerCase()"),
            "the needle is lowercased once, and the haystack with it"
        );
    }

    #[test]
    fn the_tree_and_the_filter_box_narrow_the_one_list_together() {
        // Picking a branch is a second narrowing of the same list, not a second
        // list. Both have to reach the same decision about a row, or clicking a
        // host would show rows the typed filter had already ruled out.
        let filter = SCRIPT
            .split_once("function filterRow(row, id) {")
            .expect("the script still filters rows")
            .1;
        for cut in [
            "(needle !== '' && text.indexOf(needle) < 0)",
            "(device !== '' && homes.get(id) !== device)",
            "!inScope(id)",
        ] {
            assert!(
                filter.contains(cut),
                "a row has to survive every narrowing at once, not any one: {cut}"
            );
        }
        assert!(
            SCRIPT.contains("rows.forEach(function (row, id) { filterRow(row, id); });"),
            "picking a branch and typing both re-decide every row"
        );
    }

    #[test]
    fn a_branch_claims_whole_segments_and_not_prefixes() {
        // Scoping to example.com/v1 must leave example.com/v10 alone, which is
        // what the trailing separator in the comparison is for.
        assert!(
            SCRIPT.contains("held.key === scope || held.key.indexOf(scope + '/') === 0"),
            "the scope test must compare whole path segments"
        );
    }

    #[test]
    fn a_flow_leaving_the_list_leaves_the_tree_with_it() {
        // The list is capped at MAX_ROWS. Without the same eviction on the tree
        // side, the branches keep every flow the process has ever seen, their
        // counts describe flows nothing can show, and the cap stops meaning
        // anything.
        let trim = SCRIPT
            .split_once("function trim() {")
            .expect("the script still trims the list")
            .1;
        assert!(
            trim.contains("unplace(last.flowId);"),
            "trimming a row must take it off its branch as well"
        );
        let wipe = SCRIPT
            .split_once("function wipe() {")
            .expect("the script still wipes")
            .1;
        for reset in [
            "strip(treeEl);",
            "groups.clear();",
            "branches.clear();",
            "scope = '';",
        ] {
            assert!(
                wipe.contains(reset),
                "clearing the capture must empty the tree too: {reset}"
            );
        }
        assert!(
            SCRIPT.contains("while (rec && rec.total === 0) {"),
            "a branch whose last flow left has to be pruned, not kept empty"
        );
        assert!(
            SCRIPT.contains("if (rec.key === scope) { scopeTo(scope, false); }"),
            "a pruned branch cannot go on being the thing the list is narrowed to"
        );
    }

    /// Byte offsets of every colour literal in a stylesheet: a `#` followed by
    /// exactly three or six hex digits and then something that is not one. The
    /// length check is what keeps an id selector like `#detail` or `#empty` out
    /// of the results.
    fn colour_literals(css: &str) -> Vec<usize> {
        let bytes = css.as_bytes();
        let mut found = Vec::new();
        for (at, _) in css.match_indices('#') {
            let digits = bytes[at + 1..]
                .iter()
                .take_while(|b| b.is_ascii_hexdigit())
                .count();
            let after = bytes.get(at + 1 + digits);
            let runs_on = after.is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-');
            if (digits == 3 || digits == 6) && !runs_on {
                found.push(at);
            }
        }
        found
    }

    #[test]
    fn every_colour_is_named_once_and_carries_both_schemes() {
        // The page is read in whichever scheme the machine is set to, and only
        // one of the two gets looked at while it is being worked on. A literal
        // outside the palette is a colour that was only ever checked against one
        // background; a palette entry that is not a pair is the same thing.
        let (palette, rest) = CSS
            .split_once("html, body {")
            .expect("the palette still comes before the page");
        assert!(
            colour_literals(rest).is_empty(),
            "every colour belongs in the palette, found one further down: {:?}",
            colour_literals(rest)
                .iter()
                .map(|at| &rest[*at..*at + 7])
                .collect::<Vec<_>>()
        );

        let mut entries = 0;
        for line in palette.lines() {
            let Some((name, value)) = line.trim().split_once(": ") else {
                continue;
            };
            if !name.starts_with("--") {
                continue;
            }
            entries += 1;
            assert!(
                value.starts_with("light-dark(") && colour_literals(value).len() == 2,
                "{name} has to name a colour for each scheme, got {value}"
            );
        }
        assert!(entries > 12, "the palette lost most of itself: {entries}");

        assert!(
            page("nonce").contains("content=\"light dark\""),
            "the page has to admit to both schemes or the browser paints its own"
        );
    }

    #[test]
    fn the_scheme_follows_the_machine_until_it_is_told_not_to() {
        // The switch works by changing which half of every light-dark() pair is
        // used, so it needs no second palette to fall out of step with.
        for rule in [
            ":root[data-theme=\"light\"] { color-scheme: light; }",
            ":root[data-theme=\"dark\"] { color-scheme: dark; }",
        ] {
            assert!(CSS.contains(rule), "the theme switch needs {rule}");
        }
        assert!(
            SCRIPT.contains("document.documentElement.removeAttribute('data-theme');"),
            "going back to system means dropping the override, not picking a side"
        );
        // Storage is refused outright in private browsing, and a page that
        // throws on load paints nothing at all.
        let remembered = SCRIPT
            .split_once("function rememberedTheme() {")
            .expect("the script still remembers a theme")
            .1;
        assert!(
            remembered.contains("try {") && remembered.contains("return 'system';"),
            "unreadable storage has to fall back rather than throw"
        );
        assert!(
            SCRIPT.contains("THEMES.indexOf(held) < 0 ? 'system' : held"),
            "a stored value from another build is not one of ours"
        );
    }

    #[test]
    fn the_bottom_pane_shows_one_side_or_all_of_them() {
        // Request and response are the same shape and are read against each
        // other, so both have to fit on screen at once as well as one at a time.
        for line in [
            "panes.className = paired ? 'panes both' : 'panes';",
            "panes.appendChild(pane(side, flow, request, response, frames));",
        ] {
            assert!(SCRIPT.contains(line), "the bottom pane needs both modes: {line}");
        }
        for tab in ["offer('info', 'Info');", "offer('request', 'Request');"] {
            assert!(SCRIPT.contains(tab), "the bottom pane lost a tab: {tab}");
        }
        // Which side you are reading is a preference, not a property of the
        // flow, so it is declared outside the function that draws one.
        assert!(
            SCRIPT.contains("var side = 'info';") && SCRIPT.contains("var paired = false;"),
            "the choice of side must outlive the flow that was on screen"
        );
        // A flow in flight has no response, and most have no frames. What every
        // flow has is the account of itself, so that is where a missing side
        // lands rather than on a tab that is not there.
        for fallback in [
            "if (side === 'response' && !response) { side = 'info'; }",
            "if (side === 'frames' && !frames) { side = 'info'; }",
        ] {
            assert!(
                SCRIPT.contains(fallback),
                "a missing side must not leave the pane pointed at nothing: {fallback}"
            );
        }
    }

    #[test]
    fn the_copy_control_is_a_mark_that_still_says_what_it_did() {
        // A single character has no room to report anything, so what it did has
        // to reach the tooltip as well, and a control with no words at all needs
        // a name for anything that is not looking at it.
        for named in [
            "mark.setAttribute('aria-label', 'Copy as cURL');",
            "mark.title = 'Copy as cURL';",
            "caret.setAttribute('aria-label', 'Other things to copy');",
            "caret.title = 'Other things to copy';",
        ] {
            assert!(SCRIPT.contains(named), "a wordless control has to name itself: {named}");
        }
        let says = SCRIPT
            .split_once("function says(button, mark, why) {")
            .expect("the script still speaks through the mark")
            .1;
        assert!(
            says.contains("button.textContent = mark;") && says.contains("button.title = why;"),
            "every outcome must change the mark and the tooltip together"
        );
        // The clipboard is absent over plain HTTP to a LAN address, which is
        // how a phone reaches this page. The command is the point either way.
        assert!(
            SCRIPT.contains("offer(button, text);"),
            "a refused clipboard must still put the command on screen"
        );
    }

    #[test]
    fn the_copy_menu_offers_only_what_the_flow_has() {
        // An entry for a body that was never captured copies an empty string
        // and looks like the copy failed, so each one is asked for first.
        for guard in [
            "if (request.body) {",
            "if (response) {",
            "if (response.body) {",
        ] {
            assert!(
                SCRIPT.contains(guard),
                "the menu must not offer what the flow does not have: {guard}"
            );
        }
        // Every entry goes through the one copy path, so the mark reports the
        // outcome whichever of them was picked.
        assert_eq!(
            SCRIPT.matches("copyWhat(mark, make);").count(),
            1,
            "the menu entries share one copy path"
        );
        // A menu left open over a flow that is no longer on screen is a menu
        // acting on the wrong one.
        assert!(
            SCRIPT.contains("document.addEventListener('click', shut);"),
            "a click anywhere else has to close the menu"
        );
        assert!(
            SCRIPT.contains("if (event.key === 'Escape') { shut(); }"),
            "escape has to close the menu"
        );
        assert!(
            SCRIPT.contains("event.stopPropagation();"),
            "the click that opens the menu must not also be the one that closes it"
        );
    }

    #[test]
    fn switching_halves_hands_back_the_frame_list() {
        // The frames block is one of the halves now, so leaving it detaches the
        // node every later frame would have been appended to.
        let draw = SCRIPT
            .split_once("function draw() {")
            .expect("the bottom pane still redraws itself")
            .1;
        for reset in ["frameList = null;", "frameOwner = null;"] {
            assert!(
                draw.contains(reset),
                "redrawing the bottom pane must drop the frame list: {reset}"
            );
        }
    }

    #[test]
    fn a_device_that_no_longer_has_a_flow_stops_being_offered() {
        // The chips are counted from the flows on screen. A flow evicted from
        // the ring buffer that never decrements its device leaves a chip that
        // narrows the list to nothing.
        let trim = SCRIPT
            .split_once("function trim() {")
            .expect("the script still trims")
            .1;
        assert!(
            trim.contains("forget(last.flowId);"),
            "an evicted flow must stop counting towards its device"
        );
        assert!(
            SCRIPT.contains("if (device && !seen.has(device)) { pickDevice(device); }"),
            "a device with nothing left cannot go on being the one that is picked"
        );
        // One device is the ordinary case: a row of chips to choose between one
        // thing is a row that only takes up height.
        assert!(
            SCRIPT.contains("if (seen.size < 2) {"),
            "a single device needs no choosing between"
        );
    }

    #[test]
    fn both_halves_of_the_column_carry_a_bar_and_fold_away() {
        for shelf in [
            "data-part=\"live\"",
            "data-part=\"saved\"",
            "data-part=\"recent\"",
        ] {
            assert!(
                BODY.contains(shelf),
                "each half of the column needs a bar of its own: {shelf}"
            );
        }
        // A folded half keeps its bar and nothing else, or there is no way back.
        assert!(
            CSS.contains(".part.shut > *:not(.shelf) { display: none; }"),
            "folding a half must leave the bar that unfolds it"
        );
        // The shares are set on the ids, so the rule that drops them has to be
        // as well. A class alone loses, and the folded half goes on holding the
        // room it was given, which is a bar with a hole under it.
        assert!(
            CSS.contains("#live.shut, #saved.shut, #recent.shut { flex: none;"),
            "a folded half must give its share of the column back"
        );
        // Panel-wide rows; absolute count rail; star replaces digit on pin hover.
        assert!(
            CSS.contains(".tree-scroll {\n  flex: none;\n  width: 100%; max-width: 100%;\n  overflow-x: hidden; overflow-y: hidden;"),
            "the tree stays the panel width; long names ellipsis instead of a sticky rail"
        );
        assert!(
            BODY.contains("class=\"tree-scroll\"")
                && BODY.contains("id=\"hosts\"")
                && BODY.contains("id=\"books\""),
            "hosts and books sit inside the tree shell"
        );
        assert!(
            CSS.contains(".gcount {\n  position: absolute; right: 6px;")
                && CSS.contains("text-align: right;")
                && CSS.contains("font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;"),
            "counts sit absolute on the row's right edge, monospace right-aligned"
        );
        assert!(
            !CSS.contains("position: sticky; right:")
                && !CSS.contains(".gcount {\n  position: sticky"),
            "counts must not be sticky: they painted over the shelf buttons"
        );
        assert!(
            CSS.contains("width: calc(100% + var(--d));")
                && CSS.contains("margin-left: calc(0px - var(--d));")
                && CSS.contains("--d: calc(var(--d) + 11px);")
                && CSS.contains("padding: 3px 2.5rem 3px calc(4px + var(--d));"),
            "nested rows span the full panel and reserve a fixed count rail"
        );
        assert!(
            CSS.contains(".shelf {\n  position: sticky; top: 0; left: 0; z-index: 5;"),
            "the shelf stays above scrolled rows so hunt/sift stay clickable"
        );
        assert!(
            CSS.contains(".gpin {\n  position: absolute; right: 6px;")
                && CSS.contains(".gpin:hover > .star { visibility: visible; color: var(--dim); }")
                && CSS.contains(".star.on { visibility: visible; color: var(--accent); }")
                && CSS.contains(".gpin:hover > .gcount,\n.gpin:has(> .star.on) > .gcount { visibility: hidden; }")
                && !CSS.contains(".gline:hover > .star")
                && !CSS.contains(".star {\n  position: absolute; right: 0; top: 50%; transform: translateY(-50%);\n  box-sizing: border-box;\n  min-width: 2.25rem;\n  visibility: hidden; padding: 0; margin: 0; cursor: default;\n  background: none; border: none; color: var(--warn);"),
            "star replaces the count on digit hover; dim/accent colours, not yellow"
        );
        assert!(
            SCRIPT.contains("var pin = el('span', 'gpin');")
                && SCRIPT.contains("pin.appendChild(starFor(box, label));")
                && SCRIPT.contains("pin.appendChild(count);"),
            "host rows wrap star and count so hover is limited to the digit"
        );
        assert!(
            !SCRIPT.contains("el('span', 'gmain')") && !CSS.contains(".gmain {"),
            "per-row gmain scroll panes must stay gone"
        );
        assert!(
            SCRIPT.contains("localStorage.setItem('proxima.shut', JSON.stringify(shutParts));"),
            "which half is folded has to outlive the tab"
        );
        // The button on the saved bar adds a collection rather than folding it.
        let adds = SCRIPT
            .split_once("document.getElementById('new-book')")
            .expect("the script still adds collections")
            .1;
        assert!(
            adds.contains("event.stopPropagation();"),
            "adding a collection must not fold the section it is added to"
        );
    }

    #[test]
    fn each_tree_searches_itself_without_touching_the_capture() {
        for control in ["id=\"hunt-live\"", "id=\"hunt-saved\"", "id=\"live-hunt\"", "id=\"saved-hunt\""] {
            assert!(BODY.contains(control), "each tree needs a search of its own: {control}");
        }
        // A branch that answers has to bring its ancestors with it, or it hides
        // inside a parent that does not answer itself.
        assert!(
            SCRIPT.contains("for (var up = rec; up; up = up.parent) { up.astray = false; }"),
            "a branch that answers must pull the ones above it into view"
        );
        // Hiding is one decision made in one place: an emptied branch and an
        // unanswering branch both go through it.
        let dress = SCRIPT
            .split_once("function dress(rec) {")
            .expect("the script still decides what a branch shows")
            .1;
        assert!(
            dress.contains("(rec.total > 0 && rec.shown === 0) || rec.astray === true"),
            "the filter box and the search must not each hide branches on their own"
        );
        // A host arriving mid-search would otherwise land on screen past a
        // filter it was never shown.
        assert!(
            SCRIPT.contains("if (hostHunt !== '') { huntHosts(hostHunt); }"),
            "a branch made while a search is on has to answer it too"
        );
        // The search buttons sit on bars that fold.
        let boxes = SCRIPT
            .split_once("function huntBox(buttonId, inputId, run) {")
            .expect("the script still builds search boxes")
            .1;
        assert!(
            boxes.contains("event.stopPropagation();"),
            "opening a search must not fold the section it searches"
        );
    }

    #[test]
    fn each_tree_can_be_cut_a_second_way_from_the_bar_it_sits_on() {
        for control in ["id=\"sift-live\"", "id=\"sift-saved\""] {
            assert!(
                BODY.contains(control),
                "each tree needs a grouping button of its own: {control}"
            );
        }
        // The button sits on a bar that folds, and inside a menu that a click
        // anywhere else closes: the click that opens it must do neither.
        let boxes = SCRIPT
            .split_once("function siftBox(buttonId, build) {")
            .expect("the script still builds grouping menus")
            .1
            .split_once("\n  siftBox(")
            .expect("the grouping menus are still built by it")
            .0;
        assert_eq!(
            boxes.matches("event.stopPropagation();").count(),
            2,
            "opening the menu and picking from it must each keep the click"
        );
        // Grouped by device the address is a whole segment above the host, so
        // the scope test already reaches everything under it.
        assert!(
            SCRIPT.contains("key += '/' + spot.host;"),
            "the device has to sit above the host as a branch, not beside it"
        );
        // Regrouping throws the tree away, so what it was built from has to
        // outlive the flow that carried it.
        let regroup = SCRIPT
            .split_once("function regroup() {")
            .expect("the script still regroups the tree")
            .1;
        for step in ["strip(treeEl);", "groups.clear();", "branches.clear();"] {
            assert!(
                regroup.contains(step),
                "regrouping must build the tree again rather than patch it: {step}"
            );
        }
        assert!(
            SCRIPT.contains("spots.set(flow.id, branch(flow));"),
            "the tree has to keep where a flow belongs, or it cannot be rebuilt"
        );
        // A cap that evicts rows without evicting what was kept beside them is
        // a leak the cap was there to prevent.
        let trim = SCRIPT
            .split_once("function trim() {")
            .expect("the script still trims the list")
            .1;
        for gone in ["spots.delete(last.flowId);", "bads.delete(last.flowId);"] {
            assert!(
                trim.contains(gone),
                "a trimmed row must take everything held under its id: {gone}"
            );
        }
    }

    #[test]
    fn a_menu_says_it_is_a_menu_and_whether_it_is_open() {
        // A mark for a name and a tick for a state is all a menu here shows,
        // and neither of them is anything to a reader that is not looking.
        for control in ["id=\"sift-live\"", "id=\"sift-saved\""] {
            let opens = BODY
                .split_once(control)
                .expect("the grouping buttons are still in the markup")
                .1;
            let button = opens.split_once('>').expect("the button still ends").0;
            for said in ["aria-haspopup=\"menu\"", "aria-expanded=\"false\""] {
                assert!(
                    button.contains(said),
                    "a button that opens a menu has to say so: {control} {said}"
                );
            }
        }
        assert_eq!(
            SCRIPT.matches("setAttribute('aria-expanded', 'true')").count(),
            1,
            "one place opens a menu, and it is where the state is set"
        );
        let shut = SCRIPT
            .split_once("function shut() {")
            .expect("the script still closes menus")
            .1;
        assert!(
            shut.contains("openCaret.setAttribute('aria-expanded', 'false');"),
            "a menu closed by a click elsewhere has to stop saying it is open"
        );
        // The picks are one of a set rather than a switch each, which is what
        // the tick beside them means and what the state has to say.
        assert!(
            SCRIPT.contains("entry.setAttribute('role', 'menuitemradio');")
                && SCRIPT.contains("entry.setAttribute('aria-checked', on ? 'true' : 'false');"),
            "an exclusive choice has to read as one"
        );
    }

    #[test]
    fn a_saved_url_is_filed_under_the_host_it_names() {
        // The composer's own box takes what is typed, and what is typed is
        // often a host without a scheme. Filed under a parse failure, most of
        // a collection would end up in one heap called nothing in particular.
        let host = SCRIPT
            .split_once("function hostOf(url) {")
            .expect("the script still reads a host out of a saved URL")
            .1;
        assert!(
            host.contains("new URL('https://' + text).host"),
            "a URL saved without a scheme still names a host"
        );
        assert!(
            host.contains("if (text.indexOf('://') >= 0) { return 'no host'; }"),
            "a scheme that is present and unusable must not be guessed at twice"
        );
        assert_eq!(
            host.matches("'no host'").count(),
            5,
            "everything that names no host is filed as naming none"
        );
    }

    #[test]
    fn a_menu_left_open_is_the_one_a_click_elsewhere_closes() {
        // Two menus on one page, and one pair of variables saying which is
        // open. Set where a menu is built, they name the last one built rather
        // than the open one, and the other is left on screen for good.
        assert_eq!(
            SCRIPT.matches("openMenu = menu;").count(),
            2,
            "each menu has to claim the open slot when it opens"
        );
        for opened in ["if (open) {", "menu.hidden = false;"] {
            assert!(
                SCRIPT.contains(opened),
                "the slot is claimed on the way open, not on the way shut: {opened}"
            );
        }
        // Closing takes back the class that says a menu is open, so what a
        // button says about its own settings cannot be the same class.
        assert!(
            SCRIPT.contains("classList.toggle('set',"),
            "a used menu and an open menu must not be the same mark"
        );
        assert!(
            CSS.contains(".icon.set {"),
            "the mark for a used menu has to be drawn"
        );
    }

    #[test]
    fn what_the_tree_is_cut_by_outlives_the_tab() {
        assert!(
            SCRIPT.contains("localStorage.setItem('proxima.sift', JSON.stringify({"),
            "how the trees are grouped has to outlive the tab"
        );
        let recall = SCRIPT
            .split_once("function recallSift() {")
            .expect("the script still reads back the grouping")
            .1;
        assert!(
            recall.contains("catch (error) { return; }"),
            "unreadable or invented storage has to fall back rather than throw"
        );
        // Storage is not ours to trust: anything but a value this build knows
        // leaves the tree grouped the way it starts out.
        for guard in [
            "if (held.live === 'device') { liveGroup = 'device'; }",
            "held.bad === true",
        ] {
            assert!(
                recall.contains(guard),
                "a stored value has to be one of ours before it is used: {guard}"
            );
        }
    }

    /// List load builds FlowQuery params (method/status/onlyErrors/kind) and
    /// free-text stays `search`. Live rows re-apply the same predicates.
    #[test]
    fn the_list_fetch_sends_structured_flow_query_filters() {
        let build = SCRIPT
            .split_once("function flowsQueryUrl() {")
            .expect("flowsQueryUrl builds GET /api/flows")
            .1;
        let body = build
            .split_once("function structuredFilterCount() {")
            .expect("structuredFilterCount follows flowsQueryUrl")
            .0;
        for fragment in [
            "parts.push('method=' + encodeURIComponent(listMethod))",
            "parts.push('status=' + encodeURIComponent(listStatus))",
            "parts.push('kind=' + encodeURIComponent(listKind))",
            "parts.push('onlyErrors=1')",
            "parts.push('onlyMocked=1')",
            "parts.push('search=' + encodeURIComponent(search))",
            "'/api/flows?' + parts.join('&')",
        ] {
            assert!(
                body.contains(fragment),
                "flowsQueryUrl must still assemble {fragment}"
            );
        }
        assert!(
            SCRIPT.contains("if (onlyMocked && !flow.mocked)"),
            "live filter must cut on FlowSummary.mocked when Mocks only is set"
        );
        assert!(
            SCRIPT.contains("var page = await getJson(flowsQueryUrl());"),
            "reload must fetch through flowsQueryUrl, not a bare limit"
        );
        // Client-side twin for live ws events between server reloads.
        assert!(
            SCRIPT.contains("function matchesListFilters(id) {"),
            "live rows must honour structured filters without waiting for reload"
        );
        let filter = SCRIPT
            .split_once("function filterRow(row, id) {")
            .expect("filterRow still exists")
            .1;
        assert!(
            filter.contains("!matchesListFilters(id)"),
            "filterRow must apply structured FlowQuery cuts"
        );
        // Menu maps onto the same state the query builder reads.
        for control in [
            "setListMethod('GET')",
            "setListStatus('2xx')",
            "setListKind('websocket')",
            "setOnlyErrors(true)",
        ] {
            assert!(
                SCRIPT.contains(control),
                "the live sift menu must offer {control}"
            );
        }
        // Active filter count is visible somewhere subtle (count strip + badge).
        assert!(
            SCRIPT.contains("structuredFilterCount()"),
            "active structured filters must be counted for the UI"
        );
        assert!(
            CSS.contains("#sift-live[data-count]::after")
                || SCRIPT.contains("' filter'"),
            "active filter count has to surface in the chrome"
        );
    }

    #[test]
    fn a_kept_host_goes_to_the_top_and_stays_there() {
        // Hosts arrive in the order the device asks for them, so the one being
        // watched has to be movable out of that order, and stay moved.
        assert!(
            SCRIPT.contains("localStorage.setItem('proxima.kept', JSON.stringify(kept));"),
            "keeping a host has to outlive the tab"
        );
        let read = SCRIPT
            .split_once("function readKept() {")
            .expect("the script still reads what was kept")
            .1;
        assert!(
            read.contains("try {") && read.contains("return [];"),
            "unreadable or invented storage has to fall back rather than throw"
        );
        // The star sits on the line that narrows the list, so it has to keep
        // its click, the same as the twisty does.
        let star = SCRIPT
            .split_once("function starFor(box, host) {")
            .expect("the script still builds a star")
            .1;
        assert!(
            star.contains("event.stopPropagation();"),
            "keeping a host must not also narrow the list to it"
        );
    }

    /// Composer URL box paints scheme, host, path and query under a transparent
    /// input so the caret stays real while tokens take colour. Mirror spans only.
    /// The detail head reuses the same tokenizer so a selected flow's URL is
    /// coloured the same way (not plain mono).
    #[test]
    fn composer_url_field_paints_tokens_under_a_transparent_input() {
        assert!(
            BODY.contains("id=\"c-url-mirror\"") && BODY.contains("class=\"url-field\""),
            "composer URL sits in a field with a coloured mirror under the input"
        );
        assert!(
            CSS.contains(".url-mirror .u-host")
                && CSS.contains(".url-mirror .u-key")
                && CSS.contains(".url-mirror .u-val")
                && CSS.contains("-webkit-text-fill-color: transparent"),
            "URL mirror token colours and transparent input text must stay wired"
        );
        assert!(
            CSS.contains(".durl .u-host")
                && CSS.contains(".durl .u-key")
                && CSS.contains(".durl .u-val"),
            "detail head URL must share the same token colours as the composer"
        );
        assert!(
            CSS.contains(".row .path .u-host")
                && CSS.contains(".row .path .u-key")
                && CSS.contains(".row .path .u-val"),
            "list path column must share the same token colours as the composer"
        );
        assert!(
            CSS.contains(".row .method.m-GET")
                && CSS.contains(".row .hostname")
                && CSS.contains("color: var(--accent)"),
            "list method and host must be coloured, not plain mono ink"
        );
        assert!(
            SCRIPT.contains("function tokenizeUrl(raw)")
                && SCRIPT.contains("function paintUrlMirror()")
                && SCRIPT.contains("function fillUrlTokens(into, text)")
                && SCRIPT.contains("paintUrlMirror();"),
            "typing and openSaved must repaint the URL mirror from tokenizeUrl"
        );
        assert!(
            SCRIPT.contains("fillUrlTokens(durl, str(request.url))"),
            "detail head must paint the request URL through the shared tokenizer"
        );
        assert!(
            SCRIPT.contains("fillUrlTokens(row.querySelector('.path'), str(flow.path))")
                || SCRIPT.contains("fillUrlTokens(row.querySelector(\".path\"), str(flow.path))"),
            "list paint must colour the path column through the shared tokenizer"
        );
        assert!(
            SCRIPT.contains("u-pair")
                && SCRIPT.contains("function wireUrlPair(pair, root)")
                && CSS.contains(".u-pair:hover")
                && CSS.contains(".u-pair.on"),
            "query key=value must group into hover/select pairs"
        );
        assert!(
            CSS.contains(".c-params tbody tr:hover")
                && CSS.contains(".c-params tbody tr:focus-within")
                && CSS.contains(".qparams .hrow:hover")
                && CSS.contains(".qparams .hrow.on"),
            "query-parameter tables must light key and value on hover or select"
        );
        // {{var}} and query keys/values are the reason this is more than host colour.
        assert!(
            SCRIPT.contains("'u-var'") && SCRIPT.contains("'u-key'") && SCRIPT.contains("'u-val'"),
            "tokenizer must colour query params and environment placeholders"
        );
    }

    /// Query params table under the URL bar, Postman-style: key/value rows
    /// rewrite the query string; the URL bar re-parses into rows. Spans/inputs
    /// only — no HTML from the URL. Captured requests get a read-only copy on
    /// the Request tab. Params and response folds collapse like tree shelves.
    #[test]
    fn composer_query_params_table_syncs_with_the_url_bar() {
        assert!(
            BODY.contains("id=\"c-params-body\"") && BODY.contains("Query parameters"),
            "composer must expose a query-parameter table under the URL"
        );
        assert!(
            CSS.contains(".c-params") && CSS.contains(".c-fold"),
            "param table and fold styling must be present"
        );
        assert!(
            BODY.contains("id=\"c-out-wrap\"")
                && BODY.contains("id=\"c-headers-wrap\"")
                && BODY.contains("id=\"c-body-wrap\"")
                && SCRIPT.contains("wireFold('c-params-wrap'")
                && SCRIPT.contains("wireFold('c-headers-wrap'")
                && SCRIPT.contains("wireFold('c-body-wrap'")
                && SCRIPT.contains("wireFold('c-out-wrap'")
                && SCRIPT.contains("outFold.open()"),
            "params, headers, body and response must fold; send re-opens the response"
        );
        assert!(
            SCRIPT.contains("function syncParamsFromUrl()")
                && SCRIPT.contains("function writeUrlFromParams()")
                && SCRIPT.contains("function parseQueryString(query)")
                && SCRIPT.contains("function buildQueryString(rows)"),
            "URL and table must round-trip through parse/build helpers"
        );
        // fillComposer (used by openSaved) loads a URL that may already carry a
        // query; the table has to fill without waiting for a keystroke.
        let fill = SCRIPT
            .split_once("function fillComposer(name, spec, opts) {")
            .expect("the script still fills the composer from a saved or recent request")
            .1;
        assert!(
            fill.contains("syncParamsFromUrl();"),
            "opening a saved request must fill the params table from its URL"
        );
        // {{var}} must survive encode for environment send.
        assert!(
            SCRIPT.contains(".replace(/%7B/gi, '{')"),
            "encodeParam must keep {{var}} braces usable after a table edit"
        );
        // Captured traffic: Request tab lists the same breakdown without editing.
        assert!(
            SCRIPT.contains("function queryParamsBlock(url)")
                && SCRIPT.contains("box.appendChild(queryParamsBlock(request.url));"),
            "Request tab must show a read-only query parameter breakdown"
        );
    }

    #[test]
    fn saved_requests_go_out_and_come_back_the_way_the_composer_sends_them() {
        // A saved request is a SendSpec under a name. Saving one shape and
        // loading another would leave the composer filling fields nothing reads.
        for field in ["method:", "url: url,", "headers:", "bodyBase64:"] {
            assert!(
                SCRIPT.contains(field),
                "a saved request carries what the send endpoint acts on: {field}"
            );
        }
        assert!(
            SCRIPT.contains("id: editingSavedId || '',")
                || SCRIPT.contains("id: editingSavedId || \"\","),
            "save must reuse the open request's id when set, else empty for the store to mint"
        );
        assert!(
            SCRIPT.contains("var editingSavedId"),
            "composer must remember which saved request is open so Save can overwrite"
        );
        assert!(
            SCRIPT.contains("function openSaved(book, saved) {")
                && SCRIPT.contains("fillComposer(str(saved.name), saved.spec || {}, {"),
            "openSaved must load the saved request through fillComposer"
        );
        let fill = SCRIPT
            .split_once("function fillComposer(name, spec, opts) {")
            .expect("the script still fills the composer")
            .1;
        for filled in ["c-method", "c-url", "c-headers", "c-body"] {
            assert!(
                fill.contains(filled),
                "opening a saved request has to fill {filled}"
            );
        }
        assert!(
            fill.contains("editingSavedId") || SCRIPT.contains("savedId: str(saved.id)"),
            "opening a saved request must record its id for the next Save"
        );
        assert!(
            fill.contains("composing(true);"),
            "a saved request is only of use in the composer, so open it there"
        );
        // An answer left over from the request that was open a moment ago reads
        // as this one's: same shape, same pane, only the URL above it changed.
        assert!(
            fill.contains("strip(outEl);"),
            "opening another request must take the last one's answer down with it"
        );
        // Save must replace by id when editing, not always concat a new entry.
        let save = SCRIPT
            .split_once("async function saveComposed() {")
            .expect("the script still saves a composed request")
            .1;
        assert!(
            save.contains("requests[r] = saved") || save.contains("requests[r]=saved"),
            "Save of an open request must overwrite that entry in the collection"
        );
        assert!(
            save.contains("if (!replaced)") || save.contains("if(!replaced)"),
            "only a brand-new save should append; re-saves replace"
        );
        // Put body must not round-trip client history (server owns revisions).
        assert!(
            SCRIPT.contains("function bookForPut(book)"),
            "collections PUT must strip history before send"
        );
        let put = SCRIPT
            .split_once("function bookForPut(book) {")
            .expect("bookForPut still defined")
            .1;
        assert!(
            !put.split("function ").next().unwrap_or("").contains("history"),
            "bookForPut must not include history on the wire"
        );
        // History button next to Save + fold + Recent shelf surface change/send history.
        assert!(
            BODY.contains("id=\"c-history\"")
                && BODY.contains(">History</button>")
                && SCRIPT.contains("function showHistory()")
                && SCRIPT.contains("historyBtn.addEventListener('click', showHistory)"),
            "composer must put a History button next to Save that opens the versions fold"
        );
        assert!(
            BODY.contains("id=\"c-versions\"")
                && BODY.contains("c-fold-name\">History</span>")
                && SCRIPT.contains("function paintVersions()"),
            "composer must expose a History fold for saved-request revisions"
        );
        assert!(
            SCRIPT.contains("histBtn.textContent")
                || SCRIPT.contains("History (' + n + ')'"),
            "History button label must reflect the version count when present"
        );
        assert!(
            BODY.contains("id=\"recent\"")
                && BODY.contains("id=\"recent-list\"")
                && SCRIPT.contains("function loadRecent()")
                && SCRIPT.contains("function openRecent(entry)"),
            "left column must list recent sends and open them in the composer"
        );
        assert!(
            SCRIPT.contains("'/api/send-history'")
                || SCRIPT.contains("\"/api/send-history\""),
            "Recent shelf talks to /api/send-history"
        );
    }

    /// Live traffic becomes a saved request by drag, by copy/paste, or by the
    /// copy menu. The page must keep those three paths, not only "compose then save".
    #[test]
    fn live_requests_can_be_saved_by_drag_and_by_copy() {
        for needle in [
            "var SAVED_CLIP_PREFIX = 'proxima-saved-request:';",
            "function flowToSaved(id)",
            "function saveFlowToCollection(flowId, book)",
            "function acceptLiveDrop(node, bookOf)",
            "function wireLiveDragSource(el, getFlowId)",
            "function copyFlowAsSaved(id)",
            "item('Copy as saved request'",
            "Save to collection",
            "live-drop",
            "row-dragging",
        ] {
            assert!(
                SCRIPT.contains(needle) || CSS.contains(needle),
                "live → saved must stay wired: missing {needle}"
            );
        }
        // No HTML5 draggable: the system grab hand cannot be styled away.
        assert!(
            !SCRIPT.contains("row.draggable = true")
                && !SCRIPT.contains(".draggable = true")
                && !SCRIPT.contains("dragstart"),
            "live drag must use pointer events, not HTML5 draggable"
        );
        assert!(
            CSS.contains("drop-over"),
            "drop targets need a visible drag-over state"
        );
        assert!(
            !CSS.contains("cursor: grab")
                && !CSS.contains("cursor: pointer")
                && !CSS.contains("cursor: col-resize"),
            "no hand/grab/col-resize cursors"
        );
    }

    /// The composer's own payload is checked elsewhere against `SendSpec`. This
    /// is the other half: what a saved request looks like on disk.
    #[test]
    fn a_saved_request_is_a_collection_the_store_accepts() {
        let payload = serde_json::json!({
            "id": "",
            "name": "Saved requests",
            "requests": [{
                "id": "",
                "name": "orders",
                "spec": {
                    "method": "POST",
                    "url": "https://api.example.com/v1/orders",
                    "headers": [["content-type", "application/json"]],
                    "bodyBase64": "aGk=",
                },
            }],
        });
        let book: crate::replay::Collection =
            serde_json::from_value(payload).expect("the page sends a collection");
        assert_eq!(book.requests.len(), 1);
        let spec: crate::replay::SendSpec =
            serde_json::from_value(book.requests[0].spec.clone())
                .expect("a saved spec is a SendSpec");
        assert_eq!(spec.method.as_deref(), Some("POST"));
    }

    #[test]
    fn the_tree_is_assembled_from_nodes_like_the_rest_of_the_page() {
        // Host names and path segments are captured strings, so they reach the
        // document the same way every other captured string does.
        assert!(
            SCRIPT.contains("line.appendChild(el('span', 'gname', label));"),
            "a captured name must be written as text, not built into markup"
        );
        assert!(
            SCRIPT.contains("scopeNameEl.textContent = scope;"),
            "the branch being shown is captured text too"
        );
        assert!(
            BODY.contains("<div id=\"hosts\" role=\"tree\""),
            "the tree needs a pane of its own beside the list"
        );
        assert!(
            BODY.contains("<button id=\"view\""),
            "the tree pane needs something to fold it away"
        );
    }

    #[test]
    fn the_tree_column_can_be_resized_and_remembers() {
        // A fixed 15rem column is fine until a long host name needs more room,
        // or the list needs it back. The edge has to move, and the choice has
        // to outlive the tab the same way theme and grouping do.
        assert!(
            BODY.contains("id=\"tree-grip\""),
            "the tree needs an edge to drag"
        );
        assert!(
            CSS.contains("--tree-w"),
            "the tree width has to be a thing the page can change"
        );
        assert!(
            !CSS.contains("cursor: col-resize")
                && !CSS.contains("cursor: grab")
                && !CSS.contains("cursor: pointer"),
            "no hand, grab, or col-resize cursors in the inspector"
        );
        assert!(
            SCRIPT.contains("localStorage.setItem('proxima.tree-w'"),
            "how wide the tree is has to outlive the tab"
        );
        let read = SCRIPT
            .split_once("function readTreeWidth() {")
            .expect("the script still reads back the tree width")
            .1;
        assert!(
            read.contains("catch (error)") && read.contains("return TREE_W_DEFAULT"),
            "unreadable or invented storage has to fall back rather than throw"
        );
        assert!(
            SCRIPT.contains("TREE_W_MIN") && SCRIPT.contains("TREE_W_MAX"),
            "a dragged edge has to stop before the list disappears"
        );
    }

    #[test]
    fn the_event_socket_reconnects_on_its_own_with_a_bounded_backoff() {
        for line in [
            "socket.addEventListener('close', retry);",
            "setTimeout(connect, backoff);",
            "backoff = Math.min(backoff * 2, RETRY_MAX);",
            "backoff = RETRY_MIN;",
        ] {
            assert!(
                SCRIPT.contains(line),
                "the socket has to come back after the server restarts: {line}"
            );
        }
        // A throw out of the constructor is the one failure that never reaches a
        // close event, so it has to schedule its own retry.
        assert!(
            SCRIPT.contains("retry();\n      return;"),
            "a WebSocket that will not even construct must still schedule a retry"
        );
    }

    #[test]
    fn a_detail_pane_replaced_by_a_message_stops_owning_the_frame_list() {
        // Selecting a flow whose detail fetch then fails used to leave frameList
        // pointing at a node no longer in the document, and every later frame
        // for that id was appended to it where nobody could see it.
        let hint = SCRIPT
            .split_once("function hint(text) {")
            .expect("the script still has a hint function")
            .1;
        let body = hint.split_once('}').expect("hint has a body").0;
        for reset in ["frameList = null", "frameOwner = null"] {
            assert!(
                body.contains(reset),
                "tearing the detail pane down must drop the frame list: {reset}"
            );
        }
    }

    /// A flow opened while it was still in flight used to keep showing "in
    /// flight" and an empty response body until the row was clicked away from
    /// and back, because the pane was only ever built by `select`.
    #[test]
    fn a_flow_that_finishes_while_it_is_open_redraws_its_own_pane() {
        for line in [
            "if (event.flow && event.flow.id === selectedId &&",
            "signature(event.flow) !== rendered) {",
            "select(selectedId, false);",
            "rendered = signature(summaries.get(id));",
            "summaries.set(flow.id, flow);",
        ] {
            assert!(
                SCRIPT.contains(line),
                "an update for the open flow has to reach the pane below: {line}"
            );
        }

        // Every field the pane can show that a later event can change has to be
        // in the signature, or the redraw never fires for it.
        let body = SCRIPT
            .split_once("function signature(flow) {")
            .expect("the script still has a signature function")
            .1
            .split_once("\n  }")
            .expect("signature has a body")
            .0;
        for field in ["state", "status", "responseSize", "duration", "error"] {
            assert!(
                body.contains(&format!("flow.{field}")),
                "{field} changes after a row appears, so it belongs in the signature"
            );
        }
    }

    /// A resync exists because the list has holes in it. Dropping the pane
    /// someone was reading is collateral damage, not part of the fix.
    #[test]
    fn resynchronising_the_list_reopens_whatever_was_selected() {
        for line in [
            "var reopen = selectedId;",
            "if (reopen && rows.has(reopen)) { select(reopen, false); }",
        ] {
            assert!(
                SCRIPT.contains(line),
                "a reload must put the open flow back: {line}"
            );
        }
    }

    /// Bookkeeping that `wipe` forgets outlives the rows it describes, and the
    /// signature check would then compare against a flow that is gone.
    #[test]
    fn clearing_the_list_forgets_the_summaries_it_kept() {
        let body = SCRIPT
            .split_once("function wipe() {")
            .expect("the script still has a wipe function")
            .1
            .split_once("\n  }")
            .expect("wipe has a body")
            .0;
        for reset in ["summaries.clear()", "rendered = ''"] {
            assert!(
                body.contains(reset),
                "wiping the list must drop the bookkeeping behind the pane: {reset}"
            );
        }
        assert!(
            SCRIPT.contains("summaries.delete(last.flowId);"),
            "a trimmed row must not leave its summary behind"
        );
    }

    #[test]
    fn the_policy_names_the_nonce_and_forbids_everything_else() {
        let policy = policy("abc123");
        assert!(policy.contains("script-src 'nonce-abc123'"));
        assert!(policy.contains("style-src 'nonce-abc123'"));
        assert!(policy.starts_with("default-src 'none'"));
        assert!(
            policy.contains("connect-src 'self' ws: wss:"),
            "the event socket has to survive the policy"
        );
        assert!(!policy.contains("unsafe-inline"));
        assert!(page("abc123").contains("nonce=\"abc123\""));
    }

    #[test]
    fn a_nonce_is_safe_in_both_a_header_and_an_attribute() {
        for _ in 0..64 {
            let value = nonce();
            assert_eq!(value.len(), 22, "16 bytes of base64 without padding");
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "a nonce must never need escaping, got {value}"
            );
        }
    }

    #[test]
    fn only_the_root_path_answers_with_the_inspector() {
        let root = serve("/");
        assert_eq!(root.status(), StatusCode::OK);
        assert_eq!(
            root.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert!(root.headers().contains_key(header::CONTENT_SECURITY_POLICY));

        for path in ["/api/nope", "/favicon.ico", "/flows/abc"] {
            assert_eq!(
                serve(path).status(),
                StatusCode::NOT_FOUND,
                "{path} is not the inspector"
            );
        }
    }

    #[test]
    fn the_list_reads_only_fields_a_flow_summary_sends() {
        let summary = FlowSummary {
            id: "abc".to_string(),
            kind: FlowKind::Http,
            state: FlowState::Complete,
            intercepted: true,
            method: "GET".to_string(),
            scheme: Scheme::Https,
            authority: "example.com".to_string(),
            path: "/".to_string(),
            http_version: HttpVersion::Http11,
            status: Some(200),
            content_type: None,
            request_size: 0,
            response_size: 12,
            start: 1,
            duration: Some(3),
            error: None,
            likely_pinning: true,
            client: "192.168.1.4".to_string(),
            transport: None,
            connection_id: None,
            stream_id: None,
            mocked: false,
        };
        let json = serde_json::to_value(&summary).expect("a summary serialises");
        let object = json.as_object().expect("a summary is an object");

        for field in [
            "id",
            "kind",
            "state",
            "method",
            "authority",
            "path",
            "status",
            "responseSize",
            "duration",
            "error",
            "likelyPinning",
            "client",
        ] {
            assert!(
                object.contains_key(field),
                "the flow list reads {field}, which FlowSummary no longer sends"
            );
        }
        // mocked is omit-when-false; the list still reads the key when present.
        assert!(
            !object.contains_key("mocked"),
            "ordinary rows omit mocked so list JSON stays quiet"
        );
        let mut mocked = summary.clone();
        mocked.mocked = true;
        let mocked_json = serde_json::to_value(&mocked).expect("mocked summary serialises");
        assert_eq!(mocked_json["mocked"], true);
    }

    #[test]
    fn the_composer_reads_only_fields_a_send_result_sends() {
        let result = crate::replay::SendResult {
            flow_id: "abc".to_string(),
            status: 200,
            status_text: "OK".to_string(),
            http_version: HttpVersion::Http11,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body_base64: "aGk=".to_string(),
            timings: crate::types::FlowTimings {
                start: 1,
                end: Some(4),
                ..Default::default()
            },
        };
        let json = serde_json::to_value(&result).expect("a send result serialises");
        let object = json.as_object().expect("a send result is an object");

        for field in [
            "status",
            "statusText",
            "httpVersion",
            "headers",
            "bodyBase64",
            "timings",
        ] {
            assert!(
                object.contains_key(field),
                "the composer reads {field}, which SendResult no longer sends"
            );
        }
    }

    /// The Frames tab is where inject lives. A websocket with no frames yet
    /// still has to offer it, or the first thing you can do on a live socket is
    /// wait for the peer.
    #[test]
    fn a_websocket_flow_offers_frames_even_before_any_arrive() {
        assert!(
            SCRIPT.contains("flow.kind === 'websocket' ? [] : null"),
            "an empty websocket must still open the Frames tab for inject"
        );
        assert!(
            SCRIPT.contains("function injectForm(id, flow)"),
            "the frames pane must build an inject form"
        );
        assert!(
            SCRIPT.contains("function injectFrame(id, direction, opcode, text, closeCode, closeReason, button, status)"),
            "the inject form must post through injectFrame"
        );
        assert!(
            CSS.contains(".frame.injected .dir::after"),
            "injected frames must read as injected in the list"
        );
        assert!(
            SCRIPT.contains("if (message.injected) { line.className += ' injected'; }"),
            "frameLine must honour the injected flag the capture records"
        );
        assert!(
            CSS.contains(".frame.compressed .dir::after"),
            "deflate frames must read as compressed in the list"
        );
        assert!(
            SCRIPT.contains("if (message.compressed) { line.className += ' compressed'; }"),
            "frameLine must honour the compressed flag the capture records"
        );
        assert!(
            SCRIPT.contains("if (message.compressed) { meta += ' wire'; }"),
            "compressed frames must label size as wire length (display may be inflated)"
        );
        // P11: inject form states the same fail-closed contract as README/API.
        assert!(
            SCRIPT.contains("skips rewrite rules and breakpoints"),
            "inject form must say injects skip rewrite and breakpoints"
        );
        assert!(
            SCRIPT.contains("marked injected"),
            "inject form must say injected frames are marked"
        );
        assert!(
            SCRIPT.contains("no continuations or drop markers"),
            "inject form must name opcodes that cannot be injected"
        );
        assert!(
            BODY.contains("Injected frames skip breakpoints"),
            "breakpoints panel must say injects skip holds (parity with rewrite)"
        );
        assert!(
            BODY.contains("Injected frames skip these rules"),
            "rewrite panel must keep stating injects skip rewrite"
        );
        assert!(
            SCRIPT.contains("Drop markers and continuations are skipped")
                && SCRIPT.contains("uncompressed"),
            "replay form must keep deflate / drop-marker honesty"
        );
    }

    /// Frames tab filter bar: direction, opcode, text search over a retained
    /// window; live ws:message and filter changes share matchesFrame.
    #[test]
    fn frames_tab_filters_by_direction_opcode_and_text() {
        assert!(
            SCRIPT.contains("var frameFilters = { direction: '', opcodes: null, query: '' };"),
            "frame filters must live as a small retained state object"
        );
        assert!(
            SCRIPT.contains("function matchesFrame(message)"),
            "one matcher must decide visibility for both live rows and re-renders"
        );
        assert!(
            SCRIPT.contains("function frameFilterBar()"),
            "the frames pane must offer a filter bar"
        );
        assert!(
            SCRIPT.contains("function renderFrames()"),
            "changing filters must re-paint from the retained window"
        );
        assert!(
            SCRIPT.contains("function retainFrame(message)"),
            "live frames must trim the retained window, not only the DOM"
        );
        assert!(
            SCRIPT.contains("Frame direction filter") && SCRIPT.contains("Frame opcode filter"),
            "direction and opcode filters must be labelled controls"
        );
        assert!(
            SCRIPT.contains("Search frame text"),
            "a text search box must sit on the filter bar"
        );
        // Substring on raw text (lowercased), never a RegExp built from the needle.
        assert!(
            SCRIPT.contains("raw.toLowerCase().indexOf(needle) < 0"),
            "frame text search must stay a substring match on the raw payload"
        );
        assert!(
            SCRIPT.contains("retainFrame(event.message || {});")
                && SCRIPT.contains("renderFrames();"),
            "live ws:message must retain then re-render under the active filters"
        );
        assert!(
            CSS.contains(".inject.filters"),
            "frame filters must share the inject control styling"
        );
    }

    /// Pretty-print is display-only: opcode 1 JSON goes through the tokenizer
    /// via /api/json/view; search still runs on the raw captured text.
    #[test]
    fn text_frames_pretty_print_json_without_changing_search() {
        assert!(
            SCRIPT.contains("function paintFramePayload(textEl, message)"),
            "frame display must paint through paintFramePayload"
        );
        assert!(
            SCRIPT.contains("fetchJsonView(raw)")
                && SCRIPT.contains("paintJson(textEl, view)"),
            "JSON text frames must use /api/json/view then paintJson"
        );
        assert!(
            SCRIPT.contains("message.opcode === 1 && wantsJsonView"),
            "pretty/colour is for text frames that look like JSON"
        );
        assert!(
            SCRIPT.contains("paintFramePayload(textEl, message)"),
            "frameLine must paint via paintFramePayload, not raw text alone"
        );
        // matchesFrame still reads message.text, not displayText(...).
        let matcher = SCRIPT
            .split_once("function matchesFrame(message) {")
            .expect("matchesFrame still exists")
            .1;
        let body = matcher
            .split_once("function displayText")
            .expect("displayText follows matchesFrame")
            .0;
        assert!(
            body.contains("message.text") && !body.contains("displayText"),
            "search must use raw message.text, not the pretty-printed display"
        );
        assert!(
            SCRIPT.contains("'/api/json/view'"),
            "inspector must call the tokenizer-backed JSON view endpoint"
        );
    }

    /// Opcode 0xf is the capture retention marker, not a peer frame and not
    /// injectable. The list has to say so.
    #[test]
    fn drop_markers_read_as_retention_gaps() {
        assert!(
            SCRIPT.contains("if (code === 15) { return 'gap'; }"),
            "opcode 15 must label as a gap, not a real opcode number alone"
        );
        assert!(
            SCRIPT.contains("'retention gap'"),
            "the direction column must name the gap for what it is"
        );
        assert!(
            SCRIPT.contains("var gap = message.opcode === 15;"),
            "frameLine must special-case the retention marker"
        );
        assert!(
            CSS.contains(".frame.gap"),
            "gaps need a quieter style so they do not look injectable"
        );
        // Filter bar offers real opcodes only; gap is not a peer frame to pick.
        let filter_bar = SCRIPT
            .split_once("function frameFilterBar() {")
            .expect("frameFilterBar still exists")
            .1;
        let filter_body = filter_bar
            .split_once("function addOption(select, value, label) {")
            .expect("addOption follows frameFilterBar")
            .0;
        for real in ["'1', 'text'", "'2', 'binary'", "'8', 'close'", "'9', 'ping'", "'10', 'pong'"]
        {
            assert!(
                filter_body.contains(real),
                "frame filter opcode list must still offer {real}"
            );
        }
        assert!(
            !filter_body.contains("'15'") && !filter_body.contains("gap"),
            "frame filter must not treat retention gaps as a selectable opcode"
        );
    }

    /// Closed sockets keep an honest inject hint; the form still renders so the
    /// tab layout does not jump when a live flow finishes.
    #[test]
    fn closed_websocket_flows_keep_an_honest_inject_hint() {
        assert!(
            SCRIPT.contains(
                "This socket is closed. Inject only works on a live upgraded flow."
            ),
            "a finished websocket must say inject needs a live upgraded flow"
        );
        let form = SCRIPT
            .split_once("function injectForm(id, flow) {")
            .expect("injectForm still exists")
            .1;
        let body = form
            .split_once("async function injectFrame(")
            .expect("injectFrame follows injectForm")
            .0;
        assert!(
            body.contains("flow.state === 'complete'")
                && body.contains("flow.state === 'error'")
                && body.contains("flow.state === 'aborted'"),
            "closed inject hint must cover complete, error, and aborted states"
        );
        assert!(
            body.contains("form.appendChild(el('p', 'hint', closed"),
            "the closed hint must be the inject form's status copy, not a second panel"
        );
    }

    /// Successful inject posts only; the event socket paints the recorded frame.
    /// Drawing the POST response here would double every injected row.
    #[test]
    fn inject_success_does_not_double_draw_the_frame() {
        let inject = SCRIPT
            .split_once("async function injectFrame(id, direction, opcode, text, closeCode, closeReason, button, status) {")
            .expect("injectFrame still exists")
            .1;
        // frameLine may sit after the replay helpers; still the next list painter.
        let body = inject
            .split_once("function frameLine(message, absoluteIndex) {")
            .expect("frameLine follows inject helpers")
            .0;
        assert!(
            body.contains("status.textContent = 'Injected.';"),
            "a successful inject must only mark status, not invent a list row"
        );
        for forbidden in [
            "retainFrame(",
            "renderFrames(",
            "frameLine(",
            "frameList.appendChild",
            "frameMessages.push",
        ] {
            assert!(
                !body.contains(forbidden),
                "injectFrame must not {forbidden}: the event socket owns the list"
            );
        }
        // Live path is still the one that retains then re-renders.
        assert!(
            SCRIPT.contains("if (event.type === 'ws:message' && event.id === frameOwner && frameList)")
                && SCRIPT.contains("retainFrame(event.message || {});")
                && SCRIPT.contains("renderFrames();"),
            "ws:message must remain the sole path that adds inject rows to the list"
        );
    }

    /// The Frames tab keeps a retained window, then paints only matches. Trimming
    /// the DOM alone would drop filtered-out frames that should reappear later.
    #[test]
    fn frames_tab_retains_a_window_then_paints_matches() {
        assert!(
            SCRIPT.contains("var MAX_FRAMES = 200;"),
            "the frames tab must cap how many messages it keeps"
        );
        assert!(
            SCRIPT.contains("all.slice(-MAX_FRAMES)"),
            "initial load must keep only the trailing window"
        );
        assert!(
            SCRIPT.contains("while (frameMessages.length > MAX_FRAMES)")
                && SCRIPT.contains("frameMessages.shift();"),
            "live retain must drop from the front of the retained window"
        );
        let render = SCRIPT
            .split_once("function renderFrames() {")
            .expect("renderFrames still exists")
            .1;
        let render_body = render
            .split_once("function retainFrame(message) {")
            .expect("retainFrame follows renderFrames")
            .0;
        assert!(
            render_body.contains("if (matchesFrame(frameMessages[i]))")
                && render_body.contains(
                    "frameList.appendChild(frameLine(frameMessages[i], frameIndexBase + i));"
                ),
            "renderFrames must paint only retained rows that match the active filters"
        );
        assert!(
            SCRIPT.contains("block.appendChild(injectForm(id, flow));")
                && SCRIPT.contains("block.appendChild(replayForm(id, flow));")
                && SCRIPT.contains("block.appendChild(frameFilterBar());"),
            "Frames pane must stack inject, then replay, then filters, above the list"
        );
        // Filter changes re-paint immediately; no submit button on the bar.
        let filter = SCRIPT
            .split_once("function applyFilters() {")
            .expect("applyFilters still exists")
            .1;
        let filter_tail = filter.split_once("return bar;").expect("filter bar returns").0;
        assert!(
            filter_tail.contains("dir.addEventListener('change', applyFilters);")
                && filter_tail.contains("op.addEventListener('change', applyFilters);")
                && filter_tail.contains("query.addEventListener('input', applyFilters);"),
            "direction, opcode, and search must re-render as soon as they change"
        );
    }

    /// matchesFrame covers direction, opcode set, and raw-text substring; empty
    /// filters mean "any". The matcher is the single source of list visibility.
    #[test]
    fn matches_frame_checks_direction_opcode_and_raw_text() {
        let matcher = SCRIPT
            .split_once("function matchesFrame(message) {")
            .expect("matchesFrame still exists")
            .1;
        let body = matcher
            .split_once("function displayText(message) {")
            .expect("displayText follows matchesFrame")
            .0;
        assert!(
            body.contains("frameFilters.direction && message.direction !== frameFilters.direction"),
            "direction filter must compare against message.direction"
        );
        assert!(
            body.contains("frameFilters.opcodes && !frameFilters.opcodes[message.opcode]"),
            "opcode filter must look up message.opcode in the active set"
        );
        assert!(
            body.contains("typeof message.text === 'string' ? message.text : ''")
                && body.contains("raw.toLowerCase().indexOf(needle) < 0"),
            "text search must substring-match lowercased raw message.text"
        );
        assert!(
            body.contains("if (!message) { return false; }") && body.contains("return true;"),
            "a null message is hidden; an unfiltered message stays visible"
        );
    }

    /// paintFramePayload colours opcode-1 JSON only; binary/close/etc. stay raw
    /// (or absent). Non-JSON text frames must fall back without throwing away text.
    #[test]
    fn display_text_pretty_prints_json_text_frames_only() {
        let display = SCRIPT
            .split_once("function paintFramePayload(textEl, message) {")
            .expect("paintFramePayload still exists")
            .1;
        let body = display
            .split_once("function renderFrames() {")
            .expect("renderFrames follows paintFramePayload")
            .0;
        assert!(
            body.contains("message.opcode === 1 && wantsJsonView"),
            "pretty/colour is gated on text frames that look like JSON"
        );
        assert!(
            body.contains("paintJson(textEl, view)") && body.contains("fetchJsonView(raw)"),
            "valid JSON frames must go through the tokenizer view endpoint"
        );
        assert!(
            body.contains("textEl.textContent = raw"),
            "non-JSON or pending paint must keep the raw payload as text"
        );
        assert!(
            body.contains("if (raw === null) { return; }"),
            "a frame without text must not invent a display string"
        );
        assert!(
            SCRIPT.contains("'/api/json/view'") && CSS.contains(".json .j-property"),
            "tokenizer paint classes and endpoint must stay wired"
        );
    }

    /// WS rewrite rules are first-class UI: GET|PUT /api/ws-rewrite, form fields
    /// match the config rule shape, and notes already show under flow Info.
    #[test]
    fn the_inspector_surfaces_ws_rewrite_rules() {
        assert!(
            BODY.contains("id=\"rewrite\""),
            "the header must offer a WS rewrite control"
        );
        assert!(
            BODY.contains("id=\"rewriter\""),
            "rules must have a panel of their own"
        );
        assert!(
            SCRIPT.contains("async function saveRewriteRules()"),
            "the rules form must PUT /api/ws-rewrite"
        );
        assert!(
            SCRIPT.contains("getJson('/api/ws-rewrite')"),
            "the panel must load current rules"
        );
        assert!(
            SCRIPT.contains("fetch('/api/ws-rewrite'"),
            "save and clear must hit the rewrite endpoint"
        );
        for field in [
            "hosts:",
            "pathPrefix:",
            "directions:",
            "opcodes:",
            "textRegex:",
            "drop:",
            "replaceText:",
            "replaceBase64:",
        ] {
            assert!(
                SCRIPT.contains(field),
                "WS rewrite UI must still send {field}"
            );
        }
        assert!(
            BODY.contains("per frame") || BODY.contains("per-frame") || SCRIPT.contains("per frame"),
            "the UI must state per-frame matching limits"
        );
    }

    /// HTTP rewrite / map-local mock: GET|PUT /api/rewrite, one-rule form
    /// (hosts, methods, path, mock, path/query/body rewrites) and a rules list.
    #[test]
    fn the_inspector_surfaces_http_rewrite_mock_rules() {
        assert!(
            BODY.contains("id=\"httprewrite\""),
            "the header must offer an HTTP rewrite control"
        );
        assert!(
            BODY.contains("id=\"httprewriter\""),
            "HTTP rewrite rules must have a panel of their own"
        );
        assert!(
            BODY.contains("id=\"hr-hosts\"")
                && BODY.contains("id=\"hr-methods\"")
                && BODY.contains("id=\"hr-path\"")
                && BODY.contains("id=\"hr-mock-status\"")
                && BODY.contains("id=\"hr-headers\"")
                && BODY.contains("id=\"hr-body\"")
                && BODY.contains("id=\"hr-body-file\"")
                && BODY.contains("id=\"hr-path-repl\"")
                && BODY.contains("id=\"hr-query-repl\"")
                && BODY.contains("id=\"hr-req-body-find\"")
                && BODY.contains("id=\"hr-req-body-replace\"")
                && BODY.contains("id=\"hr-req-body-max\"")
                && BODY.contains("id=\"hr-res-body-find\"")
                && BODY.contains("id=\"hr-res-body-replace\"")
                && BODY.contains("id=\"hr-res-body-max\"")
                && BODY.contains("id=\"hr-save\"")
                && BODY.contains("id=\"hr-clear\"")
                && BODY.contains("id=\"hr-list\""),
            "the form must expose hosts, methods, path, mock fields, path/query/body rewrites, save, clear and list"
        );
        assert!(
            SCRIPT.contains("async function saveHttpRewriteRules()"),
            "the rules form must PUT /api/rewrite"
        );
        assert!(
            SCRIPT.contains("getJson('/api/rewrite')"),
            "the panel must load current rules"
        );
        assert!(
            SCRIPT.contains("fetch('/api/rewrite'"),
            "save and clear must hit the HTTP rewrite endpoint"
        );
        assert!(
            SCRIPT.contains("function httpRewriting(on)"),
            "HTTP rewrite must own a seat mode like compose/break/ws-rewrite"
        );
        assert!(
            CSS.contains("main.httprewriting") && CSS.contains("#httprewriter"),
            "HTTP rewrite panel must share the side-panel seat styles"
        );
        for field in [
            "hosts:",
            "methods:",
            "pathPrefix:",
            "requestHeaders:",
            "responseHeaders:",
            "pathReplacements:",
            "queryReplacements:",
            "requestBody:",
            "responseBody:",
            "mock:",
            "status:",
            "headers:",
            "body:",
            "bodyFile:",
            "maxBytes:",
            "replacements:",
        ] {
            assert!(
                SCRIPT.contains(field),
                "HTTP rewrite UI must still send {field}"
            );
        }
        assert!(
            SCRIPT.contains("path×"),
            "list paint must surface path rewrites when present"
        );
        assert!(
            SCRIPT.contains("req-body") && SCRIPT.contains("res-body"),
            "list paint must surface request and response body rewrites"
        );
        assert!(
            SCRIPT.contains("ruleHasPathBodyRewrites"),
            "armed state and list badges must notice path/query/body rewrites"
        );
        assert!(
            BODY.contains("map local") || BODY.contains("without dialling"),
            "the UI must state that mock answers without dialling the origin"
        );
    }

    /// Breakpoints and held pauses are first-class UI: rules via PUT, resolve
    /// via POST, and both pause events on the stream strip under the header.
    /// Kind is selectable (ws / http); HTTP pauses edit method, url, headers,
    /// body and optional status.
    #[test]
    fn the_inspector_surfaces_ws_breakpoints_and_held_pauses() {
        assert!(
            BODY.contains("id=\"break\""),
            "the header must offer a Breakpoints control"
        );
        assert!(
            BODY.contains("id=\"breaker\""),
            "rules must have a panel of their own"
        );
        assert!(
            BODY.contains("id=\"pauses\""),
            "held frames must land in a strip the page can fill"
        );
        assert!(
            BODY.contains("id=\"b-kind\""),
            "rules form must offer kind ws/http"
        );
        assert!(
            BODY.contains("id=\"b-http-half\""),
            "rules form must offer HTTP half"
        );
        assert!(
            BODY.contains("id=\"b-methods\""),
            "rules form must offer HTTP methods"
        );
        assert!(
            BODY.contains("WebSocket frames or HTTP messages"),
            "breakpoint hint must cover both kinds"
        );
        assert!(
            SCRIPT.contains("event.type === 'pause:hit'"),
            "the event socket must accept pause:hit"
        );
        assert!(
            SCRIPT.contains("event.type === 'pause:resolved'"),
            "the event socket must accept pause:resolved"
        );
        assert!(
            SCRIPT.contains("function notePause(pause)"),
            "a hit must enter the local pause map"
        );
        assert!(
            SCRIPT.contains("function resolvePause(pauseId, action, body, button, status)"),
            "release and drop must post through one helper"
        );
        assert!(
            SCRIPT.contains("function pauseCardHttp(pause)"),
            "HTTP pauses need their own card builder"
        );
        assert!(
            SCRIPT.contains("function pauseCardWs(pause)"),
            "WS pauses need their own card builder"
        );
        assert!(
            SCRIPT.contains("async function saveRules()"),
            "the rules form must PUT /api/breakpoints"
        );
        assert!(
            SCRIPT.contains("JSON.stringify({ rules: [rule] })"),
            "saving must send a rules envelope the endpoint deserialises"
        );
        assert!(
            SCRIPT.contains("JSON.stringify({ rules: [] })"),
            "clearing must PUT an empty rules list"
        );
        assert!(
            CSS.contains(".pauses"),
            "held pauses need styles so they stay visible under the header"
        );
        // Field names the form and release body put on the wire.
        for field in [
            "enabled:",
            "kind: kind",
            "hosts:",
            "pathPrefix:",
            "directions:",
            "opcodes:",
            "timeoutMs:",
            "httpHalf:",
            "methods:",
            "dataBase64",
            "opcode:",
            "method:",
            "url:",
            "headers:",
            "body.status",
        ] {
            assert!(
                SCRIPT.contains(field),
                "breakpoint UI must still send {field}"
            );
        }
        assert!(
            SCRIPT.contains("? 'http' : 'ws'"),
            "saveRules must still emit kind ws or http"
        );
        assert!(
            SCRIPT.contains("Held HTTP request") || SCRIPT.contains("Held HTTP response"),
            "HTTP pause cards must label the half"
        );
    }

    /// Frames tab live replay: form posts history (or one index) through
    /// `/ws/replay`; list rows still come only from the event socket.
    #[test]
    fn frames_tab_offers_live_ws_replay() {
        assert!(
            SCRIPT.contains("function replayForm(id, flow)"),
            "the frames pane must build a replay form"
        );
        assert!(
            SCRIPT.contains(
                "function replayFrames(sourceId, indices, directions, delayMs, targetFlowId, button, status)"
            ),
            "replay must post through replayFrames"
        );
        assert!(
            SCRIPT.contains("Replay history")
                && SCRIPT.contains("Replay direction filter")
                && SCRIPT.contains("Target flow id"),
            "replay form must offer direction filter, target, and a history action"
        );
        assert!(
            SCRIPT.contains("frameIndexBase")
                && SCRIPT.contains("frameLine(frameMessages[i], frameIndexBase + i)"),
            "per-frame replay needs absolute indices into source history"
        );
        assert!(
            SCRIPT.contains("function isInjectableOpcode(code)")
                && SCRIPT.contains("Replay this frame"),
            "injectable frames must offer a single-frame replay control"
        );
        assert!(
            SCRIPT.contains(
                "This socket is closed. Replay only works onto a live upgraded flow"
            ),
            "a finished websocket must say replay needs a live target"
        );
        // Successful replay must not invent list rows from response.messages.
        let replay = SCRIPT
            .split_once(
                "async function replayFrames(sourceId, indices, directions, delayMs, targetFlowId, button, status) {",
            )
            .expect("replayFrames still exists")
            .1;
        let body = replay
            .split_once("function frameLine(message, absoluteIndex) {")
            .expect("frameLine follows replayFrames")
            .0;
        for forbidden in [
            "retainFrame(",
            "renderFrames(",
            "frameLine(",
            "frameList.appendChild",
            "frameMessages.push",
            "parsed.messages",
        ] {
            assert!(
                !body.contains(forbidden),
                "replayFrames must not {forbidden}: the event socket owns the list"
            );
        }
        assert!(
            body.contains("status.textContent = note;")
                || body.contains("status.textContent = 'Replaying...'"),
            "a successful replay must only mark status"
        );
        assert!(
            CSS.contains(".inject.replay") && CSS.contains(".frame-replay"),
            "replay form and per-row control need styles"
        );
    }

    /// Same contract as inject: every key the page posts has to be one
    /// WsReplayRequest deserialises (deny_unknown_fields).
    #[test]
    fn every_key_the_ws_replay_form_sends_is_one_the_endpoint_acts_on() {
        let payload = serde_json::json!({
            "mode": "live",
            "indices": [0, 2],
            "directions": ["send"],
            "delayMs": 10,
            "targetFlowId": "other-id",
            "stopOnError": true,
        });
        let object = payload.as_object().expect("the payload is an object");
        for key in object.keys() {
            assert!(
                SCRIPT.contains(&format!("{key}:"))
                    || SCRIPT.contains(&format!("body.{key}"))
                    || SCRIPT.contains(&format!("\"{key}\"")),
                "{key} is in this test but the replay form no longer sends it"
            );
        }

        let req: crate::replay::WsReplayRequest =
            serde_json::from_value(payload).expect("the replay form payload is a WsReplayRequest");
        assert_eq!(req.mode.as_deref(), Some("live"));
        assert_eq!(req.indices.as_deref(), Some(&[0usize, 2][..]));
        assert_eq!(
            req.directions.as_ref().map(|d| d.as_slice()),
            Some(&["send".to_string()][..])
        );
        assert_eq!(req.delay_ms, Some(10));
        assert_eq!(req.target_flow_id.as_deref(), Some("other-id"));
        assert_eq!(req.stop_on_error, Some(true));

        for field in [
            "body.mode = 'live'",
            "body.indices = indices",
            "body.directions = directions",
            "body.delayMs = delayMs",
            "body.targetFlowId = targetFlowId",
            "body.stopOnError = true",
        ] {
            assert!(
                SCRIPT.contains(field),
                "the replay form must still send {field}"
            );
        }

        // A key the endpoint does not act on must be refused, not swallowed.
        let mut invented = serde_json::json!({ "mode": "live" });
        invented["followRedirects"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<crate::replay::WsReplayRequest>(invented).is_err(),
            "a key the replay endpoint does not act on must be refused, not swallowed"
        );
    }

    /// Same contract as the HTTP composer: every key the page posts has to be
    /// one the endpoint deserialises, or inject silently does something else.
    #[test]
    fn every_key_the_ws_inject_form_sends_is_one_the_endpoint_acts_on() {
        let payload = serde_json::json!({
            "direction": "send",
            "opcode": 1,
            "text": "hello",
            "dataBase64": "aGk=",
            "closeCode": 1000,
            "closeReason": "bye",
        });
        let object = payload.as_object().expect("the payload is an object");
        for key in object.keys() {
            assert!(
                SCRIPT.contains(&format!("{key}:")) || SCRIPT.contains(&format!("body.{key}")),
                "{key} is in this test but the inject form no longer sends it"
            );
        }

        // The real request body is built in injectFrame; deserialising the same
        // shape through the route's private struct is not possible here, so the
        // camelCase fields of WsMessage-bound inject are checked against the
        // documented request shape instead.
        for field in [
            "direction:",
            "opcode:",
            "text = text",
            "dataBase64",
            "closeCode",
            "closeReason",
        ] {
            assert!(
                SCRIPT.contains(field),
                "the inject form must still send {field}"
            );
        }
        assert!(
            SCRIPT.contains("body.closeCode = code;"),
            "close frames must send closeCode"
        );
        assert!(
            SCRIPT.contains("body.closeReason = closeReason;"),
            "close frames must send closeReason when set"
        );
        assert!(
            SCRIPT.contains("body.dataBase64 = toBase64(text);"),
            "binary frames must send dataBase64"
        );
        assert!(
            SCRIPT.contains("body.text = text;"),
            "text frames must send text"
        );
    }

    /// Serde drops a key it does not recognise, so a field the page invents
    /// reads on screen as a promise and on the wire as nothing at all.
    #[test]
    fn every_key_the_composer_sends_is_one_the_send_endpoint_acts_on() {
        let payload = serde_json::json!({
            "method": "POST",
            "url": "https://api.example.com/v1/thing",
            "headers": [["content-type", "application/json"]],
            "bodyBase64": "aGk=",
        });
        let object = payload.as_object().expect("the payload is an object");
        for key in object.keys() {
            assert!(
                SCRIPT.contains(&format!("{key}:")),
                "{key} is in this test but the composer no longer sends it"
            );
        }

        let spec: crate::replay::SendSpec =
            serde_json::from_value(payload).expect("the composer's payload is a SendSpec");
        assert_eq!(spec.method.as_deref(), Some("POST"));
        assert_eq!(
            spec.url.as_deref(),
            Some("https://api.example.com/v1/thing")
        );

        // The composer once sent this and nothing has ever implemented it.
        let mut invented = serde_json::json!({ "url": "https://example.com/" });
        invented["followRedirects"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<crate::replay::SendSpec>(invented).is_err(),
            "a key the engine does not act on must be refused, not swallowed"
        );
        assert!(
            !SCRIPT.contains("followRedirects"),
            "the composer must not ask for a behaviour nothing implements"
        );
    }

    /// Shared H2+H3 multiplex identity on Flow / FlowSummary. The list and
    /// Info pane read the same camelCase keys the REST and event socket send;
    /// transport stays optional and is not required for H2 connectionId.
    #[test]
    fn multiplex_fields_are_read_from_summary_and_full_flow() {
        // List filter needle includes connection/stream so typing a session id
        // groups sibling streams without a separate API field.
        assert!(
            SCRIPT.contains("str(flow.connectionId), str(flow.streamId)"),
            "list filter must match connectionId and streamId from FlowSummary"
        );
        // Row tooltip surfaces version, transport, conn, stream without new columns.
        assert!(
            SCRIPT.contains("tips.push('conn ' + str(flow.connectionId));"),
            "list row title must show connectionId when present"
        );
        assert!(
            SCRIPT.contains("tips.push('stream ' + String(flow.streamId));"),
            "list row title must show streamId when present"
        );
        // Info facts: same keys for H2 and H3; transport only when set.
        assert!(
            SCRIPT.contains("if (flow.transport) { pairs.push(['Transport', str(flow.transport)]); }"),
            "Info must show transport only when present (H3 quic; omit for TCP H2)"
        );
        assert!(
            SCRIPT.contains("if (flow.connectionId) { pairs.push(['Connection', str(flow.connectionId)]); }"),
            "Info must show connectionId for H2 and H3 multiplex sessions"
        );
        assert!(
            SCRIPT.contains("pairs.push(['Stream id', String(flow.streamId)]);"),
            "Info must show client-leg streamId when known"
        );
        assert!(
            SCRIPT.contains("pairs.push(['Upstream stream id', String(flow.upstreamStreamId)]);"),
            "Info must show upstreamStreamId (full flow only) when MITM reopened multiplex"
        );
        // Click connection to filter siblings on the same multiplex session.
        assert!(
            SCRIPT.contains("function filterByConnection(connectionId)"),
            "Connection fact must offer filter-by-session for H2/H3 grouping"
        );
        assert!(
            SCRIPT.contains("filterByConnection(str(flow.connectionId));"),
            "clicking Connection must filter the list to that session id"
        );
        assert!(
            CSS.contains("button.flink"),
            "connection filter control needs distinct styling"
        );
        // Detail head is method alone; version is not glued on as "GET 2.0".
        assert!(
            SCRIPT.contains("head.appendChild(el('span', 'dmethod', str(request.method)));"),
            "detail method line must show method only"
        );
        assert!(
            !SCRIPT.contains("methodLabel + '  ' + str(request.httpVersion)"),
            "detail method must not append httpVersion"
        );
        // Filter box copy mentions connection so the shared key is discoverable.
        assert!(
            BODY.contains("status or connection"),
            "filter placeholder must mention connection for multiplex session search"
        );
        // Event-socket status frames drive the chrome strip for bound UDP
        // listeners and scaffolds (quic / reverse-h3 / wireguard / tun);
        // never the TCP proxy port, and never a claim that WG crypto or host
        // packet capture works.
        assert!(
            SCRIPT.contains("st.quicEnabled || st.quicPort || st.quicNote || st.reverseH3"),
            "status events must read ServerStatus quic fields"
        );
        assert!(
            SCRIPT.contains("QUIC :' + st.quicPort"),
            "status strip must show the UDP quicPort when bound"
        );
        assert!(
            SCRIPT.contains("st.reverseH3"),
            "status strip must surface reverseH3 upstream when set"
        );
        assert!(
            SCRIPT.contains("accept-only"),
            "status strip must label accept-only when no reverse upstream"
        );
        assert!(
            SCRIPT.contains("st.quicNote"),
            "status strip must put quicNote on the live indicator title"
        );
        assert!(
            SCRIPT.contains("st.wireguardEnabled || st.wireguardPort || st.wireguardNote"),
            "status events must read ServerStatus wireguard fields"
        );
        assert!(
            SCRIPT.contains("WG :' + st.wireguardPort"),
            "status strip must show the WG UDP port when bound"
        );
        assert!(
            SCRIPT.contains("scaffold"),
            "WG/TUN strip labels must say scaffold so they are not fake claims"
        );
        assert!(
            SCRIPT.contains("st.wireguardNote"),
            "status strip must put wireguardNote on the live indicator title"
        );
        assert!(
            SCRIPT.contains("st.tunEnabled || st.tunActive || st.tunNote"),
            "status events must read ServerStatus tun fields"
        );
        assert!(
            SCRIPT.contains("TUN scaffold"),
            "status strip must label TUN as scaffold when active"
        );
        assert!(
            SCRIPT.contains("st.tunNote"),
            "status strip must put tunNote on the live indicator title"
        );
        assert!(
            SCRIPT.contains("st.tunActive"),
            "status strip must gate the TUN label on tunActive"
        );
        // Archive stats panel: gated on ServerStatus.archiving, loads the
        // canned report, seats mutually exclusive with compose/break/rewrite.
        assert!(
            SCRIPT.contains("st.archiving"),
            "status events must read ServerStatus.archiving for the archive button"
        );
        assert!(
            SCRIPT.contains("st.archiveDropped"),
            "status events must read archiveDropped for the archive drop note"
        );
        assert!(
            SCRIPT.contains("/api/archive/stats"),
            "archive panel must call GET /api/archive/stats"
        );
        assert!(
            BODY.contains("id=\"archive\"")
                && BODY.contains("id=\"archiver\"")
                && BODY.contains("id=\"a-status\"")
                && BODY.contains("id=\"a-body\"")
                && BODY.contains("id=\"a-refresh\"")
                && BODY.contains("id=\"a-dropped\""),
            "archive panel needs its shell ids: archive, archiver, a-status, a-body, a-refresh, a-dropped"
        );
        assert!(
            SCRIPT.contains("function archiveView(on)"),
            "archive panel must use a seat toggler like the other full-seat panels"
        );
        assert!(
            SCRIPT.contains("archiveView(false)"),
            "compose/break/rewrite/select/scope must release the archive seat"
        );
        assert!(
            SCRIPT.contains("mainEl.classList.toggle('archiving', on)"),
            "archive seat must toggle the archiving class on main"
        );
        assert!(
            CSS.contains("main.archiving > #archiver"),
            "archive seat CSS must place #archiver like the other full-seat panels"
        );
        assert!(
            SCRIPT.contains("Archive is not enabled"),
            "when archiving is off the panel must explain rather than call a dead endpoint only"
        );
        assert!(
            SCRIPT.contains("paintArchiveStats")
                && SCRIPT.contains("Busiest hosts")
                && SCRIPT.contains("Status classes")
                && SCRIPT.contains("Slowest paths")
                && SCRIPT.contains("Heaviest responses"),
            "archive panel must render totals, hosts, statuses, slowest and heaviest sections"
        );
        // P11: likelyPinning is a cert-reject signal, not pure pinning proof.
        assert!(
            SCRIPT.contains("not pure pinning proof")
                || SCRIPT.contains("user-installed CA")
                || SCRIPT.contains("user-CA policy"),
            "Info error copy must not claim pure app pinning for likelyPinning"
        );
        assert!(
            SCRIPT.contains("pin.title")
                && SCRIPT.contains("Not pure pinning proof"),
            "PINNED badge tooltip must state cert-reject is not pure pinning proof"
        );

        // Map-local mock: list badge + filter token + detail banner, not only
        // rewrite notes. flow.mocked drives every surface.
        assert!(
            SCRIPT.contains("row.querySelector('.mock').hidden = !flow.mocked"),
            "list row must show the mock badge from summary.mocked"
        );
        assert!(
            SCRIPT.contains("flow.mocked ? 'mock mocked' : ''"),
            "filter haystack must include a synthetic mock token for map-local rows"
        );
        assert!(
            SCRIPT.contains("Mocked response (map local)"),
            "detail pane must banner map-local mocks, not bury them in rewrites"
        );
        assert!(
            SCRIPT.contains("if (flow.mocked)"),
            "detail rendering must branch on flow.mocked"
        );

        // FlowSummary still serialises the optional keys the list reads.
        let summary = FlowSummary {
            id: "s1".into(),
            kind: FlowKind::Http,
            state: FlowState::Complete,
            intercepted: true,
            method: "GET".into(),
            scheme: Scheme::Https,
            authority: "example.com".into(),
            path: "/".into(),
            http_version: HttpVersion::Http2,
            status: Some(200),
            content_type: None,
            request_size: 0,
            response_size: 0,
            start: 1,
            duration: Some(2),
            error: None,
            likely_pinning: false,
            client: "10.0.0.2".into(),
            transport: None,
            connection_id: Some("tls-session-uuid".into()),
            stream_id: Some(3),
            mocked: false,
        };
        let json = serde_json::to_value(&summary).expect("summary serialises");
        assert_eq!(json["connectionId"], "tls-session-uuid");
        assert_eq!(json["streamId"], 3);
        assert_eq!(json["httpVersion"], "2.0");
        assert!(
            json.as_object().unwrap().get("transport").is_none(),
            "H2 summary must omit transport so TCP list JSON stays quiet"
        );
        assert!(
            json.as_object().unwrap().get("upstreamStreamId").is_none(),
            "upstreamStreamId is full-Flow only, not on FlowSummary"
        );
        assert!(
            json.as_object().unwrap().get("mocked").is_none(),
            "ordinary summary omits mocked when false"
        );
    }
}
