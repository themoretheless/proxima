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
  <input id="filter" type="search" placeholder="Filter by method, host, path or status" autocomplete="off" spellcheck="false" aria-label="Filter">
  <span id="count" class="count"></span>
  <button id="theme" class="btn" type="button" title="Light, dark, or whatever this machine is set to">Theme: system</button>
  <button id="view" class="btn on" type="button">Hide tree</button>
  <button id="compose" class="btn" type="button">Compose</button>
  <button id="clear" class="btn" type="button">Clear</button>
  <a class="btn" href="/setup">Set up a device</a>
</header>
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
      <div id="hosts" role="tree" aria-label="Hosts and paths"></div>
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
      <div id="books" role="tree" aria-label="Saved requests"></div>
      <p id="no-books" class="pad hint">Nothing saved yet. Compose a request, name it, and save.</p>
    </div>
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
      <button id="c-save" class="btn" type="button">Save</button>
    </div>
    <div class="c-line">
      <select id="c-method" aria-label="Method">
        <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option>
        <option>DELETE</option><option>HEAD</option><option>OPTIONS</option>
      </select>
      <input id="c-url" type="text" spellcheck="false" autocomplete="off"
             placeholder="https://api.example.com/v1/thing" aria-label="URL">
      <button id="c-send" class="btn" type="button">Send</button>
    </div>
    <label class="c-label" for="c-headers">Headers, one per line, as Name: value</label>
    <textarea id="c-headers" spellcheck="false" placeholder="content-type: application/json"></textarea>
    <label class="c-label" for="c-body">Body</label>
    <textarea id="c-body" spellcheck="false"></textarea>
    <div id="c-out"></div>
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
  border-radius: 7px; font: inherit; text-decoration: none; cursor: pointer;
  white-space: nowrap;
}
.btn:hover { background: var(--btn-hover); }
/* The tree stands beside both panes, and the request sits under the list it
   was picked from rather than off to one side of it: header lines and bodies
   are wide things, and a column beside the list is not. */
main {
  flex: 1; min-height: 0; display: grid;
  grid-template-columns: minmax(0, 15rem) minmax(0, 1fr);
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
   thing being picked from. */
main.composing { grid-template-rows: minmax(0, 1fr); }
main.composing > #list, main.composing > #detail { display: none; }
main.composing > #composer { grid-column: 2; grid-row: 1; }
main.composing.flat > #composer { grid-column: 1; }
#composer {
  overflow: auto; min-height: 0; padding: 12px 14px 40px;
  display: flex; flex-direction: column; gap: 8px;
}
.c-line { display: flex; gap: 8px; }
#c-url { flex: 1; min-width: 0; }
#composer select, #composer input, #composer textarea {
  background: var(--bg); color: var(--ink); border: 1px solid var(--line);
  border-radius: 7px; padding: 5px 9px; font: inherit;
}
#composer select:focus, #composer input:focus, #composer textarea:focus {
  outline: 1px solid var(--accent); border-color: var(--accent);
}
#composer textarea { min-height: 92px; resize: vertical; }
.c-label {
  color: var(--dim); font-size: 11px; letter-spacing: .06em; text-transform: uppercase;
}
.btn.on { border-color: var(--accent); color: var(--accent); }
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
.row span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.row .host { display: flex; gap: 6px; align-items: baseline; min-width: 0; }
.row .hostname { min-width: 0; }
.pin {
  flex: none; display: inline-block; padding: 0 4px; border-radius: 3px;
  background: var(--warn); color: var(--pin-ink); font-size: 10px; font-weight: 700;
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
  min-height: 0; display: flex; flex-direction: column; overflow: hidden;
  border-right: 1px solid var(--line);
}
/* Both halves carry the same bar and fold away the same way. A folded one
   keeps only its bar, and the space it was using goes to the other. */
.part { display: flex; flex-direction: column; min-height: 0; }
.part.shut > *:not(.shelf) { display: none; }
/* The hosts take the height they need and no more, so the bar under them sits
   right below the last one rather than at some share of the column decided in
   advance. Past two thirds they stop growing and scroll instead, or a busy
   capture would push the saved requests off the bottom. */
#live { flex: 0 1 auto; max-height: 66%; }
#saved { flex: 1 1 auto; border-top: 1px solid var(--line); }
/* Written against the ids on purpose: the shares above are set that way too,
   and a class alone loses to them, which leaves a folded half still holding
   the room it was given. Folded halves stack at the top instead. */
#live.shut, #saved.shut { flex: none; }
#hosts { flex: 0 1 auto; min-height: 0; overflow: auto; padding: 4px 0 12px; }
/* Devices sit above the hosts because they are the coarser cut: which machine,
   then which of its hosts. One device is the usual case, and one chip that
   says so is small enough to leave alone. */
#devices {
  flex: none; display: flex; flex-wrap: wrap; gap: 4px; padding: 6px 8px;
  border-bottom: 1px solid var(--rule);
}
#devices:empty { display: none; }
.chip {
  padding: 2px 8px; cursor: pointer; white-space: nowrap;
  background: none; border: 1px solid var(--btn-line); border-radius: 20px;
  color: var(--dim); font: inherit; font-size: 11px;
}
.chip:hover { background: var(--hover); color: var(--ink); }
.chip.on { background: var(--pick); border-color: var(--accent); color: var(--accent); }
.star {
  flex: none; visibility: hidden; padding: 0 2px; cursor: pointer;
  background: none; border: none; color: var(--dim); font: inherit; font-size: 11px;
}
.star.on { visibility: visible; color: var(--accent); }
.gline:hover .star { visibility: visible; }
#books { flex: 1; min-height: 0; overflow: auto; padding: 2px 0 12px; }
.shelf {
  flex: none; display: flex; align-items: center; gap: 6px; cursor: default;
  padding: 4px 6px 4px 8px; border-bottom: 1px solid var(--rule);
}
.shelf:hover { background: var(--hover); }
.shelf > .twist { font-size: 10px; }
.shelf .icon { width: 22px; height: 22px; font-size: 13px; }
.hunt {
  flex: none; margin: 5px 8px 3px; height: 24px; padding: 0 8px;
  background: var(--field); color: var(--ink);
  border: 1px solid var(--line); border-radius: 7px; font: inherit; font-size: 12px;
}
.hunt:focus { outline: none; border-color: var(--accent); }
.shelf-name {
  flex: 1; color: var(--dim); font-size: 11px;
  letter-spacing: .06em; text-transform: uppercase;
}
.pad { margin: 0; padding: 10px 12px; font-size: 12px; }
.sitem {
  display: flex; gap: 6px; align-items: baseline; padding: 3px 8px 3px 12px;
  cursor: default; font-size: 12px;
}
.sitem:hover { background: var(--hover); }
.smethod {
  flex: none; width: 3.2rem; color: var(--dim);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px;
}
.sname { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* A control that destroys something should not be sitting under the pointer
   before the pointer is anywhere near it. */
.kill {
  flex: none; visibility: hidden; padding: 0 3px; cursor: pointer;
  background: none; border: none; color: var(--dim); font: inherit; font-size: 13px;
}
.kill:hover { color: var(--bad); }
.sitem:hover .kill, .gline:hover .kill { visibility: visible; }
.gline {
  display: flex; gap: 6px; align-items: baseline; padding: 3px 10px 3px 4px;
  cursor: default; border-radius: 0 6px 6px 0;
}
.gline:hover { background: var(--hover); }
.gline.picked { background: var(--pick); box-shadow: inset 2px 0 0 var(--accent); }
.twist { flex: none; width: .9rem; color: var(--dim); text-align: center; }
.gname {
  flex: 1; min-width: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
  color: var(--dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.group.host > .gline > .gname { color: var(--ink); }
.gcount { flex: none; color: var(--dim); font-size: 11px; }
.gline.picked > .gname, .gline.picked > .gcount { color: var(--accent); }
.gbody { margin-left: 11px; border-left: 1px solid var(--rule); }
.group.shut > .gbody { display: none; }
#scope {
  display: flex; gap: 6px; align-items: baseline; padding: 5px 10px;
  color: var(--dim); font-size: 12px; border-bottom: 1px solid var(--line);
}
#scope button {
  background: none; border: none; padding: 0; margin: 0; cursor: pointer;
  color: var(--accent); font: inherit;
}
#scope.idle { display: none; }
#empty { flex: none; margin: 0; padding: 22px 14px; color: var(--dim); }
.hint { color: var(--dim); }
.dhead { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.icon {
  flex: none; width: 26px; height: 26px; padding: 0; cursor: pointer;
  display: inline-flex; align-items: center; justify-content: center;
  background: var(--btn); color: var(--dim); border: 1px solid var(--btn-line);
  border-radius: 7px; font: inherit; font-size: 14px; line-height: 1;
}
.icon:hover { background: var(--btn-hover); color: var(--ink); }
.icon.caret { width: 18px; font-size: 10px; }
.icon.on { border-color: var(--accent); color: var(--accent); }
/* Not the same thing as an open menu: this one says the menu was used. */
.icon.set { border-color: var(--accent); color: var(--accent); }
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
  padding: 5px 9px; text-align: left; white-space: nowrap; cursor: pointer;
  background: none; border: none; border-radius: 6px; color: var(--ink); font: inherit;
}
.mitem:hover { background: var(--hover); }
/* The same menu, hung off a button that sits at the right edge of a narrow
   column: measured from that edge instead, or most of it would be off the
   side of the tree it belongs to. */
.sift { position: relative; display: inline-flex; }
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
/* The switch over the bottom pane. Request and response are the same shape and
   are usually read against each other, so both fitting on one screen is worth
   a mode of its own rather than a second click every time. */
.tabs { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.tab {
  height: 26px; padding: 0 10px; background: none; cursor: pointer;
  border: 1px solid transparent; border-radius: 7px; color: var(--dim); font: inherit;
}
.tab:hover { background: var(--hover); color: var(--ink); }
.tab.on { background: var(--pick); border-color: var(--accent); color: var(--accent); }
.tabs .gap { flex: 1; min-width: 12px; }
.panes.both { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 0 20px; }
.panes.both > .wide { grid-column: 1 / -1; }
.frame { display: grid; grid-template-columns: 9rem 9rem minmax(0, 1fr); gap: 8px; font-size: 12px; padding: 2px 0; }
.frame .dir { color: var(--dim); }
.frame.up .dir { color: var(--accent); }
.frame .text { word-break: break-all; white-space: pre-wrap; }
@media (max-width: 1000px) {
  /* The tree is the pane you can do without: the filter box narrows the same
     list without taking a column to do it. */
  main, main.flat { grid-template-columns: minmax(0, 1fr); }
  main > #tree { display: none; }
  main > #list, main > #detail, main.composing > #composer { grid-column: 1; }
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
  var onlyBad = false;
  var bookGroup = 'book';
  var selectedId = null;
  var detailToken = 0;
  var queue = null;
  var greeted = false;
  var backoff = RETRY_MIN;
  var frameList = null;
  var frameOwner = null;
  var side = 'info';
  var paired = false;

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
    row.appendChild(el('span', 'method'));
    var host = el('span', 'host');
    host.appendChild(el('span', 'hostname'));
    host.appendChild(el('span', 'pin', 'PINNED'));
    row.appendChild(host);
    row.appendChild(el('span', 'path'));
    row.appendChild(el('span', 'status'));
    row.appendChild(el('span', 'size'));
    row.appendChild(el('span', 'dur'));
    row.addEventListener('click', function () { select(row.flowId); });
    return row;
  }

  function paint(row, flow) {
    row.querySelector('.method').textContent = str(flow.method);
    row.querySelector('.hostname').textContent = str(flow.authority);
    row.querySelector('.pin').hidden = !flow.likelyPinning;
    row.querySelector('.path').textContent = str(flow.path);
    row.querySelector('.status').textContent = statusLabel(flow);
    row.querySelector('.size').textContent = size(flow.responseSize);
    row.querySelector('.dur').textContent =
      typeof flow.duration === 'number' ? millis(flow.duration) : '...';

    var mark = statusClass(flow);
    var cls = 'row ' + mark;
    if (flow.likelyPinning) { cls += ' pinned'; }
    if (flow.id === selectedId) { cls += ' on'; }
    row.className = cls;
    // What "went wrong" means to the menu below: a status the server refused
    // with, or a flow that never got one at all.
    bads.set(flow.id, mark === 's4' || mark === 's5' || mark === 'serr');

    needles.set(flow.id, [
      str(flow.method), str(flow.authority), str(flow.path),
      statusLabel(flow), str(flow.error), str(flow.client)
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

  // The narrowings are one decision: a row survives the typed needle, the
  // device the chips picked, whatever the menu on the bar is asking for, and
  // the branch that was clicked, or it is not on screen.
  function filterRow(row, id) {
    var text = needles.get(id) || '';
    var hide = (needle !== '' && text.indexOf(needle) < 0)
      || (device !== '' && homes.get(id) !== device)
      || (onlyBad && !bads.get(id))
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
    detailToken += 1;
    hint('Pick a request to see its headers and body.');
    tally();
  }

  function tally() {
    var total = rows.size;
    emptyEl.hidden = total > 0;
    if (!total) { countEl.textContent = ''; return; }
    countEl.textContent = visible === total
      ? total + ' flows'
      : visible + ' of ' + total + ' flows';
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
    var count = el('span', 'gcount', '0');
    line.appendChild(count);
    // The star keeps a host at the top, so it belongs to a line that is one:
    // grouped by device the top line is an address, and keeping it would mean
    // something else again.
    if (!parent && liveGroup === 'host') { line.appendChild(starFor(box, label)); }
    var body = el('div', 'gbody');
    box.appendChild(line);
    box.appendChild(body);
    // The twisty folds the branch away, the rest of the line narrows the list.
    // Two jobs on one row, so the first has to keep the click to itself.
    twist.addEventListener('click', function (event) {
      event.stopPropagation();
      twist.textContent = box.classList.toggle('shut') ? '▸' : '▾';
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
    if (scope) { scopeTo(scope); }
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
    if (onlyBad && !bads.get(id)) { return 0; }
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
      if (rec.key === scope) { scopeTo(scope); }
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

  function scopeTo(key) {
    scope = scope === key ? '' : key;
    groups.forEach(function (rec) { rec.line.classList.toggle('picked', rec.key === scope); });
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
    detailEl.appendChild(el('p', 'hint', text));
  }

  async function select(id) {
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
    var request = flow.request || {};
    var response = flow.response || null;

    var head = el('div', 'dhead');
    // One line, and the copy sits at the head of it: it acts on the URL beside
    // it, and a row of its own for a single control was a row of mostly nothing.
    head.appendChild(copyBar(flow, request, response));
    head.appendChild(el('span', 'dmethod', str(request.method)));
    head.appendChild(el('span', 'durl mono', str(request.url)));
    detailEl.appendChild(head);

    sides(flow, request, response);
  }

  /* The bottom pane holds two halves of one exchange. Which of them is on
     screen is a preference rather than a property of the flow, so it is kept
     across selections: picking the next request does not put you back on a
     tab you had just moved away from. */

  function sides(flow, request, response) {
    var frames = Array.isArray(flow.wsMessages) ? flow.wsMessages : null;
    var tabs = el('div', 'tabs');
    var panes = el('div', 'panes');
    var buttons = [];

    function draw() {
      strip(panes);
      // Whatever the frame list was pointing at is about to leave the document.
      frameList = null;
      frameOwner = null;
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
      box.appendChild(frameBlock(flow.id, frames));
      return box;
    }
    if (which === 'info') {
      box.appendChild(facts(flow, request, response));
      if (flow.error) {
        var trouble = el('div', 'error');
        trouble.appendChild(el('div', 'etitle', str(flow.error.message)));
        if (flow.error.likelyPinning) {
          trouble.appendChild(el('p', null, 'The client rejected the Proxima certificate, which almost always means the app pins its own. Nothing here is broken and no setting on this machine will decrypt it: the app has to be built against a permissive network security config, or run on a device where Proxima is in the system trust store.'));
        }
        box.appendChild(trouble);
      }
      return box;
    }
    var half = which === 'response' ? response : request;
    box.appendChild(headerBlock(
      which === 'response' ? 'Response headers' : 'Request headers', half.headers));
    box.appendChild(bodyBlock(flow.id, which, half.body));
    return box;
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
    pairs.push(['HTTP', str(request.httpVersion)]);
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
      grid.appendChild(el('span', 'fval', pairs[i][1]));
    }
    return grid;
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
    into.textContent = indent(text, contentType) +
      (cut ? '\n\n[stopped after ' + MAX_BODY_CHARS + ' characters]' : '');
  }

  // Reformatting JSON is worth it: most captured JSON arrives on one line.
  function indent(text, contentType) {
    if (!contentType || String(contentType).toLowerCase().indexOf('json') < 0) { return text; }
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch (error) {
      return text;
    }
  }

  function frameBlock(id, messages) {
    var block = el('section', 'block');
    block.appendChild(el('h2', null, 'WebSocket frames'));
    frameList = el('div', 'frames mono');
    frameOwner = id;
    var recent = messages.slice(-MAX_FRAMES);
    for (var i = 0; i < recent.length; i++) {
      frameList.appendChild(frameLine(recent[i]));
    }
    block.appendChild(frameList);
    return block;
  }

  function frameLine(message) {
    var out = message.direction === 'send';
    var line = el('div', out ? 'frame up' : 'frame down');
    line.appendChild(el('span', 'dir', out ? 'client to server' : 'server to client'));
    line.appendChild(el('span', 'meta',
      opcode(message.opcode) + ', ' + size(message.size) + (message.truncated ? ', cut short' : '')));
    if (typeof message.text === 'string') { line.appendChild(el('span', 'text', message.text)); }
    return line;
  }

  function opcode(code) {
    if (code === 1) { return 'text'; }
    if (code === 2) { return 'binary'; }
    if (code === 8) { return 'close'; }
    if (code === 9) { return 'ping'; }
    if (code === 10) { return 'pong'; }
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
        select(selectedId);
      }
      return;
    }
    if (event.type === 'clear') { wipe(); return; }
    if (event.type === 'status') {
      // The first one is the handshake. A later one means the socket dropped
      // events on the floor and this list has holes in it.
      if (greeted) { reload(); } else { greeted = true; }
      return;
    }
    if (event.type === 'ws:message' && event.id === frameOwner && frameList) {
      frameList.appendChild(frameLine(event.message || {}));
      while (frameList.childElementCount > MAX_FRAMES) {
        frameList.removeChild(frameList.firstChild);
      }
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
      var page = await getJson('/api/flows?limit=' + MAX_ROWS);
      wipe();
      var list = page && Array.isArray(page.flows) ? page.flows : [];
      for (var i = 0; i < list.length; i++) { upsert(list[i], false); }
    } catch (error) {
      stateEl.textContent = 'cannot read flows';
    }
    var pending = queue;
    queue = null;
    for (var j = 0; j < pending.length; j++) { apply(pending[j]); }
    tally();
    if (reopen && rows.has(reopen)) { select(reopen); }
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

  function composing(on) {
    mainEl.classList.toggle('composing', on);
    composerEl.hidden = !on;
    composeBtn.classList.toggle('on', on);
    if (on) { document.getElementById('c-url').focus(); }
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
    if (!url) {
      outEl.appendChild(el('p', 'hint', 'Give it a URL first.'));
      return;
    }

    var bodyText = document.getElementById('c-body').value;
    var spec = {
      method: document.getElementById('c-method').value,
      url: url,
      headers: readHeaders(document.getElementById('c-headers').value),
      bodyBase64: bodyText ? toBase64(bodyText) : null
    };

    button.disabled = true;
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
        outEl.appendChild(el('p', 'hint', 'The request failed.'));
        outEl.appendChild(el('pre', 'mono', text));
        return;
      }

      var result = JSON.parse(text);
      var took = result.timings && result.timings.end
        ? result.timings.end - result.timings.start
        : null;
      var summary = el('section', 'block');
      summary.appendChild(el('h2', null, 'Response'));
      summary.appendChild(el('p', 'mono',
        str(result.status) + ' ' + str(result.statusText) + '   ' + str(result.httpVersion) +
        (took === null ? '' : '   ' + millis(took))));
      outEl.appendChild(summary);
      outEl.appendChild(headerBlock('Response headers', result.headers));

      var shown;
      try { shown = fromBase64(result.bodyBase64); }
      catch (error) { shown = '[the body is not text]'; }
      var body = el('section', 'block');
      body.appendChild(el('h2', null, 'Response body'));
      body.appendChild(el('pre', 'mono', indent(shown, contentTypeOf(result.headers))));
      outEl.appendChild(body);
    } catch (error) {
      strip(outEl);
      outEl.appendChild(el('p', 'hint', 'Could not send: ' + error.message));
    } finally {
      button.disabled = false;
    }
  }

  composeBtn.addEventListener('click', function () { composing(composerEl.hidden); });
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

  async function loadBooks() {
    try {
      var got = await getJson('/api/collections');
      books = Array.isArray(got) ? got : [];
    } catch (error) {
      books = [];
    }
    paintBooks();
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
      noBooksEl.textContent = 'Nothing saved yet. Compose a request, name it, and save.';
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

    line.addEventListener('click', function () {
      twist.textContent = box.classList.toggle('shut') ? '▸' : '▾';
    });

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

    item.addEventListener('click', function () { openSaved(saved); });
    return item;
  }

  // Straight into the composer, which is where a saved request is of any use.
  function openSaved(saved) {
    var spec = saved.spec || {};
    document.getElementById('c-method').value = str(spec.method) || 'GET';
    document.getElementById('c-url').value = str(spec.url);
    document.getElementById('c-headers').value = headerLines(spec.headers);
    var body = '';
    if (spec.bodyBase64) {
      try { body = fromBase64(spec.bodyBase64); } catch (error) { body = ''; }
    }
    document.getElementById('c-body').value = body;
    document.getElementById('c-name').value = str(saved.name);
    // The answer on screen belongs to the request that was open a moment ago.
    // Left up, it reads as the answer to this one, and it is convincing: same
    // shape, same pane, only the URL above it has changed.
    strip(outEl);
    composing(true);
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

  async function putBook(book) {
    var url = book.id ? '/api/collections/' + encodeURIComponent(book.id) : '/api/collections';
    var response = await fetch(url, {
      method: book.id ? 'PUT' : 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(book),
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
      // The store mints the id: an empty one is its word for new.
      id: '',
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
    book.requests = (book.requests || []).concat([saved]);

    strip(out);
    try {
      await putBook(book);
      await loadBooks();
      out.appendChild(el('p', 'hint', 'Saved as ' + saved.name + '.'));
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
    head('Show');
    pick('Everything', !onlyBad, function () { showBad(false); });
    pick('Failures only', onlyBad, function () { showBad(true); });
  });

  function regroupLive(how) {
    if (liveGroup === how) { return; }
    liveGroup = how;
    dressSift();
    regroup();
  }

  // The counts on the branches answer the same question the list does, so the
  // tree is re-added up rather than left describing traffic nothing shows.
  function showBad(only) {
    if (onlyBad === only) { return; }
    onlyBad = only;
    dressSift();
    rows.forEach(function (row, id) { filterRow(row, id); });
    restack();
    tally();
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
        live: liveGroup, bad: onlyBad, saved: bookGroup
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
    onlyBad = held.bad === true;
    dressSift();
  }

  /* Two things a button can be saying at once: that its menu is open, and that
     something in that menu is set to other than the default. The first is the
     class every menu here uses and is taken back the moment the menu closes,
     so the second needs one of its own or it would close with it. */

  function dressSift() {
    document.getElementById('sift-live').classList
      .toggle('set', onlyBad || liveGroup !== 'host');
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
  loadBooks();

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
            SCRIPT.contains("into.textContent = indent(text, contentType) +"),
            "a captured body must still be written as text, not built into markup"
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
    const KNOWN_PATHS: [&str; 9] = [
        "/api/flows",
        "/api/flows?limit=",
        "/api/flows/",
        "/api/stream",
        "/api/send",
        "/api/collections",
        "/api/collections/",
        "/body/",
        "/curl",
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
                "'/api/flows/' + encodeURIComponent(id) + '/curl'",
                "/api/flows/{id}/curl",
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
            SCRIPT.contains("if (rec.key === scope) { scopeTo(scope); }"),
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
        for shelf in ["data-part=\"live\"", "data-part=\"saved\""] {
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
            CSS.contains("#live.shut, #saved.shut { flex: none; }"),
            "a folded half must give its share of the column back"
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
            SCRIPT.contains("id: '',"),
            "the store mints request ids, and an empty one is how it is asked to"
        );
        let open = SCRIPT
            .split_once("function openSaved(saved) {")
            .expect("the script still opens a saved request")
            .1;
        for filled in ["c-method", "c-url", "c-headers", "c-body"] {
            assert!(
                open.contains(filled),
                "opening a saved request has to fill {filled}"
            );
        }
        assert!(
            open.contains("composing(true);"),
            "a saved request is only of use in the composer, so open it there"
        );
        // An answer left over from the request that was open a moment ago reads
        // as this one's: same shape, same pane, only the URL above it changed.
        assert!(
            open.contains("strip(outEl);"),
            "opening another request must take the last one's answer down with it"
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
            "select(selectedId);",
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
            "if (reopen && rows.has(reopen)) { select(reopen); }",
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
}
