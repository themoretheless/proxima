//! The page a phone sees first.
//!
//! It loads over plain HTTP, through the proxy, before any certificate has been
//! trusted. That rules out every external stylesheet, font, script and image:
//! the only thing the device can reach at that moment is this process. So the
//! whole page, including the connectivity check, is inlined here.
//!
//! It is also the page that decides whether someone gets Proxima working or
//! gives up. The order of the steps, and the prominence of the iOS trust switch,
//! are the substance of this file rather than its decoration.

use crate::types::ServerStatus;

use super::{friendly_date, url_host, ApiState};

/// The connectivity check targets a real HTTPS origin, because the point is to
/// prove a full handshake through the proxy. example.com is reserved by IANA
/// for exactly this, is always up, and is not a host anyone puts on a skip list.
const CHECK_URL: &str = "https://example.com/";
const CHECK_HOST: &str = "example.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Platform {
    Ios,
    Android,
    Desktop,
}

impl Platform {
    fn key(self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
            Platform::Desktop => "desktop",
        }
    }
}

/// iPadOS in its default desktop mode is indistinguishable from a Mac here, so
/// the page also re-checks on the client where `navigator.maxTouchPoints` can
/// settle it.
pub(crate) fn detect(user_agent: Option<&str>) -> Platform {
    let ua = user_agent.unwrap_or("").to_ascii_lowercase();
    if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod") {
        Platform::Ios
    } else if ua.contains("android") {
        Platform::Android
    } else {
        Platform::Desktop
    }
}

pub(super) fn render(state: &ApiState, user_agent: Option<&str>) -> String {
    let status = super::status(state);
    let platform = detect(user_agent);

    let primary = status
        .addresses
        .first()
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let proxy_port = state.proxy_port;
    let ui_port = state.ui_port;
    let setup_host = state
        .config
        .setup_hosts
        .first()
        .cloned()
        .unwrap_or_else(|| "proxima.setup".to_string());
    let expiry = friendly_date(state.ca.not_after());

    let mut page = String::with_capacity(24 * 1024);
    page.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    page.push_str("<meta charset=\"utf-8\">\n");
    page.push_str(
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n",
    );
    page.push_str("<meta name=\"color-scheme\" content=\"light dark\">\n");
    page.push_str("<title>Proxima setup</title>\n<style>");
    page.push_str(CSS);
    page.push_str("</style>\n</head>\n<body>\n");

    header(&mut page);
    address_card(&mut page, &primary, proxy_port, &status);
    tabs(&mut page, platform);
    ios_panel(&mut page, platform, &primary, proxy_port, &setup_host);
    android_panel(&mut page, platform, &primary, proxy_port, &setup_host);
    desktop_panel(&mut page, platform, &primary, proxy_port, ui_port);
    install_button(&mut page, platform);
    check_card(&mut page);
    certificate_card(&mut page, &status.ca_fingerprint, &expiry);
    footer(&mut page, &primary, ui_port);

    page.push_str("<script>const PROXIMA = ");
    page.push_str(&config_json(
        platform, &status, &primary, proxy_port, ui_port,
    ));
    page.push_str(";</script>\n<script>");
    page.push_str(SCRIPT);
    page.push_str("</script>\n</body>\n</html>\n");
    page
}

/* ------------------------------------------------------------------ */
/* sections                                                            */
/* ------------------------------------------------------------------ */

fn header(page: &mut String) {
    page.push_str(
        r#"<header>
  <div class="mark">PROXIMA</div>
  <h1>Set this device up</h1>
  <p class="lede">Two things have to happen: point this device's Wi-Fi proxy at Proxima, then trust its certificate. Both are reversible.</p>
</header>
"#,
    );
}

fn address_card(page: &mut String, primary: &str, proxy_port: u16, status: &ServerStatus) {
    page.push_str("<section class=\"card figures\">\n");
    page.push_str("  <div class=\"figure\"><span class=\"k\">Server</span><span class=\"v mono\">");
    page.push_str(&escape(primary));
    page.push_str("</span></div>\n");
    page.push_str("  <div class=\"figure\"><span class=\"k\">Port</span><span class=\"v mono\">");
    page.push_str(&proxy_port.to_string());
    page.push_str("</span></div>\n");

    if status.addresses.len() > 1 {
        page.push_str("  <p class=\"aside\">If that address does not work, this machine is also reachable at ");
        let alternatives: Vec<String> = status
            .addresses
            .iter()
            .skip(1)
            .take(4)
            .map(|address| format!("<code>{}</code>", escape(address)))
            .collect();
        page.push_str(&alternatives.join(", "));
        page.push_str(". Use the one on the same network as this device.</p>\n");
    }
    page.push_str("</section>\n");
}

fn tabs(page: &mut String, platform: Platform) {
    page.push_str("<nav class=\"tabs\" role=\"tablist\">\n");
    for (key, label) in [
        ("ios", "iPhone or iPad"),
        ("android", "Android"),
        ("desktop", "Desktop"),
    ] {
        let selected = key == platform.key();
        page.push_str("  <button type=\"button\" role=\"tab\" class=\"tab");
        if selected {
            page.push_str(" on");
        }
        page.push_str("\" data-tab=\"");
        page.push_str(key);
        page.push_str("\" aria-selected=\"");
        page.push_str(if selected { "true" } else { "false" });
        page.push_str("\">");
        page.push_str(label);
        page.push_str("</button>\n");
    }
    page.push_str("</nav>\n");
}

fn panel_open(page: &mut String, key: &str, platform: Platform) {
    page.push_str("<section class=\"panel\" data-panel=\"");
    page.push_str(key);
    page.push_str("\" role=\"tabpanel\"");
    if key != platform.key() {
        page.push_str(" hidden");
    }
    page.push_str(">\n");
}

fn ios_panel(
    page: &mut String,
    platform: Platform,
    primary: &str,
    proxy_port: u16,
    setup_host: &str,
) {
    panel_open(page, "ios", platform);
    page.push_str("<ol>\n");

    page.push_str("<li><b>Point Wi-Fi at Proxima.</b> Settings, Wi-Fi, tap the small <b>i</b> beside the network you are on. Scroll to <b>Configure Proxy</b>, choose <b>Manual</b>.<div class=\"kv\"><div><span class=\"k\">Server</span><span class=\"mono\">");
    page.push_str(&escape(primary));
    page.push_str("</span></div><div><span class=\"k\">Port</span><span class=\"mono\">");
    page.push_str(&proxy_port.to_string());
    page.push_str("</span></div></div>Leave <b>Authentication</b> off. Tap <b>Save</b>.</li>\n");

    page.push_str("<li><b>Come back here.</b> Open <code>http://");
    page.push_str(&escape(setup_host));
    page.push_str("</code> in Safari and tap the button below. Safari will say a profile was downloaded.</li>\n");

    page.push_str("<li><b>Install the profile.</b> Settings, then <b>Profile Downloaded</b> near the top. Tap <b>Install</b>, enter your passcode, tap <b>Install</b> again.</li>\n");

    page.push_str("<li class=\"pivotal\"><b>Turn on full trust. Everyone misses this step.</b><div class=\"path\">Settings &rsaquo; General &rsaquo; About &rsaquo; scroll to the bottom &rsaquo; Certificate Trust Settings</div>Switch on <b>Proxima CA</b>. Installing the profile is not enough on its own: until this switch is on, every HTTPS connection will simply fail.</li>\n");

    page.push_str("<li><b>Check it.</b> Use the button further down this page.</li>\n");
    page.push_str("</ol>\n</section>\n");
}

fn android_panel(
    page: &mut String,
    platform: Platform,
    primary: &str,
    proxy_port: u16,
    setup_host: &str,
) {
    panel_open(page, "android", platform);
    page.push_str("<ol>\n");

    page.push_str("<li><b>Point Wi-Fi at Proxima.</b> Settings, Network &amp; internet, Wi-Fi, tap your network, then the pencil or <b>Modify network</b>. Open <b>Advanced options</b> and set <b>Proxy</b> to <b>Manual</b>.<div class=\"kv\"><div><span class=\"k\">Hostname</span><span class=\"mono\">");
    page.push_str(&escape(primary));
    page.push_str("</span></div><div><span class=\"k\">Port</span><span class=\"mono\">");
    page.push_str(&proxy_port.to_string());
    page.push_str("</span></div></div>Save.</li>\n");

    page.push_str("<li><b>Download the certificate.</b> Reopen <code>http://");
    page.push_str(&escape(setup_host));
    page.push_str("</code> and tap the button below. It saves <code>proxima-ca.crt</code> to Downloads.</li>\n");

    page.push_str("<li><b>Install it as a CA certificate.</b> Settings, search for <b>certificate</b>, then <b>Install a certificate</b> and <b>CA certificate</b>. Confirm the warning, pick <code>proxima-ca.crt</code>. The exact menu path moves around between manufacturers and versions; searching Settings is faster than hunting.</li>\n");

    page.push_str("<li><b>Check it.</b> Use the button further down this page. A browser is the right thing to test with.</li>\n");
    page.push_str("</ol>\n");

    page.push_str("<div class=\"warn\"><b>Android 7 and later ignore user certificates in most apps.</b> Since Nougat, a user installed CA is only trusted by apps whose network security config opts in. Browsers do opt in, so web traffic decrypts fine. A stock third party app will not: its HTTPS either fails or, more often, keeps working while staying unreadable here. There is no setting on this page that changes that. The ways around it are a debug build of the app with a permissive network security config, or a rooted device where the certificate goes into the system store.</div>\n");
    page.push_str("</section>\n");
}

fn desktop_panel(
    page: &mut String,
    platform: Platform,
    primary: &str,
    proxy_port: u16,
    ui_port: u16,
) {
    panel_open(page, "desktop", platform);
    page.push_str("<ol>\n");

    page.push_str("<li><b>Send traffic through the proxy.</b> System wide on macOS: System Settings, Network, your connection, Details, Proxies, and set both the HTTP and HTTPS proxy to <code>");
    page.push_str(&escape(primary));
    page.push_str("</code> port <code>");
    page.push_str(&proxy_port.to_string());
    page.push_str(
        "</code>. For one terminal instead:<pre class=\"mono\">export HTTPS_PROXY=http://",
    );
    page.push_str(&escape(&url_host(primary)));
    page.push(':');
    page.push_str(&proxy_port.to_string());
    page.push_str("\nexport HTTP_PROXY=$HTTPS_PROXY</pre></li>\n");

    page.push_str("<li><b>Download the certificate</b> with the button below, then trust it.<div class=\"os\"><b>macOS</b><br>Double click <code>proxima-ca.crt</code>, add it to the <b>System</b> keychain, then open it in Keychain Access and set <b>Trust</b> to <b>Always Trust</b>.</div><div class=\"os\"><b>Windows</b><br>In an administrator prompt: <code>certutil -addstore -f Root proxima-ca.crt</code></div><div class=\"os\"><b>Linux</b><br><code>sudo cp proxima-ca.crt /usr/local/share/ca-certificates/</code><br><code>sudo update-ca-certificates</code><br>Firefox and Chrome keep their own stores and need it imported separately.</div></li>\n");

    page.push_str("<li><b>Or trust nothing at all</b> and point one command at it:<pre class=\"mono\">curl --proxy http://");
    page.push_str(&escape(&url_host(primary)));
    page.push(':');
    page.push_str(&proxy_port.to_string());
    page.push_str(" \\\n     --cacert proxima-ca.crt \\\n     https://example.com</pre></li>\n");

    page.push_str("<li><b>Watch the traffic</b> at <code>http://127.0.0.1:");
    page.push_str(&ui_port.to_string());
    page.push_str("</code> on this machine, or <code>http://");
    page.push_str(&escape(&url_host(primary)));
    page.push(':');
    page.push_str(&ui_port.to_string());
    page.push_str("</code> from anywhere on the network.</li>\n");

    page.push_str("</ol>\n</section>\n");
}

fn install_button(page: &mut String, platform: Platform) {
    let (href, label) = match platform {
        Platform::Ios => ("/cert.mobileconfig", "Install the Proxima profile"),
        _ => ("/cert", "Download the Proxima certificate"),
    };
    page.push_str("<a class=\"install\" id=\"install\" href=\"");
    page.push_str(href);
    page.push_str("\">");
    page.push_str(label);
    page.push_str("</a>\n");
}

fn check_card(page: &mut String) {
    page.push_str(
        r#"<section class="card">
  <h2>Check it works</h2>
  <p class="aside">This asks the device to fetch an HTTPS page and then asks Proxima whether it saw it. The device needs working internet for this.</p>
  <button type="button" class="btn" id="check">Check it works</button>
  <div class="result" id="result" hidden></div>
</section>
"#,
    );
}

fn certificate_card(page: &mut String, fingerprint: &str, expiry: &str) {
    page.push_str("<section class=\"card\">\n  <h2>What you are trusting</h2>\n");
    page.push_str(
        "  <div class=\"figure\"><span class=\"k\">SHA-256</span></div>\n  <div class=\"fp mono\">",
    );
    page.push_str(&escape(fingerprint));
    page.push_str("</div>\n");
    page.push_str("  <div class=\"figure\"><span class=\"k\">Expires</span><span class=\"v\">");
    page.push_str(&escape(expiry));
    page.push_str("</span></div>\n");
    page.push_str("  <p class=\"aside\">Compare that fingerprint with the one Proxima printed on the machine you are debugging from. They should match exactly. If they do not, something else is answering this page and you should stop.</p>\n");
    page.push_str("  <p class=\"aside\">While this certificate is trusted, whoever holds its private key can read this device's HTTPS traffic. Install it only on devices you control, and remove it when you are finished: on iOS delete the profile, on Android remove it under user credentials, on macOS delete it from Keychain Access.</p>\n");
    page.push_str("</section>\n");
}

fn footer(page: &mut String, primary: &str, ui_port: u16) {
    page.push_str("<footer>Traffic appears at <code>http://");
    page.push_str(&escape(&url_host(primary)));
    page.push(':');
    page.push_str(&ui_port.to_string());
    page.push_str("</code>. Apps that pin their certificates will refuse this one and show up here as failures rather than as readable traffic; that is expected, not a bug in the setup.</footer>\n");
}

fn config_json(
    platform: Platform,
    status: &ServerStatus,
    primary: &str,
    proxy_port: u16,
    ui_port: u16,
) -> String {
    let bases: Vec<String> = status
        .addresses
        .iter()
        .take(6)
        .map(|address| format!("http://{}:{}", url_host(address), ui_port))
        .collect();

    let value = serde_json::json!({
        "platform": platform.key(),
        "apiBases": bases,
        "proxyHost": primary,
        "proxyPort": proxy_port,
        "checkUrl": CHECK_URL,
        "checkHost": CHECK_HOST,
    });

    // A "</" inside the literal would end the script element early. Nothing we
    // put in here contains one today, and this makes sure it stays that way.
    serde_json::to_string(&value)
        .unwrap_or_else(|_| "{}".to_string())
        .replace("</", "<\\/")
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/* ------------------------------------------------------------------ */
/* assets, inlined because nothing external is reachable yet           */
/* ------------------------------------------------------------------ */

const CSS: &str = r#"
*, *::before, *::after { box-sizing: border-box; }
/* The same palette the inspector carries, written the same way: one name per
   colour, each naming both schemes. A phone opens this page in whichever scheme
   it is set to, and there is no switch here to correct a colour that was only
   ever checked against one background. */
:root {
  color-scheme: light dark;
  --bg: light-dark(#faf9f5, #262624);
  --card: light-dark(#f0eee6, #30302e);
  --line: light-dark(#e2dfd4, #3d3d3a);
  --ink: light-dark(#1f1e1d, #f0eee6);
  --dim: light-dark(#73716a, #a09d94);
  --accent: light-dark(#c96442, #d97757);
  --good: light-dark(#3d7f56, #7bc08d);
  --warn: light-dark(#a06c11, #e0b054);
  --bad: light-dark(#b3392c, #e58a7a);
  --field: light-dark(#ffffff, #1f1f1e);
  --pick: light-dark(#f7e8e2, #3b2f2a);
  --accent-ink: light-dark(#ffffff, #2a1207);
  --accent-down: light-dark(#a94f33, #c2653f);
  --btn: light-dark(#ffffff, #3a3a37);
  --btn-line: light-dark(#ddd9cd, #4b4b47);
  --btn-down: light-dark(#f2f0e8, #454541);
  --note-line: light-dark(#dfc48a, #6b5310);
  --note-bg: light-dark(#fbf3e2, #251d08);
  --note-ink: light-dark(#6b4e12, #f0dca4);
  --note-mark: light-dark(#8a6413, #ffd76a);
  --good-line: light-dark(#b6d6c2, #1f5b38);
  --good-bg: light-dark(#eef6f1, #0f1f16);
  --warn-line: light-dark(#e4cf9c, #6b5310);
  --warn-bg: light-dark(#fbf4e6, #241d08);
  --bad-line: light-dark(#e6c3bb, #6b3a30);
  --bad-bg: light-dark(#fbeeea, #2a1c18);
}
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 17px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  padding: 24px 18px calc(48px + env(safe-area-inset-bottom));
  max-width: 44rem; margin-inline: auto;
  -webkit-font-smoothing: antialiased;
}
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
header { margin-bottom: 22px; }
.mark { font-size: 12px; letter-spacing: .18em; color: var(--accent); font-weight: 700; }
h1 { font-size: 30px; line-height: 1.15; margin: 6px 0 10px; letter-spacing: -.02em; }
h2 { font-size: 19px; margin: 0 0 10px; }
.lede { color: var(--dim); margin: 0; }
.card {
  background: var(--card); border: 1px solid var(--line);
  border-radius: 14px; padding: 16px 18px; margin: 18px 0;
}
.figures { display: flex; flex-wrap: wrap; gap: 12px 32px; }
.figure { display: flex; flex-direction: column; gap: 2px; }
.k { font-size: 12px; letter-spacing: .08em; text-transform: uppercase; color: var(--dim); }
.v { font-size: 22px; }
.figures .aside { flex-basis: 100%; margin: 4px 0 0; }
.aside { color: var(--dim); font-size: 15px; margin: 10px 0 0; }
.fp {
  font-size: 13px; word-break: break-all; line-height: 1.7;
  color: var(--ink); background: var(--field); border: 1px solid var(--line);
  border-radius: 8px; padding: 10px 12px; margin: 6px 0 14px;
}
.tabs { display: flex; gap: 8px; margin: 22px 0 4px; }
.tab {
  flex: 1; min-height: 48px; padding: 0 10px;
  background: var(--card); color: var(--dim);
  border: 1px solid var(--line); border-radius: 11px;
  font: inherit; font-size: 15px; cursor: pointer;
}
.tab.on { color: var(--ink); border-color: var(--accent); background: var(--pick); }
.panel[hidden] { display: none; }
ol { padding-left: 1.35em; margin: 18px 0; }
ol > li { margin-bottom: 20px; padding-left: 4px; }
ol > li::marker { color: var(--accent); font-weight: 700; }
li.pivotal {
  background: var(--note-bg); border: 1px solid var(--note-line);
  border-radius: 12px; padding: 14px 14px 14px 8px; margin-left: -8px;
}
.path {
  margin: 8px 0; padding: 9px 11px; background: var(--field);
  border: 1px solid var(--line); border-radius: 8px;
  font-size: 15px; color: var(--ink);
}
.kv { display: flex; gap: 26px; margin: 10px 0; }
.kv .mono { font-size: 19px; display: block; }
.os { margin: 12px 0 0; color: var(--dim); font-size: 15px; }
.os b { color: var(--ink); }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .9em; background: var(--field); border: 1px solid var(--line);
  border-radius: 5px; padding: 1px 5px;
  /* break-word, not break-all: a host name should move to the next line whole
     rather than split down the middle of itself. */
  overflow-wrap: break-word;
}
pre {
  background: var(--field); border: 1px solid var(--line); border-radius: 9px;
  padding: 12px; margin: 10px 0 0; overflow-x: auto; font-size: 14px;
}
.install {
  display: flex; align-items: center; justify-content: center; text-align: center;
  min-height: 60px; margin: 26px 0; padding: 0 16px;
  background: var(--accent); color: var(--accent-ink); text-decoration: none;
  border-radius: 14px; font-size: 18px; font-weight: 650;
}
.install:active { background: var(--accent-down); }
.btn {
  width: 100%; min-height: 56px; font: inherit; font-size: 17px; font-weight: 600;
  background: var(--btn); color: var(--ink); border: 1px solid var(--btn-line);
  border-radius: 12px; cursor: pointer;
}
.btn:active { background: var(--btn-down); }
.btn[disabled] { opacity: .6; }
.result {
  margin-top: 14px; padding: 13px 14px; border-radius: 11px;
  border: 1px solid var(--line); background: var(--field); font-size: 16px;
}
.result.busy { color: var(--dim); }
.result.good { border-color: var(--good-line); background: var(--good-bg); color: var(--good); }
.result.warn { border-color: var(--warn-line); background: var(--warn-bg); color: var(--warn); }
.result.bad  { border-color: var(--bad-line); background: var(--bad-bg); color: var(--bad); }
.result .hint { display: block; margin-top: 6px; color: var(--dim); font-size: 15px; }
.warn {
  margin: 18px 0; padding: 14px; border-radius: 12px;
  border: 1px solid var(--note-line); background: var(--note-bg); color: var(--note-ink); font-size: 15px;
}
.warn b { color: var(--note-mark); }
footer { margin-top: 30px; color: var(--dim); font-size: 14px; }
"#;

const SCRIPT: &str = r#"
(function () {
  var apiBase = null;

  function byId(id) { return document.getElementById(id); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function selectTab(name) {
    var tabs = document.querySelectorAll('[data-tab]');
    for (var i = 0; i < tabs.length; i++) {
      var on = tabs[i].getAttribute('data-tab') === name;
      tabs[i].classList.toggle('on', on);
      tabs[i].setAttribute('aria-selected', on ? 'true' : 'false');
    }
    var panels = document.querySelectorAll('[data-panel]');
    for (var j = 0; j < panels.length; j++) {
      panels[j].hidden = panels[j].getAttribute('data-panel') !== name;
    }
    var install = byId('install');
    if (name === 'ios') {
      install.href = '/cert.mobileconfig';
      install.textContent = 'Install the Proxima profile';
    } else {
      install.href = '/cert';
      install.textContent = 'Download the Proxima certificate';
    }
  }

  var tabButtons = document.querySelectorAll('[data-tab]');
  for (var t = 0; t < tabButtons.length; t++) {
    tabButtons[t].addEventListener('click', function (event) {
      selectTab(event.currentTarget.getAttribute('data-tab'));
    });
  }

  // An iPad in desktop mode sends a Macintosh user agent, so the server cannot
  // tell them apart. Touch points can.
  if (PROXIMA.platform === 'desktop' &&
      /Macintosh/.test(navigator.userAgent) &&
      navigator.maxTouchPoints > 1) {
    selectTab('ios');
  }

  // Returns the number of matching flows, or null when Proxima is unreachable
  // from this device, which is itself a useful thing to know.
  async function total(query) {
    var bases = PROXIMA.apiBases.slice();
    if (apiBase) { bases.unshift(apiBase); }
    for (var i = 0; i < bases.length; i++) {
      try {
        var response = await fetch(bases[i] + '/api/flows?limit=1&' + query, { cache: 'no-store' });
        if (!response.ok) { continue; }
        var body = await response.json();
        apiBase = bases[i];
        return typeof body.total === 'number' ? body.total : 0;
      } catch (error) {
        // Try the next address this machine answers on.
      }
    }
    return null;
  }

  function report(kind, text, hint) {
    var box = byId('result');
    box.hidden = false;
    box.className = 'result ' + kind;
    box.textContent = text;
    if (hint) {
      var span = document.createElement('span');
      span.className = 'hint';
      span.textContent = hint;
      box.appendChild(span);
    }
  }

  async function check() {
    var button = byId('check');
    button.disabled = true;
    report('busy', 'Fetching an HTTPS page through the proxy...');

    var token = 'proximacheck' + Math.random().toString(16).slice(2) + Date.now().toString(16);
    var hostQuery = 'host=' + encodeURIComponent(PROXIMA.checkHost);
    var before = await total(hostQuery);

    // no-cors is enough: an opaque response still means the TLS handshake
    // through the proxy succeeded, which is the whole question.
    var tls = false;
    try {
      await fetch(PROXIMA.checkUrl + '?' + token, { mode: 'no-cors', cache: 'no-store' });
      tls = true;
    } catch (error) {
      tls = false;
    }

    var decrypted = 0;
    var seen = before;
    // Only worth polling if Proxima answered the first time. Otherwise this is
    // a dozen more connections to an address that is not listening.
    if (before !== null) {
      for (var attempt = 0; attempt < 6; attempt++) {
        await sleep(400);
        decrypted = await total('search=' + encodeURIComponent(token));
        seen = await total(hostQuery);
        if (decrypted) { break; }
      }
    }

    button.disabled = false;

    if (decrypted) {
      report('good', 'Working. Proxima read an HTTPS request from this device.',
        'Whatever you do on this device from now on shows up in the inspector.');
      return;
    }
    if (before === null || seen === null) {
      if (tls) {
        report('warn', 'HTTPS worked, but this page cannot reach the Proxima API to confirm it was captured.',
          'Look at the Proxima window: if a request to ' + PROXIMA.checkHost + ' just appeared, you are set up.');
      } else {
        report('bad', 'The HTTPS request failed and Proxima is unreachable from here.',
          'Check that the proxy is set to ' + PROXIMA.proxyHost + ' port ' + PROXIMA.proxyPort + ', and that this device has internet.');
      }
      return;
    }
    if (seen > before) {
      if (tls) {
        report('warn', 'The request reached Proxima but was not decrypted.',
          'It was tunnelled through untouched, which means ' + PROXIMA.checkHost + ' is on the skip list or decryption is off.');
      } else {
        report('bad', 'The request reached Proxima but TLS failed.',
          'That is the certificate. Install it, and on iOS also switch it on under Settings, General, About, Certificate Trust Settings.');
      }
      return;
    }
    if (tls) {
      report('bad', 'HTTPS worked, but nothing went through Proxima.',
        'The proxy is not set. Go back to step 1 and set it to ' + PROXIMA.proxyHost + ' port ' + PROXIMA.proxyPort + '.');
    } else {
      report('bad', 'Could not reach an HTTPS site, and nothing arrived at Proxima.',
        'Check the proxy host and port first, then that this device has internet.');
    }
  }

  byId('check').addEventListener('click', function () {
    check().catch(function (error) {
      report('bad', 'The check itself failed.', String(error));
      byId('check').disabled = false;
    });
  });
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agents_pick_a_platform() {
        assert_eq!(
            detect(Some(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
            )),
            Platform::Ios
        );
        assert_eq!(
            detect(Some("Mozilla/5.0 (iPad; CPU OS 16_0)")),
            Platform::Ios
        );
        assert_eq!(
            detect(Some("Mozilla/5.0 (Linux; Android 14; Pixel 8)")),
            Platform::Android
        );
        assert_eq!(
            detect(Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")),
            Platform::Desktop
        );
        // No user agent at all is a desktop tool of some kind.
        assert_eq!(detect(None), Platform::Desktop);
        assert_eq!(detect(Some("curl/8.4.0")), Platform::Desktop);
    }

    #[test]
    fn html_escaping_covers_the_dangerous_characters() {
        assert_eq!(escape("a&b"), "a&amp;b");
        assert_eq!(escape("<script>"), "&lt;script&gt;");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape("it's"), "it&#39;s");
    }

    #[test]
    fn the_page_never_reaches_off_device() {
        // Every asset has to be inline: this page loads before any certificate
        // is trusted, and before the device knows Proxima exists.
        for fragment in ["src=\"http", "href=\"http", "@import", "//cdn", "fonts."] {
            assert!(
                !CSS.contains(fragment) && !SCRIPT.contains(fragment),
                "the setup page must not reference {fragment}"
            );
        }
    }
}
