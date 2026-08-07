//! Proxima: an HTTPS interception proxy and API client.
//!
//! The pieces fit together like this:
//!
//! - [`ca`] mints the certificates that let us read TLS.
//! - [`capture`] holds captured traffic and broadcasts live events.
//! - [`proxy`] is the port the phone points at (TCP; never sees QUIC).
//! - [`api`] serves the inspector UI, the REST API and the device setup page.
//! - [`replay`] re-sends captured requests and composes new ones.
//! - `quic` (optional `--features quic`): HTTP/3 reverse/MITM over UDP. The
//!   regular TCP proxy path cannot observe or invent QUIC traffic.
//! - `wireguard` (optional `--features wireguard`): userspace device-join
//!   scaffold (UDP bind + trait stubs). Noise/WG crypto is not shipped; phone
//!   Wi-Fi HTTP proxy settings never feed this path.
//! - `tun` (optional `--features tun`): local TUN / packet-capture scaffold
//!   (no device open). Not a working host capture path; see module docs for
//!   macOS/Linux limits.

pub mod api;
pub mod ca;
pub mod capture;
pub mod config;
pub mod proxy;
pub mod replay;
pub mod runtime;
pub mod types;

#[cfg(feature = "gui")]
pub mod gui;

/// QUIC / HTTP/3 over UDP (bind, TLS MITM with the same CA, reverse H3).
///
/// Compiled only with `--features quic`. Without that feature the binary has no
/// quinn/h3 cost; runtime refuses QUIC bind flags with rebuild guidance.
///
/// Public entry points live on the module root (`bind_udp`, `QuicServer`,
/// `server_crypto`, `client_crypto`, `spawn`, `codes`, ...). The classic TCP
/// proxy under [`proxy`] never observes QUIC.
#[cfg(feature = "quic")]
pub mod quic;

/// WireGuard userspace device-join scaffold (UDP bind, demux/tunnel stubs).
///
/// Compiled only with `--features wireguard`. Config/CLI/status fields for WG
/// are always present; without this feature, requesting a WG listener fails
/// with rebuild guidance. Crypto and a working phone tunnel are not shipped.
#[cfg(feature = "wireguard")]
pub mod wireguard;

/// Local TUN / packet-capture scaffold (no device open).
///
/// Compiled only with `--features tun`. Config/CLI/status fields for TUN are
/// always present; without this feature, requesting TUN mode fails with
/// rebuild guidance. Does not open utun or `/dev/net/tun`.
#[cfg(feature = "tun")]
pub mod tun;

pub use config::Config;

#[cfg(test)]
mod feature_gate_tests {
    /// Config knobs for TUN always compile; the serve module is feature-gated.
    #[test]
    fn tun_config_knobs_always_available() {
        let cfg = crate::Config::default();
        assert!(!cfg.tun);
        assert!(!cfg.wants_tun());
        assert_eq!(
            crate::config::tun_feature_enabled(),
            cfg!(feature = "tun")
        );
    }

    /// Prove `--features tun` links the scaffold module (compile-gated).
    #[cfg(feature = "tun")]
    #[test]
    fn tun_module_linked_when_feature_on() {
        use crate::tun::TunDevice;

        let note = crate::tun::platform_support_note();
        assert!(
            note.contains("macOS") || note.contains("utun") || note.contains("Linux"),
            "linked platform note: {note}"
        );
        // Trait stub is callable and never succeeds as a real device.
        let device = crate::tun::NotImplementedDevice;
        assert!(device.open().is_err());
        assert!(device.read_packet().is_err());
    }
}

/// P11 docs honesty: README and PLANS claims must stay aligned with shipped
/// behaviour (TCP never sees QUIC; no Alt-Svc helper; WS inject API surface).
#[cfg(test)]
mod p11_docs_honesty_tests {
    const README: &str = include_str!("../README.md");
    const PLANS: &str = include_str!("../PLANS.md");

    #[test]
    fn readme_and_plans_forbid_em_dash() {
        // Project text rule: never U+2014. A regression here is usually a
        // paste from a word processor into operator docs.
        assert!(
            !README.contains('\u{2014}'),
            "README.md must not contain an em dash (U+2014)"
        );
        assert!(
            !PLANS.contains('\u{2014}'),
            "PLANS.md must not contain an em dash (U+2014)"
        );
    }

    #[test]
    fn readme_states_tcp_proxy_never_sees_quic() {
        assert!(
            README.contains("UDP/QUIC never arrives on")
                || README.contains("never invents H3")
                || README.contains("cannot see QUIC"),
            "README must keep TCP --port honesty about QUIC/UDP"
        );
        assert!(
            README.contains("TCP CONNECT only") || README.contains("TCP CONNECT"),
            "README must say phone system-proxy is TCP CONNECT only"
        );
        assert!(
            README.contains("WireGuard or TUN") || README.contains("WireGuard") && README.contains("TUN"),
            "README must point phone QUIC path at WG/TUN (not shipped as a tunnel)"
        );
    }

    #[test]
    fn readme_documents_force_tcp_tips_without_product_helper() {
        assert!(
            README.contains("Force-TCP operator tips")
                || README.contains("force-TCP")
                || README.contains("Force the browser onto TCP"),
            "README must document force-TCP operator tips"
        );
        assert!(
            README.contains("No built-in Alt-Svc strip")
                || README.contains("no Alt-Svc"),
            "README must state Proxima has no Alt-Svc strip helper"
        );
        assert!(
            README.contains("client force-TCP flag")
                || README.contains("force-TCP flag")
                || README.contains("No Alt-Svc helper"),
            "README must not invent a client force-TCP product flag"
        );
        assert!(
            README.contains("--no-http2") && README.contains("upstream"),
            "README must keep --no-http2 as upstream-only"
        );
    }

    #[test]
    fn readme_chrome_user_ca_is_not_pure_pinning_proof() {
        assert!(
            README.contains("user-CA") || README.contains("user-installed CA"),
            "README must name Chrome user-CA QUIC limits"
        );
        assert!(
            README.contains("pure app pinning")
                || README.contains("not only app pinning")
                || README.contains("proof of app pinning"),
            "README must say quic_cert_reject/likely_pinning is not pure pinning proof"
        );
        assert!(
            README.contains("quic_cert_reject") && README.contains("likely_pinning"),
            "README must name quic_cert_reject and likely_pinning together"
        );
    }

    #[test]
    fn readme_ws_inject_api_matches_shipped_routes() {
        assert!(
            README.contains("POST /api/flows/{id}/ws/send"),
            "README must document ws/send"
        );
        assert!(
            README.contains("POST /api/flows/{id}/ws/replay"),
            "README must document ws/replay"
        );
        for field in [
            "direction",
            "opcode",
            "dataBase64",
            "closeCode",
            "closeReason",
            "targetFlowId",
            "delayMs",
            "stopOnError",
            "maxFrames",
        ] {
            assert!(
                README.contains(field),
                "README ws API docs must name camelCase field {field}"
            );
        }
        assert!(
            README.contains("skips rewrite rules and breakpoints")
                || README.contains("skips rewrite") && README.contains("breakpoints"),
            "README must state inject skips rewrite and breakpoints"
        );
        assert!(
            README.contains("compose")
                && (README.contains("\"compose\"") || README.contains("mode: \"compose\"")),
            "README must document compose mode"
        );
        assert!(
            README.contains("drop marker") || README.contains("drop markers"),
            "README must document drop-marker fail-closed limits"
        );
        assert!(
            README.contains("uncompressed"),
            "README must document deflate uncompressed replay"
        );
        // Status codes from the API sketch (200 / 400 / 404 / 409 / 502 for compose dial).
        for code in ["**200**", "**400**", "**404**", "**409**"] {
            assert!(
                README.contains(code),
                "README ws API must document status {code}"
            );
        }
        assert!(
            README.contains("**502**") || README.contains("502"),
            "README must document compose dial failure as 502"
        );
    }

    #[test]
    fn plans_interim_honesty_aligns_with_readme() {
        assert!(
            PLANS.contains("invisible on the default TCP proxy")
                || PLANS.contains("never invents H3"),
            "PLANS Interim honesty must keep TCP/QUIC visibility clear"
        );
        assert!(
            PLANS.contains("not pure app-pinning proof")
                || PLANS.contains("not pure pinning"),
            "PLANS must not treat likely_pinning as pure pinning proof"
        );
        assert!(
            PLANS.contains("No Alt-Svc helper") || PLANS.contains("no Alt-Svc"),
            "PLANS must keep Alt-Svc helper as not built"
        );
        assert!(
            PLANS.contains("ws/send") && PLANS.contains("ws/replay"),
            "PLANS must reference shipped inject/replay API docs"
        );
        assert!(
            PLANS.contains("compose") || PLANS.contains("Compose mode"),
            "PLANS must reference WebSocket compose replay"
        );
    }
}
