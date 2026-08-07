//! Platform notes for local TUN / packet capture (docs only in P10).
//!
//! A real capture path would open a virtual interface or use OS packet filter
//! APIs. This module only returns honest strings for status, banner, and tests.
//! It never opens `utun`, `/dev/net/tun`, or any Network Extension.

/// Short multi-line platform support note for operators and status.
///
/// Covers macOS and Linux only. Windows capture is not claimed and is not
/// part of this scaffold.
pub fn platform_support_note() -> &'static str {
    "Local TUN / packet-capture scaffold (no device open). \
     macOS: a real path would use utun and/or Network Extension; there is no \
     TPROXY-style redirect on Darwin. \
     Linux: a real path would use /dev/net/tun and typically CAP_NET_ADMIN \
     (and often policy routing). \
     Windows host capture is not supported or claimed in this scaffold. \
     This mode never invents HTTP/CONNECT/H3 flows."
}

/// One-line note suitable for `ServerStatus.tun_note` when the feature is on.
pub fn short_status_note(active: bool) -> String {
    if active {
        "TUN scaffold task is running (shutdown watch only; no utun//dev/net/tun open; \
         no packet capture). macOS: utun/Network Extension (no TPROXY). \
         Linux: /dev/net/tun + CAP_NET_ADMIN. Not a working capture path."
            .to_string()
    } else {
        "TUN scaffold is compiled in but not requested. \
         macOS/Linux capture is not shipped; no Windows capture claim. \
         Use --tun or --mode tun to start the no-op scaffold task."
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_note_covers_macos_and_linux_not_windows_capture() {
        let note = platform_support_note();
        assert!(
            note.contains("macOS") || note.contains("utun"),
            "must document Darwin limits: {note}"
        );
        assert!(
            note.contains("Linux") || note.contains("/dev/net/tun"),
            "must document Linux limits: {note}"
        );
        assert!(
            note.contains("CAP_NET_ADMIN") || note.contains("net/tun"),
            "must mention Linux privilege/device: {note}"
        );
        assert!(
            note.contains("not supported") || note.contains("not claimed") || note.contains("Windows"),
            "must not claim Windows capture works: {note}"
        );
        assert!(
            !note.to_ascii_lowercase().contains("working capture")
                || note.contains("never")
                || note.contains("no device"),
            "must not imply live host capture: {note}"
        );
    }

    #[test]
    fn short_status_note_distinguishes_active() {
        let on = short_status_note(true);
        assert!(on.contains("scaffold") || on.contains("no-op") || on.contains("watch"));
        assert!(on.contains("no") || on.contains("not"));
        let off = short_status_note(false);
        assert!(off.contains("not requested") || off.contains("compiled"));
    }
}
