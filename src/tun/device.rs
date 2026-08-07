//! TUN device trait stub.
//!
//! A real implementation would open a virtual interface (macOS `utun`, Linux
//! `/dev/net/tun`), configure addresses/routes, and yield raw IP packets. P10
//! only defines the surface and returns a clear not-implemented error so call
//! sites can be written ahead of OS glue.
//!
//! **Never open a real device in the scaffold.** [`NotImplementedDevice`] always
//! bails; the serve path does not call `open` either.

use anyhow::{bail, Result};

/// Local TUN / virtual interface (capture not shipped).
///
/// Implementations must not claim success as live host packet capture.
pub trait TunDevice: Send + Sync {
    /// Open the virtual interface (or attach to an existing one).
    ///
    /// P10 default: always errors with not-implemented.
    fn open(&self) -> Result<()>;

    /// Read one raw IP packet from the device when open.
    ///
    /// P10 default: always errors. Callers must not invent HTTP/CONNECT/H3
    /// flows from a successful read that never happens here.
    fn read_packet(&self) -> Result<Vec<u8>>;
}

/// Placeholder device used to exercise the trait without OS privileges.
#[derive(Debug, Default, Clone, Copy)]
pub struct NotImplementedDevice;

impl TunDevice for NotImplementedDevice {
    fn open(&self) -> Result<()> {
        bail!(
            "TUN device open is not implemented in this build (scaffold only). \
             The --features tun gate enables the serve module, not utun or \
             /dev/net/tun. A working local capture path is not shipped."
        );
    }

    fn read_packet(&self) -> Result<Vec<u8>> {
        bail!(
            "TUN packet read is not implemented in this build (scaffold only). \
             No virtual interface is open; no packets are captured."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_read_are_honestly_not_implemented() {
        let device = NotImplementedDevice;
        let open_err = device
            .open()
            .expect_err("scaffold must not open a real device");
        let open_msg = format!("{open_err:#}");
        assert!(
            open_msg.contains("not implemented") || open_msg.contains("not shipped"),
            "open error must say capture is absent: {open_msg}"
        );
        assert!(
            open_msg.contains("utun")
                || open_msg.contains("/dev/net/tun")
                || open_msg.contains("scaffold"),
            "open error should name the missing device path: {open_msg}"
        );

        let read_err = device
            .read_packet()
            .expect_err("scaffold must not pretend to read packets");
        let read_msg = format!("{read_err:#}");
        assert!(
            read_msg.contains("not implemented") || read_msg.contains("not shipped"),
            "read error must say capture is absent: {read_msg}"
        );
        assert!(
            read_msg.contains("No virtual interface")
                || read_msg.contains("no packets")
                || read_msg.contains("not"),
            "read error must not imply packets were produced: {read_msg}"
        );
    }
}
