//! WireGuard tunnel trait stub.
//!
//! A real implementation would run Noise_IK, track peers, and decrypt outer
//! WG frames into inner IP packets. P9 only defines the surface and returns
//! a clear not-implemented error so call sites can be written ahead of crypto.

use anyhow::{bail, Result};

/// Userspace WireGuard tunnel (crypto not shipped).
///
/// Implementations must never log private keys or handshake payloads.
pub trait WireGuardTunnel: Send + Sync {
    /// Accept one outer UDP datagram from a peer and, when crypto exists,
    /// yield zero or more decrypted inner IP packets.
    ///
    /// P9 default: always errors with not-implemented. Callers must not treat
    /// success as a working tunnel.
    fn open_packet(&self, outer_datagram: &[u8]) -> Result<Vec<Vec<u8>>>;
}

/// Placeholder tunnel used by the scaffold listen path.
///
/// Exists so the trait is exercised without shipping a crypto crate.
#[derive(Debug, Default, Clone, Copy)]
pub struct NotImplementedTunnel;

impl WireGuardTunnel for NotImplementedTunnel {
    fn open_packet(&self, _outer_datagram: &[u8]) -> Result<Vec<Vec<u8>>> {
        bail!(
            "WireGuard crypto is not implemented in this build (scaffold only). \
             Rebuild guidance does not apply here: the feature enables the listen \
             module, not Noise/WG. A working device tunnel is not shipped."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_packet_is_honestly_not_implemented() {
        let tunnel = NotImplementedTunnel;
        let err = tunnel
            .open_packet(&[0u8; 32])
            .expect_err("scaffold must not pretend to decrypt");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not implemented") || msg.contains("not shipped"),
            "error must say crypto is absent: {msg}"
        );
    }
}
