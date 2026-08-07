//! Inner IP packet classification after WireGuard decryption.
//!
//! Userspace TCP reassembly is out of scope. This module only peeks at IPv4
//! headers enough to label UDP vs TCP vs other, so a later QUIC handoff can
//! take UDP datagrams without inventing a full network stack.
//!
//! The outer WireGuard UDP framing is not handled here: callers pass
//! **decrypted inner** IP packets (or test fixtures that look like them).

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;

use anyhow::{bail, Result};

/// Result of classifying one inner IP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemuxedPacket {
    /// IPv4 UDP; payload is the UDP data (not including IP/UDP headers).
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: Vec<u8>,
    },
    /// IPv4 TCP; payload is the TCP segment body (no stream reassembly).
    Tcp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: Vec<u8>,
    },
    /// Non-IPv4, truncated, or a protocol we do not classify yet.
    Other {
        /// IPv4 protocol number when the IP header was readable; otherwise None.
        protocol: Option<u8>,
        /// Total raw length of the buffer we were given.
        len: usize,
    },
}

/// Boxed future returned by [`UdpIngress`] (object-safe async hook).
pub type UdpIngressFut<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Hook for demuxed inner UDP (future QUIC/H3 ingress).
///
/// P9 keeps this free of quinn types. A later adapter behind
/// `--features quic,wireguard` can implement this trait and feed the H3 path
/// without changing the trait shape defined here.
///
/// Boxed futures so the trait stays object-safe (`Arc<dyn UdpIngress>` on
/// [`super::WgDeps`]).
pub trait UdpIngress: Send + Sync {
    /// Deliver one demuxed UDP datagram that arrived via the WG tunnel.
    fn push_udp<'a>(
        &'a self,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &'a [u8],
    ) -> UdpIngressFut<'a>;
}

/// Default ingress: accept and discard.
///
/// Used until a dual-feature adapter wires demuxed UDP into QUIC.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullUdpIngress;

impl UdpIngress for NullUdpIngress {
    fn push_udp<'a>(
        &'a self,
        _src: SocketAddr,
        _dst: SocketAddr,
        _payload: &'a [u8],
    ) -> UdpIngressFut<'a> {
        Box::pin(async move { Ok(()) })
    }
}

/// Classify a single inner IP packet (IPv4 only in P9).
///
/// Returns [`DemuxedPacket::Other`] for short buffers, non-IPv4, or protocols
/// other than TCP/UDP. Does not validate checksums.
pub fn demux_ip_packet(packet: &[u8]) -> DemuxedPacket {
    if packet.len() < 20 {
        return DemuxedPacket::Other {
            protocol: None,
            len: packet.len(),
        };
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return DemuxedPacket::Other {
            protocol: None,
            len: packet.len(),
        };
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return DemuxedPacket::Other {
            protocol: None,
            len: packet.len(),
        };
    }
    let protocol = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let l4 = &packet[ihl..];

    match protocol {
        17 => match parse_udp(src_ip, dst_ip, l4) {
            Ok(pkt) => pkt,
            Err(_) => DemuxedPacket::Other {
                protocol: Some(17),
                len: packet.len(),
            },
        },
        6 => match parse_tcp(src_ip, dst_ip, l4) {
            Ok(pkt) => pkt,
            Err(_) => DemuxedPacket::Other {
                protocol: Some(6),
                len: packet.len(),
            },
        },
        other => DemuxedPacket::Other {
            protocol: Some(other),
            len: packet.len(),
        },
    }
}

fn parse_udp(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, l4: &[u8]) -> Result<DemuxedPacket> {
    if l4.len() < 8 {
        bail!("UDP header truncated");
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let length = u16::from_be_bytes([l4[4], l4[5]]) as usize;
    // Prefer declared length when it fits; otherwise take remaining bytes.
    let payload_end = if length >= 8 && length <= l4.len() {
        length
    } else {
        l4.len()
    };
    let payload = l4[8..payload_end].to_vec();
    Ok(DemuxedPacket::Udp {
        src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
        dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
        payload,
    })
}

fn parse_tcp(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, l4: &[u8]) -> Result<DemuxedPacket> {
    if l4.len() < 20 {
        bail!("TCP header truncated");
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let data_offset = ((l4[12] >> 4) as usize) * 4;
    if data_offset < 20 || l4.len() < data_offset {
        bail!("TCP data offset invalid");
    }
    let payload = l4[data_offset..].to_vec();
    Ok(DemuxedPacket::Tcp {
        src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
        dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
        payload,
    })
}

/// Build a minimal IPv4+UDP (or TCP) buffer for unit tests.
#[cfg(test)]
fn sample_ipv4(protocol: u8, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    // IPv4 header: version/IHL, TOS, total length, id, flags, ttl, proto, checksum, src, dst
    let l4_len = if protocol == 17 {
        8 + payload.len()
    } else {
        20 + payload.len()
    };
    let total = 20 + l4_len;
    pkt.push(0x45); // v4, IHL=5
    pkt.push(0);
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // id
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    pkt.push(64); // ttl
    pkt.push(protocol);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    if protocol == 17 {
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(payload);
    } else if protocol == 6 {
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // seq
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
        pkt.push(0x50); // data offset 5 (20 bytes)
        pkt.push(0);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // window
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent
        pkt.extend_from_slice(payload);
    }
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demux_classifies_sample_ipv4_udp() {
        let pkt = sample_ipv4(17, 12345, 443, b"hello");
        match demux_ip_packet(&pkt) {
            DemuxedPacket::Udp { src, dst, payload } => {
                assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(src.port(), 12345);
                assert_eq!(dst.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
                assert_eq!(dst.port(), 443);
                assert_eq!(payload, b"hello");
            }
            other => panic!("expected Udp, got {other:?}"),
        }
    }

    #[test]
    fn demux_classifies_sample_ipv4_tcp() {
        let pkt = sample_ipv4(6, 54321, 443, b"GET /");
        match demux_ip_packet(&pkt) {
            DemuxedPacket::Tcp { src, dst, payload } => {
                assert_eq!(src.port(), 54321);
                assert_eq!(dst.port(), 443);
                assert_eq!(payload, b"GET /");
            }
            other => panic!("expected Tcp, got {other:?}"),
        }
    }

    #[test]
    fn demux_other_for_short_and_non_ipv4() {
        assert!(matches!(
            demux_ip_packet(&[1, 2, 3]),
            DemuxedPacket::Other { protocol: None, len: 3 }
        ));
        // IPv6 version nibble
        let mut v6 = vec![0x60; 40];
        assert!(matches!(
            demux_ip_packet(&v6),
            DemuxedPacket::Other { protocol: None, .. }
        ));
        let _ = &mut v6;
    }

    #[tokio::test]
    async fn null_udp_ingress_is_default_hook() {
        let ingress = NullUdpIngress;
        let src = "10.0.0.1:1".parse().unwrap();
        let dst = "10.0.0.2:443".parse().unwrap();
        ingress
            .push_udp(src, dst, b"x")
            .await
            .expect("null ingress accepts");
    }

    #[test]
    fn demux_icmp_and_unknown_protocol_are_other() {
        let icmp = sample_ipv4(1, 0, 0, b"");
        // sample_ipv4 only builds L4 for TCP/UDP; still has IPv4 header + empty L4.
        match demux_ip_packet(&icmp) {
            DemuxedPacket::Other {
                protocol: Some(1),
                ..
            } => {}
            other => panic!("expected ICMP Other, got {other:?}"),
        }
        let unknown = sample_ipv4(99, 1, 2, b"x");
        match demux_ip_packet(&unknown) {
            DemuxedPacket::Other {
                protocol: Some(99),
                ..
            } => {}
            other => panic!("expected proto 99 Other, got {other:?}"),
        }
    }

    #[test]
    fn demux_truncated_udp_and_tcp_are_other() {
        // Full IPv4 header claiming UDP, but fewer than 8 L4 bytes.
        let mut short_udp = sample_ipv4(17, 1, 2, b"");
        short_udp.truncate(20 + 4);
        assert!(
            matches!(
                demux_ip_packet(&short_udp),
                DemuxedPacket::Other {
                    protocol: Some(17),
                    ..
                }
            ),
            "truncated UDP must not invent a datagram"
        );

        let mut short_tcp = sample_ipv4(6, 1, 2, b"");
        short_tcp.truncate(20 + 10);
        assert!(
            matches!(
                demux_ip_packet(&short_tcp),
                DemuxedPacket::Other {
                    protocol: Some(6),
                    ..
                }
            ),
            "truncated TCP must not invent a segment"
        );
    }

    #[test]
    fn demux_udp_empty_payload_is_still_udp() {
        let pkt = sample_ipv4(17, 9, 53, b"");
        match demux_ip_packet(&pkt) {
            DemuxedPacket::Udp { payload, dst, .. } => {
                assert!(payload.is_empty());
                assert_eq!(dst.port(), 53);
            }
            other => panic!("expected empty-payload Udp, got {other:?}"),
        }
    }
}
