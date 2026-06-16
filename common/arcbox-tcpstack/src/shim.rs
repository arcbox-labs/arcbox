//! L3 ↔ L2 shim for running the L2 classifier / TCP shim over an L3 link.
//!
//! The classifier and [`TcpBridge`](crate::tcp_bridge) assume Ethernet framing
//! (ARP, a gateway+guest MAC). A host `utun` is an L3 link that carries bare IP
//! packets with no L2 header. This shim bridges the gap:
//!
//! - [`L3ToL2Source`] wraps an L3 [`FrameSource`] (IP packets) so the
//!   classifier sees Ethernet frames — each IP packet is prefixed with a fixed
//!   synthetic Ethernet header.
//! - [`l2_to_l3`] is the egress filter: it strips the synthetic Ethernet header
//!   from a frame the datapath wants to send "to the guest", yielding the IP
//!   packet to write back to the `utun`. ARP and other non-IPv4 frames have no
//!   meaning on an L3 link and are dropped.
//!
//! There is no real L2 on a `utun`, so the MACs are fixed constants and ARP is
//! never emitted upstream.

use std::os::fd::RawFd;

use arcbox_packet::ethernet::{ETH_HEADER_LEN, EtherType, EthernetHeader, strip_ethernet_header};

use crate::frame_source::FrameSource;

/// Synthetic gateway MAC — the source of host → "guest" frames on the L3 link.
pub const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Synthetic host MAC — the "guest" side of the L3 link (the utun peer).
pub const HOST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Wraps an L3 [`FrameSource`] so the L2 classifier sees Ethernet frames.
///
/// Each inbound IP packet from `inner` is prefixed with a synthetic Ethernet
/// header (`HOST_MAC` → `GATEWAY_MAC`, EtherType IPv4) into an internal buffer
/// before being handed to the classifier. Non-IPv4 packets are dropped (a
/// `utun` only carries IP; IPv6 is out of scope for this shim).
pub struct L3ToL2Source<S: FrameSource> {
    inner: S,
    /// Synthetic Ethernet header (`HOST_MAC` → `GATEWAY_MAC`, IPv4), built once.
    header: [u8; ETH_HEADER_LEN],
    /// Reused frame buffer: synthetic Ethernet header + IP packet.
    buf: Vec<u8>,
}

impl<S: FrameSource> L3ToL2Source<S> {
    /// Wraps an L3 frame source.
    #[must_use]
    pub fn new(inner: S) -> Self {
        let header = EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: HOST_MAC,
            ethertype: EtherType::Ipv4,
        }
        .to_bytes();
        Self {
            inner,
            header,
            buf: vec![0u8; ETH_HEADER_LEN + 65535],
        }
    }

    /// Returns a reference to the wrapped L3 source.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: FrameSource> FrameSource for L3ToL2Source<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    fn drain(&mut self, mut f: impl FnMut(&[u8])) {
        // Snapshot the constant header, then split the borrow so the inner
        // source and the scratch buffer can be used together in the closure.
        let header = self.header;
        let Self { inner, buf, .. } = self;
        inner.drain(|ip_packet| {
            // Only IPv4 (version nibble == 4); drop everything else.
            if ip_packet.is_empty() || (ip_packet[0] >> 4) != 4 {
                return;
            }
            let total = ETH_HEADER_LEN + ip_packet.len();
            if total > buf.len() {
                return;
            }
            buf[..ETH_HEADER_LEN].copy_from_slice(&header);
            buf[ETH_HEADER_LEN..total].copy_from_slice(ip_packet);
            f(&buf[..total]);
        });
    }
}

/// Egress filter: strips the synthetic Ethernet header from an L2 frame
/// destined for the "guest", returning the IP packet to write to the `utun`.
///
/// Returns `None` for frames that have no L3 meaning — ARP replies the
/// classifier may synthesize, or any non-IPv4 EtherType.
#[must_use]
pub fn l2_to_l3(frame: &[u8]) -> Option<&[u8]> {
    if EthernetHeader::parse(frame)?.ethertype != EtherType::Ipv4 {
        return None;
    }
    Some(strip_ethernet_header(frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_source::FrameSource;

    /// A [`FrameSource`] that replays a fixed list of IP packets once.
    struct VecSource {
        packets: Vec<Vec<u8>>,
    }

    impl FrameSource for VecSource {
        fn as_raw_fd(&self) -> RawFd {
            -1
        }
        fn drain(&mut self, mut f: impl FnMut(&[u8])) {
            for p in self.packets.drain(..) {
                f(&p);
            }
        }
    }

    /// Minimal IPv4 packet (20-byte header, version=4) with the given protocol.
    fn ipv4_packet(proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p[9] = proto;
        p
    }

    #[test]
    fn wraps_ipv4_with_synthetic_ethernet_header() {
        let mut src = L3ToL2Source::new(VecSource {
            packets: vec![ipv4_packet(6)],
        });
        let mut frames: Vec<Vec<u8>> = Vec::new();
        src.drain(|f| frames.push(f.to_vec()));

        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert_eq!(frame.len(), ETH_HEADER_LEN + 20);
        assert_eq!(&frame[0..6], &GATEWAY_MAC);
        assert_eq!(&frame[6..12], &HOST_MAC);
        assert_eq!(&frame[12..14], &EtherType::Ipv4.to_raw().to_be_bytes());
        // The IP packet survives intact after the header.
        assert_eq!(frame[ETH_HEADER_LEN], 0x45);
    }

    #[test]
    fn drops_non_ipv4_l3_packets() {
        // A packet whose first nibble is 6 (IPv6) must be dropped.
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        let mut src = L3ToL2Source::new(VecSource { packets: vec![p] });
        let mut count = 0;
        src.drain(|_| count += 1);
        assert_eq!(count, 0, "IPv6 must not be wrapped");
    }

    #[test]
    fn l2_to_l3_strips_header_for_ipv4() {
        let mut frame = vec![0u8; ETH_HEADER_LEN + 20];
        frame[12..14].copy_from_slice(&EtherType::Ipv4.to_raw().to_be_bytes());
        frame[ETH_HEADER_LEN] = 0x45;
        let ip = l2_to_l3(&frame).expect("IPv4 frame should yield an IP packet");
        assert_eq!(ip.len(), 20);
        assert_eq!(ip[0], 0x45);
    }

    #[test]
    fn l2_to_l3_drops_arp() {
        let mut frame = vec![0u8; ETH_HEADER_LEN + 28];
        frame[12..14].copy_from_slice(&[0x08, 0x06]); // ARP
        assert!(l2_to_l3(&frame).is_none(), "ARP has no L3 representation");
    }
}
