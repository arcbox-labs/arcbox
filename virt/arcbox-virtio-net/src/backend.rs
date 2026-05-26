//! `NetBackend` trait + the cross-platform `LoopbackBackend`.

use std::collections::VecDeque;

use crate::header::NetPacket;

/// Which offload features the guest has negotiated — passed to the backend
/// after feature acknowledgement so it can configure the host side to match.
///
/// For a TAP-based backend this is translated into the kernel's `TUN_F_*`
/// bitmask; for userspace backends it's typically a no-op. We keep the
/// shape abstract rather than leaking Linux constants into the trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetOffloadFlags {
    /// Guest can receive partial checksums — host may stamp
    /// `CSUM_PARTIAL`-style frames.
    pub csum: bool,
    /// Guest accepts TCPv4 segmentation offload.
    pub tso4: bool,
    /// Guest accepts TCPv6 segmentation offload.
    pub tso6: bool,
    /// Guest accepts TSO with ECN.
    pub tso_ecn: bool,
    /// Guest accepts UDP fragmentation offload.
    pub ufo: bool,
}

/// Network backend trait.
pub trait NetBackend: Send + Sync {
    /// Sends a packet.
    fn send(&mut self, packet: &NetPacket) -> std::io::Result<usize>;

    /// Sends a TSO/GSO packet.
    ///
    /// Called when the guest emits a packet with `gso_type != GSO_NONE`.
    /// The packet contains a large payload that the guest expects the device
    /// to segment (or relay as-is if the host stack handles it).
    ///
    /// The default implementation ignores the GSO header and forwards the
    /// packet via `send()`. Backends that can exploit TSO (e.g. writing
    /// directly to a host `TcpStream`) should override this.
    fn send_tso(&mut self, packet: &NetPacket) -> std::io::Result<usize> {
        self.send(packet)
    }

    /// Receives a packet.
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Returns whether packets are available to receive.
    fn has_data(&self) -> bool;

    /// Returns whether this backend supports TSO offload.
    ///
    /// When true, the device advertises `GUEST_TSO4/6` and `HOST_TSO4/6`
    /// features to the guest, and routes TSO packets through `send_tso()`.
    fn supports_tso(&self) -> bool {
        false
    }

    /// Configure host-side offload to match the features the guest negotiated.
    ///
    /// Call from the device's `activate()` hook after `ack_features`. The
    /// flags come from the guest's acknowledged `GUEST_*` feature bits — the
    /// backend is free to translate (e.g. TAP translates to `TUN_F_*`) or
    /// ignore. Default is no-op so non-kernel backends don't need to care.
    fn configure_offload(&mut self, flags: NetOffloadFlags) -> std::io::Result<()> {
        let _ = flags;
        Ok(())
    }

    /// Configure the size of the `virtio_net_hdr` prepended to each frame on
    /// the backend's wire representation.
    ///
    /// For TAP, this must match the guest's view of the header
    /// (`sizeof(virtio_net_hdr_v1)` = 12 bytes when `MRG_RXBUF` or any of
    /// the modern flags are negotiated; 10 bytes on legacy). Default no-op.
    fn set_vnet_hdr_sz(&mut self, size: u32) -> std::io::Result<()> {
        let _ = size;
        Ok(())
    }
}

/// Loopback network backend for testing.
pub struct LoopbackBackend {
    /// Packet queue.
    packets: VecDeque<Vec<u8>>,
}

impl LoopbackBackend {
    /// Creates a new loopback backend.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packets: VecDeque::new(),
        }
    }
}

impl Default for LoopbackBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NetBackend for LoopbackBackend {
    fn send(&mut self, packet: &NetPacket) -> std::io::Result<usize> {
        self.packets.push_back(packet.data.clone());
        Ok(packet.data.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(packet) = self.packets.pop_front() {
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        } else {
            Ok(0)
        }
    }

    fn has_data(&self) -> bool {
        !self.packets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_backend_new() {
        let backend = LoopbackBackend::new();
        assert!(!backend.has_data());
    }

    #[test]
    fn test_loopback_backend_default() {
        let backend = LoopbackBackend::default();
        assert!(!backend.has_data());
    }

    #[test]
    fn test_loopback_backend_send_recv() {
        let mut backend = LoopbackBackend::new();

        let packet = NetPacket::new(vec![1, 2, 3, 4, 5]);
        let sent = backend.send(&packet).unwrap();
        assert_eq!(sent, 5);

        assert!(backend.has_data());

        let mut buf = [0u8; 10];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], &[1, 2, 3, 4, 5]);

        assert!(!backend.has_data());
    }

    #[test]
    fn test_loopback_backend_recv_empty() {
        let mut backend = LoopbackBackend::new();

        let mut buf = [0u8; 10];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_loopback_backend_multiple_packets() {
        let mut backend = LoopbackBackend::new();

        for i in 0..5 {
            let packet = NetPacket::new(vec![i; 10]);
            backend.send(&packet).unwrap();
        }

        for i in 0..5 {
            assert!(backend.has_data());
            let mut buf = [0u8; 20];
            let n = backend.recv(&mut buf).unwrap();
            assert_eq!(n, 10);
            assert!(buf[..n].iter().all(|&b| b == i));
        }

        assert!(!backend.has_data());
    }

    #[test]
    fn test_loopback_backend_small_buffer() {
        let mut backend = LoopbackBackend::new();

        let packet = NetPacket::new(vec![0xAA; 100]);
        backend.send(&packet).unwrap();

        let mut buf = [0u8; 10];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 10);
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_loopback_large_packet() {
        let mut backend = LoopbackBackend::new();

        let data = vec![0xAB; 65536];
        let packet = NetPacket::new(data.clone());
        let sent = backend.send(&packet).unwrap();
        assert_eq!(sent, 65536);

        let mut buf = vec![0u8; 65536];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, 65536);
        assert_eq!(buf, data);
    }

    #[test]
    fn test_loopback_supports_tso_default_false() {
        let backend = LoopbackBackend::new();
        assert!(!backend.supports_tso());
    }
}
