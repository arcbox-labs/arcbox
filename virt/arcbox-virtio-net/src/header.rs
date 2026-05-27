//! `VirtIO`-net wire format — header struct and `NetPacket` envelope.

use arcbox_virtio_core::virtio_bindings;

/// `VirtIO` network header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHeader {
    /// Flags.
    pub flags: u8,
    /// GSO type.
    pub gso_type: u8,
    /// Header length.
    pub hdr_len: u16,
    /// GSO size.
    pub gso_size: u16,
    /// Checksum start.
    pub csum_start: u16,
    /// Checksum offset.
    pub csum_offset: u16,
    /// Number of buffers.
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    /// Size of the header in bytes.
    pub const SIZE: usize = 12;

    /// No GSO.
    pub const GSO_NONE: u8 = virtio_bindings::virtio_net::VIRTIO_NET_HDR_GSO_NONE as u8;
    /// TCP/IPv4 GSO.
    pub const GSO_TCPV4: u8 = virtio_bindings::virtio_net::VIRTIO_NET_HDR_GSO_TCPV4 as u8;
    /// UDP GSO.
    pub const GSO_UDP: u8 = virtio_bindings::virtio_net::VIRTIO_NET_HDR_GSO_UDP as u8;
    /// TCP/IPv6 GSO.
    pub const GSO_TCPV6: u8 = virtio_bindings::virtio_net::VIRTIO_NET_HDR_GSO_TCPV6 as u8;
    /// ECN flag.
    pub const GSO_ECN: u8 = virtio_bindings::virtio_net::VIRTIO_NET_HDR_GSO_ECN as u8;

    /// Header needs checksum.
    pub const FLAG_NEEDS_CSUM: u8 = virtio_bindings::virtio_net::VIRTIO_NET_HDR_F_NEEDS_CSUM as u8;
    /// Data is valid.
    pub const FLAG_DATA_VALID: u8 = virtio_bindings::virtio_net::VIRTIO_NET_HDR_F_DATA_VALID as u8;

    /// Creates a new header.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_le_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_le_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_le_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_le_bytes([bytes[8], bytes[9]]),
            num_buffers: u16::from_le_bytes([bytes[10], bytes[11]]),
        })
    }

    /// Converts to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.flags;
        bytes[1] = self.gso_type;
        bytes[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.num_buffers.to_le_bytes());
        bytes
    }
}

/// Network packet.
#[derive(Debug, Clone)]
pub struct NetPacket {
    /// `VirtIO` header.
    pub header: VirtioNetHeader,
    /// Packet data (Ethernet frame).
    pub data: Vec<u8>,
}

impl NetPacket {
    /// Creates a new packet.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            header: VirtioNetHeader::new(),
            data,
        }
    }

    /// Returns the total size including header.
    #[must_use]
    pub fn total_size(&self) -> usize {
        VirtioNetHeader::SIZE + self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(VirtioNetHeader::SIZE, 12);
    }

    #[test]
    fn test_header_constants() {
        assert_eq!(VirtioNetHeader::GSO_NONE, 0);
        assert_eq!(VirtioNetHeader::GSO_TCPV4, 1);
        assert_eq!(VirtioNetHeader::GSO_UDP, 3);
        assert_eq!(VirtioNetHeader::GSO_TCPV6, 4);
        assert_eq!(VirtioNetHeader::GSO_ECN, 0x80);
        assert_eq!(VirtioNetHeader::FLAG_NEEDS_CSUM, 1);
        assert_eq!(VirtioNetHeader::FLAG_DATA_VALID, 2);
    }

    #[test]
    fn test_header_new() {
        let header = VirtioNetHeader::new();
        assert_eq!(header.flags, 0);
        assert_eq!(header.gso_type, 0);
        assert_eq!(header.hdr_len, 0);
        assert_eq!(header.gso_size, 0);
        assert_eq!(header.csum_start, 0);
        assert_eq!(header.csum_offset, 0);
        assert_eq!(header.num_buffers, 0);
    }

    #[test]
    fn test_header_serialization() {
        let header = VirtioNetHeader {
            flags: 1,
            gso_type: 2,
            hdr_len: 0x1234,
            gso_size: 0x5678,
            csum_start: 0x9ABC,
            csum_offset: 0xDEF0,
            num_buffers: 0x1111,
        };

        let bytes = header.to_bytes();
        let parsed = VirtioNetHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.gso_type, header.gso_type);
        assert_eq!(parsed.hdr_len, header.hdr_len);
        assert_eq!(parsed.gso_size, header.gso_size);
        assert_eq!(parsed.csum_start, header.csum_start);
        assert_eq!(parsed.csum_offset, header.csum_offset);
        assert_eq!(parsed.num_buffers, header.num_buffers);
    }

    #[test]
    fn test_header_from_bytes_too_small() {
        let bytes = [0u8; 11];
        assert!(VirtioNetHeader::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_header_from_bytes_exact_size() {
        let bytes = [0u8; 12];
        assert!(VirtioNetHeader::from_bytes(&bytes).is_some());
    }

    #[test]
    fn test_header_from_bytes_larger() {
        let bytes = [0u8; 100];
        let header = VirtioNetHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.flags, 0);
    }

    #[test]
    fn test_header_endianness() {
        let header = VirtioNetHeader {
            flags: 0,
            gso_type: 0,
            hdr_len: 0x0102,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        };

        let bytes = header.to_bytes();
        // Little-endian: 0x0102 should be stored as [0x02, 0x01]
        assert_eq!(bytes[2], 0x02);
        assert_eq!(bytes[3], 0x01);
    }

    #[test]
    fn test_packet_new() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let packet = NetPacket::new(data.clone());

        assert_eq!(packet.data, data);
        assert_eq!(packet.header.flags, 0);
    }

    #[test]
    fn test_packet_total_size() {
        let data = vec![0u8; 100];
        let packet = NetPacket::new(data);

        assert_eq!(packet.total_size(), VirtioNetHeader::SIZE + 100);
    }

    #[test]
    fn test_packet_empty() {
        let packet = NetPacket::new(vec![]);
        assert_eq!(packet.total_size(), VirtioNetHeader::SIZE);
        assert!(packet.data.is_empty());
    }

    #[test]
    fn test_packet_large() {
        let data = vec![0u8; 9000];
        let packet = NetPacket::new(data);
        assert_eq!(packet.total_size(), VirtioNetHeader::SIZE + 9000);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_header_clone_copy() {
        let header = VirtioNetHeader {
            flags: 1,
            gso_type: 2,
            hdr_len: 3,
            gso_size: 4,
            csum_start: 5,
            csum_offset: 6,
            num_buffers: 7,
        };

        let cloned = header.clone();
        let copied = header;

        assert_eq!(cloned.flags, 1);
        assert_eq!(copied.flags, 1);
    }

    #[test]
    fn test_packet_clone() {
        let packet = NetPacket {
            header: VirtioNetHeader::new(),
            data: vec![1, 2, 3],
        };

        let cloned = packet.clone();
        assert_eq!(cloned.data, packet.data);
    }
}
