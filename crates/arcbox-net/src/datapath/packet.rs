//! Zero-copy packet representation.
//!
//! This module provides packet structures that reference shared memory directly
//! without copying data, enabling high-performance packet processing.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};

/// Network protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Protocol {
    /// Unknown or unsupported protocol.
    #[default]
    Unknown = 0,
    /// Internet Control Message Protocol.
    Icmp = 1,
    /// Transmission Control Protocol.
    Tcp = 6,
    /// User Datagram Protocol.
    Udp = 17,
    /// ICMPv6.
    Icmpv6 = 58,
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            _ => Self::Unknown,
        }
    }
}

/// IP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum IpVersion {
    /// Unknown version.
    #[default]
    Unknown = 0,
    /// IPv4.
    V4 = 4,
    /// IPv6.
    V6 = 6,
}

/// Pre-parsed packet metadata for fast path processing.
///
/// Storing parsed header offsets and protocol information avoids
/// repeated parsing in the hot path.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketMetadata {
    /// Offset to L2 (Ethernet) header from packet start.
    pub l2_offset: u16,
    /// Offset to L3 (IP) header from packet start.
    pub l3_offset: u16,
    /// Offset to L4 (TCP/UDP) header from packet start.
    pub l4_offset: u16,
    /// L4 protocol type.
    pub protocol: Protocol,
    /// IP version.
    pub ip_version: IpVersion,
    /// Cached flow hash for connection tracking lookups.
    pub flow_hash: u64,
    /// Source port (for TCP/UDP).
    pub src_port: u16,
    /// Destination port (for TCP/UDP).
    pub dst_port: u16,
    /// Packet flags (e.g., TCP flags).
    pub flags: u8,
    /// Padding for alignment.
    _padding: [u8; 3],
}

impl PacketMetadata {
    /// Creates empty metadata.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            l2_offset: 0,
            l3_offset: 0,
            l4_offset: 0,
            protocol: Protocol::Unknown,
            ip_version: IpVersion::Unknown,
            flow_hash: 0,
            src_port: 0,
            dst_port: 0,
            flags: 0,
            _padding: [0; 3],
        }
    }

    /// Returns true if this is a TCP packet.
    #[inline]
    #[must_use]
    pub const fn is_tcp(&self) -> bool {
        matches!(self.protocol, Protocol::Tcp)
    }

    /// Returns true if this is a UDP packet.
    #[inline]
    #[must_use]
    pub const fn is_udp(&self) -> bool {
        matches!(self.protocol, Protocol::Udp)
    }

    /// Returns true if this is an ICMP packet.
    #[inline]
    #[must_use]
    pub const fn is_icmp(&self) -> bool {
        matches!(self.protocol, Protocol::Icmp | Protocol::Icmpv6)
    }
}

/// Zero-copy packet referencing shared memory directly.
///
/// This structure holds a pointer to packet data in guest memory
/// without copying the actual data. The reference count enables
/// safe deferred release after processing.
///
/// # Safety
///
/// The data pointer must remain valid for the lifetime of this packet.
/// The caller is responsible for ensuring the underlying memory is not
/// deallocated or modified while the packet is in use.
///
/// # Cache Line Alignment
///
/// The structure is aligned to 64 bytes to prevent false sharing
/// when packets are processed in parallel.
#[repr(C, align(64))]
pub struct ZeroCopyPacket {
    /// Pointer to packet data in shared memory.
    data: *const u8,
    /// Packet data length in bytes.
    len: u32,
    /// Pre-parsed packet metadata.
    metadata: PacketMetadata,
    /// Reference count for deferred release.
    refcount: AtomicU32,
    /// VirtIO descriptor index for completion.
    desc_idx: u16,
    /// Flags.
    flags: u16,
    /// Timestamp when packet was received (microseconds).
    timestamp: u64,
}

// Safety: The packet data pointer is read-only and can be shared.
unsafe impl Send for ZeroCopyPacket {}
unsafe impl Sync for ZeroCopyPacket {}

impl Default for ZeroCopyPacket {
    fn default() -> Self {
        Self::empty()
    }
}

impl ZeroCopyPacket {
    /// Packet flag: needs checksum calculation.
    pub const FLAG_NEEDS_CSUM: u16 = 1 << 0;
    /// Packet flag: is a GSO packet.
    pub const FLAG_GSO: u16 = 1 << 1;
    /// Packet flag: from guest (TX direction).
    pub const FLAG_FROM_GUEST: u16 = 1 << 2;
    /// Packet flag: to guest (RX direction).
    pub const FLAG_TO_GUEST: u16 = 1 << 3;

    /// Creates an empty packet.
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            data: std::ptr::null(),
            len: 0,
            metadata: PacketMetadata::new(),
            refcount: AtomicU32::new(0),
            desc_idx: 0,
            flags: 0,
            timestamp: 0,
        }
    }

    /// Creates a new zero-copy packet from raw parts.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `data` points to valid memory for at least `len` bytes.
    /// - The memory remains valid for the lifetime of the packet.
    /// - The memory is not modified while the packet is in use.
    #[inline]
    #[must_use]
    pub const unsafe fn from_raw_parts(data: *const u8, len: u32, desc_idx: u16) -> Self {
        Self {
            data,
            len,
            metadata: PacketMetadata::new(),
            refcount: AtomicU32::new(1),
            desc_idx,
            flags: 0,
            timestamp: 0,
        }
    }

    /// Creates a packet from a slice (for testing/non-zero-copy paths).
    ///
    /// # Safety
    ///
    /// The slice must remain valid for the lifetime of the packet.
    #[inline]
    #[must_use]
    pub const unsafe fn from_slice(data: &[u8], desc_idx: u16) -> Self {
        Self {
            data: data.as_ptr(),
            len: data.len() as u32,
            metadata: PacketMetadata::new(),
            refcount: AtomicU32::new(1),
            desc_idx,
            flags: 0,
            timestamp: 0,
        }
    }

    /// Returns true if this packet is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0 || self.data.is_null()
    }

    /// Returns the packet data length.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns the packet data as a slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure the underlying memory is still valid.
    #[inline]
    #[must_use]
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.data.is_null() {
            &[]
        } else {
            // Safety: caller guarantees memory validity per function contract.
            unsafe { std::slice::from_raw_parts(self.data, self.len as usize) }
        }
    }

    /// Returns the raw data pointer.
    #[inline]
    #[must_use]
    pub const fn data_ptr(&self) -> *const u8 {
        self.data
    }

    /// Returns the descriptor index.
    #[inline]
    #[must_use]
    pub const fn desc_idx(&self) -> u16 {
        self.desc_idx
    }

    /// Returns a reference to the packet metadata.
    #[inline]
    #[must_use]
    pub const fn metadata(&self) -> &PacketMetadata {
        &self.metadata
    }

    /// Returns a mutable reference to the packet metadata.
    #[inline]
    #[must_use]
    pub fn metadata_mut(&mut self) -> &mut PacketMetadata {
        &mut self.metadata
    }

    /// Sets the packet metadata.
    #[inline]
    pub fn set_metadata(&mut self, metadata: PacketMetadata) {
        self.metadata = metadata;
    }

    /// Returns the packet flags.
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Sets packet flags.
    #[inline]
    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }

    /// Adds a flag.
    #[inline]
    pub fn add_flag(&mut self, flag: u16) {
        self.flags |= flag;
    }

    /// Checks if a flag is set.
    #[inline]
    #[must_use]
    pub const fn has_flag(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }

    /// Returns the timestamp.
    #[inline]
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Sets the timestamp.
    #[inline]
    pub fn set_timestamp(&mut self, timestamp: u64) {
        self.timestamp = timestamp;
    }

    /// Increments the reference count.
    #[inline]
    pub fn add_ref(&self) {
        self.refcount.fetch_add(1, Ordering::AcqRel);
    }

    /// Decrements the reference count and returns true if it reached zero.
    #[inline]
    pub fn release(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// Returns the current reference count.
    #[inline]
    #[must_use]
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Parses packet headers and populates metadata.
    ///
    /// # Safety
    ///
    /// The packet data must be valid and accessible.
    pub unsafe fn parse_headers(&mut self) {
        if self.len < 14 {
            return; // Too short for Ethernet header
        }

        // Use raw pointer to avoid borrow conflict with metadata mutation.
        // Safety: caller guarantees data validity per function contract.
        let data = unsafe { std::slice::from_raw_parts(self.data, self.len as usize) };

        // Ethernet header is 14 bytes
        self.metadata.l2_offset = 0;
        self.metadata.l3_offset = 14;

        // Check EtherType
        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        match ethertype {
            0x0800 => {
                // IPv4
                self.metadata.ip_version = IpVersion::V4;
                self.parse_ipv4(data, 14);
            }
            0x86DD => {
                // IPv6
                self.metadata.ip_version = IpVersion::V6;
                self.parse_ipv6(data, 14);
            }
            0x8100 => {
                // VLAN tagged - skip 4 bytes
                self.metadata.l3_offset = 18;
                if self.len >= 18 {
                    let inner_ethertype = u16::from_be_bytes([data[16], data[17]]);
                    match inner_ethertype {
                        0x0800 => {
                            self.metadata.ip_version = IpVersion::V4;
                            self.parse_ipv4(data, 18);
                        }
                        0x86DD => {
                            self.metadata.ip_version = IpVersion::V6;
                            self.parse_ipv6(data, 18);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        // Calculate flow hash
        self.metadata.flow_hash = self.calculate_flow_hash();
    }

    /// Parses IPv4 header.
    fn parse_ipv4(&mut self, data: &[u8], offset: usize) {
        if data.len() < offset + 20 {
            return; // Too short for IPv4 header
        }

        let ihl = (data[offset] & 0x0F) as usize * 4;
        self.metadata.l4_offset = (offset + ihl) as u16;
        self.metadata.protocol = Protocol::from(data[offset + 9]);

        // Parse L4 ports for TCP/UDP
        let l4_offset = self.metadata.l4_offset as usize;
        if data.len() >= l4_offset + 4 {
            match self.metadata.protocol {
                Protocol::Tcp | Protocol::Udp => {
                    self.metadata.src_port =
                        u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
                    self.metadata.dst_port =
                        u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);

                    // TCP flags
                    if self.metadata.protocol == Protocol::Tcp && data.len() >= l4_offset + 14 {
                        self.metadata.flags = data[l4_offset + 13];
                    }
                }
                _ => {}
            }
        }
    }

    /// Parses IPv6 header.
    fn parse_ipv6(&mut self, data: &[u8], offset: usize) {
        if data.len() < offset + 40 {
            return; // Too short for IPv6 header
        }

        self.metadata.l4_offset = (offset + 40) as u16;
        self.metadata.protocol = Protocol::from(data[offset + 6]); // Next Header

        // Parse L4 ports for TCP/UDP
        let l4_offset = self.metadata.l4_offset as usize;
        if data.len() >= l4_offset + 4 {
            match self.metadata.protocol {
                Protocol::Tcp | Protocol::Udp => {
                    self.metadata.src_port =
                        u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
                    self.metadata.dst_port =
                        u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);

                    // TCP flags
                    if self.metadata.protocol == Protocol::Tcp && data.len() >= l4_offset + 14 {
                        self.metadata.flags = data[l4_offset + 13];
                    }
                }
                _ => {}
            }
        }
    }

    /// Calculates a flow hash for connection tracking.
    fn calculate_flow_hash(&self) -> u64 {
        // Simple FNV-1a hash of the 5-tuple
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;

        hash ^= self.metadata.protocol as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);

        hash ^= self.metadata.src_port as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);

        hash ^= self.metadata.dst_port as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);

        // Include IP addresses if we have them
        unsafe {
            let data = self.as_slice();
            if self.metadata.ip_version == IpVersion::V4 {
                let l3 = self.metadata.l3_offset as usize;
                if data.len() >= l3 + 20 {
                    // Source IP
                    for i in 0..4 {
                        hash ^= data[l3 + 12 + i] as u64;
                        hash = hash.wrapping_mul(0x0100_0000_01b3);
                    }
                    // Dest IP
                    for i in 0..4 {
                        hash ^= data[l3 + 16 + i] as u64;
                        hash = hash.wrapping_mul(0x0100_0000_01b3);
                    }
                }
            } else if self.metadata.ip_version == IpVersion::V6 {
                let l3 = self.metadata.l3_offset as usize;
                if data.len() >= l3 + 40 {
                    // Source IP (16 bytes)
                    for i in 0..16 {
                        hash ^= data[l3 + 8 + i] as u64;
                        hash = hash.wrapping_mul(0x0100_0000_01b3);
                    }
                    // Dest IP (16 bytes)
                    for i in 0..16 {
                        hash ^= data[l3 + 24 + i] as u64;
                        hash = hash.wrapping_mul(0x0100_0000_01b3);
                    }
                }
            }
        }

        hash
    }

    /// Returns the source IPv4 address, if this is an IPv4 packet.
    ///
    /// # Safety
    ///
    /// The packet data must be valid.
    #[must_use]
    pub unsafe fn src_ipv4(&self) -> Option<Ipv4Addr> {
        if self.metadata.ip_version != IpVersion::V4 {
            return None;
        }
        // Safety: caller guarantees data validity per function contract.
        let data = unsafe { self.as_slice() };
        let l3 = self.metadata.l3_offset as usize;
        if data.len() >= l3 + 20 {
            Some(Ipv4Addr::new(
                data[l3 + 12],
                data[l3 + 13],
                data[l3 + 14],
                data[l3 + 15],
            ))
        } else {
            None
        }
    }

    /// Returns the destination IPv4 address, if this is an IPv4 packet.
    ///
    /// # Safety
    ///
    /// The packet data must be valid.
    #[must_use]
    pub unsafe fn dst_ipv4(&self) -> Option<Ipv4Addr> {
        if self.metadata.ip_version != IpVersion::V4 {
            return None;
        }
        // Safety: caller guarantees data validity per function contract.
        let data = unsafe { self.as_slice() };
        let l3 = self.metadata.l3_offset as usize;
        if data.len() >= l3 + 20 {
            Some(Ipv4Addr::new(
                data[l3 + 16],
                data[l3 + 17],
                data[l3 + 18],
                data[l3 + 19],
            ))
        } else {
            None
        }
    }

    /// Returns the source IPv6 address, if this is an IPv6 packet.
    ///
    /// # Safety
    ///
    /// The packet data must be valid.
    #[must_use]
    pub unsafe fn src_ipv6(&self) -> Option<Ipv6Addr> {
        if self.metadata.ip_version != IpVersion::V6 {
            return None;
        }
        // Safety: caller guarantees data validity per function contract.
        let data = unsafe { self.as_slice() };
        let l3 = self.metadata.l3_offset as usize;
        if data.len() >= l3 + 40 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[l3 + 8..l3 + 24]);
            Some(Ipv6Addr::from(octets))
        } else {
            None
        }
    }

    /// Returns the destination IPv6 address, if this is an IPv6 packet.
    ///
    /// # Safety
    ///
    /// The packet data must be valid.
    #[must_use]
    pub unsafe fn dst_ipv6(&self) -> Option<Ipv6Addr> {
        if self.metadata.ip_version != IpVersion::V6 {
            return None;
        }
        // Safety: caller guarantees data validity per function contract.
        let data = unsafe { self.as_slice() };
        let l3 = self.metadata.l3_offset as usize;
        if data.len() >= l3 + 40 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[l3 + 24..l3 + 40]);
            Some(Ipv6Addr::from(octets))
        } else {
            None
        }
    }
}

impl std::fmt::Debug for ZeroCopyPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroCopyPacket")
            .field("data", &self.data)
            .field("len", &self.len)
            .field("metadata", &self.metadata)
            .field("refcount", &self.refcount.load(Ordering::Relaxed))
            .field("desc_idx", &self.desc_idx)
            .field("flags", &self.flags)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_size() {
        // Ensure packet fits in a cache line
        assert!(std::mem::size_of::<ZeroCopyPacket>() <= 128);
        // Ensure alignment
        assert_eq!(std::mem::align_of::<ZeroCopyPacket>(), 64);
    }

    #[test]
    fn test_empty_packet() {
        let pkt = ZeroCopyPacket::empty();
        assert!(pkt.is_empty());
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.refcount(), 0);
    }

    #[test]
    fn test_protocol_from() {
        assert_eq!(Protocol::from(1), Protocol::Icmp);
        assert_eq!(Protocol::from(6), Protocol::Tcp);
        assert_eq!(Protocol::from(17), Protocol::Udp);
        assert_eq!(Protocol::from(58), Protocol::Icmpv6);
        assert_eq!(Protocol::from(255), Protocol::Unknown);
    }

    #[test]
    fn test_metadata() {
        let mut meta = PacketMetadata::new();
        meta.protocol = Protocol::Tcp;
        meta.src_port = 12345;
        meta.dst_port = 80;

        assert!(meta.is_tcp());
        assert!(!meta.is_udp());
        assert!(!meta.is_icmp());
    }

    #[test]
    fn test_packet_from_slice() {
        let data = [0u8; 64];
        let pkt = unsafe { ZeroCopyPacket::from_slice(&data, 42) };

        assert!(!pkt.is_empty());
        assert_eq!(pkt.len(), 64);
        assert_eq!(pkt.desc_idx(), 42);
        assert_eq!(pkt.refcount(), 1);
    }

    #[test]
    fn test_refcount() {
        let data = [0u8; 64];
        let pkt = unsafe { ZeroCopyPacket::from_slice(&data, 0) };

        assert_eq!(pkt.refcount(), 1);

        pkt.add_ref();
        assert_eq!(pkt.refcount(), 2);

        assert!(!pkt.release());
        assert_eq!(pkt.refcount(), 1);

        assert!(pkt.release());
        assert_eq!(pkt.refcount(), 0);
    }

    #[test]
    fn test_flags() {
        let mut pkt = ZeroCopyPacket::empty();

        assert_eq!(pkt.flags(), 0);
        assert!(!pkt.has_flag(ZeroCopyPacket::FLAG_NEEDS_CSUM));

        pkt.add_flag(ZeroCopyPacket::FLAG_NEEDS_CSUM);
        assert!(pkt.has_flag(ZeroCopyPacket::FLAG_NEEDS_CSUM));
        assert!(!pkt.has_flag(ZeroCopyPacket::FLAG_GSO));

        pkt.add_flag(ZeroCopyPacket::FLAG_GSO);
        assert!(pkt.has_flag(ZeroCopyPacket::FLAG_NEEDS_CSUM));
        assert!(pkt.has_flag(ZeroCopyPacket::FLAG_GSO));
    }
}
