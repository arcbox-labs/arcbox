//! Packet translation for NAT.
//!
//! This module provides zero-copy in-place packet modification for NAT.

use std::net::Ipv4Addr;

use super::NatEngineConfig;
use super::checksum::{update_checksum_for_ip, update_checksum_for_nat};
use super::conntrack::{ConnTrackKey, ConnTrackTable};

/// NAT direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatDirection {
    /// Outbound: guest -> external network (SNAT).
    Outbound,
    /// Inbound: external network -> guest (reverse NAT).
    Inbound,
}

/// NAT translation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatResult {
    /// Packet was translated successfully.
    Translated,
    /// Packet was passed through without translation.
    PassThrough,
    /// Packet was dropped.
    Dropped,
}

/// Translation error.
#[derive(Debug, Clone)]
pub enum TranslateError {
    /// Packet too short.
    PacketTooShort,
    /// Invalid IP header.
    InvalidIpHeader,
    /// Unsupported protocol.
    UnsupportedProtocol,
    /// Connection tracking table full.
    ConnTrackFull,
}

impl std::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "packet too short"),
            Self::InvalidIpHeader => write!(f, "invalid IP header"),
            Self::UnsupportedProtocol => write!(f, "unsupported protocol"),
            Self::ConnTrackFull => write!(f, "connection tracking table full"),
        }
    }
}

impl std::error::Error for TranslateError {}

/// High-performance NAT engine.
pub struct NatEngine {
    /// Connection tracking table.
    conntrack: ConnTrackTable,
    /// External IP address.
    external_ip: Ipv4Addr,
    /// Internal network prefix.
    internal_prefix: Ipv4Addr,
    /// Internal network mask.
    internal_mask: u32,
}

impl NatEngine {
    /// Creates a new NAT engine.
    #[must_use]
    pub fn new(config: &NatEngineConfig) -> Self {
        Self {
            conntrack: ConnTrackTable::new(
                config.external_ip,
                config.port_range_start,
                config.port_range_end,
                config.fast_cache_size,
                config.connection_timeout_secs,
            ),
            external_ip: config.external_ip,
            internal_prefix: Ipv4Addr::new(192, 168, 64, 0),
            internal_mask: 0xFFFF_FF00, // /24
        }
    }

    /// Creates a NAT engine with a specific external IP.
    #[must_use]
    pub fn with_external_ip(external_ip: Ipv4Addr) -> Self {
        Self::new(&NatEngineConfig::new(external_ip))
    }

    /// Sets the internal network.
    pub fn set_internal_network(&mut self, prefix: Ipv4Addr, prefix_len: u8) {
        self.internal_prefix = prefix;
        self.internal_mask = if prefix_len >= 32 {
            0xFFFF_FFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
    }

    /// Checks if an IP is in the internal network.
    #[inline]
    fn is_internal(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let prefix_u32 = u32::from(self.internal_prefix);
        (ip_u32 & self.internal_mask) == (prefix_u32 & self.internal_mask)
    }

    /// Translates a packet.
    ///
    /// # Safety
    ///
    /// The packet buffer must be valid and large enough for the IP header
    /// and transport header to be modified in place.
    pub unsafe fn translate(
        &mut self,
        packet: &mut [u8],
        direction: NatDirection,
    ) -> Result<NatResult, TranslateError> {
        // Minimum: Ethernet (14) + IP (20) + TCP/UDP (8)
        if packet.len() < 42 {
            return Err(TranslateError::PacketTooShort);
        }

        // Check EtherType (should be IPv4: 0x0800)
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype != 0x0800 {
            return Ok(NatResult::PassThrough);
        }

        // Parse IP header
        let ip_offset = 14;
        let version_ihl = packet[ip_offset];
        if (version_ihl >> 4) != 4 {
            return Err(TranslateError::InvalidIpHeader);
        }

        let ihl = ((version_ihl & 0x0F) * 4) as usize;
        if ihl < 20 || ip_offset + ihl > packet.len() {
            return Err(TranslateError::InvalidIpHeader);
        }

        let protocol = packet[ip_offset + 9];

        // Only handle TCP (6) and UDP (17)
        if protocol != 6 && protocol != 17 {
            return Ok(NatResult::PassThrough);
        }

        // Extract IP addresses
        let src_ip = Ipv4Addr::new(
            packet[ip_offset + 12],
            packet[ip_offset + 13],
            packet[ip_offset + 14],
            packet[ip_offset + 15],
        );
        let dst_ip = Ipv4Addr::new(
            packet[ip_offset + 16],
            packet[ip_offset + 17],
            packet[ip_offset + 18],
            packet[ip_offset + 19],
        );

        // Extract ports
        let l4_offset = ip_offset + ihl;
        if l4_offset + 4 > packet.len() {
            return Err(TranslateError::PacketTooShort);
        }

        let src_port = u16::from_be_bytes([packet[l4_offset], packet[l4_offset + 1]]);
        let dst_port = u16::from_be_bytes([packet[l4_offset + 2], packet[l4_offset + 3]]);

        // Safety: packet bounds have been validated above
        match direction {
            NatDirection::Outbound => unsafe {
                self.translate_outbound(
                    packet, ip_offset, l4_offset, src_ip, dst_ip, src_port, dst_port, protocol,
                )
            },
            NatDirection::Inbound => unsafe {
                self.translate_inbound(
                    packet, ip_offset, l4_offset, src_ip, dst_ip, src_port, dst_port, protocol,
                )
            },
        }
    }

    /// Translates an outbound packet (SNAT).
    #[allow(clippy::too_many_arguments)]
    unsafe fn translate_outbound(
        &mut self,
        packet: &mut [u8],
        ip_offset: usize,
        l4_offset: usize,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Result<NatResult, TranslateError> {
        // Only NAT internal sources
        if !self.is_internal(src_ip) {
            return Ok(NatResult::PassThrough);
        }

        // Get or create connection tracking entry
        let key = ConnTrackKey::new(src_ip, dst_ip, src_port, dst_port, protocol);
        let entry = self.conntrack.get_or_create(key);

        let nat_ip = *entry.nat_src.ip();
        let nat_port = entry.nat_src.port();

        // Update packet: source IP and port
        let old_ip_bytes = src_ip.octets();
        let new_ip_bytes = nat_ip.octets();

        // Modify source IP
        packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&new_ip_bytes);

        // Update IP checksum
        let old_ip_checksum = u16::from_be_bytes([packet[ip_offset + 10], packet[ip_offset + 11]]);
        let new_ip_checksum = update_checksum_for_ip(old_ip_checksum, old_ip_bytes, new_ip_bytes);
        packet[ip_offset + 10..ip_offset + 12].copy_from_slice(&new_ip_checksum.to_be_bytes());

        // Modify source port
        packet[l4_offset..l4_offset + 2].copy_from_slice(&nat_port.to_be_bytes());

        // Update L4 checksum (TCP or UDP)
        let checksum_offset = if protocol == 6 {
            l4_offset + 16 // TCP checksum at offset 16
        } else {
            l4_offset + 6 // UDP checksum at offset 6
        };

        if checksum_offset + 2 <= packet.len() {
            let old_l4_checksum =
                u16::from_be_bytes([packet[checksum_offset], packet[checksum_offset + 1]]);

            // Skip if UDP checksum is 0 (optional)
            if protocol != 17 || old_l4_checksum != 0 {
                let new_l4_checksum = update_checksum_for_nat(
                    old_l4_checksum,
                    old_ip_bytes,
                    src_port,
                    new_ip_bytes,
                    nat_port,
                );
                packet[checksum_offset..checksum_offset + 2]
                    .copy_from_slice(&new_l4_checksum.to_be_bytes());
            }
        }

        // Record packet in connection tracking
        entry.record_packet(packet.len() as u64);

        Ok(NatResult::Translated)
    }

    /// Translates an inbound packet (reverse NAT).
    #[allow(clippy::too_many_arguments)]
    unsafe fn translate_inbound(
        &mut self,
        packet: &mut [u8],
        ip_offset: usize,
        l4_offset: usize,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Result<NatResult, TranslateError> {
        // Only process packets destined to our external IP
        if dst_ip != self.external_ip {
            return Ok(NatResult::PassThrough);
        }

        // Lookup reverse mapping
        let nat_key = ConnTrackKey::new(src_ip, dst_ip, src_port, dst_port, protocol);

        let entry = match self.conntrack.lookup_reverse(&nat_key) {
            Some(e) => e,
            None => return Ok(NatResult::Dropped), // No matching connection
        };

        let orig_ip = *entry.orig_src.ip();
        let orig_port = entry.orig_src.port();

        // Update packet: destination IP and port
        let old_ip_bytes = dst_ip.octets();
        let new_ip_bytes = orig_ip.octets();

        // Modify destination IP
        packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&new_ip_bytes);

        // Update IP checksum
        let old_ip_checksum = u16::from_be_bytes([packet[ip_offset + 10], packet[ip_offset + 11]]);
        let new_ip_checksum = update_checksum_for_ip(old_ip_checksum, old_ip_bytes, new_ip_bytes);
        packet[ip_offset + 10..ip_offset + 12].copy_from_slice(&new_ip_checksum.to_be_bytes());

        // Modify destination port
        packet[l4_offset + 2..l4_offset + 4].copy_from_slice(&orig_port.to_be_bytes());

        // Update L4 checksum
        let checksum_offset = if protocol == 6 {
            l4_offset + 16
        } else {
            l4_offset + 6
        };

        if checksum_offset + 2 <= packet.len() {
            let old_l4_checksum =
                u16::from_be_bytes([packet[checksum_offset], packet[checksum_offset + 1]]);

            if protocol != 17 || old_l4_checksum != 0 {
                let new_l4_checksum = update_checksum_for_nat(
                    old_l4_checksum,
                    old_ip_bytes,
                    dst_port,
                    new_ip_bytes,
                    orig_port,
                );
                packet[checksum_offset..checksum_offset + 2]
                    .copy_from_slice(&new_l4_checksum.to_be_bytes());
            }
        }

        // Record packet and mark reply seen
        entry.record_packet(packet.len() as u64);

        Ok(NatResult::Translated)
    }

    /// Returns the connection tracking table.
    #[must_use]
    pub fn conntrack(&self) -> &ConnTrackTable {
        &self.conntrack
    }

    /// Returns a mutable reference to the connection tracking table.
    #[must_use]
    pub fn conntrack_mut(&mut self) -> &mut ConnTrackTable {
        &mut self.conntrack
    }

    /// Expires old connections.
    pub fn expire_connections(&mut self) -> usize {
        self.conntrack.expire_old()
    }

    /// Returns the number of tracked connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.conntrack.len()
    }
}

impl std::fmt::Debug for NatEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatEngine")
            .field("external_ip", &self.external_ip)
            .field("connections", &self.conntrack.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 54]; // Ethernet + IP + TCP

        // Ethernet header
        packet[12] = 0x08; // EtherType: IPv4
        packet[13] = 0x00;

        // IP header
        packet[14] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[15] = 0x00; // DSCP/ECN
        packet[16] = 0x00; // Total length (high)
        packet[17] = 40; // Total length (low): 20 + 20
        packet[23] = protocol;
        packet[26..30].copy_from_slice(&src_ip);
        packet[30..34].copy_from_slice(&dst_ip);

        // TCP/UDP header
        packet[34..36].copy_from_slice(&src_port.to_be_bytes());
        packet[36..38].copy_from_slice(&dst_port.to_be_bytes());

        packet
    }

    #[test]
    fn test_nat_outbound() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(10, 0, 0, 1));
        engine.set_internal_network(Ipv4Addr::new(192, 168, 64, 0), 24);

        let mut packet = create_test_packet(
            [192, 168, 64, 100],
            [8, 8, 8, 8],
            12345,
            80,
            6, // TCP
        );

        let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };
        assert_eq!(result.unwrap(), NatResult::Translated);

        // Check source IP was changed to external IP
        assert_eq!(&packet[26..30], &[10, 0, 0, 1]);

        // Connection should be tracked
        assert_eq!(engine.connection_count(), 1);
    }

    #[test]
    fn test_nat_passthrough_external() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(10, 0, 0, 1));
        engine.set_internal_network(Ipv4Addr::new(192, 168, 64, 0), 24);

        // Source is not in internal network
        let mut packet = create_test_packet([8, 8, 4, 4], [8, 8, 8, 8], 12345, 80, 6);

        let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };
        assert_eq!(result.unwrap(), NatResult::PassThrough);

        // Source IP should be unchanged
        assert_eq!(&packet[26..30], &[8, 8, 4, 4]);
    }

    #[test]
    fn test_nat_inbound() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(10, 0, 0, 1));
        engine.set_internal_network(Ipv4Addr::new(192, 168, 64, 0), 24);

        // First create outbound connection
        let mut outbound = create_test_packet([192, 168, 64, 100], [8, 8, 8, 8], 12345, 80, 6);
        unsafe {
            engine
                .translate(&mut outbound, NatDirection::Outbound)
                .unwrap()
        };

        // Get the NAT port
        let nat_port = u16::from_be_bytes([outbound[34], outbound[35]]);

        // Create inbound response
        let mut inbound = create_test_packet([8, 8, 8, 8], [10, 0, 0, 1], 80, nat_port, 6);

        let result = unsafe { engine.translate(&mut inbound, NatDirection::Inbound) };
        assert_eq!(result.unwrap(), NatResult::Translated);

        // Destination should be restored to original
        assert_eq!(&inbound[30..34], &[192, 168, 64, 100]);
    }

    #[test]
    fn test_nat_inbound_no_connection() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(10, 0, 0, 1));

        // Inbound packet without existing connection
        let mut packet = create_test_packet([8, 8, 8, 8], [10, 0, 0, 1], 80, 54321, 6);

        let result = unsafe { engine.translate(&mut packet, NatDirection::Inbound) };
        assert_eq!(result.unwrap(), NatResult::Dropped);
    }

    #[test]
    fn test_is_internal() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(10, 0, 0, 1));
        engine.set_internal_network(Ipv4Addr::new(192, 168, 64, 0), 24);

        assert!(engine.is_internal(Ipv4Addr::new(192, 168, 64, 1)));
        assert!(engine.is_internal(Ipv4Addr::new(192, 168, 64, 100)));
        assert!(engine.is_internal(Ipv4Addr::new(192, 168, 64, 255)));
        assert!(!engine.is_internal(Ipv4Addr::new(192, 168, 65, 1)));
        assert!(!engine.is_internal(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
