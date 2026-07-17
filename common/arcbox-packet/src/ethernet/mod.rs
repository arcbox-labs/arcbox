//! Ethernet frame parsing, construction, and ARP handling.
//!
//! Provides minimal L2 utilities for the custom network datapath:
//! - Ethernet header parse/construct
//! - ARP responder (gateway only)
//! - UDP/IP/Ethernet packet builder for DHCP and DNS responses

mod checksum;
mod tcp;
mod udp;

#[cfg(test)]
mod tests;

pub use checksum::{ipv4_header_checksum, tcp_checksum};
pub use tcp::{
    SynAckParams, SynParams, TcpFrameParams, TcpSynOptions, build_tcp_ack_frame,
    build_tcp_data_frame, build_tcp_data_frame_partial_csum, build_tcp_fin_frame,
    build_tcp_rst_frame, build_tcp_syn_ack_frame, build_tcp_syn_frame, parse_tcp_syn_options,
    tcp_pseudo_header_checksum,
};
pub use udp::{MAX_UDP_PAYLOAD, build_udp_ip_ethernet};

use std::net::Ipv4Addr;

/// Ethernet header size in bytes.
pub const ETH_HEADER_LEN: usize = 14;

/// Minimum frame size for an ARP packet (Ethernet + 28-byte ARP payload).
const ARP_FRAME_MIN_LEN: usize = ETH_HEADER_LEN + 28;

/// EtherType values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Unknown(u16),
}

impl EtherType {
    /// Parses EtherType from raw two-byte big-endian value.
    #[must_use]
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86DD => Self::Ipv6,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw two-byte big-endian value.
    #[must_use]
    pub fn to_raw(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86DD,
            Self::Unknown(v) => v,
        }
    }
}

/// Parsed Ethernet header fields.
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: EtherType,
}

impl EthernetHeader {
    /// Parses an Ethernet header from the start of `data`.
    ///
    /// Returns `None` if the data is shorter than 14 bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ETH_HEADER_LEN {
            return None;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);
        let raw_type = u16::from_be_bytes([data[12], data[13]]);
        Some(Self {
            dst_mac,
            src_mac,
            ethertype: EtherType::from_raw(raw_type),
        })
    }

    /// Serialises the header into a 14-byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ETH_HEADER_LEN] {
        let mut buf = [0u8; ETH_HEADER_LEN];
        buf[0..6].copy_from_slice(&self.dst_mac);
        buf[6..12].copy_from_slice(&self.src_mac);
        buf[12..14].copy_from_slice(&self.ethertype.to_raw().to_be_bytes());
        buf
    }
}

/// Returns the payload slice after the 14-byte Ethernet header.
#[must_use]
pub fn strip_ethernet_header(frame: &[u8]) -> &[u8] {
    if frame.len() <= ETH_HEADER_LEN {
        return &[];
    }
    &frame[ETH_HEADER_LEN..]
}

/// Prepends a 14-byte Ethernet header (IPv4 EtherType) to an IP packet.
#[must_use]
pub fn prepend_ethernet_header(ip_packet: &[u8], dst_mac: [u8; 6], src_mac: [u8; 6]) -> Vec<u8> {
    let hdr = EthernetHeader {
        dst_mac,
        src_mac,
        ethertype: EtherType::Ipv4,
    };
    let mut frame = Vec::with_capacity(ETH_HEADER_LEN + ip_packet.len());
    frame.extend_from_slice(&hdr.to_bytes());
    frame.extend_from_slice(ip_packet);
    frame
}

/// Responds to ARP requests targeting the gateway IP.
pub struct ArpResponder {
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
}

impl ArpResponder {
    /// Creates a new ARP responder for the given gateway.
    #[must_use]
    pub fn new(gateway_ip: Ipv4Addr, gateway_mac: [u8; 6]) -> Self {
        Self {
            gateway_ip,
            gateway_mac,
        }
    }

    /// If `frame` is an ARP Request for the gateway IP, returns a complete
    /// ARP Reply Ethernet frame. Otherwise returns `None`.
    #[must_use]
    pub fn handle_arp(&self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < ARP_FRAME_MIN_LEN {
            return None;
        }

        let arp = &frame[ETH_HEADER_LEN..];

        // Hardware type = Ethernet (1), Protocol type = IPv4 (0x0800)
        if u16::from_be_bytes([arp[0], arp[1]]) != 1
            || u16::from_be_bytes([arp[2], arp[3]]) != 0x0800
        {
            return None;
        }

        // HLEN = 6, PLEN = 4, Operation = Request (1)
        if arp[4] != 6 || arp[5] != 4 || u16::from_be_bytes([arp[6], arp[7]]) != 1 {
            return None;
        }

        // Target protocol address (bytes 24..28 of ARP payload)
        let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
        if target_ip != self.gateway_ip {
            return None;
        }

        // Sender hardware address (bytes 8..14) and sender IP (14..18)
        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&arp[8..14]);
        let sender_ip_bytes: [u8; 4] = [arp[14], arp[15], arp[16], arp[17]];

        // Build ARP Reply
        let mut reply = Vec::with_capacity(ARP_FRAME_MIN_LEN);

        // Ethernet header: dst=sender, src=gateway, EtherType=ARP
        reply.extend_from_slice(&sender_mac);
        reply.extend_from_slice(&self.gateway_mac);
        reply.extend_from_slice(&0x0806u16.to_be_bytes());

        // ARP payload
        reply.extend_from_slice(&1u16.to_be_bytes()); // Hardware type: Ethernet
        reply.extend_from_slice(&0x0800u16.to_be_bytes()); // Protocol type: IPv4
        reply.push(6); // HLEN
        reply.push(4); // PLEN
        reply.extend_from_slice(&2u16.to_be_bytes()); // Operation: Reply
        reply.extend_from_slice(&self.gateway_mac); // Sender hardware addr
        reply.extend_from_slice(&self.gateway_ip.octets()); // Sender protocol addr
        reply.extend_from_slice(&sender_mac); // Target hardware addr
        reply.extend_from_slice(&sender_ip_bytes); // Target protocol addr

        Some(reply)
    }
}
