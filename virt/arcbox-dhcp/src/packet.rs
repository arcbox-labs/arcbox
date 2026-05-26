//! DHCP packet parsing and serialization.
//!
//! Handles the wire format of DHCP messages (RFC 2131), including
//! header fields and option parsing/encoding.

use std::net::Ipv4Addr;

use crate::config::DhcpConfig;
use crate::error::{DhcpError, Result};

/// DHCP message type.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    /// DHCPDISCOVER
    Discover = 1,
    /// DHCPOFFER
    Offer = 2,
    /// DHCPREQUEST
    Request = 3,
    /// DHCPDECLINE
    Decline = 4,
    /// DHCPACK
    Ack = 5,
    /// DHCPNAK
    Nak = 6,
    /// DHCPRELEASE
    Release = 7,
    /// DHCPINFORM
    Inform = 8,
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            8 => Ok(Self::Inform),
            _ => Err(()),
        }
    }
}

/// DHCP packet.
///
/// Simplified representation of a DHCP packet covering the fields
/// needed for server-side processing.
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    /// Operation (1 = request, 2 = reply).
    pub op: u8,
    /// Hardware type (1 = Ethernet).
    pub htype: u8,
    /// Hardware address length.
    pub hlen: u8,
    /// Hops.
    pub hops: u8,
    /// Transaction ID.
    pub xid: u32,
    /// Seconds elapsed.
    pub secs: u16,
    /// Flags.
    pub flags: u16,
    /// Client IP address.
    pub ciaddr: Ipv4Addr,
    /// Your IP address (assigned by server).
    pub yiaddr: Ipv4Addr,
    /// Server IP address.
    pub siaddr: Ipv4Addr,
    /// Gateway IP address.
    pub giaddr: Ipv4Addr,
    /// Client hardware address.
    pub chaddr: [u8; 16],
    /// Options (simplified).
    pub message_type: Option<DhcpMessageType>,
    /// Requested IP.
    pub requested_ip: Option<Ipv4Addr>,
    /// Client hostname.
    pub hostname: Option<String>,
}

impl DhcpPacket {
    /// DHCP magic cookie.
    const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

    /// Minimum DHCP packet size.
    const MIN_SIZE: usize = 236;

    /// Creates a new empty DHCP packet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            op: 0,
            htype: 1, // Ethernet
            hlen: 6,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 16],
            message_type: None,
            requested_ip: None,
            hostname: None,
        }
    }

    /// Parses a DHCP packet from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(DhcpError::Protocol("packet too short".to_string()));
        }

        let mut packet = Self::new();

        packet.op = data[0];
        packet.htype = data[1];
        packet.hlen = data[2];
        packet.hops = data[3];
        packet.xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        packet.secs = u16::from_be_bytes([data[8], data[9]]);
        packet.flags = u16::from_be_bytes([data[10], data[11]]);
        packet.ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        packet.yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        packet.siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        packet.giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
        packet.chaddr[..16].copy_from_slice(&data[28..44]);

        // Skip sname (64 bytes) and file (128 bytes), then parse options
        let options_start = 236;
        if data.len() > options_start + 4 {
            // Check magic cookie
            if data[options_start..options_start + 4] == Self::MAGIC_COOKIE {
                Self::parse_options(&mut packet, &data[options_start + 4..]);
            }
        }

        Ok(packet)
    }

    /// Parses DHCP options.
    fn parse_options(packet: &mut Self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let option_code = data[i];
            if option_code == 255 {
                // End option
                break;
            }
            if option_code == 0 {
                // Pad option
                i += 1;
                continue;
            }

            if i + 1 >= data.len() {
                break;
            }

            let option_len = data[i + 1] as usize;
            if i + 2 + option_len > data.len() {
                break;
            }

            let option_data = &data[i + 2..i + 2 + option_len];

            match option_code {
                53 if !option_data.is_empty() => {
                    // DHCP Message Type
                    packet.message_type = DhcpMessageType::try_from(option_data[0]).ok();
                }
                50 if option_data.len() >= 4 => {
                    // Requested IP Address
                    packet.requested_ip = Some(Ipv4Addr::new(
                        option_data[0],
                        option_data[1],
                        option_data[2],
                        option_data[3],
                    ));
                }
                12 => {
                    // Hostname
                    packet.hostname = String::from_utf8(option_data.to_vec()).ok();
                }
                _ => {
                    // Ignore other options
                }
            }

            i += 2 + option_len;
        }
    }

    /// Serializes the DHCP packet to bytes.
    #[must_use]
    pub fn serialize(&self, config: &DhcpConfig) -> Vec<u8> {
        let mut data = vec![0u8; 576]; // Minimum DHCP packet size

        data[0] = self.op;
        data[1] = self.htype;
        data[2] = self.hlen;
        data[3] = self.hops;
        data[4..8].copy_from_slice(&self.xid.to_be_bytes());
        data[8..10].copy_from_slice(&self.secs.to_be_bytes());
        data[10..12].copy_from_slice(&self.flags.to_be_bytes());
        data[12..16].copy_from_slice(&self.ciaddr.octets());
        data[16..20].copy_from_slice(&self.yiaddr.octets());
        data[20..24].copy_from_slice(&self.siaddr.octets());
        data[24..28].copy_from_slice(&self.giaddr.octets());
        data[28..44].copy_from_slice(&self.chaddr);

        // Magic cookie
        let mut offset = 236;
        data[offset..offset + 4].copy_from_slice(&Self::MAGIC_COOKIE);
        offset += 4;

        // Options
        // Message type
        if let Some(msg_type) = self.message_type {
            data[offset] = 53;
            data[offset + 1] = 1;
            data[offset + 2] = msg_type as u8;
            offset += 3;
        }

        // Subnet mask
        data[offset] = 1;
        data[offset + 1] = 4;
        data[offset + 2..offset + 6].copy_from_slice(&config.netmask.octets());
        offset += 6;

        // Router (gateway)
        data[offset] = 3;
        data[offset + 1] = 4;
        data[offset + 2..offset + 6].copy_from_slice(&config.gateway.octets());
        offset += 6;

        // Lease time
        let lease_secs = config.lease_duration.as_secs() as u32;
        data[offset] = 51;
        data[offset + 1] = 4;
        data[offset + 2..offset + 6].copy_from_slice(&lease_secs.to_be_bytes());
        offset += 6;

        // DHCP server identifier
        data[offset] = 54;
        data[offset + 1] = 4;
        data[offset + 2..offset + 6].copy_from_slice(&config.server_ip.octets());
        offset += 6;

        // DNS servers (cap at 63 to fit in single-byte option length)
        if !config.dns_servers.is_empty() {
            let count = config.dns_servers.len().min(63);
            let needed = offset + 2 + count * 4 + 1; // +1 for end option
            if needed > data.len() {
                data.resize(needed, 0);
            }
            data[offset] = 6;
            data[offset + 1] = (count * 4) as u8;
            offset += 2;
            for dns in config.dns_servers.iter().take(count) {
                data[offset..offset + 4].copy_from_slice(&dns.octets());
                offset += 4;
            }
        }

        // End option
        data[offset] = 255;

        data.truncate(offset + 1);
        data
    }

    /// Returns the client MAC address.
    #[must_use]
    pub fn client_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }
}

impl Default for DhcpPacket {
    fn default() -> Self {
        Self::new()
    }
}
