//! Built-in DHCP server.
//!
//! This module provides a simple DHCP server implementation for providing
//! IP addresses to VMs connected via TAP devices.
//!
//! The implementation supports:
//! - DHCP DISCOVER/OFFER/REQUEST/ACK flow
//! - IP address allocation and lease management
//! - DNS server and gateway configuration
//!
//! # Example
//!
//! ```no_run
//! use arcbox_net::dhcp::{DhcpServer, DhcpConfig};
//! use std::net::Ipv4Addr;
//!
//! let config = DhcpConfig::new(
//!     Ipv4Addr::new(192, 168, 64, 1),
//!     Ipv4Addr::new(255, 255, 255, 0),
//! );
//!
//! let mut server = DhcpServer::new(config);
//! // server.start("arcbox0").await.unwrap();
//! ```

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::error::{NetError, Result};
use crate::nat::IpAllocator;

/// Default DHCP lease duration (24 hours).
pub const DEFAULT_LEASE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// DHCP server port.
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port.
pub const DHCP_CLIENT_PORT: u16 = 68;

/// DHCP configuration.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Server IP address (usually the gateway).
    pub server_ip: Ipv4Addr,
    /// Subnet mask.
    pub netmask: Ipv4Addr,
    /// Gateway address (defaults to server_ip).
    pub gateway: Ipv4Addr,
    /// DNS servers.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Lease duration.
    pub lease_duration: Duration,
    /// DHCP pool start.
    pub pool_start: Ipv4Addr,
    /// DHCP pool end.
    pub pool_end: Ipv4Addr,
    /// Domain name.
    pub domain_name: Option<String>,
}

impl DhcpConfig {
    /// Creates a new DHCP configuration.
    #[must_use]
    pub fn new(server_ip: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        // Calculate default pool range (server_ip + 1 to server_ip + 253)
        let server_u32 = u32::from(server_ip);
        let pool_start = Ipv4Addr::from(server_u32 + 1);
        let pool_end = Ipv4Addr::from(server_u32 + 253);

        Self {
            server_ip,
            netmask,
            gateway: server_ip,
            dns_servers: vec![server_ip], // Default to gateway as DNS
            lease_duration: DEFAULT_LEASE_DURATION,
            pool_start,
            pool_end,
            domain_name: None,
        }
    }

    /// Sets the gateway address.
    #[must_use]
    pub fn with_gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway = gateway;
        self
    }

    /// Sets the DNS servers.
    #[must_use]
    pub fn with_dns_servers(mut self, servers: Vec<Ipv4Addr>) -> Self {
        self.dns_servers = servers;
        self
    }

    /// Sets the lease duration.
    #[must_use]
    pub fn with_lease_duration(mut self, duration: Duration) -> Self {
        self.lease_duration = duration;
        self
    }

    /// Sets the address pool range.
    #[must_use]
    pub fn with_pool_range(mut self, start: Ipv4Addr, end: Ipv4Addr) -> Self {
        self.pool_start = start;
        self.pool_end = end;
        self
    }

    /// Sets the domain name.
    #[must_use]
    pub fn with_domain_name(mut self, name: impl Into<String>) -> Self {
        self.domain_name = Some(name.into());
        self
    }
}

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

/// DHCP lease information.
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// Client MAC address.
    pub mac: [u8; 6],
    /// Assigned IP address.
    pub ip: Ipv4Addr,
    /// Client hostname (if provided).
    pub hostname: Option<String>,
    /// Lease start time.
    pub lease_start: Instant,
    /// Lease duration.
    pub lease_duration: Duration,
}

impl DhcpLease {
    /// Checks if the lease has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.lease_start.elapsed() >= self.lease_duration
    }

    /// Returns the time remaining on the lease.
    #[must_use]
    pub fn time_remaining(&self) -> Duration {
        let elapsed = self.lease_start.elapsed();
        if elapsed >= self.lease_duration {
            Duration::ZERO
        } else {
            self.lease_duration - elapsed
        }
    }
}

/// DHCP packet.
///
/// This is a simplified representation of a DHCP packet.
/// The actual wire format is more complex.
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
            return Err(NetError::Dhcp("packet too short".to_string()));
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
                Self::parse_options(&mut packet, &data[options_start + 4..])?;
            }
        }

        Ok(packet)
    }

    /// Parses DHCP options.
    fn parse_options(packet: &mut DhcpPacket, data: &[u8]) -> Result<()> {
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
                53 => {
                    // DHCP Message Type
                    if !option_data.is_empty() {
                        packet.message_type = DhcpMessageType::try_from(option_data[0]).ok();
                    }
                }
                50 => {
                    // Requested IP Address
                    if option_data.len() >= 4 {
                        packet.requested_ip = Some(Ipv4Addr::new(
                            option_data[0],
                            option_data[1],
                            option_data[2],
                            option_data[3],
                        ));
                    }
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

        Ok(())
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

        // DNS servers
        if !config.dns_servers.is_empty() {
            data[offset] = 6;
            data[offset + 1] = (config.dns_servers.len() * 4) as u8;
            offset += 2;
            for dns in &config.dns_servers {
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

/// DHCP server.
///
/// Provides IP addresses to clients via the DHCP protocol.
pub struct DhcpServer {
    /// Server configuration.
    config: DhcpConfig,
    /// IP address allocator.
    allocator: IpAllocator,
    /// Active leases (MAC -> Lease).
    leases: HashMap<[u8; 6], DhcpLease>,
    /// IP reservations (MAC -> IP).
    reservations: HashMap<[u8; 6], Ipv4Addr>,
}

impl DhcpServer {
    /// Creates a new DHCP server.
    #[must_use]
    pub fn new(config: DhcpConfig) -> Self {
        let allocator = IpAllocator::new(config.pool_start, config.pool_end);

        Self {
            config,
            allocator,
            leases: HashMap::new(),
            reservations: HashMap::new(),
        }
    }

    /// Returns the server IP.
    #[must_use]
    pub fn server_ip(&self) -> Ipv4Addr {
        self.config.server_ip
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &DhcpConfig {
        &self.config
    }

    /// Returns active leases.
    #[must_use]
    pub fn leases(&self) -> &HashMap<[u8; 6], DhcpLease> {
        &self.leases
    }

    /// Reserves an IP address for a specific MAC.
    pub fn reserve_ip(&mut self, mac: [u8; 6], ip: Ipv4Addr) {
        self.reservations.insert(mac, ip);
        self.allocator.allocate_specific(ip);
    }

    /// Removes an IP reservation.
    pub fn remove_reservation(&mut self, mac: &[u8; 6]) {
        if let Some(ip) = self.reservations.remove(mac) {
            self.allocator.release(ip);
        }
    }

    /// Handles an incoming DHCP packet.
    ///
    /// Returns the response packet if one should be sent.
    ///
    /// # Errors
    ///
    /// Returns an error if packet processing fails.
    pub fn handle_packet(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let packet = DhcpPacket::parse(data)?;

        // Only handle BOOTREQUEST (client -> server)
        if packet.op != 1 {
            return Ok(None);
        }

        let response = match packet.message_type {
            Some(DhcpMessageType::Discover) => Some(self.handle_discover(&packet)?),
            Some(DhcpMessageType::Request) => Some(self.handle_request(&packet)?),
            Some(DhcpMessageType::Release) => {
                self.handle_release(&packet)?;
                None
            }
            Some(DhcpMessageType::Decline) => {
                self.handle_decline(&packet)?;
                None
            }
            _ => None,
        };

        Ok(response)
    }

    /// Handles DHCPDISCOVER.
    fn handle_discover(&mut self, packet: &DhcpPacket) -> Result<Vec<u8>> {
        let mac = packet.client_mac();

        // Clean up expired leases
        self.cleanup_expired_leases();

        // Check for reservation
        let ip = if let Some(&reserved_ip) = self.reservations.get(&mac) {
            reserved_ip
        } else if let Some(lease) = self.leases.get(&mac) {
            // Existing lease
            lease.ip
        } else if let Some(requested) = packet.requested_ip {
            // Try to honor requested IP
            if self.allocator.is_available(requested) {
                self.allocator.allocate_specific(requested);
                requested
            } else {
                self.allocator
                    .allocate()
                    .ok_or_else(|| NetError::Dhcp("no IP addresses available".to_string()))?
            }
        } else {
            // Allocate new IP
            self.allocator
                .allocate()
                .ok_or_else(|| NetError::Dhcp("no IP addresses available".to_string()))?
        };

        // Create OFFER response
        let mut response = DhcpPacket::new();
        response.op = 2; // BOOTREPLY
        response.xid = packet.xid;
        response.yiaddr = ip;
        response.siaddr = self.config.server_ip;
        response.flags = packet.flags;
        response.chaddr = packet.chaddr;
        response.message_type = Some(DhcpMessageType::Offer);

        tracing::debug!(
            "DHCPOFFER: {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            ip,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );

        Ok(response.serialize(&self.config))
    }

    /// Handles DHCPREQUEST.
    fn handle_request(&mut self, packet: &DhcpPacket) -> Result<Vec<u8>> {
        let mac = packet.client_mac();
        let requested_ip = packet
            .requested_ip
            .or_else(|| {
                if packet.ciaddr != Ipv4Addr::UNSPECIFIED {
                    Some(packet.ciaddr)
                } else {
                    None
                }
            })
            .ok_or_else(|| NetError::Dhcp("no IP requested".to_string()))?;

        // Verify the IP is available or already leased to this client
        let valid = if let Some(lease) = self.leases.get(&mac) {
            lease.ip == requested_ip
        } else if let Some(&reserved) = self.reservations.get(&mac) {
            reserved == requested_ip
        } else {
            self.allocator.is_available(requested_ip) || {
                // Check if we can allocate it
                self.allocator.allocate_specific(requested_ip)
            }
        };

        if !valid {
            // Send NAK
            let mut response = DhcpPacket::new();
            response.op = 2;
            response.xid = packet.xid;
            response.siaddr = self.config.server_ip;
            response.flags = packet.flags;
            response.chaddr = packet.chaddr;
            response.message_type = Some(DhcpMessageType::Nak);

            tracing::debug!(
                "DHCPNAK: {} denied for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                requested_ip,
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );

            return Ok(response.serialize(&self.config));
        }

        // Create or update lease
        let lease = DhcpLease {
            mac,
            ip: requested_ip,
            hostname: packet.hostname.clone(),
            lease_start: Instant::now(),
            lease_duration: self.config.lease_duration,
        };
        self.leases.insert(mac, lease);

        // Create ACK response
        let mut response = DhcpPacket::new();
        response.op = 2;
        response.xid = packet.xid;
        response.yiaddr = requested_ip;
        response.siaddr = self.config.server_ip;
        response.flags = packet.flags;
        response.chaddr = packet.chaddr;
        response.message_type = Some(DhcpMessageType::Ack);

        tracing::debug!(
            "DHCPACK: {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            requested_ip,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );

        Ok(response.serialize(&self.config))
    }

    /// Handles DHCPRELEASE.
    fn handle_release(&mut self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.client_mac();

        if let Some(lease) = self.leases.remove(&mac) {
            // Don't release reserved IPs
            if !self.reservations.contains_key(&mac) {
                self.allocator.release(lease.ip);
            }

            tracing::debug!(
                "DHCPRELEASE: {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                lease.ip,
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
        }

        Ok(())
    }

    /// Handles DHCPDECLINE.
    fn handle_decline(&mut self, packet: &DhcpPacket) -> Result<()> {
        // Client is saying the IP is already in use
        // We should mark it as unavailable
        if let Some(ip) = packet.requested_ip {
            self.allocator.allocate_specific(ip);

            tracing::warn!("DHCPDECLINE: {} reported as in use", ip);
        }

        Ok(())
    }

    /// Cleans up expired leases.
    pub fn cleanup_expired_leases(&mut self) {
        let expired: Vec<[u8; 6]> = self
            .leases
            .iter()
            .filter(|(mac, lease)| lease.is_expired() && !self.reservations.contains_key(*mac))
            .map(|(mac, _)| *mac)
            .collect();

        for mac in expired {
            if let Some(lease) = self.leases.remove(&mac) {
                self.allocator.release(lease.ip);
                tracing::debug!("Expired lease for {}", lease.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_config_new() {
        let config = DhcpConfig::new(
            Ipv4Addr::new(192, 168, 64, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        );

        assert_eq!(config.server_ip, Ipv4Addr::new(192, 168, 64, 1));
        assert_eq!(config.gateway, Ipv4Addr::new(192, 168, 64, 1));
        assert_eq!(config.pool_start, Ipv4Addr::new(192, 168, 64, 2));
    }

    #[test]
    fn test_dhcp_message_type_conversion() {
        assert_eq!(DhcpMessageType::try_from(1), Ok(DhcpMessageType::Discover));
        assert_eq!(DhcpMessageType::try_from(5), Ok(DhcpMessageType::Ack));
        assert!(DhcpMessageType::try_from(100).is_err());
    }

    #[test]
    fn test_dhcp_lease_expiration() {
        let lease = DhcpLease {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            ip: Ipv4Addr::new(192, 168, 64, 2),
            hostname: None,
            lease_start: Instant::now(),
            lease_duration: Duration::from_secs(1),
        };

        assert!(!lease.is_expired());
        assert!(lease.time_remaining() > Duration::ZERO);
    }

    #[test]
    fn test_dhcp_server_reservation() {
        let config = DhcpConfig::new(
            Ipv4Addr::new(192, 168, 64, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        let mut server = DhcpServer::new(config);

        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ip = Ipv4Addr::new(192, 168, 64, 100);

        server.reserve_ip(mac, ip);
        assert!(!server.allocator.is_available(ip));

        server.remove_reservation(&mac);
        assert!(server.allocator.is_available(ip));
    }
}
