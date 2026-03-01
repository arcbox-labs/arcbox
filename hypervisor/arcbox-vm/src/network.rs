use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::error::{Result, VmmError};

/// Result of allocating network resources for a single VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAllocation {
    /// TAP interface name (e.g. `vmtap0`).
    pub tap_name: String,
    /// IP address assigned to the guest.
    pub ip_address: Ipv4Addr,
    /// Gateway IP.
    pub gateway: Ipv4Addr,
    /// MAC address (deterministic from VM ID).
    pub mac_address: String,
    /// DNS servers.
    pub dns_servers: Vec<String>,
}

/// Shared manager for TAP interfaces and guest IP addresses.
pub struct NetworkManager {
    /// Bridge interface name.
    #[allow(dead_code)]
    bridge: String,
    /// Base IP from which the pool starts (host-octet 2 onwards).
    base: Ipv4Addr,
    /// Network prefix length (e.g. 16 for /16).
    prefix_len: u8,
    /// Gateway IP.
    gateway: Ipv4Addr,
    /// DNS servers.
    dns: Vec<String>,
    /// Set of already-allocated guest IPs.
    allocated: Mutex<HashSet<u32>>,
}

impl NetworkManager {
    /// Create a new manager from the network configuration.
    ///
    /// `cidr` must be in `a.b.c.d/n` notation (e.g. `"172.20.0.0/16"`).
    pub fn new(bridge: &str, cidr: &str, gateway: &str, dns: Vec<String>) -> Result<Self> {
        let (base, prefix_len) = parse_cidr(cidr)?;
        if !(1..=30).contains(&prefix_len) {
            return Err(VmmError::Network(format!(
                "prefix length {prefix_len} out of range 1–30"
            )));
        }
        let gateway = gateway
            .parse::<Ipv4Addr>()
            .map_err(|e| VmmError::Network(format!("invalid gateway: {e}")))?;

        Ok(Self {
            bridge: bridge.to_owned(),
            base,
            prefix_len,
            gateway,
            dns,
            allocated: Mutex::new(HashSet::new()),
        })
    }

    /// Allocate a TAP interface and guest IP for `vm_id`.
    ///
    /// On Linux this creates a real TAP device and attaches it to the bridge.
    /// The call is best-effort on non-Linux platforms (tests / macOS CI).
    pub fn allocate(&self, vm_id: &str) -> Result<NetworkAllocation> {
        let ip = self.next_ip()?;
        let tap_name = tap_name_from_ip(ip);
        let mac = mac_from_vm_id(vm_id);

        info!(vm_id, tap = %tap_name, ip = %ip, "allocating network");

        #[cfg(target_os = "linux")]
        if let Err(e) = self.create_tap(&tap_name) {
            self.allocated.lock().unwrap().remove(&u32::from(ip));
            return Err(e);
        }

        Ok(NetworkAllocation {
            tap_name,
            ip_address: ip,
            gateway: self.gateway,
            mac_address: mac,
            dns_servers: self.dns.clone(),
        })
    }

    /// Release the TAP interface and guest IP associated with `vm_id`.
    pub fn release(&self, alloc: &NetworkAllocation) {
        let ip_int = u32::from(alloc.ip_address);
        self.allocated.lock().unwrap().remove(&ip_int);

        debug!(tap = %alloc.tap_name, ip = %alloc.ip_address, "releasing network");

        #[cfg(target_os = "linux")]
        let _ = destroy_tap(&alloc.tap_name);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    fn next_ip(&self) -> Result<Ipv4Addr> {
        // prefix_len is validated to 1..=30 in new(), so shifts are safe.
        let host_bits = 32 - u32::from(self.prefix_len);
        let mask = !((1u32 << host_bits) - 1);
        let host_max = (1u32 << host_bits) - 2; // excludes network address (0) and broadcast

        // Mask away any host bits so arithmetic stays within the subnet.
        let network_base = u32::from(self.base) & mask;

        let mut allocated = self.allocated.lock().unwrap();
        // offset 0 = network address, 1 = gateway; start at 2.
        for offset in 2..=host_max {
            let candidate = network_base + offset;
            if !allocated.contains(&candidate) {
                allocated.insert(candidate);
                return Ok(Ipv4Addr::from(candidate));
            }
        }
        Err(VmmError::Network("IP pool exhausted".into()))
    }

    #[cfg(target_os = "linux")]
    fn create_tap(&self, tap_name: &str) -> Result<()> {
        use std::process::Command;

        // Remove any stale TAP left over from a previous crashed run.
        let _ = Command::new("/usr/sbin/ip")
            .args(["link", "delete", tap_name])
            .status();

        // Create TAP interface
        let status = Command::new("/usr/sbin/ip")
            .args(["tuntap", "add", tap_name, "mode", "tap"])
            .status()
            .map_err(|e| VmmError::Network(format!("ip tuntap add: {e}")))?;
        if !status.success() {
            return Err(VmmError::Network(format!(
                "failed to create TAP {tap_name}"
            )));
        }

        // Bring up
        let _ = Command::new("/usr/sbin/ip")
            .args(["link", "set", tap_name, "up"])
            .status();

        // Attach to bridge
        if !self.bridge.is_empty() {
            let _ = Command::new("/usr/sbin/ip")
                .args(["link", "set", tap_name, "master", &self.bridge])
                .status();
        }

        Ok(())
    }
}

// =============================================================================
// Platform helpers
// =============================================================================

#[cfg(target_os = "linux")]
fn destroy_tap(tap_name: &str) {
    use std::process::Command;
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "delete", tap_name])
        .status();
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(VmmError::Network(format!("invalid CIDR: {cidr}")));
    }
    let addr = parts[0]
        .parse::<Ipv4Addr>()
        .map_err(|e| VmmError::Network(format!("invalid CIDR address: {e}")))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|e| VmmError::Network(format!("invalid prefix length: {e}")))?;
    Ok((addr, prefix))
}

fn tap_name_from_ip(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    // Encode last two octets with a delimiter to keep name short and unambiguous.
    format!("vmtap{}-{}", octets[2], octets[3])
}

fn mac_from_vm_id(vm_id: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    vm_id.hash(&mut hasher);
    let h = hasher.finish();
    // Locally administered, unicast: set bit 1 of first octet, clear bit 0.
    let b: [u8; 6] = [
        0x02 | (((h >> 40) & 0xfe) as u8),
        ((h >> 32) & 0xff) as u8,
        ((h >> 24) & 0xff) as u8,
        ((h >> 16) & 0xff) as u8,
        ((h >> 8) & 0xff) as u8,
        (h & 0xff) as u8,
    ];
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_sequential_ips() {
        let mgr = NetworkManager::new("fcvmm0", "172.20.0.0/16", "172.20.0.1", vec![]).unwrap();
        let a1 = mgr.allocate("vm-1").unwrap();
        let a2 = mgr.allocate("vm-2").unwrap();
        assert_ne!(a1.ip_address, a2.ip_address);
    }

    #[test]
    fn test_release_returns_ip_to_pool() {
        let mgr = NetworkManager::new("fcvmm0", "172.20.0.0/16", "172.20.0.1", vec![]).unwrap();
        let a1 = mgr.allocate("vm-1").unwrap();
        let first_ip = a1.ip_address;
        mgr.release(&a1);
        let a2 = mgr.allocate("vm-1").unwrap();
        assert_eq!(a2.ip_address, first_ip);
    }

    #[test]
    fn test_mac_deterministic() {
        assert_eq!(mac_from_vm_id("abc"), mac_from_vm_id("abc"));
        assert_ne!(mac_from_vm_id("abc"), mac_from_vm_id("xyz"));
    }

    #[test]
    fn test_invalid_prefix_len_rejected() {
        assert!(NetworkManager::new("br0", "10.0.0.0/0", "10.0.0.1", vec![]).is_err());
        assert!(NetworkManager::new("br0", "10.0.0.0/31", "10.0.0.1", vec![]).is_err());
        assert!(NetworkManager::new("br0", "10.0.0.0/32", "10.0.0.1", vec![]).is_err());
        assert!(NetworkManager::new("br0", "10.0.0.0/24", "10.0.0.1", vec![]).is_ok());
    }

    #[test]
    fn test_next_ip_respects_subnet_boundary() {
        // /30 has exactly 2 host addresses (.1 gateway, .2 first usable)
        let mgr = NetworkManager::new("br0", "10.0.0.0/30", "10.0.0.1", vec![]).unwrap();
        let a = mgr.allocate("vm-1").unwrap();
        assert_eq!(a.ip_address, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        // Pool is now exhausted
        assert!(mgr.allocate("vm-2").is_err());
    }
}
