//! VPN awareness.
//!
//! This module provides VPN detection and network interface discovery.
//! It identifies active VPN connections by:
//! - Detecting common VPN interface names (utun, ppp, tun, tap, ipsec)
//! - Checking routing tables for VPN routes
//! - Identifying the VPN server endpoint

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

/// VPN interface types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VpnType {
    /// Apple/macOS native VPN (utun).
    AppleUtun,
    /// WireGuard VPN.
    WireGuard,
    /// OpenVPN (tun/tap).
    OpenVpn,
    /// IPSec VPN.
    IpSec,
    /// PPP-based VPN (PPTP, L2TP).
    Ppp,
    /// Tailscale VPN.
    Tailscale,
    /// Unknown VPN type.
    Unknown,
}

impl VpnType {
    /// Returns the typical interface name pattern for this VPN type.
    #[must_use]
    pub fn interface_pattern(&self) -> &'static str {
        match self {
            VpnType::AppleUtun | VpnType::WireGuard | VpnType::Tailscale => "utun",
            VpnType::OpenVpn => "tun",
            VpnType::IpSec => "ipsec",
            VpnType::Ppp => "ppp",
            VpnType::Unknown => "",
        }
    }
}

/// Detected VPN interface information.
#[derive(Debug, Clone)]
pub struct VpnInterface {
    /// Interface name (e.g., "utun0").
    pub name: String,
    /// VPN type.
    pub vpn_type: VpnType,
    /// IP address assigned to the interface.
    pub ip_address: Option<IpAddr>,
    /// Peer/server IP address (if known).
    pub peer_address: Option<IpAddr>,
    /// Whether this is the default route.
    pub is_default_route: bool,
}

/// VPN detector.
///
/// Detects active VPN connections on the system by examining
/// network interfaces and routing tables.
pub struct VpnDetector {
    /// Detected VPN interfaces (cached).
    interfaces: Vec<VpnInterface>,
    /// Last detection timestamp.
    last_check: Option<std::time::Instant>,
    /// Cache duration.
    cache_duration: std::time::Duration,
}

impl VpnDetector {
    /// Creates a new VPN detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
            last_check: None,
            cache_duration: std::time::Duration::from_secs(5),
        }
    }

    /// Creates a new VPN detector with custom cache duration.
    #[must_use]
    pub fn with_cache_duration(cache_duration: std::time::Duration) -> Self {
        Self {
            interfaces: Vec::new(),
            last_check: None,
            cache_duration,
        }
    }

    /// Checks if a VPN is active.
    ///
    /// This method caches the result to avoid repeated system calls.
    pub fn is_vpn_active(&mut self) -> bool {
        self.refresh_if_needed();
        !self.interfaces.is_empty()
    }

    /// Gets the primary VPN interface name.
    ///
    /// Returns the VPN interface that is the default route, or the first
    /// detected VPN interface if none is the default route.
    pub fn vpn_interface(&mut self) -> Option<String> {
        self.refresh_if_needed();

        // Prefer the interface that is the default route.
        self.interfaces
            .iter()
            .find(|i| i.is_default_route)
            .or_else(|| self.interfaces.first())
            .map(|i| i.name.clone())
    }

    /// Gets all detected VPN interfaces.
    pub fn vpn_interfaces(&mut self) -> &[VpnInterface] {
        self.refresh_if_needed();
        &self.interfaces
    }

    /// Gets the VPN server/peer IP address.
    pub fn vpn_server(&mut self) -> Option<IpAddr> {
        self.refresh_if_needed();

        self.interfaces.iter().find_map(|i| i.peer_address)
    }

    /// Forces a refresh of VPN detection.
    pub fn refresh(&mut self) {
        self.interfaces = Self::detect_vpn_interfaces();
        self.last_check = Some(std::time::Instant::now());
    }

    /// Refreshes if the cache has expired.
    fn refresh_if_needed(&mut self) {
        let needs_refresh = match self.last_check {
            None => true,
            Some(last) => last.elapsed() > self.cache_duration,
        };

        if needs_refresh {
            self.refresh();
        }
    }

    /// Detects VPN interfaces on the system.
    #[cfg(target_os = "macos")]
    fn detect_vpn_interfaces() -> Vec<VpnInterface> {
        let mut interfaces = Vec::new();

        // Get interface list from ifconfig.
        let ifconfig_output = match Command::new("ifconfig").arg("-a").output() {
            Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
            Err(_) => return interfaces,
        };

        // Get default route to identify which interface is the VPN default.
        let default_route_interface = Self::get_default_route_interface();

        // Parse ifconfig output for VPN interfaces.
        let mut current_interface: Option<String> = None;
        let mut current_ip: Option<IpAddr> = None;

        for line in ifconfig_output.lines() {
            // Interface line starts without whitespace.
            if !line.starts_with(char::is_whitespace) && line.contains(':') {
                // Save previous interface if it was a VPN.
                if let Some(name) = current_interface.take() {
                    if let Some(vpn_type) = Self::classify_interface(&name) {
                        let is_default = default_route_interface.as_ref() == Some(&name);
                        interfaces.push(VpnInterface {
                            name,
                            vpn_type,
                            ip_address: current_ip.take(),
                            peer_address: None,
                            is_default_route: is_default,
                        });
                    }
                }

                // Parse new interface name.
                if let Some(colon_pos) = line.find(':') {
                    let name = line[..colon_pos].to_string();
                    if Self::classify_interface(&name).is_some() {
                        current_interface = Some(name);
                    }
                }
                current_ip = None;
            } else if current_interface.is_some() {
                // Parse inet line for IP address.
                let trimmed = line.trim();
                if trimmed.starts_with("inet ") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                            current_ip = Some(IpAddr::V4(ip));
                        }
                    }
                }
            }
        }

        // Don't forget the last interface.
        if let Some(name) = current_interface {
            if let Some(vpn_type) = Self::classify_interface(&name) {
                let is_default = default_route_interface.as_ref() == Some(&name);
                interfaces.push(VpnInterface {
                    name,
                    vpn_type,
                    ip_address: current_ip,
                    peer_address: None,
                    is_default_route: is_default,
                });
            }
        }

        interfaces
    }

    /// Detects VPN interfaces on Linux.
    #[cfg(target_os = "linux")]
    fn detect_vpn_interfaces() -> Vec<VpnInterface> {
        let mut interfaces = Vec::new();

        // Read /sys/class/net for interface list.
        let net_dir = match std::fs::read_dir("/sys/class/net") {
            Ok(dir) => dir,
            Err(_) => return interfaces,
        };

        // Get default route interface.
        let default_route_interface = Self::get_default_route_interface();

        for entry in net_dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            if let Some(vpn_type) = Self::classify_interface(&name) {
                // Get IP address from /proc/net/fib_trie or ip command.
                let ip_address = Self::get_interface_ip_linux(&name);
                let is_default = default_route_interface.as_ref() == Some(&name);

                interfaces.push(VpnInterface {
                    name,
                    vpn_type,
                    ip_address,
                    peer_address: None,
                    is_default_route: is_default,
                });
            }
        }

        interfaces
    }

    /// Fallback for unsupported platforms.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn detect_vpn_interfaces() -> Vec<VpnInterface> {
        Vec::new()
    }

    /// Gets the default route interface.
    #[cfg(target_os = "macos")]
    fn get_default_route_interface() -> Option<String> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("interface:") {
                return trimmed
                    .strip_prefix("interface:")
                    .map(|s| s.trim().to_string());
            }
        }

        None
    }

    /// Gets the default route interface on Linux.
    #[cfg(target_os = "linux")]
    fn get_default_route_interface() -> Option<String> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse "default via X.X.X.X dev INTERFACE ..."
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(dev_idx) = parts.iter().position(|&p| p == "dev") {
                if let Some(interface) = parts.get(dev_idx + 1) {
                    return Some((*interface).to_string());
                }
            }
        }

        None
    }

    /// Fallback for unsupported platforms.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn get_default_route_interface() -> Option<String> {
        None
    }

    /// Gets the IP address of an interface on Linux.
    #[cfg(target_os = "linux")]
    fn get_interface_ip_linux(interface: &str) -> Option<IpAddr> {
        let output = Command::new("ip")
            .args(["addr", "show", interface])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                // Parse "inet X.X.X.X/prefix ..."
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip_cidr = parts[1];
                    let ip_str = ip_cidr.split('/').next()?;
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        return Some(IpAddr::V4(ip));
                    }
                }
            }
        }

        None
    }

    /// Classifies an interface name as a VPN type.
    fn classify_interface(name: &str) -> Option<VpnType> {
        // Common VPN interface patterns.
        if name.starts_with("utun") {
            // Check if it's Tailscale (usually utun with specific routing).
            // For now, just classify as AppleUtun.
            Some(VpnType::AppleUtun)
        } else if name.starts_with("tun") || name.starts_with("tap") {
            Some(VpnType::OpenVpn)
        } else if name.starts_with("ppp") {
            Some(VpnType::Ppp)
        } else if name.starts_with("ipsec") {
            Some(VpnType::IpSec)
        } else if name.starts_with("wg") {
            Some(VpnType::WireGuard)
        } else if name == "tailscale0" {
            Some(VpnType::Tailscale)
        } else {
            None
        }
    }

    /// Gets VPN-related routes.
    ///
    /// Returns a set of destination networks that are routed through VPN interfaces.
    #[must_use]
    pub fn get_vpn_routes(&self) -> HashSet<String> {
        let mut routes = HashSet::new();

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = Command::new("netstat").args(["-rn"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // Format: Destination Gateway Flags Refs Use Netif Expire
                    if parts.len() >= 6 {
                        let interface = parts[5];
                        if Self::classify_interface(interface).is_some() {
                            routes.insert(parts[0].to_string());
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("ip").args(["route"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(dev_idx) = parts.iter().position(|&p| p == "dev") {
                        if let Some(interface) = parts.get(dev_idx + 1) {
                            if Self::classify_interface(interface).is_some() {
                                if let Some(dest) = parts.first() {
                                    routes.insert((*dest).to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        routes
    }
}

impl Default for VpnDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_interface() {
        assert_eq!(
            VpnDetector::classify_interface("utun0"),
            Some(VpnType::AppleUtun)
        );
        assert_eq!(
            VpnDetector::classify_interface("utun5"),
            Some(VpnType::AppleUtun)
        );
        assert_eq!(
            VpnDetector::classify_interface("tun0"),
            Some(VpnType::OpenVpn)
        );
        assert_eq!(
            VpnDetector::classify_interface("tap0"),
            Some(VpnType::OpenVpn)
        );
        assert_eq!(VpnDetector::classify_interface("ppp0"), Some(VpnType::Ppp));
        assert_eq!(
            VpnDetector::classify_interface("wg0"),
            Some(VpnType::WireGuard)
        );
        assert_eq!(
            VpnDetector::classify_interface("tailscale0"),
            Some(VpnType::Tailscale)
        );

        // Non-VPN interfaces.
        assert_eq!(VpnDetector::classify_interface("en0"), None);
        assert_eq!(VpnDetector::classify_interface("lo0"), None);
        assert_eq!(VpnDetector::classify_interface("bridge0"), None);
    }

    #[test]
    fn test_vpn_detector_creation() {
        let detector = VpnDetector::new();
        assert!(detector.interfaces.is_empty());
        assert!(detector.last_check.is_none());
    }

    #[test]
    fn test_vpn_type_pattern() {
        assert_eq!(VpnType::AppleUtun.interface_pattern(), "utun");
        assert_eq!(VpnType::OpenVpn.interface_pattern(), "tun");
        assert_eq!(VpnType::Ppp.interface_pattern(), "ppp");
        assert_eq!(VpnType::WireGuard.interface_pattern(), "utun");
    }

    #[test]
    fn test_vpn_detection() {
        let mut detector = VpnDetector::new();

        // This test just verifies detection runs without panic.
        // Actual VPN detection depends on system state.
        let _active = detector.is_vpn_active();
        let _interface = detector.vpn_interface();
        let _interfaces = detector.vpn_interfaces();
    }

    #[test]
    fn test_cache_refresh() {
        let mut detector = VpnDetector::with_cache_duration(std::time::Duration::from_millis(10));

        // First call triggers detection.
        let _ = detector.is_vpn_active();
        assert!(detector.last_check.is_some());

        let first_check = detector.last_check;

        // Immediate second call should use cache.
        let _ = detector.is_vpn_active();
        assert_eq!(detector.last_check, first_check);

        // Wait for cache to expire.
        std::thread::sleep(std::time::Duration::from_millis(15));

        // This call should refresh.
        let _ = detector.is_vpn_active();
        assert_ne!(detector.last_check, first_check);
    }
}
