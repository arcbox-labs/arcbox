//! Boot protocol types shared between the host-side sandbox orchestrator
//! and the guest-side `vm-agent`.
//!
//! These types define the contract passed through kernel boot parameters.
//! Both sides import from this module so the encoding is defined once.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Parsed representation of the Linux kernel `ip=` boot parameter.
///
/// Format: `ip=<client>::<gateway>:<netmask>::eth0:off`
///
/// Constructed by the sandbox manager (`arcbox_vm::SandboxManager`) when
/// building boot args, and parsed by `vm-agent` to derive the DNS
/// nameserver from the gateway.
///
/// [`fmt::Display`] and [`FromStr`] round-trip through the same format so the
/// encoding is defined exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelIpParam {
    /// Guest IP address (the `<client>` field).
    pub client: Ipv4Addr,
    /// Gateway IP (also serves as the guest DNS nameserver).
    pub gateway: Ipv4Addr,
    /// Subnet mask derived from the network prefix length.
    pub netmask: Ipv4Addr,
}

impl fmt::Display for KernelIpParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ip={}::{}:{}::eth0:off",
            self.client, self.gateway, self.netmask,
        )
    }
}

impl FromStr for KernelIpParam {
    type Err = String;

    /// Parse a kernel `ip=` token (e.g. `ip=172.20.0.2::172.20.0.1:255.255.0.0::eth0:off`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = s.strip_prefix("ip=").ok_or("missing ip= prefix")?;
        let mut fields = value.split(':');

        let client = fields
            .next()
            .filter(|s| !s.is_empty())
            .ok_or("missing client field")?
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("invalid client IP: {e}"))?;

        // Skip <server> (always empty in our usage).
        fields.next();

        let gateway = fields
            .next()
            .filter(|s| !s.is_empty())
            .ok_or("missing gateway field")?
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("invalid gateway IP: {e}"))?;

        let netmask = fields
            .next()
            .filter(|s| !s.is_empty())
            .ok_or("missing netmask field")?
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("invalid netmask: {e}"))?;

        Ok(Self {
            client,
            gateway,
            netmask,
        })
    }
}

/// Network reconfiguration command sent to `vm-agent` over the exec vsock
/// channel (`MSG_NET_RECONFIG`) after a fresh-network snapshot restore.
///
/// A restored VM still carries the network the kernel configured from the
/// origin's `ip=` boot parameter; when the restore allocated a new TAP/IP
/// (`network_override`), the host sends this command so the guest
/// re-addresses `eth0`, replaces the default route, and repoints DNS at the
/// new gateway. Serialized as JSON, mirroring `StartCommand`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetReconfigCommand {
    /// New guest IP address for `eth0`.
    pub ip: Ipv4Addr,
    /// Subnet mask (e.g. 255.255.0.0).
    pub netmask: Ipv4Addr,
    /// Gateway IP (also serves as the guest DNS nameserver).
    pub gateway: Ipv4Addr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let param = KernelIpParam {
            client: Ipv4Addr::new(172, 20, 0, 2),
            gateway: Ipv4Addr::new(172, 20, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 0, 0),
        };
        let s = param.to_string();
        assert_eq!(s, "ip=172.20.0.2::172.20.0.1:255.255.0.0::eth0:off");
        assert_eq!(s.parse::<KernelIpParam>().unwrap(), param);
    }

    #[test]
    fn rejects_invalid() {
        assert!("no-prefix".parse::<KernelIpParam>().is_err());
        assert!("ip=".parse::<KernelIpParam>().is_err());
        assert!(
            "ip=bogus::1.2.3.4:255.0.0.0::eth0:off"
                .parse::<KernelIpParam>()
                .is_err()
        );
    }
}
