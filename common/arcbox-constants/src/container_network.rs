//! Container address-pool configuration shared by the host and guest.

use core::fmt;
use core::net::Ipv4Addr;
use core::str::FromStr;

/// Production-compatible container address pool.
pub const DEFAULT_CONTAINER_NETWORK_CIDR: &str = "172.16.0.0/12";

const RESERVED_GUEST_NETWORKS: [(Ipv4Addr, u8, &str); 3] = [
    (Ipv4Addr::new(10, 0, 2, 0), 24, "10.0.2.0/24"),
    (Ipv4Addr::new(10, 42, 0, 0), 16, "10.42.0.0/16"),
    (Ipv4Addr::new(10, 43, 0, 0), 16, "10.43.0.0/16"),
];

/// A validated private IPv4 address pool for Docker networks.
///
/// The prefix range leaves enough space for Docker to divide the pool into
/// sixteen bridge networks while avoiding host-wide private routes such as
/// `10.0.0.0/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContainerNetwork {
    addr: Ipv4Addr,
    prefix: u8,
}

impl ContainerNetwork {
    /// Smallest supported address-pool prefix.
    pub const MIN_PREFIX: u8 = 12;

    /// Largest supported address-pool prefix.
    pub const MAX_PREFIX: u8 = 24;

    /// Creates a validated private container address pool.
    ///
    /// # Errors
    ///
    /// Returns an error when the prefix is unsupported, host bits are set, or
    /// any part of the network falls outside RFC 1918 private address space.
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, ContainerNetworkError> {
        if !(Self::MIN_PREFIX..=Self::MAX_PREFIX).contains(&prefix) {
            return Err(ContainerNetworkError::PrefixOutOfRange(prefix));
        }

        let mask = u32::MAX << (32 - prefix);
        let addr_bits = u32::from(addr);
        if addr_bits & !mask != 0 {
            return Err(ContainerNetworkError::HostBitsSet {
                given: addr,
                corrected: Ipv4Addr::from(addr_bits & mask),
                prefix,
            });
        }

        let last = Ipv4Addr::from(addr_bits | !mask);
        if !addr.is_private() || !last.is_private() {
            return Err(ContainerNetworkError::NotPrivate { addr, prefix });
        }

        if let Some((_, _, reserved)) =
            RESERVED_GUEST_NETWORKS
                .iter()
                .find(|(reserved_addr, reserved_prefix, _)| {
                    networks_overlap(addr, prefix, *reserved_addr, *reserved_prefix)
                })
        {
            return Err(ContainerNetworkError::ReservedOverlap { reserved });
        }

        Ok(Self { addr, prefix })
    }

    /// Reads the container address pool from an ArcBox kernel command line.
    ///
    /// A missing token preserves compatibility with guests booted by an older
    /// daemon. A present but invalid token is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error when `arcbox.container_network=` contains an invalid
    /// [`ContainerNetwork`].
    pub fn from_kernel_cmdline(cmdline: &str) -> Result<Self, ContainerNetworkError> {
        cmdline
            .split_whitespace()
            .find_map(|token| token.strip_prefix(crate::cmdline::CONTAINER_NETWORK_KEY))
            .map_or_else(|| Ok(Self::default()), str::parse)
    }

    /// Returns the network address.
    #[must_use]
    pub const fn addr(self) -> Ipv4Addr {
        self.addr
    }

    /// Returns the address-pool prefix length.
    #[must_use]
    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    /// Returns the prefix Docker uses for each bridge network in this pool.
    #[must_use]
    pub const fn docker_network_prefix(self) -> u8 {
        self.prefix + 4
    }

    /// Returns the gateway address assigned to Docker's default bridge.
    ///
    /// The second of the sixteen child networks is used so the production
    /// default remains `172.17.0.1/16`.
    #[must_use]
    pub fn docker_bridge_gateway(self) -> Ipv4Addr {
        let child_size = 1_u32 << (32 - self.docker_network_prefix());
        Ipv4Addr::from(u32::from(self.addr) + child_size + 1)
    }
}

fn networks_overlap(
    left_addr: Ipv4Addr,
    left_prefix: u8,
    right_addr: Ipv4Addr,
    right_prefix: u8,
) -> bool {
    let shared_prefix = left_prefix.min(right_prefix);
    let mask = u32::MAX << (32 - shared_prefix);
    u32::from(left_addr) & mask == u32::from(right_addr) & mask
}

impl Default for ContainerNetwork {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::new(172, 16, 0, 0),
            prefix: 12,
        }
    }
}

impl fmt::Display for ContainerNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for ContainerNetwork {
    type Err = ContainerNetworkError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = value
            .split_once('/')
            .ok_or(ContainerNetworkError::MissingPrefix)?;
        let addr = addr
            .parse()
            .map_err(|_| ContainerNetworkError::InvalidAddress)?;
        let prefix = prefix
            .parse()
            .map_err(|_| ContainerNetworkError::InvalidPrefix)?;
        Self::new(addr, prefix)
    }
}

/// Validation errors for [`ContainerNetwork`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerNetworkError {
    /// The CIDR omitted its `/prefix` suffix.
    MissingPrefix,
    /// The address is not valid IPv4.
    InvalidAddress,
    /// The prefix is not an unsigned integer.
    InvalidPrefix,
    /// The prefix is outside the supported address-pool range.
    PrefixOutOfRange(u8),
    /// The address is not the canonical base of the requested network.
    HostBitsSet {
        /// Address supplied by the caller.
        given: Ipv4Addr,
        /// Canonical network address for the supplied prefix.
        corrected: Ipv4Addr,
        /// Supplied prefix length.
        prefix: u8,
    },
    /// The network is not fully contained in RFC 1918 private space.
    NotPrivate {
        /// Supplied network address.
        addr: Ipv4Addr,
        /// Supplied prefix length.
        prefix: u8,
    },
    /// The network overlaps an address range reserved inside the guest.
    ReservedOverlap {
        /// Guest network that conflicts with the requested container pool.
        reserved: &'static str,
    },
}

impl fmt::Display for ContainerNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => write!(f, "container network is missing a prefix"),
            Self::InvalidAddress => write!(f, "container network has an invalid IPv4 address"),
            Self::InvalidPrefix => write!(f, "container network has an invalid prefix"),
            Self::PrefixOutOfRange(prefix) => write!(
                f,
                "container network prefix /{prefix} must be between /{} and /{}",
                ContainerNetwork::MIN_PREFIX,
                ContainerNetwork::MAX_PREFIX
            ),
            Self::HostBitsSet {
                given,
                corrected,
                prefix,
            } => write!(
                f,
                "{given}/{prefix} has host bits set; use {corrected}/{prefix}"
            ),
            Self::NotPrivate { addr, prefix } => {
                write!(f, "container network {addr}/{prefix} is not private")
            }
            Self::ReservedOverlap { reserved } => {
                write!(
                    f,
                    "container network overlaps reserved guest network {reserved}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ContainerNetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preserves_the_production_pool_and_bridge() {
        let network = ContainerNetwork::default();

        assert_eq!(network, DEFAULT_CONTAINER_NETWORK_CIDR.parse().unwrap());
        assert_eq!(network.docker_network_prefix(), 16);
        assert_eq!(
            network.docker_bridge_gateway(),
            Ipv4Addr::new(172, 17, 0, 1)
        );
    }

    #[test]
    fn custom_private_pool_derives_docker_and_route_networks() {
        let network: ContainerNetwork = "10.64.0.0/16".parse().unwrap();

        assert_eq!(network.docker_network_prefix(), 20);
        assert_eq!(
            network.docker_bridge_gateway(),
            Ipv4Addr::new(10, 64, 16, 1)
        );
    }

    #[test]
    fn invalid_pools_are_rejected_at_the_boundary() {
        assert!(matches!(
            "10.64.1.0/16".parse::<ContainerNetwork>(),
            Err(ContainerNetworkError::HostBitsSet { .. })
        ));
        assert!(matches!(
            "192.168.0.0/13".parse::<ContainerNetwork>(),
            Err(ContainerNetworkError::NotPrivate { .. })
        ));
        assert!(matches!(
            "10.0.0.0/8".parse::<ContainerNetwork>(),
            Err(ContainerNetworkError::PrefixOutOfRange(8))
        ));
        assert!(matches!(
            "10.0.0.0/25".parse::<ContainerNetwork>(),
            Err(ContainerNetworkError::PrefixOutOfRange(25))
        ));
    }

    #[test]
    fn guest_reserved_network_overlaps_are_rejected() {
        for (pool, reserved) in [
            ("10.0.2.0/24", "10.0.2.0/24"),
            ("10.0.0.0/20", "10.0.2.0/24"),
            ("10.42.1.0/24", "10.42.0.0/16"),
            ("10.32.0.0/12", "10.42.0.0/16"),
            ("10.43.0.0/16", "10.43.0.0/16"),
        ] {
            assert_eq!(
                pool.parse::<ContainerNetwork>(),
                Err(ContainerNetworkError::ReservedOverlap { reserved }),
                "{pool} should conflict with {reserved}"
            );
        }

        assert!("10.44.0.0/16".parse::<ContainerNetwork>().is_ok());
    }

    #[test]
    fn kernel_cmdline_defaults_only_when_the_token_is_absent() {
        assert_eq!(
            ContainerNetwork::from_kernel_cmdline("root=/dev/vda").unwrap(),
            ContainerNetwork::default()
        );
        assert_eq!(
            ContainerNetwork::from_kernel_cmdline(
                "root=/dev/vda arcbox.container_network=10.80.0.0/20"
            )
            .unwrap(),
            "10.80.0.0/20".parse().unwrap()
        );
        assert!(
            ContainerNetwork::from_kernel_cmdline(
                "root=/dev/vda arcbox.container_network=10.80.1.0/20"
            )
            .is_err()
        );
    }
}
