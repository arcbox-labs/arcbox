//! [`TapNetwork`] as the port's [`GuestNetwork`].
//!
//! Nothing here is new behavior: every method is one of the inherent
//! operations spoken in the port's vocabulary. The mapping, in one place:
//!
//! | port | inherent |
//! |------|----------|
//! | `reserve(vm, policy)` | `reserve(vm)`; the [`NetworkAllocation`] becomes a [`NetworkLease`] |
//! | `activate(lease, mode)` | `activate(alloc, mode)`; returns the TAP as a [`NicSpec`] named `eth0` |
//! | `quarantine(lease)` | `quarantine_checked(vm, alloc)` |
//! | `release(lease)` | `release_checked(alloc)` |
//! | `identity(lease)` | the invariant identity, or the pool identity for a TAP activated as `LegacySnapshot` |
//!
//! A [`NetworkLease`] carries what the port needs — VM, address, prefix,
//! gateway, MAC, cleanup token — and the allocation is rebuilt from it:
//! the TAP name is a function of the address, the resolver list is the
//! network's own. [`NetworkPolicy`]'s `Isolated` and `Nat` are the same TAP
//! shape here (egress policy is the composer's netfilter business, not the
//! link's); `Bridged` is refused at `reserve`, since a bridged attachment is
//! not something a TAP network offers.

use std::net::IpAddr;

use arcbox_vm_driver::net::{
    AttachMode, GuestNetwork, NetworkIdentity, NetworkLease, NetworkMode, NetworkPolicy,
};
use arcbox_vm_driver::{Error, NicAttachment, NicSpec, Result, VmId};
use async_trait::async_trait;

use crate::{NetworkAllocation, TapNetwork, invariant, tap_name_from_ip};

/// The device name every guest sees its one NIC under.
pub const NIC_ID: &str = "eth0";

impl TapNetwork {
    /// The mode `tap_name` was activated in by this process, if it is up.
    fn attach_mode(&self, tap_name: &str) -> Option<AttachMode> {
        self.attached.lock().unwrap().get(tap_name).copied()
    }

    /// The [`NetworkLease`] for `vm` over `allocation`.
    fn lease(vm: &VmId, allocation: &NetworkAllocation) -> NetworkLease {
        NetworkLease {
            vm: vm.clone(),
            ip: IpAddr::V4(allocation.ip_address),
            prefix_len: allocation.prefix_len,
            gateway: IpAddr::V4(allocation.gateway),
            mac: crate::mac_from_vm_id(vm.as_str()),
            cleanup_token: allocation.cleanup_token.clone(),
        }
    }

    /// The allocation `lease` stands for. The TAP name derives from the
    /// address and the resolver list is this network's; a lease carrying an
    /// IPv6 address cannot have come from here and is refused.
    fn allocation(&self, lease: &NetworkLease) -> Result<NetworkAllocation> {
        let (IpAddr::V4(ip), IpAddr::V4(gateway)) = (lease.ip, lease.gateway) else {
            return Err(Error::Network(format!(
                "lease for {} carries {} via {}; the TAP network is IPv4-only",
                lease.vm, lease.ip, lease.gateway
            )));
        };
        Ok(NetworkAllocation {
            tap_name: tap_name_from_ip(ip),
            ip_address: ip,
            prefix_len: lease.prefix_len,
            gateway,
            mac_address: lease.mac.to_string(),
            dns_servers: self.dns.clone(),
            cleanup_token: lease.cleanup_token.clone(),
        })
    }

    /// The NIC the driver boots `lease`'s VM with: `eth0`, the lease's MAC,
    /// attached to the lease's TAP.
    fn nic_spec(lease: &NetworkLease, allocation: &NetworkAllocation) -> NicSpec {
        NicSpec {
            id: NIC_ID.to_owned(),
            mac: lease.mac,
            attachment: NicAttachment::Tap {
                name: allocation.tap_name.clone(),
            },
        }
    }

    /// The network as `lease`'s guest sees it under `mode`: the fixed
    /// invariant link, or the pool address itself for a legacy-snapshot
    /// restore. The resolver is the gateway either way — the guest writes
    /// `nameserver <gateway>` from the kernel `ip=` parameter and from the
    /// reconfigure command alike.
    fn identity_for(lease: &NetworkLease, mode: AttachMode) -> NetworkIdentity {
        match mode {
            AttachMode::Invariant => NetworkIdentity {
                ip: IpAddr::V4(invariant::GUEST_IP),
                prefix_len: invariant::GUEST_PREFIX_LEN,
                gateway: IpAddr::V4(invariant::GUEST_GATEWAY),
                dns: vec![IpAddr::V4(invariant::GUEST_GATEWAY)],
                mac: lease.mac,
            },
            AttachMode::LegacySnapshot => NetworkIdentity {
                ip: lease.ip,
                prefix_len: lease.prefix_len,
                gateway: lease.gateway,
                dns: vec![lease.gateway],
                mac: lease.mac,
            },
        }
    }
}

#[async_trait]
impl GuestNetwork for TapNetwork {
    /// Reserves a pool address for `vm`. `Isolated` and `Nat` both get the
    /// point-to-point TAP; `Bridged` is refused.
    async fn reserve(&self, vm: &VmId, policy: NetworkPolicy) -> Result<NetworkLease> {
        match policy.mode {
            NetworkMode::Isolated | NetworkMode::Nat => {}
            NetworkMode::Bridged => {
                return Err(Error::Network(
                    "bridged attachment is not offered by the TAP network".into(),
                ));
            }
            other => {
                return Err(Error::Network(format!(
                    "network mode {other:?} is not offered by the TAP network"
                )));
            }
        }
        let allocation = Self::reserve(self, vm.as_str())?;
        Ok(Self::lease(vm, &allocation))
    }

    async fn activate(&self, lease: &NetworkLease, mode: AttachMode) -> Result<NicSpec> {
        let allocation = self.allocation(lease)?;
        Self::activate(self, &allocation, mode)?;
        Ok(Self::nic_spec(lease, &allocation))
    }

    async fn quarantine(&self, lease: NetworkLease) -> Result<()> {
        let allocation = self.allocation(&lease)?;
        Ok(self.quarantine_checked(lease.vm.as_str(), &allocation)?)
    }

    async fn release(&self, lease: NetworkLease) -> Result<()> {
        let allocation = self.allocation(&lease)?;
        Ok(self.release_checked(&allocation)?)
    }

    fn identity(&self, lease: &NetworkLease) -> NetworkIdentity {
        let mode = match lease.ip {
            IpAddr::V4(ip) => self
                .attach_mode(&tap_name_from_ip(ip))
                .unwrap_or(AttachMode::Invariant),
            // Not a lease of this network; there is no TAP to look up.
            IpAddr::V6(_) => AttachMode::Invariant,
        };
        Self::identity_for(lease, mode)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use arcbox_vm_driver::MacAddr;

    use super::*;

    fn v4(ip: &str) -> IpAddr {
        IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap())
    }

    fn network() -> TapNetwork {
        TapNetwork::new("172.20.0.0/16", "172.20.0.1", vec!["1.1.1.1".into()]).unwrap()
    }

    fn vm(id: &str) -> VmId {
        VmId::new(id).unwrap()
    }

    fn policy(mode: NetworkMode) -> NetworkPolicy {
        NetworkPolicy { mode }
    }

    #[tokio::test]
    async fn reserve_hands_out_a_lease_over_the_pool() {
        let network = network();
        let lease = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        assert_eq!(lease.vm, vm("box"));
        assert_eq!(lease.ip, v4("172.20.0.2"));
        assert_eq!(lease.prefix_len, 16);
        assert_eq!(lease.gateway, v4("172.20.0.1"));
        assert_eq!(lease.mac, crate::mac_from_vm_id("box"));
        assert!(lease.mac.is_unicast());
        assert!(uuid::Uuid::parse_str(&lease.cleanup_token).is_ok());

        // The next lease takes the next address; the ip decides the TAP.
        let next = GuestNetwork::reserve(&network, &vm("other"), policy(NetworkMode::Isolated))
            .await
            .unwrap();
        assert_eq!(next.ip, v4("172.20.0.3"));
        assert_ne!(next.mac, lease.mac);
    }

    #[tokio::test]
    async fn bridged_is_refused_at_reserve() {
        let network = network();
        let error = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Bridged))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Network(message) if message.contains("bridged")),
            "{error}"
        );
        // Nothing was reserved: the first address is still free.
        let lease = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        assert_eq!(lease.ip, v4("172.20.0.2"));
    }

    #[tokio::test]
    async fn lease_round_trips_through_the_allocation_and_names_the_nic() {
        let network = network();
        let lease = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        let allocation = network.allocation(&lease).unwrap();
        assert_eq!(
            allocation,
            NetworkAllocation {
                tap_name: "vmtap0-2".into(),
                ip_address: "172.20.0.2".parse().unwrap(),
                prefix_len: 16,
                gateway: "172.20.0.1".parse().unwrap(),
                mac_address: lease.mac.to_string(),
                dns_servers: vec!["1.1.1.1".into()],
                cleanup_token: lease.cleanup_token.clone(),
            }
        );
        assert_eq!(TapNetwork::lease(&vm("box"), &allocation), lease);

        let nic = TapNetwork::nic_spec(&lease, &allocation);
        assert_eq!(nic.id, NIC_ID);
        assert_eq!(nic.mac, lease.mac);
        assert_eq!(
            nic.attachment,
            NicAttachment::Tap {
                name: "vmtap0-2".into()
            }
        );
    }

    #[test]
    fn a_foreign_ipv6_lease_is_refused() {
        let network = network();
        let lease = NetworkLease {
            vm: vm("box"),
            ip: "fd00::2".parse().unwrap(),
            prefix_len: 64,
            gateway: "fd00::1".parse().unwrap(),
            mac: MacAddr::new([2, 0, 0, 0, 0, 1]),
            cleanup_token: String::new(),
        };
        let error = network.allocation(&lease).unwrap_err();
        assert!(
            matches!(&error, Error::Network(m) if m.contains("IPv4-only")),
            "{error}"
        );
        // Identity still answers — the invariant shape, which needs nothing
        // from the address.
        assert_eq!(network.identity(&lease).ip, v4("169.254.100.2"));
    }

    #[test]
    fn identity_follows_the_recorded_attach_mode() {
        let network = network();
        let lease = TapNetwork::lease(&vm("box"), &TapNetwork::reserve(&network, "box").unwrap());

        // Not activated yet: what a fresh boot gets on its command line.
        let fresh = network.identity(&lease);
        assert_eq!(fresh.ip, v4("169.254.100.2"));
        assert_eq!(fresh.prefix_len, 30);
        assert_eq!(fresh.gateway, v4("169.254.100.1"));
        assert_eq!(fresh.dns, vec![v4("169.254.100.1")]);
        assert_eq!(fresh.mac, lease.mac);

        // A legacy-snapshot restore re-addresses the guest to the pool.
        network
            .attached
            .lock()
            .unwrap()
            .insert("vmtap0-2".into(), AttachMode::LegacySnapshot);
        let legacy = network.identity(&lease);
        assert_eq!(legacy.ip, v4("172.20.0.2"));
        assert_eq!(legacy.prefix_len, 16);
        assert_eq!(legacy.gateway, v4("172.20.0.1"));
        assert_eq!(legacy.dns, vec![v4("172.20.0.1")]);
        assert_eq!(legacy.mac, lease.mac);

        network
            .attached
            .lock()
            .unwrap()
            .insert("vmtap0-2".into(), AttachMode::Invariant);
        assert_eq!(network.identity(&lease), fresh);
    }
}
