//! [`TapNetwork`] as the port's [`GuestNetwork`] and [`NetworkReconcile`].
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
//! | `reconcile()` | `Some(self)` while a quarantine ledger is kept |
//! | `NetworkReconcile::*` | the `*_quarantine` / `*_startup_cleanup` methods |
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
    NetworkReconcile,
};
use arcbox_vm_driver::{Error, NicAttachment, NicSpec, Result, VmId};
use async_trait::async_trait;
use tracing::error;

use crate::{NetworkAllocation, TapNetError, TapNetwork, invariant, tap_name_from_ip};

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

    fn reconcile(&self) -> Option<&dyn NetworkReconcile> {
        self.quarantine_dir.is_some().then_some(self)
    }
}

impl TapNetwork {
    /// Quarantined ids the port cannot name: written by a process that
    /// predates it under a longer id budget than [`VmId`] allows. Every
    /// lease the port itself quarantines carries a `VmId`, so this is only
    /// ever legacy ledger content — finalizable through the inherent
    /// surface, invisible through the port.
    fn unnameable_quarantines(&self) -> Vec<String> {
        self.pending_quarantines()
            .into_iter()
            .filter_map(|(id, _)| VmId::new(id.as_str()).is_err().then_some(id))
            .collect()
    }
}

#[async_trait]
impl NetworkReconcile for TapNetwork {
    /// Every quarantined VM with its token. A ledger id the port cannot
    /// name is left out — and, since it keeps the startup gate closed until
    /// something else finalizes it, logged at error level.
    async fn pending_cleanups(&self) -> Vec<(VmId, String)> {
        self.pending_quarantines()
            .into_iter()
            .filter_map(|(id, token)| match VmId::new(id.as_str()) {
                Ok(vm) => Some((vm, token)),
                Err(error) => {
                    error!(
                        %id,
                        %error,
                        "quarantined network id is not a vm id: the port cannot finalize \
                         it, and the startup gate stays closed until the sandbox manager \
                         does or the ledger entry is removed"
                    );
                    None
                }
            })
            .collect()
    }

    async fn validate_cleanup(&self, vm: &VmId, token: &str) -> Result<()> {
        self.validate_quarantine(vm.as_str(), token)?;
        Ok(())
    }

    async fn finalize_cleanup(&self, vm: &VmId, token: &str) -> Result<()> {
        Ok(self.finalize_quarantine(vm.as_str(), token)?)
    }

    async fn startup_cleanup_token(&self) -> Option<String> {
        Self::startup_cleanup_token(self)
    }

    async fn validate_startup_cleanup(&self, token: &str) -> Result<()> {
        Ok(Self::validate_startup_cleanup(self, token)?)
    }

    /// Ends the startup sweep. When the inherent gate refuses because
    /// quarantines are still pending and some of them are ids the port
    /// cannot name, the error says so — the caller's own `pending_cleanups`
    /// would otherwise read empty while the gate stays shut.
    async fn finalize_startup_cleanup(&self, token: &str) -> Result<()> {
        match Self::finalize_startup_cleanup(self, token) {
            Err(TapNetError::Unavailable(message)) => {
                let unnameable = self.unnameable_quarantines();
                if unnameable.is_empty() {
                    return Err(TapNetError::Unavailable(message).into());
                }
                Err(Error::Network(format!(
                    "{message}; {} of them cannot be named through the driver port \
                     ({}) and must be finalized through the sandbox manager or removed \
                     from the quarantine ledger",
                    unnameable.len(),
                    unnameable.join(", ")
                )))
            }
            other => Ok(other?),
        }
    }

    async fn wait_startup_cleanup_complete(&self) {
        Self::wait_startup_cleanup_complete(self).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use arcbox_vm_driver::MacAddr;

    use super::*;
    use crate::{Datapath, IptablesLegacy};

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

    #[test]
    fn reconcile_is_offered_only_with_a_ledger() {
        assert!(network().reconcile().is_none());
        let root = tempfile::tempdir().unwrap();
        let ledgered = TapNetwork::with_quarantine_dir(
            "172.20.0.0/16",
            "172.20.0.1",
            vec![],
            root.path().join("q"),
            Datapath::default(),
            Arc::new(IptablesLegacy::default()),
        )
        .unwrap();
        assert!(ledgered.reconcile().is_some());
    }

    /// The token protocol through the port: quarantine, then the pending
    /// list names the lease's token, a wrong token is refused, and
    /// finalizing returns the address to the pool. Off Linux only, where
    /// quarantine touches no kernel state.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn cleanup_protocol_speaks_the_lease_token() {
        let root = tempfile::tempdir().unwrap();
        let network = TapNetwork::with_quarantine_dir(
            "10.0.0.0/30",
            "10.0.0.1",
            vec![],
            root.path().join("q"),
            Datapath::default(),
            Arc::new(IptablesLegacy::default()),
        )
        .unwrap();
        network.mark_reconciled();
        let reconcile = network.reconcile().unwrap();
        let startup = reconcile.startup_cleanup_token().await.unwrap();
        reconcile.finalize_startup_cleanup(&startup).await.unwrap();
        assert!(reconcile.startup_cleanup_token().await.is_none());

        let lease = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        network.quarantine(lease.clone()).await.unwrap();
        assert_eq!(
            reconcile.pending_cleanups().await,
            vec![(vm("box"), lease.cleanup_token.clone())]
        );
        // The address stays out of the pool, and the id stays refused.
        assert!(matches!(
            GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat)).await,
            Err(Error::Network(_))
        ));
        assert!(
            reconcile
                .validate_cleanup(&vm("box"), "wrong-generation")
                .await
                .is_err()
        );
        reconcile
            .validate_cleanup(&vm("box"), &lease.cleanup_token)
            .await
            .unwrap();
        reconcile
            .finalize_cleanup(&vm("box"), &lease.cleanup_token)
            .await
            .unwrap();
        assert!(reconcile.pending_cleanups().await.is_empty());
        let reused = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        assert_eq!(reused.ip, lease.ip);
    }

    /// A ledger written under a longer id budget than `VmId` allows (a
    /// pre-port sandbox manager) still loads and is finalizable through the
    /// inherent surface; through the port it is invisible in
    /// `pending_cleanups`, and the startup finalization names it instead of
    /// failing with a bare "generations remain pending".
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn a_ledger_id_the_port_cannot_name_is_reported_not_swallowed() {
        let root = tempfile::tempdir().unwrap();
        let ledger = root.path().join("q");
        let long_id = "x".repeat(VmId::MAX_LEN + 1);
        {
            let network = TapNetwork::with_quarantine_dir(
                "10.0.0.0/29",
                "10.0.0.1",
                vec![],
                ledger.clone(),
                Datapath::default(),
                Arc::new(IptablesLegacy::default()),
            )
            .unwrap();
            network.mark_reconciled();
            let startup = TapNetwork::startup_cleanup_token(&network).unwrap();
            TapNetwork::finalize_startup_cleanup(&network, &startup).unwrap();
            let allocation = TapNetwork::reserve(&network, &long_id).unwrap();
            network.quarantine_checked(&long_id, &allocation).unwrap();
        }

        let restarted = TapNetwork::with_quarantine_dir(
            "10.0.0.0/29",
            "10.0.0.1",
            vec![],
            ledger,
            Datapath::default(),
            Arc::new(IptablesLegacy::default()),
        )
        .unwrap();
        restarted.mark_reconciled();
        let reconcile = restarted.reconcile().unwrap();
        assert!(reconcile.pending_cleanups().await.is_empty());
        let startup = reconcile.startup_cleanup_token().await.unwrap();
        let error = reconcile
            .finalize_startup_cleanup(&startup)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Network(m) if m.contains(&long_id) && m.contains("sandbox manager")),
            "{error}"
        );

        // The inherent surface still owns it: finalize there, then the port
        // can end the startup sweep.
        let (id, token) = restarted.pending_quarantines().remove(0);
        assert_eq!(id, long_id);
        restarted.finalize_quarantine(&id, &token).unwrap();
        reconcile.finalize_startup_cleanup(&startup).await.unwrap();
    }
}
