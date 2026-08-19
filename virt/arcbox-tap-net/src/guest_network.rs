//! [`TapNetwork`] as the port's [`GuestNetwork`] and [`NetworkReconcile`].
//!
//! Nothing here is new behavior: every method is one of the inherent
//! operations spoken in the port's vocabulary. The mapping, in one place:
//!
//! | port | inherent |
//! |------|----------|
//! | `reserve(vm, policy)` | `reserve(vm)`; the [`NetworkAllocation`] becomes a [`NetworkLease`] |
//! | `activate(lease, mode)` | `activate(alloc, mode)`; returns the TAP as a [`NicSpec`] named `eth0` |
//! | `adopt(lease, mode)` | `adopt(vm, alloc, mode)`; the guest is already running |
//! | `quarantine(lease)` | `quarantine_checked(vm, alloc)` |
//! | `release(lease)` | `release_checked(alloc)` |
//! | `identity(lease, mode)` | the invariant identity, or the pool identity under `LegacySnapshot` |
//! | `host_ingress(lease)` | `expose_target(tap)`, with the pool IP's fwmark |
//! | `reconcile()` | `Some(self)` while a quarantine ledger is kept |
//! | `NetworkReconcile::*` | the `*_quarantine` / `*_startup_cleanup` methods |
//! | `replay_complete()` | `mark_reconciled()` |
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
    AttachMode, GuestNetwork, HostIngress, NetworkIdentity, NetworkLease, NetworkMode,
    NetworkPolicy, NetworkReconcile,
};
use arcbox_vm_driver::{Error, NicAttachment, NicSpec, Result, VmId};
use async_trait::async_trait;

use crate::{ExposeTarget, NetworkAllocation, TapNetwork, invariant, tap_name_from_ip};

/// The device name every guest sees its one NIC under.
pub const NIC_ID: &str = "eth0";

impl TapNetwork {
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

    /// The TAP is the running guest's NIC: adoption re-establishes the
    /// host state around it and leaves the device alone.
    async fn adopt(&self, lease: &NetworkLease, mode: AttachMode) -> Result<()> {
        let allocation = self.allocation(lease)?;
        Ok(Self::adopt(self, lease.vm.as_str(), &allocation, mode)?)
    }

    async fn quarantine(&self, lease: NetworkLease) -> Result<()> {
        let allocation = self.allocation(&lease)?;
        Ok(self.quarantine_checked(lease.vm.as_str(), &allocation)?)
    }

    async fn release(&self, lease: NetworkLease) -> Result<()> {
        let allocation = self.allocation(&lease)?;
        Ok(self.release_checked(&allocation)?)
    }

    /// An IPv6 address cannot have come from this pool, so there is
    /// nothing to withhold — the same reasoning [`TapNetwork::allocation`]
    /// refuses one on, without an error to report to a caller that has no
    /// answer for it.
    fn hold_address(&self, address: IpAddr) {
        if let IpAddr::V4(ip) = address {
            Self::hold_address(self, ip);
        }
    }

    fn identity(&self, lease: &NetworkLease, mode: AttachMode) -> NetworkIdentity {
        Self::identity_for(lease, mode)
    }

    /// What the lease's TAP actually carries: an eBPF or legacy TAP takes
    /// DNAT to the pool address, an iptables one takes the fixed guest
    /// address plus the pool IP's mark, which is what selects that TAP's
    /// policy-routing table (CORE-81/CORE-83).
    ///
    /// [`TryFrom<HostIngress> for ExposeTarget`](ExposeTarget::try_from) is
    /// the inverse, for the System VM code that still names the local type.
    fn host_ingress(&self, lease: &NetworkLease) -> Result<HostIngress> {
        let allocation = self.allocation(lease)?;
        Ok(match self.expose_target(&allocation.tap_name) {
            ExposeTarget::PoolIp => HostIngress::PoolAddress,
            ExposeTarget::GuestIpWithFwmark => HostIngress::GuestAddress {
                fwmark: invariant::fwmark(allocation.ip_address),
            },
        })
    }

    fn reconcile(&self) -> Option<&dyn NetworkReconcile> {
        self.quarantine_dir.is_some().then_some(self)
    }
}

#[async_trait]
impl NetworkReconcile for TapNetwork {
    /// Every quarantined VM with its token.
    ///
    /// The error is a broken invariant rather than an expected on-disk
    /// case: every id this crate reserves or writes passes the `VmId`
    /// rules (`quarantine::validate_id`), and a marker file carrying
    /// anything else never enters the map — the load skips it, holding its
    /// address out of the pool without registering a cleanup nothing could
    /// finalize. Should one reach here anyway, the whole list fails rather
    /// than losing that one entry from it: nothing can name the entry, so
    /// nothing can finalize it, so `finalize_startup_cleanup` refuses while
    /// it sits in the map and the startup gate never opens. Dropping it
    /// would trade one loud failure for that permanent, unexplained
    /// stall.
    async fn pending_cleanups(&self) -> Result<Vec<(VmId, String)>> {
        self.pending_quarantines()
            .into_iter()
            .map(|(id, token)| {
                let vm = VmId::new(id.as_str()).map_err(|error| {
                    Error::Network(format!(
                        "quarantine ledger holds an id this port cannot name: {error}"
                    ))
                })?;
                Ok((vm, token))
            })
            .collect()
    }

    /// The ledger's own copy of the allocation, back as the lease it was.
    /// After a restart it is the only record of the address that
    /// generation held, which is what the host's cleanup matches on.
    async fn validate_cleanup(&self, vm: &VmId, token: &str) -> Result<NetworkLease> {
        let allocation = self.validate_quarantine(vm.as_str(), token)?;
        Ok(Self::lease(vm, &allocation))
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

    async fn finalize_startup_cleanup(&self, token: &str) -> Result<()> {
        Ok(Self::finalize_startup_cleanup(self, token)?)
    }

    async fn wait_startup_cleanup_complete(&self) {
        Self::wait_startup_cleanup_complete(self).await;
    }

    fn replay_complete(&self) {
        self.mark_reconciled();
    }
}

/// The port's answer as this crate's own vocabulary, for the System VM
/// code that still names [`ExposeTarget`] (R3 moves that call to the
/// composition root and this impl goes with it).
///
/// Lossy in one direction only: a mark travels with
/// [`HostIngress::GuestAddress`] and [`ExposeTarget`] has no room for it.
/// That costs nothing over *this* network, whose `host_ingress` mints the
/// mark as `invariant::fwmark(pool_ip)` — the value the System VM's
/// port-forward code derives from the pool address it is handed anyway —
/// so the round trip through here is lossless. It would cost an adapter
/// whose mark is anything else, which is why this conversion belongs to
/// the adapter that can make that promise rather than to the consumer.
impl TryFrom<HostIngress> for ExposeTarget {
    type Error = Error;

    fn try_from(ingress: HostIngress) -> Result<Self> {
        match ingress {
            HostIngress::PoolAddress => Ok(Self::PoolIp),
            HostIngress::GuestAddress { .. } => Ok(Self::GuestIpWithFwmark),
            other => Err(Error::Network(format!(
                "host ingress {other:?} has no expose target on a TAP network"
            ))),
        }
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

    /// The pool must stop offering an adopted address, or the next
    /// `reserve` puts a second sandbox on a live guest's TAP — and a
    /// refused adoption must leave it exactly as it was, since the owner's
    /// fallback is to tear that sandbox down. Off Linux, where adoption's
    /// host half has no live device to find.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn an_adopted_address_leaves_the_pool_and_a_refusal_changes_nothing() {
        // What a previous process journaled, its guest still running.
        let previous = network();
        let lease = GuestNetwork::reserve(&previous, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        assert_eq!(lease.ip, v4("172.20.0.2"));
        drop(previous);

        let restarted = network();
        GuestNetwork::adopt(&restarted, &lease, AttachMode::Invariant)
            .await
            .unwrap();
        let fresh = GuestNetwork::reserve(&restarted, &vm("other"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        assert_eq!(fresh.ip, v4("172.20.0.3"), "the adopted address is held");

        // Two records claiming one address: adopting either is a guess.
        let mut twin = lease.clone();
        twin.vm = vm("twin");
        twin.mac = crate::mac_from_vm_id("twin");
        let error = GuestNetwork::adopt(&restarted, &twin, AttachMode::Invariant)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Network(m) if m.contains("172.20.0.2")),
            "{error}"
        );
        // The refusal handed nothing back: were it to free the live
        // guest's address, the pool would offer it here.
        let next = GuestNetwork::reserve(&restarted, &vm("third"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        assert_eq!(next.ip, v4("172.20.0.4"));
    }

    /// Live or awaiting cleanup finalization, never both: a quarantined
    /// id is refused before any host work, in the class no retry fixes.
    #[tokio::test]
    async fn a_quarantined_lease_is_not_adoptable() {
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
        // The allocation a previous process journaled and this one found
        // in its ledger, awaiting the host's cleanup finalization.
        let allocation = TapNetwork::reserve(&network(), "box").unwrap();
        ledgered
            .quarantined
            .lock()
            .unwrap()
            .insert("box".to_owned(), allocation.clone());

        let lease = TapNetwork::lease(&vm("box"), &allocation);
        let error = GuestNetwork::adopt(&ledgered, &lease, AttachMode::Invariant)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::PreconditionFailed(m) if m.contains("box")),
            "{error}"
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
        assert_eq!(
            network.identity(&lease, AttachMode::Invariant).ip,
            v4("169.254.100.2")
        );
    }

    #[test]
    fn identity_follows_the_attach_mode_it_is_given() {
        let network = network();
        let lease = TapNetwork::lease(&vm("box"), &TapNetwork::reserve(&network, "box").unwrap());

        // What a fresh boot — and every invariant restore — is told.
        let fresh = network.identity(&lease, AttachMode::Invariant);
        assert_eq!(fresh.ip, v4("169.254.100.2"));
        assert_eq!(fresh.prefix_len, 30);
        assert_eq!(fresh.gateway, v4("169.254.100.1"));
        assert_eq!(fresh.dns, vec![v4("169.254.100.1")]);
        assert_eq!(fresh.mac, lease.mac);

        // A legacy-snapshot restore re-addresses the guest to the pool.
        let legacy = network.identity(&lease, AttachMode::LegacySnapshot);
        assert_eq!(legacy.ip, v4("172.20.0.2"));
        assert_eq!(legacy.prefix_len, 16);
        assert_eq!(legacy.gateway, v4("172.20.0.1"));
        assert_eq!(legacy.dns, vec![v4("172.20.0.1")]);
        assert_eq!(legacy.mac, lease.mac);
    }

    /// Host ingress follows what the lease's TAP actually carries, which
    /// is the inverse of what the guest is told under the invariant
    /// identity: the guest holds the fixed address while the host must
    /// target the pool one. No mapping from identity + lease could say
    /// that, which is why the port asks the network.
    #[tokio::test]
    async fn host_ingress_follows_the_tap_and_inverts_the_guest_identity() {
        let network = network();
        let lease = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        let tap = network.allocation(&lease).unwrap().tap_name;
        let record = |applied| {
            network.applied.lock().unwrap().insert(tap.clone(), applied);
        };

        record(crate::AppliedDatapath::Ebpf);
        assert_eq!(
            network.host_ingress(&lease).unwrap(),
            HostIngress::PoolAddress
        );
        // The guest, meanwhile, is told the fixed invariant address.
        assert_eq!(
            network.identity(&lease, AttachMode::Invariant).ip,
            v4("169.254.100.2")
        );

        record(crate::AppliedDatapath::Filter);
        assert_eq!(
            network.host_ingress(&lease).unwrap(),
            HostIngress::GuestAddress {
                fwmark: invariant::fwmark("172.20.0.2".parse().unwrap()),
            }
        );

        // A lease this network could never have handed out.
        let mut foreign = lease;
        foreign.ip = "fd00::2".parse().unwrap();
        assert!(network.host_ingress(&foreign).is_err());
    }

    /// The round trip over this network is lossless: the mark it mints is
    /// the one the System VM's port-forward code derives for itself.
    #[tokio::test]
    async fn expose_target_round_trips_through_host_ingress() {
        let network = network();
        let lease = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        let tap = network.allocation(&lease).unwrap().tap_name;
        for (applied, expected) in [
            (crate::AppliedDatapath::Ebpf, ExposeTarget::PoolIp),
            (crate::AppliedDatapath::Untranslated, ExposeTarget::PoolIp),
            (
                crate::AppliedDatapath::Filter,
                ExposeTarget::GuestIpWithFwmark,
            ),
        ] {
            network.applied.lock().unwrap().insert(tap.clone(), applied);
            let ingress = network.host_ingress(&lease).unwrap();
            assert_eq!(ExposeTarget::try_from(ingress).unwrap(), expected);
            if let HostIngress::GuestAddress { fwmark } = ingress {
                assert_eq!(fwmark, invariant::fwmark("172.20.0.2".parse().unwrap()));
            }
        }
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

    /// The loader refuses a ledger file whose id the port cannot name (see
    /// below), so this can only be reached by planting one — but the list
    /// is read from durable state, and an entry it cannot name pins an
    /// address out of the pool. Reporting it is what makes that visible;
    /// dropping it would hide the leak, and panicking would take the
    /// caller down.
    #[tokio::test]
    async fn a_ledger_id_the_port_cannot_name_is_reported() {
        let root = tempfile::tempdir().unwrap();
        let network = TapNetwork::with_quarantine_dir(
            "172.20.0.0/16",
            "172.20.0.1",
            vec![],
            root.path().join("q"),
            Datapath::default(),
            Arc::new(IptablesLegacy::default()),
        )
        .unwrap();
        let long_id = "x".repeat(VmId::MAX_LEN + 1);
        network.quarantined.lock().unwrap().insert(
            long_id.clone(),
            NetworkAllocation {
                tap_name: "vmtap0-3".into(),
                ip_address: "172.20.0.3".parse().unwrap(),
                prefix_len: 16,
                gateway: "172.20.0.1".parse().unwrap(),
                mac_address: crate::mac_from_vm_id(&long_id).to_string(),
                dns_servers: vec![],
                cleanup_token: uuid::Uuid::new_v4().to_string(),
            },
        );

        let error = network
            .reconcile()
            .unwrap()
            .pending_cleanups()
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Network(m) if m.contains("cannot name")),
            "{error}"
        );
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
        let reconcile = network.reconcile().unwrap();
        // Until the owner says it has replayed, no token finalizes the
        // sweep — what it must cover is still being discovered. The class
        // is the point: come back later, holding the very token that was
        // just refused, rather than "fetch a current one".
        assert!(matches!(
            reconcile
                .validate_startup_cleanup(&TapNetwork::startup_cleanup_token(&network).unwrap())
                .await,
            Err(Error::Unavailable(_))
        ));
        reconcile.replay_complete();
        // Once it has, a token that names no pending sweep is the other
        // answer entirely: a failed precondition no retry can satisfy.
        assert!(matches!(
            reconcile
                .validate_startup_cleanup("another-generation")
                .await,
            Err(Error::PreconditionFailed(_))
        ));
        let startup = reconcile.startup_cleanup_token().await.unwrap();
        reconcile.finalize_startup_cleanup(&startup).await.unwrap();
        assert!(reconcile.startup_cleanup_token().await.is_none());

        let lease = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        network.quarantine(lease.clone()).await.unwrap();
        assert_eq!(
            reconcile.pending_cleanups().await.unwrap(),
            vec![(vm("box"), lease.cleanup_token.clone())]
        );
        // The address stays out of the pool, and the id is refused until
        // the host finalizes — a retry-later answer, not a fault.
        assert!(matches!(
            GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat)).await,
            Err(Error::Unavailable(_))
        ));
        // A token from another generation is a failed precondition: no
        // retry of it can ever succeed.
        assert!(matches!(
            reconcile
                .validate_cleanup(&vm("box"), "wrong-generation")
                .await,
            Err(Error::PreconditionFailed(_))
        ));
        // The right token hands back the lease the ledger holds — after a
        // restart, the only surviving record of that generation's address.
        assert_eq!(
            reconcile
                .validate_cleanup(&vm("box"), &lease.cleanup_token)
                .await
                .unwrap(),
            lease
        );
        reconcile
            .finalize_cleanup(&vm("box"), &lease.cleanup_token)
            .await
            .unwrap();
        assert!(reconcile.pending_cleanups().await.unwrap().is_empty());
        let reused = GuestNetwork::reserve(&network, &vm("box"), policy(NetworkMode::Nat))
            .await
            .unwrap();
        assert_eq!(reused.ip, lease.ip);
    }

    /// The network only ever carries ids the port can name: an id past
    /// `VmId::MAX_LEN` is refused at `reserve` (before any TAP exists) with
    /// the port's own message, and a ledger file that carries one (written
    /// outside this contract, or by a build whose rules were wider) is
    /// skipped at load rather than admitted as a quarantine
    /// `NetworkReconcile` could never list or finalize. Skipped is not
    /// forgotten: the entry stays on disk and its address stays out of the
    /// pool, because a guest this process cannot name may still be on it.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn ids_the_port_cannot_name_are_refused_not_stranded() {
        let root = tempfile::tempdir().unwrap();
        let ledger = root.path().join("q");
        let network = || {
            TapNetwork::with_quarantine_dir(
                "10.0.0.0/29",
                "10.0.0.1",
                vec![],
                ledger.clone(),
                Datapath::default(),
                Arc::new(IptablesLegacy::default()),
            )
        };
        let long_id = "x".repeat(VmId::MAX_LEN + 1);
        let fresh = network().unwrap();
        fresh.mark_reconciled();
        let startup = TapNetwork::startup_cleanup_token(&fresh).unwrap();
        TapNetwork::finalize_startup_cleanup(&fresh, &startup).unwrap();
        let error = TapNetwork::reserve(&fresh, &long_id).unwrap_err();
        assert!(error.to_string().contains("exceeds 64"), "{error}");
        // Nothing was taken from the pool.
        assert_eq!(
            TapNetwork::reserve(&fresh, "box").unwrap().ip_address,
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );

        // A file from outside the contract: the ledger's shape, over-long id.
        let allocation = NetworkAllocation {
            tap_name: tap_name_from_ip("10.0.0.3".parse().unwrap()),
            ip_address: "10.0.0.3".parse().unwrap(),
            prefix_len: 29,
            gateway: "10.0.0.1".parse().unwrap(),
            mac_address: crate::mac_from_vm_id(&long_id).to_string(),
            dns_servers: vec![],
            cleanup_token: uuid::Uuid::new_v4().to_string(),
        };
        let marker = serde_json::json!({ "id": long_id, "allocation": allocation });
        std::fs::write(
            ledger.join(format!("{long_id}.json")),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        // This used to be fatal, and being fatal was the opposite of
        // useful: the load runs inside the constructor, so one marker this
        // build cannot name meant no network at all — and the ledger holds
        // host resources that still need reaping, which a host that cannot
        // construct its network never reaps. The marker is skipped, and it
        // stays on disk for a version that can name it.
        let reloaded = network().expect("an unnameable marker is skipped, not fatal");
        reloaded.mark_reconciled();
        let startup = TapNetwork::startup_cleanup_token(&reloaded).unwrap();
        TapNetwork::finalize_startup_cleanup(&reloaded, &startup)
            .expect("a skipped marker is no pending cleanup, so the gate opens");
        assert!(
            !reloaded.quarantine_pending(&long_id),
            "a skipped marker is not registered as a pending cleanup"
        );
        assert!(
            ledger.join(format!("{long_id}.json")).exists(),
            "its entry is left where a later version can read it"
        );
        // And the gate opening is exactly why the address must be withheld
        // by something else: nothing can finalize a cleanup for an id
        // nothing can name, so nothing would ever hand this address back.
        // A guest may still be on it, and `activate` would destroy the TAP
        // that address names.
        assert_eq!(
            TapNetwork::reserve(&reloaded, "box").unwrap().ip_address,
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            TapNetwork::reserve(&reloaded, "next").unwrap().ip_address,
            "10.0.0.4".parse::<Ipv4Addr>().unwrap(),
            "10.0.0.3 is the skipped marker's address and must not be reissued"
        );
    }
}
