//! The second port in this crate: what a VM's NIC is attached to.
//!
//! [`GuestNetwork`] plans and builds the host side of a guest interface —
//! an address, a TAP or equivalent, filters — and hands the driver a
//! [`NicSpec`] to boot with. The Linux TAP adapter, the platform's IPv6
//! dataplane, and the trivial MAC-minting networks behind the VZ/HV drivers
//! all sit behind it. Cleanup after a VM is a two-step, token-guarded
//! protocol ([`NetworkReconcile`]) because host forwarding state outlives
//! the VM and must be confirmed gone before an address is reused.

use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::spec::{MacAddr, NicSpec, VmId};

/// Plans, builds, and tears down the host side of guest NICs.
#[async_trait]
pub trait GuestNetwork: Send + Sync {
    /// Reserves an address and plans host resources for `vm`; nothing is
    /// created on the host yet.
    async fn reserve(&self, vm: &VmId, policy: NetworkPolicy) -> Result<NetworkLease>;

    /// Creates the host side (TAP, filters) for `lease` and returns the NIC
    /// the driver boots with.
    async fn activate(&self, lease: &NetworkLease, mode: AttachMode) -> Result<NicSpec>;

    /// Tears the host side down but keeps the address reserved until the
    /// cleanup protocol confirms host forwarding state is gone. Idempotent.
    async fn quarantine(&self, lease: NetworkLease) -> Result<()>;

    /// Returns the address to the pool outright, skipping quarantine.
    async fn release(&self, lease: NetworkLease) -> Result<()>;

    /// The network as the guest sees it under `mode`: what goes on the
    /// kernel command line or into a net-reconfigure command.
    ///
    /// The mode is the caller's, not the lease's: a lease is reserved
    /// before anyone knows how it will be attached, and the same lease
    /// reads differently once activated as [`AttachMode::LegacySnapshot`]
    /// (the guest owns the pool address) than as [`AttachMode::Invariant`]
    /// (the address is the host's, translated per interface). Pass what
    /// [`GuestNetwork::activate`] was given.
    fn identity(&self, lease: &NetworkLease, mode: AttachMode) -> NetworkIdentity;

    /// The cleanup-token protocol and startup sweep, when the network keeps
    /// a quarantine ledger.
    fn reconcile(&self) -> Option<&dyn NetworkReconcile> {
        None
    }
}

/// What kind of connectivity a VM gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// The connectivity mode.
    pub mode: NetworkMode,
}

/// Connectivity modes a network may offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkMode {
    /// Host and guest can talk; nothing beyond the host.
    Isolated,
    /// Egress through the host's address.
    Nat,
    /// The guest appears on the host's link.
    Bridged,
}

/// How the host side is attached, for networks that keep the legacy shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Fixed guest identity with per-interface translation host-side: every
    /// fresh boot and every invariant-snapshot restore.
    Invariant,
    /// The interface carries the pool address itself: restores of
    /// checkpoints taken before the invariant identity existed.
    LegacySnapshot,
}

/// A reserved address and the host resources planned for one VM.
///
/// Serialized into the VM's durable record so cleanup can be replayed after
/// a crash; `cleanup_token` is what the two-step cleanup protocol checks.
///
/// Deliberately plain — no `#[non_exhaustive]`, because a runtime builds
/// one from a record it read back and needs every field. What that costs
/// is that the field *names* are an on-disk contract: a field added here
/// must carry `#[serde(default)]` so a record written before it still
/// loads, and nothing may key on the order they are declared in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkLease {
    /// The VM this lease belongs to.
    pub vm: VmId,
    /// The guest's address.
    pub ip: IpAddr,
    /// The subnet prefix length.
    pub prefix_len: u8,
    /// The gateway the guest routes through.
    pub gateway: IpAddr,
    /// The guest's MAC address.
    pub mac: MacAddr,
    /// Opaque; presented to [`NetworkReconcile::finalize_cleanup`] to prove
    /// the caller is finishing *this* generation of the VM's cleanup.
    pub cleanup_token: String,
}

/// The network as the guest sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIdentity {
    /// The guest's address.
    pub ip: IpAddr,
    /// The subnet prefix length.
    pub prefix_len: u8,
    /// The gateway the guest routes through.
    pub gateway: IpAddr,
    /// Resolvers the guest should use.
    pub dns: Vec<IpAddr>,
    /// The guest's MAC address.
    pub mac: MacAddr,
}

/// The quarantine ledger's cleanup protocol.
///
/// Two flows share the token discipline. Per VM: after `quarantine`, the
/// host side (forwarding rules, listeners) is cleaned by someone else, who
/// then `validate`s and `finalize`s with the lease's token; only then does
/// the address return to the pool. At startup: the network sweeps what a
/// previous process left behind and, when there is anything, mints a
/// startup token that gates the same validate/finalize pair before the
/// network declares itself settled.
#[async_trait]
pub trait NetworkReconcile: Send + Sync {
    /// VMs whose leases are quarantined, with the token each finalization
    /// must present.
    ///
    /// Fallible because a durable ledger is read back from disk: an entry
    /// whose id is not a [`VmId`] is one this protocol could never name,
    /// list, or finalize, and its address would stay out of the pool
    /// forever. The caller sees that as an error rather than as a shorter
    /// list.
    async fn pending_cleanups(&self) -> Result<Vec<(VmId, String)>>;

    /// Checks that `token` names `vm`'s pending cleanup generation.
    async fn validate_cleanup(&self, vm: &VmId, token: &str) -> Result<()>;

    /// Ends `vm`'s quarantine and returns its address to the pool.
    async fn finalize_cleanup(&self, vm: &VmId, token: &str) -> Result<()>;

    /// The token for the startup sweep's host-side cleanup, while one is
    /// pending.
    async fn startup_cleanup_token(&self) -> Option<String>;

    /// Checks that `token` names the pending startup cleanup.
    async fn validate_startup_cleanup(&self, token: &str) -> Result<()>;

    /// Marks the startup sweep's host-side cleanup done.
    async fn finalize_startup_cleanup(&self, token: &str) -> Result<()>;

    /// Waits until no startup cleanup is pending.
    async fn wait_startup_cleanup_complete(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_round_trips_through_json() {
        let lease = NetworkLease {
            vm: VmId::new("vm-1").unwrap(),
            ip: "10.200.0.2".parse().unwrap(),
            prefix_len: 16,
            gateway: "10.200.0.1".parse().unwrap(),
            mac: "02:fa:ce:00:00:02".parse().unwrap(),
            cleanup_token: "gen-1".into(),
        };
        let json = serde_json::to_string(&lease).unwrap();
        assert_eq!(serde_json::from_str::<NetworkLease>(&json).unwrap(), lease);
        assert!(json.contains("\"02:fa:ce:00:00:02\""));
        assert!(json.contains("\"10.200.0.2\""));
    }
}
