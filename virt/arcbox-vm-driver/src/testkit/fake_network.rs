//! An in-memory [`GuestNetwork`] with a quarantine ledger.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use tokio::sync::watch;

use super::lock;
use crate::error::{Error, Result};
use crate::net::{
    AttachMode, GuestNetwork, HostIngress, NetworkIdentity, NetworkLease, NetworkPolicy,
    NetworkReconcile,
};
use crate::spec::{MacAddr, NicAttachment, NicSpec, VmId};

/// An in-memory guest network.
///
/// Leases come from `10.200.0.0/16` (gateway `10.200.0.1`, lowest free host
/// number first, so a released address is reused); `activate` returns a
/// `NicSpec` on `tapN`; `quarantine` moves a lease into a ledger that
/// [`NetworkReconcile`] drains through the token protocol.
/// [`FakeNetwork::with_startup_cleanup`] starts with a pending startup
/// cleanup so that half of the protocol can be exercised too — including
/// its ordering: until [`NetworkReconcile::replay_complete`] says the
/// owner has finished replaying, no token names a finalizable sweep.
/// `adopt` is the third way a lease becomes live;
/// [`FakeNetwork::fail_adopt_once`] scripts the refusal to fall back from.
///
/// It answers that protocol in the same error *classes* a real adapter
/// does — [`Error::Unavailable`] for come-back-later (a pending startup
/// sweep, which closes the whole pool; a quarantined id; a gate still held
/// by pending generations) and [`Error::PreconditionFailed`] for a token
/// naming no pending generation.
/// A caller's retry and precondition handling is therefore testable over
/// this fake; flattening either into [`Error::Network`] would make a
/// broken path look fine here and fail against the TAP network.
pub struct FakeNetwork {
    ledger: Mutex<Ledger>,
    /// `true` while a startup cleanup is pending.
    startup_pending: watch::Sender<bool>,
    /// Scripted failure, armed once and consumed by the next `adopt`.
    fail_adopt: AtomicBool,
}

#[derive(Default)]
struct Ledger {
    /// Host numbers in use, active or quarantined.
    used: BTreeSet<u16>,
    active: HashMap<VmId, NetworkLease>,
    /// The mode each adopted lease was originally activated in.
    adopted: HashMap<VmId, AttachMode>,
    quarantined: HashMap<VmId, NetworkLease>,
    startup: Option<StartupCleanup>,
    minted: u64,
}

struct StartupCleanup {
    token: String,
    host_cleaned: bool,
    /// `true` once the owner said it had replayed its durable state into
    /// this ledger; until then no token names a finalizable sweep.
    replayed: bool,
}

const PREFIX_LEN: u8 = 16;
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
/// Host numbers below this are the network and gateway addresses.
const FIRST_HOST: u16 = 2;

impl FakeNetwork {
    /// A network with nothing pending.
    pub fn new() -> Self {
        Self::build(None)
    }

    /// A network whose startup sweep found leftovers: `token` gates the
    /// startup cleanup and `wait_startup_cleanup_complete` blocks until it
    /// is finalized.
    pub fn with_startup_cleanup(token: impl Into<String>) -> Self {
        Self::build(Some(StartupCleanup {
            token: token.into(),
            host_cleaned: false,
            replayed: false,
        }))
    }

    fn build(startup: Option<StartupCleanup>) -> Self {
        let pending = startup.is_some();
        Self {
            ledger: Mutex::new(Ledger {
                startup,
                ..Ledger::default()
            }),
            startup_pending: watch::Sender::new(pending),
            fail_adopt: AtomicBool::new(false),
        }
    }

    /// Arms a scripted failure: the next [`GuestNetwork::adopt`] fails
    /// and changes nothing — an adapter that cannot re-establish the host
    /// state its guest needs, which the owner must answer by tearing the
    /// VM down rather than keeping a live but unreachable one.
    pub fn fail_adopt_once(&self) {
        self.fail_adopt.store(true, Ordering::Release);
    }

    /// The mode `vm`'s lease was adopted in, if it was adopted.
    pub fn adopted_mode(&self, vm: &VmId) -> Option<AttachMode> {
        lock(&self.ledger).adopted.get(vm).copied()
    }

    fn set_startup_pending(&self, ledger: &Ledger) {
        self.startup_pending.send_replace(ledger.startup_pending());
    }
}

impl Default for FakeNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl Ledger {
    /// `true` while the startup sweep's host-side cleanup is pending —
    /// the gate that closes the whole pool.
    fn startup_pending(&self) -> bool {
        self.startup.as_ref().is_some_and(|s| !s.host_cleaned)
    }

    fn lowest_free_host(&self) -> Option<u16> {
        (FIRST_HOST..u16::MAX).find(|n| !self.used.contains(n))
    }

    /// The error for a lease that is not the VM's current one — an older
    /// generation, or one whose address has since been handed to another VM.
    fn stale(&self, lease: &NetworkLease) -> Error {
        let other_holder = self
            .active
            .iter()
            .chain(self.quarantined.iter())
            .find(|(vm, held)| **vm != lease.vm && held.ip == lease.ip)
            .map(|(vm, _)| vm);
        match other_holder {
            Some(vm) => Error::Network(format!(
                "vm {} lease {} is stale: {} is now held by vm {vm}",
                lease.vm, lease.cleanup_token, lease.ip
            )),
            None => Error::Network(format!(
                "vm {} lease {} is not its current lease",
                lease.vm, lease.cleanup_token
            )),
        }
    }
}

fn host_number(ip: IpAddr) -> Result<u16> {
    match ip {
        IpAddr::V4(v4) if v4.octets()[..2] == [10, 200] => {
            let [_, _, hi, lo] = v4.octets();
            Ok(u16::from_be_bytes([hi, lo]))
        }
        other => Err(Error::Network(format!(
            "{other} is not a fake-network address (10.200.0.0/16)"
        ))),
    }
}

#[async_trait]
impl GuestNetwork for FakeNetwork {
    async fn reserve(&self, vm: &VmId, _policy: NetworkPolicy) -> Result<NetworkLease> {
        let mut ledger = lock(&self.ledger);
        // While the startup sweep is pending the *whole* pool is closed,
        // not just the ids in it: the host has yet to confirm that the
        // forwarding state of a previous process is gone.
        if ledger.startup_pending() {
            return Err(Error::Unavailable(
                "startup cleanup is awaiting host finalization".into(),
            ));
        }
        // A quarantined id is the protocol's retry-later case too: the
        // address comes back once the host finalizes that generation.
        if ledger.quarantined.contains_key(vm) {
            return Err(Error::Unavailable(format!(
                "vm {vm} cleanup is awaiting host finalization"
            )));
        }
        if ledger.active.contains_key(vm) {
            return Err(Error::Network(format!("vm {vm} already holds a lease")));
        }
        let host = ledger
            .lowest_free_host()
            .ok_or_else(|| Error::Network("fake network address pool exhausted".into()))?;
        ledger.used.insert(host);
        ledger.minted += 1;
        let [hi, lo] = host.to_be_bytes();
        let lease = NetworkLease {
            vm: vm.clone(),
            ip: IpAddr::V4(Ipv4Addr::new(10, 200, hi, lo)),
            prefix_len: PREFIX_LEN,
            gateway: IpAddr::V4(GATEWAY),
            mac: MacAddr::new([0x02, 0xfa, 0xce, 0x00, hi, lo]),
            cleanup_token: format!("fake-cleanup-{}", ledger.minted),
        };
        ledger.active.insert(vm.clone(), lease.clone());
        Ok(lease)
    }

    async fn activate(&self, lease: &NetworkLease, _mode: AttachMode) -> Result<NicSpec> {
        let ledger = lock(&self.ledger);
        if ledger.quarantined.contains_key(&lease.vm) {
            return Err(Error::Network(format!(
                "vm {} lease is quarantined; reserve a new one",
                lease.vm
            )));
        }
        let reserved = ledger
            .active
            .get(&lease.vm)
            .ok_or_else(|| Error::NotFound(lease.vm.clone()))?;
        if reserved != lease {
            return Err(Error::Network(format!(
                "vm {} lease does not match the one reserved",
                lease.vm
            )));
        }
        let host = host_number(lease.ip)?;
        Ok(NicSpec {
            id: "eth0".into(),
            mac: lease.mac,
            attachment: NicAttachment::Tap {
                name: format!("tap{host}"),
            },
        })
    }

    /// Re-registers `lease` as live. Nothing here dies with a process, so
    /// adoption is bookkeeping only: the address leaves the pool as
    /// `reserve` takes it, and the mode is recorded
    /// ([`FakeNetwork::adopted_mode`]). Its refusals are a real adapter's,
    /// each saying the durable record cannot be true — a lease of another
    /// network, one awaiting cleanup finalization (live or quarantined,
    /// never both), an address already held (re-adoption included: this is
    /// not idempotent) — plus a VM that already holds a live lease, which
    /// is this fake being stricter than an address pool can be, as its
    /// `reserve` already is. Unlike `reserve` it is not gated on the
    /// startup sweep: adoption is what that sweep does.
    async fn adopt(&self, lease: &NetworkLease, mode: AttachMode) -> Result<()> {
        if self.fail_adopt.swap(false, Ordering::AcqRel) {
            return Err(Error::Network(format!(
                "scripted adopt failure for vm {}",
                lease.vm
            )));
        }
        let host = host_number(lease.ip)?;
        let mut ledger = lock(&self.ledger);
        if ledger.quarantined.contains_key(&lease.vm) {
            return Err(Error::PreconditionFailed(format!(
                "vm {} lease is quarantined; it cannot also be live",
                lease.vm
            )));
        }
        // Address before VM, as the TAP network answers it: its live state
        // is the address pool, so re-adopting a live lease is the
        // duplicate-address refusal there too. The VM check below is this
        // fake being stricter than an address pool can be — the same
        // strictness its `reserve` already has.
        if !ledger.used.insert(host) {
            return Err(Error::Network(format!(
                "vm {} cannot adopt {}: the address is already held",
                lease.vm, lease.ip
            )));
        }
        if ledger.active.contains_key(&lease.vm) {
            ledger.used.remove(&host);
            return Err(Error::PreconditionFailed(format!(
                "vm {} already holds a live lease",
                lease.vm
            )));
        }
        ledger.active.insert(lease.vm.clone(), lease.clone());
        ledger.adopted.insert(lease.vm.clone(), mode);
        Ok(())
    }

    async fn quarantine(&self, lease: NetworkLease) -> Result<()> {
        let mut ledger = lock(&self.ledger);
        let host = host_number(lease.ip)?;
        if let Some(existing) = ledger.quarantined.get(&lease.vm) {
            if existing.cleanup_token == lease.cleanup_token {
                return Ok(());
            }
            // Another generation of this id is mid-cleanup: retry-later,
            // like the reserve above.
            return Err(Error::Unavailable(format!(
                "vm {} already has a different quarantined lease",
                lease.vm
            )));
        }
        match ledger.active.get(&lease.vm) {
            Some(current) if *current == lease => {
                ledger.active.remove(&lease.vm);
                ledger.adopted.remove(&lease.vm);
            }
            Some(_) => return Err(ledger.stale(&lease)),
            // A lease replayed from a durable record after a crash is
            // quarantined even if this process never handed it out — unless
            // its address has since gone to another VM, which makes the
            // record stale rather than orphaned.
            None => {
                if ledger.used.contains(&host) {
                    return Err(ledger.stale(&lease));
                }
                ledger.used.insert(host);
            }
        }
        ledger.quarantined.insert(lease.vm.clone(), lease);
        Ok(())
    }

    async fn release(&self, lease: NetworkLease) -> Result<()> {
        let mut ledger = lock(&self.ledger);
        let host = host_number(lease.ip)?;
        let current = ledger
            .active
            .get(&lease.vm)
            .or_else(|| ledger.quarantined.get(&lease.vm));
        match current {
            Some(current) if *current == lease => {
                ledger.active.remove(&lease.vm);
                ledger.adopted.remove(&lease.vm);
                ledger.quarantined.remove(&lease.vm);
                ledger.used.remove(&host);
                Ok(())
            }
            Some(_) => Err(ledger.stale(&lease)),
            // Nothing held for this VM: releasing again is a no-op, unless
            // the address now belongs to someone else.
            None if ledger.used.contains(&host) => Err(ledger.stale(&lease)),
            None => Ok(()),
        }
    }

    /// The lease's own address, whichever mode it was attached in: the
    /// fake translates nothing per interface, so the guest sees exactly
    /// what was reserved for it.
    fn identity(&self, lease: &NetworkLease, _mode: AttachMode) -> NetworkIdentity {
        NetworkIdentity {
            ip: lease.ip,
            prefix_len: lease.prefix_len,
            gateway: lease.gateway,
            dns: vec![lease.gateway],
            mac: lease.mac,
        }
    }

    /// The lease's own address: the fake translates nothing per interface,
    /// so there is no mark to set and nothing for the host to target but
    /// the address the guest itself holds.
    fn host_ingress(&self, lease: &NetworkLease) -> Result<HostIngress> {
        host_number(lease.ip)?;
        Ok(HostIngress::PoolAddress)
    }

    fn reconcile(&self) -> Option<&dyn NetworkReconcile> {
        Some(self)
    }
}

#[async_trait]
impl NetworkReconcile for FakeNetwork {
    /// Always `Ok`: this ledger is a map keyed by [`VmId`], so it cannot
    /// hold an id the protocol could not name.
    async fn pending_cleanups(&self) -> Result<Vec<(VmId, String)>> {
        Ok(lock(&self.ledger)
            .quarantined
            .iter()
            .map(|(vm, lease)| (vm.clone(), lease.cleanup_token.clone()))
            .collect())
    }

    async fn validate_cleanup(&self, vm: &VmId, token: &str) -> Result<NetworkLease> {
        lock(&self.ledger).validate_cleanup(vm, token).cloned()
    }

    async fn finalize_cleanup(&self, vm: &VmId, token: &str) -> Result<()> {
        let mut ledger = lock(&self.ledger);
        ledger.validate_cleanup(vm, token)?;
        if let Some(lease) = ledger.quarantined.remove(vm) {
            ledger.used.remove(&host_number(lease.ip)?);
        }
        Ok(())
    }

    async fn startup_cleanup_token(&self) -> Option<String> {
        lock(&self.ledger)
            .startup
            .as_ref()
            .filter(|s| !s.host_cleaned)
            .map(|s| s.token.clone())
    }

    async fn validate_startup_cleanup(&self, token: &str) -> Result<()> {
        lock(&self.ledger).validate_startup_cleanup(token)
    }

    async fn finalize_startup_cleanup(&self, token: &str) -> Result<()> {
        let mut ledger = lock(&self.ledger);
        ledger.validate_startup_cleanup(token)?;
        if !ledger.quarantined.is_empty() {
            // Retry-later: the gate opens once those generations drain.
            return Err(Error::Unavailable(
                "cleanup generations remain pending; finalize them first".into(),
            ));
        }
        if let Some(startup) = ledger.startup.as_mut() {
            startup.host_cleaned = true;
        }
        self.set_startup_pending(&ledger);
        Ok(())
    }

    async fn wait_startup_cleanup_complete(&self) {
        let mut pending = self.startup_pending.subscribe();
        // A closed channel cannot happen: the sender lives in `self`.
        let _ = pending.wait_for(|pending| !pending).await;
    }

    fn replay_complete(&self) {
        if let Some(startup) = lock(&self.ledger).startup.as_mut() {
            startup.replayed = true;
        }
    }
}

impl Ledger {
    /// A token that does not name a pending generation — of this VM or of
    /// none at all — is a failed precondition: no retry of that token can
    /// succeed, the caller needs a current one.
    fn validate_cleanup(&self, vm: &VmId, token: &str) -> Result<&NetworkLease> {
        let lease = self
            .quarantined
            .get(vm)
            .ok_or_else(|| Error::PreconditionFailed(format!("vm {vm} has no pending cleanup")))?;
        if lease.cleanup_token != token {
            return Err(Error::PreconditionFailed(format!(
                "vm {vm} cleanup token does not name the pending generation"
            )));
        }
        Ok(lease)
    }

    fn validate_startup_cleanup(&self, token: &str) -> Result<()> {
        match &self.startup {
            // The owner is still discovering what the previous process
            // left: come back, rather than "that token is wrong".
            Some(startup) if !startup.replayed => Err(Error::Unavailable(
                "the network's owner has not finished replaying its durable state".into(),
            )),
            Some(startup) if !startup.host_cleaned && startup.token == token => Ok(()),
            Some(startup) if !startup.host_cleaned => Err(Error::PreconditionFailed(
                "startup cleanup token mismatch".into(),
            )),
            _ => Err(Error::PreconditionFailed(
                "no startup cleanup is pending".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetworkMode;

    fn id(s: &str) -> VmId {
        VmId::new(s).unwrap()
    }

    fn policy() -> NetworkPolicy {
        NetworkPolicy {
            mode: NetworkMode::Nat,
        }
    }

    #[tokio::test]
    async fn leases_take_the_lowest_free_host_and_release_reuses_it() {
        let net = FakeNetwork::new();
        let a = net.reserve(&id("a"), policy()).await.unwrap();
        let b = net.reserve(&id("b"), policy()).await.unwrap();
        assert_eq!(a.ip, "10.200.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(b.ip, "10.200.0.3".parse::<IpAddr>().unwrap());
        assert!(a.mac.is_unicast() && a.mac != b.mac);
        assert!(net.reserve(&id("a"), policy()).await.is_err());

        let nic = net.activate(&a, AttachMode::Invariant).await.unwrap();
        assert_eq!(
            nic.attachment,
            NicAttachment::Tap {
                name: "tap2".into()
            }
        );
        assert_eq!(nic.mac, a.mac);

        net.release(a.clone()).await.unwrap();
        let c = net.reserve(&id("c"), policy()).await.unwrap();
        assert_eq!(c.ip, a.ip);
    }

    #[tokio::test]
    async fn the_guest_sees_its_lease_in_either_attach_mode() {
        let net = FakeNetwork::new();
        let lease = net.reserve(&id("a"), policy()).await.unwrap();
        let invariant = net.identity(&lease, AttachMode::Invariant);
        assert_eq!(invariant.ip, lease.ip);
        assert_eq!(invariant.gateway, lease.gateway);
        assert_eq!(invariant.mac, lease.mac);
        assert_eq!(invariant.dns, vec![lease.gateway]);
        // Nothing is translated per interface here, so the mode changes
        // nothing about what the guest is told — and the host reaches the
        // guest at that same address, with no mark to set.
        assert_eq!(net.identity(&lease, AttachMode::LegacySnapshot), invariant);
        assert_eq!(net.host_ingress(&lease).unwrap(), HostIngress::PoolAddress);
        // A lease from another network is not one this fake can answer for.
        let mut foreign = lease;
        foreign.ip = "192.0.2.7".parse().unwrap();
        assert!(net.host_ingress(&foreign).is_err());
    }

    /// A lease as a previous process's durable record hands it back: this
    /// network never minted it.
    fn replayed(vm: &str, host: u16) -> NetworkLease {
        let [hi, lo] = host.to_be_bytes();
        NetworkLease {
            vm: id(vm),
            ip: IpAddr::V4(Ipv4Addr::new(10, 200, hi, lo)),
            prefix_len: PREFIX_LEN,
            gateway: IpAddr::V4(GATEWAY),
            mac: MacAddr::new([0x02, 0xfa, 0xce, 0x00, hi, lo]),
            cleanup_token: format!("boot-1-{vm}"),
        }
    }

    /// Adoption is the third way a lease becomes live, so the pool must
    /// stop offering its address and every live-path read must answer
    /// about it.
    #[tokio::test]
    async fn an_adopted_lease_holds_its_address_and_answers_the_live_reads() {
        let net = FakeNetwork::new();
        let live = replayed("a", 2);
        net.adopt(&live, AttachMode::Invariant).await.unwrap();
        assert_eq!(net.adopted_mode(&id("a")), Some(AttachMode::Invariant));
        // Re-adopting a live lease is the address collision, the answer the
        // TAP network gives it too — `adopt` is not a no-op the second time.
        assert!(matches!(
            net.adopt(&live, AttachMode::Invariant).await,
            Err(Error::Network(_))
        ));
        // The pool has stopped offering that address...
        let next = net.reserve(&id("b"), policy()).await.unwrap();
        assert_ne!(next.ip, live.ip);
        // ...and the reads a live lease answers do answer about it.
        assert_eq!(net.identity(&live, AttachMode::Invariant).ip, live.ip);
        assert_eq!(net.host_ingress(&live).unwrap(), HostIngress::PoolAddress);

        // Two records claiming one address: adopting either is a guess.
        let mut twin = live.clone();
        twin.vm = id("twin");
        assert!(matches!(
            net.adopt(&twin, AttachMode::Invariant).await,
            Err(Error::Network(_))
        ));
        // The refusal changed nothing: the pool hands out what it would
        // have handed out anyway.
        let after = net.reserve(&id("c"), policy()).await.unwrap();
        assert_eq!(after.ip, "10.200.0.4".parse::<IpAddr>().unwrap());
        // Not a lease of this network at all.
        let mut foreign = live.clone();
        foreign.ip = "192.0.2.7".parse().unwrap();
        assert!(net.adopt(&foreign, AttachMode::Invariant).await.is_err());

        // Live and awaiting cleanup are exclusive, in both directions.
        net.quarantine(live.clone()).await.unwrap();
        assert_eq!(net.adopted_mode(&id("a")), None);
        assert!(matches!(
            net.adopt(&live, AttachMode::Invariant).await,
            Err(Error::PreconditionFailed(_))
        ));
    }

    /// The scripted refusal an owner falls back from leaves the pool
    /// untouched, so tearing the VM down is all that happened.
    #[tokio::test]
    async fn a_scripted_adopt_failure_takes_nothing_and_is_armed_once() {
        let net = FakeNetwork::new();
        let live = replayed("a", 2);
        net.fail_adopt_once();
        assert!(net.adopt(&live, AttachMode::Invariant).await.is_err());
        assert_eq!(net.adopted_mode(&id("a")), None);
        // Nothing was taken: the same adopt goes through once the knob is
        // spent, where a half-applied one would refuse a duplicate.
        net.adopt(&live, AttachMode::LegacySnapshot).await.unwrap();
        assert_eq!(net.adopted_mode(&id("a")), Some(AttachMode::LegacySnapshot));
    }

    #[tokio::test]
    async fn quarantine_holds_the_address_until_the_token_finalizes_it() {
        let net = FakeNetwork::new();
        let a = net.reserve(&id("a"), policy()).await.unwrap();
        net.quarantine(a.clone()).await.unwrap();
        net.quarantine(a.clone()).await.unwrap(); // idempotent
        let mut other = a.clone();
        other.cleanup_token = "other".into();
        assert!(matches!(
            net.quarantine(other).await,
            Err(Error::Unavailable(_))
        ));
        assert!(net.activate(&a, AttachMode::Invariant).await.is_err());

        let reconcile = net.reconcile().unwrap();
        assert_eq!(
            reconcile.pending_cleanups().await.unwrap(),
            vec![(id("a"), a.cleanup_token.clone())]
        );
        // A token that names no pending generation is a failed
        // precondition; the id itself is refused until the host finalizes,
        // which is a retry-later. Callers turn those into 412 and 503.
        assert!(matches!(
            reconcile.validate_cleanup(&id("a"), "wrong").await,
            Err(Error::PreconditionFailed(_))
        ));
        // The right token hands the lease back: the address is what the
        // host's cleanup of that generation is keyed by, and after a
        // restart the ledger is the only place it survives.
        assert_eq!(
            reconcile
                .validate_cleanup(&id("a"), &a.cleanup_token)
                .await
                .unwrap(),
            a
        );
        assert!(matches!(
            net.reserve(&id("a"), policy()).await,
            Err(Error::Unavailable(_))
        ));
        // Still held: the next lease does not get a's address.
        let b = net.reserve(&id("b"), policy()).await.unwrap();
        assert_ne!(b.ip, a.ip);

        reconcile
            .finalize_cleanup(&id("a"), &a.cleanup_token)
            .await
            .unwrap();
        assert!(reconcile.pending_cleanups().await.unwrap().is_empty());
        let c = net.reserve(&id("c"), policy()).await.unwrap();
        assert_eq!(c.ip, a.ip);
    }

    #[tokio::test]
    async fn stale_leases_neither_free_nor_quarantine_a_reassigned_address() {
        let net = FakeNetwork::new();
        let a1 = net.reserve(&id("a"), policy()).await.unwrap();
        net.release(a1.clone()).await.unwrap();
        // Releasing what is already released is a no-op...
        net.release(a1.clone()).await.unwrap();
        // ...until the address belongs to someone else.
        let second = net.reserve(&id("b"), policy()).await.unwrap();
        assert_eq!(second.ip, a1.ip);
        assert!(net.release(a1.clone()).await.is_err());
        assert!(net.quarantine(a1.clone()).await.is_err());
        // The new holder keeps it: nobody else gets that address.
        let third = net.reserve(&id("c"), policy()).await.unwrap();
        assert_ne!(third.ip, second.ip);

        // A VM's older generation cannot touch its current lease either.
        let a2 = net.reserve(&id("a"), policy()).await.unwrap();
        assert!(net.release(a1.clone()).await.is_err());
        assert!(net.quarantine(a1).await.is_err());
        assert!(net.activate(&a2, AttachMode::Invariant).await.is_ok());

        // A quarantined lease is released only by itself.
        net.quarantine(a2.clone()).await.unwrap();
        let mut forged = a2.clone();
        forged.cleanup_token = "forged".into();
        assert!(net.release(forged).await.is_err());
        net.release(a2.clone()).await.unwrap();
        assert!(
            net.reconcile()
                .unwrap()
                .pending_cleanups()
                .await
                .unwrap()
                .is_empty()
        );
        let reused = net.reserve(&id("d"), policy()).await.unwrap();
        assert_eq!(reused.ip, a2.ip);

        // A durable-record replay of an address nobody holds still lands in
        // quarantine and pins the address until its token finalizes it.
        let mut replayed = reused.clone();
        replayed.vm = id("ghost");
        replayed.ip = "10.200.0.5".parse().unwrap(); // the lowest free host
        replayed.cleanup_token = "ghost-1".into();
        net.quarantine(replayed.clone()).await.unwrap();
        let next = net.reserve(&id("e"), policy()).await.unwrap();
        assert_eq!(next.ip, "10.200.0.6".parse::<IpAddr>().unwrap());
        let reconcile = net.reconcile().unwrap();
        reconcile
            .finalize_cleanup(&id("ghost"), "ghost-1")
            .await
            .unwrap();
        let unpinned = net.reserve(&id("f"), policy()).await.unwrap();
        assert_eq!(unpinned.ip, replayed.ip);
    }

    #[tokio::test]
    async fn startup_cleanup_gates_on_its_token_and_on_drained_quarantines() {
        let net = std::sync::Arc::new(FakeNetwork::with_startup_cleanup("boot-1"));
        let reconcile = net.reconcile().unwrap();
        assert_eq!(
            reconcile.startup_cleanup_token().await.as_deref(),
            Some("boot-1")
        );
        // Nothing can be finalized while the owner is still replaying its
        // durable state: even its own token is a come-back-later, because
        // what the sweep must cover is not yet known.
        assert!(matches!(
            reconcile.validate_startup_cleanup("boot-1").await,
            Err(Error::Unavailable(_))
        ));
        reconcile.replay_complete();
        // Another generation's token can never name this sweep.
        assert!(matches!(
            reconcile.validate_startup_cleanup("boot-2").await,
            Err(Error::PreconditionFailed(_))
        ));

        // The pool is closed while the sweep is pending — every id, not
        // just the ones in the ledger.
        assert!(matches!(
            net.reserve(&id("a"), policy()).await,
            Err(Error::Unavailable(_))
        ));

        // A quarantine can still arrive alongside a pending sweep, because
        // that is where both come from: a previous process's leases,
        // replayed from its durable records.
        let a = NetworkLease {
            vm: id("a"),
            ip: IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2)),
            prefix_len: PREFIX_LEN,
            gateway: IpAddr::V4(GATEWAY),
            mac: MacAddr::new([0x02, 0xfa, 0xce, 0x00, 0x00, 0x02]),
            cleanup_token: "boot-1-a".into(),
        };
        net.quarantine(a.clone()).await.unwrap();
        // A quarantined lease keeps the startup cleanup from finalizing —
        // retry-later, since finalizing that generation opens the gate.
        assert!(matches!(
            reconcile.finalize_startup_cleanup("boot-1").await,
            Err(Error::Unavailable(_))
        ));

        let waiter = tokio::spawn({
            let net = std::sync::Arc::clone(&net);
            async move { net.wait_startup_cleanup_complete().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        reconcile
            .finalize_cleanup(&id("a"), &a.cleanup_token)
            .await
            .unwrap();
        reconcile.finalize_startup_cleanup("boot-1").await.unwrap();
        assert_eq!(reconcile.startup_cleanup_token().await, None);
        // The pool opens with it, and the replayed address is back in it.
        assert_eq!(net.reserve(&id("a"), policy()).await.unwrap().ip, a.ip);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("waiter released")
            .unwrap();

        // Nothing pending: returns at once.
        FakeNetwork::new().wait_startup_cleanup_complete().await;
    }
}
