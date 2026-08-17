//! `arcbox-tap-net` — the Linux TAP guest network of the sandbox stack.
//!
//! One [`TapNetwork`] owns an IPv4 pool and, per VM, a persistent TAP
//! device on an isolated point-to-point link, the identity-invariant NAT
//! that gives every guest the same address ([`invariant`]) — applied per
//! TAP either as two eBPF TCX programs or as the iptables rule set behind
//! the [`PacketFilter`] seam — and the durable quarantine ledger that keeps
//! a released address out of the pool until host-side forwarding state is
//! confirmed gone. It moved here from `arcbox-vm/src/network` as the Linux
//! adapter of the `arcbox-vm-driver` `GuestNetwork` port (vm-stack-redesign
//! D-VM6, R2). Everything that touches the kernel is Linux-only; the pool,
//! the encoders, and the ledger compile and are unit-tested everywhere.
//!
//! Two surfaces, one state: the [`GuestNetwork`] / [`NetworkReconcile`]
//! impls ([`guest_network`]) are what every consumer reaches — a
//! [`NetworkLease`] instead of a [`NetworkAllocation`], a [`NicSpec`] out
//! of activation — and [`TapNetwork`]'s inherent methods are what they are
//! written in. Only the constructors are called from outside now; the
//! System VM composes this network and then speaks to it through the port.
//!
//! [`GuestNetwork`]: arcbox_vm_driver::net::GuestNetwork
//! [`NetworkReconcile`]: arcbox_vm_driver::net::NetworkReconcile
//! [`NetworkLease`]: arcbox_vm_driver::net::NetworkLease
//! [`NicSpec`]: arcbox_vm_driver::NicSpec

#![warn(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use arcbox_vm_driver::MacAddr;
pub use arcbox_vm_driver::net::AttachMode;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, info};
use uuid::Uuid;

pub use crate::allocation::NetworkAllocation;
pub use crate::error::{Result, TapNetError};
pub use packet_filter::{IptablesLegacy, PacketFilter};

pub mod allocation;
pub mod error;
pub mod guest_network;

#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "the loader is Linux-only; other platforms keep the pure map-value helpers for unit tests"
    )
)]
mod ebpf;
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "TAP translation executes only on Linux; other platforms keep the pure rule builders for unit tests"
    )
)]
pub mod invariant;
pub mod packet_filter;
mod quarantine;
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "the netlink send is Linux-gated; other platforms keep the encoders for unit tests"
    )
)]
mod rtnetlink;
#[cfg(target_os = "linux")]
mod tap;

/// How the pool-IP <-> fixed-guest-IP translation of an invariant sandbox TAP
/// (CORE-81) is applied host-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Datapath {
    /// Per-TAP TCX eBPF programs: two attach syscalls and one map update per
    /// activation, stateless, O(1) per packet (CORE-83). Falls back to
    /// [`Self::Iptables`] automatically when the BPF object cannot be loaded
    /// or attached.
    #[default]
    Ebpf,
    /// The CORE-81 iptables rule set (mark + DNAT/SNAT + fwmark fib rules);
    /// conntrack-stateful and O(active sandboxes) per packet. Also the only
    /// mechanism ever applied to legacy (non-invariant) TAPs.
    Iptables,
}

/// The name this type had inside `arcbox-vm`, kept so the System VM's
/// composition still reads as it did.
pub type NetworkManager = TapNetwork;

/// The translation mechanism actually applied to an active TAP.
///
/// Distinct from the configured [`Datapath`]: a TAP configured for
/// eBPF lands on `Iptables` when the object cannot be loaded or this TAP's
/// attach fails. Teardown and expose targeting must follow what was applied,
/// not what was asked for — which is why a [`AttachMode::LegacySnapshot`]
/// TAP records [`Self::Untranslated`] rather than nothing at all: absent and
/// "deliberately untranslated" are opposite answers for expose targeting,
/// and only the second one is knowable from the lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "only the Linux activation path constructs these; other platforms activate nothing"
    )
)]
enum AppliedDatapath {
    /// TCX programs + map entry + onlink gateway route.
    Ebpf,
    /// The CORE-81 iptables/fwmark rule set.
    Iptables,
    /// None: the guest owns the pool address itself, so nothing is
    /// rewritten per TAP ([`AttachMode::LegacySnapshot`]).
    Untranslated,
}

/// How host-side expose/port-forward DNAT must target a sandbox.
///
/// This crate answers the question through the port, as
/// [`GuestNetwork::host_ingress`]; the type stays public because the
/// System VM's port-forward code still names it (R3 moves that call to
/// the composition root).
///
/// [`GuestNetwork::host_ingress`]: arcbox_vm_driver::net::GuestNetwork::host_ingress
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposeTarget {
    /// DNAT straight to the pool IP, delivered by the main-table TAP route.
    /// Legacy guests own that address; on the eBPF datapath the TAP's egress
    /// program rewrites it after routing. No mangle companion either way.
    PoolIp,
    /// DNAT to the fixed invariant guest IP with a companion fwmark `MARK`
    /// rule on the same match, so the rewritten destination routes out the
    /// right TAP through the CORE-81 fwmark table (iptables datapath only).
    GuestIpWithFwmark,
}

/// The TAP network: an IPv4 pool plus, per VM, a point-to-point TAP with
/// its translation, and the quarantine ledger.
///
/// Reached through the `GuestNetwork` port ([`guest_network`]), which is
/// written in the inherent methods below. Both share this one state, so a
/// lease the port activated is a TAP the inherent `release_checked` tears
/// down.
pub struct TapNetwork {
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
    /// Allocations whose TAP is inactive but whose IP cannot be recycled until
    /// the host confirms its listeners are gone.
    quarantined: Mutex<HashMap<String, NetworkAllocation>>,
    /// Durable quarantine marker directory for sandbox networking.
    quarantine_dir: Option<PathBuf>,
    /// Gates allocation after an agent restart until the host has finalized
    /// every replayed cleanup ticket.
    startup_barrier: AtomicBool,
    /// Wakes requests waiting for the current startup cleanup generation.
    startup_changed: watch::Sender<()>,
    /// Opaque process-generation token for the host's initial cleanup pass.
    startup_token: String,
    /// Whether the host has removed all listeners retained across this agent
    /// process restart.
    startup_host_cleaned: AtomicBool,
    /// Whether guest durable-state reconciliation has completed.
    startup_reconciled: AtomicBool,
    /// Configured translation mechanism for invariant TAPs (CORE-83).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "consulted only by the Linux activation path; other platforms activate nothing"
        )
    )]
    datapath: Datapath,
    /// Mechanism actually applied per active invariant TAP, recorded at
    /// activation. Keyed by TAP name; entries live exactly as long as the
    /// TAP (activation inserts, teardown removes). A TAP absent here was
    /// either activated by a previous agent process (its eBPF links died
    /// with that process) or is legacy — both tear down via the tolerant
    /// iptables removal and expose via the fwmark form.
    applied: Mutex<HashMap<String, AppliedDatapath>>,
    /// How the iptables-datapath translation (and the eBPF fallback) is
    /// expressed on this host; see [`packet_filter`].
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "consulted only by the Linux activation path; other platforms activate nothing"
        )
    )]
    packet_filter: Arc<dyn PacketFilter>,
    /// Lazily loaded eBPF datapath state (CORE-83).
    #[cfg(target_os = "linux")]
    ebpf: Mutex<ebpf::Engine>,
}

impl TapNetwork {
    /// Create a new manager from the network configuration.
    ///
    /// `cidr` must be in `a.b.c.d/n` notation (e.g. `"172.20.0.0/16"`).
    pub fn new(cidr: &str, gateway: &str, dns: Vec<String>) -> Result<Self> {
        Self::new_inner(
            cidr,
            gateway,
            dns,
            None,
            Datapath::default(),
            Arc::new(IptablesLegacy::default()),
        )
    }

    /// Create a manager that persists inactive allocations until host cleanup
    /// is finalized, translating invariant TAPs via `datapath` and, where
    /// that means netfilter rules, through `packet_filter`.
    pub fn with_quarantine_dir(
        cidr: &str,
        gateway: &str,
        dns: Vec<String>,
        quarantine_dir: PathBuf,
        datapath: Datapath,
        packet_filter: Arc<dyn PacketFilter>,
    ) -> Result<Self> {
        Self::new_inner(
            cidr,
            gateway,
            dns,
            Some(quarantine_dir),
            datapath,
            packet_filter,
        )
    }

    fn new_inner(
        cidr: &str,
        gateway: &str,
        dns: Vec<String>,
        quarantine_dir: Option<PathBuf>,
        datapath: Datapath,
        packet_filter: Arc<dyn PacketFilter>,
    ) -> Result<Self> {
        let (base, prefix_len) = parse_cidr(cidr)?;
        if !(1..=30).contains(&prefix_len) {
            return Err(TapNetError::Network(format!(
                "prefix length {prefix_len} out of range 1–30"
            )));
        }
        let gateway = gateway
            .parse::<Ipv4Addr>()
            .map_err(|e| TapNetError::Network(format!("invalid gateway: {e}")))?;
        let quarantined = quarantine_dir
            .as_deref()
            .map(|dir| quarantine::load_quarantines(dir, base, prefix_len, gateway))
            .transpose()?
            .unwrap_or_default();
        let mut allocated = HashSet::new();
        for allocation in quarantined.values() {
            if !allocated.insert(u32::from(allocation.ip_address)) {
                return Err(TapNetError::Network(format!(
                    "duplicate quarantined sandbox IP {}",
                    allocation.ip_address
                )));
            }
        }

        let startup_barrier = quarantine_dir.is_some();
        let startup_token = if startup_barrier {
            Uuid::new_v4().to_string()
        } else {
            String::new()
        };
        let (startup_changed, _) = watch::channel(());
        Ok(Self {
            base,
            prefix_len,
            gateway,
            dns,
            allocated: Mutex::new(allocated),
            quarantined: Mutex::new(quarantined),
            quarantine_dir,
            startup_barrier: AtomicBool::new(startup_barrier),
            startup_changed,
            startup_token,
            startup_host_cleaned: AtomicBool::new(!startup_barrier),
            startup_reconciled: AtomicBool::new(!startup_barrier),
            datapath,
            applied: Mutex::new(HashMap::new()),
            packet_filter,
            #[cfg(target_os = "linux")]
            ebpf: Mutex::new(ebpf::Engine::Unloaded),
        })
    }

    /// Allocate a TAP interface and guest IP for `vm_id`.
    ///
    /// On Linux this creates a persistent TAP device with a point-to-point IP
    /// configuration (gateway ↔ sandbox IP). The call is best-effort on
    /// non-Linux platforms (tests / macOS CI).
    ///
    /// General (non-sandbox) VMs boot the pool identity directly, so this
    /// keeps the legacy TAP shape; the sandbox lifecycle activates invariant
    /// TAPs via [`Self::activate`].
    pub fn allocate(&self, vm_id: &str) -> Result<NetworkAllocation> {
        let allocation = self.reserve(vm_id)?;
        if let Err(error) = self.activate(&allocation, AttachMode::LegacySnapshot) {
            self.release(&allocation);
            return Err(error);
        }
        Ok(allocation)
    }

    /// Whether `vm_id`'s released network is still quarantined awaiting
    /// host-side cleanup finalization (a same-id [`Self::reserve`] is
    /// refused until then).
    pub fn quarantine_pending(&self, vm_id: &str) -> bool {
        self.quarantined.lock().unwrap().contains_key(vm_id)
    }

    /// Reserves an IP and computes its deterministic TAP metadata without
    /// creating any host resource. Sandbox lifecycle code journals this value
    /// before calling [`Self::activate`]. `vm_id` is held to the driver
    /// port's `VmId` rules here (`[A-Za-z0-9._-]`, at most 64 bytes), so that
    /// whatever is reserved can later be quarantined and named through the
    /// port.
    pub fn reserve(&self, vm_id: &str) -> Result<NetworkAllocation> {
        quarantine::validate_id(vm_id)?;
        self.ensure_startup_cleanup_complete()?;
        if self.quarantined.lock().unwrap().contains_key(vm_id) {
            return Err(TapNetError::Unavailable(format!(
                "sandbox {vm_id} network cleanup is awaiting host finalization"
            )));
        }
        let ip = self.next_ip()?;
        let tap_name = tap_name_from_ip(ip);
        Ok(NetworkAllocation {
            tap_name,
            ip_address: ip,
            prefix_len: self.prefix_len,
            gateway: self.gateway,
            mac_address: mac_from_vm_id(vm_id).to_string(),
            dns_servers: self.dns.clone(),
            cleanup_token: Uuid::new_v4().to_string(),
        })
    }

    /// Materializes a previously reserved network allocation.
    ///
    /// In [`AttachMode::Invariant`] the TAP's local address is the fixed
    /// [`invariant::GUEST_GATEWAY`] and the per-TAP 1:1 NAT (pool IP ↔ fixed
    /// guest IP) is installed alongside — every fresh boot and every
    /// invariant-snapshot restore; in [`AttachMode::LegacySnapshot`] the TAP
    /// carries the pool gateway and no translation, matching guests that own
    /// the pool IP directly — restores of snapshots that predate the
    /// invariant identity, whose guests are re-addressed over the reconfig
    /// RPC.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Linux TAP activation is fallible; macOS test builds compile the no-op branch"
    )]
    pub fn activate(&self, allocation: &NetworkAllocation, mode: AttachMode) -> Result<()> {
        info!(
            tap = %allocation.tap_name,
            ip = %allocation.ip_address,
            ?mode,
            "activating sandbox network"
        );
        #[cfg(target_os = "linux")]
        {
            let local = match mode {
                AttachMode::Invariant => invariant::GUEST_GATEWAY,
                AttachMode::LegacySnapshot => self.gateway,
            };
            tap::create(&allocation.tap_name, local, allocation.ip_address)?;
            if mode == AttachMode::Invariant {
                if let Err(error) = self.install_translation(allocation) {
                    // Unwind the partial translation and the TAP so a failed
                    // activation leaves no half-translated interface behind.
                    let _ = self.deactivate_translation(allocation);
                    tap::destroy(&allocation.tap_name);
                    return Err(error);
                }
            } else {
                // A legacy guest owns the pool address, so this TAP carries
                // no translation — recorded, not left absent, because
                // `expose_target` reads an absent record as "an invariant
                // TAP this process did not activate" and answers the
                // opposite way.
                self.applied
                    .lock()
                    .unwrap()
                    .insert(allocation.tap_name.clone(), AppliedDatapath::Untranslated);
            }
        }
        Ok(())
    }

    /// Apply the invariant pool-IP translation to an existing TAP, honoring
    /// the configured [`Datapath`] and falling back to iptables when
    /// the eBPF path is unavailable, then record what was applied.
    #[cfg(target_os = "linux")]
    fn install_translation(&self, allocation: &NetworkAllocation) -> Result<()> {
        let applied = match self.datapath {
            Datapath::Iptables => {
                invariant::install(
                    &*self.packet_filter,
                    &allocation.tap_name,
                    allocation.ip_address,
                )?;
                AppliedDatapath::Iptables
            }
            Datapath::Ebpf => match self.attach_ebpf(allocation) {
                Ok(ebpf::Attach::Done) => AppliedDatapath::Ebpf,
                // The load failure already warned once; stay quiet per TAP.
                Ok(ebpf::Attach::EngineUnavailable) => {
                    invariant::install(
                        &*self.packet_filter,
                        &allocation.tap_name,
                        allocation.ip_address,
                    )?;
                    AppliedDatapath::Iptables
                }
                Err(error) => {
                    tracing::warn!(
                        tap = %allocation.tap_name,
                        %error,
                        "eBPF TAP attach failed; using iptables NAT for this TAP"
                    );
                    invariant::install(
                        &*self.packet_filter,
                        &allocation.tap_name,
                        allocation.ip_address,
                    )?;
                    AppliedDatapath::Iptables
                }
            },
        };
        self.applied
            .lock()
            .unwrap()
            .insert(allocation.tap_name.clone(), applied);
        Ok(())
    }

    /// TCX-attach both NAT programs, map the TAP's ifindex to its pool IP,
    /// and swap the kernel peer route for the onlink gateway route that
    /// steers the (still-untranslated) pool destination into this TAP.
    #[cfg(target_os = "linux")]
    fn attach_ebpf(&self, allocation: &NetworkAllocation) -> Result<ebpf::Attach> {
        let mut engine = self.ebpf.lock().unwrap();
        let pool = ebpf::PoolValues::new(self.base, self.prefix_len, self.gateway);
        let Some(nat) = engine.ensure_loaded(pool) else {
            return Ok(ebpf::Attach::EngineUnavailable);
        };
        let ifindex = invariant::tap_ifindex(&allocation.tap_name)?;
        nat.attach(&allocation.tap_name, ifindex, allocation.ip_address)?;
        if let Err(error) = rtnetlink::execute(
            &rtnetlink::replace_gateway_route(allocation.ip_address, invariant::GUEST_IP, ifindex),
            &[],
        ) {
            let _ = nat.detach(&allocation.tap_name);
            return Err(error);
        }
        info!(
            ifindex,
            pool_ip = %allocation.ip_address,
            "ebpf datapath attached"
        );
        Ok(ebpf::Attach::Done)
    }

    /// Remove whatever translation this process applied to the TAP.
    ///
    /// eBPF TAPs detach their links and drop their map entry (the gateway
    /// route dies with the TAP). Everything else — iptables TAPs, legacy
    /// TAPs, and TAPs activated by a previous agent process (whose eBPF
    /// links died with it) — takes the tolerant iptables removal, exactly
    /// as before CORE-83.
    #[cfg(target_os = "linux")]
    fn deactivate_translation(&self, alloc: &NetworkAllocation) -> Result<()> {
        let applied = self.applied.lock().unwrap().remove(&alloc.tap_name);
        if applied == Some(AppliedDatapath::Ebpf) {
            if let Some(nat) = self.ebpf.lock().unwrap().loaded_mut() {
                return nat.detach(&alloc.tap_name);
            }
            return Ok(());
        }
        invariant::remove(&*self.packet_filter, &alloc.tap_name, alloc.ip_address)
    }

    /// How expose DNAT must target the sandbox behind `tap_name` (CORE-83).
    ///
    /// Follows the *applied* datapath, not the configured one: an eBPF TAP's
    /// egress program translates pool-IP packets on the TAP itself and a
    /// legacy TAP never translated anything, so the plain pool-IP form
    /// suffices for both; everything else — iptables TAPs, and TAPs whose
    /// activation record died with a previous agent process — needs the
    /// CORE-81 guest-IP + fwmark form.
    pub(crate) fn expose_target(&self, tap_name: &str) -> ExposeTarget {
        match self.applied.lock().unwrap().get(tap_name) {
            Some(AppliedDatapath::Ebpf | AppliedDatapath::Untranslated) => ExposeTarget::PoolIp,
            Some(AppliedDatapath::Iptables) | None => ExposeTarget::GuestIpWithFwmark,
        }
    }

    /// Release the TAP interface and guest IP associated with `vm_id`.
    pub fn release(&self, alloc: &NetworkAllocation) {
        if let Err(error) = self.release_checked(alloc) {
            tracing::warn!(
                tap = %alloc.tap_name,
                ip = %alloc.ip_address,
                error = %error,
                "sandbox network release incomplete"
            );
        }
    }

    /// Release a network allocation and report whether the TAP disappeared.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Linux TAP cleanup is fallible; macOS test builds compile the no-op branch"
    )]
    pub fn release_checked(&self, alloc: &NetworkAllocation) -> Result<()> {
        // Translation state does not die with the device; remove it first
        // (tolerant of absence, so legacy TAPs are a no-op). A failure here
        // must NOT abort the teardown: propagating before the TAP destroy
        // would strand the device and leak the pool address forever (the
        // allocation is only returned to the pool below, and expire paths do
        // not retry Network errors). Finish the teardown, then surface the
        // first error.
        #[cfg(target_os = "linux")]
        let translation_result = self.deactivate_translation(alloc);
        #[cfg(target_os = "linux")]
        let tap_result = tap::destroy_checked(&alloc.tap_name);

        let ip_int = u32::from(alloc.ip_address);
        self.allocated.lock().unwrap().remove(&ip_int);

        debug!(tap = %alloc.tap_name, ip = %alloc.ip_address, "releasing network");
        #[cfg(target_os = "linux")]
        {
            translation_result?;
            tap_result?;
        }
        Ok(())
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
        Err(TapNetError::Network("IP pool exhausted".into()))
    }
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(TapNetError::Network(format!("invalid CIDR: {cidr}")));
    }
    let addr = parts[0]
        .parse::<Ipv4Addr>()
        .map_err(|e| TapNetError::Network(format!("invalid CIDR address: {e}")))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|e| TapNetError::Network(format!("invalid prefix length: {e}")))?;
    Ok((addr, prefix))
}

fn tap_name_from_ip(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    // Encode last two octets with a delimiter to keep name short and unambiguous.
    format!("vmtap{}-{}", octets[2], octets[3])
}

/// The guest MAC of `vm_id`: deterministic, locally administered, unicast.
fn mac_from_vm_id(vm_id: &str) -> MacAddr {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    vm_id.hash(&mut hasher);
    let h = hasher.finish();
    // Locally administered, unicast: set bit 1 of first octet, clear bit 0.
    MacAddr::new([
        0x02 | (((h >> 40) & 0xfe) as u8),
        ((h >> 32) & 0xff) as u8,
        ((h >> 24) & 0xff) as u8,
        ((h >> 16) & 0xff) as u8,
        ((h >> 8) & 0xff) as u8,
        (h & 0xff) as u8,
    ])
}

#[cfg(test)]
mod tests;
