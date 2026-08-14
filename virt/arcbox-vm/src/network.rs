use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, info};
use uuid::Uuid;

use crate::config::SandboxDatapath;
use crate::error::{Result, VmmError};

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
mod quarantine;
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "the netlink send is Linux-gated; other platforms keep the encoders for unit tests"
    )
)]
mod rtnetlink;

/// Host-side addressing scheme applied when a sandbox TAP is materialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TapMode {
    /// Fixed guest identity + per-TAP 1:1 NAT (CORE-81): the TAP's local
    /// address is [`invariant::GUEST_GATEWAY`] and the pool IP is translated
    /// host-side. Every fresh boot and every invariant-snapshot restore.
    Invariant,
    /// The pre-invariant shape: the TAP's local address is the pool gateway
    /// and the guest owns the pool IP directly. Only restores of legacy
    /// snapshots (no `net_invariant` marker), whose guests are re-addressed
    /// over the reconfig RPC.
    LegacySnapshot,
}

/// The translation mechanism actually applied to an active invariant TAP.
///
/// Distinct from the configured [`SandboxDatapath`]: a TAP configured for
/// eBPF lands on `Iptables` when the object cannot be loaded or this TAP's
/// attach fails. Teardown and expose targeting must follow what was applied,
/// not what was asked for.
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
}

/// How host-side expose/port-forward DNAT must target a sandbox.
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

/// Default prefix length for backwards-compatible deserialization of records
/// that predate the `prefix_len` field.
const fn default_prefix_len() -> u8 {
    16
}

/// Result of allocating network resources for a single VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAllocation {
    /// TAP interface name (e.g. `vmtap0`).
    pub tap_name: String,
    /// IP address assigned to the guest.
    pub ip_address: Ipv4Addr,
    /// Network prefix length (e.g. 16 for /16).
    #[serde(default = "default_prefix_len")]
    pub prefix_len: u8,
    /// Gateway IP.
    pub gateway: Ipv4Addr,
    /// MAC address (deterministic from VM ID).
    pub mac_address: String,
    /// DNS servers.
    pub dns_servers: Vec<String>,
    /// Opaque generation token carried through host cleanup finalization.
    #[serde(default)]
    pub cleanup_token: String,
}

impl NetworkAllocation {
    /// Return the subnet mask as an `Ipv4Addr` (e.g. prefix_len 16 → 255.255.0.0).
    ///
    /// Values above 32 are clamped to 32 to avoid shift overflow.
    pub fn netmask(&self) -> Ipv4Addr {
        let p = self.prefix_len.min(32);
        if p == 0 {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::from(!0u32 << (32 - p))
        }
    }
}

/// Shared manager for TAP interfaces and guest IP addresses.
pub struct NetworkManager {
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
    datapath: SandboxDatapath,
    /// Mechanism actually applied per active invariant TAP, recorded at
    /// activation. Keyed by TAP name; entries live exactly as long as the
    /// TAP (activation inserts, teardown removes). A TAP absent here was
    /// either activated by a previous agent process (its eBPF links died
    /// with that process) or is legacy — both tear down via the tolerant
    /// iptables removal and expose via the fwmark form.
    applied: Mutex<HashMap<String, AppliedDatapath>>,
    /// Lazily loaded eBPF datapath state (CORE-83).
    #[cfg(target_os = "linux")]
    ebpf: Mutex<ebpf::Engine>,
}

impl NetworkManager {
    /// Create a new manager from the network configuration.
    ///
    /// `cidr` must be in `a.b.c.d/n` notation (e.g. `"172.20.0.0/16"`).
    pub fn new(cidr: &str, gateway: &str, dns: Vec<String>) -> Result<Self> {
        Self::new_inner(cidr, gateway, dns, None, SandboxDatapath::default())
    }

    /// Create a manager that persists inactive allocations until host cleanup
    /// is finalized, translating invariant TAPs via `datapath`.
    pub(crate) fn with_quarantine_dir(
        cidr: &str,
        gateway: &str,
        dns: Vec<String>,
        quarantine_dir: PathBuf,
        datapath: SandboxDatapath,
    ) -> Result<Self> {
        Self::new_inner(cidr, gateway, dns, Some(quarantine_dir), datapath)
    }

    fn new_inner(
        cidr: &str,
        gateway: &str,
        dns: Vec<String>,
        quarantine_dir: Option<PathBuf>,
        datapath: SandboxDatapath,
    ) -> Result<Self> {
        let (base, prefix_len) = parse_cidr(cidr)?;
        if !(1..=30).contains(&prefix_len) {
            return Err(VmmError::Network(format!(
                "prefix length {prefix_len} out of range 1–30"
            )));
        }
        let gateway = gateway
            .parse::<Ipv4Addr>()
            .map_err(|e| VmmError::Network(format!("invalid gateway: {e}")))?;
        let quarantined = quarantine_dir
            .as_deref()
            .map(|dir| quarantine::load_quarantines(dir, base, prefix_len, gateway))
            .transpose()?
            .unwrap_or_default();
        let mut allocated = HashSet::new();
        for allocation in quarantined.values() {
            if !allocated.insert(u32::from(allocation.ip_address)) {
                return Err(VmmError::Network(format!(
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
        if let Err(error) = self.activate(&allocation, TapMode::LegacySnapshot) {
            self.release(&allocation);
            return Err(error);
        }
        Ok(allocation)
    }

    /// Whether `vm_id`'s released network is still quarantined awaiting
    /// host-side cleanup finalization (a same-id [`Self::reserve`] is
    /// refused until then).
    pub(crate) fn quarantine_pending(&self, vm_id: &str) -> bool {
        self.quarantined.lock().unwrap().contains_key(vm_id)
    }

    /// Reserves an IP and computes its deterministic TAP metadata without
    /// creating any host resource. Sandbox lifecycle code journals this value
    /// before calling [`Self::activate`].
    pub(crate) fn reserve(&self, vm_id: &str) -> Result<NetworkAllocation> {
        self.ensure_startup_cleanup_complete()?;
        if self.quarantined.lock().unwrap().contains_key(vm_id) {
            return Err(VmmError::Unavailable(format!(
                "sandbox {vm_id} network cleanup is awaiting host finalization"
            )));
        }
        let ip = self.next_ip()?;
        let tap_name = tap_name_from_ip(ip);
        let mac = mac_from_vm_id(vm_id);

        Ok(NetworkAllocation {
            tap_name,
            ip_address: ip,
            prefix_len: self.prefix_len,
            gateway: self.gateway,
            mac_address: mac,
            dns_servers: self.dns.clone(),
            cleanup_token: Uuid::new_v4().to_string(),
        })
    }

    /// Materializes a previously reserved network allocation.
    ///
    /// In [`TapMode::Invariant`] the TAP's local address is the fixed
    /// [`invariant::GUEST_GATEWAY`] and the per-TAP 1:1 NAT (pool IP ↔ fixed
    /// guest IP) is installed alongside; in [`TapMode::LegacySnapshot`] the
    /// TAP carries the pool gateway and no translation, matching guests that
    /// own the pool IP directly.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Linux TAP activation is fallible; macOS test builds compile the no-op branch"
    )]
    pub(crate) fn activate(&self, allocation: &NetworkAllocation, mode: TapMode) -> Result<()> {
        info!(
            tap = %allocation.tap_name,
            ip = %allocation.ip_address,
            ?mode,
            "activating sandbox network"
        );
        #[cfg(target_os = "linux")]
        {
            let local = match mode {
                TapMode::Invariant => invariant::GUEST_GATEWAY,
                TapMode::LegacySnapshot => self.gateway,
            };
            self.create_tap(&allocation.tap_name, local, allocation.ip_address)?;
            if mode == TapMode::Invariant
                && let Err(error) = self.install_translation(allocation)
            {
                // Unwind the partial translation and the TAP so a failed
                // activation leaves no half-translated interface behind.
                let _ = self.deactivate_translation(allocation);
                destroy_tap(&allocation.tap_name);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Apply the invariant pool-IP translation to an existing TAP, honoring
    /// the configured [`SandboxDatapath`] and falling back to iptables when
    /// the eBPF path is unavailable, then record what was applied.
    #[cfg(target_os = "linux")]
    fn install_translation(&self, allocation: &NetworkAllocation) -> Result<()> {
        let applied = match self.datapath {
            SandboxDatapath::Iptables => {
                invariant::install(&allocation.tap_name, allocation.ip_address)?;
                AppliedDatapath::Iptables
            }
            SandboxDatapath::Ebpf => match self.attach_ebpf(allocation) {
                Ok(ebpf::Attach::Done) => AppliedDatapath::Ebpf,
                // The load failure already warned once; stay quiet per TAP.
                Ok(ebpf::Attach::EngineUnavailable) => {
                    invariant::install(&allocation.tap_name, allocation.ip_address)?;
                    AppliedDatapath::Iptables
                }
                Err(error) => {
                    tracing::warn!(
                        tap = %allocation.tap_name,
                        %error,
                        "eBPF TAP attach failed; using iptables NAT for this TAP"
                    );
                    invariant::install(&allocation.tap_name, allocation.ip_address)?;
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
        invariant::remove(&alloc.tap_name, alloc.ip_address)
    }

    /// How expose DNAT must target the sandbox behind `tap_name` (CORE-83).
    ///
    /// Follows the *applied* datapath, not the configured one: an eBPF TAP's
    /// egress program translates pool-IP packets on the TAP itself, so the
    /// plain pool-IP form suffices; everything else — iptables TAPs, legacy
    /// guests, and TAPs whose activation record died with a previous agent
    /// process — needs the CORE-81 guest-IP + fwmark form.
    pub(crate) fn expose_target(&self, tap_name: &str, net_invariant: bool) -> ExposeTarget {
        if !net_invariant {
            return ExposeTarget::PoolIp;
        }
        match self.applied.lock().unwrap().get(tap_name) {
            Some(AppliedDatapath::Ebpf) => ExposeTarget::PoolIp,
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
    pub(crate) fn release_checked(&self, alloc: &NetworkAllocation) -> Result<()> {
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
        let tap_result = destroy_tap_checked(&alloc.tap_name);

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
        Err(VmmError::Network("IP pool exhausted".into()))
    }

    #[cfg(target_os = "linux")]
    fn create_tap(&self, tap_name: &str, local: Ipv4Addr, ip: Ipv4Addr) -> Result<()> {
        use std::os::fd::FromRawFd;
        use std::os::unix::io::AsRawFd;

        // Remove any stale TAP left over from a previous crashed run.
        destroy_tap_checked(tap_name)?;

        let name_bytes = tap_name.as_bytes();
        if name_bytes.len() >= libc::IFNAMSIZ {
            return Err(VmmError::Network(format!("TAP name too long: {tap_name}")));
        }

        // 1. Create persistent TAP device via /dev/net/tun.
        let tun = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| VmmError::Network(format!("open /dev/net/tun: {e}")))?;

        let mut ifr = new_ifreq(name_bytes);
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;

        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        const TUNSETPERSIST: libc::c_ulong = 0x400454cb;

        // SAFETY: tun fd is valid, ifr is initialized with name and flags.
        if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF as _, &ifr) } < 0 {
            return Err(VmmError::Network(format!(
                "TUNSETIFF {tap_name}: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Make persistent so Firecracker can reopen the TAP by name.
        // SAFETY: tun fd is attached to the TAP device after TUNSETIFF.
        if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETPERSIST as _, 1i32) } < 0 {
            return Err(VmmError::Network(format!(
                "TUNSETPERSIST {tap_name}: {}",
                std::io::Error::last_os_error()
            )));
        }
        drop(tun);

        // 2. Bring interface up via ioctl on a helper socket.
        // SAFETY: standard socket creation.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            destroy_tap(tap_name);
            return Err(VmmError::Network(format!(
                "socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: sock is a valid fd returned by socket().
        let sock = unsafe { std::os::fd::OwnedFd::from_raw_fd(sock) };

        // SAFETY: sock and ifr.ifr_name are valid; kernel writes ifr_flags.
        if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS as _, &ifr) } < 0 {
            destroy_tap(tap_name);
            return Err(VmmError::Network(format!(
                "SIOCGIFFLAGS {tap_name}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: ifr_flags is valid from SIOCGIFFLAGS; adding IFF_UP.
        unsafe { ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16 };
        // SAFETY: sock and ifr are valid.
        if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &ifr) } < 0 {
            destroy_tap(tap_name);
            return Err(VmmError::Network(format!(
                "SIOCSIFFLAGS UP {tap_name}: {}",
                std::io::Error::last_os_error()
            )));
        }

        // 3. Configure point-to-point IP on TAP host end (the gateway the
        //    guest routes through) so the sandbox can use it as its default
        //    gateway. Each TAP is an isolated link — sandboxes cannot see
        //    each other at L2.
        //
        // Wrap in a closure so a failure in any set_ifaddr triggers TAP cleanup.
        if let Err(e) = (|| -> Result<()> {
            // Set local address (gateway).
            set_ifaddr(
                &sock,
                &ifr,
                libc::SIOCSIFADDR,
                local,
                tap_name,
                "SIOCSIFADDR",
            )?;
            // Set peer (destination) address (sandbox IP).
            set_ifaddr(
                &sock,
                &ifr,
                libc::SIOCSIFDSTADDR,
                ip,
                tap_name,
                "SIOCSIFDSTADDR",
            )?;
            // Set /32 netmask so the kernel creates a proper host route to the peer.
            set_ifaddr(
                &sock,
                &ifr,
                libc::SIOCSIFNETMASK,
                Ipv4Addr::BROADCAST, // 255.255.255.255
                tap_name,
                "SIOCSIFNETMASK",
            )?;
            Ok(())
        })() {
            destroy_tap(tap_name);
            return Err(e);
        }

        Ok(())
    }
}

// Platform helpers

/// Creates a zero-initialized `ifreq` with the given interface name.
#[cfg(target_os = "linux")]
fn new_ifreq(name_bytes: &[u8]) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: caller must ensure name_bytes.len() < IFNAMSIZ.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast::<u8>(),
            name_bytes.len(),
        );
    }
    ifr
}

/// Sets an IPv4 address on an interface via ioctl.
#[cfg(target_os = "linux")]
fn set_ifaddr(
    sock: &std::os::fd::OwnedFd,
    ifr: &libc::ifreq,
    request: libc::c_ulong,
    addr: Ipv4Addr,
    tap_name: &str,
    label: &str,
) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let mut req = *ifr;
    let mut addr_in: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr_in.sin_family = libc::AF_INET as libc::sa_family_t;
    addr_in.sin_addr.s_addr = u32::from(addr).to_be();

    // SAFETY: sockaddr_in fits within ifr_ifru (both are >= 16 bytes).
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&raw const addr_in).cast::<u8>(),
            (&raw mut req.ifr_ifru).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
    // SAFETY: sock and req are valid; kernel reads ifr_name and sockaddr.
    if unsafe { libc::ioctl(sock.as_raw_fd(), request as _, &req) } < 0 {
        return Err(VmmError::Network(format!(
            "{label} {tap_name} {addr}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Destroys a persistent TAP device.
///
/// First attempts to clear the persist flag via ioctl (re-attach then
/// `TUNSETPERSIST 0`). If the interface still exists afterwards, falls back
/// to `ip link delete` which works regardless of fd state.
#[cfg(target_os = "linux")]
fn destroy_tap(tap_name: &str) {
    if let Err(error) = destroy_tap_checked(tap_name) {
        tracing::warn!(tap = tap_name, error = %error, "failed to destroy TAP");
    }
}

#[cfg(target_os = "linux")]
fn destroy_tap_checked(tap_name: &str) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let name_bytes = tap_name.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(VmmError::Network(format!("TAP name too long: {tap_name}")));
    }

    // Try ioctl-based removal first.
    if let Ok(tun) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
    {
        let mut ifr = new_ifreq(name_bytes);
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;

        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        const TUNSETPERSIST: libc::c_ulong = 0x400454cb;

        // SAFETY: tun fd is valid, ifr is properly initialized.
        if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF as _, &ifr) } >= 0 {
            // SAFETY: tun fd is attached to the TAP device; clearing persist removes it.
            let _ = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETPERSIST as _, 0i32) };
        }
        drop(tun);
    }

    // Fallback: if the interface still exists, use ip link delete.
    //
    // The existence check and the delete race the kernel: clearing
    // TUNSETPERSIST above and dropping the fd removes a non-persistent TAP
    // asynchronously, so the sysfs entry can outlive the decision to delete
    // and vanish before `ip` runs. A delete that fails because the device
    // is already gone has reached exactly the state this function exists to
    // reach, so the post-check below — not the exit status — decides: the
    // device being absent is success no matter why `ip` complained.
    //
    // Deliberately not a message match: the System VM ships busybox `ip`
    // ("can't find device 'x'", exit 2) while a dev host has iproute2
    // ("Cannot find device \"x\"", exit 1), so any wording test would pass
    // CI and still fail in production.
    //
    // PATH lookup, not an absolute path: the System VM rootfs installs the
    // busybox `ip` applet at /bin/ip (BUSYBOX_SYMLINKS in boot-assets
    // rootfs.rs) while Linux hosts carry iproute2 in /sbin or /usr/sbin —
    // no single absolute path exists in both environments, and the old
    // hardcoded /usr/sbin/ip made every create that lost the sysfs race
    // above fail with ENOENT inside the guest.
    let sysfs = format!("/sys/class/net/{tap_name}");
    let mut delete_error = None;
    if std::path::Path::new(&sysfs).exists() {
        let output = std::process::Command::new("ip")
            .args(["link", "delete", tap_name])
            .output()
            .map_err(|error| {
                VmmError::Network(format!("run ip link delete {tap_name}: {error}"))
            })?;
        if !output.status.success() {
            delete_error = Some(String::from_utf8_lossy(&output.stderr).trim().to_owned());
        }
    }
    if std::path::Path::new(&sysfs).exists() {
        return Err(VmmError::Network(match delete_error {
            Some(stderr) => format!("ip link delete {tap_name}: {stderr}"),
            None => format!("TAP {tap_name} still exists after deletion"),
        }));
    }
    Ok(())
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

    /// Returns true when the process effective UID is 0.
    /// TAP creation requires root on Linux; tests that call `allocate()` skip
    /// when this returns false.
    #[cfg(target_os = "linux")]
    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .map(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(2))
                    .map(|uid| uid == "0")
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    #[test]
    fn test_allocate_sequential_ips() {
        #[cfg(target_os = "linux")]
        if !is_root() {
            eprintln!("SKIP test_allocate_sequential_ips — requires root (TAP creation)");
            return;
        }
        let mgr = NetworkManager::new("172.20.0.0/16", "172.20.0.1", vec![]).unwrap();
        let a1 = mgr.allocate("vm-1").unwrap();
        let a2 = mgr.allocate("vm-2").unwrap();
        assert_ne!(a1.ip_address, a2.ip_address);
    }

    #[test]
    fn test_release_returns_ip_to_pool() {
        #[cfg(target_os = "linux")]
        if !is_root() {
            eprintln!("SKIP test_release_returns_ip_to_pool — requires root (TAP creation)");
            return;
        }
        let mgr = NetworkManager::new("172.20.0.0/16", "172.20.0.1", vec![]).unwrap();
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
        assert!(NetworkManager::new("10.0.0.0/0", "10.0.0.1", vec![]).is_err());
        assert!(NetworkManager::new("10.0.0.0/31", "10.0.0.1", vec![]).is_err());
        assert!(NetworkManager::new("10.0.0.0/32", "10.0.0.1", vec![]).is_err());
        assert!(NetworkManager::new("10.0.0.0/24", "10.0.0.1", vec![]).is_ok());
    }

    #[test]
    fn test_next_ip_respects_subnet_boundary() {
        #[cfg(target_os = "linux")]
        if !is_root() {
            eprintln!("SKIP test_next_ip_respects_subnet_boundary — requires root (TAP creation)");
            return;
        }
        // /30 has exactly 2 host addresses (.1 gateway, .2 first usable)
        let mgr = NetworkManager::new("10.0.0.0/30", "10.0.0.1", vec![]).unwrap();
        let a = mgr.allocate("vm-1").unwrap();
        assert_eq!(a.ip_address, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        // Pool is now exhausted
        assert!(mgr.allocate("vm-2").is_err());
    }

    #[test]
    fn test_pool_exhaustion_on_slash29() {
        #[cfg(target_os = "linux")]
        if !is_root() {
            eprintln!("SKIP test_pool_exhaustion_on_slash29 — requires root (TAP creation)");
            return;
        }
        // /29 has 6 usable addresses; gateway takes offset 1, leaving 5 for VMs.
        let mgr = NetworkManager::new("10.0.0.0/29", "10.0.0.1", vec![]).unwrap();
        for i in 0..5 {
            mgr.allocate(&format!("vm-{i}")).unwrap();
        }
        assert!(mgr.allocate("vm-overflow").is_err());
    }

    #[test]
    fn test_mac_unicast_and_locally_administered_bits() {
        let mac = mac_from_vm_id("test-vm");
        let first_byte = u8::from_str_radix(&mac[..2], 16).unwrap();
        // Bit 1 set → locally administered; bit 0 clear → unicast.
        assert_eq!(
            first_byte & 0x02,
            0x02,
            "locally administered bit must be set"
        );
        assert_eq!(first_byte & 0x01, 0x00, "multicast bit must be clear");
    }

    #[test]
    fn test_netmask_slash0() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_netmask_slash8() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 8,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::new(255, 0, 0, 0));
    }

    #[test]
    fn test_netmask_slash16() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 16,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn test_netmask_slash24() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 24,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn test_netmask_slash30() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 30,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::new(255, 255, 255, 252));
    }

    #[test]
    fn test_netmask_slash32() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 32,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        assert_eq!(alloc.netmask(), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn test_netmask_out_of_range_clamps_to_32() {
        let alloc = NetworkAllocation {
            tap_name: String::new(),
            ip_address: Ipv4Addr::UNSPECIFIED,
            prefix_len: 33,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac_address: String::new(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        };
        // prefix_len 33 should clamp to /32 → 255.255.255.255
        assert_eq!(alloc.netmask(), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn test_tap_name_encodes_last_two_octets() {
        let ip: Ipv4Addr = "172.20.3.17".parse().unwrap();
        assert_eq!(tap_name_from_ip(ip), "vmtap3-17");

        let ip2: Ipv4Addr = "10.0.255.1".parse().unwrap();
        assert_eq!(tap_name_from_ip(ip2), "vmtap255-1");
    }

    /// Expose targeting must follow the datapath actually applied to the
    /// TAP, and default to the fwmark form when the record is gone (agent
    /// restart) — the eBPF links died with that process, so only the
    /// iptables machinery could still be translating.
    #[test]
    fn expose_target_follows_the_applied_datapath() {
        let manager = NetworkManager::new("172.20.0.0/16", "172.20.0.1", vec![]).unwrap();
        // Legacy guests own the pool IP outright.
        assert_eq!(
            manager.expose_target("vmtap0-2", false),
            ExposeTarget::PoolIp
        );
        // Invariant TAP without an activation record.
        assert_eq!(
            manager.expose_target("vmtap0-2", true),
            ExposeTarget::GuestIpWithFwmark
        );
        let record = |applied| {
            manager
                .applied
                .lock()
                .unwrap()
                .insert("vmtap0-2".to_owned(), applied)
        };
        record(AppliedDatapath::Ebpf);
        assert_eq!(
            manager.expose_target("vmtap0-2", true),
            ExposeTarget::PoolIp
        );
        record(AppliedDatapath::Iptables);
        assert_eq!(
            manager.expose_target("vmtap0-2", true),
            ExposeTarget::GuestIpWithFwmark
        );
    }

    #[tokio::test]
    async fn startup_waiter_unblocks_after_host_finalization() {
        let root = tempfile::tempdir().unwrap();
        let manager = std::sync::Arc::new(
            NetworkManager::with_quarantine_dir(
                "10.0.0.0/30",
                "10.0.0.1",
                vec![],
                root.path().join("network-quarantine"),
                SandboxDatapath::default(),
            )
            .unwrap(),
        );
        manager.mark_reconciled();

        let waiter = {
            let manager = std::sync::Arc::clone(&manager);
            tokio::spawn(async move {
                manager.wait_startup_cleanup_complete().await;
            })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        let token = manager.startup_cleanup_token().unwrap();
        manager.finalize_startup_cleanup(&token).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("startup waiter must wake")
            .unwrap();
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn durable_quarantine_blocks_reuse_until_startup_and_generation_finalize() {
        let root = tempfile::tempdir().unwrap();
        let quarantine = root.path().join("network-quarantine");
        let manager = NetworkManager::with_quarantine_dir(
            "10.0.0.0/30",
            "10.0.0.1",
            vec![],
            quarantine.clone(),
            SandboxDatapath::default(),
        )
        .unwrap();
        manager.mark_reconciled();
        let first_startup = manager.startup_cleanup_token().unwrap();
        manager.finalize_startup_cleanup(&first_startup).unwrap();
        let allocation = manager.reserve("old").unwrap();
        quarantine::write_quarantine(&quarantine, "old", &allocation).unwrap();
        drop(manager);

        let restarted = NetworkManager::with_quarantine_dir(
            "10.0.0.0/30",
            "10.0.0.1",
            vec![],
            quarantine,
            SandboxDatapath::default(),
        )
        .unwrap();
        restarted.mark_reconciled();
        assert!(restarted.reserve("new").is_err());
        assert!(restarted.validate_startup_cleanup(&first_startup).is_err());
        assert!(
            restarted
                .validate_quarantine("old", "wrong-generation")
                .is_err()
        );

        let startup = restarted.startup_cleanup_token().unwrap();
        assert!(restarted.finalize_startup_cleanup(&startup).is_err());
        assert!(
            restarted.reserve("new").is_err(),
            "the quarantined generation must keep the startup gate closed"
        );
        restarted
            .finalize_quarantine("old", &allocation.cleanup_token)
            .unwrap();
        assert!(restarted.reserve("new").is_err());
        restarted.finalize_startup_cleanup(&startup).unwrap();
        let reused = restarted.reserve("new").unwrap();
        assert_eq!(reused.ip_address, allocation.ip_address);
    }

    #[test]
    fn quarantine_loader_rejects_foreign_or_inconsistent_allocations() {
        let mutations: [fn(&mut NetworkAllocation); 4] = [
            |allocation: &mut NetworkAllocation| {
                allocation.ip_address = "192.0.2.2".parse().unwrap();
            },
            |allocation: &mut NetworkAllocation| {
                allocation.tap_name = "vmtap-wrong".into();
            },
            |allocation: &mut NetworkAllocation| {
                allocation.mac_address = "02:00:00:00:00:00".into();
            },
            |allocation: &mut NetworkAllocation| {
                allocation.gateway = "10.0.0.9".parse().unwrap();
            },
        ];
        for mutate in mutations {
            let root = tempfile::tempdir().unwrap();
            let quarantine = root.path().join("network-quarantine");
            std::fs::create_dir(&quarantine).unwrap();
            let mut allocation = NetworkAllocation {
                tap_name: tap_name_from_ip("10.0.0.2".parse().unwrap()),
                ip_address: "10.0.0.2".parse().unwrap(),
                prefix_len: 30,
                gateway: "10.0.0.1".parse().unwrap(),
                mac_address: mac_from_vm_id("box"),
                dns_servers: vec![],
                cleanup_token: Uuid::new_v4().to_string(),
            };
            mutate(&mut allocation);
            quarantine::write_quarantine(&quarantine, "box", &allocation).unwrap();
            assert!(
                NetworkManager::with_quarantine_dir(
                    "10.0.0.0/30",
                    "10.0.0.1",
                    vec![],
                    quarantine,
                    SandboxDatapath::default(),
                )
                .is_err()
            );
        }
    }
}
