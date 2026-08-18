//! Environment-specific components a composer supplies to the sandbox stack.
//!
//! The manager runs in more than one environment — the ArcBox System VM
//! with its known busybox userland, or a stock distro on a bare-metal
//! node — and the parts that differ are supplied here rather than assumed
//! in the code. [`SandboxEnvironment::default`] is the reference
//! environment, the System VM's, so `SandboxManager::new(config)` behaves
//! exactly as before; a composer on another userland overrides the members
//! it owns and calls `SandboxManager::with_environment`.

use std::sync::Arc;

use arcbox_snapshot::snapshot_cow::{BlockTools, BusyboxBlockTools};
use arcbox_vm_driver::VmDriver;
use arcbox_vm_driver::net::GuestNetwork;

use crate::agent::GuestAgentFactory;
use crate::network::{IptablesLegacy, PacketFilter};
use crate::snapshot_cow::CowManager;

/// What differs between hosts of the sandbox stack.
#[derive(Clone)]
pub struct SandboxEnvironment {
    /// The VMM the sandboxes run under, behind the driver port
    /// (`arcbox_vm_driver::VmDriver`). `None` — the reference — is the
    /// Firecracker driver built from the config's `[firecracker]` section
    /// inside `SandboxManager::with_environment`; a composer wanting
    /// another VMM supplies its adapter here. Whatever is supplied must
    /// claim the `Prepare` capability: the boot and warm-pool flows spawn
    /// the VMM ahead of the guest, and a driver without it is refused at
    /// construction rather than at the first boot.
    pub driver: Option<Arc<dyn VmDriver>>,
    /// What the sandboxes' NICs attach to, behind the guest-network port
    /// (`arcbox_vm_driver::net::GuestNetwork`). `None` — the reference —
    /// is the Linux TAP network built from the config's `[network]`
    /// section, its datapath, and the packet filter below, inside
    /// `SandboxManager::with_environment`; a composer on another
    /// dataplane supplies its own here. Whatever is supplied must offer
    /// the `NetworkReconcile` capability: the quarantine ledger is how a
    /// host learns which addresses a previous process still holds, and a
    /// network without it is refused at construction rather than at the
    /// first cleanup ticket.
    pub network: Option<Arc<dyn GuestNetwork>>,
    /// How the runtime reaches the agent inside each sandbox, behind the
    /// guest-agent port ([`crate::agent::GuestAgentFactory`]). `None` — the
    /// reference — is the `arcbox-vm-proto` client over the driver's vsock
    /// capability ([`crate::agent::VmProtoAgentFactory`]), which is what
    /// every Firecracker sandbox speaks; a composer whose Computers are
    /// not reachable that way supplies its own. The factory also decides
    /// what the readiness gate needs from the driver, so an environment
    /// whose driver cannot serve it is refused at construction rather than
    /// at the first boot.
    pub agent: Option<Arc<dyn GuestAgentFactory>>,
    /// Loop-device and block-size operations for the copy-on-write rootfs
    /// and the `vm-agent` injection mount
    /// (`arcbox_snapshot::snapshot_cow::BlockTools`). The reference is
    /// busybox; a composer on a stock distro supplies
    /// `UtilLinuxBlockTools::discover()?`.
    pub block_tools: Arc<dyn BlockTools>,
    /// The copy-on-write rootfs manager. `None` — the reference — is built
    /// from the config's data dir and [`Self::block_tools`] inside
    /// `SandboxManager::with_environment`; a composer that needs a
    /// differently-built one (a probed manager, a foreign thin pool)
    /// supplies it here rather than reaching into a constructed manager.
    pub cow_manager: Option<Arc<CowManager>>,
    /// How the identity-invariant translation is expressed in the host's
    /// netfilter framework ([`crate::network::packet_filter`]) — used by
    /// the iptables datapath and as the eBPF datapath's fallback.
    pub packet_filter: Arc<dyn PacketFilter>,
}

impl Default for SandboxEnvironment {
    /// The System VM's userland: the Firecracker driver from the config,
    /// the TAP network from the config, the vm-proto agent client, busybox
    /// applets at
    /// [`BusyboxBlockTools::DEFAULT_PATH`], iptables-legacy at
    /// [`IptablesLegacy::DEFAULT_PATH`].
    fn default() -> Self {
        Self {
            driver: None,
            network: None,
            agent: None,
            block_tools: Arc::new(BusyboxBlockTools::default()),
            cow_manager: None,
            packet_filter: Arc::new(IptablesLegacy::default()),
        }
    }
}

impl std::fmt::Debug for SandboxEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxEnvironment")
            .field(
                "driver",
                &self.driver.as_ref().map_or("<from config>", |d| d.name()),
            )
            .finish_non_exhaustive()
    }
}
