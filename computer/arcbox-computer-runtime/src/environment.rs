//! Environment-specific components a composer supplies to the sandbox stack.
//!
//! The manager runs in more than one environment — the ArcBox System VM
//! with its known busybox userland, or a stock distro on a bare-metal
//! node — and every part that differs is supplied here rather than built
//! in the code. There is no default and no member is optional:
//! [`SandboxManager::new`](crate::SandboxManager::new) builds none of the
//! four, so what VMM its Computers run on is the composer's decision and
//! never a fallback taken here (vm-stack-redesign R3, charter D4).
//!
//! The System VM's composition is `arcbox_agent::sandbox::node_environment`
//! — the Firecracker driver from the config's `[firecracker]` section, the
//! TAP network from its `[network]` section, the `arcbox-vm-proto` agent
//! client, and a copy-on-write rootfs manager over busybox.

use std::sync::Arc;

use arcbox_vm_driver::VmDriver;
use arcbox_vm_driver::net::GuestNetwork;

use crate::agent::GuestAgentFactory;
use crate::snapshot_cow::CowManager;

/// What differs between hosts of the sandbox stack.
#[derive(Clone)]
pub struct NodeEnvironment {
    /// The VMM the sandboxes run under, behind the driver port
    /// (`arcbox_vm_driver::VmDriver`). It must claim the `Prepare` and
    /// `Staging` capabilities and offer `vsock`: the boot and warm-pool
    /// flows spawn the VMM ahead of the guest, every flow stages the files
    /// its computer boots from, and the guest agent is reached over vsock.
    /// A driver that cannot is refused by
    /// [`SandboxManager::new`](crate::SandboxManager::new) rather than at
    /// the first boot.
    pub driver: Arc<dyn VmDriver>,
    /// What the sandboxes' NICs attach to, behind the guest-network port
    /// (`arcbox_vm_driver::net::GuestNetwork`). It must offer the
    /// `NetworkReconcile` capability: the quarantine ledger is how a host
    /// learns which addresses a previous process still holds, and a
    /// network without it is refused at construction rather than at the
    /// first cleanup ticket.
    pub network: Arc<dyn GuestNetwork>,
    /// How the runtime reaches the agent inside each sandbox, behind the
    /// guest-agent port ([`crate::agent::GuestAgentFactory`]). The
    /// reference is the `arcbox-vm-proto` client over the driver's vsock
    /// capability ([`crate::agent::VmProtoAgentFactory`]), which is what
    /// every Firecracker sandbox speaks; a composer whose Computers are
    /// not reachable that way supplies its own. The factory also decides
    /// what the readiness gate needs from the driver, so an environment
    /// whose driver cannot serve it is refused at construction rather than
    /// at the first boot.
    pub agent: Arc<dyn GuestAgentFactory>,
    /// The copy-on-write rootfs manager. Built by the composer, because
    /// what it needs — the data directory, the loop-device tooling of the
    /// host's userland, where its `dmsetup` lives — is exactly what
    /// differs between environments.
    pub cow_manager: Arc<CowManager>,
}

impl std::fmt::Debug for NodeEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeEnvironment")
            .field("driver", &self.driver.name())
            .finish_non_exhaustive()
    }
}
