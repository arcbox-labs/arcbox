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

use crate::network::{IptablesLegacy, PacketFilter};

/// What differs between hosts of the sandbox stack.
#[derive(Clone)]
pub struct SandboxEnvironment {
    /// Loop-device and block-size operations for the copy-on-write rootfs
    /// (`arcbox_snapshot::snapshot_cow::BlockTools`).
    pub block_tools: Arc<dyn BlockTools>,
    /// How the identity-invariant translation is expressed in the host's
    /// netfilter framework ([`crate::network::packet_filter`]) — used by
    /// the iptables datapath and as the eBPF datapath's fallback.
    pub packet_filter: Arc<dyn PacketFilter>,
}

impl Default for SandboxEnvironment {
    /// The System VM's userland: busybox applets at
    /// [`BusyboxBlockTools::DEFAULT_PATH`], iptables-legacy at
    /// [`IptablesLegacy::DEFAULT_PATH`].
    fn default() -> Self {
        Self {
            block_tools: Arc::new(BusyboxBlockTools::default()),
            packet_filter: Arc::new(IptablesLegacy::default()),
        }
    }
}

impl std::fmt::Debug for SandboxEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxEnvironment").finish_non_exhaustive()
    }
}
