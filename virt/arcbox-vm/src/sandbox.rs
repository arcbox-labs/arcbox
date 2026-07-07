//! `SandboxManager` — orchestrates sandbox microVM lifecycle.
//!
//! A sandbox is a short-lived, strongly-isolated microVM decoupled from its
//! workload: when the initial `cmd` process exits the sandbox transitions back
//! to `Ready` rather than stopping, and continues accepting `Run` calls until
//! an explicit `Stop`/`Remove` or TTL expiry.
//!
//! `create_sandbox` returns immediately with state `"starting"`.  The VM boots
//! in a background task which broadcasts a `"ready"` event on success.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use fc_sdk::VmBuilder;
use fc_sdk::types::{BootSource, Drive, NetworkInterface, Vsock};
use nix::unistd::{Gid, Uid, chown};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::boot_proto::KernelIpParam;
use crate::config::VmmConfig;
use crate::error::{Result, VmmError};
use crate::network::{NetworkAllocation, NetworkManager};
use crate::snapshot::SnapshotCatalog;
use crate::snapshot_cow::{CowHandle, CowManager};
use crate::spawn::{spawn_direct, spawn_jailer};
use crate::vsock::{self, ExecInputMsg, OutputChunk, StartCommand};

mod boot;
mod checkpoint;
mod cleanup;
mod lifecycle;
mod reconcile;
mod types;
mod workload;

pub use types::{
    CheckpointInfo, CheckpointSummary, RestoreSandboxSpec, SandboxEvent, SandboxId, SandboxInfo,
    SandboxInstance, SandboxMountSpec, SandboxNetworkInfo, SandboxNetworkSpec, SandboxSpec,
    SandboxState, SandboxSummary,
};

const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Shared registry of live sandbox instances.
pub(crate) type InstanceMap = Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>;

/// Manages the full lifecycle of multiple sandbox microVMs.
pub struct SandboxManager {
    instances: Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: Arc<NetworkManager>,
    snapshots: Arc<SnapshotCatalog>,
    config: Arc<VmmConfig>,
    events_tx: broadcast::Sender<SandboxEvent>,
    cow_manager: Arc<CowManager>,
}

impl SandboxManager {
    /// Create a new manager from the given configuration.
    pub fn new(config: VmmConfig) -> Result<Self> {
        let network = Arc::new(NetworkManager::new(
            &config.network.cidr,
            &config.network.gateway,
            config.network.dns.clone(),
        )?);
        let snapshots = Arc::new(SnapshotCatalog::new(&config.firecracker.data_dir));
        let (events_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let cow_manager = Arc::new(
            CowManager::new(&config.firecracker.data_dir)
                .map_err(|e| VmmError::Config(format!("CowManager init: {e}")))?,
        );

        // Ensure the jailer chroot base directory exists.
        if let Some(ref jc) = config.firecracker.jailer {
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            std::fs::create_dir_all(base).map_err(VmmError::Io)?;
        }

        let config = Arc::new(config);

        // Sweep leftovers of a previous agent process (crash / respawn):
        // orphaned Firecracker processes, TAPs, dm devices, chroots. Only
        // meaningful inside a tokio runtime; sync constructions (unit tests)
        // have no previous instance to reconcile.
        if tokio::runtime::Handle::try_current().is_ok() {
            let config = Arc::clone(&config);
            let network = Arc::clone(&network);
            let cow_manager = Arc::clone(&cow_manager);
            tokio::spawn(async move {
                reconcile::sweep_orphans(&config, &network, &cow_manager).await;
            });
        }

        Ok(Self {
            instances: Arc::new(RwLock::new(HashMap::new())),
            network,
            snapshots,
            config,
            events_tx,
            cow_manager,
        })
    }
}
