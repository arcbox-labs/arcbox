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
use crate::snapshot::{SnapshotCatalog, SnapshotDraft};
use crate::snapshot_cow::{CowHandle, CowManager};
use crate::spawn::{spawn_direct, spawn_jailer};
use crate::vsock::{self, ExecInputMsg, ExitStatus, OutputChunk, StartCommand};

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
    /// Flips to `true` once the startup orphan sweep has finished. Create and
    /// restore gate on it so a re-created same-id sandbox can never race the
    /// sweep (see [`SandboxManager::await_reconcile`]).
    reconcile_done: tokio::sync::watch::Receiver<bool>,
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
        // orphaned Firecracker processes, TAPs, dm devices, chroots. Create and
        // restore wait for this to finish (await_reconcile) so a re-created
        // same-id sandbox can't have its deterministically-named resources torn
        // down mid-flight. Only meaningful inside a tokio runtime; sync
        // constructions (unit tests) have no previous instance to reconcile.
        let (reconcile_tx, reconcile_done) = tokio::sync::watch::channel(false);
        if tokio::runtime::Handle::try_current().is_ok() {
            let config = Arc::clone(&config);
            let network = Arc::clone(&network);
            let cow_manager = Arc::clone(&cow_manager);
            let snapshots = Arc::clone(&snapshots);
            tokio::spawn(async move {
                reconcile::sweep_orphans(&config, &network, &cow_manager, &snapshots).await;
                let _ = reconcile_tx.send(true);
            });
        } else {
            let _ = reconcile_tx.send(true);
        }

        Ok(Self {
            instances: Arc::new(RwLock::new(HashMap::new())),
            network,
            snapshots,
            config,
            events_tx,
            cow_manager,
            reconcile_done,
        })
    }

    /// Wait until the startup orphan sweep has completed.
    ///
    /// The sweep tears down resources by deterministic per-id names
    /// (`arcbox-snap-{id}`, the id's TAP, `arcbox-cow-{id}`) and adjusts the
    /// shared template refcount. A create/restore that runs concurrently with
    /// it — e.g. a client re-creating the same id right after an agent restart
    /// — would have its live device destroyed or a live template detached.
    /// Gating create/restore on the sweep removes that class entirely; it runs
    /// once, so after completion this returns immediately.
    pub(super) async fn await_reconcile(&self) {
        let mut rx = self.reconcile_done.clone();
        let _ = rx.wait_for(|&done| done).await;
    }
}

/// Validate a caller-supplied sandbox or snapshot id.
///
/// Ids become filesystem path components, jailer `--id` values, and dm/TAP name
/// fragments, so they are restricted to `[A-Za-z0-9_-]`. This rejects path
/// traversal (`/`, `\`, `..`), NUL, whitespace, and anything the jailer would
/// otherwise reject much later with an opaque boot failure.
pub(super) fn validate_id(kind: &str, id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(VmmError::Config(format!("{kind} must not be empty")));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(VmmError::Config(format!(
            "invalid {kind} {id:?}: only ASCII letters, digits, '-' and '_' are allowed"
        )));
    }
    Ok(())
}

/// Atomically reserve `id` in the instance map with a placeholder instance.
///
/// Create and restore both derive per-sandbox resources deterministically from
/// the id (CoW file `arcbox-cow-{id}`, dm device `arcbox-snap-{id}`, TAP name).
/// A check-then-insert with those resources set up in between is a TOCTOU: two
/// concurrent restores to the same id both pass the check, then the second
/// `create_sparse_file` truncates the file the first's loop device is backing,
/// corrupting the winner's rootfs. Reserving the id up front (check + insert
/// under one write lock) makes the loser fail fast with `AlreadyExists` before
/// it touches any shared resource. The reservation is removed on drop unless
/// [`IdReservation::commit`] is called, so every restore error path unwinds it.
pub(super) fn reserve_id(
    instances: &InstanceMap,
    id: &SandboxId,
    placeholder: SandboxInstance,
) -> Result<IdReservation> {
    let mut map = instances.write().unwrap();
    if map.contains_key(id) {
        return Err(VmmError::AlreadyExists(id.clone()));
    }
    map.insert(id.clone(), Arc::new(Mutex::new(placeholder)));
    Ok(IdReservation {
        instances: Arc::clone(instances),
        id: id.clone(),
        committed: false,
    })
}

/// RAII reservation returned by [`reserve_id`]. Drops the placeholder from the
/// instance map unless committed.
pub(super) struct IdReservation {
    instances: InstanceMap,
    id: SandboxId,
    committed: bool,
}

impl IdReservation {
    /// The reserved instance `Arc`, for populating it in place on success.
    pub(super) fn instance(&self) -> Arc<Mutex<SandboxInstance>> {
        self.instances
            .read()
            .unwrap()
            .get(&self.id)
            .cloned()
            .expect("reserved instance is present until commit/drop")
    }

    /// Keep the reservation: the instance is now fully initialized.
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for IdReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.instances.write().unwrap().remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder(id: &str) -> SandboxInstance {
        SandboxInstance::new(
            id.to_owned(),
            SandboxSpec::default(),
            None,
            PathBuf::from("/tmp/x"),
        )
    }

    #[test]
    fn reserve_id_rejects_a_concurrent_duplicate() {
        let instances: InstanceMap = Arc::new(RwLock::new(HashMap::new()));
        let first = reserve_id(&instances, &"dup".to_owned(), placeholder("dup")).unwrap();
        // A second reservation of the same id must fail while the first is live.
        assert!(matches!(
            reserve_id(&instances, &"dup".to_owned(), placeholder("dup")),
            Err(VmmError::AlreadyExists(_))
        ));
        first.commit();
        assert!(instances.read().unwrap().contains_key("dup"));
    }

    #[test]
    fn validate_id_accepts_safe_ids_and_rejects_traversal() {
        for ok in ["sandbox1", "a-b_c", "0f3e9d16-1234", "A_B-9"] {
            assert!(validate_id("id", ok).is_ok(), "{ok} should be valid");
        }
        for bad in ["", "..", ".", "a/b", "a\\b", "a b", "a.b", "a\0b", "../etc"] {
            assert!(
                validate_id("id", bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn dropped_reservation_unwinds_the_placeholder() {
        let instances: InstanceMap = Arc::new(RwLock::new(HashMap::new()));
        {
            let _r = reserve_id(&instances, &"tmp".to_owned(), placeholder("tmp")).unwrap();
            assert!(instances.read().unwrap().contains_key("tmp"));
            // no commit → dropped here
        }
        assert!(!instances.read().unwrap().contains_key("tmp"));
        // The id is free to reserve again after an unwound restore.
        let again = reserve_id(&instances, &"tmp".to_owned(), placeholder("tmp"));
        assert!(again.is_ok());
    }
}
