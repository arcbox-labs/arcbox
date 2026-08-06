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
mod execution;
mod lifecycle;
mod pause;
mod persistence;
mod pool;
mod reconcile;
mod types;
mod warm;
mod workload;

pub use execution::{
    ExecutionChannel, ExecutionOutput, ExecutionSnapshot, ExecutionSpec, StdinState,
};
pub use pause::reason as pause_reason;
pub use types::{
    CheckpointInfo, CheckpointSummary, RestoreSandboxSpec, SandboxEvent, SandboxId, SandboxInfo,
    SandboxInstance, SandboxMountSpec, SandboxNetworkInfo, SandboxNetworkSpec, SandboxSpec,
    SandboxState, SandboxSummary,
};

const EVENT_CHANNEL_CAPACITY: usize = 256;
type ReconcileResult = std::result::Result<(), Arc<str>>;

/// Shared registry of live sandbox instances.
pub(crate) type InstanceMap = Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>;

/// Manages the full lifecycle of multiple sandbox microVMs.
pub struct SandboxManager {
    instances: Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    records: Arc<persistence::SandboxRecordStore>,
    network: Arc<NetworkManager>,
    snapshots: Arc<SnapshotCatalog>,
    config: Arc<VmmConfig>,
    events_tx: broadcast::Sender<SandboxEvent>,
    cow_manager: Arc<CowManager>,
    /// Pre-warmed restore slots (CORE-78); see `pool.rs`.
    pool: Arc<pool::SlotPool>,
    /// Warm template snapshot bookkeeping (CORE-77); see `warm.rs`.
    warm: Arc<warm::WarmCache>,
    /// Addressable executions (CORE-55); see `execution.rs`.
    executions: Arc<execution::ExecutionRegistry>,
    /// Publishes the startup reconciliation result. Lifecycle and read APIs
    /// gate on it so callers never observe partial recovered state.
    reconcile_done: tokio::sync::watch::Receiver<Option<ReconcileResult>>,
}

impl SandboxManager {
    /// Create a new manager from the given configuration.
    pub fn new(config: VmmConfig) -> Result<Self> {
        let records = Arc::new(persistence::SandboxRecordStore::new(Path::new(
            &config.firecracker.data_dir,
        ))?);
        drop(records.load_all()?);
        let network = Arc::new(NetworkManager::with_quarantine_dir(
            &config.network.cidr,
            &config.network.gateway,
            config.network.dns.clone(),
            Path::new(&config.firecracker.data_dir).join("sandbox-network-quarantine"),
            config.firecracker.sandbox_datapath,
        )?);
        let snapshots = Arc::new(SnapshotCatalog::new(&config.firecracker.data_dir));
        let (events_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let cow_manager = Arc::new(CowManager::new(&config.firecracker.data_dir)?);

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
        let (reconcile_tx, reconcile_done) = tokio::sync::watch::channel(None);
        let executions = Arc::new(execution::ExecutionRegistry::default());
        let instances = Arc::new(RwLock::new(HashMap::new()));
        if tokio::runtime::Handle::try_current().is_ok() {
            let config = Arc::clone(&config);
            let network = Arc::clone(&network);
            let cow_manager = Arc::clone(&cow_manager);
            let snapshots = Arc::clone(&snapshots);
            let records = Arc::clone(&records);
            let instances = Arc::clone(&instances);
            tokio::spawn(async move {
                let result = async {
                    let swept = reconcile::sweep_orphans(
                        &config,
                        &network,
                        &cow_manager,
                        &snapshots,
                        &records,
                    )
                    .await?;
                    let inactive = reconcile::normalize_durable_records(
                        &records,
                        Path::new(&config.firecracker.data_dir),
                        Some(&swept.ids),
                    )?;
                    reconcile::finalize_sweep(swept).await?;
                    network.mark_reconciled();
                    Ok::<_, VmmError>(inactive)
                }
                .await
                .map(|inactive| {
                    let mut map = instances.write().unwrap();
                    map.extend(
                        inactive
                            .into_iter()
                            .map(|instance| (instance.id.clone(), Arc::new(Mutex::new(instance)))),
                    );
                })
                .map_err(|error| Arc::<str>::from(error.to_string()));
                let _ = reconcile_tx.send(Some(result));
            });
            // Executions die with their sandbox; purge on terminal events so
            // every teardown path (stop / remove / TTL / boot failure) is
            // covered without threading the registry through each of them.
            execution::spawn_teardown_purge(Arc::clone(&executions), events_tx.subscribe());
        } else {
            let inactive = reconcile::normalize_durable_records(
                &records,
                Path::new(&config.firecracker.data_dir),
                None,
            )?;
            network.mark_reconciled();
            instances.write().unwrap().extend(
                inactive
                    .into_iter()
                    .map(|instance| (instance.id.clone(), Arc::new(Mutex::new(instance)))),
            );
            let _ = reconcile_tx.send(Some(Ok(())));
        }

        Ok(Self {
            instances,
            records,
            network,
            snapshots,
            config,
            events_tx,
            cow_manager,
            pool: Arc::new(pool::SlotPool::default()),
            warm: Arc::new(warm::WarmCache::default()),
            executions,
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
    pub(super) async fn await_reconcile(&self) -> Result<()> {
        let mut rx = self.reconcile_done.clone();
        let result = rx
            .wait_for(Option::is_some)
            .await
            .map_err(|error| VmmError::Other(format!("sandbox reconciliation stopped: {error}")))?
            .clone()
            .expect("wait_for returned only after reconciliation completed");
        result.map_err(|error| {
            VmmError::Other(format!(
                "sandbox durable-state reconciliation failed: {error}"
            ))
        })
    }

    fn check_reconcile(&self) -> Result<()> {
        let result = self.reconcile_done.borrow().clone();
        match result {
            None => Err(VmmError::Other(
                "sandbox durable-state reconciliation is still running".into(),
            )),
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(VmmError::Other(format!(
                "sandbox durable-state reconciliation failed: {error}"
            ))),
        }
    }

    /// Return sandbox IDs whose inactive network allocation still awaits host
    /// forwarding cleanup.
    pub async fn pending_network_cleanups(&self) -> Result<Vec<(String, String)>> {
        self.await_reconcile().await?;
        Ok(self.network.pending_quarantines())
    }

    /// Validate one exact pending host-cleanup ticket.
    pub async fn validate_network_cleanup(
        &self,
        id: &str,
        token: &str,
    ) -> Result<NetworkAllocation> {
        self.await_reconcile().await?;
        self.network.validate_quarantine(id, token)
    }

    /// Recycle one exact inactive sandbox generation after forwarding cleanup.
    pub async fn finalize_network_cleanup(&self, id: &str, token: &str) -> Result<()> {
        self.await_reconcile().await?;
        self.network.finalize_quarantine(id, token)
    }

    /// Reject allocation/exposure until startup cleanup replay is finalized.
    pub fn ensure_startup_cleanup_complete(&self) -> Result<()> {
        self.network.ensure_startup_cleanup_complete()
    }

    /// Wait until the current agent generation's startup cleanup is complete.
    pub async fn wait_startup_cleanup_complete(&self) {
        self.network.wait_startup_cleanup_complete().await;
    }

    /// Opaque ticket for the host cleanup pass required after agent startup.
    pub async fn startup_cleanup_token(&self) -> Result<Option<String>> {
        self.await_reconcile().await?;
        Ok(self.network.startup_cleanup_token())
    }

    /// Validate the current process-generation startup cleanup ticket.
    pub async fn validate_startup_cleanup(&self, token: &str) -> Result<()> {
        self.await_reconcile().await?;
        self.network.validate_startup_cleanup(token)
    }

    /// Release the startup gate once host listeners and legacy DNAT are gone.
    pub async fn finalize_startup_cleanup(&self, token: &str) -> Result<()> {
        self.await_reconcile().await?;
        self.network.finalize_startup_cleanup(token)
    }

    /// Return the active generation's network identity: the external pool IP
    /// (what DNS, expose, and the API report), its opaque cleanup token, and
    /// how expose DNAT must target the sandbox (CORE-81/CORE-83).
    pub fn sandbox_network_identity(&self, id: &str) -> Result<SandboxNetworkIdentity> {
        self.ensure_startup_cleanup_complete()?;
        let instance = self.get_instance(&id.to_owned())?;
        let instance = instance.lock().unwrap();
        let allocation = instance
            .network
            .as_ref()
            .ok_or_else(|| VmmError::WrongState {
                id: id.to_owned(),
                expected: "sandbox with an active network allocation".into(),
                actual: instance.state.to_string(),
            })?;
        Ok(SandboxNetworkIdentity {
            ip: allocation.ip_address,
            cleanup_token: allocation.cleanup_token.clone(),
            expose: self
                .network
                .expose_target(&allocation.tap_name, instance.net_invariant),
        })
    }
}

/// A sandbox's network identity as seen by forwarding and DNS consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxNetworkIdentity {
    /// External pool IP — the address the rest of the system keeps using.
    pub ip: std::net::Ipv4Addr,
    /// Opaque generation token carried through host cleanup finalization.
    pub cleanup_token: String,
    /// How expose DNAT must target this sandbox, decided by the datapath
    /// actually applied to its TAP (CORE-81/CORE-83).
    pub expose: crate::network::ExposeTarget,
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
    let instance = Arc::new(Mutex::new(placeholder));
    map.insert(id.clone(), Arc::clone(&instance));
    Ok(IdReservation {
        instances: Arc::clone(instances),
        id: id.clone(),
        instance,
        committed: false,
    })
}

pub(super) fn ensure_current_instance(
    instances: &InstanceMap,
    id: &str,
    expected: &Arc<Mutex<SandboxInstance>>,
) -> Result<()> {
    if instances
        .read()
        .unwrap()
        .get(id)
        .is_some_and(|current| Arc::ptr_eq(current, expected))
    {
        Ok(())
    } else {
        Err(VmmError::WrongState {
            id: id.to_owned(),
            expected: "the sandbox generation selected by this operation".into(),
            actual: "a newer generation now owns this sandbox ID".into(),
        })
    }
}

/// RAII reservation returned by [`reserve_id`]. Drops the placeholder from the
/// instance map unless committed.
pub(super) struct IdReservation {
    instances: InstanceMap,
    id: SandboxId,
    instance: Arc<Mutex<SandboxInstance>>,
    committed: bool,
}

impl IdReservation {
    /// The reserved instance `Arc`, for populating it in place on success.
    pub(super) fn instance(&self) -> Arc<Mutex<SandboxInstance>> {
        Arc::clone(&self.instance)
    }

    /// Keep the reservation: the instance is now fully initialized.
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for IdReservation {
    fn drop(&mut self) {
        if !self.committed {
            let mut map = self.instances.write().unwrap();
            if map
                .get(&self.id)
                .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
            {
                map.remove(&self.id);
            }
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

    #[test]
    fn stale_reservation_does_not_remove_a_replacement() {
        let instances: InstanceMap = Arc::new(RwLock::new(HashMap::new()));
        let reservation = reserve_id(&instances, &"same".to_owned(), placeholder("same")).unwrap();
        let replacement = Arc::new(Mutex::new(placeholder("same")));
        instances
            .write()
            .unwrap()
            .insert("same".to_owned(), Arc::clone(&replacement));

        assert!(ensure_current_instance(&instances, "same", &reservation.instance).is_err());
        drop(reservation);

        let current = instances.read().unwrap()["same"].clone();
        assert!(Arc::ptr_eq(&current, &replacement));
    }
}
