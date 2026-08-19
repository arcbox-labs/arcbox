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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use arcbox_vm_driver::net::{
    AttachMode, GuestNetwork, HostIngress, NetworkIdentity, NetworkLease, NetworkMode,
    NetworkPolicy, NetworkReconcile,
};
use arcbox_vm_driver::{
    CheckpointFormat, CheckpointImage, CheckpointKind, DiskSource, IsolationSpec, NicSpec, Prepare,
    PreparedVm, Staging, VmDriver, VmHandle, VmId,
};
use chrono::{DateTime, Utc};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::agent::{ExecInputMsg, ExitStatus, OutputChunk, PortWait, StartCommand};
use crate::agent::{GuestAgent, Readiness};
use crate::config::VmmConfig;
use crate::environment::NodeEnvironment;
use crate::error::{Result, VmmError};
use crate::lifecycle::actor::{
    Command, ComputerActor, ComputerSeed, ComputerSnapshot, Deadlines, Mailbox, Seeded,
};
use crate::lifecycle::event::{Provision, RestoreOrigin};
use crate::lifecycle::flows::{BootLaunch, ComputerFlows, ComputerServices, Launch, RestoreLaunch};
use crate::lifecycle::runtime::{ComputerRuntime, Runtime};
use crate::snapshot::{SnapshotCatalog, SnapshotMeta};
use crate::snapshot_cow::{CowHandle, CowManager};
use crate::template_catalog::TemplateCatalog;

pub(crate) mod boot;
mod checkpoint;
pub(crate) mod cleanup;
mod execution;
mod files;
mod lifecycle;
pub(crate) mod pause;
pub(crate) mod policy;
pub(crate) mod pool;
pub(crate) mod reconcile;
pub(crate) mod record;
pub(crate) mod spec;
mod templates;
mod timers;
pub(crate) mod types;
pub(crate) mod warm;
pub(crate) mod workload;

pub use execution::{
    ExecutionChannel, ExecutionOutput, ExecutionSnapshot, ExecutionSpec, StdinState,
};
pub use pause::reason as pause_reason;
pub(crate) use spec::ROOTFS_DISK_ID;
pub(crate) use types::NetworkAttachment;
pub use types::{
    CheckpointInfo, CheckpointSummary, IdleAction, LifecycleUpdate, RestoreSandboxSpec,
    SandboxEvent, SandboxId, SandboxInfo, SandboxMountSpec, SandboxNetworkInfo, SandboxNetworkSpec,
    SandboxSpec, SandboxState, SandboxSummary, TemplateWarmRef,
};

const EVENT_CHANNEL_CAPACITY: usize = 256;
type ReconcileResult = std::result::Result<(), Arc<str>>;

/// One computer as the registry holds it: its mailbox, its read snapshot, and
/// the identity that tells this incarnation from a same-id replacement.
///
/// What replaced `Arc<Mutex<ComputerRuntime>>`. Every verb is a send on the
/// mailbox and every read is a borrow of the snapshot, so neither the map
/// lock nor a per-computer mutex is ever held across an await — the
/// discipline `list_sandboxes` used to have to state.
#[derive(Clone)]
pub(crate) struct ComputerRef {
    mailbox: Mailbox,
    snapshot: tokio::sync::watch::Receiver<ComputerSnapshot>,
    incarnation: Uuid,
}

/// The live computers, by id.
pub(crate) type Computers = Arc<RwLock<HashMap<SandboxId, ComputerRef>>>;

/// Manages the full lifecycle of multiple sandbox microVMs.
pub struct SandboxManager {
    computers: Computers,
    records: Arc<record::SandboxRecordStore>,
    /// What every computer's flows are built from — the driver, the guest
    /// network, the agent factory, the record store, the catalogs and the
    /// pool. One `Arc`, cloned into each actor.
    services: Arc<ComputerServices>,
    snapshots: Arc<SnapshotCatalog>,
    /// Template catalog (CORE-107); see `templates.rs` for the manager surface.
    templates: Arc<TemplateCatalog>,
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
    /// Whether the deadline timers may fire. `false` until
    /// [`Self::into_shared`], which is the inertness contract a plain
    /// [`Self::new`] manager has: unit tests of unrelated surfaces rely on it.
    /// The actors hold receivers, so the flip reaches every one of them —
    /// including the ones the startup sweep seeded before it was flipped.
    timers_enabled: tokio::sync::watch::Sender<bool>,
}

impl SandboxManager {
    /// Create a new manager from the given configuration, over the
    /// environment-specific components the composer supplies.
    ///
    /// Fails with [`VmmError::Config`] when the environment's driver lacks a
    /// capability every sandbox needs — `Prepare` (the flows spawn the VMM
    /// ahead of the guest), `Staging` (every flow brings its computer's
    /// files into the area the VMM can reach), `Vsock` (the guest agent is
    /// reached over it), or whatever the agent factory's readiness gate
    /// needs (`VsockListen` for the guest's dial-out) — or when its guest
    /// network offers no `NetworkReconcile` (the cleanup-token protocol is
    /// how a host releases the addresses a previous process held), so an
    /// environment missing one is refused here instead of at the first boot
    /// or the first cleanup ticket.
    pub fn new(config: VmmConfig, environment: NodeEnvironment) -> Result<Self> {
        let NodeEnvironment {
            driver,
            network,
            agent,
            cow_manager,
        } = environment;
        let capabilities = driver.capabilities();
        for (missing, capability, need) in [
            (
                driver.prepare().is_none(),
                "prepare",
                "the boot and pool flows spawn the VMM ahead of the guest",
            ),
            (
                !capabilities.staging,
                "staging",
                "every flow brings the files its computer boots from into the area the VMM \
                 can reach, and pause takes the disk back out of it",
            ),
            // The last hard-wired transport assumption in this layer: every
            // agent implementation the crate ships reaches its guest through
            // the VM handle. A composition root that knows its Computers are
            // not dialable at all is what will retire it.
            (
                !capabilities.vsock,
                "vsock",
                "the guest agent is reached over vsock",
            ),
            // What the readiness gate needs is the agent port's answer, not
            // this layer's: only a dial-out has to be listened for before
            // the guest starts.
            (
                matches!(agent.readiness(), Readiness::DialOut { .. })
                    && !capabilities.vsock_listen,
                "vsock_listen",
                "the readiness gate is the guest's vsock dial-out",
            ),
        ] {
            if missing {
                return Err(VmmError::Config(format!(
                    "VM driver `{}` has no {capability} capability; {need}",
                    driver.name()
                )));
            }
        }
        let records = Arc::new(record::SandboxRecordStore::new(Path::new(
            &config.firecracker.data_dir,
        ))?);
        drop(records.load_all()?);
        if network.reconcile().is_none() {
            return Err(VmmError::Config(
                "guest network has no reconcile capability; the quarantine ledger is how a host \
                 releases the addresses a previous process held"
                    .into(),
            ));
        }
        let snapshots = Arc::new(SnapshotCatalog::new(&config.firecracker.data_dir));
        let templates = Arc::new(TemplateCatalog::new(&config.firecracker.data_dir));
        let (events_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let config = Arc::new(config);

        // Sweep leftovers of a previous agent process (crash / respawn):
        // orphaned VMM processes, TAPs, dm devices, chroots. Create and
        // restore wait for this to finish (await_reconcile) so a re-created
        // same-id sandbox can't have its deterministically-named resources torn
        // down mid-flight. Only meaningful inside a tokio runtime; sync
        // constructions (unit tests) have no previous instance to reconcile.
        let (reconcile_tx, reconcile_done) = tokio::sync::watch::channel(None);
        let executions = Arc::new(execution::ExecutionRegistry::default());
        let computers: Computers = Arc::new(RwLock::new(HashMap::new()));
        let pool = Arc::new(pool::SlotPool::default());
        let (timers_enabled, timers_gate) = tokio::sync::watch::channel(false);
        let services = Arc::new(ComputerServices {
            driver,
            network,
            agents: agent,
            config: Arc::clone(&config),
            cow_manager: Arc::clone(&cow_manager),
            records: Arc::clone(&records),
            snapshots: Arc::clone(&snapshots),
            events_tx: events_tx.clone(),
            pool: Arc::clone(&pool),
        });
        if tokio::runtime::Handle::try_current().is_ok() {
            let config = Arc::clone(&config);
            let cow_manager = Arc::clone(&cow_manager);
            let snapshots = Arc::clone(&snapshots);
            let records = Arc::clone(&records);
            let computers = Arc::clone(&computers);
            let services = Arc::clone(&services);
            let network = Arc::clone(&services.network);
            let driver = Arc::clone(&services.driver);
            tokio::spawn(async move {
                let result = async {
                    let mut swept = reconcile::sweep_orphans(
                        &config,
                        driver.as_ref(),
                        &*network,
                        &cow_manager,
                        &snapshots,
                        &records,
                    )
                    .await?;
                    let mut runtime = swept.take_runtime();
                    let mut inactive = Vec::new();
                    let normalized = reconcile::normalize_durable_records(
                        &records,
                        Path::new(&config.firecracker.data_dir),
                        Some(&mut runtime),
                        &mut inactive,
                    );
                    // A reclaimed sandbox is in exactly one of these two by
                    // now — never claimed, or built into an instance — and
                    // dropping either would kill its guest while leaving its
                    // lease and template refcount held. Release both before
                    // reporting the refusal.
                    reconcile::release_unclaimed(&mut runtime, &*network, &cow_manager).await;
                    if let Err(error) = normalized {
                        reconcile::release_instances(&mut inactive, &*network, &cow_manager).await;
                        return Err(error);
                    }
                    // Publish before anything else can fail. The reclaimed
                    // sandboxes' only handles live in these computers, so a
                    // later error — a runtime directory that will not delete,
                    // say — would otherwise un-reclaim every guest by
                    // dropping them, over something none of them caused.
                    reconcile::seed_computers(inactive, &computers, &services, &timers_gate);
                    reconcile::finalize_sweep(swept).await?;
                    reconcile_capability(&*network).replay_complete();
                    Ok::<_, VmmError>(())
                }
                .await
                .map_err(|error| Arc::<str>::from(error.to_string()));
                let _ = reconcile_tx.send(Some(result));
            });
            // Executions die with their sandbox; purge on terminal events so
            // every teardown path (stop / remove / TTL / boot failure) is
            // covered without threading the registry through each of them.
            execution::spawn_teardown_purge(Arc::clone(&executions), events_tx.subscribe());
        } else {
            let mut inactive = Vec::new();
            reconcile::normalize_durable_records(
                &records,
                Path::new(&config.firecracker.data_dir),
                None,
                &mut inactive,
            )?;
            reconcile_capability(&*services.network).replay_complete();
            reconcile::seed_computers(inactive, &computers, &services, &timers_enabled.subscribe());
            let _ = reconcile_tx.send(Some(Ok(())));
        }

        Ok(Self {
            computers,
            records,
            services,
            snapshots,
            templates,
            config,
            events_tx,
            cow_manager,
            pool,
            warm: Arc::new(warm::WarmCache::default()),
            executions,
            reconcile_done,
            timers_enabled,
        })
    }

    /// Wrap the manager in an `Arc` and let its computers' deadline timers
    /// fire.
    ///
    /// Production embedders (the guest agent's `SandboxService`) must use
    /// this; a plain [`Self::new`] manager never fires idle timers (unit
    /// tests exercising unrelated surfaces rely on that inertness).
    ///
    /// One `watch` flip, which every actor is holding a receiver for — the
    /// weak self-handle a detached expiry task needed is gone with the
    /// detached task.
    #[must_use]
    pub fn into_shared(self) -> Arc<Self> {
        // `send_replace`, not `send`: a manager with no computers yet has no
        // receivers, and `send` would refuse — leaving every actor spawned
        // afterwards reading a gate that was never opened.
        self.timers_enabled.send_replace(true);
        Arc::new(self)
    }

    /// What every actor this manager spawns is built from.
    pub(super) fn spawn_context(
        &self,
    ) -> (Arc<ComputerServices>, tokio::sync::watch::Receiver<bool>) {
        (Arc::clone(&self.services), self.timers_enabled.subscribe())
    }

    /// This computer's registry entry.
    pub(super) fn computer(&self, id: &SandboxId) -> Result<ComputerRef> {
        self.check_reconcile()?;
        self.computers
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| VmmError::NotFound(id.clone()))
    }

    /// This computer's mailbox.
    pub(super) fn mailbox(&self, id: &SandboxId) -> Result<Mailbox> {
        Ok(self.computer(id)?.mailbox)
    }

    /// What a read of this computer sees, without touching its mailbox.
    pub(super) fn snapshot(&self, id: &SandboxId) -> Result<ComputerSnapshot> {
        Ok(self.computer(id)?.snapshot.borrow().clone())
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
        Ok(self
            .reconcile_network()
            .pending_cleanups()
            .await
            .map_err(VmmError::from)?
            .into_iter()
            .map(|(vm, token)| (vm.as_str().to_owned(), token))
            .collect())
    }

    /// Validate one exact pending host-cleanup ticket.
    ///
    /// Returns the lease that generation held: the host's forwarding rules
    /// for it are keyed by its address, and after an agent restart the
    /// quarantine ledger is the only place that address survives.
    pub async fn validate_network_cleanup(&self, id: &str, token: &str) -> Result<NetworkLease> {
        self.await_reconcile().await?;
        Ok(self
            .reconcile_network()
            .validate_cleanup(&VmId::new(id)?, token)
            .await?)
    }

    /// Recycle one exact inactive sandbox generation after forwarding cleanup.
    pub async fn finalize_network_cleanup(&self, id: &str, token: &str) -> Result<()> {
        self.await_reconcile().await?;
        Ok(self
            .reconcile_network()
            .finalize_cleanup(&VmId::new(id)?, token)
            .await?)
    }

    /// Wait until the current agent generation's startup cleanup is complete.
    pub async fn wait_startup_cleanup_complete(&self) {
        self.reconcile_network()
            .wait_startup_cleanup_complete()
            .await;
    }

    /// Opaque ticket for the host cleanup pass required after agent startup.
    pub async fn startup_cleanup_token(&self) -> Result<Option<String>> {
        self.await_reconcile().await?;
        Ok(self.reconcile_network().startup_cleanup_token().await)
    }

    /// Validate the current process-generation startup cleanup ticket.
    pub async fn validate_startup_cleanup(&self, token: &str) -> Result<()> {
        self.await_reconcile().await?;
        Ok(self
            .reconcile_network()
            .validate_startup_cleanup(token)
            .await?)
    }

    /// Release the startup gate once host listeners and legacy DNAT are gone.
    pub async fn finalize_startup_cleanup(&self, token: &str) -> Result<()> {
        self.await_reconcile().await?;
        Ok(self
            .reconcile_network()
            .finalize_startup_cleanup(token)
            .await?)
    }

    /// The guest network's cleanup protocol.
    pub(super) fn reconcile_network(&self) -> &dyn NetworkReconcile {
        reconcile_capability(&*self.services.network)
    }

    /// Return the active generation's network identity: the external pool IP
    /// (what DNS, expose, and the API report), its opaque cleanup token, and
    /// how expose DNAT must target the sandbox (CORE-81/CORE-83).
    ///
    /// No startup-cleanup gate here, unlike every method above. An identity
    /// needs a live lease; a lease comes only from `reserve`, which the
    /// guest network refuses while the same startup barrier is closed; and
    /// both callers in the guest agent await `wait_startup_cleanup_complete`
    /// before asking. The gate this used to take could therefore only ever
    /// have fired for a sandbox that has no lease to report anyway, and it
    /// has no non-blocking form on the port.
    pub fn sandbox_network_identity(&self, id: &str) -> Result<SandboxNetworkIdentity> {
        let snapshot = self.snapshot(&id.to_owned())?;
        let lease = snapshot
            .lease
            .as_ref()
            .ok_or_else(|| VmmError::WrongState {
                id: id.to_owned(),
                expected: "sandbox with an active network allocation".into(),
                actual: snapshot.state.to_string(),
            })?;
        Ok(SandboxNetworkIdentity {
            ip: lease.ipv4()?,
            cleanup_token: lease.cleanup_token.clone(),
            expose: self.services.network.host_ingress(lease)?,
        })
    }
}

/// What the sandbox stack needs from a [`NetworkLease`] beyond its fields.
///
/// The port's lease carries an [`IpAddr`](std::net::IpAddr) because a guest
/// network need not be IPv4 (the platform's node dataplane is IPv6-only),
/// while everything downstream of *this* manager — the pool address it
/// reports, the netmask a legacy guest is reconfigured with, the crash
/// journal's on-disk shape — is v4. The narrowing happens here, once, and
/// says so when a lease cannot answer.
pub(super) trait LeaseExt {
    /// The lease's address.
    fn ipv4(&self) -> Result<std::net::Ipv4Addr>;
    /// The gateway the guest routes through.
    fn gateway_ipv4(&self) -> Result<std::net::Ipv4Addr>;
}

impl LeaseExt for NetworkLease {
    fn ipv4(&self) -> Result<std::net::Ipv4Addr> {
        ipv4(self.ip)
    }

    fn gateway_ipv4(&self) -> Result<std::net::Ipv4Addr> {
        ipv4(self.gateway)
    }
}

/// One address of a lease or identity, narrowed. See [`LeaseExt`].
pub(super) fn ipv4(address: std::net::IpAddr) -> Result<std::net::Ipv4Addr> {
    match address {
        std::net::IpAddr::V4(v4) => Ok(v4),
        std::net::IpAddr::V6(v6) => Err(VmmError::Network(format!(
            "the guest network offered {v6}; this manager's sandboxes are IPv4-only"
        ))),
    }
}

/// The subnet mask `prefix_len` describes, clamped at /32 so an
/// out-of-range prefix cannot overflow the shift.
pub(super) fn netmask(prefix_len: u8) -> std::net::Ipv4Addr {
    let prefix = prefix_len.min(32);
    if prefix == 0 {
        std::net::Ipv4Addr::UNSPECIFIED
    } else {
        std::net::Ipv4Addr::from(!0u32 << (32 - prefix))
    }
}

/// The connectivity every sandbox gets: egress through the host's address,
/// which is what the System VM's netfilter provides for the pool.
pub(super) const fn sandbox_network_policy() -> NetworkPolicy {
    NetworkPolicy {
        mode: NetworkMode::Nat,
    }
}

/// The mode a guest's interface is activated in, which is also the mode
/// [`GuestNetwork::identity`] must be read under: a fresh boot and every
/// invariant-snapshot restore take the fixed identity, and only checkpoints
/// taken before it existed carry the pool address on the interface itself.
pub(super) const fn attach_mode(net_invariant: bool) -> AttachMode {
    if net_invariant {
        AttachMode::Invariant
    } else {
        AttachMode::LegacySnapshot
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
    ///
    /// The guest network's own answer, passed through unchanged: rendering
    /// it as forwarding rules is the composing host's job, and only that
    /// host knows which network it built.
    pub expose: HostIngress,
}

/// The guest network's cleanup protocol, which [`SandboxManager::new`]
/// requires — the quarantine ledger gates every address the pool hands
/// out, and the startup sweep gates the pool itself.
pub(super) fn reconcile_capability(network: &dyn GuestNetwork) -> &dyn NetworkReconcile {
    network
        .reconcile()
        .expect("SandboxManager::new requires the guest network's reconcile capability")
}

/// The driver's `Prepare` capability, which [`SandboxManager::new`]
/// requires — the boot, pool, and restore flows all spawn the VMM before
/// there is a guest to run on it.
pub(crate) fn prepare_capability(driver: &dyn VmDriver) -> &dyn Prepare {
    driver
        .prepare()
        .expect("SandboxManager::new requires the driver's Prepare capability")
}

/// A grip's `Staging` capability, which [`SandboxManager::new`] requires —
/// every flow that puts a guest on a VMM first brings that guest's files
/// into the area the VMM can reach, and pause takes its disk back out of
/// it.
///
/// Takes the accessor's answer rather than the grip it came from: both
/// grips on a VM have one and they name the same area, so a computer
/// booted here asks its [`PreparedVm`] and one this process adopted asks
/// its [`VmHandle`](arcbox_vm_driver::VmHandle).
pub(crate) fn staging_capability(staging: Option<&dyn Staging>) -> &dyn Staging {
    staging.expect("SandboxManager::new requires the driver's Staging capability")
}

/// The VMM's pid as the crash journal records it: what a restart sweep
/// kills before tearing the sandbox's other resources down.
pub(crate) fn journaled_pid(prepared: &dyn PreparedVm) -> Option<i32> {
    prepared
        .record()
        .process
        .and_then(|process| i32::try_from(process.pid).ok())
}

/// The isolation every sandbox VMM runs under: the jailer's, when one is
/// configured; none otherwise (direct mode).
pub(crate) fn isolation_spec(config: &VmmConfig) -> Result<IsolationSpec> {
    config
        .firecracker
        .jailer
        .as_ref()
        .map_or(Ok(IsolationSpec::None), IsolationSpec::try_from)
}

/// Where a paused computer's retained disk overlay lives: a function of the
/// data dir and the id, which is why the flows that keep, rename, look for
/// and delete it can all say it the same way.
pub(crate) fn preserved_cow_file(config: &VmmConfig, id: &str) -> PathBuf {
    PathBuf::from(&config.firecracker.data_dir)
        .join("cow")
        .join(format!("arcbox-cow-{id}.img"))
}

/// A checkpoint as the catalog holds it, which is what
/// [`Staging::stage_checkpoint`] takes and what the driver reads back.
///
/// The catalog writes one directory per checkpoint and puts `vmstate` and
/// `mem` in it, so the image is that directory — read off the meta's own
/// `vmstate_path` rather than recomputed from the catalog's layout, which
/// this layer does not own. Its name is what the driver stages the
/// checkpoint under, and a restore reproduces that name from the same
/// image, so the two cannot drift. The format is the one the catalog
/// recorded at capture; legacy entries default to the Firecracker format.
pub(crate) fn catalogued_checkpoint(meta: &SnapshotMeta) -> Result<CheckpointImage> {
    let dir = meta.vmstate_path.parent().ok_or_else(|| {
        VmmError::Snapshot(format!(
            "checkpoint {} records a vmstate at {}, which is in no directory",
            meta.id,
            meta.vmstate_path.display()
        ))
    })?;
    Ok(CheckpointImage {
        dir: dir.to_path_buf(),
        format: CheckpointFormat::new(&meta.format),
        kind: CheckpointKind::Full,
    })
}

/// Validate a caller-supplied sandbox or snapshot id.
///
/// Ids become filesystem path components and dm/TAP name fragments, so they are
/// restricted to `[A-Za-z0-9_-]`. This rejects path traversal (`/`, `\`, `..`),
/// NUL and whitespace. The narrower rule a VMM imposes on the id it runs under
/// is *not* checked here — that is [`VmId`]'s, applied by
/// [`validate_new_sandbox_id`] where an id becomes a VM identity.
///
/// Deliberately NO length cap here: this also runs against persisted
/// records, and what one legacy over-long id would cost differs by call
/// site. On the sweep path it costs that record its reconciliation — the
/// journal is skipped rather than acted on, and every resource it names
/// is held (`reconcile::sweep_orphans`). On a record *load* it costs
/// every record theirs: [`SandboxRecordStore::load_all`] validates each
/// id and propagates, so one rejection aborts the whole startup read,
/// which is the stronger reason the cap is absent. It also runs against
/// snapshot / execution ids that never become a VM identity at all. Both
/// limits the driver imposes are enforced only where a sandbox id enters
/// the system: [`validate_new_sandbox_id`].
///
/// The gap between this alphabet and [`VmId`]'s is not academic: `_` is
/// legal here and is not a `VmId`, so every record a pre-#680 process
/// wrote for an `inst_…` sandbox is one this process cannot name — which
/// is exactly what the sweep and the quarantine ledger read back.
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

/// Validate a sandbox id at request ingress (create / restore), where it
/// becomes the identity the VM runs under.
///
/// Both halves belong to the driver, and neither is restated here. The
/// alphabet and the 64-byte ceiling are [`VmId`]'s: an id a VMM will not
/// take is refused by construction, and Firecracker — which `panic!`s on
/// its own `--id` in *both* jailed and direct mode — is what that rule is
/// cut to. The length budget is [`VmDriver::id_budget`], measured on the
/// layout the configured driver will actually lay down, so a longer chroot
/// base or binary name tightens it rather than silently reintroducing the
/// failure it exists to prevent.
///
/// Refusing here is the whole point: past this call the id is validated
/// again inside the async boot task, where the refusal arrives with
/// nothing tying it back to the request that caused it — an
/// `InvalidInstanceId` under the jailer, an abort under bare Firecracker,
/// and an opaque "timed out waiting for socket" when it is the length
/// (the driver's readiness probe is a `connect()`, which ENAMETOOLONGs on
/// every attempt while the VMM is up and bound inside its chroot; caught
/// by the CORE-107 prewarm e2e, whose 51-char builder id overflowed the
/// stock budget).
pub(super) fn validate_new_sandbox_id(
    id: &str,
    driver: &dyn VmDriver,
    config: &VmmConfig,
) -> Result<()> {
    VmId::new(id)?;
    if let Some(budget) = driver.id_budget(&isolation_spec(config)?)
        && id.len() > budget
    {
        return Err(VmmError::Config(format!(
            "invalid sandbox id {id:?}: at most {budget} characters under this \
             driver's layout (its sockets must fit the AF_UNIX path limit)"
        )));
    }
    Ok(())
}

/// Atomically claim `id` in the registry and stand up its actor.
///
/// Create and restore both derive per-computer resources deterministically
/// from the id (CoW file `arcbox-cow-{id}`, dm device `arcbox-snap-{id}`, TAP
/// name). A check-then-insert with those resources set up in between is a
/// TOCTOU: two concurrent restores to the same id both pass the check, then
/// the second `create_sparse_file` truncates the file the first's loop device
/// is backing, corrupting the winner's rootfs. Claiming the id up front
/// (check + insert under one write lock) makes the loser fail fast with
/// `AlreadyExists` before it touches any shared resource.
///
/// The actor is **not** spawned here. Its seed needs the durable generation
/// and the deadlines the record computes, and both are resolved after the
/// claim; the mailbox and the read snapshot exist from the claim on, so a
/// caller that finds the entry finds a usable computer either way. The claim
/// is released on drop unless [`ActorReservation::spawn`] is called, so every
/// error path unwinds it.
pub(crate) fn reserve_actor(
    computers: &Computers,
    id: &SandboxId,
    runtime: ComputerRuntime,
) -> Result<ActorReservation> {
    let mut map = computers.write().unwrap();
    if map.contains_key(id) {
        return Err(VmmError::AlreadyExists(id.clone()));
    }
    let incarnation = Uuid::new_v4();
    let (mailbox_tx, commands) = tokio::sync::mpsc::unbounded_channel();
    let runtime = Arc::new(Mutex::new(runtime));
    let (snapshot_tx, snapshot) = tokio::sync::watch::channel(ComputerSnapshot::project(
        &runtime.lock().unwrap(),
        SandboxState::Starting,
        Deadlines::default(),
    ));
    map.insert(
        id.clone(),
        ComputerRef {
            mailbox: Mailbox::new(mailbox_tx.clone()),
            snapshot,
            incarnation,
        },
    );
    drop(map);
    Ok(ActorReservation {
        computers: Arc::clone(computers),
        id: id.clone(),
        incarnation,
        runtime,
        mailbox: Mailbox::new(mailbox_tx),
        commands: Some(commands),
        snapshot_tx: Some(snapshot_tx),
    })
}

/// A claimed id, its runtime state, and the channels its actor will run on.
///
/// Dropping it without [`Self::spawn`] releases the claim; the mailbox's last
/// sender goes with it, so an actor already running would stop too.
pub(crate) struct ActorReservation {
    computers: Computers,
    id: SandboxId,
    incarnation: Uuid,
    runtime: Runtime,
    mailbox: Mailbox,
    commands: Option<tokio::sync::mpsc::UnboundedReceiver<Command>>,
    snapshot_tx: Option<tokio::sync::watch::Sender<ComputerSnapshot>>,
}

impl ActorReservation {
    /// The claimed computer's runtime state, for the caller to populate
    /// before its actor starts.
    pub(crate) fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Start the actor and keep the claim.
    pub(crate) fn spawn(mut self, seed: ActorSpawn) -> Mailbox {
        let ActorSpawn {
            services,
            timers_enabled,
            generation,
            deadlines,
            launch,
            seeded,
        } = seed;
        let mailbox = self.mailbox.clone();
        let flows = Arc::new(ComputerFlows::new(
            self.id.clone(),
            Arc::clone(&self.runtime),
            Arc::clone(&services),
            &mailbox,
            launch,
        ));
        let unregister = {
            let computers = Arc::clone(&self.computers);
            let id = self.id.clone();
            let incarnation = self.incarnation;
            Arc::new(move || forget_computer(&computers, &id, incarnation))
        };
        let vm_dir = self.runtime.lock().unwrap().vm_dir.clone();
        let actor = ComputerActor::new(
            ComputerSeed {
                id: self.id.clone(),
                runtime: Arc::clone(&self.runtime),
                unregister,
                generation,
                vm_dir,
                records: Arc::clone(&services.records),
                events_tx: services.events_tx.clone(),
                tasks: flows,
                deadlines,
                timers_enabled,
                seeded,
            },
            self.commands.take().expect("spawned once"),
            self.snapshot_tx.take().expect("spawned once"),
        );
        // Constructors are synchronous and may run outside a runtime (unit
        // tests of unrelated surfaces); such a manager has no actors to run
        // and never provisions one.
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(actor.run());
        }
        mailbox
    }
}

impl Drop for ActorReservation {
    fn drop(&mut self) {
        if self.commands.is_some() {
            forget_computer(&self.computers, &self.id, self.incarnation);
        }
    }
}

/// Everything an actor needs that the reservation does not already hold.
///
/// Assembled from the manager's own pieces rather than from `&SandboxManager`
/// so the startup sweep can seed actors too: it runs in a task spawned from
/// the constructor, before the manager it belongs to exists.
pub(crate) struct ActorSpawn {
    pub(crate) services: Arc<ComputerServices>,
    pub(crate) timers_enabled: tokio::sync::watch::Receiver<bool>,
    pub(crate) generation: Option<Uuid>,
    pub(crate) deadlines: Deadlines,
    pub(crate) launch: Launch,
    pub(crate) seeded: Seeded,
}

/// Drop `id`'s entry when it is still `incarnation`'s.
///
/// The identity check replaces the `Arc::ptr_eq` guard the instance map
/// needed: a computer removed and re-created under the same id (deterministic
/// caller-supplied ids make this common) installs a fresh entry, and the
/// departing actor must not evict it.
fn forget_computer(computers: &Computers, id: &SandboxId, incarnation: Uuid) {
    let mut map = computers.write().unwrap();
    if map
        .get(id)
        .is_some_and(|current| current.incarnation == incarnation)
    {
        map.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use arcbox_vm_driver::testkit::FakeDriver;

    use super::*;

    fn placeholder(id: &str) -> ComputerRuntime {
        ComputerRuntime::new(
            id.to_owned(),
            SandboxSpec::default(),
            None,
            PathBuf::from("/tmp/x"),
        )
    }

    /// The manager refuses, at construction, a driver that cannot spawn the
    /// VMM ahead of a boot, dial the guest, or take its readiness dial-out:
    /// every sandbox flow needs all three, so a driver without one would
    /// fail at the first create instead.
    #[test]
    fn construction_requires_the_drivers_prepare_and_vsock_capabilities() {
        use arcbox_vm_driver::testkit::FakeDriver;
        use arcbox_vm_driver::{DriverCapabilities, VmDriver as _};

        let dir = tempfile::tempdir().unwrap();
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = dir.path().to_string_lossy().into_owned();
        // The vm-proto factory, not the agent fake: only a dial-out
        // readiness makes the driver's `vsock_listen` a requirement, which
        // is one of the three refusals below.
        let environment = |driver: FakeDriver| NodeEnvironment {
            driver: Arc::new(driver),
            agent: Arc::new(crate::agent::VmProtoAgentFactory::default()),
            ..crate::testkit::fake_environment(&config).unwrap()
        };
        let all = FakeDriver::new().capabilities();

        for (name, capabilities) in [
            (
                "prepare",
                DriverCapabilities {
                    prepare: false,
                    ..all.clone()
                },
            ),
            (
                "vsock",
                DriverCapabilities {
                    vsock: false,
                    ..all.clone()
                },
            ),
            (
                "vsock_listen",
                DriverCapabilities {
                    vsock_listen: false,
                    ..all
                },
            ),
        ] {
            let driver = FakeDriver::builder().capabilities(capabilities).build();
            let error = SandboxManager::new(config.clone(), environment(driver))
                .err()
                .unwrap_or_else(|| panic!("a driver without {name} is refused"));
            assert!(matches!(error, VmmError::Config(_)), "{error}");
            assert!(error.to_string().contains(name), "{error}");
        }

        let manager = SandboxManager::new(config.clone(), environment(FakeDriver::new()))
            .expect("a driver with every needed capability is accepted");
        assert_eq!(manager.services.driver.name(), "fake");
    }

    #[test]
    fn a_claimed_id_rejects_a_concurrent_duplicate() {
        let computers: Computers = Arc::new(RwLock::new(HashMap::new()));
        let first = reserve_actor(&computers, &"dup".to_owned(), placeholder("dup")).unwrap();
        // A second claim of the same id must fail while the first is live —
        // before either touches the per-id resources they both derive.
        assert!(matches!(
            reserve_actor(&computers, &"dup".to_owned(), placeholder("dup")),
            Err(VmmError::AlreadyExists(_))
        ));
        drop(first);
        assert!(!computers.read().unwrap().contains_key("dup"));
    }

    /// A jailed config, which is what makes a driver answer with a budget
    /// at all — the layout behind that answer is the driver's business.
    fn jailed_config() -> VmmConfig {
        let mut config = VmmConfig::default();
        config.firecracker.jailer = Some(crate::config::JailerConfig {
            binary: "/usr/bin/jailer".into(),
            uid: 0,
            gid: 0,
            chroot_base_dir: Some("/srv/jailer".into()),
            netns: None,
            new_pid_ns: false,
            cgroup_version: None,
            parent_cgroup: None,
            resource_limits: Vec::new(),
        });
        config
    }

    /// The id shape the platform node actually mints, in the rendering a
    /// driver can run: the control plane's `inst_<uuid v7>` with the `_`
    /// the VMM refuses turned into a `-`.
    const CONTROL_PLANE_ID: &str = "inst-019e409e-7546-7a3e-8b2c-1f2e3d4c5b6a";

    #[test]
    fn validate_id_accepts_safe_ids_and_rejects_traversal() {
        for ok in ["sandbox1", "a-b_c", "0f3e9d16-1234", "A_B-9"] {
            assert!(validate_id("id", ok).is_ok(), "{ok} should be valid");
        }
        // The generic validator stays uncapped and keeps the underscore: it
        // also runs against persisted records and against snapshot /
        // execution ids that never become a VM identity, where a legacy id
        // must not become fatal.
        assert!(validate_id("id", &"a".repeat(60)).is_ok());
        assert!(validate_id("id", "inst_019e409e-7546").is_ok());
        for bad in ["", "..", ".", "a/b", "a\\b", "a b", "a.b", "a\0b", "../etc"] {
            assert!(
                validate_id("id", bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    /// Ingress holds a new id to whatever budget the *configured* driver
    /// reports for the isolation it will run under — this layer keeps no
    /// copy of a number. Anything past it must fail fast here instead of
    /// surfacing as a socket connect timeout.
    ///
    /// Whether a given layout leaves room for the ids an ArcBox node mints
    /// is the adapter's own question, answered against the deployed
    /// constants in `arcbox-fc-driver`
    /// (`the_deployed_jail_layout_admits_the_ids_a_node_mints`).
    #[test]
    fn a_new_sandbox_id_is_held_to_the_drivers_own_budget() {
        let mut config = jailed_config();
        let budget = CONTROL_PLANE_ID.len();
        let driver = FakeDriver::builder().jailed_id_budget(budget).build();
        assert!(validate_new_sandbox_id(CONTROL_PLANE_ID, &driver, &config).is_ok());
        assert!(validate_new_sandbox_id(&"a".repeat(budget), &driver, &config).is_ok());
        assert!(validate_new_sandbox_id(&"a".repeat(budget + 1), &driver, &config).is_err());

        // A tighter budget refuses what the looser one took, rather than
        // silently reintroducing the connect timeout.
        let tighter = FakeDriver::builder().jailed_id_budget(budget - 1).build();
        assert!(validate_new_sandbox_id(CONTROL_PLANE_ID, &tighter, &config).is_err());

        // A driver that reports no budget for this isolation bounds
        // nothing: only `VmId`'s own 64-byte ceiling is left.
        config.firecracker.jailer = None;
        assert!(validate_new_sandbox_id(&"a".repeat(budget + 1), &tighter, &config).is_ok());
    }

    /// CORE-140. Firecracker validates the `--id` it is handed and refuses it
    /// by panicking — under the jailer *and* in direct mode, where the same
    /// flag is passed straight to the VMM. So the refusal cannot be gated on
    /// a jailer being configured: it belongs to the id itself.
    #[test]
    fn an_underscored_id_is_refused_at_ingress_in_every_spawn_mode() {
        let mut config = jailed_config();
        let driver = FakeDriver::builder()
            .jailed_id_budget(CONTROL_PLANE_ID.len())
            .build();
        for _ in 0..2 {
            let error =
                validate_new_sandbox_id(&CONTROL_PLANE_ID.replacen('-', "_", 1), &driver, &config)
                    .expect_err("firecracker would refuse to run under this id");
            assert!(
                matches!(&error, VmmError::Config(message) if message.contains('_')),
                "the error should name the offending character, got {error}"
            );
            assert!(validate_new_sandbox_id(CONTROL_PLANE_ID, &driver, &config).is_ok());
            // Direct mode passes the same `--id`, so it is refused there too.
            config.firecracker.jailer = None;
        }
    }

    #[test]
    fn a_dropped_claim_frees_the_id() {
        let computers: Computers = Arc::new(RwLock::new(HashMap::new()));
        {
            let _claim = reserve_actor(&computers, &"tmp".to_owned(), placeholder("tmp")).unwrap();
            assert!(computers.read().unwrap().contains_key("tmp"));
            // never spawned → dropped here
        }
        assert!(!computers.read().unwrap().contains_key("tmp"));
        // The id is free to claim again after an unwound restore.
        assert!(reserve_actor(&computers, &"tmp".to_owned(), placeholder("tmp")).is_ok());
    }

    /// A departing actor unregisters *its own* entry and no other.
    ///
    /// The `Arc::ptr_eq` guard the instance map needed, as an incarnation:
    /// a computer removed and re-created under the same id (deterministic
    /// caller-supplied ids make this common) installs a fresh entry, and the
    /// one on its way out must not evict it.
    #[test]
    fn a_departing_actor_does_not_evict_its_replacement() {
        let computers: Computers = Arc::new(RwLock::new(HashMap::new()));
        let departing = reserve_actor(&computers, &"same".to_owned(), placeholder("same")).unwrap();
        let incarnation = departing.incarnation;
        std::mem::forget(departing);

        assert!(matches!(
            reserve_actor(&computers, &"same".to_owned(), placeholder("same")),
            Err(VmmError::AlreadyExists(_))
        ));
        forget_computer(&computers, &"same".to_owned(), incarnation);
        let replacement = reserve_actor(&computers, &"same".to_owned(), placeholder("same"))
            .expect("the id is free once the departing actor let it go");

        forget_computer(&computers, &"same".to_owned(), incarnation);
        assert!(
            computers.read().unwrap().contains_key("same"),
            "the stale incarnation must not evict the replacement"
        );
        drop(replacement);
        assert!(!computers.read().unwrap().contains_key("same"));
    }
}
