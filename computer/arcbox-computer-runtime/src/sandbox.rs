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

use arcbox_fc_driver::jail::{
    SnapshotFiles, api_socket_path, chroot_root, link_or_copy_for_jailer, move_file,
    stage_kernel_for_jailer, stage_rootfs_copy_for_jailer, stage_rootfs_device_for_jailer,
    stage_snapshot_files,
};
use arcbox_fc_driver::{FcDriver, FcDriverConfig};
use arcbox_vm_driver::net::{
    AttachMode, GuestNetwork, NetworkIdentity, NetworkLease, NetworkMode, NetworkPolicy,
    NetworkReconcile,
};
use arcbox_vm_driver::{
    CheckpointFormat, CheckpointImage, CheckpointKind, IsolationSpec, NicSpec, Prepare, PreparedVm,
    VmDriver, VmHandle, VmId,
};
use chrono::{DateTime, Utc};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::agent::{ClockSync, ExecInputMsg, ExitStatus, OutputChunk, PortWait, StartCommand};
use crate::agent::{GuestAgent, GuestAgentFactory, Readiness, VmProtoAgentFactory};
use crate::config::VmmConfig;
use crate::environment::SandboxEnvironment;
use crate::error::{Result, VmmError};
use crate::network::NetworkManager;
use crate::snapshot::{SnapshotCatalog, SnapshotDraft};
use crate::snapshot_cow::{CowHandle, CowManager, CowOptions};
use crate::template_catalog::TemplateCatalog;

mod boot;
mod checkpoint;
mod cleanup;
mod execution;
mod files;
mod lifecycle;
mod pause;
pub(crate) mod policy;
mod pool;
pub(crate) mod reconcile;
pub(crate) mod record;
mod spec;
mod templates;
#[cfg(test)]
mod testing;
mod timers;
pub(crate) mod types;
mod warm;
pub(crate) mod workload;

pub use execution::{
    ExecutionChannel, ExecutionOutput, ExecutionSnapshot, ExecutionSpec, StdinState,
};
pub use pause::reason as pause_reason;
pub(crate) use types::NetworkAttachment;
pub use types::{
    CheckpointInfo, CheckpointSummary, IdleAction, LifecycleUpdate, RestoreSandboxSpec,
    SandboxEvent, SandboxId, SandboxInfo, SandboxInstance, SandboxMountSpec, SandboxNetworkInfo,
    SandboxNetworkSpec, SandboxSpec, SandboxState, SandboxSummary, TemplateWarmRef,
};

const EVENT_CHANNEL_CAPACITY: usize = 256;
type ReconcileResult = std::result::Result<(), Arc<str>>;

/// Shared registry of live sandbox instances.
pub(crate) type InstanceMap = Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>;

/// Manages the full lifecycle of multiple sandbox microVMs.
pub struct SandboxManager {
    instances: Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    records: Arc<record::SandboxRecordStore>,
    /// The VMM every sandbox runs under, behind the driver port. Its
    /// `Prepare` capability is required at construction: the boot and pool
    /// flows spawn the VMM ahead of the guest.
    driver: Arc<dyn VmDriver>,
    /// What every sandbox NIC attaches to, behind the guest-network port.
    /// Its `NetworkReconcile` capability is required at construction: the
    /// cleanup-token protocol and the startup sweep are not optional here.
    network: Arc<dyn GuestNetwork>,
    /// How every sandbox's guest agent is reached, behind the guest-agent
    /// port. It also owns the readiness gate the boot flow arms before the
    /// guest starts.
    agent: Arc<dyn GuestAgentFactory>,
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
    /// Per-sandbox TTL / idle expiry timers (CORE-21/60); see `timers.rs`.
    timers: timers::LifecycleTimers,
    /// Weak self-handle set by [`Self::into_shared`]; idle timers need it to
    /// reach the pause/remove flows from a detached task.
    self_handle: std::sync::OnceLock<std::sync::Weak<Self>>,
}

impl SandboxManager {
    /// Create a new manager from the given configuration, in the reference
    /// environment ([`SandboxEnvironment::default`]).
    pub fn new(config: VmmConfig) -> Result<Self> {
        Self::with_environment(config, SandboxEnvironment::default())
    }

    /// Create a new manager from the given configuration, with the
    /// environment-specific components the composer supplies.
    ///
    /// Fails with [`VmmError::Config`] when the environment's driver lacks a
    /// capability every sandbox needs — `Prepare` (the flows spawn the VMM
    /// ahead of the guest), `Vsock` (the guest agent is reached over it), or
    /// whatever the agent factory's readiness gate needs (`VsockListen` for
    /// the guest's dial-out) — or when its guest network offers no
    /// `NetworkReconcile` (the cleanup-token protocol is how a host
    /// releases the addresses a previous process held), so an environment
    /// missing one is refused here instead of at the first boot or the
    /// first cleanup ticket.
    pub fn with_environment(config: VmmConfig, environment: SandboxEnvironment) -> Result<Self> {
        let driver = environment.driver.unwrap_or_else(|| {
            Arc::new(FcDriver::new(FcDriverConfig::from(&config.firecracker))) as Arc<dyn VmDriver>
        });
        let agent = environment.agent.unwrap_or_else(|| {
            Arc::new(VmProtoAgentFactory::default()) as Arc<dyn GuestAgentFactory>
        });
        let capabilities = driver.capabilities();
        for (missing, capability, need) in [
            (
                driver.prepare().is_none(),
                "prepare",
                "the boot and pool flows spawn the VMM ahead of the guest",
            ),
            // The last hard-wired transport assumption in this layer: every
            // agent implementation the crate ships reaches its guest through
            // the VM handle. It leaves with the composition root (PR-G),
            // which is what will know whether its Computers are dialable at
            // all.
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
        let network: Arc<dyn GuestNetwork> = match environment.network {
            Some(network) => network,
            None => Arc::new(NetworkManager::with_quarantine_dir(
                &config.network.cidr,
                &config.network.gateway,
                config.network.dns.clone(),
                Path::new(&config.firecracker.data_dir).join("sandbox-network-quarantine"),
                config.firecracker.sandbox_datapath,
                environment.packet_filter,
            )?),
        };
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
        let mut cow_options = CowOptions::new(&config.firecracker.data_dir);
        cow_options.block_tools = environment.block_tools;
        if let Some(candidates) = &config.firecracker.dmsetup_candidates {
            cow_options.dmsetup_candidates = candidates.iter().map(PathBuf::from).collect();
        }
        let cow_manager = Arc::new(CowManager::new(cow_options)?);

        // Ensure the jailer chroot base directory exists.
        if let Some(ref jc) = config.firecracker.jailer {
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            std::fs::create_dir_all(base).map_err(VmmError::Io)?;
        }

        let config = Arc::new(config);

        // Sweep leftovers of a previous agent process (crash / respawn):
        // orphaned VMM processes, TAPs, dm devices, chroots. Create and
        // restore wait for this to finish (await_reconcile) so a re-created
        // same-id sandbox can't have its deterministically-named resources torn
        // down mid-flight. Only meaningful inside a tokio runtime; sync
        // constructions (unit tests) have no previous instance to reconcile.
        let (reconcile_tx, reconcile_done) = tokio::sync::watch::channel(None);
        let executions = Arc::new(execution::ExecutionRegistry::default());
        let instances = Arc::new(RwLock::new(HashMap::new()));
        if tokio::runtime::Handle::try_current().is_ok() {
            let config = Arc::clone(&config);
            let driver = Arc::clone(&driver);
            let network = Arc::clone(&network);
            let cow_manager = Arc::clone(&cow_manager);
            let snapshots = Arc::clone(&snapshots);
            let records = Arc::clone(&records);
            let instances = Arc::clone(&instances);
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
                    // sandboxes' only handles live in these instances, so a
                    // later error — a runtime directory that will not delete,
                    // say — would otherwise un-reclaim every guest by
                    // dropping them, over something none of them caused.
                    instances.write().unwrap().extend(
                        inactive
                            .into_iter()
                            .map(|instance| (instance.id.clone(), Arc::new(Mutex::new(instance)))),
                    );
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
            reconcile_capability(&*network).replay_complete();
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
            driver,
            network,
            agent,
            snapshots,
            templates,
            config,
            events_tx,
            cow_manager,
            pool: Arc::new(pool::SlotPool::default()),
            warm: Arc::new(warm::WarmCache::default()),
            executions,
            reconcile_done,
            timers: timers::LifecycleTimers::default(),
            self_handle: std::sync::OnceLock::new(),
        })
    }

    /// Wrap the manager in an `Arc` and start the lifecycle monitor that
    /// arms/cancels the idle and TTL timers off the event stream.
    ///
    /// Production embedders (the guest agent's `SandboxService`) must use
    /// this; a plain [`Self::new`] manager never fires idle timers (unit
    /// tests exercising unrelated surfaces rely on that inertness).
    #[must_use]
    pub fn into_shared(self) -> Arc<Self> {
        let manager = Arc::new(self);
        let _ = manager.self_handle.set(Arc::downgrade(&manager));
        if tokio::runtime::Handle::try_current().is_ok() {
            timers::spawn_lifecycle_monitor(&manager);
        }
        manager
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
        reconcile_capability(&*self.network)
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
        let instance = self.get_instance(&id.to_owned())?;
        let instance = instance.lock().unwrap();
        let lease = instance
            .network
            .as_ref()
            .ok_or_else(|| VmmError::WrongState {
                id: id.to_owned(),
                expected: "sandbox with an active network allocation".into(),
                actual: instance.state.to_string(),
            })?;
        Ok(SandboxNetworkIdentity {
            ip: lease.ipv4()?,
            cleanup_token: lease.cleanup_token.clone(),
            expose: crate::network::ExposeTarget::try_from(self.network.host_ingress(lease)?)?,
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
    pub expose: crate::network::ExposeTarget,
}

/// The guest network's cleanup protocol, which
/// [`SandboxManager::with_environment`] requires — the quarantine ledger
/// gates every address the pool hands out, and the startup sweep gates the
/// pool itself.
pub(super) fn reconcile_capability(network: &dyn GuestNetwork) -> &dyn NetworkReconcile {
    network.reconcile().expect(
        "SandboxManager::with_environment requires the guest network's reconcile capability",
    )
}

/// The driver's `Prepare` capability, which [`SandboxManager::with_environment`]
/// requires — the boot, pool, and restore flows all spawn the VMM before
/// there is a guest to run on it.
pub(super) fn prepare_capability(driver: &dyn VmDriver) -> &dyn Prepare {
    driver
        .prepare()
        .expect("SandboxManager::with_environment requires the driver's Prepare capability")
}

/// The VMM's pid as the crash journal records it: what a restart sweep
/// kills before tearing the sandbox's other resources down.
pub(super) fn journaled_pid(prepared: &dyn PreparedVm) -> Option<i32> {
    prepared
        .record()
        .process
        .and_then(|process| i32::try_from(process.pid).ok())
}

/// The isolation every sandbox VMM runs under: the jailer's, when one is
/// configured; none otherwise (direct mode).
pub(super) fn isolation_spec(config: &VmmConfig) -> Result<IsolationSpec> {
    config
        .firecracker
        .jailer
        .as_ref()
        .map_or(Ok(IsolationSpec::None), IsolationSpec::try_from)
}

/// A catalogued checkpoint as the driver reads it back: the directory the
/// files were staged into (`vmstate` + `mem`) and the format the catalog
/// recorded at capture — legacy entries default to the Firecracker format.
pub(super) fn checkpoint_image(dir: PathBuf, format: &str) -> CheckpointImage {
    CheckpointImage {
        dir,
        format: CheckpointFormat::new(format),
        kind: CheckpointKind::Full,
    }
}

/// Stock sandbox id budget: what [`max_sandbox_id_len`] computes for the
/// guest config (`/var/lib/arcbox/jailer` + `firecracker`), kept as the
/// fallback when no jailer is configured — direct mode has no jailer
/// socket, but ids still become path components everywhere else.
const STOCK_MAX_ID_LEN: usize = 44;

/// Longest sandbox id the configured jailer layout leaves room for: the
/// jailer API socket (`arcbox_fc_driver::jail::api_socket_path`, under
/// `{chroot_base}/{vmm basename}/{id}/root`) must fit AF_UNIX's 107-byte
/// `sun_path`. An oversized id otherwise fails as an opaque "timed out
/// waiting for socket": the driver's readiness probe is a `connect()`,
/// which ENAMETOOLONGs on every attempt even though the VMM is up and
/// bound inside the chroot (caught by the CORE-107 prewarm e2e, whose
/// 51-char builder id overflowed the stock budget by 7 bytes). Measured on
/// the driver's own layout so a longer chroot base or binary name tightens
/// the budget instead of silently reintroducing the timeout.
pub(super) fn max_sandbox_id_len(config: &VmmConfig) -> usize {
    const SUN_PATH: usize = 107;
    let Some(jc) = &config.firecracker.jailer else {
        return STOCK_MAX_ID_LEN;
    };
    // Everything around the id, measured on a one-byte id.
    let with_one_byte_id = api_socket_path(&chroot_root(
        &config.firecracker.binary,
        jc.chroot_base(),
        "x",
    ));
    SUN_PATH.saturating_sub(with_one_byte_id.as_os_str().len() - 1)
}

/// Validate a caller-supplied sandbox or snapshot id.
///
/// Ids become filesystem path components, jailer `--id` values, and dm/TAP name
/// fragments, so they are restricted to `[A-Za-z0-9_-]`. This rejects path
/// traversal (`/`, `\`, `..`), NUL, whitespace, and anything the jailer would
/// otherwise reject much later with an opaque boot failure.
///
/// Deliberately NO length cap here: this also runs against persisted
/// records (reconcile, record loads) — where rejecting one legacy
/// over-long id would abort a whole sweep — and against snapshot /
/// execution ids that never enter the jailer path. The jailer budget is
/// enforced only where a sandbox id enters the system:
/// [`validate_new_sandbox_id`].
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

/// Validate a sandbox id at request ingress (create / restore), where the
/// id becomes a jailer identity — [`validate_id`] plus the
/// [`max_sandbox_id_len`] socket-path budget.
pub(super) fn validate_new_sandbox_id(id: &str, config: &VmmConfig) -> Result<()> {
    let max = max_sandbox_id_len(config);
    if id.len() > max {
        return Err(VmmError::Config(format!(
            "invalid sandbox id {id:?}: at most {max} characters \
             (the jailer socket path must fit the AF_UNIX limit)"
        )));
    }
    validate_id("sandbox id", id)
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
        let environment = |driver: FakeDriver| SandboxEnvironment {
            driver: Some(Arc::new(driver)),
            ..SandboxEnvironment::default()
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
            let error = SandboxManager::with_environment(config.clone(), environment(driver))
                .err()
                .unwrap_or_else(|| panic!("a driver without {name} is refused"));
            assert!(matches!(error, VmmError::Config(_)), "{error}");
            assert!(error.to_string().contains(name), "{error}");
        }

        let manager = SandboxManager::with_environment(config, environment(FakeDriver::new()))
            .expect("a driver with every needed capability is accepted");
        assert_eq!(manager.driver.name(), "fake");
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
        // A 36-char UUID fits; anything past the jailer socket budget must
        // fail fast at ingress instead of surfacing as a socket connect
        // timeout. The generic validator stays uncapped — it also runs
        // against persisted records and non-jailer (snapshot/execution)
        // ids, where a legacy over-long id must not become fatal.
        let mut config = VmmConfig::default();
        config.firecracker.binary = "/usr/local/bin/firecracker".into();
        config.firecracker.jailer = Some(crate::config::JailerConfig {
            binary: "/usr/local/bin/jailer".into(),
            uid: 0,
            gid: 0,
            chroot_base_dir: Some("/var/lib/arcbox/jailer".into()),
            netns: None,
            new_pid_ns: false,
            cgroup_version: None,
            parent_cgroup: None,
            resource_limits: Vec::new(),
        });
        // The stock guest layout leaves exactly 44 bytes for the id.
        assert_eq!(max_sandbox_id_len(&config), 44);
        assert!(validate_new_sandbox_id(&"a".repeat(44), &config).is_ok());
        assert!(validate_new_sandbox_id(&"a".repeat(45), &config).is_err());
        // A longer chroot base tightens the budget instead of silently
        // reintroducing the connect timeout.
        config
            .firecracker
            .jailer
            .as_mut()
            .expect("jailer set above")
            .chroot_base_dir = Some(format!("/var/lib/arcbox/jailer/{}", "x".repeat(10)));
        assert_eq!(max_sandbox_id_len(&config), 33);
        assert!(validate_new_sandbox_id(&"a".repeat(34), &config).is_err());
        assert!(validate_id("id", &"a".repeat(60)).is_ok());
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
