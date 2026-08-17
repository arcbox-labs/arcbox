//! Crash-recovery reconciliation for sandbox runtime state.
//!
//! `SandboxManager` state is in-memory; if the agent restarts (crash,
//! supervision respawn) the VMM processes, TAP devices, dm-snapshot
//! devices, and jailer chroots of running sandboxes are left with no owner,
//! and fresh IP allocations can collide with orphaned TAPs. To recover,
//! every successful boot/restore persists a small `state.json` next to the
//! sandbox's runtime files, and a new manager sweeps those records.
//!
//! A sandbox whose VM is *still running* is reclaimed rather than
//! destroyed, so a crash or an upgrade of the composing process does not
//! cost every guest on the node its work (CORE-135). One journal is adopted
//! when all of these hold, and killed the moment any of them does not —
//! every refusal falls back to the teardown this sweep did before adoption
//! existed, because re-establishing the wrong host state is worse than
//! starting over:
//!
//! - the driver's `Adopt` capability found and reconnected to the VMM;
//! - that handle reports [`VmState::Running`] — a quiesced guest is a
//!   checkpoint that died between the pause and the resume;
//! - the handle has vsock, which is what separates a full one from the
//!   process-only fallback an orphan with a dead API yields: without it
//!   nothing can be run, paused or checkpointed in the sandbox, only killed;
//! - the durable record is `Ready`. `Starting` died with the boot task that
//!   was driving it and nothing here finishes one; the transitional phases
//!   died between resource states;
//! - the journal says how its lease attaches ([`SandboxStateRecord::attach_mode`]),
//!   and the guest network takes that lease back under exactly that mode;
//! - the CoW manager re-registers the dm-snapshot the guest is running on.
//!
//! Everything else is torn down as before, and then durable lifecycle
//! records are normalized for replay and inspection.
//!
//! What a reclaim does *not* restore is the host's half: the composing host
//! clears every sandbox's DNS record and port listeners on the startup
//! handshake ([`SandboxHost::clear_host_state`]'s premise was that a
//! restarting agent left nothing alive), so an adopted sandbox keeps
//! running and stays reachable over vsock and at its address, but loses its
//! name and its published ports until something re-registers them. Nothing
//! leaks — the guest-side forwarding rules survive and a later Remove still
//! sweeps them — and the fix belongs to the host half, not here.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arcbox_vm_driver::net::{AttachMode, GuestNetwork, NetworkIdentity, NetworkLease};
use arcbox_vm_driver::{ProcessRecord, ShutdownMode, VmDriver, VmHandle, VmId, VmRecord, VmState};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::policy::recovery::{self, JournalEvidence, RecoveryAction, SweepAction};
use super::record::{SandboxRecord, SandboxRecordStore, SandboxTransition};
use super::{LeaseExt, SandboxInstance, SandboxState};
use crate::config::VmmConfig;
use crate::error::{Result, VmmError};
use crate::network::NetworkAllocation;
use crate::snapshot_cow::{CowHandle, CowManager};

/// How long the sweep gives the driver to find and reconnect to one
/// orphaned VMM. Finding one is a `/proc` walk and reconnecting a couple of
/// API calls; an orphan whose API never answers must not hang the sweep —
/// and with it every create — forever.
const ADOPT_TIMEOUT: Duration = Duration::from_secs(10);

/// File name of the per-sandbox crash-recovery record.
const STATE_FILE: &str = "state.json";
const AGENT_RESTART_ERROR: &str = "sandbox runtime was cleaned after agent restart";

/// Id prefix of pre-warmed restore slots (CORE-78). A slot's chroot,
/// dm/CoW names, and runtime dir are keyed by `pool-<uuid>`, so the
/// startup sweep recognizes and reclaims orphaned slots like any other
/// journaled sandbox.
pub(super) const POOL_SLOT_PREFIX: &str = "pool-";

/// Plain serializable mirror of [`CowHandle`].
///
/// `CowHandle` itself is deliberately `!Clone`/`!Serialize` (it owns a
/// template refcount); this record carries just enough to rebuild a handle
/// for teardown after a restart.
#[derive(Debug, Serialize, Deserialize)]
struct CowRecord {
    dm_name: String,
    dm_device: String,
    cow_loop: String,
    cow_file: PathBuf,
    template_path: PathBuf,
}

impl CowRecord {
    fn from_handle(handle: &CowHandle) -> Self {
        Self {
            dm_name: handle.dm_name.clone(),
            dm_device: handle.dm_device.clone(),
            cow_loop: handle.cow_loop.clone(),
            cow_file: handle.cow_file.clone(),
            template_path: handle.template_path.clone(),
        }
    }

    /// The handle this record stands for. By reference because the sweep
    /// decides a record's fate before it disposes of it, so it still needs
    /// the rest of the record afterwards.
    fn to_handle(&self) -> CowHandle {
        CowHandle {
            dm_name: self.dm_name.clone(),
            dm_device: self.dm_device.clone(),
            cow_loop: self.cow_loop.clone(),
            cow_file: self.cow_file.clone(),
            template_path: self.template_path.clone(),
        }
    }
}

/// Crash-recovery record of one live sandbox.
///
/// Every field except `id` is `#[serde(default)]`, and new fields must keep
/// that convention: it lets a newer agent read an older record (missing fields
/// default) and an older agent read a newer one (unknown fields are ignored),
/// so a schema change never silently disables reconciliation of a pre-upgrade
/// sandbox — which would leak its resources.
///
/// One scoped exception: `pool_slot_id` changes the *interpretation* of `id`
/// (resource names key on the slot, not the sandbox), so an agent from before
/// CORE-78 reading a pool-adopted record computes the wrong expected CoW/chroot
/// names, fails validation, and skips — not corrupts — that one sandbox's
/// cleanup (a bounded leak until the next new-agent sweep). Accepted because
/// the daemon stages the agent it shipped with, so an old agent only ever sees
/// new records across a daemon downgrade.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SandboxStateRecord {
    /// Sandbox ID (also the directory name).
    pub id: String,
    /// The VMM's PID at boot time.
    #[serde(default)]
    pub pid: Option<i32>,
    /// The lease to hand back, in the shape `arcbox-tap-net`'s
    /// [`NetworkAllocation`] has written since before the guest-network
    /// port existed.
    ///
    /// The lease is what the sweep actually needs, but the on-disk shape
    /// is a contract in both directions (see the type doc above), and
    /// `NetworkAllocation`'s `tap_name` and `dns_servers` are not
    /// `#[serde(default)]`: dropping either would turn one skipped
    /// sandbox into a sweep that fails to parse and leaks every journaled
    /// resource on an agent that predates the port. Both are therefore
    /// reconstructed on write — the TAP name by [`tap_name_for`], the
    /// same rule [`validate_state_record`] enforces, and the resolvers
    /// from the network config the pool was built with — and neither is
    /// read back: [`SandboxStateRecord::lease`] is what the sweep uses.
    #[serde(default)]
    pub network: Option<NetworkAllocation>,
    /// dm-snapshot CoW resources to tear down.
    #[serde(default)]
    cow: Option<CowRecord>,
    /// Whether a jailer chroot was created for this sandbox.
    #[serde(default)]
    pub jailer: bool,
    /// For restored sandboxes: the recreated origin directory to remove.
    #[serde(default)]
    pub restore_origin_dir: Option<PathBuf>,
    /// For sandboxes that adopted a pre-warmed pool slot (CORE-78): the
    /// slot id the jailer chroot and dm/CoW names are keyed by.
    #[serde(default)]
    pub pool_slot_id: Option<String>,
    /// The [`AttachMode`] this record's lease was activated as — what
    /// [`GuestNetwork::adopt`] must re-establish for a sandbox the sweep
    /// keeps alive.
    ///
    /// Emphatically **not** derivable from [`Self::net_invariant`]: a cold
    /// boot always activates [`AttachMode::Invariant`], while that flag says
    /// only whether the boot baked the invariant `ip=` into the guest's
    /// command line — false whenever the caller supplied their own. Restore
    /// and resume are the only paths that vary the mode, and they take it
    /// from the *snapshot's* flag. Re-establishing `LegacySnapshot` on a TAP
    /// that was activated `Invariant` is no translation at all, i.e. a live
    /// guest nothing can reach.
    ///
    /// `None` for a networkless sandbox, and in every record written before
    /// adoption existed. A record that names a lease without it is not
    /// adoptable: the wrong datapath is worse than the teardown it replaces.
    #[serde(default)]
    pub attach_mode: Option<JournaledAttachMode>,
    /// Whether the guest holds the fixed invariant identity (CORE-81).
    ///
    /// [`SandboxInstance::net_invariant`] as an adopted sandbox is rebuilt
    /// with it, and so what that sandbox's next checkpoint records as its
    /// restore contract. A different fact from [`Self::attach_mode`] — see
    /// there.
    #[serde(default)]
    pub net_invariant: bool,
}

/// How a lease's host side was attached, in the journal's own vocabulary.
///
/// A journal-local mirror of [`AttachMode`], which carries no serde derives;
/// mapped at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum JournaledAttachMode {
    Invariant,
    LegacySnapshot,
}

impl From<AttachMode> for JournaledAttachMode {
    fn from(mode: AttachMode) -> Self {
        match mode {
            AttachMode::Invariant => Self::Invariant,
            AttachMode::LegacySnapshot => Self::LegacySnapshot,
        }
    }
}

impl From<JournaledAttachMode> for AttachMode {
    fn from(mode: JournaledAttachMode) -> Self {
        match mode {
            JournaledAttachMode::Invariant => Self::Invariant,
            JournaledAttachMode::LegacySnapshot => Self::LegacySnapshot,
        }
    }
}

/// A lease as the journal records it: the address, the [`AttachMode`] its
/// host side is activated as, and whether the guest holds the fixed
/// invariant identity.
///
/// The three travel together because a restart that keeps the guest running
/// must re-establish that exact datapath, and no two of them give the third.
/// One parameter rather than a lease plus two loose flags is what stops a
/// journal site from recording an address without saying how it is attached.
#[derive(Clone, Copy)]
pub(super) struct JournaledLease<'a> {
    lease: &'a NetworkLease,
    mode: AttachMode,
    invariant_identity: bool,
}

impl<'a> JournaledLease<'a> {
    /// A cold boot's lease. Its host side is always activated
    /// [`AttachMode::Invariant`] (`lifecycle.rs`, unconditional);
    /// `baked_invariant_ip` says only whether the boot also put that
    /// identity on the guest's command line.
    pub fn cold_boot(lease: &'a NetworkLease, baked_invariant_ip: bool) -> Self {
        Self {
            lease,
            mode: AttachMode::Invariant,
            invariant_identity: baked_invariant_ip,
        }
    }

    /// A restore's or resume's lease: the snapshot's own flag decides both
    /// the mode and the guest's identity — the same expression that feeds
    /// the `activate` these journal writes precede.
    pub fn from_snapshot(lease: &'a NetworkLease, net_invariant: bool) -> Self {
        Self {
            lease,
            mode: super::attach_mode(net_invariant),
            invariant_identity: net_invariant,
        }
    }
}

/// The TAP name an allocation for `ip` carries.
///
/// One definition, shared by the journal writer and
/// [`validate_state_record`], so a record this agent writes is exactly one
/// it accepts.
fn tap_name_for(ip: std::net::Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("vmtap{}-{}", octets[2], octets[3])
}

impl SandboxStateRecord {
    /// Assemble a record from boot/restore results.
    pub fn new(
        id: &str,
        pid: Option<i32>,
        network: Option<JournaledLease<'_>>,
        cow: Option<&CowHandle>,
        config: &VmmConfig,
        restore_origin_dir: Option<&Path>,
    ) -> Result<Self> {
        let allocation = network
            .map(|net| legacy_allocation(net.lease, &config.network.dns))
            .transpose()?;
        Ok(Self {
            id: id.to_owned(),
            pid,
            network: allocation,
            cow: cow.map(CowRecord::from_handle),
            jailer: config.firecracker.jailer.is_some(),
            restore_origin_dir: restore_origin_dir.map(Path::to_path_buf),
            pool_slot_id: None,
            attach_mode: network.map(|net| net.mode.into()),
            net_invariant: network.is_some_and(|net| net.invariant_identity),
        })
    }

    /// The lease this record's network field stands for, for a sweep that
    /// must hand the address back.
    pub fn lease(&self) -> Result<Option<NetworkLease>> {
        self.network
            .as_ref()
            .map(|allocation| {
                Ok(NetworkLease {
                    vm: VmId::new(self.id.as_str())?,
                    ip: allocation.ip_address.into(),
                    prefix_len: allocation.prefix_len,
                    gateway: allocation.gateway.into(),
                    mac: allocation.mac_address.parse().map_err(VmmError::from)?,
                    cleanup_token: allocation.cleanup_token.clone(),
                })
            })
            .transpose()
    }

    /// Key the record's chroot and dm/CoW resources by an adopted pool
    /// slot id instead of the sandbox id.
    pub fn with_pool_slot(mut self, slot_id: Option<&str>) -> Self {
        self.pool_slot_id = slot_id.map(str::to_owned);
        self
    }

    /// Id the per-sandbox host resources (chroot, dm/CoW names) are
    /// actually named after: the adopted pool slot id when present, the
    /// sandbox id otherwise.
    pub fn resource_owner(&self) -> &str {
        self.pool_slot_id.as_deref().unwrap_or(&self.id)
    }
}

/// `lease` in the journal's legacy allocation shape.
///
/// `tap_name` and `dns_servers` are the two fields a lease does not carry;
/// see [`SandboxStateRecord::network`] for why they are written anyway.
fn legacy_allocation(lease: &NetworkLease, dns: &[String]) -> Result<NetworkAllocation> {
    let ip = lease.ipv4()?;
    Ok(NetworkAllocation {
        tap_name: tap_name_for(ip),
        ip_address: ip,
        prefix_len: lease.prefix_len,
        gateway: lease.gateway_ipv4()?,
        mac_address: lease.mac.to_string(),
        dns_servers: dns.to_vec(),
        cleanup_token: lease.cleanup_token.clone(),
    })
}

/// Atomically persist crash-recovery metadata before resources are exposed.
pub(super) fn write_state_record(vm_dir: &Path, record: &SandboxStateRecord) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(record)?;
    arcbox_atomic_file::write(&vm_dir.join(STATE_FILE), &bytes)?;
    Ok(())
}

/// Creates a runtime directory and durably links it from its parent.
pub(super) fn create_runtime_dir(vm_dir: &Path) -> Result<()> {
    let parent = vm_dir.parent().ok_or_else(|| {
        crate::error::VmmError::Config(format!(
            "sandbox runtime directory has no parent: {}",
            vm_dir.display()
        ))
    })?;
    let data_dir = parent.parent().ok_or_else(|| {
        crate::error::VmmError::Config(format!(
            "sandbox runtime parent has no parent: {}",
            parent.display()
        ))
    })?;
    std::fs::create_dir_all(vm_dir)?;
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(vm_dir, std::fs::Permissions::from_mode(0o700))?;
    std::fs::File::open(parent)?.sync_all()?;
    std::fs::File::open(data_dir)?.sync_all()?;
    Ok(())
}

/// Remove the crash-recovery record (resources have been released).
pub(super) fn clear_state_record(vm_dir: &Path) -> Result<()> {
    match std::fs::remove_file(vm_dir.join(STATE_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::fs::File::open(vm_dir)?.sync_all()?;
    Ok(())
}

/// One sandbox whose VM outlived the process that booted it, with every
/// runtime resource the sweep took back for it.
pub(super) struct AdoptedSandbox {
    handle: Arc<dyn VmHandle>,
    lease: Option<NetworkLease>,
    identity: Option<NetworkIdentity>,
    cow_handle: Option<CowHandle>,
    pool_slot_id: Option<String>,
    net_invariant: bool,
}

/// What one sweep did, in the two pieces its caller needs at different
/// moments: [`OrphanSweep::take_runtime`] first, for normalization, and the
/// runtime directories afterwards, for [`finalize_sweep`].
///
/// Both halves are private so neither can be read after the first has been
/// taken out.
pub(super) struct OrphanSweep {
    /// Ids whose journaled resources were torn down.
    ids: HashSet<String>,
    /// Sandboxes reclaimed alive, by id. Their journals stay on disk — they
    /// are live state again, not debris — and so do their runtime dirs.
    adopted: HashMap<String, AdoptedSandbox>,
    runtime_dirs: Vec<PathBuf>,
}

impl SweptRuntime {
    /// A sweep that reclaimed nothing and kept nothing alive.
    #[cfg(test)]
    fn nothing_kept() -> Self {
        Self {
            swept: HashSet::new(),
            adopted: HashMap::new(),
        }
    }
}

impl OrphanSweep {
    fn empty() -> Self {
        Self {
            ids: HashSet::new(),
            adopted: HashMap::new(),
            runtime_dirs: Vec::new(),
        }
    }

    /// What [`normalize_durable_records`] needs, taken out so the runtime
    /// directories stay here for [`finalize_sweep`] — which must not run
    /// until normalization has committed.
    pub(super) fn take_runtime(&mut self) -> SweptRuntime {
        SweptRuntime {
            swept: std::mem::take(&mut self.ids),
            adopted: std::mem::take(&mut self.adopted),
        }
    }
}

/// Sweep `<data_dir>/sandboxes/*/state.json`: reclaim every sandbox whose VM
/// is still running, tear down everything else, and drop the snapshots a
/// checkpoint never finished writing.
///
/// Runs once per manager construction, in the background. Ordering per
/// killed sandbox mirrors live teardown: kill the VMM → wait for exit → dm
/// teardown → TAP release → chroot + directory removal.
pub(super) async fn sweep_orphans(
    config: &VmmConfig,
    driver: &dyn VmDriver,
    network: &dyn GuestNetwork,
    cow_manager: &CowManager,
    snapshots: &crate::snapshot::SnapshotCatalog,
    store: &SandboxRecordStore,
) -> Result<OrphanSweep> {
    // Snapshots staged by a checkpoint that died mid-flight: unfinished by
    // definition, and each can hold a full memory dump.
    snapshots.sweep_incomplete();

    let sandboxes_dir = PathBuf::from(&config.firecracker.data_dir).join("sandboxes");
    let entries = match std::fs::read_dir(&sandboxes_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OrphanSweep::empty());
        }
        Err(error) => return Err(error.into()),
    };
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry?;
        let dir = entry.path();
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let state_path = dir.join(STATE_FILE);
        let record: SandboxStateRecord = match std::fs::read(&state_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            // No record: either never booted or cleanly stopped.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        validate_state_record(config, &sandboxes_dir, &dir, &record)?;
        records.push((dir, record));
    }
    // `read_dir` order is arbitrary; a stable one makes a sweep that fails
    // partway reproducible, and lets a test say which journal it failed on.
    records.sort_by(|(_, left), (_, right)| left.id.cmp(&right.id));

    // Durable phases first: whether a journaled VM may be kept depends on
    // what its record says the sandbox was doing.
    let durable = store.load_all()?;
    let retained = recovery::retained_ids(
        durable
            .iter()
            .map(|record| (record.id.as_str(), record.phase)),
    );
    let phases: HashMap<&str, _> = durable
        .iter()
        .map(|record| (record.id.as_str(), record.phase))
        .collect();

    // From the first reclaim on, every error path has to hand back what it
    // took: propagating out of here would drop the map, which kills each
    // reclaimed guest through its handle while leaving its lease and
    // template refcount held.
    let mut adopted = HashMap::new();
    let reaped = reap_orphans(
        &records,
        &mut adopted,
        &retained,
        &phases,
        config,
        driver,
        network,
        cow_manager,
    )
    .await;
    let (swept, runtime_dirs) = match reaped {
        Ok(reaped) => reaped,
        Err(error) => {
            release_reclaimed(&mut adopted, network, cow_manager).await;
            return Err(error);
        }
    };

    Ok(OrphanSweep {
        ids: swept,
        adopted,
        runtime_dirs,
    })
}

/// Decide each journal's fate and tear down everything not kept.
///
/// Split out so [`sweep_orphans`] has exactly one place to release what a
/// failure leaves reclaimed but unowned.
#[allow(
    clippy::too_many_arguments,
    reason = "the sweep's whole resource set, threaded rather than re-derived"
)]
async fn reap_orphans(
    records: &[(PathBuf, SandboxStateRecord)],
    adopted: &mut HashMap<String, AdoptedSandbox>,
    retained: &HashSet<String>,
    phases: &HashMap<&str, super::record::PersistPhase>,
    config: &VmmConfig,
    driver: &dyn VmDriver,
    network: &dyn GuestNetwork,
    cow_manager: &CowManager,
) -> Result<(HashSet<String>, Vec<PathBuf>)> {
    // Every VM this sweep does not keep must be dead before the global CoW
    // sweep runs: a live VMM pins its dm device, and a pinned device turns
    // a reap into an error that fails the whole reconciliation.
    for (dir, record) in records {
        if let Some(reclaimed) = adopt_or_kill(
            driver,
            network,
            cow_manager,
            dir,
            record,
            phases.get(record.id.as_str()).copied(),
        )
        .await?
        {
            adopted.insert(record.id.clone(), reclaimed);
        }
    }

    // The dm devices an adopted VM is running on, keyed the way the CoW
    // manager names them. Their overlay files are kept too — the two sets
    // are distinct because a paused sandbox has a retained file and no
    // device, so folding them together would leave the device of a sandbox
    // that crashed mid-pause unreaped.
    let live_devices: HashSet<String> = records
        .iter()
        .filter(|(_, record)| adopted.contains_key(&record.id))
        .map(|(_, record)| record.resource_owner().to_owned())
        .collect();
    let mut keep_cow_files = retained.clone();
    keep_cow_files.extend(live_devices.iter().cloned());
    cow_manager.reconcile_stale(&keep_cow_files, &live_devices)?;

    let mut swept = HashSet::new();
    let mut runtime_dirs = Vec::new();
    for (dir, record) in records {
        // An adopted sandbox's journal names what this process now owns, so
        // it stays exactly where it is — as does its runtime directory,
        // which `finalize_sweep` only removes for the ids listed here.
        if adopted.contains_key(&record.id) {
            continue;
        }
        if recovery::sweep_action(&record.id, retained) == SweepAction::DropStaleJournal {
            info!(sandbox_id = %record.id, "dropping stale pause journal, keeping retained state");
            clear_state_record(dir)?;
            continue;
        }
        info!(sandbox_id = %record.id, "reconciling orphaned sandbox");

        if let Some(cow) = &record.cow {
            cow_manager.teardown_checked(&cow.to_handle()).await?;
        }

        if let Some(lease) = record.lease()? {
            network.quarantine(lease).await.map_err(VmmError::from)?;
        }

        if record.jailer
            && let Some(ref jc) = config.firecracker.jailer
        {
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let chroot = arcbox_fc_driver::jail::chroot_root(
                &config.firecracker.binary,
                base,
                record.resource_owner(),
            );
            if let Some(parent) = chroot.parent() {
                remove_dir_if_present(parent).await?;
            }
        }

        runtime_dirs.push(dir.clone());
        swept.insert(record.id.clone());
    }

    Ok((swept, runtime_dirs))
}

/// Deletes cleanup journals only after durable lifecycle normalization commits.
pub(super) async fn finalize_sweep(sweep: OrphanSweep) -> Result<()> {
    for dir in sweep.runtime_dirs {
        remove_dir_if_present(&dir).await?;
    }
    Ok(())
}

/// What the sweep established, for the normalization that follows it.
///
/// Split from [`OrphanSweep`] because the adopted runtime state is moved
/// onto the instances built here while the runtime directories it also
/// carries are needed afterwards, by [`finalize_sweep`].
pub(super) struct SweptRuntime {
    swept: HashSet<String>,
    adopted: HashMap<String, AdoptedSandbox>,
}

/// Normalizes durable records after the orphan sweep decided each sandbox's
/// fate.
///
/// A sandbox whose VM the sweep reclaimed comes back live, with the runtime
/// state that came with it. Interrupted live phases become inspectable
/// failures; already inactive sandboxes are reconstructed without runtime
/// handles. A create intent stays resumable, while an interrupted removal
/// finishes as a durable tombstone.
/// Both the sweep's runtime and the instances built from it are the
/// caller's, so a refusal partway through loses neither: what was never
/// claimed stays in `sweep` for [`release_unclaimed`], and what was already
/// built is in `built` for [`release_instances`]. An adopted instance holds
/// the only handle keeping its guest alive, so dropping either here would
/// kill that guest with its lease and template refcount still held.
pub(super) fn normalize_durable_records(
    store: &SandboxRecordStore,
    data_dir: &Path,
    sweep: Option<&mut SweptRuntime>,
    built: &mut Vec<SandboxInstance>,
) -> Result<()> {
    let inactive = built;
    let mut nothing_adopted = HashMap::new();
    let (swept, adopted) = match sweep {
        Some(sweep) => (Some(&sweep.swept), &mut sweep.adopted),
        None => (None, &mut nothing_adopted),
    };

    for record in store.load_all()? {
        let evidence = match &swept {
            None => JournalEvidence::Unchecked,
            Some(_) if adopted.contains_key(&record.id) => JournalEvidence::Adopted,
            Some(ids) if ids.contains(&record.id) => JournalEvidence::Swept,
            Some(_) => JournalEvidence::Unjournaled,
        };
        match recovery::plan(record.phase, evidence) {
            RecoveryAction::LeaveResumable => {}
            RecoveryAction::RefuseUnjournaled => {
                return Err(crate::error::VmmError::Unavailable(format!(
                    "sandbox {} is {} but has no cleanup journal",
                    record.id,
                    record.phase.as_str()
                )));
            }
            RecoveryAction::RefuseAdopted => {
                return Err(crate::error::VmmError::Unavailable(format!(
                    "sandbox {} is {}, a phase the startup sweep must not adopt",
                    record.id,
                    record.phase.as_str()
                )));
            }
            RecoveryAction::Fail => {
                let record = store
                    .transition(
                        &record.id,
                        record.generation,
                        SandboxTransition::Failed(AGENT_RESTART_ERROR.into()),
                    )?
                    .confirmed("sandbox restart normalization")?;
                inactive.push(inactive_instance(record, SandboxState::Failed, data_dir));
            }
            RecoveryAction::Reinstate(state) => {
                let instance = match adopted.remove(&record.id) {
                    Some(reclaimed) => adopted_instance(record, state, data_dir, reclaimed),
                    None => inactive_instance(record, state, data_dir),
                };
                inactive.push(instance);
            }
            RecoveryAction::FinishRemove => {
                store
                    .finish_remove(&record.id, record.generation)?
                    .confirmed("sandbox removal recovery")?;
            }
        }
    }

    Ok(())
}

/// Dispose of every reclaimed sandbox [`normalize_durable_records`] did not
/// take: kill its VM and hand back the two resources the reclaim took.
///
/// A no-op on the happy path — normalization claims every adopted record —
/// and the reason it is called on the error path too. Dropping the map
/// there would kill each VM through the handle's `Drop` while leaving its
/// lease live in the network and its template refcount held, which is the
/// one shape this sweep must never produce: resources released by nobody,
/// in a process whose reconciliation has already failed.
///
/// Best-effort per resource, because it runs while an error is already on
/// its way out and each sandbox's journal survives to be swept again.
pub(super) async fn release_unclaimed(
    runtime: &mut SweptRuntime,
    network: &dyn GuestNetwork,
    cow_manager: &CowManager,
) {
    release_reclaimed(&mut runtime.adopted, network, cow_manager).await;
}

/// Give back the two resources a reclaim took, and kill the VM it took them
/// for.
///
/// Every failure between reclaiming a sandbox and handing it to the instance
/// map routes through here. Letting the map drop instead would kill each VM
/// through its handle's `Drop` while leaving its lease live in the network
/// and its template refcount held — resources released by nobody. Killing is
/// the right disposition once nothing can own them; doing it silently, and
/// only half of it, is not.
///
/// Best-effort per resource: it runs while an error is already on its way
/// out, and every sandbox's journal survives to be swept again.
async fn release_reclaimed(
    adopted: &mut HashMap<String, AdoptedSandbox>,
    network: &dyn GuestNetwork,
    cow_manager: &CowManager,
) {
    for (id, adopted) in adopted.drain() {
        release_one(
            &id,
            &adopted.handle,
            adopted.cow_handle.as_ref(),
            adopted.lease,
            network,
            cow_manager,
        )
        .await;
    }
}

/// The same, for reclaimed sandboxes that recovery already built instances
/// for when it refused. They hold exactly what the map entries held —
/// dropping the vector would lose them the same way.
pub(super) async fn release_instances(
    instances: &mut Vec<SandboxInstance>,
    network: &dyn GuestNetwork,
    cow_manager: &CowManager,
) {
    for instance in instances.drain(..) {
        let mut instance = instance;
        let Some(handle) = instance.handle.take() else {
            continue;
        };
        release_one(
            &instance.id,
            &handle,
            instance.cow_handle.as_ref(),
            instance.network.take(),
            network,
            cow_manager,
        )
        .await;
    }
}

/// Kill this VM, and when the kill fails hand it to the next process instead
/// of letting go of it.
///
/// Every path that reaches here owns the last handle, and a handle that is
/// merely dropped kills — unreaped, and with its vsock socket unlinked. After
/// a kill that already failed, that leaves the guest alive and unreachable:
/// the damaged-guest outcome, arrived at silently. Detaching first makes the
/// drop a no-op, and the sandbox's journal survives every path that can reach
/// here, so the next sweep finds the VM again. A driver without `Detach` runs
/// its VMs in-process and never produced a handle for this sweep to reclaim,
/// so there is nothing to hand over there.
///
/// `Err` means the VM is still alive. Whether that is fatal is the caller's:
/// [`release_one`] is best-effort and warns, [`adopt_or_kill`] has to stop the
/// sweep, because a live VMM pins the dm device the global CoW reap is about
/// to walk.
async fn kill_or_hand_over(id: &str, handle: &Arc<dyn VmHandle>) -> Result<()> {
    let Err(error) = handle.shutdown(ShutdownMode::Kill).await else {
        return Ok(());
    };
    if let Some(detach) = handle.detach()
        && let Err(error) = detach.detach().await
    {
        warn!(sandbox_id = %id, %error, "handing the vmm over failed; dropping it kills it");
    }
    Err(error.into())
}

/// Let go of one reclaimed sandbox: kill its VM, then hand back the disk
/// overlay and the address it was running on.
///
/// The order is the one live teardown uses and is load-bearing in the same
/// way — a VMM that is still alive holds its dm device open and its TAP fd,
/// so a failed kill **stops** the release rather than continuing past it.
/// Taking the disk and the address away from a guest that is still running
/// would leave it alive and broken, which is worse than leaving all three
/// for the next sweep: the sandbox's journal survives this path, so there
/// is one.
async fn release_one(
    id: &str,
    handle: &Arc<dyn VmHandle>,
    cow_handle: Option<&CowHandle>,
    lease: Option<NetworkLease>,
    network: &dyn GuestNetwork,
    cow_manager: &CowManager,
) {
    warn!(sandbox_id = %id, "releasing a reclaimed sandbox that recovery did not take");
    if let Err(error) = kill_or_hand_over(id, handle).await {
        warn!(
            sandbox_id = %id, %error,
            "killing the reclaimed vmm failed; leaving it, its disk and its address for the next sweep"
        );
        return;
    }
    if let Some(cow_handle) = cow_handle
        && let Err(error) = cow_manager.teardown_checked(cow_handle).await
    {
        warn!(sandbox_id = %id, %error, "releasing the reclaimed disk overlay failed");
    }
    if let Some(lease) = lease
        && let Err(error) = network.quarantine(lease).await
    {
        warn!(sandbox_id = %id, %error, "quarantining the reclaimed lease failed");
    }
}

fn inactive_instance(
    record: SandboxRecord,
    state: SandboxState,
    data_dir: &Path,
) -> SandboxInstance {
    let vm_dir = data_dir.join("sandboxes").join(&record.id);
    let mut instance = SandboxInstance::new_with_generation(
        record.id,
        record.effective_spec,
        None,
        vm_dir,
        record.generation,
    );
    instance.state = state;
    instance.created_at = record.created_at;
    instance.error = record.error;
    // The TTL cap survives restarts: a reloaded paused sandbox still
    // expires (the lifecycle monitor re-arms the timer after reconcile).
    instance.ttl_deadline = record.ttl_deadline;
    if state == SandboxState::Paused {
        instance.pause_snapshot_id = record.pause_snapshot_id;
        instance.paused_at = record.paused_at;
    }
    instance
}

/// [`inactive_instance`] plus everything the sweep reclaimed: the VM's
/// handle, the lease whose datapath was re-established and the identity the
/// guest holds over it, the disk overlay, and the slot the resources are
/// named after.
///
/// `prepared` stays `None` — a `PreparedVm` is the driver's grip on the VMM
/// *process*, and nothing hands one back across a restart; teardown of an
/// adopted sandbox goes through the handle instead (`cleanup.rs`). `ready_at`
/// is not journaled, so it stays `None` rather than being invented from this
/// restart's clock.
fn adopted_instance(
    record: SandboxRecord,
    state: SandboxState,
    data_dir: &Path,
    adopted: AdoptedSandbox,
) -> SandboxInstance {
    let AdoptedSandbox {
        handle,
        lease,
        identity,
        cow_handle,
        pool_slot_id,
        net_invariant,
    } = adopted;
    let mut instance = inactive_instance(record, state, data_dir);
    instance.handle = Some(handle);
    instance.network = lease;
    instance.net_identity = identity;
    instance.cow_handle = cow_handle;
    instance.pool_slot_id = pool_slot_id;
    instance.net_invariant = net_invariant;
    instance
}

/// Reclaim the VM a cleanup journal names, or kill it.
///
/// The driver's `Adopt` capability finds it — the journaled pid when it is
/// still that VMM (a pid recycled since the record was written is not), else
/// whatever the driver recognises as the VM by the record's identity: the
/// id the resources are keyed by (the adopted pool slot's, for a claimed
/// sandbox) and its runtime directory. Nothing found is the common case:
/// the VMM died with the agent. A driver without `Adopt` runs its VMs
/// in-process, and those died with the agent by construction.
///
/// A handle that comes back is either reclaimed — with its datapath and its
/// disk overlay — or killed and reaped, so the dm teardown that follows
/// never hits EBUSY on an open block device. [`reclaim`] decides which,
/// and every one of its refusals falls back to that kill: the behaviour this
/// sweep had before adoption existed.
async fn adopt_or_kill(
    driver: &dyn VmDriver,
    network: &dyn GuestNetwork,
    cow_manager: &CowManager,
    runtime_dir: &Path,
    record: &SandboxStateRecord,
    phase: Option<super::record::PersistPhase>,
) -> Result<Option<AdoptedSandbox>> {
    let Some(adopt) = driver.adopt() else {
        return Ok(None);
    };
    let vm_record = VmRecord {
        id: VmId::new(record.resource_owner())?,
        driver: driver.name().to_owned(),
        runtime_dir: runtime_dir.to_path_buf(),
        process: record
            .pid
            .and_then(|pid| u32::try_from(pid).ok())
            .map(|pid| ProcessRecord {
                pid,
                api_socket: None,
            }),
    };
    let adopted = tokio::time::timeout(ADOPT_TIMEOUT, adopt.adopt(&vm_record))
        .await
        .map_err(|_| {
            VmmError::Process(format!(
                "sandbox {}: the driver did not find or reconnect to its vmm within {}s",
                record.id,
                ADOPT_TIMEOUT.as_secs()
            ))
        })??;
    let Some(handle) = adopted else {
        return Ok(None);
    };
    let handle: Arc<dyn VmHandle> = Arc::from(handle);

    match reclaim(network, cow_manager, record, phase, &handle).await {
        Ok(reclaimed) => {
            info!(sandbox_id = %record.id, vm = %vm_record.id, "reclaimed a sandbox whose vm outlived its agent");
            Ok(Some(reclaimed))
        }
        Err(reason) => {
            info!(
                sandbox_id = %record.id, vm = %vm_record.id, %reason,
                "killing the orphaned vmm"
            );
            // A kill that fails leaves the VM alive and still pinning its dm
            // device, so the sweep stops here rather than walking into the
            // global CoW reap. Stopping means giving the VM up as well: this
            // is the only handle, and dropping it undetached would kill it
            // unreaped and unlink its vsock — alive and unreachable. What
            // `reclaim` re-established before it refused stays for the next
            // sweep, which the surviving journal guarantees there is.
            kill_or_hand_over(&record.id, &handle).await?;
            Ok(None)
        }
    }
}

/// Take this live VM and the host state it was running on back, or say why
/// it cannot be taken.
///
/// `Err` carries why not, and is never fatal — the caller kills instead,
/// which is what this sweep always did. Nothing partial needs unwinding
/// here either: the two resources this takes (the lease's datapath, the
/// template refcount) are released by exactly the teardown the kill path
/// then runs, and releasing them here as well would double-drop the
/// template's refcount.
async fn reclaim(
    network: &dyn GuestNetwork,
    cow_manager: &CowManager,
    record: &SandboxStateRecord,
    phase: Option<super::record::PersistPhase>,
    handle: &Arc<dyn VmHandle>,
) -> std::result::Result<AdoptedSandbox, String> {
    // A guest that is quiesced (a checkpoint that died between the pause and
    // the resume) or gone answers nothing; only a running one is usable.
    match handle.state() {
        VmState::Running => {}
        state => return Err(format!("its vm is {state}")),
    }
    // What separates a full handle from the process-only fallback an orphan
    // whose API never answered yields: without vsock nothing can be run,
    // paused or checkpointed in this sandbox, only killed. Adopting one
    // would leave a sandbox that answers `inspect` and fails everything else.
    if handle.vsock().is_none() {
        return Err("its vmm's api never answered, so only a kill can be driven through it".into());
    }
    // `Ready` and nothing else. `Starting` died with the boot task that was
    // driving it and no path here finishes one; the transitional phases died
    // between resource states, so what their journals name is half-built.
    // `Starting` also covers the pool-slot handover window, where the slot's
    // journal and the claiming sandbox's briefly name one VMM (`checkpoint.rs`
    // documents why both exist): reclaiming through one while the other kills
    // is precisely what that window must stay safe against.
    match phase {
        Some(super::record::PersistPhase::Ready) => {}
        Some(phase) => return Err(format!("its durable record is {}", phase.as_str())),
        None => return Err("it has no durable record".into()),
    }

    let lease = record.lease().map_err(|error| error.to_string())?;
    let mode = match (&lease, record.attach_mode) {
        (Some(_), None) => {
            return Err(
                "its journal predates adoption and does not say how its network attaches".into(),
            );
        }
        (_, mode) => mode.map(AttachMode::from),
    };
    // Re-establish the host state that died with the previous process. Not
    // idempotent by design: an adapter that cannot take the lease back says
    // so rather than leaving a live guest unreachable.
    let identity = match (&lease, mode) {
        (Some(lease), Some(mode)) => {
            network
                .adopt(lease, mode)
                .await
                .map_err(|error| format!("its network could not be re-established: {error}"))?;
            Some(network.identity(lease, mode))
        }
        _ => None,
    };

    let cow_handle = record.cow.as_ref().map(CowRecord::to_handle);
    if let Some(cow_handle) = &cow_handle {
        cow_manager
            .adopt(cow_handle)
            .map_err(|error| format!("its disk overlay could not be re-registered: {error}"))?;
    }

    Ok(AdoptedSandbox {
        handle: Arc::clone(handle),
        lease,
        identity,
        cow_handle,
        pool_slot_id: record.pool_slot_id.clone(),
        net_invariant: record.net_invariant,
    })
}

async fn remove_dir_if_present(path: &Path) -> Result<()> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_state_record(
    config: &VmmConfig,
    sandboxes_dir: &Path,
    directory: &Path,
    record: &SandboxStateRecord,
) -> Result<()> {
    super::validate_id("sandbox id", &record.id)?;
    if directory.file_name().and_then(|name| name.to_str()) != Some(record.id.as_str()) {
        return Err(crate::error::VmmError::Config(format!(
            "sandbox cleanup record id {} does not match directory {}",
            record.id,
            directory.display()
        )));
    }
    if let Some(network) = &record.network {
        let expected = tap_name_for(network.ip_address);
        if network.tap_name != expected {
            return Err(crate::error::VmmError::Config(format!(
                "sandbox {} cleanup record has unexpected TAP {}",
                record.id, network.tap_name
            )));
        }
    }
    if let Some(slot_id) = &record.pool_slot_id {
        super::validate_id("pool slot id", slot_id)?;
        if !slot_id.starts_with(POOL_SLOT_PREFIX) {
            return Err(crate::error::VmmError::Config(format!(
                "sandbox {} cleanup record has non-pool slot id {slot_id}",
                record.id
            )));
        }
    }
    if let Some(cow) = &record.cow {
        let owner = record.resource_owner();
        let expected_name = format!("arcbox-snap-{owner}");
        let expected_file = Path::new(&config.firecracker.data_dir)
            .join("cow")
            .join(format!("arcbox-cow-{owner}.img"));
        if cow.dm_name != expected_name
            || cow.dm_device != format!("/dev/mapper/{expected_name}")
            || cow.cow_file != expected_file
        {
            return Err(crate::error::VmmError::Config(format!(
                "sandbox {} cleanup record has invalid CoW resources",
                record.id
            )));
        }
    }
    if let Some(origin) = &record.restore_origin_dir {
        let origin_id = origin.file_name().and_then(|name| name.to_str());
        if origin.parent() != Some(sandboxes_dir) || origin_id.is_none() {
            return Err(crate::error::VmmError::Config(format!(
                "sandbox {} restore origin escapes {}",
                record.id,
                sandboxes_dir.display()
            )));
        }
        super::validate_id("restore origin sandbox id", origin_id.unwrap())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::SandboxSpec;
    use super::super::record::{PersistPhase, ProvisionIntent, SandboxProvisionOutcome};
    use super::*;

    /// `state.json` written before the guest-network port existed, verbatim.
    /// The sweep replays leases out of records like this one, so the shape
    /// is a contract in both directions: this agent must read it, and an
    /// agent that predates the port must read what this one writes (its
    /// `NetworkAllocation` has no `#[serde(default)]` on `tap_name` or
    /// `dns_servers`, and a record missing either fails its whole sweep).
    const LEGACY_RECORD: &str = r#"{
      "id": "box",
      "pid": 4242,
      "network": {
        "tap_name": "vmtap0-7",
        "ip_address": "172.20.0.7",
        "prefix_len": 16,
        "gateway": "172.20.0.1",
        "mac_address": "02:fc:00:00:00:07",
        "dns_servers": ["1.1.1.1"],
        "cleanup_token": "gen-1"
      },
      "cow": null,
      "jailer": true,
      "restore_origin_dir": null,
      "pool_slot_id": null
    }"#;

    #[test]
    fn a_pre_port_journal_loads_and_is_written_back_unchanged() {
        let record: SandboxStateRecord = serde_json::from_str(LEGACY_RECORD).unwrap();
        let lease = record.lease().unwrap().expect("the record holds a lease");
        assert_eq!(lease.vm.as_str(), "box");
        assert_eq!(lease.ip, "172.20.0.7".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(lease.prefix_len, 16);
        assert_eq!(
            lease.gateway,
            "172.20.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(lease.mac.to_string(), "02:fc:00:00:00:07");
        assert_eq!(lease.cleanup_token, "gen-1");

        // ...and the record this agent writes from that lease still says
        // everything the old shape said, field for field — including the two
        // the lease does not carry, which are reconstructed rather than
        // dropped. What adoption added is purely additive on top.
        let mut config = VmmConfig::default();
        config.network.dns = vec!["1.1.1.1".into()];
        config.firecracker.jailer = Some(crate::config::JailerConfig {
            binary: "/usr/bin/jailer".into(),
            uid: 0,
            gid: 0,
            chroot_base_dir: None,
            netns: None,
            new_pid_ns: false,
            cgroup_version: None,
            parent_cgroup: None,
            resource_limits: vec![],
        });
        let written = SandboxStateRecord::new(
            "box",
            Some(4242),
            Some(JournaledLease::cold_boot(&lease, true)),
            None,
            &config,
            None,
        )
        .unwrap();
        let mut value = serde_json::to_value(&written).unwrap();
        let fields = value.as_object_mut().unwrap();
        assert_eq!(
            fields.remove("attach_mode"),
            Some(serde_json::json!("invariant"))
        );
        assert_eq!(
            fields.remove("net_invariant"),
            Some(serde_json::json!(true))
        );
        assert_eq!(
            value,
            serde_json::from_str::<serde_json::Value>(LEGACY_RECORD).unwrap()
        );
    }

    /// The two fields adoption added default the way the record's
    /// both-directions contract requires: a journal written before they
    /// existed loads, and says it is not adoptable rather than guessing a
    /// datapath.
    #[test]
    fn a_journal_without_an_attach_mode_loads_as_not_adoptable() {
        let record: SandboxStateRecord = serde_json::from_str(LEGACY_RECORD).unwrap();
        assert_eq!(record.attach_mode, None);
        assert!(!record.net_invariant);
    }

    /// A cold boot always activates `Invariant`, whatever the guest's own
    /// identity ends up being — the distinction the journal exists to keep.
    #[test]
    fn a_cold_boot_journals_the_invariant_mode_even_without_the_invariant_identity() {
        let lease = NetworkLease {
            vm: VmId::new("box").unwrap(),
            ip: "172.20.0.7".parse().unwrap(),
            prefix_len: 16,
            gateway: "172.20.0.1".parse().unwrap(),
            mac: "02:fc:00:00:00:07".parse().unwrap(),
            cleanup_token: "gen-1".into(),
        };
        let config = VmmConfig::default();
        for baked in [true, false] {
            let record = SandboxStateRecord::new(
                "box",
                None,
                Some(JournaledLease::cold_boot(&lease, baked)),
                None,
                &config,
                None,
            )
            .unwrap();
            assert_eq!(record.attach_mode, Some(JournaledAttachMode::Invariant));
            assert_eq!(record.net_invariant, baked);
        }
        // A restore or resume is the only thing that varies the mode, and
        // both halves come from the snapshot's flag there.
        let legacy = SandboxStateRecord::new(
            "box",
            None,
            Some(JournaledLease::from_snapshot(&lease, false)),
            None,
            &config,
            None,
        )
        .unwrap();
        assert_eq!(
            legacy.attach_mode,
            Some(JournaledAttachMode::LegacySnapshot)
        );
        assert!(!legacy.net_invariant);
    }

    fn record_in_phase(store: &SandboxRecordStore, id: &str, phase: PersistPhase) -> SandboxRecord {
        let spec = SandboxSpec {
            id: Some(id.into()),
            ..SandboxSpec::default()
        };
        let record = match store.provision_intent(id, "create-key", spec).unwrap() {
            ProvisionIntent::Created(record) => record,
            other => panic!("expected a new record, got {other:?}"),
        };
        let generation = record.generation;

        match phase {
            PersistPhase::Creating => return record,
            PersistPhase::Failed => {
                store
                    .transition(
                        id,
                        generation,
                        SandboxTransition::Failed("original failure".into()),
                    )
                    .unwrap();
            }
            PersistPhase::Removing => {
                store
                    .transition(
                        id,
                        generation,
                        SandboxTransition::Starting(SandboxProvisionOutcome {
                            ip_address: "192.0.2.2".into(),
                        }),
                    )
                    .unwrap();
                store
                    .transition(id, generation, SandboxTransition::Removing)
                    .unwrap();
            }
            phase => {
                store
                    .transition(
                        id,
                        generation,
                        SandboxTransition::Starting(SandboxProvisionOutcome {
                            ip_address: "192.0.2.2".into(),
                        }),
                    )
                    .unwrap();
                match phase {
                    PersistPhase::Starting => {}
                    PersistPhase::Ready => {
                        store
                            .transition(id, generation, SandboxTransition::Ready)
                            .unwrap();
                    }
                    PersistPhase::Stopping | PersistPhase::Stopped => {
                        store
                            .transition(id, generation, SandboxTransition::Stopping)
                            .unwrap();
                        if phase == PersistPhase::Stopped {
                            store
                                .transition(id, generation, SandboxTransition::Stopped)
                                .unwrap();
                        }
                    }
                    PersistPhase::Pausing | PersistPhase::Paused | PersistPhase::Resuming => {
                        store
                            .transition(id, generation, SandboxTransition::Ready)
                            .unwrap();
                        store
                            .transition(id, generation, SandboxTransition::Pausing)
                            .unwrap();
                        if phase != PersistPhase::Pausing {
                            store
                                .transition(
                                    id,
                                    generation,
                                    SandboxTransition::Paused {
                                        snapshot_id: "snap".into(),
                                    },
                                )
                                .unwrap();
                        }
                        if phase == PersistPhase::Resuming {
                            store
                                .transition(id, generation, SandboxTransition::Resuming)
                                .unwrap();
                        }
                    }
                    _ => unreachable!("phase handled above"),
                }
            }
        }

        store.load(id).unwrap().unwrap()
    }

    #[test]
    fn state_record_roundtrips_through_json() {
        let record = SandboxStateRecord {
            id: "sb-1".into(),
            pid: Some(42),
            network: None,
            cow: Some(CowRecord {
                dm_name: "arcbox-snap-sb-1".into(),
                dm_device: "/dev/mapper/arcbox-snap-sb-1".into(),
                cow_loop: "/dev/loop7".into(),
                cow_file: "/var/lib/arcbox/cow/sb-1".into(),
                template_path: "/var/lib/arcbox/sandbox/rootfs.ext4".into(),
            }),
            jailer: true,
            restore_origin_dir: None,
            pool_slot_id: Some("pool-1".into()),
            attach_mode: Some(JournaledAttachMode::Invariant),
            net_invariant: true,
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        let parsed: SandboxStateRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.id, "sb-1");
        assert_eq!(parsed.pid, Some(42));
        assert!(parsed.jailer);
        assert_eq!(parsed.pool_slot_id.as_deref(), Some("pool-1"));
        assert_eq!(parsed.resource_owner(), "pool-1");
        let handle = parsed.cow.unwrap().to_handle();
        assert_eq!(handle.dm_name, "arcbox-snap-sb-1");
    }

    #[test]
    fn cleanup_record_validation_keys_cow_resources_by_the_pool_slot() {
        let config = VmmConfig::default();
        let sandboxes_dir = Path::new("/var/lib/firecracker-vmm/sandboxes");
        let directory = sandboxes_dir.join("sb-1");
        let cow_for = |owner: &str| CowRecord {
            dm_name: format!("arcbox-snap-{owner}"),
            dm_device: format!("/dev/mapper/arcbox-snap-{owner}"),
            cow_loop: "/dev/loop7".into(),
            cow_file: Path::new(&config.firecracker.data_dir)
                .join("cow")
                .join(format!("arcbox-cow-{owner}.img")),
            template_path: "/var/lib/arcbox/sandbox/rootfs.ext4".into(),
        };
        let record = |slot: Option<&str>, cow_owner: &str| SandboxStateRecord {
            id: "sb-1".into(),
            pid: None,
            network: None,
            cow: Some(cow_for(cow_owner)),
            jailer: true,
            restore_origin_dir: None,
            pool_slot_id: slot.map(str::to_owned),
            attach_mode: None,
            net_invariant: false,
        };

        // Slot-keyed resources validate against the slot id, not the sandbox id.
        validate_state_record(
            &config,
            sandboxes_dir,
            &directory,
            &record(Some("pool-abc"), "pool-abc"),
        )
        .unwrap();
        // A claimed record whose CoW is named after the sandbox id is corrupt.
        assert!(
            validate_state_record(
                &config,
                sandboxes_dir,
                &directory,
                &record(Some("pool-abc"), "sb-1"),
            )
            .is_err()
        );
        // A slot id outside the pool namespace is rejected.
        assert!(
            validate_state_record(
                &config,
                sandboxes_dir,
                &directory,
                &record(Some("other-abc"), "other-abc"),
            )
            .is_err()
        );
        // Without a slot the sandbox id keys the resources, as before.
        validate_state_record(&config, sandboxes_dir, &directory, &record(None, "sb-1")).unwrap();
    }

    #[test]
    fn clearing_state_record_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(STATE_FILE), b"journal").unwrap();

        clear_state_record(tmp.path()).unwrap();
        clear_state_record(tmp.path()).unwrap();

        assert!(!tmp.path().join(STATE_FILE).exists());
    }

    #[test]
    fn startup_normalizes_crash_phases_and_restores_inactive_records() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        for (id, phase) in [
            ("creating", PersistPhase::Creating),
            ("starting", PersistPhase::Starting),
            ("ready", PersistPhase::Ready),
            ("stopping", PersistPhase::Stopping),
            ("stopped", PersistPhase::Stopped),
            ("failed", PersistPhase::Failed),
            ("removing", PersistPhase::Removing),
        ] {
            record_in_phase(&store, id, phase);
        }

        let mut inactive = Vec::new();
        normalize_durable_records(&store, data_dir.path(), None, &mut inactive).unwrap();
        let inactive: HashMap<_, _> = inactive
            .into_iter()
            .map(|instance| (instance.id.clone(), instance))
            .collect();

        assert_eq!(inactive.len(), 5);
        for id in ["starting", "ready", "stopping"] {
            let record = store.load(id).unwrap().unwrap();
            assert_eq!(record.phase, PersistPhase::Failed);
            assert_eq!(record.error.as_deref(), Some(AGENT_RESTART_ERROR));

            let instance = &inactive[id];
            assert_eq!(instance.state, SandboxState::Failed);
            assert_eq!(instance.error.as_deref(), Some(AGENT_RESTART_ERROR));
            assert_eq!(instance.record_generation, Some(record.generation));
            assert!(instance.prepared.is_none());
            assert!(instance.handle.is_none());
            assert!(instance.network.is_none());
        }

        assert_eq!(inactive["stopped"].state, SandboxState::Stopped);
        assert_eq!(inactive["failed"].state, SandboxState::Failed);
        assert_eq!(
            inactive["failed"].error.as_deref(),
            Some("original failure")
        );
        assert_eq!(
            store.load("creating").unwrap().unwrap().phase,
            PersistPhase::Creating
        );
        assert!(store.load("removing").unwrap().is_none());
        assert!(!inactive.contains_key("removing"));
    }

    #[test]
    fn paused_records_survive_restart_while_interrupted_transitions_fail() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        record_in_phase(&store, "clean", PersistPhase::Paused);
        record_in_phase(&store, "mid-pause", PersistPhase::Pausing);
        record_in_phase(&store, "mid-resume", PersistPhase::Resuming);

        let mut inactive = Vec::new();
        normalize_durable_records(
            &store,
            data_dir.path(),
            Some(&mut SweptRuntime::nothing_kept()),
            &mut inactive,
        )
        .unwrap();
        let inactive: HashMap<_, _> = inactive
            .into_iter()
            .map(|instance| (instance.id.clone(), instance))
            .collect();

        let clean = &inactive["clean"];
        assert_eq!(clean.state, SandboxState::Paused);
        assert_eq!(clean.pause_snapshot_id.as_deref(), Some("snap"));
        assert!(clean.paused_at.is_some());
        assert_eq!(
            store.load("clean").unwrap().unwrap().phase,
            PersistPhase::Paused
        );

        // An interrupted pause/resume never reached a durable Paused commit;
        // its resources were swept, so it degrades honestly.
        for id in ["mid-pause", "mid-resume"] {
            assert_eq!(inactive[id].state, SandboxState::Failed, "{id}");
            assert_eq!(
                store.load(id).unwrap().unwrap().phase,
                PersistPhase::Failed,
                "{id}"
            );
        }
    }

    /// The crash window between the durable `Paused` commit and the journal
    /// clear must not cost the sandbox its retained disk state: the restart
    /// sweep drops the stale journal and keeps everything else.
    #[tokio::test]
    async fn stale_pause_journal_is_dropped_and_retained_state_survives() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        record_in_phase(&store, "napper", PersistPhase::Paused);

        let vm_dir = data_dir.path().join("sandboxes").join("napper");
        std::fs::create_dir_all(&vm_dir).unwrap();
        std::fs::write(vm_dir.join(STATE_FILE), br#"{"id": "napper"}"#).unwrap();
        let parked_rootfs = vm_dir.join(super::super::pause::PAUSED_ROOTFS_FILE);
        std::fs::write(&parked_rootfs, b"disk").unwrap();
        let cow_dir = data_dir.path().join("cow");
        std::fs::create_dir_all(&cow_dir).unwrap();
        let cow_file = cow_dir.join("arcbox-cow-napper.img");
        std::fs::write(&cow_file, b"overlay").unwrap();
        drop(store);

        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        let manager = super::super::SandboxManager::new(config).unwrap();
        manager.await_reconcile().await.unwrap();

        assert!(!vm_dir.join(STATE_FILE).exists());
        assert!(parked_rootfs.exists());
        assert!(cow_file.exists());
        let instances = manager.instances.read().unwrap();
        let inst = instances["napper"].lock().unwrap();
        assert_eq!(inst.state, SandboxState::Paused);
        assert_eq!(inst.pause_snapshot_id.as_deref(), Some("snap"));
    }

    /// A journal whose VMM outlived the agent: the sweep finds it through
    /// the driver's Adopt capability, kills it, and clears the journal —
    /// before anything else the sandbox held is torn down.
    #[tokio::test]
    async fn startup_sweep_kills_the_journaled_vmm_through_adopt() {
        use arcbox_vm_driver::testkit::FakeDriver;
        use arcbox_vm_driver::{BootSpec, ConsoleSpec, IsolationSpec, VmSpec, VmState};

        let data_dir = tempfile::tempdir().unwrap();
        let driver = FakeDriver::new();
        let vm_dir = data_dir.path().join("sandboxes").join("orphan");
        std::fs::create_dir_all(&vm_dir).unwrap();
        // The previous agent's VM: booted, then left running when that
        // agent died — which is what a detached handle stands for here.
        let vm = driver
            .boot(
                VmSpec {
                    id: VmId::new("orphan").unwrap(),
                    cpus: 1,
                    memory_mib: 128,
                    boot: BootSpec::Kernel {
                        image: "/vmlinux".into(),
                        cmdline: String::new(),
                        initrd: None,
                    },
                    disks: vec![],
                    nics: vec![],
                    vsock: None,
                    shares: vec![],
                    console: ConsoleSpec::Off,
                    balloon: false,
                    entropy: false,
                    dirty_tracking: false,
                    isolation: IsolationSpec::None,
                },
                &vm_dir,
            )
            .await
            .unwrap();
        vm.detach().unwrap().detach().await.unwrap();
        let pid = vm.record().process.map(|process| process.pid).unwrap();
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        write_state_record(
            &vm_dir,
            &SandboxStateRecord::new(
                "orphan",
                Some(i32::try_from(pid).unwrap()),
                None,
                None,
                &config,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        let manager = super::super::SandboxManager::with_environment(
            config,
            crate::SandboxEnvironment {
                driver: Some(std::sync::Arc::new(driver)),
                ..crate::SandboxEnvironment::default()
            },
        )
        .unwrap();
        manager.await_reconcile().await.unwrap();

        assert_eq!(
            vm.state(),
            VmState::Exited(arcbox_vm_driver::ExitStatus::signaled(9)),
            "the orphaned vm is killed through its adopted handle"
        );
        assert!(!vm_dir.join(STATE_FILE).exists(), "the journal is cleared");
    }

    /// How the adoption tests below differ from one another, each shifting
    /// exactly one predicate away from the case that is kept alive.
    /// A VM whose kill never succeeds — the reaper never sees it exit.
    /// Wrapping a real fake handle keeps `detach` live, so a test can tell
    /// "handed over" from "dropped, and therefore killed".
    struct RefusesShutdown(Arc<dyn VmHandle>);

    #[async_trait::async_trait]
    impl VmHandle for RefusesShutdown {
        fn id(&self) -> &VmId {
            self.0.id()
        }
        fn record(&self) -> VmRecord {
            self.0.record()
        }
        fn state(&self) -> VmState {
            self.0.state()
        }
        fn events(&self) -> tokio::sync::broadcast::Receiver<arcbox_vm_driver::VmEvent> {
            self.0.events()
        }
        async fn shutdown(
            &self,
            _mode: ShutdownMode,
        ) -> arcbox_vm_driver::Result<arcbox_vm_driver::ExitStatus> {
            Err(arcbox_vm_driver::Error::Driver {
                driver: "fake",
                message: "the reaper did not see it exit".into(),
                source: None,
            })
        }
        fn detach(&self) -> Option<&dyn arcbox_vm_driver::Detach> {
            self.0.detach()
        }
    }

    struct AdoptionCase {
        /// Whether the VM the previous agent left behind has vsock — i.e.
        /// whether the driver hands back a full handle or the process-only
        /// fallback of an orphan whose API never answered.
        vsock: bool,
        /// The durable phase the sandbox's record is in.
        phase: PersistPhase,
        /// Whether the journal says how its lease attaches. A record written
        /// before adoption existed does not.
        journal_attach_mode: bool,
        /// Whether the guest network can take the lease back.
        network_adopts: bool,
    }

    impl AdoptionCase {
        /// The case adoption exists for: a `Ready` sandbox whose VM answers.
        fn live() -> Self {
            Self {
                vsock: true,
                phase: PersistPhase::Ready,
                journal_attach_mode: true,
                network_adopts: true,
            }
        }
    }

    /// A VM the previous agent booted in `vm_dir`, optionally handed over
    /// rather than killed. Kept undetached, the fake driver refuses to adopt
    /// it — which is how a sweep-time adopt failure is staged.
    async fn boot_previous_vm(
        driver: &arcbox_vm_driver::testkit::FakeDriver,
        vm_dir: &Path,
        id: &str,
        vsock: bool,
        handed_over: bool,
    ) -> Box<dyn VmHandle> {
        use arcbox_vm_driver::{BootSpec, ConsoleSpec, IsolationSpec, VmSpec, VsockSpec};

        std::fs::create_dir_all(vm_dir).unwrap();
        let vm = driver
            .boot(
                VmSpec {
                    id: VmId::new(id).unwrap(),
                    cpus: 1,
                    memory_mib: 128,
                    boot: BootSpec::Kernel {
                        image: "/vmlinux".into(),
                        cmdline: String::new(),
                        initrd: None,
                    },
                    disks: vec![],
                    nics: vec![],
                    vsock: vsock.then_some(VsockSpec { guest_cid: 3 }),
                    shares: vec![],
                    console: ConsoleSpec::Off,
                    balloon: false,
                    entropy: false,
                    dirty_tracking: false,
                    isolation: IsolationSpec::None,
                },
                vm_dir,
            )
            .await
            .unwrap();
        if handed_over {
            vm.detach().unwrap().detach().await.unwrap();
        }
        vm
    }

    /// Plant one sandbox that outlived its agent — a detached VM, a durable
    /// record, and a crash journal naming both — then build a fresh manager
    /// over the same data directory and report what its sweep made of it.
    ///
    /// Returns the previous agent's view of the VM and the manager, so a
    /// caller can tell "reclaimed" from "killed" by the VM's own state.
    async fn sweep_one(
        data_dir: &Path,
        case: &AdoptionCase,
        unjournaled: &[(&str, PersistPhase)],
    ) -> (
        Box<dyn VmHandle>,
        super::super::SandboxManager,
        std::sync::Arc<arcbox_vm_driver::testkit::FakeNetwork>,
        Result<()>,
    ) {
        use arcbox_vm_driver::testkit::{FakeDriver, FakeNetwork};

        let driver = FakeDriver::new();
        let network = std::sync::Arc::new(FakeNetwork::new());
        let vm_dir = data_dir.join("sandboxes").join("keeper");
        let vm = boot_previous_vm(&driver, &vm_dir, "keeper", case.vsock, true).await;
        let pid = vm.record().process.map(|process| process.pid).unwrap();

        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
        let store = SandboxRecordStore::new(data_dir).unwrap();
        record_in_phase(&store, "keeper", case.phase);
        // Durable records with no journal at all, which is what makes
        // recovery refuse to normalize and fails the whole reconciliation.
        for (id, phase) in unjournaled {
            record_in_phase(&store, id, *phase);
        }
        drop(store);

        let lease = NetworkLease {
            vm: VmId::new("keeper").unwrap(),
            ip: "10.200.0.9".parse().unwrap(),
            prefix_len: 16,
            gateway: "10.200.0.1".parse().unwrap(),
            mac: "02:fc:00:00:00:09".parse().unwrap(),
            cleanup_token: "gen-1".into(),
        };
        let mut record = SandboxStateRecord::new(
            "keeper",
            Some(i32::try_from(pid).unwrap()),
            Some(JournaledLease::cold_boot(&lease, true)),
            None,
            &config,
            None,
        )
        .unwrap();
        if !case.journal_attach_mode {
            record.attach_mode = None;
            record.net_invariant = false;
        }
        write_state_record(&vm_dir, &record).unwrap();

        if !case.network_adopts {
            network.fail_adopt_once();
        }
        let manager = super::super::SandboxManager::with_environment(
            config,
            crate::SandboxEnvironment {
                driver: Some(std::sync::Arc::new(driver)),
                network: Some(std::sync::Arc::clone(&network) as std::sync::Arc<dyn GuestNetwork>),
                ..crate::SandboxEnvironment::default()
            },
        )
        .unwrap();
        let reconciled = manager.await_reconcile().await;
        (vm, manager, network, reconciled)
    }

    /// The payload: a `Ready` sandbox whose VM outlived its agent comes back
    /// with everything it was running on, and its journal stays where it is.
    #[tokio::test]
    async fn a_live_ready_sandbox_is_reclaimed_rather_than_killed() {
        let data_dir = tempfile::tempdir().unwrap();
        let (vm, manager, network, reconciled) =
            sweep_one(data_dir.path(), &AdoptionCase::live(), &[]).await;
        reconciled.unwrap();

        assert_eq!(vm.state(), VmState::Running, "the guest was never killed");
        let instances = manager.instances.read().unwrap();
        let inst = instances["keeper"].lock().unwrap();
        // `Ready`, not `Running`: the workload the previous process was
        // streaming did not survive it, and `Running` refuses the next `Run`.
        assert_eq!(inst.state, SandboxState::Ready);
        assert!(inst.handle.is_some(), "the VM's handle came back");
        assert!(inst.prepared.is_none(), "no PreparedVm crosses a restart");
        assert_eq!(
            inst.network.as_ref().map(|lease| lease.ip.to_string()),
            Some("10.200.0.9".to_owned()),
            "the lease came back"
        );
        assert!(
            inst.net_identity.is_some(),
            "the guest is described the way its boot described it"
        );
        assert!(inst.net_invariant, "and under the identity it holds");
        assert_eq!(
            network.adopted_mode(&VmId::new("keeper").unwrap()),
            Some(AttachMode::Invariant),
            "the datapath is re-established as the journal says it was built"
        );
        assert!(
            data_dir
                .path()
                .join("sandboxes/keeper")
                .join(STATE_FILE)
                .exists(),
            "an adopted journal is live state, not debris"
        );
    }

    /// The sweep itself can fail after reclaiming: an orphan the driver
    /// refuses to adopt aborts it, and what it already took must be handed
    /// back rather than dropped. Deterministic because the sweep sorts its
    /// journals, so `keeper` is reclaimed before `zzz-broken` fails.
    #[tokio::test]
    async fn a_failed_sweep_hands_back_what_it_already_reclaimed() {
        use arcbox_vm_driver::testkit::{FakeDriver, FakeNetwork};

        let data_dir = tempfile::tempdir().unwrap();
        let driver = FakeDriver::new();
        let network = std::sync::Arc::new(FakeNetwork::new());
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();

        let keeper_dir = data_dir.path().join("sandboxes").join("keeper");
        let keeper = boot_previous_vm(&driver, &keeper_dir, "keeper", true, true).await;
        let lease = NetworkLease {
            vm: VmId::new("keeper").unwrap(),
            ip: "10.200.0.9".parse().unwrap(),
            prefix_len: 16,
            gateway: "10.200.0.1".parse().unwrap(),
            mac: "02:fc:00:00:00:09".parse().unwrap(),
            cleanup_token: "gen-1".into(),
        };
        write_state_record(
            &keeper_dir,
            &SandboxStateRecord::new(
                "keeper",
                keeper
                    .record()
                    .process
                    .map(|process| i32::try_from(process.pid).unwrap()),
                Some(JournaledLease::cold_boot(&lease, true)),
                None,
                &config,
                None,
            )
            .unwrap(),
        )
        .unwrap();

        // Still owned by a live handle, which the fake driver refuses to
        // adopt — the sweep's own error, after `keeper` was reclaimed.
        let broken_dir = data_dir.path().join("sandboxes").join("zzz-broken");
        let _broken = boot_previous_vm(&driver, &broken_dir, "zzz-broken", true, false).await;
        write_state_record(
            &broken_dir,
            &SandboxStateRecord::new("zzz-broken", None, None, None, &config, None).unwrap(),
        )
        .unwrap();

        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        record_in_phase(&store, "keeper", PersistPhase::Ready);
        drop(store);

        let manager = super::super::SandboxManager::with_environment(
            config,
            crate::SandboxEnvironment {
                driver: Some(std::sync::Arc::new(driver)),
                network: Some(std::sync::Arc::clone(&network) as std::sync::Arc<dyn GuestNetwork>),
                ..crate::SandboxEnvironment::default()
            },
        )
        .unwrap();

        manager
            .await_reconcile()
            .await
            .expect_err("an orphan the driver cannot adopt fails the sweep");
        assert_eq!(
            keeper.state(),
            VmState::Exited(arcbox_vm_driver::ExitStatus::signaled(9)),
            "the reclaimed vm is killed rather than left ownerless"
        );
        assert_eq!(
            network.adopted_mode(&VmId::new("keeper").unwrap()),
            None,
            "and its lease is handed back rather than left live"
        );
    }

    /// Recovery can still refuse *after* the sweep reclaimed something — a
    /// peer record in a live phase with no journal is enough. What the sweep
    /// took must then be handed back explicitly: letting the map drop would
    /// kill each VM through its handle while leaving the lease live in the
    /// network and the template refcount held, i.e. resources nobody owns in
    /// a process whose reconciliation has already failed.
    #[tokio::test]
    async fn a_failed_normalization_hands_back_what_the_sweep_reclaimed() {
        // Durable records are normalized in sorted order, so the peer's id
        // decides whether the refusal lands before `keeper` was claimed (it
        // is still in the sweep's map) or after (it is already an instance).
        // Both lose it if the loser is dropped rather than released.
        for peer in ["aaa-ghost", "zzz-ghost"] {
            let data_dir = tempfile::tempdir().unwrap();
            let (vm, _manager, network, reconciled) = sweep_one(
                data_dir.path(),
                &AdoptionCase::live(),
                &[(peer, PersistPhase::Ready)],
            )
            .await;

            // `await_reconcile` reports the task's failure as text, so the
            // message is what says which refusal it was.
            let error = reconciled.expect_err("an unjournaled live record refuses normalization");
            assert!(
                error.to_string().contains("has no cleanup journal"),
                "{peer}: unexpected reconciliation failure: {error}"
            );
            assert_eq!(
                vm.state(),
                VmState::Exited(arcbox_vm_driver::ExitStatus::signaled(9)),
                "{peer}: the reclaimed vm is killed rather than left ownerless"
            );
            assert_eq!(
                network.adopted_mode(&VmId::new("keeper").unwrap()),
                None,
                "{peer}: its lease is handed back rather than left live"
            );
        }
    }

    /// A kill that fails leaves a guest running, and taking its disk and its
    /// address away then would leave it alive and broken. The release stops
    /// instead; the journal survives for the next sweep to retry.
    #[tokio::test]
    async fn a_release_whose_kill_fails_keeps_the_disk_and_the_address() {
        use arcbox_vm_driver::testkit::{FakeDriver, FakeNetwork};

        let data_dir = tempfile::tempdir().unwrap();
        let driver = FakeDriver::new();
        let network = FakeNetwork::new();
        let probe = Arc::new(crate::snapshot_cow::CowTestProbe::default());
        let cow_manager = CowManager::new_with_test_probe(
            crate::snapshot_cow::CowOptions::new(data_dir.path()),
            Arc::clone(&probe),
        )
        .unwrap();

        let vm_dir = data_dir.path().join("sandboxes").join("stuck");
        // Still owned, so that giving ownership up is observable: the fake
        // driver refuses to adopt an owned VM, and a dropped-not-detached
        // handle kills it.
        let vm = boot_previous_vm(&driver, &vm_dir, "stuck", true, false).await;
        let vm_record = vm.record();
        let lease = network
            .reserve(
                &VmId::new("stuck").unwrap(),
                super::super::sandbox_network_policy(),
            )
            .await
            .unwrap();
        network.release(lease.clone()).await.unwrap();
        network.adopt(&lease, AttachMode::Invariant).await.unwrap();

        let mut adopted = HashMap::new();
        adopted.insert(
            "stuck".to_owned(),
            AdoptedSandbox {
                handle: Arc::new(RefusesShutdown(Arc::from(vm))),
                lease: Some(lease),
                identity: None,
                cow_handle: Some(CowHandle {
                    dm_name: "arcbox-snap-stuck".into(),
                    dm_device: "/dev/mapper/arcbox-snap-stuck".into(),
                    cow_loop: "/dev/loop7".into(),
                    cow_file: data_dir.path().join("cow/arcbox-cow-stuck.img"),
                    template_path: "/rootfs.ext4".into(),
                }),
                pool_slot_id: None,
                net_invariant: true,
            },
        );

        release_reclaimed(&mut adopted, &network, &cow_manager).await;

        assert_eq!(
            probe.teardown_count(),
            0,
            "a guest that is still running keeps its disk"
        );
        assert_eq!(
            network.adopted_mode(&VmId::new("stuck").unwrap()),
            Some(AttachMode::Invariant),
            "and its address"
        );
        // And the guest itself: the release let go of it rather than
        // dropping the handle, which would have killed it unreaped.
        let readopted = driver
            .adopt()
            .expect("the fake driver adopts")
            .adopt(&vm_record)
            .await
            .unwrap();
        assert!(
            readopted.is_some(),
            "the vm is still there for the next sweep to retry"
        );
    }

    /// The kill every adoption refusal falls back to can itself fail, and by
    /// then the sweep owns the only handle on a VM that is still running.
    /// Dropping it would kill unreaped and unlink the vsock — a guest left
    /// alive and unreachable, which is the outcome this whole path exists to
    /// prevent. So the fallback hands the VM over and reports the failure;
    /// the caller decides what to do with it.
    #[tokio::test]
    async fn a_kill_that_fails_hands_the_vm_over_instead_of_dropping_it() {
        use arcbox_vm_driver::testkit::FakeDriver;

        let data_dir = tempfile::tempdir().unwrap();
        let driver = FakeDriver::new();
        let vm_dir = data_dir.path().join("sandboxes").join("stuck");
        // Still owned: the fake driver refuses to adopt an owned VM, so a
        // later adopt succeeding is proof the handover happened.
        let vm = boot_previous_vm(&driver, &vm_dir, "stuck", true, false).await;
        let vm_record = vm.record();
        let handle: Arc<dyn VmHandle> = Arc::new(RefusesShutdown(Arc::from(vm)));

        let failed = kill_or_hand_over("stuck", &handle).await;

        assert!(
            failed.is_err(),
            "a vm that is still alive is reported, not swallowed"
        );
        drop(handle);
        let readopted = driver
            .adopt()
            .expect("the fake driver adopts")
            .adopt(&vm_record)
            .await
            .unwrap();
        assert!(
            readopted.is_some(),
            "the vm was handed over, so letting go of the handle did not kill it"
        );
    }

    /// Each predicate on its own: shift one away from the live case and the
    /// sweep falls back to the teardown it did before adoption existed.
    #[tokio::test]
    async fn every_adoption_predicate_falls_back_to_the_kill() {
        for (what, case) in [
            (
                "a process-only handle whose api never answered",
                AdoptionCase {
                    vsock: false,
                    ..AdoptionCase::live()
                },
            ),
            (
                "a boot that never reached ready",
                AdoptionCase {
                    phase: PersistPhase::Starting,
                    ..AdoptionCase::live()
                },
            ),
            (
                "a journal that predates adoption",
                AdoptionCase {
                    journal_attach_mode: false,
                    ..AdoptionCase::live()
                },
            ),
            (
                "a network that cannot take the lease back",
                AdoptionCase {
                    network_adopts: false,
                    ..AdoptionCase::live()
                },
            ),
        ] {
            let data_dir = tempfile::tempdir().unwrap();
            let (vm, manager, _, reconciled) = sweep_one(data_dir.path(), &case, &[]).await;
            reconciled.unwrap();

            assert_eq!(
                vm.state(),
                VmState::Exited(arcbox_vm_driver::ExitStatus::signaled(9)),
                "{what}: the vm is killed through its adopted handle"
            );
            assert!(
                !data_dir
                    .path()
                    .join("sandboxes/keeper")
                    .join(STATE_FILE)
                    .exists(),
                "{what}: the journal is cleared"
            );
            let instances = manager.instances.read().unwrap();
            let inst = instances["keeper"].lock().unwrap();
            assert_eq!(inst.state, SandboxState::Failed, "{what}");
            assert!(inst.handle.is_none(), "{what}");
        }
    }

    #[test]
    fn active_record_without_cleanup_journal_blocks_normalization() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        record_in_phase(&store, "starting", PersistPhase::Starting);

        assert!(matches!(
            normalize_durable_records(
                &store,
                data_dir.path(),
                Some(&mut SweptRuntime::nothing_kept()),
                &mut Vec::new()
            ),
            Err(crate::error::VmmError::Unavailable(_))
        ));
        assert_eq!(
            store.load("starting").unwrap().unwrap().phase,
            PersistPhase::Starting
        );
    }
}
