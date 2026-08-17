//! Crash-recovery reconciliation for sandbox runtime state.
//!
//! `SandboxManager` state is in-memory; if the agent restarts (crash,
//! supervision respawn) the Firecracker processes, TAP devices, dm-snapshot
//! devices, and jailer chroots of running sandboxes leak, and fresh IP
//! allocations can collide with orphaned TAPs. To recover, every successful
//! boot/restore persists a small `state.json` next to the sandbox's runtime
//! files, and a new manager sweeps those records: orphaned Firecracker
//! processes are killed and every held resource is torn down. Sandboxes are
//! not live-reconciled yet: startup destroys orphaned runtime resources, then
//! normalizes durable lifecycle records for replay and inspection.

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::info;

use super::persistence::{SandboxPhase, SandboxRecord, SandboxRecordStore, SandboxTransition};
use super::{SandboxInstance, SandboxState};
use crate::config::VmmConfig;
use crate::error::Result;
use crate::network::{NetworkAllocation, NetworkManager};
use crate::snapshot_cow::{CowHandle, CowManager};

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

    fn into_handle(self) -> CowHandle {
        CowHandle {
            dm_name: self.dm_name,
            dm_device: self.dm_device,
            cow_loop: self.cow_loop,
            cow_file: self.cow_file,
            template_path: self.template_path,
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
    /// Firecracker PID at boot time.
    #[serde(default)]
    pub pid: Option<i32>,
    /// Network allocation to release (TAP + IP).
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
}

impl SandboxStateRecord {
    /// Assemble a record from boot/restore results.
    pub fn new(
        id: &str,
        pid: Option<i32>,
        network: Option<&NetworkAllocation>,
        cow: Option<&CowHandle>,
        jailer: bool,
        restore_origin_dir: Option<&Path>,
    ) -> Self {
        Self {
            id: id.to_owned(),
            pid,
            network: network.cloned(),
            cow: cow.map(CowRecord::from_handle),
            jailer,
            restore_origin_dir: restore_origin_dir.map(Path::to_path_buf),
            pool_slot_id: None,
        }
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

pub(super) struct OrphanSweep {
    pub ids: HashSet<String>,
    runtime_dirs: Vec<PathBuf>,
}

/// Sweep `<data_dir>/sandboxes/*/state.json` and tear down every leftover,
/// plus snapshots a checkpoint never finished writing.
///
/// Runs once per manager construction, in the background. Ordering per
/// sandbox mirrors live teardown: kill Firecracker → wait for exit → dm
/// teardown → TAP release → chroot + directory removal.
pub(super) async fn sweep_orphans(
    config: &VmmConfig,
    network: &NetworkManager,
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
            return Ok(OrphanSweep {
                ids: HashSet::new(),
                runtime_dirs: Vec::new(),
            });
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

    // Firecracker pins dm devices, so every owned process must be dead before
    // the global CoW sweep can report meaningful cleanup failures.
    for (_, record) in &records {
        let mut pids = discover_firecracker_pids(config, record)?;
        if let Some(pid) = record.pid {
            pids.insert(pid);
        }
        for pid in pids {
            kill_orphaned_firecracker(pid).await?;
        }
    }
    // Durably Paused sandboxes keep their retained disk state (the detached
    // COW overlay or parked rootfs): Paused is committed only after
    // `release_for_pause` (or the resume unwind) released every runtime
    // resource, so a cleanup journal found next to it is a leftover of the
    // crash window between that commit and the journal clear — not evidence
    // of a torn release. Those journals are dropped as stale; every other
    // journaled sandbox is swept.
    let paused: HashSet<String> = store
        .load_all()?
        .into_iter()
        .filter(|record| record.phase == SandboxPhase::Paused)
        .map(|record| record.id)
        .collect();
    cow_manager.reconcile_stale(&paused)?;

    let mut swept = HashSet::new();
    let mut runtime_dirs = Vec::new();
    for (dir, mut record) in records {
        if paused.contains(&record.id) {
            info!(sandbox_id = %record.id, "dropping stale pause journal, keeping retained state");
            clear_state_record(&dir)?;
            continue;
        }
        info!(sandbox_id = %record.id, "reconciling orphaned sandbox");

        if let Some(cow) = record.cow.take() {
            cow_manager.teardown_checked(&cow.into_handle()).await?;
        }

        if let Some(alloc) = &record.network {
            network.quarantine_checked(&record.id, alloc)?;
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

        runtime_dirs.push(dir);
        swept.insert(record.id);
    }

    Ok(OrphanSweep {
        ids: swept,
        runtime_dirs,
    })
}

/// Deletes cleanup journals only after durable lifecycle normalization commits.
pub(super) async fn finalize_sweep(sweep: OrphanSweep) -> Result<()> {
    for dir in sweep.runtime_dirs {
        remove_dir_if_present(&dir).await?;
    }
    Ok(())
}

/// Normalizes durable records after orphan resources have been swept.
///
/// Interrupted live phases become inspectable failures; already inactive
/// sandboxes are reconstructed without runtime handles. A create intent stays
/// resumable, while an interrupted removal finishes as a durable tombstone.
pub(super) fn normalize_durable_records(
    store: &SandboxRecordStore,
    data_dir: &Path,
    swept: Option<&HashSet<String>>,
) -> Result<Vec<SandboxInstance>> {
    let mut inactive = Vec::new();

    for record in store.load_all()? {
        match record.phase {
            SandboxPhase::Creating => {}
            SandboxPhase::Starting | SandboxPhase::Ready | SandboxPhase::Stopping => {
                if swept.is_some_and(|ids| !ids.contains(&record.id)) {
                    return Err(crate::error::VmmError::Unavailable(format!(
                        "sandbox {} is {} but has no cleanup journal",
                        record.id,
                        record.phase.as_str()
                    )));
                }
                let record = store
                    .transition(
                        &record.id,
                        record.generation,
                        SandboxTransition::Failed(AGENT_RESTART_ERROR.into()),
                    )?
                    .confirmed("sandbox restart normalization")?;
                inactive.push(inactive_instance(record, SandboxState::Failed, data_dir));
            }
            // An interrupted pause/resume died between resource states; the
            // sweep already tore down whatever its journal listed (including
            // the disk overlay), so the sandbox is unrecoverable. Unlike the
            // live phases above, a missing journal is normal here — a resume
            // starts from a Paused record whose journal was already cleared
            // (after the Paused commit) and re-journals as it re-allocates.
            SandboxPhase::Pausing | SandboxPhase::Resuming => {
                let record = store
                    .transition(
                        &record.id,
                        record.generation,
                        SandboxTransition::Failed(AGENT_RESTART_ERROR.into()),
                    )?
                    .confirmed("sandbox restart normalization")?;
                inactive.push(inactive_instance(record, SandboxState::Failed, data_dir));
            }
            // Paused commits only after every runtime resource was released,
            // and the sweep preserves durably Paused retained state (clearing
            // any stale journal), so a paused sandbox always survives a
            // restart resumable.
            SandboxPhase::Paused => {
                inactive.push(inactive_instance(record, SandboxState::Paused, data_dir));
            }
            SandboxPhase::Stopped => {
                inactive.push(inactive_instance(record, SandboxState::Stopped, data_dir));
            }
            SandboxPhase::Failed => {
                inactive.push(inactive_instance(record, SandboxState::Failed, data_dir));
            }
            SandboxPhase::Removing => {
                store
                    .finish_remove(&record.id, record.generation)?
                    .confirmed("sandbox removal recovery")?;
            }
        }
    }

    Ok(inactive)
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

/// SIGKILL an orphaned Firecracker process and wait for it to disappear.
///
/// The PID may have been recycled since the record was written, so the
/// process is killed only when its command name still looks like
/// Firecracker (Linux `/proc/<pid>/comm`; on other targets the check
/// degrades to "process exists").
async fn kill_orphaned_firecracker(pid: i32) -> Result<()> {
    if !process_is_firecracker(pid) {
        return Ok(());
    }
    match nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    ) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(error) => {
            return Err(crate::error::VmmError::Process(format!(
                "kill orphaned firecracker {pid}: {error}"
            )));
        }
    }
    // The orphan was reparented to init, which reaps it; poll until the PID
    // vanishes so dm teardown doesn't hit EBUSY on the open block device.
    for _ in 0..50 {
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(crate::error::VmmError::Process(format!(
        "orphaned firecracker {pid} did not exit after SIGKILL"
    )))
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
        let octets = network.ip_address.octets();
        let expected = format!("vmtap{}-{}", octets[2], octets[3]);
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

/// True when `pid` is alive and (on Linux) named like a Firecracker binary.
fn process_is_firecracker(pid: i32) -> bool {
    if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            Ok(comm) => comm.trim_end().starts_with("firecracker"),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

#[cfg(target_os = "linux")]
fn discover_firecracker_pids(
    config: &VmmConfig,
    record: &SandboxStateRecord,
) -> Result<HashSet<i32>> {
    let mut matches = HashSet::new();
    let direct_socket = Path::new(&config.firecracker.data_dir)
        .join("sandboxes")
        .join(&record.id)
        .join("firecracker.sock");
    let jailer_root = config.firecracker.jailer.as_ref().map(|jailer| {
        let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
        arcbox_fc_driver::jail::chroot_root(
            &config.firecracker.binary,
            base,
            record.resource_owner(),
        )
    });

    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if !process_is_firecracker(pid) {
            continue;
        }
        let proc_dir = entry.path();
        let direct_match = std::fs::read(proc_dir.join("cmdline"))
            .ok()
            .is_some_and(|bytes| cmdline_matches(&bytes, &record.id, &direct_socket));
        let jailer_match = jailer_root.as_ref().is_some_and(|expected| {
            std::fs::read_link(proc_dir.join("root"))
                .ok()
                .is_some_and(|root| root == *expected)
        });
        if direct_match || jailer_match {
            matches.insert(pid);
        }
    }
    Ok(matches)
}

#[cfg(not(target_os = "linux"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Linux process discovery reads /proc and is fallible"
)]
fn discover_firecracker_pids(
    _config: &VmmConfig,
    _record: &SandboxStateRecord,
) -> Result<HashSet<i32>> {
    Ok(HashSet::new())
}

#[cfg(any(target_os = "linux", test))]
fn cmdline_matches(bytes: &[u8], id: &str, socket: &Path) -> bool {
    let args: Vec<_> = bytes
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    args.windows(2).any(|pair| {
        (pair[0] == b"--id" && pair[1] == id.as_bytes())
            || (pair[0] == b"--api-sock" && pair[1] == socket.as_os_str().as_encoded_bytes())
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::SandboxSpec;
    use super::super::persistence::{ProvisionIntent, SandboxProvisionOutcome};
    use super::*;

    fn record_in_phase(store: &SandboxRecordStore, id: &str, phase: SandboxPhase) -> SandboxRecord {
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
            SandboxPhase::Creating => return record,
            SandboxPhase::Failed => {
                store
                    .transition(
                        id,
                        generation,
                        SandboxTransition::Failed("original failure".into()),
                    )
                    .unwrap();
            }
            SandboxPhase::Removing => {
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
                    SandboxPhase::Starting => {}
                    SandboxPhase::Ready => {
                        store
                            .transition(id, generation, SandboxTransition::Ready)
                            .unwrap();
                    }
                    SandboxPhase::Stopping | SandboxPhase::Stopped => {
                        store
                            .transition(id, generation, SandboxTransition::Stopping)
                            .unwrap();
                        if phase == SandboxPhase::Stopped {
                            store
                                .transition(id, generation, SandboxTransition::Stopped)
                                .unwrap();
                        }
                    }
                    SandboxPhase::Pausing | SandboxPhase::Paused | SandboxPhase::Resuming => {
                        store
                            .transition(id, generation, SandboxTransition::Ready)
                            .unwrap();
                        store
                            .transition(id, generation, SandboxTransition::Pausing)
                            .unwrap();
                        if phase != SandboxPhase::Pausing {
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
                        if phase == SandboxPhase::Resuming {
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
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        let parsed: SandboxStateRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.id, "sb-1");
        assert_eq!(parsed.pid, Some(42));
        assert!(parsed.jailer);
        assert_eq!(parsed.pool_slot_id.as_deref(), Some("pool-1"));
        assert_eq!(parsed.resource_owner(), "pool-1");
        let handle = parsed.cow.unwrap().into_handle();
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
    fn dead_pid_is_not_firecracker() {
        // PID 0 targets "the calling process group" for kill(2); use an
        // implausibly high PID instead.
        assert!(!process_is_firecracker(i32::MAX - 1));
    }

    #[test]
    fn firecracker_command_line_matches_only_the_owned_id_or_socket() {
        let socket = Path::new("/var/lib/arcbox/sandbox/sandboxes/box/firecracker.sock");
        assert!(cmdline_matches(
            b"firecracker\0--api-sock\0/var/lib/arcbox/sandbox/sandboxes/box/firecracker.sock\0",
            "box",
            socket
        ));
        assert!(cmdline_matches(b"firecracker\0--id\0box\0", "box", socket));
        assert!(!cmdline_matches(
            b"firecracker\0--id\0other\0",
            "box",
            socket
        ));
    }

    #[test]
    fn startup_normalizes_crash_phases_and_restores_inactive_records() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        for (id, phase) in [
            ("creating", SandboxPhase::Creating),
            ("starting", SandboxPhase::Starting),
            ("ready", SandboxPhase::Ready),
            ("stopping", SandboxPhase::Stopping),
            ("stopped", SandboxPhase::Stopped),
            ("failed", SandboxPhase::Failed),
            ("removing", SandboxPhase::Removing),
        ] {
            record_in_phase(&store, id, phase);
        }

        let inactive = normalize_durable_records(&store, data_dir.path(), None).unwrap();
        let inactive: HashMap<_, _> = inactive
            .into_iter()
            .map(|instance| (instance.id.clone(), instance))
            .collect();

        assert_eq!(inactive.len(), 5);
        for id in ["starting", "ready", "stopping"] {
            let record = store.load(id).unwrap().unwrap();
            assert_eq!(record.phase, SandboxPhase::Failed);
            assert_eq!(record.error.as_deref(), Some(AGENT_RESTART_ERROR));

            let instance = &inactive[id];
            assert_eq!(instance.state, SandboxState::Failed);
            assert_eq!(instance.error.as_deref(), Some(AGENT_RESTART_ERROR));
            assert_eq!(instance.record_generation, Some(record.generation));
            assert!(instance.process.is_none());
            assert!(instance.vm.is_none());
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
            SandboxPhase::Creating
        );
        assert!(store.load("removing").unwrap().is_none());
        assert!(!inactive.contains_key("removing"));
    }

    #[test]
    fn paused_records_survive_restart_while_interrupted_transitions_fail() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        record_in_phase(&store, "clean", SandboxPhase::Paused);
        record_in_phase(&store, "mid-pause", SandboxPhase::Pausing);
        record_in_phase(&store, "mid-resume", SandboxPhase::Resuming);

        let inactive =
            normalize_durable_records(&store, data_dir.path(), Some(&HashSet::new())).unwrap();
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
            SandboxPhase::Paused
        );

        // An interrupted pause/resume never reached a durable Paused commit;
        // its resources were swept, so it degrades honestly.
        for id in ["mid-pause", "mid-resume"] {
            assert_eq!(inactive[id].state, SandboxState::Failed, "{id}");
            assert_eq!(
                store.load(id).unwrap().unwrap().phase,
                SandboxPhase::Failed,
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
        record_in_phase(&store, "napper", SandboxPhase::Paused);

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

    #[test]
    fn active_record_without_cleanup_journal_blocks_normalization() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        record_in_phase(&store, "starting", SandboxPhase::Starting);

        assert!(matches!(
            normalize_durable_records(&store, data_dir.path(), Some(&HashSet::new())),
            Err(crate::error::VmmError::Unavailable(_))
        ));
        assert_eq!(
            store.load("starting").unwrap().unwrap().phase,
            SandboxPhase::Starting
        );
    }
}
