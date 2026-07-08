//! Crash-recovery reconciliation for sandbox runtime state.
//!
//! `SandboxManager` state is in-memory; if the agent restarts (crash,
//! supervision respawn) the Firecracker processes, TAP devices, dm-snapshot
//! devices, and jailer chroots of running sandboxes leak, and fresh IP
//! allocations can collide with orphaned TAPs. To recover, every successful
//! boot/restore persists a small `state.json` next to the sandbox's runtime
//! files, and a new manager sweeps those records: orphaned Firecracker
//! processes are killed and every held resource is torn down. Sandboxes are
//! ephemeral by design, so reconciliation destroys rather than re-adopts.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::VmmConfig;
use crate::network::{NetworkAllocation, NetworkManager};
use crate::snapshot_cow::{CowHandle, CowManager};

/// File name of the per-sandbox crash-recovery record.
const STATE_FILE: &str = "state.json";

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
        }
    }
}

/// Persist the crash-recovery record into the sandbox's runtime directory.
///
/// Best-effort: a failed write only degrades crash recovery, never a boot.
pub(super) fn write_state_record(vm_dir: &Path, record: &SandboxStateRecord) {
    let path = vm_dir.join(STATE_FILE);
    match serde_json::to_vec_pretty(record) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                warn!(sandbox_id = %record.id, error = %e, "failed to persist sandbox state");
            }
        }
        Err(e) => warn!(sandbox_id = %record.id, error = %e, "failed to encode sandbox state"),
    }
}

/// Remove the crash-recovery record (resources have been released).
pub(super) fn clear_state_record(vm_dir: &Path) {
    let _ = std::fs::remove_file(vm_dir.join(STATE_FILE));
}

/// Sweep `<data_dir>/sandboxes/*/state.json` and tear down every leftover.
///
/// Runs once per manager construction, in the background. Ordering per
/// sandbox mirrors live teardown: kill Firecracker → wait for exit → dm
/// teardown → TAP release → chroot + directory removal.
pub(super) async fn sweep_orphans(
    config: &VmmConfig,
    network: &NetworkManager,
    cow_manager: &CowManager,
) {
    let sandboxes_dir = PathBuf::from(&config.firecracker.data_dir).join("sandboxes");
    let Ok(entries) = std::fs::read_dir(&sandboxes_dir) else {
        return;
    };

    for entry in entries.flatten() {
        let dir = entry.path();
        let state_path = dir.join(STATE_FILE);
        let record: SandboxStateRecord = match std::fs::read(&state_path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    warn!(path = %state_path.display(), error = %e, "unreadable sandbox record");
                    continue;
                }
            },
            // No record: either never booted or cleanly stopped.
            Err(_) => continue,
        };

        info!(sandbox_id = %record.id, "reconciling orphaned sandbox");

        if let Some(pid) = record.pid {
            kill_orphaned_firecracker(pid).await;
        }

        if let Some(cow) = record.cow {
            cow_manager.teardown(&cow.into_handle()).await;
        }

        if let Some(alloc) = &record.network {
            network.release(alloc);
        }

        if record.jailer
            && let Some(ref jc) = config.firecracker.jailer
        {
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let chroot = super::boot::chroot_root(&config.firecracker.binary, base, &record.id);
            if let Some(parent) = chroot.parent() {
                let _ = tokio::fs::remove_dir_all(parent).await;
            }
        }

        if let Some(origin) = &record.restore_origin_dir {
            let _ = tokio::fs::remove_dir_all(origin).await;
        }

        if let Err(e) = tokio::fs::remove_dir_all(&dir).await {
            warn!(sandbox_id = %record.id, error = %e, "failed to remove orphaned sandbox dir");
        }
    }
}

/// SIGKILL an orphaned Firecracker process and wait for it to disappear.
///
/// The PID may have been recycled since the record was written, so the
/// process is killed only when its command name still looks like
/// Firecracker (Linux `/proc/<pid>/comm`; on other targets the check
/// degrades to "process exists").
async fn kill_orphaned_firecracker(pid: i32) {
    if !process_is_firecracker(pid) {
        return;
    }
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    );
    // The orphan was reparented to init, which reaps it; poll until the PID
    // vanishes so dm teardown doesn't hit EBUSY on the open block device.
    for _ in 0..50 {
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    warn!(pid, "orphaned firecracker did not exit after SIGKILL");
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

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        let parsed: SandboxStateRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.id, "sb-1");
        assert_eq!(parsed.pid, Some(42));
        assert!(parsed.jailer);
        let handle = parsed.cow.unwrap().into_handle();
        assert_eq!(handle.dm_name, "arcbox-snap-sb-1");
    }

    #[test]
    fn dead_pid_is_not_firecracker() {
        // PID 0 targets "the calling process group" for kill(2); use an
        // implausibly high PID instead.
        assert!(!process_is_firecracker(i32::MAX - 1));
    }
}
