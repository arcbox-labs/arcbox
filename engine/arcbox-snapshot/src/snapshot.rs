use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::{Result, SnapshotError};

/// Snapshot type — mirrors Firecracker terminology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotType {
    /// Capture full memory + VM state.
    Full,
    /// Capture only dirty pages since the last snapshot.
    Diff,
}

/// VM geometry a memory snapshot was captured with.
///
/// A Firecracker memory snapshot restores only onto identical
/// vcpus/memory, so anything that restores a snapshot onto a caller-shaped
/// VM (template promotion, CORE-107) needs the capture-time geometry.
/// Absent on metas written before this field existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotGeometry {
    pub vcpus: u32,
    pub memory_mib: u64,
}

/// Metadata stored alongside each snapshot on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Unique snapshot identifier.
    pub id: String,
    /// VM identifier this snapshot belongs to.
    pub vm_id: String,
    /// Optional human-readable label.
    pub name: Option<String>,
    /// Arbitrary key-value metadata, used for filtering in ListSnapshots.
    ///
    /// `serde(default)` so snapshots catalogued before labels existed still
    /// load (they read back as unlabelled).
    #[serde(default)]
    pub labels: HashMap<String, String>,
    pub snapshot_type: SnapshotType,
    /// Absolute path to the `vmstate` file.
    pub vmstate_path: PathBuf,
    /// Absolute path to the memory file (full snapshots only).
    pub mem_path: Option<PathBuf>,
    /// When the snapshot was created.
    pub created_at: DateTime<Utc>,
    /// Parent snapshot ID (diff chain).
    pub parent_id: Option<String>,
    /// Host-absolute kernel path (required for jailer-mode restore staging).
    #[serde(default)]
    pub kernel_path: Option<String>,
    /// Host-absolute rootfs path (required for jailer-mode restore staging).
    #[serde(default)]
    pub rootfs_path: Option<String>,
    /// Whether the origin guest ran the fixed invariant network identity
    /// (CORE-81): eth0 on the constant link-local address with the constant
    /// gateway, external identity applied host-side per TAP. A restore of such
    /// a snapshot needs zero guest-side network work. `serde(default)` so
    /// legacy snapshots read back `false` and keep the reconfig-RPC path.
    #[serde(default)]
    pub net_invariant: bool,
    /// Capture-time VM geometry. `serde(default)` so legacy metas read back
    /// `None` (consumers that need it reject with an actionable error).
    #[serde(default)]
    pub geometry: Option<SnapshotGeometry>,
}

/// Info returned to callers / gRPC layer.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub id: String,
    pub vm_id: String,
    pub name: Option<String>,
    /// Arbitrary key-value metadata recorded at checkpoint time.
    pub labels: HashMap<String, String>,
    pub snapshot_type: SnapshotType,
    pub vmstate_path: PathBuf,
    pub mem_path: Option<PathBuf>,
    pub created_at: DateTime<Utc>,
}

impl From<&SnapshotMeta> for SnapshotInfo {
    fn from(m: &SnapshotMeta) -> Self {
        Self {
            id: m.id.clone(),
            vm_id: m.vm_id.clone(),
            name: m.name.clone(),
            labels: m.labels.clone(),
            snapshot_type: m.snapshot_type,
            vmstate_path: m.vmstate_path.clone(),
            mem_path: m.mem_path.clone(),
            created_at: m.created_at,
        }
    }
}

/// Name of the VM-state file inside a snapshot directory.
const VMSTATE_FILE: &str = "vmstate";

/// Name of the memory file inside a snapshot directory.
const MEM_FILE: &str = "mem";

/// Suffix marking a staging directory, i.e. a snapshot still being written.
///
/// The leading dot keeps it out of the catalog's `{snapshot_id}` namespace:
/// snapshot IDs are UUIDs, so no published entry can collide with one.
const STAGING_SUFFIX: &str = ".partial";

fn secure_dir(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(SnapshotError::from)
}

fn sync_private_file(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(SnapshotError::from)?;
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(SnapshotError::from)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(SnapshotError::from)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(SnapshotError::from)?;
    file.write_all(bytes).map_err(SnapshotError::from)?;
    file.sync_all().map_err(SnapshotError::from)
}

fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(SnapshotError::from)
}

/// True when `path` is a published snapshot directory.
///
/// Staging directories are named `.{snapshot_id}.partial` and are not catalog
/// members until [`PendingSnapshot::commit`] renames them.
fn is_catalog_entry(path: &Path) -> bool {
    path.is_dir()
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| !name.starts_with('.'))
}

/// What a caller knows about a snapshot before it is published.
///
/// The file layout (`vmstate`, `mem`) is the catalog's business, so it is not
/// part of this: [`PendingSnapshot::commit`] fills those paths in.
#[derive(Debug)]
pub struct SnapshotDraft {
    /// Optional human-readable label.
    pub name: Option<String>,
    /// Arbitrary key-value metadata carried onto the snapshot.
    pub labels: HashMap<String, String>,
    pub snapshot_type: SnapshotType,
    /// Parent snapshot ID (diff chain).
    pub parent_id: Option<String>,
    /// Host-absolute kernel path (required for jailer-mode restore staging).
    pub kernel_path: Option<String>,
    /// Host-absolute rootfs path (required for restore to rebuild the
    /// dm-snapshot origin).
    pub rootfs_path: Option<String>,
    /// Whether the origin guest ran the invariant network identity (CORE-81).
    pub net_invariant: bool,
    /// Capture-time VM geometry, when the producer knows it.
    pub geometry: Option<SnapshotGeometry>,
}

/// A snapshot being written, not yet part of the catalog.
///
/// Firecracker writes into [`Self::dir`], a staging directory that is
/// deliberately outside the catalog's namespace, and [`Self::commit`] writes
/// `meta.json` there and renames the whole directory into place. That single
/// atomic publish is what lets every reader assume a catalogued directory has
/// a readable record: a snapshot is either complete or not there at all.
///
/// Dropping without committing removes the staging directory, so a failed
/// checkpoint leaves neither a record-less entry nor a partial `vmstate`/`mem`
/// behind. A crash leaves the staging directory, which
/// [`SnapshotCatalog::sweep_incomplete`] reclaims on the next start.
pub struct PendingSnapshot<'a> {
    catalog: &'a SnapshotCatalog,
    vm_id: String,
    id: String,
    published: bool,
}

impl PendingSnapshot<'_> {
    /// Identifier the snapshot will carry once published.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Staging directory to write `vmstate` and `mem` into.
    pub fn dir(&self) -> PathBuf {
        self.catalog.staging_dir(&self.vm_id, &self.id)
    }

    /// Publish the snapshot: write the record, then rename it into the catalog.
    ///
    /// The `mem` file is recorded when the staging directory actually holds one
    /// (diff snapshots and jailer moves may not produce it).
    pub fn commit(mut self, draft: SnapshotDraft) -> Result<SnapshotMeta> {
        let staging = self.dir();
        let published = self.catalog.snapshot_dir(&self.vm_id, &self.id);
        let has_mem = staging.join(MEM_FILE).exists();

        let meta = SnapshotMeta {
            id: self.id.clone(),
            vm_id: self.vm_id.clone(),
            name: draft.name,
            labels: draft.labels,
            snapshot_type: draft.snapshot_type,
            vmstate_path: published.join(VMSTATE_FILE),
            mem_path: has_mem.then(|| published.join(MEM_FILE)),
            created_at: Utc::now(),
            parent_id: draft.parent_id,
            kernel_path: draft.kernel_path,
            rootfs_path: draft.rootfs_path,
            net_invariant: draft.net_invariant,
            geometry: draft.geometry,
        };

        sync_private_file(&staging.join(VMSTATE_FILE))?;
        if has_mem {
            sync_private_file(&staging.join(MEM_FILE))?;
        }
        let json = serde_json::to_vec_pretty(&meta)?;
        write_private_file(&SnapshotCatalog::meta_path(&staging), &json)?;
        secure_dir(&staging)?;
        sync_dir(&staging)?;
        std::fs::rename(&staging, &published).map_err(SnapshotError::from)?;
        self.published = true;
        let owner = published.parent().expect("snapshot directory has an owner");
        sync_dir(owner).map_err(|error| {
            SnapshotError::Unavailable(format!(
                "snapshot {} is visible, but publish durability is unconfirmed: {error}",
                meta.id
            ))
        })?;

        info!(snapshot_id = %meta.id, vm_id = %meta.vm_id, "snapshot registered");
        Ok(meta)
    }
}

impl Drop for PendingSnapshot<'_> {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let dir = self.dir();
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                info!(snapshot_id = %self.id, vm_id = %self.vm_id, "discarded incomplete snapshot");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(path = %dir.display(), error = %e, "failed to discard incomplete snapshot");
            }
        }
    }
}

/// Manages the on-disk snapshot catalog for all VMs.
///
/// Layout:
/// ```text
/// {data_dir}/snapshots/{vm_id}/{snapshot_id}/
///     vmstate
///     mem          (full only)
///     meta.json
/// {data_dir}/snapshots/{vm_id}/.{snapshot_id}.partial/   (being written)
/// ```
///
/// Every catalogued directory carries a readable `meta.json`, because a
/// snapshot is written into a `.partial` staging directory and renamed in as a
/// whole (see [`PendingSnapshot`]). Readers therefore treat a missing or
/// unparseable record as corruption rather than as a normal lifecycle state.
pub struct SnapshotCatalog {
    root: PathBuf,
}

impl SnapshotCatalog {
    /// Create a new catalog rooted at `{data_dir}/snapshots`.
    pub fn new(data_dir: &str) -> Self {
        Self {
            root: PathBuf::from(data_dir).join("snapshots"),
        }
    }

    /// Start a new snapshot for `vm_id`.
    ///
    /// Creates the staging directory; the snapshot enters the catalog only on
    /// [`PendingSnapshot::commit`].
    pub fn begin(&self, vm_id: &str) -> Result<PendingSnapshot<'_>> {
        let pending = PendingSnapshot {
            catalog: self,
            vm_id: vm_id.to_owned(),
            id: Uuid::new_v4().to_string(),
            published: false,
        };
        std::fs::create_dir_all(pending.dir()).map_err(SnapshotError::from)?;
        secure_dir(&self.root)?;
        secure_dir(&self.vm_dir(vm_id))?;
        secure_dir(&pending.dir())?;
        sync_dir(&self.vm_dir(vm_id))?;
        sync_dir(&self.root)?;
        if let Some(data_dir) = self.root.parent() {
            sync_dir(data_dir)?;
        }
        Ok(pending)
    }

    /// List all snapshots for a VM, sorted by creation time (oldest first).
    pub fn list(&self, vm_id: &str) -> Result<Vec<SnapshotInfo>> {
        let dir = self.vm_dir(vm_id);
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut entries: Vec<SnapshotMeta> = std::fs::read_dir(&dir)
            .map_err(SnapshotError::from)?
            .filter_map(|e| e.ok())
            .filter(|e| is_catalog_entry(&e.path()))
            .map(|e| self.read_meta(&e.path()))
            .collect::<Result<_>>()?;
        entries.sort_by_key(|m| m.created_at);
        Ok(entries.iter().map(SnapshotInfo::from).collect())
    }

    /// Look up a single snapshot by ID.
    pub fn get(&self, vm_id: &str, snapshot_id: &str) -> Result<SnapshotMeta> {
        let path = self.snapshot_dir(vm_id, snapshot_id);
        self.read_meta(&path)
    }

    /// Delete a snapshot directory from disk.
    pub fn delete(&self, vm_id: &str, snapshot_id: &str) -> Result<()> {
        let path = self.snapshot_dir(vm_id, snapshot_id);
        if !path.exists() {
            return Err(SnapshotError::Snapshot(format!(
                "snapshot {snapshot_id} not found for VM {vm_id}"
            )));
        }
        std::fs::remove_dir_all(&path).map_err(SnapshotError::from)?;
        sync_dir(&self.vm_dir(vm_id))?;
        info!(snapshot_id, vm_id, "snapshot deleted");
        Ok(())
    }

    /// Remove staging directories left behind by a crash mid-checkpoint.
    ///
    /// A committed snapshot is renamed into place atomically, so anything still
    /// staged when the process died is unfinished by definition — and can be
    /// holding a full memory dump.
    pub fn sweep_incomplete(&self) {
        let Ok(vms) = std::fs::read_dir(&self.root) else {
            return;
        };
        for vm in vms.flatten() {
            let Ok(entries) = std::fs::read_dir(vm.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let staged = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name.starts_with('.') && name.ends_with(STAGING_SUFFIX));
                if staged && path.is_dir() {
                    match std::fs::remove_dir_all(&path) {
                        Ok(()) => info!(path = %path.display(), "removed incomplete snapshot"),
                        Err(e) => {
                            warn!(path = %path.display(), error = %e, "failed to remove incomplete snapshot");
                        }
                    }
                }
            }
        }
    }

    /// Find a snapshot by ID alone, searching across all owner directories.
    pub fn find_by_id(&self, snapshot_id: &str) -> Result<SnapshotMeta> {
        if !self.root.exists() {
            return Err(SnapshotError::Snapshot(format!(
                "snapshot {snapshot_id} not found"
            )));
        }
        for entry in std::fs::read_dir(&self.root).map_err(SnapshotError::from)? {
            let entry = entry.map_err(SnapshotError::from)?;
            if entry.path().is_dir() {
                let snap_path = entry.path().join(snapshot_id);
                if is_catalog_entry(&snap_path) {
                    return self.read_meta(&snap_path);
                }
            }
        }
        Err(SnapshotError::Snapshot(format!(
            "snapshot {snapshot_id} not found"
        )))
    }

    /// List all snapshots across every owner directory, sorted by creation time.
    pub fn list_all(&self) -> Result<Vec<SnapshotInfo>> {
        if !self.root.exists() {
            return Ok(vec![]);
        }
        let mut all: Vec<SnapshotInfo> = vec![];
        for entry in std::fs::read_dir(&self.root).map_err(SnapshotError::from)? {
            let entry = entry.map_err(SnapshotError::from)?;
            if entry.path().is_dir() {
                let owner_id = entry.file_name().to_string_lossy().into_owned();
                let mut infos = self.list(&owner_id)?;
                all.append(&mut infos);
            }
        }
        all.sort_by_key(|s| s.created_at);
        Ok(all)
    }

    /// Rootfs images that catalogued snapshots depend on.
    ///
    /// Restore rebuilds the dm-snapshot origin from
    /// [`SnapshotMeta::rootfs_path`], and the guest memory in the snapshot was
    /// captured against those exact bytes — re-converting the same image with a
    /// different `vm-agent` produces a different file and is not a substitute.
    /// Anything that garbage-collects rootfs images must treat these as pinned.
    pub fn referenced_rootfs_paths(&self) -> Result<BTreeSet<PathBuf>> {
        if !self.root.exists() {
            return Ok(BTreeSet::new());
        }
        let mut pinned = BTreeSet::new();
        for vm in std::fs::read_dir(&self.root).map_err(SnapshotError::from)? {
            let vm_dir = vm.map_err(SnapshotError::from)?.path();
            if !vm_dir.is_dir() {
                continue;
            }
            for snapshot in std::fs::read_dir(&vm_dir).map_err(SnapshotError::from)? {
                let snapshot_dir = snapshot.map_err(SnapshotError::from)?.path();
                if !is_catalog_entry(&snapshot_dir) {
                    continue;
                }
                // Strict by design: a catalogued directory always carries a
                // readable record (see [`PendingSnapshot`]), so a failure here
                // is real corruption — and treating unknown references as "none"
                // is what would delete an image a restore still needs.
                if let Some(rootfs) = self.read_meta(&snapshot_dir)?.rootfs_path {
                    pinned.insert(PathBuf::from(rootfs));
                }
            }
        }
        Ok(pinned)
    }

    /// Delete a snapshot knowing only its ID (searches across all owner directories).
    pub fn delete_by_id(&self, snapshot_id: &str) -> Result<()> {
        let meta = self.find_by_id(snapshot_id)?;
        self.delete(&meta.vm_id, snapshot_id)
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    fn vm_dir(&self, vm_id: &str) -> PathBuf {
        self.root.join(vm_id)
    }

    fn snapshot_dir(&self, vm_id: &str, snapshot_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join(snapshot_id)
    }

    fn staging_dir(&self, vm_id: &str, snapshot_id: &str) -> PathBuf {
        self.vm_dir(vm_id)
            .join(format!(".{snapshot_id}{STAGING_SUFFIX}"))
    }

    fn meta_path(dir: &Path) -> PathBuf {
        dir.join("meta.json")
    }

    fn read_meta(&self, dir: &Path) -> Result<SnapshotMeta> {
        let json = std::fs::read_to_string(Self::meta_path(dir)).map_err(SnapshotError::from)?;
        let meta = serde_json::from_str(&json)?;
        Ok(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Publish a snapshot the way a producer does: stage, write a `vmstate`,
    /// then commit.
    fn publish(catalog: &SnapshotCatalog, vm_id: &str, draft: SnapshotDraft) -> SnapshotMeta {
        let pending = catalog.begin(vm_id).unwrap();
        std::fs::write(pending.dir().join(VMSTATE_FILE), b"vmstate").unwrap();
        pending.commit(draft).unwrap()
    }

    fn draft() -> SnapshotDraft {
        SnapshotDraft {
            labels: HashMap::new(),
            name: None,
            snapshot_type: SnapshotType::Full,
            parent_id: None,
            kernel_path: None,
            rootfs_path: None,
            net_invariant: false,
            geometry: None,
        }
    }

    fn register_one(catalog: &SnapshotCatalog, vm_id: &str) -> SnapshotMeta {
        publish(catalog, vm_id, draft())
    }

    #[test]
    fn commit_publishes_atomically_and_records_catalog_paths() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());

        let pending = catalog.begin("vm-1").unwrap();
        let staging = pending.dir();
        let id = pending.id().to_owned();
        std::fs::write(staging.join(VMSTATE_FILE), b"vmstate").unwrap();
        std::fs::write(staging.join(MEM_FILE), b"mem").unwrap();
        // Nothing is catalogued while the snapshot is still being written.
        assert!(catalog.list("vm-1").unwrap().is_empty());

        let meta = pending.commit(draft()).unwrap();

        assert!(!staging.exists());
        let published = catalog.snapshot_dir("vm-1", &id);
        assert_eq!(meta.vmstate_path, published.join(VMSTATE_FILE));
        assert_eq!(meta.mem_path, Some(published.join(MEM_FILE)));
        assert_eq!(catalog.list("vm-1").unwrap().len(), 1);
        assert_eq!(
            std::fs::metadata(&published).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in [VMSTATE_FILE, MEM_FILE, "meta.json"] {
            assert_eq!(
                std::fs::metadata(published.join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn commit_records_no_mem_when_the_snapshot_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let meta = register_one(&catalog, "vm-1");
        assert_eq!(meta.mem_path, None);
    }

    #[test]
    fn labels_survive_the_catalog_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());

        let pending = catalog.begin("vm-1").unwrap();
        std::fs::write(pending.dir().join(VMSTATE_FILE), b"vmstate").unwrap();
        let labels = HashMap::from([("env".to_owned(), "prod".to_owned())]);
        pending
            .commit(SnapshotDraft {
                labels: labels.clone(),
                ..draft()
            })
            .unwrap();

        // Read back through the catalog (i.e. off disk), not from the meta
        // the commit returned — labels are only useful if they persist.
        let listed = catalog.list("vm-1").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].labels, labels);
    }

    #[test]
    fn snapshots_catalogued_before_labels_existed_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let snap_dir = catalog.snapshot_dir("vm-1", "old-snap");
        std::fs::create_dir_all(&snap_dir).unwrap();
        // A meta.json written before the labels field existed.
        std::fs::write(
            SnapshotCatalog::meta_path(&snap_dir),
            r#"{"id":"old-snap","vm_id":"vm-1","name":null,"snapshot_type":"Full",
                "vmstate_path":"/tmp/vmstate","mem_path":null,
                "created_at":"2026-01-01T00:00:00Z","parent_id":null,
                "kernel_path":null,"rootfs_path":null}"#,
        )
        .unwrap();

        let listed = catalog.list("vm-1").unwrap();
        assert_eq!(listed.len(), 1, "pre-labels snapshot must still load");
        assert!(listed[0].labels.is_empty());
        // Field absent on disk → legacy addressing → the reconfig-RPC restore
        // path must stay selected.
        assert!(!catalog.get("vm-1", "old-snap").unwrap().net_invariant);
    }

    #[test]
    fn net_invariant_survives_the_catalog_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let meta = publish(
            &catalog,
            "vm-1",
            SnapshotDraft {
                net_invariant: true,
                ..draft()
            },
        );
        assert!(catalog.get("vm-1", &meta.id).unwrap().net_invariant);
    }

    #[test]
    fn dropping_without_commit_leaves_no_trace() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());

        let staging = {
            let pending = catalog.begin("vm-1").unwrap();
            let staging = pending.dir();
            // A failed checkpoint can leave a partial memory dump behind.
            std::fs::write(staging.join(MEM_FILE), b"partial").unwrap();
            staging
        };

        assert!(!staging.exists());
        assert!(catalog.list("vm-1").unwrap().is_empty());
        // No record-less directory to trip readers up.
        assert!(catalog.referenced_rootfs_paths().unwrap().is_empty());
    }

    #[test]
    fn sweep_incomplete_reclaims_staging_left_by_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let kept = register_one(&catalog, "vm-1");

        // Simulate a process death between `begin` and `commit`: the staging
        // directory survives because `Drop` never ran.
        let orphan = catalog.staging_dir("vm-1", "22222222-dead-beef");
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join(MEM_FILE), b"partial").unwrap();

        catalog.sweep_incomplete();

        assert!(!orphan.exists());
        assert!(catalog.get("vm-1", &kept.id).is_ok());
    }

    #[test]
    fn referenced_rootfs_paths_spans_every_vm_and_skips_snapshots_without_one() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        assert!(catalog.referenced_rootfs_paths().unwrap().is_empty());

        let with_rootfs = |vm_id: &str, rootfs: Option<String>| {
            publish(
                &catalog,
                vm_id,
                SnapshotDraft {
                    rootfs_path: rootfs,
                    ..draft()
                },
            )
        };
        with_rootfs("vm-1", Some("/var/lib/arcbox/sandbox/rootfs-a.ext4".into()));
        with_rootfs("vm-2", Some("/var/lib/arcbox/sandbox/rootfs-b.ext4".into()));
        with_rootfs("vm-2", None);

        assert_eq!(
            catalog.referenced_rootfs_paths().unwrap(),
            BTreeSet::from([
                PathBuf::from("/var/lib/arcbox/sandbox/rootfs-a.ext4"),
                PathBuf::from("/var/lib/arcbox/sandbox/rootfs-b.ext4"),
            ])
        );
    }

    #[test]
    fn referenced_rootfs_paths_fails_on_an_unreadable_record() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let meta = register_one(&catalog, "vm-1");
        std::fs::write(
            SnapshotCatalog::meta_path(&catalog.snapshot_dir("vm-1", &meta.id)),
            "{ truncated",
        )
        .unwrap();
        // Guessing "no references" here would delete an image a restore needs.
        assert!(catalog.referenced_rootfs_paths().is_err());
    }

    #[test]
    fn test_list_empty() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        assert!(catalog.list("vm-1").unwrap().is_empty());
        assert!(catalog.list_all().unwrap().is_empty());
    }

    #[test]
    fn test_register_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let meta = register_one(&catalog, "vm-1");
        let snapshots = catalog.list("vm-1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].id, meta.id);
        assert_eq!(snapshots[0].vm_id, "vm-1");
    }

    #[test]
    fn test_register_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let meta = publish(
            &catalog,
            "vm-2",
            SnapshotDraft {
                name: Some("my-snap".into()),
                snapshot_type: SnapshotType::Diff,
                ..draft()
            },
        );
        let loaded = catalog.get("vm-2", &meta.id).unwrap();
        assert_eq!(loaded.id, meta.id);
        assert_eq!(loaded.snapshot_type, SnapshotType::Diff);
        assert_eq!(loaded.name.as_deref(), Some("my-snap"));
    }

    #[test]
    fn test_delete_removes_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let meta = register_one(&catalog, "vm-1");
        catalog.delete("vm-1", &meta.id).unwrap();
        assert!(catalog.list("vm-1").unwrap().is_empty());
    }

    #[test]
    fn test_find_by_id_across_vms() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let meta = register_one(&catalog, "vm-42");
        let found = catalog.find_by_id(&meta.id).unwrap();
        assert_eq!(found.vm_id, "vm-42");
    }

    #[test]
    fn test_list_all_across_multiple_vms() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        register_one(&catalog, "vm-a");
        register_one(&catalog, "vm-a");
        register_one(&catalog, "vm-b");
        let all = catalog.list_all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_delete_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let meta = register_one(&catalog, "vm-1");
        catalog.delete_by_id(&meta.id).unwrap();
        assert!(catalog.list_all().unwrap().is_empty());
    }
}
