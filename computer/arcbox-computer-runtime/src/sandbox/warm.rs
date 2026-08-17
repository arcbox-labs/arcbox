//! Warm template snapshots (CORE-77).
//!
//! `CreateSandbox` restores from a cached snapshot when one exists for the
//! effective boot shape, instead of cold-booting a kernel. The cache IS the
//! [`SnapshotCatalog`]: a warm snapshot is an ordinary snapshot carrying the
//! reserved [`WARM_KEY_LABEL`], whose value is a hash of everything a memory
//! snapshot bakes in — the resolved kernel/rootfs paths, the kernel cmdline,
//! the VM geometry, and a content fingerprint of the rootfs file (the default
//! template rebuilds in place via temp+rename, so dev/inode/mtime/size change
//! whenever the content does; `docker:` templates are content-addressed
//! already, but the fingerprint is uniform and cheap).
//!
//! Lookup scans the catalog for the label; a miss cold-boots and publishes
//! the snapshot from the freshly Ready guest (see `publish_after_boot`).

use std::path::Path;

use super::*;
use crate::snapshot::SnapshotCatalog;

/// The policy half — what a warm key is made of, which specs may use the
/// cache, and which keys to evict — lives in [`super::policy::warm`];
/// re-exported so callers keep naming one `warm::WarmCache`.
pub(super) use super::policy::warm::{WarmCache, WarmKey, reject_reserved_labels, warm_eligible};

use super::policy::warm::{FileFingerprint, WARM_KEY_LABEL, warm_key};

/// Fingerprint the boot input at `path`: the stat half of the warm key,
/// and the only place it touches a filesystem.
fn fingerprint(path: &Path) -> std::io::Result<FileFingerprint> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok(FileFingerprint {
        dev: meta.dev(),
        ino: meta.ino(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        size: meta.size(),
    })
}

/// Derive the warm key for an effective (defaults-applied) create spec,
/// fingerprinting the kernel and rootfs files on disk.
pub(super) fn derive_warm_key(spec: &SandboxSpec) -> std::io::Result<WarmKey> {
    Ok(warm_key(
        spec,
        fingerprint(Path::new(&spec.kernel))?,
        fingerprint(Path::new(&spec.rootfs))?,
    ))
}

/// One published warm snapshot: catalog id, key, and creation time.
pub(super) struct WarmEntry {
    pub(super) snapshot_id: String,
    pub(super) key: String,
    pub(super) created_at: DateTime<Utc>,
}

/// Every warm snapshot currently in the catalog.
pub(super) fn warm_entries(catalog: &SnapshotCatalog) -> Result<Vec<WarmEntry>> {
    Ok(catalog
        .list_all()?
        .into_iter()
        .filter_map(|snapshot| {
            snapshot.labels.get(WARM_KEY_LABEL).map(|key| WarmEntry {
                snapshot_id: snapshot.id,
                key: key.clone(),
                created_at: snapshot.created_at,
            })
        })
        .collect())
}

/// Find the cached snapshot for `key`, newest first.
///
/// Publish keeps at most one snapshot per key; preferring the newest makes
/// the crash window between publishing a replacement and deleting its
/// predecessor harmless.
pub(super) fn find_warm_snapshot(
    catalog: &SnapshotCatalog,
    key: &WarmKey,
) -> Result<Option<String>> {
    Ok(warm_entries(catalog)?
        .into_iter()
        .filter(|entry| entry.key == key.hex())
        .max_by_key(|entry| entry.created_at)
        .map(|entry| entry.snapshot_id))
}

/// Everything the boot task needs to publish a warm snapshot once its
/// sandbox reaches Ready (CORE-77).
pub(super) struct WarmPublishTicket {
    pub(super) key: WarmKey,
    pub(super) cache: Arc<WarmCache>,
    pub(super) snapshots: Arc<SnapshotCatalog>,
    pub(super) pool: Arc<super::pool::SlotPool>,
}

/// Publish the warm snapshot for a freshly booted, still-idle sandbox.
///
/// Single-flighted per key, and a failed publish is a warn — cache
/// population must never fail a healthy boot. The one exception is a
/// checkpoint that left the guest frozen
/// ([`CheckpointFailure::Frozen`](super::checkpoint::CheckpointFailure)):
/// that sandbox is not healthy, and the error comes back so the boot fails
/// instead of announcing READY for a guest that never runs again.
/// `expected_state` is what the boot tail left the instance in: `Ready` for
/// a cmd-less boot, `Starting` when the tail is still holding the workload
/// slot for the initial cmd.
pub(super) async fn publish_after_boot(
    sandbox_id: &SandboxId,
    ticket: &WarmPublishTicket,
    instances: &super::InstanceMap,
    config: &VmmConfig,
    cow_manager: &CowManager,
    expected_state: SandboxState,
) -> Result<()> {
    if !ticket.cache.begin_publish(&ticket.key) {
        debug!(
            sandbox_id,
            "a warm snapshot publish for this key is already in flight"
        );
        return Ok(());
    }
    let started = std::time::Instant::now();
    let published = publish_warm_snapshot(
        sandbox_id,
        ticket,
        instances,
        config,
        cow_manager,
        expected_state,
    )
    .await;
    ticket.cache.end_publish(&ticket.key);
    match published {
        Ok(Some(snapshot_id)) => {
            let checkpoint_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            info!(
                sandbox_id,
                snapshot_id, checkpoint_ms, "warm template snapshot published"
            );
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(PublishFailure::Frozen(error)) => Err(error),
        Err(PublishFailure::Recoverable(error)) => {
            warn!(
                sandbox_id,
                %error,
                "warm snapshot publish failed; later creates keep cold-booting"
            );
            Ok(())
        }
    }
}

/// How a warm publish failed: the sandbox is either as usable as it was, or
/// its guest is frozen and the boot must fail (see
/// [`CheckpointFailure`](super::checkpoint::CheckpointFailure)).
enum PublishFailure {
    Recoverable(VmmError),
    Frozen(VmmError),
}

impl From<VmmError> for PublishFailure {
    fn from(error: VmmError) -> Self {
        Self::Recoverable(error)
    }
}

impl From<super::checkpoint::CheckpointFailure> for PublishFailure {
    fn from(failure: super::checkpoint::CheckpointFailure) -> Self {
        use super::checkpoint::CheckpointFailure;
        match failure {
            CheckpointFailure::Recoverable(error) => Self::Recoverable(error),
            CheckpointFailure::Frozen(error) => Self::Frozen(error),
        }
    }
}

/// Checkpoint into the catalog under the warm label, then enforce the cache
/// shape: one snapshot per key, at most `MAX_WARM_KEYS` distinct keys
/// (see [`super::policy::warm`]).
/// Returns `None` when the key was already cached by a concurrent create.
async fn publish_warm_snapshot(
    sandbox_id: &SandboxId,
    ticket: &WarmPublishTicket,
    instances: &super::InstanceMap,
    config: &VmmConfig,
    cow_manager: &CowManager,
    expected_state: SandboxState,
) -> std::result::Result<Option<String>, PublishFailure> {
    // A concurrent first-create may have published while this guest booted.
    if warm_entries(&ticket.snapshots)?
        .iter()
        .any(|entry| entry.key == ticket.key.hex())
    {
        return Ok(None);
    }

    let name = format!("warm-{}", &ticket.key.hex()[..12]);
    let labels = HashMap::from([(WARM_KEY_LABEL.to_owned(), ticket.key.hex().to_owned())]);
    let info = super::checkpoint::checkpoint_impl(
        instances,
        &ticket.snapshots,
        sandbox_id,
        super::checkpoint::CheckpointRequest {
            name,
            labels,
            expected_state,
            resume_after: true,
        },
    )
    .await?;
    ticket.cache.touch(&ticket.key);

    // Everything superseded is deleted, draining its pre-warmed pool slots
    // first (mirrors delete_checkpoint): older snapshots of this key — a
    // crash-window leftover — and every snapshot of an evicted key.
    let entries = warm_entries(&ticket.snapshots)?;
    let mut newest: HashMap<String, DateTime<Utc>> = HashMap::new();
    for entry in &entries {
        newest
            .entry(entry.key.clone())
            .and_modify(|at| *at = (*at).max(entry.created_at))
            .or_insert(entry.created_at);
    }
    let keys: Vec<(String, DateTime<Utc>)> = newest.into_iter().collect();
    let evicted = ticket.cache.plan_evictions(&keys);
    for entry in entries {
        let replaced = entry.key == ticket.key.hex() && entry.snapshot_id != info.snapshot_id;
        if replaced || evicted.contains(&entry.key) {
            super::pool::drain_pool_slots(
                &ticket.pool,
                config,
                cow_manager,
                Some(&entry.snapshot_id),
            )
            .await;
            if let Err(error) = ticket.snapshots.delete_by_id(&entry.snapshot_id) {
                warn!(
                    snapshot_id = %entry.snapshot_id,
                    %error,
                    "failed to delete a superseded warm snapshot"
                );
            }
        }
    }
    Ok(Some(info.snapshot_id))
}

#[cfg(test)]
mod tests {
    use super::super::testing::{
        FrozenOnCheckpoint, fake_manager, live_sandbox, live_sandbox_with,
    };
    use super::*;
    use crate::snapshot::SnapshotDraft;

    /// A stat-shaped fingerprint; every test here only needs *some* key.
    fn fingerprint_of(ino: u64) -> FileFingerprint {
        FileFingerprint {
            dev: 5,
            ino,
            mtime: 1_700_000_000,
            mtime_nsec: 123,
            size: 64 << 20,
        }
    }

    fn some_key() -> WarmKey {
        warm_key(&base_spec(), fingerprint_of(7), fingerprint_of(42))
    }

    /// The warm publish is best-effort — a failed capture that left the
    /// guest running is a warning and the boot goes on — except when the
    /// capture left the guest frozen: that comes back as the error the boot
    /// task fails the sandbox on, instead of announcing READY for it.
    #[tokio::test]
    async fn publish_after_boot_surfaces_only_a_frozen_guest() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, driver, _probe) = fake_manager(dir.path()).await;
        let ticket = |suffix: &str| WarmPublishTicket {
            key: some_key(),
            cache: Arc::new(WarmCache::default()),
            snapshots: Arc::new(SnapshotCatalog::new(
                dir.path().join(suffix).to_string_lossy().as_ref(),
            )),
            pool: Arc::new(super::super::pool::SlotPool::default()),
        };

        // The fake's capture succeeds and the guest runs on; only the commit
        // fails (no vmstate/mem pair): recoverable, so the boot proceeds.
        let (instance, _handle) = live_sandbox(&manager, &driver, "warm-ok").await;
        publish_after_boot(
            &"warm-ok".to_owned(),
            &ticket("a"),
            &manager.instances,
            &manager.config,
            &manager.cow_manager,
            SandboxState::Ready,
        )
        .await
        .expect("a recoverable publish failure is not the boot's problem");
        assert_eq!(instance.lock().unwrap().state, SandboxState::Ready);

        // The guest stayed frozen: the boot task must fail the sandbox.
        let (instance, _handle) =
            live_sandbox_with(&manager, &driver, "warm-frozen", FrozenOnCheckpoint::over).await;
        let error = publish_after_boot(
            &"warm-frozen".to_owned(),
            &ticket("b"),
            &manager.instances,
            &manager.config,
            &manager.cow_manager,
            SandboxState::Ready,
        )
        .await
        .expect_err("a frozen guest fails the boot");
        assert!(
            error.to_string().contains("could not be resumed"),
            "{error}"
        );
        // The publish itself only reports; the boot task does the failing.
        assert_eq!(instance.lock().unwrap().state, SandboxState::Ready);
    }

    fn base_spec() -> SandboxSpec {
        SandboxSpec {
            kernel: "/run/kernel/vmlinux".into(),
            rootfs: "/data/rootfs.ext4".into(),
            boot_args: "console=ttyS0 quiet".into(),
            vcpus: 2,
            memory_mib: 512,
            network: SandboxNetworkSpec { mode: "tap".into() },
            ..Default::default()
        }
    }

    #[test]
    fn rebuilding_a_boot_input_in_place_changes_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&kernel, b"kernel v1").unwrap();
        std::fs::write(&rootfs, b"template v1").unwrap();
        let mut spec = base_spec();
        spec.kernel = kernel.to_str().unwrap().to_owned();
        spec.rootfs = rootfs.to_str().unwrap().to_owned();

        let first = derive_warm_key(&spec).unwrap();
        assert_eq!(derive_warm_key(&spec).unwrap(), first, "stat is stable");

        // The rebuild discipline for both inputs: write a sibling, then
        // rename over the fixed path — same path, new inode. The kernel
        // case is exactly what a bundle version bump does to
        // runtime/kernel/vmlinux.
        let staging = dir.path().join(".rootfs.tmp");
        std::fs::write(&staging, b"template v2").unwrap();
        std::fs::rename(&staging, &rootfs).unwrap();
        let second = derive_warm_key(&spec).unwrap();
        assert_ne!(second, first);

        let staging = dir.path().join(".vmlinux.tmp");
        std::fs::write(&staging, b"kernel v2").unwrap();
        std::fs::rename(&staging, &kernel).unwrap();
        assert_ne!(derive_warm_key(&spec).unwrap(), second);
    }

    fn publish_labeled(catalog: &SnapshotCatalog, vm_id: &str, key: Option<&str>) -> String {
        let pending = catalog.begin(vm_id).unwrap();
        std::fs::write(pending.dir().join("vmstate"), b"vmstate").unwrap();
        let labels = key
            .map(|key| HashMap::from([(WARM_KEY_LABEL.to_owned(), key.to_owned())]))
            .unwrap_or_default();
        pending
            .commit(SnapshotDraft {
                name: None,
                labels,
                snapshot_type: crate::config::SnapshotType::Full,
                parent_id: None,
                kernel_path: None,
                rootfs_path: None,
                net_invariant: true,
                geometry: None,
                format: super::checkpoint::CHECKPOINT_FORMAT.to_owned(),
            })
            .unwrap()
            .id
    }

    #[test]
    fn lookup_matches_the_label_and_prefers_the_newest() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let key = some_key();
        let hex = key.hex().to_owned();

        assert_eq!(find_warm_snapshot(&catalog, &key).unwrap(), None);
        publish_labeled(&catalog, "box-1", None);
        publish_labeled(&catalog, "box-1", Some("other-key"));
        assert_eq!(find_warm_snapshot(&catalog, &key).unwrap(), None);

        let older = publish_labeled(&catalog, "box-1", Some(&hex));
        let newer = publish_labeled(&catalog, "box-2", Some(&hex));
        let found = find_warm_snapshot(&catalog, &key).unwrap().unwrap();
        assert_eq!(found, newer);
        assert_ne!(found, older);
    }
}
