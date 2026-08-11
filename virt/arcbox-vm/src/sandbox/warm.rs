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

use std::collections::HashSet;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::*;
use crate::snapshot::SnapshotCatalog;

/// Most distinct warm keys cached at once, mirroring the restore pool's
/// distinct-snapshot cap. Evicting a key deletes its snapshot (and drains
/// any pool slots staged from it).
const MAX_WARM_KEYS: usize = 2;

/// Reserved snapshot label carrying the warm key. The Checkpoint RPC rejects
/// caller-supplied labels with this name so no caller can plant a cache
/// entry that template creates would then restore from.
pub(super) const WARM_KEY_LABEL: &str = "arcbox.warm_key";

/// Identity of one warm-cacheable boot shape: hex SHA-256 over the resolved
/// boot recipe, the VM geometry, and the rootfs content fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WarmKey(String);

impl WarmKey {
    pub(super) fn hex(&self) -> &str {
        &self.0
    }
}

/// Content fingerprint of a boot input behind a resolved template path.
///
/// A memory snapshot is only valid against the exact rootfs and kernel
/// bytes it booted from, and both paths are reused across rebuilds (the
/// bundle installer overwrites the kernel in place on a version bump) —
/// the fingerprints invalidate the cache when content changes underneath a
/// path. The kernel case is the more dangerous one: the snapshot *is* the
/// old kernel's memory image, so a stale hit would silently keep
/// resurrecting the pre-bump kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileFingerprint {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    size: u64,
}

impl FileFingerprint {
    fn read(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            size: meta.size(),
        })
    }
}

/// Derive the warm key for an effective (defaults-applied) create spec,
/// fingerprinting the kernel and rootfs files on disk.
pub(super) fn derive_warm_key(spec: &SandboxSpec) -> std::io::Result<WarmKey> {
    let kernel = FileFingerprint::read(Path::new(&spec.kernel))?;
    let rootfs = FileFingerprint::read(Path::new(&spec.rootfs))?;
    Ok(derive(spec, kernel, rootfs))
}

fn derive(spec: &SandboxSpec, kernel: FileFingerprint, rootfs: FileFingerprint) -> WarmKey {
    let mut hasher = Sha256::new();
    // vcpus and memory are part of the key on purpose: a memory snapshot
    // restores only onto identical geometry.
    for text in [&spec.kernel, &spec.rootfs, &spec.boot_args] {
        hasher.update(text.as_bytes());
        hasher.update([0u8]);
    }
    for number in [u64::from(spec.vcpus), spec.memory_mib] {
        hasher.update(number.to_le_bytes());
    }
    // Field order fixes each fingerprint's position in the digest, so the
    // kernel and rootfs contributions cannot be confused for one another.
    for fingerprint in [kernel, rootfs] {
        for number in [fingerprint.dev, fingerprint.ino, fingerprint.size] {
            hasher.update(number.to_le_bytes());
        }
        for number in [fingerprint.mtime, fingerprint.mtime_nsec] {
            hasher.update(number.to_le_bytes());
        }
    }
    WarmKey(format!("{:x}", hasher.finalize()))
}

/// Whether an effective (defaults-applied) create spec may be served from —
/// and captured into — the warm cache.
///
/// `caller_supplied_boot` is captured before the defaults fill: a caller
/// pinning its own kernel or cmdline opted out of the template shape, and
/// anything doubtful cold-boots. Restore also requires jailer isolation and
/// a networked spec (the restore path re-addresses via `network_override`,
/// which net-invariant snapshots make free); an explicit `ip=` would bake a
/// caller-chosen identity into the snapshot, so it disqualifies too.
pub(super) fn warm_eligible(
    config: &VmmConfig,
    spec: &SandboxSpec,
    caller_supplied_boot: bool,
) -> bool {
    config.firecracker.warm_create
        && config.firecracker.jailer.is_some()
        && !caller_supplied_boot
        && spec.network.mode == "tap"
        && !spec.boot_args.contains("ip=")
        && spec.mounts.is_empty()
        && spec.ssh_public_key.is_none()
}

/// Reject caller-supplied labels that would collide with a reserved label:
/// the warm-cache key or the template-catalog ownership marker (CORE-107).
pub(super) fn reject_reserved_labels(labels: &HashMap<String, String>) -> Result<()> {
    if labels.contains_key(WARM_KEY_LABEL) {
        return Err(VmmError::Config(format!(
            "snapshot label {WARM_KEY_LABEL} is reserved for the warm-create cache"
        )));
    }
    if labels.contains_key(crate::template_catalog::TEMPLATE_LABEL) {
        return Err(VmmError::Config(format!(
            "snapshot label {} is reserved for the template catalog",
            crate::template_catalog::TEMPLATE_LABEL
        )));
    }
    Ok(())
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

/// In-memory cache bookkeeping: key recency for LRU eviction and the
/// per-key publish single-flight. The durable cache state is the catalog;
/// this only orders and serializes operations on it, so losing it on
/// restart costs nothing (untouched keys rank by snapshot age instead).
#[derive(Default)]
pub(super) struct WarmCache {
    inner: Mutex<WarmCacheInner>,
}

#[derive(Default)]
struct WarmCacheInner {
    /// Keys by last use (lookup hit or publish), least recent first.
    recency: Vec<String>,
    /// Keys with a publish in flight.
    publishing: HashSet<String>,
}

impl WarmCache {
    /// Record a use of `key`, making it the most recently used.
    pub(super) fn touch(&self, key: &WarmKey) {
        let mut inner = self.inner.lock().unwrap();
        inner.recency.retain(|entry| entry != key.hex());
        inner.recency.push(key.hex().to_owned());
    }

    /// Claim the single publish slot for `key`. `false` means another
    /// first-create is already checkpointing this key — skip, its result
    /// serves every later create.
    pub(super) fn begin_publish(&self, key: &WarmKey) -> bool {
        self.inner
            .lock()
            .unwrap()
            .publishing
            .insert(key.hex().to_owned())
    }

    /// Release the publish slot claimed by [`Self::begin_publish`].
    pub(super) fn end_publish(&self, key: &WarmKey) {
        self.inner.lock().unwrap().publishing.remove(key.hex());
    }

    /// Which keys to evict so at most [`MAX_WARM_KEYS`] remain, given every
    /// distinct key in the catalog with its newest snapshot's creation
    /// time. Keys never used in this process rank below every used key,
    /// oldest snapshot first.
    pub(super) fn plan_evictions(&self, catalog: &[(String, DateTime<Utc>)]) -> Vec<String> {
        let mut inner = self.inner.lock().unwrap();
        // Recency only matters for keys that still exist; pruning here also
        // keeps the list from accumulating deleted keys.
        inner
            .recency
            .retain(|entry| catalog.iter().any(|(key, _)| key == entry));
        let Some(excess) = catalog.len().checked_sub(MAX_WARM_KEYS).filter(|n| *n > 0) else {
            return Vec::new();
        };
        let mut ranked: Vec<&(String, DateTime<Utc>)> = catalog.iter().collect();
        // Ascending eviction priority: untouched keys first (oldest
        // snapshot first), then touched keys least recent first.
        ranked.sort_by_key(|(key, created_at)| {
            let recency = inner
                .recency
                .iter()
                .position(|entry| entry == key)
                .map_or(-1, |position| i64::try_from(position).unwrap_or(i64::MAX));
            (recency, *created_at)
        });
        ranked
            .into_iter()
            .take(excess)
            .map(|(key, _)| key.clone())
            .collect()
    }
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
/// Single-flighted per key, and every failure is a warn — cache population
/// must never fail a healthy boot. `expected_state` is what the boot tail
/// left the instance in: `Ready` for a cmd-less boot, `Starting` when the
/// tail is still holding the workload slot for the initial cmd.
pub(super) async fn publish_after_boot(
    sandbox_id: &SandboxId,
    ticket: &WarmPublishTicket,
    instances: &super::InstanceMap,
    config: &VmmConfig,
    cow_manager: &CowManager,
    expected_state: SandboxState,
) {
    if !ticket.cache.begin_publish(&ticket.key) {
        debug!(
            sandbox_id,
            "a warm snapshot publish for this key is already in flight"
        );
        return;
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
        }
        Ok(None) => {}
        Err(error) => {
            warn!(
                sandbox_id,
                %error,
                "warm snapshot publish failed; later creates keep cold-booting"
            );
        }
    }
}

/// Checkpoint into the catalog under the warm label, then enforce the cache
/// shape: one snapshot per key, at most [`MAX_WARM_KEYS`] distinct keys.
/// Returns `None` when the key was already cached by a concurrent create.
async fn publish_warm_snapshot(
    sandbox_id: &SandboxId,
    ticket: &WarmPublishTicket,
    instances: &super::InstanceMap,
    config: &VmmConfig,
    cow_manager: &CowManager,
    expected_state: SandboxState,
) -> Result<Option<String>> {
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
        config,
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
    use super::*;
    use crate::config::JailerConfig;
    use crate::snapshot::SnapshotDraft;

    fn kernel_fingerprint() -> FileFingerprint {
        FileFingerprint {
            dev: 5,
            ino: 7,
            mtime: 1_690_000_000,
            mtime_nsec: 456,
            size: 9 << 20,
        }
    }

    fn base_fingerprint() -> FileFingerprint {
        FileFingerprint {
            dev: 5,
            ino: 42,
            mtime: 1_700_000_000,
            mtime_nsec: 123,
            size: 64 << 20,
        }
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

    fn warm_config() -> VmmConfig {
        let mut config = VmmConfig::default();
        config.firecracker.jailer = Some(JailerConfig {
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
        config
    }

    #[test]
    fn key_is_stable_for_an_identical_shape() {
        assert_eq!(
            derive(&base_spec(), kernel_fingerprint(), base_fingerprint()),
            derive(&base_spec(), kernel_fingerprint(), base_fingerprint())
        );
    }

    type SpecEdit = Box<dyn Fn(&mut SandboxSpec)>;
    type FingerprintEdit = Box<dyn Fn(&mut FileFingerprint)>;

    #[test]
    fn key_tracks_every_boot_recipe_and_geometry_field() {
        let base = derive(&base_spec(), kernel_fingerprint(), base_fingerprint());
        let variants: Vec<SpecEdit> = vec![
            Box::new(|s| s.kernel = "/run/kernel/vmlinux-new".into()),
            Box::new(|s| s.rootfs = "/data/rootfs-other.ext4".into()),
            Box::new(|s| s.boot_args.push_str(" debug")),
            Box::new(|s| s.vcpus = 4),
            Box::new(|s| s.memory_mib = 1024),
        ];
        for mutate in variants {
            let mut spec = base_spec();
            mutate(&mut spec);
            assert_ne!(
                derive(&spec, kernel_fingerprint(), base_fingerprint()),
                base,
                "{spec:?}"
            );
        }
        // Fields outside the boot shape must NOT change the key: labels,
        // cmd, ttl are per-sandbox, not per-template.
        let mut spec = base_spec();
        spec.labels.insert("team".into(), "x".into());
        spec.cmd = vec!["sleep".into()];
        spec.ttl_seconds = 60;
        assert_eq!(
            derive(&spec, kernel_fingerprint(), base_fingerprint()),
            base
        );
    }

    #[test]
    fn key_tracks_every_fingerprint_field_of_both_files() {
        let base = derive(&base_spec(), kernel_fingerprint(), base_fingerprint());
        let variants: Vec<FingerprintEdit> = vec![
            Box::new(|f| f.dev += 1),
            Box::new(|f| f.ino += 1),
            Box::new(|f| f.mtime += 1),
            Box::new(|f| f.mtime_nsec += 1),
            Box::new(|f| f.size += 1),
        ];
        for mutate in &variants {
            let mut fingerprint = base_fingerprint();
            mutate(&mut fingerprint);
            assert_ne!(
                derive(&base_spec(), kernel_fingerprint(), fingerprint),
                base,
                "rootfs {fingerprint:?}"
            );
        }
        for mutate in &variants {
            let mut fingerprint = kernel_fingerprint();
            mutate(&mut fingerprint);
            assert_ne!(
                derive(&base_spec(), fingerprint, base_fingerprint()),
                base,
                "kernel {fingerprint:?}"
            );
        }
        // Swapping the two fingerprints must not collide: their positions
        // in the digest are what tells them apart.
        assert_ne!(
            derive(&base_spec(), base_fingerprint(), kernel_fingerprint()),
            base
        );
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

    #[test]
    fn eligibility_requires_the_template_shape() {
        let config = warm_config();
        assert!(warm_eligible(&config, &base_spec(), false));

        // A caller-pinned boot recipe opts out even when the effective spec
        // looks like the defaults.
        assert!(!warm_eligible(&config, &base_spec(), true));

        let mut no_warm = warm_config();
        no_warm.firecracker.warm_create = false;
        assert!(!warm_eligible(&no_warm, &base_spec(), false));

        // Restore needs jailer isolation; direct mode must never checkpoint
        // a snapshot it cannot restore.
        assert!(!warm_eligible(&VmmConfig::default(), &base_spec(), false));

        let mut no_net = base_spec();
        no_net.network.mode = "none".into();
        assert!(!warm_eligible(&config, &no_net, false));

        let mut explicit_ip = base_spec();
        explicit_ip.boot_args.push_str(" ip=10.0.0.9::10.0.0.1");
        assert!(!warm_eligible(&config, &explicit_ip, false));

        let mut mounted = base_spec();
        mounted.mounts.push(SandboxMountSpec {
            source: "/src".into(),
            target: "/dst".into(),
            readonly: true,
        });
        assert!(!warm_eligible(&config, &mounted, false));

        let mut ssh = base_spec();
        ssh.ssh_public_key = Some("ssh-ed25519 AAAA".into());
        assert!(!warm_eligible(&config, &ssh, false));
    }

    #[test]
    fn reserved_label_is_rejected() {
        assert!(reject_reserved_labels(&HashMap::new()).is_ok());
        let mut labels = HashMap::new();
        labels.insert("env".to_owned(), "prod".to_owned());
        assert!(reject_reserved_labels(&labels).is_ok());
        labels.insert(WARM_KEY_LABEL.to_owned(), "deadbeef".to_owned());
        assert!(reject_reserved_labels(&labels).is_err());

        let mut labels = HashMap::new();
        labels.insert(
            crate::template_catalog::TEMPLATE_LABEL.to_owned(),
            "code".to_owned(),
        );
        assert!(reject_reserved_labels(&labels).is_err());
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
            })
            .unwrap()
            .id
    }

    #[test]
    fn publish_is_single_flighted_per_key() {
        let cache = WarmCache::default();
        let key_a = WarmKey("aa".into());
        let key_b = WarmKey("bb".into());

        assert!(cache.begin_publish(&key_a));
        assert!(!cache.begin_publish(&key_a), "second publisher must skip");
        assert!(cache.begin_publish(&key_b), "keys single-flight separately");
        cache.end_publish(&key_a);
        assert!(cache.begin_publish(&key_a), "slot frees on end_publish");
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    #[test]
    fn evictions_keep_the_cap_and_respect_recency() {
        let cache = WarmCache::default();
        let catalog = vec![
            ("a".to_owned(), at(100)),
            ("b".to_owned(), at(200)),
            ("c".to_owned(), at(300)),
        ];

        // Within the cap: nothing to evict.
        assert!(cache.plan_evictions(&catalog[..2]).is_empty());

        // No recency recorded: the oldest snapshot goes.
        assert_eq!(cache.plan_evictions(&catalog), vec!["a".to_owned()]);

        // Touching the oldest protects it; the untouched oldest goes.
        cache.touch(&WarmKey("a".into()));
        assert_eq!(cache.plan_evictions(&catalog), vec!["b".to_owned()]);

        // Touched keys outrank untouched ones, least recently used first.
        cache.touch(&WarmKey("b".into()));
        cache.touch(&WarmKey("c".into()));
        assert_eq!(cache.plan_evictions(&catalog), vec!["a".to_owned()]);
    }

    #[test]
    fn evictions_ignore_recency_of_deleted_keys() {
        let cache = WarmCache::default();
        cache.touch(&WarmKey("gone".into()));
        let catalog = vec![
            ("a".to_owned(), at(100)),
            ("b".to_owned(), at(200)),
            ("c".to_owned(), at(300)),
        ];
        // "gone" is not in the catalog, so it neither protects anything nor
        // shows up as a victim.
        assert_eq!(cache.plan_evictions(&catalog), vec!["a".to_owned()]);
    }

    #[test]
    fn lookup_matches_the_label_and_prefers_the_newest() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let key = WarmKey("aa11".into());

        assert_eq!(find_warm_snapshot(&catalog, &key).unwrap(), None);
        publish_labeled(&catalog, "box-1", None);
        publish_labeled(&catalog, "box-1", Some("other-key"));
        assert_eq!(find_warm_snapshot(&catalog, &key).unwrap(), None);

        let older = publish_labeled(&catalog, "box-1", Some("aa11"));
        let newer = publish_labeled(&catalog, "box-2", Some("aa11"));
        let found = find_warm_snapshot(&catalog, &key).unwrap().unwrap();
        assert_eq!(found, newer);
        assert_ne!(found, older);
    }
}
