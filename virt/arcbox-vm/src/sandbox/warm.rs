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

use sha2::{Digest, Sha256};

use super::*;
use crate::snapshot::SnapshotCatalog;

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

/// Content fingerprint of the rootfs file behind a resolved template path.
///
/// A memory snapshot is only valid against the exact rootfs bytes it booted
/// from, and template paths are reused across rebuilds — the fingerprint is
/// what invalidates the cache when the content changes underneath the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RootfsFingerprint {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    size: u64,
}

impl RootfsFingerprint {
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
/// fingerprinting the rootfs file on disk.
pub(super) fn derive_warm_key(spec: &SandboxSpec) -> std::io::Result<WarmKey> {
    let fingerprint = RootfsFingerprint::read(Path::new(&spec.rootfs))?;
    Ok(derive(spec, fingerprint))
}

fn derive(spec: &SandboxSpec, fingerprint: RootfsFingerprint) -> WarmKey {
    let mut hasher = Sha256::new();
    // vcpus and memory are part of the key on purpose: a memory snapshot
    // restores only onto identical geometry.
    for text in [&spec.kernel, &spec.rootfs, &spec.boot_args] {
        hasher.update(text.as_bytes());
        hasher.update([0u8]);
    }
    for number in [
        u64::from(spec.vcpus),
        spec.memory_mib,
        fingerprint.dev,
        fingerprint.ino,
        fingerprint.size,
    ] {
        hasher.update(number.to_le_bytes());
    }
    for number in [fingerprint.mtime, fingerprint.mtime_nsec] {
        hasher.update(number.to_le_bytes());
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

/// Reject caller-supplied labels that would collide with the reserved
/// warm-cache label.
pub(super) fn reject_reserved_labels(labels: &HashMap<String, String>) -> Result<()> {
    if labels.contains_key(WARM_KEY_LABEL) {
        return Err(VmmError::Config(format!(
            "snapshot label {WARM_KEY_LABEL} is reserved for the warm-create cache"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JailerConfig;
    use crate::snapshot::SnapshotDraft;

    fn base_fingerprint() -> RootfsFingerprint {
        RootfsFingerprint {
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
            derive(&base_spec(), base_fingerprint()),
            derive(&base_spec(), base_fingerprint())
        );
    }

    type SpecEdit = Box<dyn Fn(&mut SandboxSpec)>;
    type FingerprintEdit = Box<dyn Fn(&mut RootfsFingerprint)>;

    #[test]
    fn key_tracks_every_boot_recipe_and_geometry_field() {
        let base = derive(&base_spec(), base_fingerprint());
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
            assert_ne!(derive(&spec, base_fingerprint()), base, "{spec:?}");
        }
        // Fields outside the boot shape must NOT change the key: labels,
        // cmd, ttl are per-sandbox, not per-template.
        let mut spec = base_spec();
        spec.labels.insert("team".into(), "x".into());
        spec.cmd = vec!["sleep".into()];
        spec.ttl_seconds = 60;
        assert_eq!(derive(&spec, base_fingerprint()), base);
    }

    #[test]
    fn key_tracks_every_fingerprint_field() {
        let base = derive(&base_spec(), base_fingerprint());
        let variants: Vec<FingerprintEdit> = vec![
            Box::new(|f| f.dev += 1),
            Box::new(|f| f.ino += 1),
            Box::new(|f| f.mtime += 1),
            Box::new(|f| f.mtime_nsec += 1),
            Box::new(|f| f.size += 1),
        ];
        for mutate in variants {
            let mut fingerprint = base_fingerprint();
            mutate(&mut fingerprint);
            assert_ne!(derive(&base_spec(), fingerprint), base, "{fingerprint:?}");
        }
    }

    #[test]
    fn rebuilding_the_rootfs_in_place_changes_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"template v1").unwrap();
        let mut spec = base_spec();
        spec.rootfs = rootfs.to_str().unwrap().to_owned();

        let first = derive_warm_key(&spec).unwrap();
        assert_eq!(derive_warm_key(&spec).unwrap(), first, "stat is stable");

        // The template builder's rebuild discipline: write a sibling, then
        // rename over the fixed path — same path, new inode.
        let staging = dir.path().join(".rootfs.tmp");
        std::fs::write(&staging, b"template v2").unwrap();
        std::fs::rename(&staging, &rootfs).unwrap();
        assert_ne!(derive_warm_key(&spec).unwrap(), first);
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
            })
            .unwrap()
            .id
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
