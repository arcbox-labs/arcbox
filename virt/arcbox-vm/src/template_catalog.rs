//! On-disk template catalog (CORE-107).
//!
//! A template is a named, versioned sandbox base: a built rootfs plus a
//! default-config bundle, optionally paired with a pre-warmed boot-to-ready
//! snapshot (`template.proto`). The catalog persists metadata only — one
//! atomically-replaced JSON file per template name under
//! `{data_dir}/template-catalog/` — while the artifacts live elsewhere and
//! are referenced, never copied: rootfs images in the converted-rootfs cache
//! (pinned through [`TemplateCatalog::rootfs_paths`]) and warm snapshots in
//! the [`SnapshotCatalog`](crate::snapshot::SnapshotCatalog) under the
//! [`TEMPLATE_LABEL`] reserved label.
//!
//! Versioning model: `Build` installs the mutable draft slot; `Publish`
//! freezes the draft as an immutable version (newest published wins bare-name
//! resolution). Version strings are caller-chosen and opaque — "newest" means
//! publish order, never a semver comparison.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::{Result, VmmError};
use crate::sandbox::atomic_write;

/// Directory under the vmm data dir holding one JSON file per template name.
const CATALOG_DIR: &str = "template-catalog";

/// Maximum length of a template name or version string.
const MAX_COMPONENT_LEN: usize = 64;

/// Reserved snapshot label marking a snapshot as owned by a catalog template.
///
/// The value is the owning template name. The checkpoint surface keeps user
/// checkpoints from squatting on it and template artifacts out of user-facing
/// snapshot lists; deleting such a snapshot goes through template deletion.
pub const TEMPLATE_LABEL: &str = "arcbox.template";

/// Readiness probe recorded in template defaults.
///
/// The native mirror of `ReadyProbe` (`template.proto`): how to decide a
/// sandbox created from the template is ready for use. Enforcement gates the
/// READY transition; expiry marks the sandbox FAILED.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadyProbeSpec {
    /// Ready when something inside the sandbox listens on this TCP port.
    Port {
        port: u16,
        /// Seconds before giving up (0 = daemon default).
        timeout_seconds: u32,
    },
    /// Ready when this command, run inside the sandbox, exits 0.
    Command {
        cmd: Vec<String>,
        /// Seconds before giving up (0 = daemon default).
        timeout_seconds: u32,
    },
}

/// Default configuration a template applies to sandboxes created from it.
///
/// The native mirror of `TemplateDefaults` (`template.proto`). Zero `vcpus` /
/// `memory_mib` mean "no template default" (the daemon default applies); the
/// per-create override rules live on `CreateSandboxRequest`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateDefaultsSpec {
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub memory_mib: u64,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Advisory: ports the workload is expected to listen on, so clients can
    /// expose them without knowing the workload. Never acted on at create.
    #[serde(default)]
    pub exposed_ports: Vec<u32>,
    #[serde(default)]
    pub ready_probe: Option<ReadyProbeSpec>,
}

/// A pre-warmed boot-to-ready snapshot plus the geometry it requires.
///
/// A memory snapshot restores only onto identical vcpus/memory, so geometry
/// is part of the artifact — create gates template-restore on an exact match
/// and cold-boots otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmArtifact {
    /// Snapshot id in the snapshot catalog (carries [`TEMPLATE_LABEL`]).
    pub snapshot_id: String,
    pub vcpus: u32,
    pub memory_mib: u64,
}

/// One built template version, or the unpublished draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateEntry {
    /// Published version string; empty in the draft slot.
    #[serde(default)]
    pub version: String,
    /// Content digest pinning this entry's artifacts (`sha256:<hex>`),
    /// computed at build time over source identity + rootfs fingerprint +
    /// warm snapshot + defaults + labels.
    pub digest: String,
    /// Guest-absolute path of the built rootfs image in the rootfs cache.
    pub rootfs_path: String,
    /// Pre-warmed snapshot, when the template carries one.
    #[serde(default)]
    pub warm: Option<WarmArtifact>,
    #[serde(default)]
    pub defaults: TemplateDefaultsSpec,
    /// Arbitrary key-value metadata (filterable in List).
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// When this entry was built (draft) or its content built (versions keep
    /// the build time, not the publish time).
    pub created_at: DateTime<Utc>,
    /// On-disk footprint of the artifacts (rootfs + warm snapshot).
    #[serde(default)]
    pub size_bytes: u64,
}

/// Durable record for one template name: the current draft plus every
/// published version in publish order (newest last).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TemplateRecord {
    name: String,
    #[serde(default)]
    draft: Option<TemplateEntry>,
    #[serde(default)]
    versions: Vec<TemplateEntry>,
}

impl TemplateRecord {
    fn entries(&self) -> impl Iterator<Item = &TemplateEntry> {
        self.versions.iter().chain(self.draft.as_ref())
    }

    fn is_empty(&self) -> bool {
        self.draft.is_none() && self.versions.is_empty()
    }
}

/// A `name[:version]` reference resolved against the catalog.
#[derive(Debug, Clone)]
pub struct ResolvedTemplate {
    /// Template name (no version suffix).
    pub name: String,
    /// The resolved entry: the exact version, or — for a bare name — the
    /// newest published version, falling back to the draft when nothing is
    /// published.
    pub entry: TemplateEntry,
}

impl ResolvedTemplate {
    /// Canonical pinned reference: `name:version@digest` (`name:@digest` for
    /// drafts). Substituted into `CreateSandboxRequest.template` before the
    /// idempotent create key is computed, so a retried create after a Publish
    /// diverges instead of silently replaying the old content.
    #[must_use]
    pub fn canonical_ref(&self) -> String {
        format!("{}:{}@{}", self.name, self.entry.version, self.entry.digest)
    }
}

/// Result of installing a draft: the stored entry plus any artifacts the
/// displaced previous draft owned exclusively.
#[derive(Debug)]
pub struct PutDraftOutcome {
    /// The entry as stored (version forced empty).
    pub entry: TemplateEntry,
    pub released: ReleasedArtifacts,
}

/// Result of publishing: the frozen version plus any released artifacts.
///
/// An idempotent re-publish can collapse a rebuilt same-digest draft whose
/// warm snapshot the published version never shared; that snapshot comes
/// back here for the caller to reclaim.
#[derive(Debug)]
pub struct PublishOutcome {
    /// The published entry.
    pub entry: TemplateEntry,
    pub released: ReleasedArtifacts,
}

/// Snapshot ids released by a catalog mutation.
///
/// Owned by removed entries and referenced by no remaining entry anywhere in
/// the catalog. The caller (`SandboxManager`) deletes them from the snapshot
/// catalog — the catalog itself never touches artifacts.
#[derive(Debug, Default)]
pub struct ReleasedArtifacts {
    pub snapshot_ids: Vec<String>,
}

/// The on-disk template catalog: one atomically-replaced JSON per name.
pub struct TemplateCatalog {
    root: PathBuf,
    /// Serializes read-modify-write cycles within this process. Cross-process
    /// safety is not a goal: one agent owns the data dir.
    lock: Mutex<()>,
}

impl TemplateCatalog {
    /// Create a catalog rooted under `data_dir`. The directory is created
    /// lazily on first write; a missing directory reads as an empty catalog.
    #[must_use]
    pub fn new(data_dir: &str) -> Self {
        Self {
            root: Path::new(data_dir).join(CATALOG_DIR),
            lock: Mutex::new(()),
        }
    }

    /// Install `entry` as the draft for `name`, displacing any previous
    /// draft. The stored entry's `version` is forced empty.
    pub fn put_draft(&self, name: &str, mut entry: TemplateEntry) -> Result<PutDraftOutcome> {
        validate_template_name(name)?;
        let _guard = self.lock.lock().unwrap();
        let mut record = self.read_record(name)?.unwrap_or_else(|| TemplateRecord {
            name: name.to_string(),
            draft: None,
            versions: Vec::new(),
        });
        entry.version = String::new();
        let displaced = record.draft.replace(entry.clone());
        self.write_record(&record)?;
        let released = self.released_after_commit(displaced.as_slice());
        Ok(PutDraftOutcome { entry, released })
    }

    /// Freeze the current draft as immutable `version`.
    ///
    /// Idempotent against retries: re-publishing an existing version succeeds
    /// when there is no draft (the earlier attempt committed) or when the
    /// draft's digest matches the published content — releasing that draft's
    /// exclusively-owned artifacts; a digest clash is
    /// [`VmmError::TemplateVersionExists`] (the divergent draft survives for
    /// publishing under a new version, and a later `put_draft` releases it).
    pub fn publish(&self, name: &str, version: &str) -> Result<PublishOutcome> {
        validate_template_name(name)?;
        validate_template_version(version)?;
        let _guard = self.lock.lock().unwrap();
        let mut record = self
            .read_record(name)?
            .ok_or_else(|| VmmError::TemplateNotFound(name.to_string()))?;
        if let Some(existing) = record.versions.iter().find(|e| e.version == version) {
            let existing = existing.clone();
            return match record.draft.as_ref() {
                None => Ok(PublishOutcome {
                    entry: existing,
                    released: ReleasedArtifacts::default(),
                }),
                Some(draft) if draft.digest == existing.digest => {
                    let displaced = record.draft.take();
                    self.write_record(&record)?;
                    // Refcount after the write so the scan observes the
                    // record without the draft, or the snapshot still looks
                    // referenced and is never released.
                    let released = self.released_after_commit(displaced.as_slice());
                    Ok(PublishOutcome {
                        entry: existing,
                        released,
                    })
                }
                Some(_) => Err(VmmError::TemplateVersionExists(format!(
                    "{name}:{version} is already published with different content"
                ))),
            };
        }
        let mut entry = record.draft.take().ok_or_else(|| {
            VmmError::FailedPrecondition(format!(
                "template {name} has no draft to publish; run Build first"
            ))
        })?;
        entry.version = version.to_string();
        record.versions.push(entry.clone());
        self.write_record(&record)?;
        Ok(PublishOutcome {
            entry,
            released: ReleasedArtifacts::default(),
        })
    }

    /// Resolve a `name` or `name:version` reference.
    pub fn resolve(&self, reference: &str) -> Result<ResolvedTemplate> {
        let (name, version) = parse_reference(reference)?;
        let record = self
            .read_record(name)?
            .ok_or_else(|| VmmError::TemplateNotFound(reference.to_string()))?;
        let entry = match version {
            Some(v) => record.versions.iter().find(|e| e.version == v).cloned(),
            None => record
                .versions
                .last()
                .cloned()
                .or_else(|| record.draft.clone()),
        }
        .ok_or_else(|| VmmError::TemplateNotFound(reference.to_string()))?;
        Ok(ResolvedTemplate {
            name: record.name,
            entry,
        })
    }

    /// Every catalog row: per name (lexical order), published versions in
    /// publish order, then the draft.
    pub fn list(&self) -> Result<Vec<(String, TemplateEntry)>> {
        let _guard = self.lock.lock().unwrap();
        let mut rows = Vec::new();
        for record in self.read_all()? {
            for entry in record.entries() {
                rows.push((record.name.clone(), entry.clone()));
            }
        }
        Ok(rows)
    }

    /// Delete a template version (`name:version`) or a whole template with
    /// all its versions and its draft (`name`).
    pub fn delete(&self, reference: &str) -> Result<ReleasedArtifacts> {
        let (name, version) = parse_reference(reference)?;
        let _guard = self.lock.lock().unwrap();
        let mut record = self
            .read_record(name)?
            .ok_or_else(|| VmmError::TemplateNotFound(reference.to_string()))?;
        let removed: Vec<TemplateEntry> = match version {
            None => {
                let mut entries: Vec<_> = record.versions.drain(..).collect();
                entries.extend(record.draft.take());
                self.remove_record(name)?;
                entries
            }
            Some(v) => {
                let index = record
                    .versions
                    .iter()
                    .position(|e| e.version == v)
                    .ok_or_else(|| VmmError::TemplateNotFound(reference.to_string()))?;
                let entry = record.versions.remove(index);
                self.write_record(&record)?;
                vec![entry]
            }
        };
        Ok(self.released_after_commit(&removed))
    }

    /// True when any catalog entry references `snapshot_id` as its warm
    /// artifact. The checkpoint surface's deletion guard keys on this so an
    /// orphaned template-labeled snapshot (record gone after a failed
    /// post-commit cleanup) stays reclaimable via `DeleteSnapshot`.
    pub fn references_snapshot(&self, snapshot_id: &str) -> Result<bool> {
        let _guard = self.lock.lock().unwrap();
        Ok(self
            .read_all()?
            .iter()
            .flat_map(TemplateRecord::entries)
            .any(|e| {
                e.warm
                    .as_ref()
                    .is_some_and(|w| w.snapshot_id == snapshot_id)
            }))
    }

    /// Rootfs images that catalog entries need to stay bootable — a pin
    /// source for the converted-rootfs cache sweep, alongside
    /// [`SnapshotCatalog::referenced_rootfs_paths`](crate::snapshot::SnapshotCatalog::referenced_rootfs_paths).
    pub fn rootfs_paths(&self) -> Result<BTreeSet<PathBuf>> {
        // Held so a listing cannot straddle a mutation and momentarily miss
        // a path the cache sweep must keep pinned.
        let _guard = self.lock.lock().unwrap();
        let mut pinned = BTreeSet::new();
        for record in self.read_all()? {
            for entry in record.entries() {
                if !entry.rootfs_path.is_empty() {
                    pinned.insert(PathBuf::from(&entry.rootfs_path));
                }
            }
        }
        Ok(pinned)
    }

    /// [`Self::released_by`] for the post-commit position: the mutation is
    /// already durable, so a failed catalog-wide scan (an unrelated corrupt
    /// record) must not turn into an error the caller would read as "nothing
    /// happened". Releasing nothing is the safe direction — a logged orphan,
    /// never a deleted snapshot something still references. The warning names
    /// every candidate id: `list_checkpoints` hides template-labeled
    /// snapshots, so this log line is how an operator discovers what to
    /// reclaim with `DeleteSnapshot` once the catalog reads cleanly.
    fn released_after_commit(&self, removed: &[TemplateEntry]) -> ReleasedArtifacts {
        self.released_by(removed).unwrap_or_else(|error| {
            let candidates: Vec<&str> = removed
                .iter()
                .filter_map(|e| e.warm.as_ref().map(|w| w.snapshot_id.as_str()))
                .collect();
            warn!(
                %error,
                snapshot_ids = candidates.join(","),
                "template catalog scan failed after a committed mutation; \
                 skipping artifact release (listed warm snapshots may be \
                 orphaned; reclaim via DeleteSnapshot once the catalog parses)"
            );
            ReleasedArtifacts::default()
        })
    }

    /// Snapshot ids among `removed` that no remaining catalog entry
    /// references. Warm snapshots are created per build and never shared, but
    /// the sweep is reference-counted anyway so a future sharing scheme can't
    /// silently turn deletion into corruption.
    fn released_by(&self, removed: &[TemplateEntry]) -> Result<ReleasedArtifacts> {
        let candidates: Vec<String> = removed
            .iter()
            .filter_map(|e| e.warm.as_ref().map(|w| w.snapshot_id.clone()))
            .collect();
        if candidates.is_empty() {
            return Ok(ReleasedArtifacts::default());
        }
        let live: HashSet<String> = self
            .read_all()?
            .iter()
            .flat_map(TemplateRecord::entries)
            .filter_map(|e| e.warm.as_ref().map(|w| w.snapshot_id.clone()))
            .collect();
        Ok(ReleasedArtifacts {
            snapshot_ids: candidates
                .into_iter()
                .filter(|id| !live.contains(id))
                .collect(),
        })
    }

    fn record_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.json"))
    }

    fn read_record(&self, name: &str) -> Result<Option<TemplateRecord>> {
        match std::fs::read_to_string(self.record_path(name)) {
            Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(VmmError::Io(e)),
        }
    }

    /// Read every record. Strict by design: a corrupt record is real
    /// corruption, and treating it as absent would unpin rootfs images the
    /// cache sweep must not reclaim.
    fn read_all(&self) -> Result<Vec<TemplateRecord>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for dirent in std::fs::read_dir(&self.root).map_err(VmmError::Io)? {
            let path = dirent.map_err(VmmError::Io)?.path();
            if !path.is_file() || path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let json = std::fs::read_to_string(&path).map_err(VmmError::Io)?;
            records.push(serde_json::from_str(&json)?);
        }
        records.sort_by(|a: &TemplateRecord, b: &TemplateRecord| a.name.cmp(&b.name));
        Ok(records)
    }

    fn write_record(&self, record: &TemplateRecord) -> Result<()> {
        if record.is_empty() {
            return self.remove_record(&record.name);
        }
        std::fs::create_dir_all(&self.root).map_err(VmmError::Io)?;
        std::fs::set_permissions(&self.root, {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o700)
        })
        .map_err(VmmError::Io)?;
        let bytes = serde_json::to_vec_pretty(record)?;
        atomic_write(&self.record_path(&record.name), &bytes)
    }

    fn remove_record(&self, name: &str) -> Result<()> {
        match std::fs::remove_file(self.record_path(name)) {
            Ok(()) => std::fs::File::open(&self.root)
                .and_then(|dir| dir.sync_all())
                .map_err(VmmError::Io),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VmmError::Io(e)),
        }
    }
}

/// Validate a template name.
///
/// Names become file names, snapshot `vm_id` components, and reference
/// prefixes, so they share the sandbox-id charset; `:` is additionally
/// impossible, keeping the `name[:version]` grammar unambiguous.
pub fn validate_template_name(name: &str) -> Result<()> {
    validate_component("template name", name, false)
}

/// Validate a template version string (`[A-Za-z0-9._-]`, e.g. "1.2.0").
pub fn validate_template_version(version: &str) -> Result<()> {
    validate_component("template version", version, true)
}

fn validate_component(kind: &str, value: &str, allow_dot: bool) -> Result<()> {
    if value.is_empty() {
        return Err(VmmError::Config(format!("{kind} must not be empty")));
    }
    if value.len() > MAX_COMPONENT_LEN {
        return Err(VmmError::Config(format!(
            "{kind} must be at most {MAX_COMPONENT_LEN} characters"
        )));
    }
    let valid = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || (allow_dot && b == b'.'));
    if !valid {
        let extra = if allow_dot { ", '.'" } else { "" };
        return Err(VmmError::Config(format!(
            "invalid {kind} {value:?}: only ASCII letters, digits, '-', '_'{extra} are allowed"
        )));
    }
    Ok(())
}

/// Split a `name[:version]` reference and validate both components.
fn parse_reference(reference: &str) -> Result<(&str, Option<&str>)> {
    match reference.split_once(':') {
        None => {
            validate_template_name(reference)?;
            Ok((reference, None))
        }
        Some((name, version)) => {
            validate_template_name(name)?;
            validate_template_version(version)?;
            Ok((name, Some(version)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(digest: &str, rootfs: &str) -> TemplateEntry {
        TemplateEntry {
            version: String::new(),
            digest: digest.to_string(),
            rootfs_path: rootfs.to_string(),
            warm: None,
            defaults: TemplateDefaultsSpec::default(),
            labels: HashMap::new(),
            created_at: Utc::now(),
            size_bytes: 0,
        }
    }

    fn warm_entry(digest: &str, snapshot_id: &str) -> TemplateEntry {
        let mut e = entry(digest, "/cache/rootfs-a.ext4");
        e.warm = Some(WarmArtifact {
            snapshot_id: snapshot_id.to_string(),
            vcpus: 2,
            memory_mib: 512,
        });
        e
    }

    fn catalog() -> (tempfile::TempDir, TemplateCatalog) {
        let dir = tempfile::tempdir().unwrap();
        let catalog = TemplateCatalog::new(dir.path().to_str().unwrap());
        (dir, catalog)
    }

    #[test]
    fn bare_name_resolves_draft_until_publish_then_newest_version() {
        let (_dir, c) = catalog();
        c.put_draft("code", entry("sha256:d1", "/cache/r1.ext4"))
            .unwrap();
        assert_eq!(c.resolve("code").unwrap().entry.digest, "sha256:d1");

        c.publish("code", "1.0").unwrap();
        c.put_draft("code", entry("sha256:d2", "/cache/r2.ext4"))
            .unwrap();
        // Published wins over the newer draft on a bare name.
        let resolved = c.resolve("code").unwrap();
        assert_eq!(resolved.entry.version, "1.0");
        assert_eq!(resolved.entry.digest, "sha256:d1");

        c.publish("code", "2.0").unwrap();
        assert_eq!(c.resolve("code").unwrap().entry.version, "2.0");
        assert_eq!(c.resolve("code:1.0").unwrap().entry.digest, "sha256:d1");
    }

    #[test]
    fn canonical_ref_pins_name_version_and_digest() {
        let (_dir, c) = catalog();
        c.put_draft("code", entry("sha256:d1", "/r.ext4")).unwrap();
        assert_eq!(
            c.resolve("code").unwrap().canonical_ref(),
            "code:@sha256:d1"
        );
        c.publish("code", "1.0").unwrap();
        assert_eq!(
            c.resolve("code").unwrap().canonical_ref(),
            "code:1.0@sha256:d1"
        );
    }

    #[test]
    fn missing_references_fail_with_the_classifier_prefix() {
        let (_dir, c) = catalog();
        let err = c.resolve("ghost").unwrap_err();
        assert!(err.to_string().starts_with("template not found:"), "{err}");
        c.put_draft("code", entry("sha256:d1", "/r.ext4")).unwrap();
        assert!(matches!(
            c.resolve("code:9.9").unwrap_err(),
            VmmError::TemplateNotFound(_)
        ));
    }

    #[test]
    fn publish_is_idempotent_for_retries_but_rejects_content_clash() {
        let (_dir, c) = catalog();
        c.put_draft("code", entry("sha256:d1", "/r.ext4")).unwrap();
        c.publish("code", "1.0").unwrap();
        // Retry after commit (no draft left): succeeds, returns the version.
        assert_eq!(c.publish("code", "1.0").unwrap().entry.digest, "sha256:d1");
        // Identical rebuild then re-publish: idempotent, draft consumed.
        c.put_draft("code", entry("sha256:d1", "/r.ext4")).unwrap();
        c.publish("code", "1.0").unwrap();
        assert_eq!(c.resolve("code").unwrap().entry.version, "1.0");
        // Different content under a taken version: refused.
        c.put_draft("code", entry("sha256:d2", "/r.ext4")).unwrap();
        assert!(matches!(
            c.publish("code", "1.0").unwrap_err(),
            VmmError::TemplateVersionExists(_)
        ));
        // The clashing draft survives for publishing under a new version.
        assert_eq!(c.publish("code", "1.1").unwrap().entry.digest, "sha256:d2");
    }

    #[test]
    fn collapsing_a_same_digest_draft_releases_its_fresh_snapshot() {
        let (_dir, c) = catalog();
        c.put_draft("code", warm_entry("sha256:d1", "snap-a"))
            .unwrap();
        c.publish("code", "1.0").unwrap();
        // A rebuild can produce identical content with a freshly allocated
        // warm snapshot; the idempotent re-publish must not leak it.
        c.put_draft("code", warm_entry("sha256:d1", "snap-b"))
            .unwrap();
        let outcome = c.publish("code", "1.0").unwrap();
        assert_eq!(outcome.entry.warm.as_ref().unwrap().snapshot_id, "snap-a");
        assert_eq!(outcome.released.snapshot_ids, vec!["snap-b".to_string()]);
    }

    #[test]
    fn a_corrupt_sibling_record_does_not_fail_a_committed_mutation() {
        let (dir, c) = catalog();
        c.put_draft("code", warm_entry("sha256:d1", "snap-1"))
            .unwrap();
        std::fs::write(
            dir.path().join("template-catalog").join("broken.json"),
            b"not json",
        )
        .unwrap();
        // The delete commits and reports success; the scan failure only
        // suppresses artifact release (logged orphan, safe direction).
        let released = c.delete("code").unwrap();
        assert!(released.snapshot_ids.is_empty());
        assert!(matches!(
            c.resolve("code").unwrap_err(),
            VmmError::TemplateNotFound(_)
        ));
    }

    #[test]
    fn publish_without_a_draft_is_a_precondition_failure() {
        let (_dir, c) = catalog();
        c.put_draft("code", entry("sha256:d1", "/r.ext4")).unwrap();
        c.publish("code", "1.0").unwrap();
        assert!(matches!(
            c.publish("code", "2.0").unwrap_err(),
            VmmError::FailedPrecondition(_)
        ));
        assert!(matches!(
            c.publish("ghost", "1.0").unwrap_err(),
            VmmError::TemplateNotFound(_)
        ));
    }

    #[test]
    fn delete_version_and_whole_template_release_unreferenced_snapshots() {
        let (_dir, c) = catalog();
        c.put_draft("code", warm_entry("sha256:d1", "snap-1"))
            .unwrap();
        c.publish("code", "1.0").unwrap();
        c.put_draft("code", warm_entry("sha256:d2", "snap-2"))
            .unwrap();

        let released = c.delete("code:1.0").unwrap();
        assert_eq!(released.snapshot_ids, vec!["snap-1".to_string()]);
        // Draft survives a version delete.
        assert_eq!(c.resolve("code").unwrap().entry.digest, "sha256:d2");

        let released = c.delete("code").unwrap();
        assert_eq!(released.snapshot_ids, vec!["snap-2".to_string()]);
        assert!(matches!(
            c.resolve("code").unwrap_err(),
            VmmError::TemplateNotFound(_)
        ));
        assert!(matches!(
            c.delete("code").unwrap_err(),
            VmmError::TemplateNotFound(_)
        ));
    }

    #[test]
    fn a_still_referenced_snapshot_is_not_released() {
        let (_dir, c) = catalog();
        // Defensive cross-reference: two entries sharing one snapshot id.
        c.put_draft("a", warm_entry("sha256:d1", "shared")).unwrap();
        c.publish("a", "1.0").unwrap();
        c.put_draft("b", warm_entry("sha256:d2", "shared")).unwrap();

        assert!(c.delete("a").unwrap().snapshot_ids.is_empty());
        assert_eq!(
            c.delete("b").unwrap().snapshot_ids,
            vec!["shared".to_string()]
        );
    }

    #[test]
    fn displacing_a_draft_releases_its_exclusive_snapshot() {
        let (_dir, c) = catalog();
        c.put_draft("code", warm_entry("sha256:d1", "snap-old"))
            .unwrap();
        let outcome = c
            .put_draft("code", warm_entry("sha256:d2", "snap-new"))
            .unwrap();
        assert_eq!(outcome.released.snapshot_ids, vec!["snap-old".to_string()]);
        assert_eq!(outcome.entry.version, "");
    }

    #[test]
    fn list_orders_by_name_then_publish_order_with_draft_last() {
        let (_dir, c) = catalog();
        c.put_draft("b", entry("sha256:b1", "/rb.ext4")).unwrap();
        c.put_draft("a", entry("sha256:a1", "/ra.ext4")).unwrap();
        c.publish("a", "1.0").unwrap();
        c.put_draft("a", entry("sha256:a2", "/ra2.ext4")).unwrap();

        let rows = c.list().unwrap();
        let keys: Vec<String> = rows
            .iter()
            .map(|(name, e)| format!("{name}:{}", e.version))
            .collect();
        assert_eq!(keys, vec!["a:1.0", "a:", "b:"]);
    }

    #[test]
    fn rootfs_paths_pin_every_entry_including_drafts() {
        let (_dir, c) = catalog();
        c.put_draft("a", entry("sha256:a1", "/cache/ra.ext4"))
            .unwrap();
        c.publish("a", "1.0").unwrap();
        c.put_draft("a", entry("sha256:a2", "/cache/ra2.ext4"))
            .unwrap();
        c.put_draft("b", entry("sha256:b1", "/cache/rb.ext4"))
            .unwrap();

        let pinned = c.rootfs_paths().unwrap();
        for path in ["/cache/ra.ext4", "/cache/ra2.ext4", "/cache/rb.ext4"] {
            assert!(pinned.contains(Path::new(path)), "missing {path}");
        }
    }

    #[test]
    fn records_survive_a_catalog_reload() {
        let (dir, c) = catalog();
        c.put_draft("code", warm_entry("sha256:d1", "snap-1"))
            .unwrap();
        c.publish("code", "1.0").unwrap();

        let reloaded = TemplateCatalog::new(dir.path().to_str().unwrap());
        let resolved = reloaded.resolve("code:1.0").unwrap();
        assert_eq!(resolved.entry.digest, "sha256:d1");
        assert_eq!(resolved.entry.warm.as_ref().unwrap().snapshot_id, "snap-1");
    }

    #[test]
    fn names_and_versions_reject_traversal_and_grammar_collisions() {
        let (_dir, c) = catalog();
        for bad in ["", "../etc", "a/b", "a b", ":1.0", "名字", &"x".repeat(65)] {
            assert!(
                matches!(c.resolve(bad), Err(VmmError::Config(_))),
                "accepted {bad:?}"
            );
        }
        // Versions allow dots; '@' stays reserved for canonical refs.
        assert!(matches!(
            c.resolve("code:1.0@sha256"),
            Err(VmmError::Config(_))
        ));
        assert!(matches!(
            c.put_draft("docker:img", entry("d", "/r")).unwrap_err(),
            VmmError::Config(_)
        ));
    }
}
