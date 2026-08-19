//! Template-catalog surface on [`ComputerManager`] (CORE-107).
//!
//! Thin delegation to [`TemplateCatalog`](crate::template_catalog::TemplateCatalog)
//! plus the artifact side effects the catalog itself never performs: draining
//! pre-warmed restore slots and deleting warm snapshots a mutation released.
//! Build orchestration (rootfs conversion, prewarm) lives in the guest agent
//! and lands its results here via [`register_template_draft`].
//!
//! [`register_template_draft`]: ComputerManager::register_template_draft

use std::collections::HashMap;
use std::path::Path;

use tracing::{info, warn};
use uuid::Uuid;

use super::ComputerManager;
use super::types::{ComputerId, ComputerSpec, ComputerState};
use crate::error::{ComputerError, Result};
use crate::snapshot::{SnapshotDraft, SnapshotGeometry};
use crate::template_catalog::{
    ReleasedArtifacts, ResolvedTemplate, TEMPLATE_LABEL, TemplateDefaultsSpec, TemplateEntry,
};
use arcbox_snapshot::SnapshotError;

/// A checkpoint copied into template ownership: everything the build
/// orchestrator needs to assemble the catalog entry.
#[derive(Debug)]
pub struct PromotedSnapshot {
    /// The template-owned copy's snapshot id (carries [`TEMPLATE_LABEL`]).
    pub snapshot_id: String,
    /// Capture-time geometry the copy restores onto.
    pub geometry: SnapshotGeometry,
    /// The origin's rootfs image path (pinned by the copied meta).
    pub rootfs_path: String,
    /// On-disk footprint of the copied vmstate + memory files. Nominal on
    /// Btrfs: the copy reflinks, so blocks are shared until either side
    /// diverges.
    pub artifact_bytes: u64,
}

impl ComputerManager {
    /// Resolve a `name[:version]` catalog reference.
    pub fn get_template(&self, reference: &str) -> Result<ResolvedTemplate> {
        self.templates.resolve(reference).map_err(Into::into)
    }

    /// Every catalog row: `(name, entry)` — published versions in publish
    /// order, then the draft, grouped by name.
    pub fn list_templates(&self) -> Result<Vec<(String, TemplateEntry)>> {
        self.templates.list().map_err(Into::into)
    }

    /// Install a built entry as `name`'s draft, reclaiming any warm snapshot
    /// the displaced previous draft owned exclusively.
    pub async fn register_template_draft(
        &self,
        name: &str,
        entry: TemplateEntry,
    ) -> Result<TemplateEntry> {
        let outcome = self.templates.put_draft(name, entry)?;
        self.delete_released_snapshots(&outcome.released).await;
        info!(template = name, digest = %outcome.entry.digest, "template draft registered");
        Ok(outcome.entry)
    }

    /// Freeze `name`'s draft as immutable `version`, reclaiming the draft's
    /// exclusively-owned artifacts when an idempotent re-publish collapses a
    /// same-digest rebuild.
    pub async fn publish_template(&self, name: &str, version: &str) -> Result<TemplateEntry> {
        let outcome = self.templates.publish(name, version)?;
        self.delete_released_snapshots(&outcome.released).await;
        Ok(outcome.entry)
    }

    /// Delete a template version (`name:version`) or a whole template
    /// (`name`), including warm snapshots no remaining entry references.
    /// Rootfs images are reclaimed separately by the rootfs-cache sweep once
    /// [`Self::pinned_rootfs_paths`] stops reporting them.
    pub async fn delete_template(&self, reference: &str) -> Result<()> {
        self.check_reconcile()?;
        let released = self.templates.delete(reference)?;
        self.delete_released_snapshots(&released).await;
        info!(template = reference, "template deleted");
        Ok(())
    }

    /// Copy checkpoint `source_snapshot_id` into a template-owned snapshot
    /// (new id, [`TEMPLATE_LABEL`] = `template_name`), decoupling the
    /// template's lifetime from the user checkpoint. Files are reflinked
    /// where the filesystem supports it (the data dir is Btrfs), so the copy
    /// is cheap; the origin's rootfs stays pinned through the copied meta.
    pub async fn promote_snapshot_to_template(
        &self,
        source_snapshot_id: &str,
        template_name: &str,
    ) -> Result<PromotedSnapshot> {
        self.check_reconcile()?;
        crate::template_catalog::validate_template_name(template_name)?;
        let source = self.snapshots.find_by_id(source_snapshot_id)?;
        if source.name.as_deref() == Some(super::pause::PAUSE_SNAPSHOT_NAME) {
            return Err(ComputerError::FailedPrecondition(format!(
                "snapshot {source_snapshot_id} is the internal pause checkpoint of a \
                 paused sandbox; checkpoint the sandbox instead"
            )));
        }
        let geometry = source.geometry.ok_or_else(|| {
            ComputerError::FailedPrecondition(format!(
                "snapshot {source_snapshot_id} predates geometry recording; \
                 re-checkpoint the sandbox with this agent and promote the new snapshot"
            ))
        })?;
        let rootfs_path = source.rootfs_path.clone().ok_or_else(|| {
            ComputerError::FailedPrecondition(format!(
                "snapshot {source_snapshot_id} records no rootfs path; \
                 re-checkpoint the sandbox and promote the new snapshot"
            ))
        })?;

        let pending = self.snapshots.begin(&format!("template-{template_name}"))?;
        let staging = pending.dir();
        let mut artifact_bytes = clone_or_copy(&source.vmstate_path, &staging.join("vmstate"))?;
        if let Some(mem) = &source.mem_path {
            artifact_bytes += clone_or_copy(mem, &staging.join("mem"))?;
        }
        let meta = pending.commit(SnapshotDraft {
            name: None,
            labels: HashMap::from([(TEMPLATE_LABEL.to_owned(), template_name.to_owned())]),
            snapshot_type: source.snapshot_type,
            parent_id: source.parent_id.clone(),
            kernel_path: source.kernel_path.clone(),
            rootfs_path: Some(rootfs_path.clone()),
            net_invariant: source.net_invariant,
            geometry: Some(geometry),
            format: source.format,
        })?;
        info!(
            template = template_name,
            source = source_snapshot_id,
            snapshot_id = %meta.id,
            "checkpoint promoted into template ownership"
        );
        Ok(PromotedSnapshot {
            snapshot_id: meta.id,
            geometry,
            rootfs_path,
            artifact_bytes,
        })
    }

    /// Boot the built rootfs once with the template's effective geometry and
    /// an empty cmd, checkpoint at READY, and destroy the builder — the
    /// snapshot then serves creates as the template's warm start point.
    /// Requires jailer mode (restore does). The builder's warm behaviour is
    /// disabled so a prewarm neither restores from nor publishes into the
    /// warm-cache LRU.
    pub async fn prewarm_template(
        &self,
        name: &str,
        rootfs_path: &str,
        defaults: &TemplateDefaultsSpec,
    ) -> Result<PrewarmOutcome> {
        if self.config.firecracker.jailer.is_none() {
            return Err(ComputerError::FailedPrecondition(
                "prewarm requires jailer mode (snapshot restore does)".into(),
            ));
        }
        let vcpus = if defaults.vcpus != 0 {
            defaults.vcpus
        } else {
            u32::try_from(self.config.defaults.vcpus).unwrap_or(1)
        };
        let memory_mib = if defaults.memory_mib != 0 {
            defaults.memory_mib
        } else {
            self.config.defaults.memory_mib
        };
        // Short id on purpose: it must fit the driver's own id budget
        // (`VmDriver::id_budget`, enforced by `validate_new_computer_id`) —
        // `template-build-<full uuid>` was 51 chars and overflowed AF_UNIX's
        // `sun_path`, failing the builder boot as an opaque socket timeout.
        // 16 hex chars keep collisions out of reach for an ephemeral,
        // single-flighted builder.
        let mut suffix = Uuid::new_v4().simple().to_string();
        suffix.truncate(16);
        let builder_id = format!("tpl-build-{suffix}");
        let spec = ComputerSpec {
            id: Some(builder_id.clone()),
            rootfs: rootfs_path.to_owned(),
            vcpus,
            memory_mib,
            // Deliberately no cmd: the checkpoint captures freshly-Ready and
            // idle. A cmd baked into the memory image would re-run on every
            // restore on top of the effective spec's cmd.
            ..Default::default()
        };
        let (id, _ip) = self
            .create_computer_inner(
                spec,
                &Uuid::new_v4().to_string(),
                super::lifecycle::WarmPolicy::Disabled,
            )
            .await?;
        let checkpoint = self.prewarm_checkpoint(&id, name).await;
        // The builder dies regardless of checkpoint success. A failed
        // teardown fails the build: a leaked live builder VM has no reaper
        // (no HealthMonitor loop), so success here would silently keep its
        // vCPUs/memory allocated. The fresh snapshot is dropped too — no
        // record references it yet — and the error names the builder id so
        // the operator can remove it and retry.
        if let Err(remove_error) = self.remove_computer(&id, true).await {
            if let Ok((snapshot_id, _)) = &checkpoint {
                self.discard_promoted_snapshot(snapshot_id).await;
            }
            return Err(ComputerError::Unavailable(format!(
                "prewarm builder sandbox {id} could not be removed ({remove_error}); \
                 remove it manually and retry the build"
            )));
        }
        let (snapshot_id, artifact_bytes) = checkpoint?;
        Ok(PrewarmOutcome {
            warm: crate::template_catalog::WarmArtifact {
                snapshot_id,
                vcpus,
                memory_mib,
            },
            artifact_bytes,
        })
    }

    /// Wait for the builder to reach READY, then checkpoint it under the
    /// template label. Polled rather than event-driven: a lagged broadcast
    /// receiver would miss the READY edge, while polling cannot.
    async fn prewarm_checkpoint(&self, id: &ComputerId, template: &str) -> Result<(String, u64)> {
        const READY_POLL_MS: u64 = 250;
        const READY_TIMEOUT_SECS: u64 = 180;
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(READY_TIMEOUT_SECS);
        loop {
            let info = self.inspect_computer(id)?;
            match info.state {
                ComputerState::Ready => break,
                ComputerState::Failed => {
                    return Err(ComputerError::FailedPrecondition(format!(
                        "prewarm boot failed: {}",
                        info.error.unwrap_or_else(|| "unknown boot failure".into())
                    )));
                }
                _ if tokio::time::Instant::now() >= deadline => {
                    return Err(ComputerError::DeadlineExceeded(format!(
                        "prewarm builder did not reach READY within {READY_TIMEOUT_SECS}s"
                    )));
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(READY_POLL_MS)).await,
            }
        }
        // The prewarm builder is this manager's own computer, captured
        // through the same path a user checkpoint takes.
        let info = self
            .capture_checkpoint(
                &id.to_owned(),
                format!("template-{template}"),
                HashMap::from([(TEMPLATE_LABEL.to_owned(), template.to_owned())]),
            )
            .await
        // The builder is force-removed by the caller whichever way this
        // ends, so a guest left frozen needs no failing here: the removal
        // kills and releases it.
        ?;
        let meta = self.snapshots.find_by_id(&info.snapshot_id)?;
        let mut artifact_bytes = std::fs::metadata(&meta.vmstate_path).map_or(0, |m| m.len());
        if let Some(mem) = &meta.mem_path {
            artifact_bytes += std::fs::metadata(mem).map_or(0, |m| m.len());
        }
        Ok((info.snapshot_id, artifact_bytes))
    }

    /// Best-effort removal of a just-promoted copy whose catalog
    /// registration failed — without it the copy would sit as a
    /// (recoverable) orphan until an operator noticed the log line.
    pub async fn discard_promoted_snapshot(&self, snapshot_id: &str) {
        self.delete_released_snapshots(&ReleasedArtifacts {
            snapshot_ids: vec![snapshot_id.to_owned()],
        })
        .await;
    }

    /// Best-effort deletion of snapshots a catalog mutation released,
    /// draining any pre-warmed restore slots staged from each first
    /// (mirroring `delete_checkpoint` — a slot restored from the snapshot
    /// would otherwise outlive it). The catalog entry is already gone, so a
    /// failed snapshot delete must not fail the mutation — it would strand
    /// the caller with a half-deleted template it can only retry into
    /// `TemplateNotFound`. Leftovers are orphaned but recoverable: they carry
    /// no `arcbox.warm_key` (warm LRU ignores them), and once no record
    /// references them the checkpoint deletion guard steps aside, so
    /// `DeleteSnapshot` by id reclaims the disk — provided the catalog still
    /// parses. An unreadable record makes that guard fail closed (an
    /// unreadable catalog must never authorise a delete), so recovery then
    /// starts with removing the bad record.
    async fn delete_released_snapshots(&self, released: &ReleasedArtifacts) {
        for snapshot_id in &released.snapshot_ids {
            self.drain_pool(Some(snapshot_id)).await;
            match self.snapshots.delete_by_id(snapshot_id) {
                Ok(()) => {}
                // `find_by_id` reports a missing snapshot as
                // `SnapshotError::Snapshot("… not found")` — benign here: a
                // retried mutation already deleted it.
                Err(SnapshotError::Snapshot(msg)) if msg.ends_with("not found") => {}
                Err(error) => warn!(
                    snapshot_id,
                    %error,
                    "failed to delete a template-owned snapshot; artifact is orphaned"
                ),
            }
        }
    }
}

/// Result of a prewarm boot-and-checkpoint.
#[derive(Debug)]
pub struct PrewarmOutcome {
    /// The template's warm artifact (snapshot id + capture geometry).
    pub warm: crate::template_catalog::WarmArtifact,
    /// On-disk footprint of the checkpoint files.
    pub artifact_bytes: u64,
}

/// Whether a template's pre-warmed snapshot can serve this create: restore
/// needs the jailer, the invariant tap identity, no caller-pinned boot
/// recipe, and an exactly matching geometry — a memory snapshot resumes
/// only onto its capture shape. Checked against the effective
/// (defaults-applied) spec. Deliberately NOT gated on
/// `config.firecracker.warm_create`: that flag governs the implicit CORE-77
/// cache, while a template's prewarm was explicitly requested at build time
/// — adding the gate would silently disable prewarm for anyone running with
/// the cache off. Stopping restores from a bad snapshot = rebuild or delete
/// the template.
pub(super) fn template_restore_eligible(
    config: &crate::config::RuntimeConfig,
    spec: &ComputerSpec,
    caller_supplied_boot: bool,
    warm: &crate::sandbox::TemplateWarmRef,
) -> bool {
    config.firecracker.jailer.is_some()
        && !caller_supplied_boot
        && spec.network.mode == "tap"
        && !spec.boot_args.contains("ip=")
        && spec.mounts.is_empty()
        && spec.ssh_public_key.is_none()
        && spec.vcpus == warm.vcpus
        && spec.memory_mib == warm.memory_mib
}

/// Copy `src` to `dst` (mode 0600, fsynced), reflinking when the filesystem
/// supports it. Returns the byte length copied.
fn clone_or_copy(src: &Path, dst: &Path) -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let source = std::fs::File::open(src).map_err(ComputerError::Io)?;
        let dest = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dst)
            .map_err(ComputerError::Io)?;
        // SAFETY: both fds are open for the duration of the call; FICLONE
        // only clones extents from the source fd into the destination fd.
        let rc = unsafe { libc::ioctl(dest.as_raw_fd(), libc::FICLONE as _, source.as_raw_fd()) };
        if rc == 0 {
            dest.sync_all().map_err(ComputerError::Io)?;
            return Ok(source.metadata().map_err(ComputerError::Io)?.len());
        }
        // Reflink unsupported here (non-Btrfs staging, cross-subvolume
        // boundary) — fall back to a plain copy below.
        drop(dest);
        let _ = std::fs::remove_file(dst);
    }
    let bytes = std::fs::copy(src, dst).map_err(ComputerError::Io)?;
    let dest = std::fs::File::open(dst).map_err(ComputerError::Io)?;
    std::fs::set_permissions(dst, {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::Permissions::from_mode(0o600)
    })
    .map_err(ComputerError::Io)?;
    dest.sync_all().map_err(ComputerError::Io)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;

    use crate::config::RuntimeConfig;
    use crate::sandbox::ComputerManager;
    use crate::snapshot::{SnapshotCatalog, SnapshotDraft};
    use crate::template_catalog::{
        TEMPLATE_LABEL, TemplateDefaultsSpec, TemplateEntry, WarmArtifact,
    };

    async fn manager(data_dir: &Path) -> ComputerManager {
        let mut config = RuntimeConfig::default();
        config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
        let environment = crate::testkit::fake_environment(&config).unwrap();
        let manager = ComputerManager::new(config, environment).unwrap();
        manager.await_reconcile().await.unwrap();
        manager
    }

    fn publish_template_snapshot(catalog: &SnapshotCatalog, template: &str) -> String {
        let pending = catalog.begin(&format!("template-{template}")).unwrap();
        std::fs::write(pending.dir().join("vmstate"), b"vmstate").unwrap();
        pending
            .commit(SnapshotDraft {
                name: None,
                labels: HashMap::from([(TEMPLATE_LABEL.to_owned(), template.to_owned())]),
                snapshot_type: crate::config::SnapshotType::Full,
                parent_id: None,
                kernel_path: None,
                rootfs_path: Some("/cache/rootfs-tpl.ext4".into()),
                net_invariant: true,
                geometry: None,
                format: crate::sandbox::checkpoint::CHECKPOINT_FORMAT.to_owned(),
            })
            .unwrap()
            .id
    }

    fn entry_with_warm(snapshot_id: &str) -> TemplateEntry {
        TemplateEntry {
            version: String::new(),
            digest: "sha256:d1".into(),
            rootfs_path: "/cache/rootfs-tpl.ext4".into(),
            warm: Some(WarmArtifact {
                snapshot_id: snapshot_id.to_owned(),
                vcpus: 2,
                memory_mib: 512,
            }),
            defaults: TemplateDefaultsSpec::default(),
            labels: HashMap::new(),
            created_at: chrono::Utc::now(),
            size_bytes: 0,
        }
    }

    #[tokio::test]
    async fn template_snapshots_are_hidden_and_delete_refused_while_referenced() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path()).await;
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let snapshot_id = publish_template_snapshot(&catalog, "code");
        m.register_template_draft("code", entry_with_warm(&snapshot_id))
            .await
            .unwrap();

        let listed = m.list_checkpoints(None).unwrap();
        assert!(
            listed.iter().all(|s| s.id != snapshot_id),
            "template snapshot leaked into the user checkpoint list"
        );

        let err = m.delete_checkpoint(&snapshot_id).await.unwrap_err();
        assert!(
            err.to_string().contains("owned by template"),
            "unexpected refusal message: {err}"
        );
        assert!(
            catalog.find_by_id(&snapshot_id).is_ok(),
            "guard must not delete"
        );
    }

    #[tokio::test]
    async fn promotion_copies_the_checkpoint_with_independent_lifetime() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path()).await;
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        // A user checkpoint with recorded geometry and a memory file.
        let pending = catalog.begin("box-1").unwrap();
        std::fs::write(pending.dir().join("vmstate"), b"vmstate").unwrap();
        std::fs::write(pending.dir().join("mem"), b"memory-image").unwrap();
        let source_id = pending
            .commit(crate::snapshot::SnapshotDraft {
                name: Some("user-checkpoint".into()),
                labels: HashMap::new(),
                snapshot_type: crate::config::SnapshotType::Full,
                parent_id: None,
                kernel_path: Some("/kernel".into()),
                rootfs_path: Some("/cache/rootfs-tpl.ext4".into()),
                net_invariant: true,
                geometry: Some(crate::snapshot::SnapshotGeometry {
                    vcpus: 2,
                    memory_mib: 512,
                }),
                format: crate::sandbox::checkpoint::CHECKPOINT_FORMAT.to_owned(),
            })
            .unwrap()
            .id;

        let promoted = m
            .promote_snapshot_to_template(&source_id, "code")
            .await
            .unwrap();
        assert_ne!(promoted.snapshot_id, source_id);
        assert_eq!(promoted.geometry.vcpus, 2);
        assert_eq!(promoted.rootfs_path, "/cache/rootfs-tpl.ext4");
        assert_eq!(
            promoted.artifact_bytes,
            b"vmstate".len() as u64 + b"memory-image".len() as u64
        );

        let copy = catalog.find_by_id(&promoted.snapshot_id).unwrap();
        assert_eq!(
            copy.labels.get(TEMPLATE_LABEL).map(String::as_str),
            Some("code")
        );
        assert!(copy.net_invariant);

        // Deleting the origin leaves the template copy intact.
        m.delete_checkpoint(&source_id).await.unwrap();
        assert!(catalog.find_by_id(&promoted.snapshot_id).is_ok());
    }

    #[tokio::test]
    async fn promotion_refuses_a_snapshot_without_geometry() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path()).await;
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let source_id = publish_template_snapshot(&catalog, "seed");

        let err = m
            .promote_snapshot_to_template(&source_id, "code")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("predates geometry recording"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn an_orphaned_template_snapshot_is_reclaimable_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path()).await;
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        // Labeled, but no catalog record references it — the failure-mode
        // orphan. DeleteSnapshot by id is the recovery path and must work.
        let snapshot_id = publish_template_snapshot(&catalog, "ghost");

        m.delete_checkpoint(&snapshot_id).await.unwrap();
        assert!(catalog.find_by_id(&snapshot_id).is_err());
    }

    #[tokio::test]
    async fn deleting_a_template_deletes_its_owned_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path()).await;
        let catalog = SnapshotCatalog::new(dir.path().to_str().unwrap());
        let snapshot_id = publish_template_snapshot(&catalog, "code");
        m.register_template_draft("code", entry_with_warm(&snapshot_id))
            .await
            .unwrap();

        m.delete_template("code").await.unwrap();
        assert!(
            catalog.find_by_id(&snapshot_id).is_err(),
            "snapshot must be reclaimed"
        );
        assert!(m.get_template("code").is_err());
    }
}
