//! Template-catalog surface on [`SandboxManager`] (CORE-107).
//!
//! Thin delegation to [`TemplateCatalog`](crate::template_catalog::TemplateCatalog)
//! plus the artifact side effects the catalog itself never performs: draining
//! pre-warmed restore slots and deleting warm snapshots a mutation released.
//! Build orchestration (rootfs conversion, prewarm) lives in the guest agent
//! and lands its results here via [`register_template_draft`].
//!
//! [`register_template_draft`]: SandboxManager::register_template_draft

use tracing::{info, warn};

use super::SandboxManager;
use crate::error::Result;
use crate::template_catalog::{ReleasedArtifacts, ResolvedTemplate, TemplateEntry};

impl SandboxManager {
    /// Resolve a `name[:version]` catalog reference.
    pub fn get_template(&self, reference: &str) -> Result<ResolvedTemplate> {
        self.templates.resolve(reference)
    }

    /// Every catalog row: `(name, entry)` — published versions in publish
    /// order, then the draft, grouped by name.
    pub fn list_templates(&self) -> Result<Vec<(String, TemplateEntry)>> {
        self.templates.list()
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

    /// Best-effort deletion of snapshots a catalog mutation released,
    /// draining any pre-warmed restore slots staged from each first
    /// (mirroring `delete_checkpoint` — a slot restored from the snapshot
    /// would otherwise outlive it). The catalog entry is already gone, so a
    /// failed snapshot delete must not fail the mutation — it would strand
    /// the caller with a half-deleted template it can only retry into
    /// `TemplateNotFound`. Leftovers are orphaned but recoverable: they carry
    /// no `arcbox.warm_key` (warm LRU ignores them), and once no record
    /// references them the checkpoint deletion guard steps aside, so
    /// `DeleteSnapshot` by id reclaims the disk.
    async fn delete_released_snapshots(&self, released: &ReleasedArtifacts) {
        for snapshot_id in &released.snapshot_ids {
            self.drain_pool(Some(snapshot_id)).await;
            match self.snapshots.delete_by_id(snapshot_id) {
                Ok(()) => {}
                // `find_by_id` reports a missing snapshot as
                // `VmmError::Snapshot("… not found")` — benign here: a retried
                // mutation already deleted it.
                Err(crate::error::VmmError::Snapshot(msg)) if msg.ends_with("not found") => {}
                Err(error) => warn!(
                    snapshot_id,
                    %error,
                    "failed to delete a template-owned snapshot; artifact is orphaned"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;

    use crate::config::VmmConfig;
    use crate::sandbox::SandboxManager;
    use crate::snapshot::{SnapshotCatalog, SnapshotDraft};
    use crate::template_catalog::{
        TEMPLATE_LABEL, TemplateDefaultsSpec, TemplateEntry, WarmArtifact,
    };

    async fn manager(data_dir: &Path) -> SandboxManager {
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
        let manager = SandboxManager::new(config).unwrap();
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
