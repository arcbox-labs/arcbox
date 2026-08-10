//! Template-catalog surface on [`SandboxManager`] (CORE-107).
//!
//! Thin delegation to [`TemplateCatalog`] plus the artifact side effects the
//! catalog itself never performs: deleting warm snapshots a mutation
//! released. Build orchestration (rootfs conversion, prewarm) lives in the
//! guest agent and lands its results here via [`register_template_draft`].
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

    /// Install a built entry as `name`'s draft, deleting any warm snapshot
    /// the displaced previous draft owned exclusively.
    pub fn register_template_draft(
        &self,
        name: &str,
        entry: TemplateEntry,
    ) -> Result<TemplateEntry> {
        let outcome = self.templates.put_draft(name, entry)?;
        self.delete_released_snapshots(&outcome.released);
        info!(template = name, digest = %outcome.entry.digest, "template draft registered");
        Ok(outcome.entry)
    }

    /// Freeze `name`'s draft as immutable `version`.
    pub fn publish_template(&self, name: &str, version: &str) -> Result<TemplateEntry> {
        self.templates.publish(name, version)
    }

    /// Delete a template version (`name:version`) or a whole template
    /// (`name`), including warm snapshots no remaining entry references.
    /// Rootfs images are reclaimed separately by the rootfs-cache sweep once
    /// [`Self::pinned_rootfs_paths`] stops reporting them.
    pub fn delete_template(&self, reference: &str) -> Result<()> {
        self.check_reconcile()?;
        let released = self.templates.delete(reference)?;
        self.delete_released_snapshots(&released);
        info!(template = reference, "template deleted");
        Ok(())
    }

    /// Best-effort deletion of snapshots a catalog mutation released. The
    /// catalog entry is already gone, so a failed snapshot delete must not
    /// fail the mutation — it would strand the caller with a half-deleted
    /// template it can only retry into `TemplateNotFound`. Leftovers are
    /// orphaned but inert (they carry no `arcbox.warm_key`, so the warm LRU
    /// ignores them) and warrant a warning, not an error.
    fn delete_released_snapshots(&self, released: &ReleasedArtifacts) {
        for snapshot_id in &released.snapshot_ids {
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
