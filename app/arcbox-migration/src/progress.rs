//! Progress types emitted during migration execution.

/// High-level migration stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStage {
    /// Preparing the migration plan.
    Prepare,
    /// Stopping source containers blocked on volume migration.
    StopSourceContainers,
    /// Importing images.
    ImportImages,
    /// Importing volumes.
    ImportVolumes,
    /// Recreating networks.
    RecreateNetworks,
    /// Recreating containers.
    RecreateContainers,
    /// Starting containers that were running on the source.
    StartContainers,
    /// Cleaning up temporary resources.
    Cleanup,
    /// Migration completed.
    Complete,
}

impl MigrationStage {
    /// Returns a stable string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::StopSourceContainers => "stop-source-containers",
            Self::ImportImages => "import-images",
            Self::ImportVolumes => "import-volumes",
            Self::RecreateNetworks => "recreate-networks",
            Self::RecreateContainers => "recreate-containers",
            Self::StartContainers => "start-containers",
            Self::Cleanup => "cleanup",
            Self::Complete => "complete",
        }
    }
}

/// Progress update emitted during migration execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationProgress {
    /// Current stage.
    pub stage: MigrationStage,
    /// Human-readable detail.
    pub detail: String,
    /// Resource kind being processed.
    pub resource_type: Option<String>,
    /// Resource name being processed.
    pub resource_name: Option<String>,
    /// Current item index (1-based).
    pub current: Option<u32>,
    /// Total number of items in the current stage.
    pub total: Option<u32>,
}
