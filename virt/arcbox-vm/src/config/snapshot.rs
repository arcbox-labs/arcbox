use serde::{Deserialize, Serialize};

/// Snapshot type — mirrors Firecracker terminology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotType {
    /// Capture full memory + VM state.
    Full,
    /// Capture only dirty pages since the last snapshot.
    Diff,
}
