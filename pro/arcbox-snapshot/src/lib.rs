//! # arcbox-snapshot
//!
//! Snapshot and restore functionality for ArcBox Pro.
//!
//! Features:
//!
//! - **VM snapshots**: Full VM state capture
//! - **Container checkpoints**: CRIU-based container snapshots
//! - **Incremental snapshots**: Efficient storage
//! - **Scheduled backups**: Automatic snapshot creation
//!
//! ## License
//!
//! This crate is licensed under BSL-1.1, which converts to MIT after 2 years.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Snapshot ID.
    pub id: String,
    /// Snapshot name.
    pub name: String,
    /// Target (VM or container) ID.
    pub target_id: String,
    /// Creation time.
    pub created: DateTime<Utc>,
    /// Size in bytes.
    pub size: u64,
    /// Parent snapshot ID (for incremental).
    pub parent: Option<String>,
}

/// Snapshot manager.
pub struct SnapshotManager {
    /// Base directory for snapshots.
    base_dir: std::path::PathBuf,
}

impl SnapshotManager {
    /// Creates a new snapshot manager.
    #[must_use]
    pub fn new(base_dir: std::path::PathBuf) -> Self {
        Self { base_dir }
    }

    /// Creates a snapshot.
    pub async fn create(&self, target_id: &str, name: &str) -> Result<SnapshotInfo, SnapshotError> {
        tracing::info!("Creating snapshot '{}' for {}", name, target_id);
        // TODO: Implement snapshot creation
        Err(SnapshotError::NotImplemented)
    }

    /// Restores from a snapshot.
    pub async fn restore(&self, snapshot_id: &str) -> Result<(), SnapshotError> {
        tracing::info!("Restoring from snapshot {}", snapshot_id);
        // TODO: Implement restore
        Err(SnapshotError::NotImplemented)
    }

    /// Lists snapshots for a target.
    pub fn list(&self, target_id: &str) -> Vec<SnapshotInfo> {
        let _ = target_id;
        // TODO: List snapshots
        Vec::new()
    }

    /// Deletes a snapshot.
    pub async fn delete(&self, snapshot_id: &str) -> Result<(), SnapshotError> {
        tracing::info!("Deleting snapshot {}", snapshot_id);
        // TODO: Delete snapshot
        Err(SnapshotError::NotImplemented)
    }
}

/// Snapshot errors.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// Snapshot not found.
    #[error("snapshot not found: {0}")]
    NotFound(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Not implemented.
    #[error("not implemented")]
    NotImplemented,
}
