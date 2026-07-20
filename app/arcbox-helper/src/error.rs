//! Structured helper errors on the tarpc wire.
//!
//! **Wire stability**: bincode encodes enum variants by index. Append new
//! variants only at the end. Renaming fields is fine with serde rename; do
//! not reorder or insert variants in the middle of a released helper major.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Error returned by privileged helper RPCs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum HelperError {
    /// Input failed parse/validate at the RPC boundary.
    #[error("{0}")]
    Validation(String),

    /// Destination is a symlink pointing outside ArcBox ownership.
    #[error("{path} is a symlink to {current} (not ArcBox-owned, not replacing)")]
    ForeignSymlink { path: String, current: String },

    /// Destination exists but is not a symlink (e.g. real docker.sock).
    #[error("{path} exists and is not a symlink (not replacing)")]
    NotASymlink { path: String },

    /// CLI link target path is itself a symlink (escape risk).
    #[error("CLI target '{target}' is a symlink (refusing to link through it)")]
    CliTargetIsSymlink { target: String },

    /// CLI link target path does not exist on disk.
    #[error("CLI target does not exist: {target}")]
    CliTargetMissing { target: String },

    /// CLI link target exists but is not a regular file.
    #[error("CLI target '{target}' is not a regular file")]
    CliTargetNotFile { target: String },

    /// Canonicalized CLI target left the ArcBox xbin tree.
    #[error("CLI target '{target}' resolves to {resolved} which is not an ArcBox xbin path")]
    CliTargetEscaped { target: String, resolved: String },

    /// File exists without the ArcBox management marker (DNS resolver, etc.).
    #[error("{path} exists and is not ArcBox-managed (not overwriting)")]
    ForeignManagedFile { path: String },

    /// Filesystem / OS operation failed.
    #[error("{op} {path}: {detail}")]
    Io {
        op: String,
        path: String,
        detail: String,
    },

    /// Catch-all for subsystem errors (routes, etc.) without a tighter variant.
    ///
    /// Prefer a dedicated variant when a call site needs structured matching.
    #[error("{0}")]
    Other(String),
}

impl HelperError {
    #[must_use]
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    #[must_use]
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }

    #[must_use]
    pub fn io(op: &str, path: impl AsRef<Path>, err: impl std::fmt::Display) -> Self {
        Self::Io {
            op: op.to_owned(),
            path: path.as_ref().display().to_string(),
            detail: err.to_string(),
        }
    }

    #[must_use]
    pub fn foreign_symlink(path: impl AsRef<Path>, current: impl AsRef<Path>) -> Self {
        Self::ForeignSymlink {
            path: path.as_ref().display().to_string(),
            current: current.as_ref().display().to_string(),
        }
    }

    #[must_use]
    pub fn not_a_symlink(path: impl AsRef<Path>) -> Self {
        Self::NotASymlink {
            path: path.as_ref().display().to_string(),
        }
    }

    #[must_use]
    pub fn foreign_managed(path: impl AsRef<Path>) -> Self {
        Self::ForeignManagedFile {
            path: path.as_ref().display().to_string(),
        }
    }
}

/// Stable machine-readable code for metrics / Desktop branching.
impl HelperError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation",
            Self::ForeignSymlink { .. } => "foreign_symlink",
            Self::NotASymlink { .. } => "not_a_symlink",
            Self::CliTargetIsSymlink { .. } => "cli_target_is_symlink",
            Self::CliTargetMissing { .. } => "cli_target_missing",
            Self::CliTargetNotFile { .. } => "cli_target_not_file",
            Self::CliTargetEscaped { .. } => "cli_target_escaped",
            Self::ForeignManagedFile { .. } => "foreign_managed_file",
            Self::Io { .. } => "io",
            Self::Other(_) => "other",
        }
    }
}
