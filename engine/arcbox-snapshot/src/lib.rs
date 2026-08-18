//! # arcbox-snapshot
//!
//! Snapshot lineage for `ArcBox` computers: the checkpoint catalog, the
//! copy-on-write rootfs manager the checkpoints are cloned through, and
//! the template catalog that promotes a snapshot into a reusable,
//! versioned base image.
//!
//! This is an engine-layer crate — daemon-free and platform-neutral. It
//! owns durable on-disk state and knows nothing about who boots the VM:
//! the guest-side sandbox manager (`arcbox-computer-runtime`) drives it
//! today, and the future registry client belongs here rather than above it.
//!
//! The device-mapper paths (`snapshot_cow`) only *do* anything on Linux,
//! where `dmsetup` and thin pools exist; they compile everywhere so the
//! layer above can too.

pub mod error;
pub mod snapshot;
pub mod snapshot_cow;
pub mod template_catalog;

#[cfg(test)]
mod test_support;

pub use error::{Result, SnapshotError};
pub use snapshot::{SnapshotCatalog, SnapshotInfo, SnapshotType};
