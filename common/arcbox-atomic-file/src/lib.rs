//! Atomic file replacement with a durable rename.
//!
//! Write a private temp sibling, `fsync` it, rename it over the
//! destination, then `fsync` the parent directory so the rename itself
//! survives a crash. Either the old contents or the new ones are visible
//! at every instant; a reader never sees a truncated file.
//!
//! # Two failures, not one
//!
//! The point of this crate is that the two ways it can fail mean
//! different things, and callers legitimately treat them differently:
//!
//! - [`AtomicWriteError::NotCommitted`] — the destination was never
//!   touched and the temp file is cleaned up. The caller simply failed.
//! - [`AtomicWriteError::DurabilityUncertain`] — the new contents are
//!   already visible, but the directory `fsync` confirming the rename did
//!   not complete, so a power loss could still resurrect the old ones.
//!
//! A catalog that must not lie about what it persisted treats the second
//! as an error; a record store that would rather keep the record and warn
//! treats it as a warning. So this crate reports which happened and lets
//! the caller decide, rather than picking one policy for everyone.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use thiserror::Error;
use uuid::Uuid;

/// How an atomic write failed.
#[derive(Debug, Error)]
pub enum AtomicWriteError {
    /// The destination was never replaced; the temp file is cleaned up.
    #[error("{} was not replaced: {source}", .path.display())]
    NotCommitted {
        /// The destination that was left untouched.
        path: PathBuf,
        /// What went wrong before the rename.
        #[source]
        source: std::io::Error,
    },

    /// The rename landed, but the directory `fsync` confirming it did not.
    /// The new contents are visible; their survival across power loss is
    /// unconfirmed.
    #[error("{} was renamed but directory durability is unconfirmed: {source}", .path.display())]
    DurabilityUncertain {
        /// The destination that now holds the new contents.
        path: PathBuf,
        /// The `fsync` failure.
        #[source]
        source: std::io::Error,
    },
}

impl AtomicWriteError {
    /// The underlying I/O failure, whichever stage it came from.
    #[must_use]
    pub const fn source_io(&self) -> &std::io::Error {
        match self {
            Self::NotCommitted { source, .. } | Self::DurabilityUncertain { source, .. } => source,
        }
    }
}

/// Atomically replaces `destination` with `bytes`, durably.
///
/// The temp sibling is created with mode 0600 and a name unique per call,
/// so concurrent writers to the same destination cannot interleave into
/// one another's file — they degrade to last-writer-wins with each
/// writer's own bytes intact.
///
/// # Errors
///
/// See [`AtomicWriteError`]: the two variants mean materially different
/// things and are worth matching on rather than collapsing.
pub fn write(destination: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
    let not_committed = |source| AtomicWriteError::NotCommitted {
        path: destination.to_path_buf(),
        source,
    };

    let Some(parent) = destination.parent() else {
        return Err(not_committed(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path has no parent: {}", destination.display()),
        )));
    };
    let temp_path = parent.join(format!(
        ".{}.{}.tmp",
        destination
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("atomic"),
        Uuid::new_v4()
    ));

    (|| {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        temp.write_all(bytes)?;
        temp.sync_all()?;
        drop(temp);
        fs::rename(&temp_path, destination)?;
        Ok::<(), std::io::Error>(())
    })()
    .map_err(|original| {
        // Leave no temp behind — the names are unique, so a leaked one is
        // never reused and would accumulate silently.
        match fs::remove_file(&temp_path) {
            Ok(()) => original,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => original,
            Err(cleanup) => std::io::Error::new(
                original.kind(),
                format!(
                    "{original}; failed to remove temporary file {}: {cleanup}",
                    temp_path.display()
                ),
            ),
        }
    })
    .map_err(not_committed)?;

    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| AtomicWriteError::DurabilityUncertain {
            path: destination.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replaced_file_holds_the_new_bytes_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.json");
        write(&path, b"first").unwrap();
        write(&path, b"second").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"second");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "record.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn a_failed_write_leaves_the_destination_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("record.json");
        // The parent does not exist, so the temp file cannot be created.
        let error = write(&path, b"payload").unwrap_err();

        assert!(matches!(error, AtomicWriteError::NotCommitted { .. }));
        assert!(!path.exists());
    }

    #[test]
    fn a_pathless_destination_is_reported_rather_than_panicking() {
        let error = write(Path::new("/"), b"payload").unwrap_err();
        assert!(matches!(error, AtomicWriteError::NotCommitted { .. }));
        assert_eq!(error.source_io().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn concurrent_writers_each_land_their_own_bytes_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contended.json");
        let long = vec![b'a'; 64 * 1024];
        let short = vec![b'b'; 64 * 1024];

        std::thread::scope(|scope| {
            for bytes in [&long, &short] {
                scope.spawn(|| {
                    for _ in 0..20 {
                        write(&path, bytes).unwrap();
                    }
                });
            }
        });

        // Whoever won, the file is one writer's payload in full — never a
        // splice of both, which is what a shared temp name would produce.
        let final_bytes = fs::read(&path).unwrap();
        assert!(final_bytes == long || final_bytes == short);
    }
}
