//! Atomic file replacement with a durable rename.
//!
//! Every durable record this crate writes — sandbox records, template
//! catalog entries — goes through here: write a private temp sibling,
//! `fsync` it, rename over the destination, then `fsync` the directory so
//! the rename itself survives a crash.
//!
//! The two outcomes are kept apart on purpose. A failure *before* the
//! rename means the destination is untouched and the caller has simply
//! failed. A failure of the final directory `fsync` means the new content
//! is already visible but might not survive power loss — recoverable, and
//! callers differ on whether that is worth an error
//! ([`write`] raises it; the sandbox record store reports it as a
//! warning and carries on).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use uuid::Uuid;

use crate::error::{Result, VmmError};

/// How an atomic write failed.
#[derive(Debug)]
pub enum AtomicWriteError {
    /// The destination was never replaced; the temp file is cleaned up.
    NotCommitted(std::io::Error),
    /// The rename landed, but the directory `fsync` confirming it did not.
    DurabilityUncertain(std::io::Error),
}

/// Atomically replaces one file, reporting the two failure modes apart.
pub fn write_reporting_durability(
    destination: &Path,
    bytes: &[u8],
) -> std::result::Result<(), AtomicWriteError> {
    let parent = destination.parent().ok_or_else(|| {
        AtomicWriteError::NotCommitted(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path has no parent: {}", destination.display()),
        ))
    })?;
    let temp_path = parent.join(format!(
        ".{}.{}.tmp",
        destination
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("sandbox"),
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
        let cleanup = fs::remove_file(&temp_path);
        match cleanup {
            Ok(()) => AtomicWriteError::NotCommitted(original),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                AtomicWriteError::NotCommitted(original)
            }
            Err(cleanup_error) => AtomicWriteError::NotCommitted(std::io::Error::new(
                original.kind(),
                format!(
                    "{original}; failed to remove temporary file {}: {cleanup_error}",
                    temp_path.display()
                ),
            )),
        }
    })?;

    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(AtomicWriteError::DurabilityUncertain)
}

/// Atomically persists a non-lifecycle file, treating unconfirmed
/// durability as an error.
pub fn write(destination: &Path, bytes: &[u8]) -> Result<()> {
    match write_reporting_durability(destination, bytes) {
        Ok(()) => Ok(()),
        Err(AtomicWriteError::NotCommitted(error)) => Err(error.into()),
        Err(AtomicWriteError::DurabilityUncertain(error)) => Err(VmmError::Unavailable(format!(
            "{} was renamed but directory durability is unconfirmed: {error}",
            destination.display()
        ))),
    }
}
