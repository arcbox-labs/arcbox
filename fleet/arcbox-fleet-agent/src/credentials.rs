//! Persistence of the long-lived machine credential.
//!
//! The credential is written once at enrollment and read on every `run`. On
//! Unix the file is locked down to `0600`; Windows ACL hardening is deferred.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The machine identity returned by `Enroll`, persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Prefixed machine id (`fltm_...`).
    pub machine_id: String,
    /// Long-lived machine token, presented in `Attach` metadata.
    pub machine_token: String,
}

/// Reads and writes [`Credential`] at a fixed path.
pub struct CredentialStore {
    path: PathBuf,
}

impl CredentialStore {
    /// Create a store backed by `path` (typically `<data_dir>/credentials.json`).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Load the stored credential, or `None` if the host has not enrolled yet.
    pub fn load(&self) -> Result<Option<Credential>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let cred = serde_json::from_slice(&bytes)
                    .with_context(|| format!("malformed credential at {}", self.path.display()))?;
                Ok(Some(cred))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    /// Persist the credential, creating the parent directory and restricting
    /// permissions to the owner.
    pub fn store(&self, cred: &Credential) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(cred).context("serializing credential")?;
        // Write-then-rename so a crash mid-write can't leave a truncated
        // credentials.json that fails to parse and strands the host unenrolled.
        // The temp file is created `0600` from the open(2) call, so the raw
        // token is never briefly world-readable — not in the temp file and not
        // (via rename, which preserves the mode) in the final path.
        let tmp = self.path.with_extension("json.tmp");
        write_private(&tmp, &json)?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

/// Write `bytes` to `path`, owner-only (`0600`) from creation on Unix.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    // `mode` only takes effect when this call creates the file; a leftover temp
    // from a crashed run keeps its old mode, so fchmod the open handle as a
    // backstop (operating on the fd, never racing a path lookup).
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

/// Windows ACL hardening is deferred to a later slice.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_credential() {
        let dir = std::env::temp_dir().join(format!("fleet-cred-{}", std::process::id()));
        let store = CredentialStore::new(dir.join("credentials.json"));
        assert!(store.load().unwrap().is_none());

        let cred = Credential {
            machine_id: "fltm_test".into(),
            machine_token: "secret".into(),
        };
        store.store(&cred).unwrap();

        let loaded = store.load().unwrap().expect("credential present");
        assert_eq!(loaded.machine_id, cred.machine_id);
        assert_eq!(loaded.machine_token, cred.machine_token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = std::fs::remove_dir_all(dir);
    }
}
