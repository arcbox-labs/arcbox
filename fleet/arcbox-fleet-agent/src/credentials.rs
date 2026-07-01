//! Persistence of the long-lived machine credential.
//!
//! The credential is written once at enrollment and read on every `run`. The
//! backend is chosen by [`CredentialMode`]: the OS keychain on macOS (login
//! Keychain) and Windows (Credential Manager), or an owner-only (`0600`) file on
//! Linux. The keychain item is access-controlled to this binary by the OS, so a
//! same-user process can't read it without a prompt — a boundary the file lacks.
//! The macOS login Keychain is unlocked by the user's login, so the agent must
//! run in that session; Linux has no keychain backend that fits a headless,
//! reboot-persistent agent, so it uses the file (encryption at rest there is the
//! deployment's job, via LUKS). See [`CredentialStore::new`].

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::CredentialMode;

/// The machine identity returned by `Enroll`, persisted by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Prefixed machine id (`fltm_...`).
    pub machine_id: String,
    /// Long-lived machine token, presented in `Attach` metadata.
    pub machine_token: String,
}

/// Reads and writes the [`Credential`] via the platform-appropriate backend.
pub enum CredentialStore {
    /// Owner-only JSON file in the data directory.
    File(FileStore),
    /// OS keychain: the login Keychain on macOS, Credential Manager on Windows.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    Keyring(KeyringStore),
}

impl CredentialStore {
    /// Select a backend from `mode` and the platform.
    ///
    /// `Auto` uses the OS keychain on macOS/Windows and the `path` file
    /// elsewhere; `Keyring` forces the keychain; `File` forces the file. `mode`
    /// is validated against the platform when parsed from the environment, so
    /// `Keyring` never reaches here on a platform without a keychain.
    pub fn new(mode: CredentialMode, path: PathBuf) -> Self {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        if matches!(mode, CredentialMode::Keyring | CredentialMode::Auto) {
            return Self::Keyring(KeyringStore);
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = mode;
        Self::File(FileStore { path })
    }

    /// Load the stored credential, or `None` if the host has not enrolled yet.
    pub fn load(&self) -> Result<Option<Credential>> {
        match self {
            Self::File(store) => store.load(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::Keyring(store) => store.load(),
        }
    }

    /// Persist the credential.
    pub fn store(&self, cred: &Credential) -> Result<()> {
        match self {
            Self::File(store) => store.store(cred),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::Keyring(store) => store.store(cred),
        }
    }
}

/// Stores the credential as an owner-only JSON file at a fixed path.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    fn load(&self) -> Result<Option<Credential>> {
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

    fn store(&self, cred: &Credential) -> Result<()> {
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
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
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

/// Refuse to persist the machine token via a file on platforms without
/// owner-only file permissions. On Windows the secure path is the OS keychain
/// (`ARCBOX_FLEET_CREDENTIAL_STORE=auto`, the default there); the file backend
/// has no ACL hardening, so writing the long-lived token at the default ACL
/// would leave it readable by other local accounts.
#[cfg(not(unix))]
fn write_private(_path: &std::path::Path, _bytes: &[u8]) -> Result<()> {
    anyhow::bail!(
        "file credential storage is not hardened on this platform; use the OS \
         keychain (ARCBOX_FLEET_CREDENTIAL_STORE=auto)"
    )
}

/// Stores the credential as a single JSON blob in the OS keychain.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub struct KeyringStore;

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl KeyringStore {
    /// Keychain service and account under which the credential blob is stored.
    const SERVICE: &'static str = "dev.arcbox.fleet-agent";
    const ACCOUNT: &'static str = "machine-credential";

    fn entry() -> Result<keyring::Entry> {
        keyring::Entry::new(Self::SERVICE, Self::ACCOUNT).context("opening OS keychain entry")
    }

    fn load(&self) -> Result<Option<Credential>> {
        match Self::entry()?.get_password() {
            Ok(json) => {
                let cred =
                    serde_json::from_str(&json).context("malformed credential in OS keychain")?;
                Ok(Some(cred))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e).context("reading credential from OS keychain"),
        }
    }

    fn store(&self, cred: &Credential) -> Result<()> {
        let json = serde_json::to_string(cred).context("serializing credential")?;
        Self::entry()?
            .set_password(&json)
            .context("writing credential to OS keychain")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The file backend is the default (and only) store on Linux, where the test
    // suite runs; the keychain backends are exercised on macOS/Windows builds.
    #[cfg(unix)]
    #[test]
    fn file_store_round_trips_at_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("fleet-cred-{}", std::process::id()));
        let path = dir.join("credentials.json");
        let store = CredentialStore::new(CredentialMode::File, path.clone());
        assert!(store.load().unwrap().is_none());

        let cred = Credential {
            machine_id: "fltm_test".into(),
            machine_token: "secret".into(),
        };
        store.store(&cred).unwrap();

        let loaded = store.load().unwrap().expect("credential present");
        assert_eq!(loaded.machine_id, cred.machine_id);
        assert_eq!(loaded.machine_token, cred.machine_token);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(dir);
    }
}
