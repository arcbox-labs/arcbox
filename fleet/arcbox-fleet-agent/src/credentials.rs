//! Persistence of the long-lived machine credential.
//!
//! The credential is written once at enrollment and read on every `run`. The
//! backend is chosen by [`CredentialMode`]: the OS keychain (login Keychain) on
//! macOS, or an owner-only (`0600`) file on Linux. The keychain item is
//! access-controlled to this binary by the OS, so a same-user process can't
//! read it without a prompt — a boundary the file lacks. The macOS login
//! Keychain is unlocked by the user's login, so the agent must run in that
//! session; Linux has no keychain backend that fits a headless,
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
    /// OS keychain: the login Keychain on macOS.
    #[cfg(target_os = "macos")]
    Keyring(KeyringStore),
}

impl CredentialStore {
    /// Select a backend from `mode` and the platform.
    ///
    /// `Auto` uses the OS keychain on macOS and the `path` file elsewhere;
    /// `Keyring` forces the keychain; `File` forces the file. `mode` is
    /// validated against the platform when parsed from the environment, so
    /// `Keyring` never reaches here on a platform without a keychain.
    ///
    /// `gateway` scopes the credential to the environment it was enrolled
    /// against: the keychain keys its entry by gateway URI, so credentials for
    /// different gateways (production, staging, local e2e) coexist instead of
    /// silently overwriting each other. The file backend is scoped by `path`
    /// (per data dir) instead.
    pub fn new(mode: CredentialMode, path: PathBuf, gateway: &str) -> Self {
        #[cfg(target_os = "macos")]
        if matches!(mode, CredentialMode::Keyring | CredentialMode::Auto) {
            return Self::Keyring(KeyringStore {
                account: gateway.to_owned(),
            });
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (mode, gateway);
        Self::File(FileStore { path })
    }

    /// Load the stored credential, or `None` if the host has not enrolled yet.
    pub fn load(&self) -> Result<Option<Credential>> {
        match self {
            Self::File(store) => store.load(),
            #[cfg(target_os = "macos")]
            Self::Keyring(store) => store.load(),
        }
    }

    /// Persist the credential.
    pub fn store(&self, cred: &Credential) -> Result<()> {
        match self {
            Self::File(store) => store.store(cred),
            #[cfg(target_os = "macos")]
            Self::Keyring(store) => store.store(cred),
        }
    }

    /// Remove the persisted credential, if any. A no-op, not an error, when
    /// none is stored — `Disconnect` clears unconditionally rather than
    /// first checking `load()`.
    pub fn clear(&self) -> Result<()> {
        match self {
            Self::File(store) => store.clear(),
            #[cfg(target_os = "macos")]
            Self::Keyring(store) => store.clear(),
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
        // `write_private` refuses a plaintext write on non-Unix, so the raw
        // token never lands in an unhardened file; on Unix it's `0600` from
        // creation and the rename preserves that mode.
        crate::fsutil::write_json_atomic(&self.path, cred, write_private)
    }

    fn clear(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {}", self.path.display())),
        }
    }
}

/// Write `bytes` to `path`, owner-only (`0600`) from creation on Unix — every
/// supported target (macOS, Linux) is Unix, so this is the only backend.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    crate::fsutil::write_owner_only(path, bytes)
}

/// Stores the credential as a single JSON blob in the OS keychain, one entry
/// per gateway (the account is the gateway URI), so enrolling against another
/// environment never clobbers this one's credential.
#[cfg(target_os = "macos")]
pub struct KeyringStore {
    /// Keychain account: the gateway URI this credential enrolls against.
    account: String,
}

#[cfg(target_os = "macos")]
impl KeyringStore {
    /// Keychain service under which every credential entry is stored.
    const SERVICE: &'static str = "dev.arcbox.fleet-agent";

    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(Self::SERVICE, &self.account).context("opening OS keychain entry")
    }

    fn load(&self) -> Result<Option<Credential>> {
        match self.entry()?.get_password() {
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
        self.entry()?
            .set_password(&json)
            .context("writing credential to OS keychain")
    }

    fn clear(&self) -> Result<()> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e).context("deleting credential from OS keychain"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The file backend is the default (and only) store on Linux, where the test
    // suite runs; the keychain backend is exercised on macOS builds.
    #[cfg(unix)]
    #[test]
    fn file_store_round_trips_at_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("fleet-cred-{}", std::process::id()));
        let path = dir.join("credentials.json");
        let store = CredentialStore::new(
            CredentialMode::File,
            path.clone(),
            "https://fleet.arcbox.dev",
        );
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

        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
        // Clearing an already-absent credential is a no-op, not an error.
        store.clear().unwrap();

        let _ = std::fs::remove_dir_all(dir);
    }
}
