//! Persistence of live-settable agent configuration.
//!
//! Only `target` values are ever persisted here — `current` is always
//! derived fresh by the engine at each start (see
//! [`crate::state::AgentState`]). Settings aren't secret, unlike the
//! machine credential, so this is always a plain file — there's no
//! OS-keychain backend to fall back to, and no reason to refuse on
//! non-Unix platforms the way `credentials.rs` does.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{AgentConfig, DockerMode};
use crate::fsutil::write_owner_only;

/// Live-settable agent configuration, as last requested (`target`) — see
/// [`crate::state::AgentState`] for the paired `current` values the engine
/// actually runs with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedSettings {
    pub load_ceiling: f64,
    pub mem_floor_mib: u64,
    pub runner_image: String,
    pub gateway: String,
    pub docker_mode: DockerMode,
    /// Direct path to the runner entry point (`run.sh`/`run.cmd`), not its
    /// containing directory.
    pub runner_script: Option<PathBuf>,
}

impl From<&AgentConfig> for PersistedSettings {
    /// Seed on first-ever start: whatever the environment resolved to.
    fn from(config: &AgentConfig) -> Self {
        Self {
            load_ceiling: config.load_ceiling,
            mem_floor_mib: config.mem_floor_mib,
            runner_image: config.docker.runner_image.clone(),
            gateway: config.gateway.clone(),
            docker_mode: config.docker.mode,
            runner_script: config.runner_script.clone(),
        }
    }
}

/// Reads and writes [`PersistedSettings`] as an owner-only JSON file.
/// Cheap to clone (just the path) — `AgentSupervisor` and
/// `control::settings::SettingsService` each hold their own handle to the
/// same file rather than sharing one instance, since there's no in-memory
/// state here to keep in sync.
#[derive(Clone)]
pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load the persisted settings, or `None` if never written (first-ever
    /// start — the caller seeds from [`AgentConfig`] instead).
    pub fn load(&self) -> Result<Option<PersistedSettings>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let settings = serde_json::from_slice(&bytes)
                    .with_context(|| format!("malformed settings at {}", self.path.display()))?;
                Ok(Some(settings))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    /// Persist `settings`, replacing whatever was there before.
    pub fn store(&self, settings: &PersistedSettings) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(settings).context("serializing settings")?;
        // Write-then-rename so a crash mid-write can't leave a truncated
        // settings.json that fails to parse on the next start.
        let tmp = self.path.with_extension("json.tmp");
        write_owner_only(&tmp, &json)?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    reason = "settings values are moved/copied here, never computed, so exact \
              float equality is always well-defined — no rounding can occur"
)]
mod tests {
    use super::*;

    fn sample() -> PersistedSettings {
        PersistedSettings {
            load_ceiling: 0.75,
            mem_floor_mib: 4096,
            runner_image: "ghcr.io/actions/actions-runner:latest".to_owned(),
            gateway: "https://fleet.arcbox.dev".to_owned(),
            docker_mode: DockerMode::Auto,
            runner_script: Some(PathBuf::from("/opt/actions-runner/run.sh")),
        }
    }

    #[cfg(unix)]
    #[test]
    fn round_trips_at_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("fleet-settings-{}", std::process::id()));
        let path = dir.join("settings.json");
        let store = SettingsStore::new(path.clone());
        assert!(store.load().unwrap().is_none());

        let settings = sample();
        store.store(&settings).unwrap();

        let loaded = store.load().unwrap().expect("settings present");
        assert_eq!(loaded, settings);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn seeds_from_agent_config() {
        let config = AgentConfig {
            gateway: "https://example.test".to_owned(),
            runner_script: Some(PathBuf::from("/opt/runner/run.sh")),
            load_ceiling: 0.5,
            mem_floor_mib: 1024,
            data_dir: PathBuf::from("/tmp/does-not-matter"),
            docker: crate::config::DockerConfig {
                mode: DockerMode::Enabled,
                runner_image: "example/image:latest".to_owned(),
            },
            credential_store: crate::config::CredentialMode::File,
        };

        let seeded = PersistedSettings::from(&config);
        assert_eq!(seeded.gateway, config.gateway);
        assert_eq!(seeded.runner_script, config.runner_script);
        assert_eq!(seeded.load_ceiling, config.load_ceiling);
        assert_eq!(seeded.mem_floor_mib, config.mem_floor_mib);
        assert_eq!(seeded.docker_mode, config.docker.mode);
        assert_eq!(seeded.runner_image, config.docker.runner_image);
    }
}
