//! Environment-driven agent configuration.
//!
//! Everything is sourced from the environment — there are no positional config
//! flags. The only CLI argument anywhere is the one-shot enrollment token.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tonic::transport::{ClientTlsConfig, Endpoint};

/// Production gateway endpoint. Overridable via `ARCBOX_FLEET_GATEWAY` for
/// local/e2e testing (e.g. `http://127.0.0.1:50061`).
pub const DEFAULT_GATEWAY: &str = "https://fleet.arcbox.dev";

const ENV_GATEWAY: &str = "ARCBOX_FLEET_GATEWAY";
const ENV_RUNNER_SCRIPT: &str = "ARCBOX_FLEET_RUNNER_SCRIPT";
const ENV_LOAD_CEILING: &str = "ARCBOX_FLEET_LOAD_CEILING";
const ENV_MEM_FLOOR_MIB: &str = "ARCBOX_FLEET_MEM_FLOOR_MIB";
const ENV_DATA_DIR: &str = "ARCBOX_FLEET_DATA_DIR";
const ENV_DOCKER: &str = "ARCBOX_FLEET_DOCKER";
const ENV_RUNNER_IMAGE: &str = "ARCBOX_FLEET_RUNNER_IMAGE";
const ENV_CREDENTIAL_STORE: &str = "ARCBOX_FLEET_CREDENTIAL_STORE";

/// Reject an offer when 1-minute load average per core exceeds this.
const DEFAULT_LOAD_CEILING: f64 = 0.9;
/// Reject an offer when available memory is below this many MiB.
const DEFAULT_MEM_FLOOR_MIB: u64 = 2048;
const DEFAULT_RUNNER_IMAGE: &str = "ghcr.io/actions/actions-runner:latest";

/// Wire-protocol version this agent speaks; the gateway rejects a mismatch.
pub const PROTOCOL_VERSION: u32 = 1;

/// Whether Docker-based Linux job execution is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DockerMode {
    /// Probe the Docker socket at startup; proceed without Docker if unavailable.
    Auto,
    /// Require Docker; fail startup if the socket is unreachable.
    Enabled,
    /// Never use Docker, even if available.
    Disabled,
}

/// Where the long-lived machine credential is persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMode {
    /// OS keychain on macOS (login Keychain) and Windows (Credential Manager);
    /// the owner-only data-dir file on Linux. On macOS the agent must run in the
    /// user's session, where the login Keychain is unlocked.
    Auto,
    /// Force the OS keychain. Supported on macOS and Windows; errors on Linux.
    Keyring,
    /// Force the data-dir file (`0600` on Unix).
    File,
}

/// Docker-specific configuration for running Linux jobs in containers.
#[derive(Debug, Clone)]
pub struct DockerConfig {
    pub mode: DockerMode,
    /// Container image used for Linux runner jobs.
    pub runner_image: String,
}

/// Resolved agent configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Gateway endpoint URI (scheme selects transport: `https` → TLS, `http` → h2c).
    pub gateway: String,
    /// Direct path to the pre-installed GitHub Actions runner's entry point
    /// (`run.sh` on Unix, `run.cmd` on Windows) — not its containing
    /// directory. `None` until set; required only by the `run` command.
    pub runner_script: Option<PathBuf>,
    /// Reject an offer when 1-minute load average per core exceeds this.
    pub load_ceiling: f64,
    /// Reject an offer when available memory (MiB) is below this.
    pub mem_floor_mib: u64,
    /// Agent data directory (credentials, logs). Defaults to `~/.arcbox/fleet`.
    pub data_dir: PathBuf,
    /// Docker runtime configuration for Linux jobs.
    pub docker: DockerConfig,
    /// Where the machine credential is persisted (OS keychain vs file).
    pub credential_store: CredentialMode,
}

impl AgentConfig {
    /// Build the configuration from environment variables, applying defaults.
    pub fn from_env() -> Result<Self> {
        let gateway = std::env::var(ENV_GATEWAY).unwrap_or_else(|_| DEFAULT_GATEWAY.to_string());

        let runner_script = std::env::var_os(ENV_RUNNER_SCRIPT).map(PathBuf::from);

        let load_ceiling = match std::env::var(ENV_LOAD_CEILING) {
            Ok(v) => parse_load_ceiling(&v)?,
            Err(_) => DEFAULT_LOAD_CEILING,
        };
        let mem_floor_mib = match std::env::var(ENV_MEM_FLOOR_MIB) {
            Ok(v) => v
                .parse()
                .with_context(|| format!("{ENV_MEM_FLOOR_MIB} must be a non-negative integer"))?,
            Err(_) => DEFAULT_MEM_FLOOR_MIB,
        };

        let data_dir = match std::env::var_os(ENV_DATA_DIR) {
            Some(dir) => PathBuf::from(dir),
            None => default_data_dir()?,
        };

        let docker_mode = match std::env::var(ENV_DOCKER).as_deref() {
            Ok("true") => DockerMode::Enabled,
            Ok("false") => DockerMode::Disabled,
            Ok("auto") | Err(_) => DockerMode::Auto,
            Ok(other) => {
                anyhow::bail!("{ENV_DOCKER} must be 'auto', 'true', or 'false', got '{other}'")
            }
        };
        let runner_image =
            std::env::var(ENV_RUNNER_IMAGE).unwrap_or_else(|_| DEFAULT_RUNNER_IMAGE.to_string());

        let credential_store = match std::env::var(ENV_CREDENTIAL_STORE).as_deref() {
            Ok("keyring") => CredentialMode::Keyring,
            Ok("file") => CredentialMode::File,
            Ok("auto") | Err(_) => CredentialMode::Auto,
            Ok(other) => {
                anyhow::bail!(
                    "{ENV_CREDENTIAL_STORE} must be 'auto', 'keyring', or 'file', got '{other}'"
                )
            }
        };
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        if credential_store == CredentialMode::Keyring {
            anyhow::bail!(
                "{ENV_CREDENTIAL_STORE}=keyring is only supported on macOS and Windows; \
                 use 'file' (the default on Linux)"
            );
        }

        Ok(Self {
            gateway,
            runner_script,
            load_ceiling,
            mem_floor_mib,
            data_dir,
            docker: DockerConfig {
                mode: docker_mode,
                runner_image,
            },
            credential_store,
        })
    }

    /// Path to the persisted machine credential.
    pub fn credentials_path(&self) -> PathBuf {
        self.data_dir.join("credentials.json")
    }

    /// Path to the local control-plane Unix socket.
    pub fn control_socket_path(&self) -> PathBuf {
        self.data_dir.join("agent.sock")
    }

    /// Path to the persisted, live-settable configuration.
    pub fn settings_path(&self) -> PathBuf {
        self.data_dir.join("settings.json")
    }

    /// Build a gateway [`Endpoint`] for an arbitrary `gateway` URI, enabling
    /// TLS for `https` URIs. Used to connect against the persisted
    /// settings' current `gateway`, which may override this config's
    /// default (see [`crate::state::AgentState::gateway_current`]).
    pub fn endpoint_for(&self, gateway: &str) -> Result<Endpoint> {
        let endpoint = Endpoint::from_shared(gateway.to_owned())
            .with_context(|| format!("invalid gateway URI: {gateway}"))?;

        if gateway.starts_with("https://") {
            // Bundled webpki roots keep trust uniform across macOS/Linux/Windows.
            return endpoint
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .context("failed to configure TLS");
        }
        Ok(endpoint)
    }
}

/// Parse `ARCBOX_FLEET_LOAD_CEILING`: a positive, finite load-per-core bound.
/// Non-finite values must be rejected here: every admission comparison against
/// `NaN` is false, which would silently disable the load gate, and `inf` never
/// rejects — a misconfiguration should fail startup, not neuter admission.
fn parse_load_ceiling(v: &str) -> Result<f64> {
    let n: f64 = v
        .parse()
        .with_context(|| format!("{ENV_LOAD_CEILING} must be a positive finite number"))?;
    if !(n.is_finite() && n > 0.0) {
        anyhow::bail!("{ENV_LOAD_CEILING} must be a positive finite number, got {n}");
    }
    Ok(n)
}

/// `~/.arcbox/fleet`, resolved from the user's home directory.
fn default_data_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".arcbox").join("fleet"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::float_cmp,
        reason = "1.5 parses exactly; no arithmetic involved"
    )]
    fn load_ceiling_requires_positive_finite() {
        assert_eq!(parse_load_ceiling("1.5").unwrap(), 1.5);
        for bad in ["0", "-1.5", "NaN", "inf", "-inf", "nonsense"] {
            assert!(parse_load_ceiling(bad).is_err(), "accepted {bad}");
        }
    }
}
