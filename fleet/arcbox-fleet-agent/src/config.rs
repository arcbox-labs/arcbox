//! Environment-driven agent configuration.
//!
//! Everything is sourced from the environment — there are no positional config
//! flags. The only CLI argument anywhere is the one-shot enrollment token.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tonic::transport::{ClientTlsConfig, Endpoint};

/// Production gateway endpoint. Overridable via `ARCBOX_FLEET_GATEWAY` for
/// local/e2e testing (e.g. `http://127.0.0.1:50061`).
pub const DEFAULT_GATEWAY: &str = "https://fleet.arcbox.dev";

const ENV_GATEWAY: &str = "ARCBOX_FLEET_GATEWAY";
const ENV_RUNNER_DIR: &str = "ARCBOX_FLEET_RUNNER_DIR";
const ENV_MAX_CONCURRENT: &str = "ARCBOX_FLEET_MAX_CONCURRENT";
const ENV_DATA_DIR: &str = "ARCBOX_FLEET_DATA_DIR";
const ENV_DOCKER: &str = "ARCBOX_FLEET_DOCKER";
const ENV_RUNNER_IMAGE: &str = "ARCBOX_FLEET_RUNNER_IMAGE";

const DEFAULT_MAX_CONCURRENT: usize = 2;
const DEFAULT_RUNNER_IMAGE: &str = "ghcr.io/actions/runner:latest";

/// Whether Docker-based Linux job execution is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerMode {
    /// Probe the Docker socket at startup; proceed without Docker if unavailable.
    Auto,
    /// Require Docker; fail startup if the socket is unreachable.
    Enabled,
    /// Never use Docker, even if available.
    Disabled,
}

/// Docker-specific configuration for running Linux jobs in containers.
#[derive(Debug, Clone)]
pub struct DockerConfig {
    pub mode: DockerMode,
    /// Container image used for Linux runner jobs when the platform sends no
    /// image (empty `ProvisionRunner.image`).
    pub runner_image: String,
}

/// Resolved agent configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Gateway endpoint URI (scheme selects transport: `https` → TLS, `http` → h2c).
    pub gateway: String,
    /// Directory holding the pre-installed GitHub Actions runner (`run.sh`/`run.cmd`).
    /// `None` until set; required only by the `run` command.
    pub runner_dir: Option<PathBuf>,
    /// Maximum number of concurrently executing runner jobs.
    pub max_concurrent: usize,
    /// Agent data directory (credentials, logs). Defaults to `~/.arcbox/fleet`.
    pub data_dir: PathBuf,
    /// Docker runtime configuration for Linux jobs.
    pub docker: DockerConfig,
}

impl AgentConfig {
    /// Build the configuration from environment variables, applying defaults.
    pub fn from_env() -> Result<Self> {
        let gateway = std::env::var(ENV_GATEWAY).unwrap_or_else(|_| DEFAULT_GATEWAY.to_string());

        let runner_dir = std::env::var_os(ENV_RUNNER_DIR).map(PathBuf::from);

        let max_concurrent = match std::env::var(ENV_MAX_CONCURRENT) {
            Ok(v) => {
                let n: usize = v
                    .parse()
                    .with_context(|| format!("{ENV_MAX_CONCURRENT} must be a positive integer"))?;
                if n == 0 {
                    anyhow::bail!("{ENV_MAX_CONCURRENT} must be a positive integer, got 0");
                }
                n
            }
            Err(_) => DEFAULT_MAX_CONCURRENT,
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

        Ok(Self {
            gateway,
            runner_dir,
            max_concurrent,
            data_dir,
            docker: DockerConfig {
                mode: docker_mode,
                runner_image,
            },
        })
    }

    /// Path to the persisted machine credential.
    pub fn credentials_path(&self) -> PathBuf {
        self.data_dir.join("credentials.json")
    }

    /// Build a gateway [`Endpoint`], enabling TLS for `https` URIs.
    pub fn endpoint(&self) -> Result<Endpoint> {
        let endpoint = Endpoint::from_shared(self.gateway.clone())
            .with_context(|| format!("invalid gateway URI: {}", self.gateway))?;

        if self.gateway.starts_with("https://") {
            // Bundled webpki roots keep trust uniform across macOS/Linux/Windows.
            return endpoint
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .context("failed to configure TLS");
        }
        Ok(endpoint)
    }
}

/// `~/.arcbox/fleet`, resolved from the user's home directory.
fn default_data_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".arcbox").join("fleet"))
}
