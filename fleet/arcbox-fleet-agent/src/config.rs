//! Environment-driven agent configuration.
//!
//! Everything is sourced from the environment — there are no positional config
//! flags. The only CLI argument anywhere is the one-shot enrollment token.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tonic::transport::{ClientTlsConfig, Endpoint};

/// Production gateway endpoint. Overridable via `ARCBOX_FLEET_GATEWAY` for
/// local/e2e testing (e.g. `http://127.0.0.1:50061`).
pub const DEFAULT_GATEWAY: &str = "https://fleet.arcbox.dev";

const ENV_GATEWAY: &str = "ARCBOX_FLEET_GATEWAY";
const ENV_RUNNER_DIR: &str = "ARCBOX_FLEET_RUNNER_DIR";
const ENV_MAX_CONCURRENT: &str = "ARCBOX_FLEET_MAX_CONCURRENT";
const ENV_DATA_DIR: &str = "ARCBOX_FLEET_DATA_DIR";

const DEFAULT_MAX_CONCURRENT: usize = 2;

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
}

impl AgentConfig {
    /// Build the configuration from environment variables, applying defaults.
    pub fn from_env() -> Result<Self> {
        let gateway = std::env::var(ENV_GATEWAY).unwrap_or_else(|_| DEFAULT_GATEWAY.to_string());

        let runner_dir = std::env::var_os(ENV_RUNNER_DIR).map(PathBuf::from);

        let max_concurrent = match std::env::var(ENV_MAX_CONCURRENT) {
            Ok(v) => v
                .parse()
                .with_context(|| format!("{ENV_MAX_CONCURRENT} must be a positive integer"))?,
            Err(_) => DEFAULT_MAX_CONCURRENT,
        };

        let data_dir = match std::env::var_os(ENV_DATA_DIR) {
            Some(dir) => PathBuf::from(dir),
            None => default_data_dir()?,
        };

        Ok(Self {
            gateway,
            runner_dir,
            max_concurrent,
            data_dir,
        })
    }

    /// The runner directory, or a clear error instructing the operator to set it.
    pub fn require_runner_dir(&self) -> Result<&Path> {
        self.runner_dir.as_deref().with_context(|| {
            format!("{ENV_RUNNER_DIR} is not set (path to the installed GitHub Actions runner)")
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
