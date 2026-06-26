//! Docker context management.
//!
//! Manages Docker CLI contexts to allow transparent use of `ArcBox`
//! as a Docker backend.
//!
//! ## Docker Context Storage
//!
//! Docker stores contexts in `~/.docker/contexts/`:
//!
//! ```text
//! ~/.docker/
//! ├── config.json              # Contains currentContext
//! └── contexts/
//!     └── meta/
//!         └── <sha256-hash>/
//!             └── meta.json    # Context metadata
//! ```

use crate::error::{DockerError, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// `ArcBox` context name.
pub const ARCBOX_CONTEXT_NAME: &str = "arcbox";

mod types;

pub use types::{
    ContextEndpoints, ContextMeta, ContextMetadata, ContextStatus, DockerConfig, DockerEndpoint,
};

/// Manages Docker CLI contexts for `ArcBox` integration.
pub struct DockerContextManager {
    /// `ArcBox` socket path.
    socket_path: PathBuf,
    /// Docker context name managed by this instance.
    context_name: String,
    /// Docker config directory (~/.docker).
    docker_config_dir: PathBuf,
}

impl DockerContextManager {
    /// Creates a new context manager.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the `ArcBox` Docker-compatible socket
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined.
    pub fn new(socket_path: PathBuf) -> Result<Self> {
        Self::new_with_context_name(socket_path, ARCBOX_CONTEXT_NAME)
    }

    /// Creates a new context manager for a specific Docker context name.
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined.
    pub fn new_with_context_name(
        socket_path: PathBuf,
        context_name: impl Into<String>,
    ) -> Result<Self> {
        let docker_config_dir = dirs::home_dir()
            .ok_or_else(|| DockerError::Context("cannot find home directory".to_string()))?
            .join(".docker");

        Ok(Self {
            socket_path,
            context_name: context_name.into(),
            docker_config_dir,
        })
    }

    /// Creates a new context manager with a custom Docker config directory.
    #[must_use]
    pub fn with_config_dir(socket_path: PathBuf, docker_config_dir: PathBuf) -> Self {
        Self::with_context_name_and_config_dir(socket_path, ARCBOX_CONTEXT_NAME, docker_config_dir)
    }

    /// Creates a new context manager with a custom context name and Docker config directory.
    #[must_use]
    pub fn with_context_name_and_config_dir(
        socket_path: PathBuf,
        context_name: impl Into<String>,
        docker_config_dir: PathBuf,
    ) -> Self {
        Self {
            socket_path,
            context_name: context_name.into(),
            docker_config_dir,
        }
    }

    /// Returns the socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the Docker config directory.
    #[must_use]
    pub fn docker_config_dir(&self) -> &Path {
        &self.docker_config_dir
    }

    /// Returns the Docker context name managed by this instance.
    #[must_use]
    pub fn context_name(&self) -> &str {
        &self.context_name
    }

    /// Checks if the `ArcBox` context exists.
    #[must_use]
    pub fn context_exists(&self) -> bool {
        self.context_meta_path().exists()
    }

    /// Checks if `ArcBox` is the current default context.
    ///
    /// # Errors
    ///
    /// Returns an error if Docker config cannot be read or parsed.
    pub fn is_default(&self) -> Result<bool> {
        let config = self.read_docker_config()?;
        Ok(config.current_context.as_deref() == Some(self.context_name()))
    }

    /// Gets the current default context name.
    ///
    /// # Errors
    ///
    /// Returns an error if Docker config cannot be read or parsed.
    pub fn current_context(&self) -> Result<Option<String>> {
        let config = self.read_docker_config()?;
        Ok(config.current_context)
    }

    /// Creates the `ArcBox` Docker context.
    ///
    /// # Errors
    ///
    /// Returns an error if the context cannot be created.
    pub fn create_context(&self) -> Result<()> {
        // Ensure directories exist.
        let meta_dir = self.context_dir();
        fs::create_dir_all(&meta_dir).map_err(|e| {
            DockerError::Context(format!("failed to create context directory: {e}"))
        })?;

        // Create context metadata.
        let meta = ContextMeta {
            name: self.context_name.clone(),
            metadata: ContextMetadata {
                description: "ArcBox Container Runtime".to_string(),
            },
            endpoints: ContextEndpoints {
                docker: DockerEndpoint {
                    host: format!("unix://{}", self.socket_path.display()),
                    skip_tls_verify: false,
                },
            },
        };

        // Write meta.json.
        let meta_path = self.context_meta_path();
        let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| {
            DockerError::Context(format!("failed to serialize context metadata: {e}"))
        })?;

        fs::write(&meta_path, meta_json)
            .map_err(|e| DockerError::Context(format!("failed to write context metadata: {e}")))?;

        info!(context = %self.context_name, "Created Docker context");
        debug!(path = %meta_path.display(), "Context metadata written");

        Ok(())
    }

    /// Removes the `ArcBox` Docker context.
    ///
    /// # Errors
    ///
    /// Returns an error if the context cannot be removed.
    pub fn remove_context(&self) -> Result<()> {
        // First, restore default if we're the current context.
        if self.is_default()? {
            self.restore_default()?;
        }

        // Remove context directory.
        let context_dir = self.context_dir();
        if context_dir.exists() {
            fs::remove_dir_all(&context_dir).map_err(|e| {
                DockerError::Context(format!("failed to remove context directory: {e}"))
            })?;

            info!(context = %self.context_name, "Removed Docker context");
        } else {
            debug!("Context directory does not exist, nothing to remove");
        }

        Ok(())
    }

    /// Sets `ArcBox` as the default Docker context.
    ///
    /// Saves the previous default context so it can be restored later.
    ///
    /// # Errors
    ///
    /// Returns an error if the default cannot be set.
    pub fn set_default(&self) -> Result<()> {
        // Ensure context exists.
        if !self.context_exists() {
            return Err(DockerError::Context(
                "ArcBox context does not exist, run create_context first".to_string(),
            ));
        }

        // Read current config.
        let mut config = self.read_docker_config()?;

        // Save previous context if it's not already arcbox.
        if let Some(ref current) = config.current_context {
            if current != self.context_name() {
                self.save_previous_context(current)?;
            }
        }

        // Set this context as default.
        config.current_context = Some(self.context_name.clone());
        self.write_docker_config(&config)?;

        info!(context = %self.context_name, "Set Docker context as default");
        Ok(())
    }

    /// Restores the previous default Docker context.
    ///
    /// # Errors
    ///
    /// Returns an error if the default cannot be restored.
    pub fn restore_default(&self) -> Result<()> {
        // Read previous context.
        let previous = self.read_previous_context()?;

        // Read current config.
        let mut config = self.read_docker_config()?;

        // Restore previous context (or clear if there was none).
        config.current_context.clone_from(&previous);
        self.write_docker_config(&config)?;

        // Clean up saved previous context.
        let _ = fs::remove_file(self.previous_context_path());

        if let Some(name) = previous {
            info!("Restored default Docker context to '{name}'");
        } else {
            info!("Cleared default Docker context");
        }

        Ok(())
    }

    /// Enables `ArcBox` Docker integration.
    ///
    /// Always creates or updates the context to ensure the socket path is current,
    /// then sets it as default. This handles upgrades where the socket path changes
    /// (e.g. `~/.arcbox/docker.sock` → `~/.arcbox/run/docker.sock`).
    ///
    /// # Errors
    ///
    /// Returns an error if the integration cannot be enabled.
    pub fn enable(&self) -> Result<()> {
        self.create_context()?;
        self.set_default()?;
        Ok(())
    }

    /// Disables `ArcBox` Docker integration.
    ///
    /// Restores the previous default context but keeps the `ArcBox` context.
    ///
    /// # Errors
    ///
    /// Returns an error if the integration cannot be disabled.
    pub fn disable(&self) -> Result<()> {
        if self.is_default()? {
            self.restore_default()?;
        }
        Ok(())
    }

    /// Gets the status of `ArcBox` Docker integration.
    #[must_use]
    pub fn status(&self) -> ContextStatus {
        ContextStatus {
            context_exists: self.context_exists(),
            is_default: self.is_default().unwrap_or(false),
            socket_path: self.socket_path.clone(),
            socket_exists: self.socket_path.exists(),
        }
    }

    /// Computes SHA256 hash of context name for directory name.
    fn context_hash(name: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Returns path to the context directory.
    fn context_dir(&self) -> PathBuf {
        let hash = Self::context_hash(&self.context_name);
        self.docker_config_dir
            .join("contexts")
            .join("meta")
            .join(hash)
    }

    /// Returns path to the context meta.json file.
    fn context_meta_path(&self) -> PathBuf {
        self.context_dir().join("meta.json")
    }

    /// Returns path to the Docker config.json file.
    fn config_path(&self) -> PathBuf {
        self.docker_config_dir.join("config.json")
    }

    /// Returns path to the saved previous context file.
    fn previous_context_path(&self) -> PathBuf {
        self.docker_config_dir
            .join(format!(".{}-previous-context", self.context_name))
    }

    /// Reads the Docker config.json file.
    fn read_docker_config(&self) -> Result<DockerConfig> {
        let config_path = self.config_path();

        if !config_path.exists() {
            return Ok(DockerConfig::default());
        }

        let data = fs::read_to_string(&config_path)
            .map_err(|e| DockerError::Context(format!("failed to read config.json: {e}")))?;

        serde_json::from_str(&data)
            .map_err(|e| DockerError::Context(format!("failed to parse config.json: {e}")))
    }

    /// Writes the Docker config.json file.
    fn write_docker_config(&self, config: &DockerConfig) -> Result<()> {
        // Ensure directory exists.
        fs::create_dir_all(&self.docker_config_dir).map_err(|e| {
            DockerError::Context(format!("failed to create .docker directory: {e}"))
        })?;

        let config_path = self.config_path();
        let json = serde_json::to_string_pretty(config)
            .map_err(|e| DockerError::Context(format!("failed to serialize config.json: {e}")))?;

        fs::write(&config_path, json)
            .map_err(|e| DockerError::Context(format!("failed to write config.json: {e}")))?;

        debug!(path = %config_path.display(), "Docker config written");
        Ok(())
    }

    /// Saves the previous context name.
    fn save_previous_context(&self, name: &str) -> Result<()> {
        let path = self.previous_context_path();
        fs::write(&path, name)
            .map_err(|e| DockerError::Context(format!("failed to save previous context: {e}")))?;
        debug!(previous = %name, "Saved previous context");
        Ok(())
    }

    /// Reads the saved previous context name.
    fn read_previous_context(&self) -> Result<Option<String>> {
        let path = self.previous_context_path();

        if !path.exists() {
            return Ok(None);
        }

        let name = fs::read_to_string(&path)
            .map_err(|e| DockerError::Context(format!("failed to read previous context: {e}")))?
            .trim()
            .to_string();

        if name.is_empty() {
            Ok(None)
        } else {
            Ok(Some(name))
        }
    }
}

#[cfg(test)]
mod tests;
