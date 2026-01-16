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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// `ArcBox` context name.
pub const ARCBOX_CONTEXT_NAME: &str = "arcbox";

/// Docker context metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContextMeta {
    /// Context name.
    pub name: String,
    /// Context metadata.
    pub metadata: ContextMetadata,
    /// Endpoints configuration.
    pub endpoints: ContextEndpoints,
}

/// Context metadata fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContextMetadata {
    /// Context description.
    pub description: String,
}

/// Context endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEndpoints {
    /// Docker endpoint.
    pub docker: DockerEndpoint,
}

/// Docker endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DockerEndpoint {
    /// Host URL (e.g., `unix:///path/to/socket`).
    pub host: String,
    /// Skip TLS verification.
    #[serde(default, rename = "SkipTLSVerify")]
    pub skip_tls_verify: bool,
}

/// Docker config.json structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerConfig {
    /// Current context name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_context: Option<String>,
    /// Other fields preserved as-is.
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

/// Manages Docker CLI contexts for `ArcBox` integration.
pub struct DockerContextManager {
    /// `ArcBox` socket path.
    socket_path: PathBuf,
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
        let docker_config_dir = dirs::home_dir()
            .ok_or_else(|| DockerError::Context("cannot find home directory".to_string()))?
            .join(".docker");

        Ok(Self {
            socket_path,
            docker_config_dir,
        })
    }

    /// Creates a new context manager with a custom Docker config directory.
    #[must_use]
    pub fn with_config_dir(socket_path: PathBuf, docker_config_dir: PathBuf) -> Self {
        Self {
            socket_path,
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

    /// Checks if the `ArcBox` context exists.
    #[must_use]
    pub fn context_exists(&self) -> bool {
        self.context_meta_path().exists()
    }

    /// Checks if `ArcBox` is the current default context.
    pub fn is_default(&self) -> Result<bool> {
        let config = self.read_docker_config()?;
        Ok(config.current_context.as_deref() == Some(ARCBOX_CONTEXT_NAME))
    }

    /// Gets the current default context name.
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
            name: ARCBOX_CONTEXT_NAME.to_string(),
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

        info!("Created Docker context '{ARCBOX_CONTEXT_NAME}'");
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

            info!("Removed Docker context '{ARCBOX_CONTEXT_NAME}'");
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
            if current != ARCBOX_CONTEXT_NAME {
                self.save_previous_context(current)?;
            }
        }

        // Set arcbox as default.
        config.current_context = Some(ARCBOX_CONTEXT_NAME.to_string());
        self.write_docker_config(&config)?;

        info!("Set '{ARCBOX_CONTEXT_NAME}' as default Docker context");
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
        config.current_context = previous.clone();
        self.write_docker_config(&config)?;

        // Clean up saved previous context.
        let _ = fs::remove_file(self.previous_context_path());

        match previous {
            Some(name) => info!("Restored default Docker context to '{name}'"),
            None => info!("Cleared default Docker context"),
        }

        Ok(())
    }

    /// Enables `ArcBox` Docker integration.
    ///
    /// Creates the context if it doesn't exist and sets it as default.
    ///
    /// # Errors
    ///
    /// Returns an error if the integration cannot be enabled.
    pub fn enable(&self) -> Result<()> {
        if !self.context_exists() {
            self.create_context()?;
        }
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

    // ========================================================================
    // Private helpers
    // ========================================================================

    /// Computes SHA256 hash of context name for directory name.
    fn context_hash(name: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Returns path to the context directory.
    fn context_dir(&self) -> PathBuf {
        let hash = Self::context_hash(ARCBOX_CONTEXT_NAME);
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
        self.docker_config_dir.join(".arcbox-previous-context")
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

/// Status of `ArcBox` Docker integration.
#[derive(Debug, Clone)]
pub struct ContextStatus {
    /// Whether the `ArcBox` context exists.
    pub context_exists: bool,
    /// Whether `ArcBox` is the default context.
    pub is_default: bool,
    /// Path to the `ArcBox` socket.
    pub socket_path: PathBuf,
    /// Whether the socket file exists.
    pub socket_exists: bool,
}

impl std::fmt::Display for ContextStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ArcBox Docker Integration Status:")?;
        writeln!(
            f,
            "  Context exists: {}",
            if self.context_exists { "yes" } else { "no" }
        )?;
        writeln!(
            f,
            "  Is default:     {}",
            if self.is_default { "yes" } else { "no" }
        )?;
        writeln!(f, "  Socket path:    {}", self.socket_path.display())?;
        write!(
            f,
            "  Socket exists:  {}",
            if self.socket_exists { "yes" } else { "no" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_context_hash() {
        // Docker uses SHA256 of the context name.
        let hash = DockerContextManager::context_hash("arcbox");
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_create_and_remove_context() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir.clone());

        // Initially no context.
        assert!(!manager.context_exists());

        // Create context.
        manager.create_context().unwrap();
        assert!(manager.context_exists());

        // Verify meta.json content.
        let meta_path = manager.context_meta_path();
        let meta_content = fs::read_to_string(&meta_path).unwrap();
        let meta: ContextMeta = serde_json::from_str(&meta_content).unwrap();
        assert_eq!(meta.name, "arcbox");
        assert!(meta.endpoints.docker.host.starts_with("unix://"));

        // Remove context.
        manager.remove_context().unwrap();
        assert!(!manager.context_exists());
    }

    #[test]
    fn test_set_and_restore_default() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir.clone());

        // Create context first.
        manager.create_context().unwrap();

        // Set up an existing default context.
        let mut config = DockerConfig::default();
        config.current_context = Some("desktop-linux".to_string());
        manager.write_docker_config(&config).unwrap();

        // Set arcbox as default.
        manager.set_default().unwrap();
        assert!(manager.is_default().unwrap());
        assert_eq!(
            manager.current_context().unwrap(),
            Some("arcbox".to_string())
        );

        // Restore previous default.
        manager.restore_default().unwrap();
        assert!(!manager.is_default().unwrap());
        assert_eq!(
            manager.current_context().unwrap(),
            Some("desktop-linux".to_string())
        );
    }

    #[test]
    fn test_enable_disable() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir.clone());

        // Enable creates context and sets default.
        manager.enable().unwrap();
        assert!(manager.context_exists());
        assert!(manager.is_default().unwrap());

        // Disable restores previous default.
        manager.disable().unwrap();
        assert!(manager.context_exists()); // Context still exists
        assert!(!manager.is_default().unwrap()); // But not default
    }

    #[test]
    fn test_status() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path.clone(), docker_config_dir);

        let status = manager.status();
        assert!(!status.context_exists);
        assert!(!status.is_default);
        assert_eq!(status.socket_path, socket_path);
        assert!(!status.socket_exists);

        // Create socket file and context.
        fs::write(&socket_path, "").unwrap();
        manager.enable().unwrap();

        let status = manager.status();
        assert!(status.context_exists);
        assert!(status.is_default);
        assert!(status.socket_exists);
    }

    #[test]
    fn test_preserves_other_config_fields() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");
        fs::create_dir_all(&docker_config_dir).unwrap();

        // Create a config with extra fields.
        let config_path = docker_config_dir.join("config.json");
        let initial_config = r#"{
            "currentContext": "desktop-linux",
            "credsStore": "osxkeychain",
            "auths": {
                "https://index.docker.io/v1/": {}
            }
        }"#;
        fs::write(&config_path, initial_config).unwrap();

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);
        manager.create_context().unwrap();
        manager.set_default().unwrap();

        // Read back and verify other fields are preserved.
        let updated_config = fs::read_to_string(&config_path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&updated_config).unwrap();

        assert_eq!(config["currentContext"], "arcbox");
        assert_eq!(config["credsStore"], "osxkeychain");
        assert!(config["auths"].is_object());
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_create_context_is_idempotent() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Create context twice - should not fail.
        manager.create_context().unwrap();
        let first_meta = fs::read_to_string(manager.context_meta_path()).unwrap();

        manager.create_context().unwrap();
        let second_meta = fs::read_to_string(manager.context_meta_path()).unwrap();

        // Content should be identical.
        assert_eq!(first_meta, second_meta);
    }

    #[test]
    fn test_remove_default_context_restores_previous() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Set up: create context with a previous default.
        let mut config = DockerConfig::default();
        config.current_context = Some("orbstack".to_string());
        manager.create_context().unwrap();
        manager.write_docker_config(&config).unwrap();
        manager.set_default().unwrap();

        assert!(manager.is_default().unwrap());

        // Remove context - should restore orbstack as default.
        manager.remove_context().unwrap();

        assert!(!manager.context_exists());
        assert_eq!(
            manager.current_context().unwrap(),
            Some("orbstack".to_string())
        );
    }

    #[test]
    fn test_set_default_without_previous_context() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // No config.json exists - fresh install scenario.
        manager.create_context().unwrap();
        manager.set_default().unwrap();

        assert!(manager.is_default().unwrap());

        // Restore should clear the context (no previous).
        manager.restore_default().unwrap();
        assert!(manager.current_context().unwrap().is_none());
    }

    #[test]
    fn test_multiple_enable_disable_cycles() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Set up initial context.
        let mut config = DockerConfig::default();
        config.current_context = Some("default".to_string());
        fs::create_dir_all(manager.docker_config_dir()).unwrap();
        manager.write_docker_config(&config).unwrap();

        // Cycle 1.
        manager.enable().unwrap();
        assert!(manager.is_default().unwrap());
        manager.disable().unwrap();
        assert_eq!(
            manager.current_context().unwrap(),
            Some("default".to_string())
        );

        // Cycle 2.
        manager.enable().unwrap();
        assert!(manager.is_default().unwrap());
        manager.disable().unwrap();
        assert_eq!(
            manager.current_context().unwrap(),
            Some("default".to_string())
        );

        // Cycle 3.
        manager.enable().unwrap();
        assert!(manager.is_default().unwrap());
        manager.disable().unwrap();
        assert_eq!(
            manager.current_context().unwrap(),
            Some("default".to_string())
        );
    }

    // ========================================================================
    // Error Handling Tests
    // ========================================================================

    #[test]
    fn test_set_default_fails_without_context() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Try to set default without creating context first.
        let result = manager.set_default();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_disable_when_not_default_is_noop() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Create context but don't set as default.
        manager.create_context().unwrap();
        assert!(!manager.is_default().unwrap());

        // Disable should succeed but do nothing.
        manager.disable().unwrap();
        assert!(!manager.is_default().unwrap());
    }

    #[test]
    fn test_remove_nonexistent_context_is_noop() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Remove context that doesn't exist - should not fail.
        manager.remove_context().unwrap();
        assert!(!manager.context_exists());
    }

    #[test]
    fn test_handles_empty_config_json() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");
        fs::create_dir_all(&docker_config_dir).unwrap();

        // Create empty config.json.
        let config_path = docker_config_dir.join("config.json");
        fs::write(&config_path, "{}").unwrap();

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Should handle empty config gracefully.
        assert!(manager.current_context().unwrap().is_none());
        assert!(!manager.is_default().unwrap());

        // Enable should work.
        manager.enable().unwrap();
        assert!(manager.is_default().unwrap());
    }

    // ========================================================================
    // Docker Compatibility Tests
    // ========================================================================

    #[test]
    fn test_context_meta_json_format() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path.clone(), docker_config_dir);
        manager.create_context().unwrap();

        // Read and verify the meta.json structure matches Docker's format.
        let meta_content = fs::read_to_string(manager.context_meta_path()).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();

        // Docker expects PascalCase keys.
        assert!(meta.get("Name").is_some());
        assert!(meta.get("Metadata").is_some());
        assert!(meta.get("Endpoints").is_some());

        // Verify nested structure.
        let endpoints = meta.get("Endpoints").unwrap();
        let docker_endpoint = endpoints.get("docker").unwrap();
        assert!(docker_endpoint.get("Host").is_some());
        assert!(docker_endpoint.get("SkipTLSVerify").is_some());

        // Verify Host format.
        let host = docker_endpoint.get("Host").unwrap().as_str().unwrap();
        assert!(host.starts_with("unix://"));
        assert!(host.contains("test.sock"));
    }

    #[test]
    fn test_context_hash_is_deterministic() {
        // Same context name should always produce the same hash.
        let hash1 = DockerContextManager::context_hash("arcbox");
        let hash2 = DockerContextManager::context_hash("arcbox");
        let hash3 = DockerContextManager::context_hash("arcbox");

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);

        // Different names produce different hashes.
        let other_hash = DockerContextManager::context_hash("other-context");
        assert_ne!(hash1, other_hash);
    }

    #[test]
    fn test_context_directory_structure() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir.clone());
        manager.create_context().unwrap();

        // Verify Docker-compatible directory structure.
        let contexts_dir = docker_config_dir.join("contexts");
        let meta_dir = contexts_dir.join("meta");

        assert!(contexts_dir.exists());
        assert!(meta_dir.exists());

        // Context should be in a hash-named directory.
        let hash = DockerContextManager::context_hash(ARCBOX_CONTEXT_NAME);
        let context_dir = meta_dir.join(&hash);
        assert!(context_dir.exists());

        // meta.json should exist in the context directory.
        let meta_path = context_dir.join("meta.json");
        assert!(meta_path.exists());
    }

    // ========================================================================
    // Real-world Scenario Tests
    // ========================================================================

    #[test]
    fn test_full_lifecycle() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path.clone(), docker_config_dir);

        // 1. Initial state - nothing exists.
        assert!(!manager.context_exists());
        let status = manager.status();
        assert!(!status.context_exists);
        assert!(!status.is_default);

        // 2. Enable integration.
        manager.enable().unwrap();
        assert!(manager.context_exists());
        assert!(manager.is_default().unwrap());

        // 3. Create socket file (simulating daemon running).
        fs::write(&socket_path, "").unwrap();
        let status = manager.status();
        assert!(status.socket_exists);

        // 4. Disable integration.
        manager.disable().unwrap();
        assert!(manager.context_exists()); // Context still exists.
        assert!(!manager.is_default().unwrap());

        // 5. Re-enable.
        manager.enable().unwrap();
        assert!(manager.is_default().unwrap());

        // 6. Remove completely.
        manager.remove_context().unwrap();
        assert!(!manager.context_exists());
        assert!(!manager.is_default().unwrap());
    }

    #[test]
    fn test_switching_from_orbstack() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");
        fs::create_dir_all(&docker_config_dir).unwrap();

        // Simulate existing OrbStack setup.
        let config_path = docker_config_dir.join("config.json");
        let orbstack_config = r#"{
            "currentContext": "orbstack",
            "credsStore": "osxkeychain",
            "auths": {},
            "plugins": {
                "debug": {"hooks": "exec"}
            }
        }"#;
        fs::write(&config_path, orbstack_config).unwrap();

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Enable ArcBox.
        manager.enable().unwrap();
        assert!(manager.is_default().unwrap());

        // Verify OrbStack config is preserved.
        let updated_config = fs::read_to_string(&config_path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&updated_config).unwrap();
        assert_eq!(config["currentContext"], "arcbox");
        assert_eq!(config["credsStore"], "osxkeychain");
        assert!(config["plugins"].is_object());

        // Disable - should restore OrbStack.
        manager.disable().unwrap();
        let restored_config = fs::read_to_string(&config_path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&restored_config).unwrap();
        assert_eq!(config["currentContext"], "orbstack");
    }

    #[test]
    fn test_socket_path_with_spaces() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("path with spaces/docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path.clone(), docker_config_dir);
        manager.create_context().unwrap();

        // Verify the socket path is correctly stored.
        let meta_content = fs::read_to_string(manager.context_meta_path()).unwrap();
        let meta: ContextMeta = serde_json::from_str(&meta_content).unwrap();

        assert!(meta.endpoints.docker.host.contains("path with spaces"));
        assert_eq!(
            meta.endpoints.docker.host,
            format!("unix://{}", socket_path.display())
        );
    }

    #[test]
    fn test_context_status_display() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("docker.sock");
        let docker_config_dir = temp_dir.path().join(".docker");

        let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

        // Get status and verify Display impl.
        let status = manager.status();
        let display = format!("{status}");

        assert!(display.contains("Context exists:"));
        assert!(display.contains("Is default:"));
        assert!(display.contains("Socket path:"));
        assert!(display.contains("Socket exists:"));
    }
}
