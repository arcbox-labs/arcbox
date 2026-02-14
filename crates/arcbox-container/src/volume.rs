//! Volume management.
//!
//! Provides persistent storage volumes for containers.

use crate::error::{ContainerError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

/// Volume information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// Volume name.
    pub name: String,
    /// Mount point on host.
    pub mountpoint: PathBuf,
    /// Driver used.
    pub driver: String,
    /// Volume labels.
    pub labels: HashMap<String, String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Scope (local or global).
    pub scope: String,
}

/// Volume metadata stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VolumeMetadata {
    name: String,
    driver: String,
    labels: HashMap<String, String>,
    created_at: DateTime<Utc>,
}

/// Volume creation options.
#[derive(Debug, Clone, Default)]
pub struct VolumeCreateOptions {
    /// Volume name. If empty, a random name will be generated.
    pub name: Option<String>,
    /// Driver to use (default: "local").
    pub driver: Option<String>,
    /// Labels to apply to the volume.
    pub labels: HashMap<String, String>,
}

/// Volume manager.
///
/// Manages persistent storage volumes for containers. Volumes are stored
/// in the data directory under `volumes/`.
pub struct VolumeManager {
    /// In-memory cache of volumes.
    volumes: HashMap<String, Volume>,
    /// Base directory for volume data.
    data_dir: PathBuf,
    /// Set of volumes currently in use (by container ID).
    in_use: HashMap<String, HashSet<String>>,
}

impl VolumeManager {
    /// Creates a new volume manager.
    ///
    /// The manager will store volumes under `data_dir/` directly (not data_dir/volumes).
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        let mut manager = Self {
            volumes: HashMap::new(),
            data_dir,
            in_use: HashMap::new(),
        };

        // Load existing volumes from disk.
        if let Err(e) = manager.load_volumes() {
            tracing::warn!("Failed to load existing volumes: {}", e);
        }

        manager
    }

    /// Loads existing volumes from disk.
    fn load_volumes(&mut self) -> Result<()> {
        let volumes_dir = &self.data_dir;

        if !volumes_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(volumes_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Try to load metadata, or create default.
            let metadata_path = path.join(".volume.json");
            let volume = if metadata_path.exists() {
                match fs::read_to_string(&metadata_path) {
                    Ok(content) => match serde_json::from_str::<VolumeMetadata>(&content) {
                        Ok(meta) => Volume {
                            name: meta.name,
                            mountpoint: path.join("_data"),
                            driver: meta.driver,
                            labels: meta.labels,
                            created_at: meta.created_at,
                            scope: "local".to_string(),
                        },
                        Err(e) => {
                            tracing::warn!("Failed to parse volume metadata for {}: {}", name, e);
                            continue;
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to read volume metadata for {}: {}", name, e);
                        continue;
                    }
                }
            } else {
                // Legacy volume without metadata.
                Volume {
                    name: name.clone(),
                    mountpoint: path.join("_data"),
                    driver: "local".to_string(),
                    labels: HashMap::new(),
                    created_at: Utc::now(),
                    scope: "local".to_string(),
                }
            };

            self.volumes.insert(name, volume);
        }

        tracing::debug!("Loaded {} volumes from disk", self.volumes.len());
        Ok(())
    }

    /// Creates a new volume.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A volume with the same name already exists
    /// - The volume directory cannot be created
    /// - The metadata cannot be written
    pub fn create(&mut self, options: VolumeCreateOptions) -> Result<&Volume> {
        let name = options
            .name
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_string());

        // Check if volume already exists.
        if self.volumes.contains_key(&name) {
            return Err(ContainerError::Volume(format!(
                "volume '{}' already exists",
                name
            )));
        }

        let volume_dir = self.data_dir.join(&name);
        let data_dir = volume_dir.join("_data");

        // Create volume directory structure.
        fs::create_dir_all(&data_dir).map_err(|e| {
            ContainerError::Volume(format!("failed to create volume directory: {}", e))
        })?;

        let created_at = Utc::now();
        let driver = options.driver.unwrap_or_else(|| "local".to_string());

        // Write metadata file.
        let metadata = VolumeMetadata {
            name: name.clone(),
            driver: driver.clone(),
            labels: options.labels.clone(),
            created_at,
        };

        let metadata_path = volume_dir.join(".volume.json");
        let metadata_json = serde_json::to_string_pretty(&metadata).map_err(|e| {
            ContainerError::Volume(format!("failed to serialize volume metadata: {}", e))
        })?;

        fs::write(&metadata_path, metadata_json).map_err(|e| {
            ContainerError::Volume(format!("failed to write volume metadata: {}", e))
        })?;

        let volume = Volume {
            name: name.clone(),
            mountpoint: data_dir,
            driver,
            labels: options.labels,
            created_at,
            scope: "local".to_string(),
        };

        self.volumes.insert(name.clone(), volume);
        tracing::info!("Created volume '{}'", name);

        Ok(self.volumes.get(&name).unwrap())
    }

    /// Creates a volume with just a name (convenience method).
    pub fn create_named(&mut self, name: impl Into<String>) -> Result<&Volume> {
        self.create(VolumeCreateOptions {
            name: Some(name.into()),
            ..Default::default()
        })
    }

    /// Gets a volume by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Volume> {
        self.volumes.get(name)
    }

    /// Returns detailed volume information (inspect).
    ///
    /// This is the same as `get()` but with a more explicit name for API compatibility.
    #[must_use]
    pub fn inspect(&self, name: &str) -> Option<&Volume> {
        self.get(name)
    }

    /// Lists all volumes.
    #[must_use]
    pub fn list(&self) -> Vec<&Volume> {
        self.volumes.values().collect()
    }

    /// Removes a volume.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The volume does not exist
    /// - The volume is currently in use by a container
    /// - The volume directory cannot be removed
    pub fn remove(&mut self, name: &str) -> Result<()> {
        // Check if volume exists.
        if !self.volumes.contains_key(name) {
            return Err(ContainerError::not_found(format!("volume '{}'", name)));
        }

        // Check if volume is in use.
        if let Some(containers) = self.in_use.get(name) {
            if !containers.is_empty() {
                return Err(ContainerError::Volume(format!(
                    "volume '{}' is in use by {} container(s)",
                    name,
                    containers.len()
                )));
            }
        }

        // Remove the volume directory.
        let volume_dir = self.data_dir.join(name);
        if volume_dir.exists() {
            fs::remove_dir_all(&volume_dir).map_err(|e| {
                ContainerError::Volume(format!("failed to remove volume directory: {}", e))
            })?;
        }

        self.volumes.remove(name);
        self.in_use.remove(name);
        tracing::info!("Removed volume '{}'", name);

        Ok(())
    }

    /// Force removes a volume, even if it's in use.
    ///
    /// # Errors
    ///
    /// Returns an error if the volume directory cannot be removed.
    pub fn remove_force(&mut self, name: &str) -> Result<()> {
        // Remove tracking first.
        self.in_use.remove(name);

        // Check if volume exists.
        if !self.volumes.contains_key(name) {
            return Err(ContainerError::not_found(format!("volume '{}'", name)));
        }

        // Remove the volume directory.
        let volume_dir = self.data_dir.join(name);
        if volume_dir.exists() {
            fs::remove_dir_all(&volume_dir).map_err(|e| {
                ContainerError::Volume(format!("failed to remove volume directory: {}", e))
            })?;
        }

        self.volumes.remove(name);
        tracing::info!("Force removed volume '{}'", name);

        Ok(())
    }

    /// Removes all unused volumes.
    ///
    /// Returns the list of removed volume names and the total reclaimed space in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if any volume cannot be removed.
    pub fn prune(&mut self) -> Result<PruneResult> {
        let mut removed = Vec::new();
        let mut space_reclaimed: u64 = 0;

        // Find unused volumes.
        let unused: Vec<String> = self
            .volumes
            .keys()
            .filter(|name| {
                self.in_use
                    .get(*name)
                    .map_or(true, |containers| containers.is_empty())
            })
            .cloned()
            .collect();

        for name in unused {
            // Calculate size before removal.
            let volume_dir = self.data_dir.join(&name);
            let size = calculate_dir_size(&volume_dir);

            match self.remove(&name) {
                Ok(()) => {
                    removed.push(name);
                    space_reclaimed += size;
                }
                Err(e) => {
                    tracing::warn!("Failed to prune volume '{}': {}", name, e);
                }
            }
        }

        tracing::info!(
            "Pruned {} volumes, reclaimed {} bytes",
            removed.len(),
            space_reclaimed
        );

        Ok(PruneResult {
            volumes_deleted: removed,
            space_reclaimed,
        })
    }

    /// Marks a volume as being used by a container.
    pub fn mark_in_use(&mut self, volume_name: &str, container_id: &str) {
        self.in_use
            .entry(volume_name.to_string())
            .or_default()
            .insert(container_id.to_string());
    }

    /// Marks a volume as no longer being used by a container.
    pub fn mark_not_in_use(&mut self, volume_name: &str, container_id: &str) {
        if let Some(containers) = self.in_use.get_mut(volume_name) {
            containers.remove(container_id);
        }
    }

    /// Checks if a volume is in use.
    #[must_use]
    pub fn is_in_use(&self, volume_name: &str) -> bool {
        self.in_use
            .get(volume_name)
            .map_or(false, |containers| !containers.is_empty())
    }

    /// Returns the number of containers using a volume.
    #[must_use]
    pub fn usage_count(&self, volume_name: &str) -> usize {
        self.in_use
            .get(volume_name)
            .map_or(0, |containers| containers.len())
    }

    /// Gets or creates a volume.
    ///
    /// If the volume exists, returns it. Otherwise creates a new one.
    pub fn get_or_create(&mut self, name: &str) -> Result<&Volume> {
        if self.volumes.contains_key(name) {
            Ok(self.volumes.get(name).unwrap())
        } else {
            self.create_named(name)
        }
    }
}

/// Result of a prune operation.
#[derive(Debug, Clone)]
pub struct PruneResult {
    /// Names of volumes that were deleted.
    pub volumes_deleted: Vec<String>,
    /// Total space reclaimed in bytes.
    pub space_reclaimed: u64,
}

/// Calculates the total size of a directory recursively.
fn calculate_dir_size(path: &std::path::Path) -> u64 {
    if !path.exists() {
        return 0;
    }

    let mut size: u64 = 0;

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = fs::metadata(&path) {
                    size += metadata.len();
                }
            } else if path.is_dir() {
                size += calculate_dir_size(&path);
            }
        }
    }

    size
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_volume() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = VolumeManager::new(temp_dir.path().to_path_buf());

        let volume = manager.create_named("test-volume").unwrap();
        assert_eq!(volume.name, "test-volume");
        assert_eq!(volume.driver, "local");
        assert!(volume.mountpoint.exists());
    }

    #[test]
    fn test_create_duplicate_volume() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = VolumeManager::new(temp_dir.path().to_path_buf());

        manager.create_named("test-volume").unwrap();
        let result = manager.create_named("test-volume");
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_volume() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = VolumeManager::new(temp_dir.path().to_path_buf());

        manager.create_named("test-volume").unwrap();
        assert!(manager.get("test-volume").is_some());

        manager.remove("test-volume").unwrap();
        assert!(manager.get("test-volume").is_none());
    }

    #[test]
    fn test_remove_volume_in_use() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = VolumeManager::new(temp_dir.path().to_path_buf());

        manager.create_named("test-volume").unwrap();
        manager.mark_in_use("test-volume", "container-1");

        let result = manager.remove("test-volume");
        assert!(result.is_err());

        manager.mark_not_in_use("test-volume", "container-1");
        let result = manager.remove("test-volume");
        assert!(result.is_ok());
    }

    #[test]
    fn test_prune_volumes() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = VolumeManager::new(temp_dir.path().to_path_buf());

        manager.create_named("volume-1").unwrap();
        manager.create_named("volume-2").unwrap();
        manager.create_named("volume-3").unwrap();

        // Mark one as in use.
        manager.mark_in_use("volume-2", "container-1");

        let result = manager.prune().unwrap();
        assert_eq!(result.volumes_deleted.len(), 2);
        assert!(result.volumes_deleted.contains(&"volume-1".to_string()));
        assert!(result.volumes_deleted.contains(&"volume-3".to_string()));

        // volume-2 should still exist.
        assert!(manager.get("volume-2").is_some());
    }

    #[test]
    fn test_load_volumes() {
        let temp_dir = TempDir::new().unwrap();

        // Create volumes with first manager.
        {
            let mut manager = VolumeManager::new(temp_dir.path().to_path_buf());
            manager.create_named("persistent-vol").unwrap();
        }

        // Load with new manager.
        let manager = VolumeManager::new(temp_dir.path().to_path_buf());
        assert!(manager.get("persistent-vol").is_some());
    }
}
