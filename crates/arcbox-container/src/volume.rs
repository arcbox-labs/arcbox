//! Volume management.

use crate::error::Result;
use serde::{Deserialize, Serialize};
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
    pub labels: std::collections::HashMap<String, String>,
}

/// Volume manager.
pub struct VolumeManager {
    volumes: std::collections::HashMap<String, Volume>,
    data_dir: PathBuf,
}

impl VolumeManager {
    /// Creates a new volume manager.
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            volumes: std::collections::HashMap::new(),
            data_dir,
        }
    }

    /// Creates a new volume.
    ///
    /// # Errors
    ///
    /// Returns an error if the volume cannot be created.
    pub fn create(&mut self, name: impl Into<String>) -> Result<&Volume> {
        let name = name.into();
        let mountpoint = self.data_dir.join("volumes").join(&name);

        let volume = Volume {
            name: name.clone(),
            mountpoint,
            driver: "local".to_string(),
            labels: std::collections::HashMap::new(),
        };

        // TODO: Create directory
        self.volumes.insert(name.clone(), volume);
        Ok(self.volumes.get(&name).unwrap())
    }

    /// Gets a volume by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Volume> {
        self.volumes.get(name)
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
    /// Returns an error if the volume cannot be removed.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        // TODO: Remove directory
        self.volumes.remove(name);
        Ok(())
    }
}
