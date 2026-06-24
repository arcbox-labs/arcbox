use super::util::{calculate_dir_size, generate_snapshot_id};
use super::{
    SnapshotCreateOptions, SnapshotError, SnapshotInfo, SnapshotManager, SnapshotState,
    SnapshotTargetType, VmRestoreData, VmSnapshotContext,
};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

impl SnapshotManager {
    /// Creates a new snapshot manager.
    ///
    /// # Arguments
    ///
    /// * `base_dir` - Directory where snapshots will be stored
    #[must_use]
    pub fn new(base_dir: PathBuf) -> Self {
        let manager = Self {
            base_dir,
            snapshots: std::sync::RwLock::new(HashMap::new()),
            restore_cache: std::sync::RwLock::new(HashMap::new()),
        };

        // Load existing snapshots from disk.
        if let Err(e) = manager.load_snapshots() {
            tracing::warn!("Failed to load existing snapshots: {}", e);
        }

        manager
    }

    /// Loads existing snapshots from disk.
    fn load_snapshots(&self) -> Result<(), SnapshotError> {
        if !self.base_dir.exists() {
            return Ok(());
        }

        let mut snapshots = self
            .snapshots
            .write()
            .map_err(|_| SnapshotError::Internal("lock poisoned".to_string()))?;

        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            let metadata_path = path.join("snapshot.json");
            if !metadata_path.exists() {
                continue;
            }

            match fs::read_to_string(&metadata_path) {
                Ok(content) => match serde_json::from_str::<SnapshotInfo>(&content) {
                    Ok(info) => {
                        snapshots.insert(info.id.clone(), info);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse snapshot metadata: {}", e);
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read snapshot metadata: {}", e);
                }
            }
        }

        tracing::debug!("Loaded {} snapshots from disk", snapshots.len());
        Ok(())
    }

    /// Creates a snapshot.
    ///
    /// # Arguments
    ///
    /// * `target_id` - ID of the VM or container to snapshot
    /// * `target_type` - Type of target (VM or Container)
    /// * `options` - Snapshot creation options
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be created.
    pub async fn create(
        &self,
        target_id: &str,
        target_type: SnapshotTargetType,
        options: SnapshotCreateOptions,
    ) -> Result<SnapshotInfo, SnapshotError> {
        let snapshot_id = generate_snapshot_id();
        let name = options
            .name
            .clone()
            .unwrap_or_else(|| format!("snapshot-{}", &snapshot_id[..8]));

        tracing::info!(
            "Creating snapshot '{}' ({}) for {:?} {}",
            name,
            snapshot_id,
            target_type,
            target_id
        );

        // Create snapshot directory.
        let snapshot_dir = self.base_dir.join(&snapshot_id);
        fs::create_dir_all(&snapshot_dir)?;

        // Create initial metadata with Creating state.
        let mut info = SnapshotInfo {
            id: snapshot_id.clone(),
            name: name.clone(),
            target_id: target_id.to_string(),
            target_type,
            created: Utc::now(),
            size: 0,
            parent: options.parent.clone(),
            description: options.description.clone(),
            labels: options.labels.clone(),
            state: SnapshotState::Creating,
        };

        // Save initial metadata.
        self.save_metadata(&info)?;

        // Capture snapshot data based on target type.
        match target_type {
            SnapshotTargetType::Vm => {
                self.capture_vm_snapshot(&snapshot_dir, target_id, &options)
                    .await?;
            }
            SnapshotTargetType::Container => {
                self.capture_container_snapshot(&snapshot_dir, target_id)
                    .await?;
            }
        }

        // Calculate snapshot size.
        info.size = calculate_dir_size(&snapshot_dir);
        info.state = SnapshotState::Ready;

        // Save final metadata.
        self.save_metadata(&info)?;

        // Update cache.
        {
            let mut snapshots = self
                .snapshots
                .write()
                .map_err(|_| SnapshotError::Internal("lock poisoned".to_string()))?;
            snapshots.insert(snapshot_id.clone(), info.clone());
        }

        tracing::info!("Created snapshot '{}' (size: {} bytes)", name, info.size);

        Ok(info)
    }

    /// Creates a VM snapshot using explicit VM state context.
    ///
    /// Unlike [`SnapshotManager::create`], this path never falls back to
    /// placeholder VM state and always writes real snapshot metadata + memory.
    ///
    /// # Errors
    ///
    /// Returns an error if snapshot creation fails.
    pub async fn create_vm_with_context(
        &self,
        target_id: &str,
        options: SnapshotCreateOptions,
        context: VmSnapshotContext,
    ) -> Result<SnapshotInfo, SnapshotError> {
        let snapshot_id = generate_snapshot_id();
        let name = options
            .name
            .clone()
            .unwrap_or_else(|| format!("snapshot-{}", &snapshot_id[..8]));

        tracing::info!(
            "Creating VM snapshot '{}' ({}) for {} with explicit context",
            name,
            snapshot_id,
            target_id
        );

        let snapshot_dir = self.base_dir.join(&snapshot_id);
        fs::create_dir_all(&snapshot_dir)?;

        let mut info = SnapshotInfo {
            id: snapshot_id.clone(),
            name: name.clone(),
            target_id: target_id.to_string(),
            target_type: SnapshotTargetType::Vm,
            created: Utc::now(),
            size: 0,
            parent: options.parent.clone(),
            description: options.description.clone(),
            labels: options.labels.clone(),
            state: SnapshotState::Creating,
        };

        self.save_metadata(&info)?;
        self.capture_vm_snapshot_with_context(&snapshot_dir, target_id, &options, context)
            .await?;

        info.size = calculate_dir_size(&snapshot_dir);
        info.state = SnapshotState::Ready;
        self.save_metadata(&info)?;

        {
            let mut snapshots = self
                .snapshots
                .write()
                .map_err(|_| SnapshotError::Internal("lock poisoned".to_string()))?;
            snapshots.insert(snapshot_id, info.clone());
        }

        tracing::info!("Created VM snapshot '{}' (size: {} bytes)", name, info.size);
        Ok(info)
    }

    /// Saves snapshot metadata to disk.
    fn save_metadata(&self, info: &SnapshotInfo) -> Result<(), SnapshotError> {
        let snapshot_dir = self.base_dir.join(&info.id);
        let metadata_path = snapshot_dir.join("snapshot.json");

        let json = serde_json::to_string_pretty(info)
            .map_err(|e| SnapshotError::Internal(e.to_string()))?;
        fs::write(metadata_path, json)?;

        Ok(())
    }

    /// Restores from a snapshot.
    ///
    /// # Arguments
    ///
    /// * `snapshot_id` - ID of the snapshot to restore
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be restored.
    pub async fn restore(&self, snapshot_id: &str) -> Result<(), SnapshotError> {
        let info = self
            .get(snapshot_id)
            .ok_or_else(|| SnapshotError::NotFound(snapshot_id.to_string()))?;

        if info.state != SnapshotState::Ready {
            return Err(SnapshotError::InvalidState(format!(
                "snapshot {} is not ready (state: {:?})",
                snapshot_id, info.state
            )));
        }

        tracing::info!(
            "Restoring {:?} {} from snapshot '{}'",
            info.target_type,
            info.target_id,
            info.name
        );

        let snapshot_dir = self.base_dir.join(snapshot_id);

        match info.target_type {
            SnapshotTargetType::Vm => {
                self.restore_vm_snapshot(&snapshot_dir, &info).await?;
            }
            SnapshotTargetType::Container => {
                self.restore_container_snapshot(&snapshot_dir, &info)
                    .await?;
            }
        }

        tracing::info!("Restored from snapshot '{}'", info.name);
        Ok(())
    }

    /// Retrieves the restore data for a snapshot after calling `restore()`.
    ///
    /// This allows the caller to access vCPU state, device state, and memory
    /// data to apply to a VM instance.
    ///
    /// # Arguments
    ///
    /// * `snapshot_id` - ID of the snapshot that was restored
    ///
    /// # Returns
    ///
    /// Returns `Some(VmRestoreData)` if restore data is available, `None` otherwise.
    pub fn take_restore_data(&self, snapshot_id: &str) -> Option<VmRestoreData> {
        self.restore_cache.write().ok()?.remove(snapshot_id)
    }

    /// Gets a snapshot by ID.
    #[must_use]
    pub fn get(&self, snapshot_id: &str) -> Option<SnapshotInfo> {
        self.snapshots.read().ok()?.get(snapshot_id).cloned()
    }

    /// Lists all snapshots.
    #[must_use]
    pub fn list_all(&self) -> Vec<SnapshotInfo> {
        self.snapshots
            .read()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Lists snapshots for a specific target.
    #[must_use]
    pub fn list(&self, target_id: &str) -> Vec<SnapshotInfo> {
        self.snapshots
            .read()
            .map(|s| {
                s.values()
                    .filter(|info| info.target_id == target_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Lists snapshots by target type.
    #[must_use]
    pub fn list_by_type(&self, target_type: SnapshotTargetType) -> Vec<SnapshotInfo> {
        self.snapshots
            .read()
            .map(|s| {
                s.values()
                    .filter(|info| info.target_type == target_type)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Deletes a snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be deleted.
    pub async fn delete(&self, snapshot_id: &str) -> Result<(), SnapshotError> {
        // Check if snapshot exists.
        let info = self
            .get(snapshot_id)
            .ok_or_else(|| SnapshotError::NotFound(snapshot_id.to_string()))?;

        // Check if any other snapshots depend on this one (as parent).
        {
            let snapshots = self
                .snapshots
                .read()
                .map_err(|_| SnapshotError::Internal("lock poisoned".to_string()))?;

            for other in snapshots.values() {
                if other.parent.as_deref() == Some(snapshot_id) {
                    return Err(SnapshotError::InUse(format!(
                        "snapshot {} is parent of {}",
                        snapshot_id, other.id
                    )));
                }
            }
        }

        tracing::info!("Deleting snapshot '{}' ({})", info.name, snapshot_id);

        // Remove snapshot directory.
        let snapshot_dir = self.base_dir.join(snapshot_id);
        if snapshot_dir.exists() {
            fs::remove_dir_all(&snapshot_dir)?;
        }

        // Remove from cache.
        {
            let mut snapshots = self
                .snapshots
                .write()
                .map_err(|_| SnapshotError::Internal("lock poisoned".to_string()))?;
            snapshots.remove(snapshot_id);
        }

        tracing::info!("Deleted snapshot '{}'", info.name);
        Ok(())
    }

    /// Prunes old snapshots, keeping only the most recent N per target.
    ///
    /// # Arguments
    ///
    /// * `keep` - Number of snapshots to keep per target
    ///
    /// # Returns
    ///
    /// List of deleted snapshot IDs.
    pub async fn prune(&self, keep: usize) -> Result<Vec<String>, SnapshotError> {
        let mut deleted = Vec::new();

        // Group snapshots by target.
        let by_target: HashMap<String, Vec<SnapshotInfo>> = {
            let snapshots = self
                .snapshots
                .read()
                .map_err(|_| SnapshotError::Internal("lock poisoned".to_string()))?;

            let mut map: HashMap<String, Vec<SnapshotInfo>> = HashMap::new();
            for info in snapshots.values() {
                map.entry(info.target_id.clone())
                    .or_default()
                    .push(info.clone());
            }
            map
        };

        // For each target, delete old snapshots.
        for (target_id, mut snapshots) in by_target {
            if snapshots.len() <= keep {
                continue;
            }

            // Sort by creation time (newest first).
            snapshots.sort_by_key(|s| std::cmp::Reverse(s.created));

            // Delete old snapshots.
            for info in snapshots.into_iter().skip(keep) {
                match self.delete(&info.id).await {
                    Ok(()) => {
                        deleted.push(info.id);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to prune snapshot {} for {}: {}",
                            info.id,
                            target_id,
                            e
                        );
                    }
                }
            }
        }

        Ok(deleted)
    }

    /// Returns the total size of all snapshots in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.snapshots
            .read()
            .map_or(0, |s| s.values().map(|info| info.size).sum())
    }
}
