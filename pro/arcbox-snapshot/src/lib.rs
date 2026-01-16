//! # arcbox-snapshot
//!
//! Snapshot and restore functionality for ArcBox Pro.
//!
//! Features:
//!
//! - **VM snapshots**: Full VM state capture
//! - **Container checkpoints**: CRIU-based container snapshots
//! - **Incremental snapshots**: Efficient storage
//! - **Scheduled backups**: Automatic snapshot creation
//!
//! ## License
//!
//! This crate is licensed under BSL-1.1, which converts to MIT after 2 years.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use arcbox_hypervisor::{DeviceSnapshot, VcpuSnapshot, VmSnapshot};

/// Snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Snapshot ID.
    pub id: String,
    /// Snapshot name.
    pub name: String,
    /// Target (VM or container) ID.
    pub target_id: String,
    /// Target type.
    pub target_type: SnapshotTargetType,
    /// Creation time.
    pub created: DateTime<Utc>,
    /// Size in bytes.
    pub size: u64,
    /// Parent snapshot ID (for incremental).
    pub parent: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Snapshot state.
    pub state: SnapshotState,
}

/// Target type for snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotTargetType {
    /// Virtual machine.
    Vm,
    /// Container.
    Container,
}

/// Snapshot state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotState {
    /// Snapshot is being created.
    Creating,
    /// Snapshot is ready.
    Ready,
    /// Snapshot is corrupted or invalid.
    Invalid,
}

/// Snapshot creation options.
#[derive(Debug, Clone, Default)]
pub struct SnapshotCreateOptions {
    /// Snapshot name (auto-generated if None).
    pub name: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Parent snapshot for incremental (None for full snapshot).
    pub parent: Option<String>,
    /// Whether to pause the VM during snapshot.
    pub pause_vm: bool,
    /// Whether to compress memory dump.
    pub compress: bool,
}

/// VM snapshot context provided by the caller.
///
/// Since `SnapshotManager` doesn't own VMs, the caller must provide this context
/// with callbacks to interact with the VM.
pub struct VmSnapshotContext {
    /// vCPU snapshots.
    pub vcpu_snapshots: Vec<VcpuSnapshot>,
    /// Device snapshots.
    pub device_snapshots: Vec<DeviceSnapshot>,
    /// Memory size in bytes.
    pub memory_size: u64,
    /// Callback to read guest memory into a buffer.
    pub memory_reader: Box<dyn FnOnce(&mut [u8]) -> Result<(), SnapshotError> + Send>,
}

/// Data needed to restore a VM from a snapshot.
///
/// Returned by `SnapshotManager::take_restore_data()` after calling `restore()`.
pub struct VmRestoreData {
    /// VM snapshot metadata and state.
    pub vm_snapshot: VmSnapshot,
    /// Guest memory content.
    pub memory: Vec<u8>,
}

impl VmRestoreData {
    /// Returns the vCPU snapshots.
    #[must_use]
    pub fn vcpu_snapshots(&self) -> &[VcpuSnapshot] {
        &self.vm_snapshot.vcpus
    }

    /// Returns the device snapshots.
    #[must_use]
    pub fn device_snapshots(&self) -> &[arcbox_hypervisor::DeviceSnapshot] {
        &self.vm_snapshot.devices
    }

    /// Returns the total memory size.
    #[must_use]
    pub fn memory_size(&self) -> u64 {
        self.vm_snapshot.total_memory
    }

    /// Returns the memory data.
    #[must_use]
    pub fn memory(&self) -> &[u8] {
        &self.memory
    }

    /// Whether the snapshot was compressed.
    #[must_use]
    pub fn was_compressed(&self) -> bool {
        self.vm_snapshot.compressed
    }
}

/// Snapshot manager.
///
/// Manages VM and container snapshots with support for incremental snapshots.
pub struct SnapshotManager {
    /// Base directory for snapshots.
    base_dir: PathBuf,
    /// In-memory cache of snapshot metadata.
    snapshots: std::sync::RwLock<HashMap<String, SnapshotInfo>>,
    /// Cache of restore data for recently restored snapshots.
    restore_cache: std::sync::RwLock<HashMap<String, VmRestoreData>>,
}

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

    /// Captures VM snapshot data using provided context.
    ///
    /// This is the main entry point for VM snapshots. The caller is responsible
    /// for pausing the VM and providing the context with vCPU/device/memory state.
    pub async fn capture_vm_snapshot_with_context(
        &self,
        snapshot_dir: &Path,
        target_id: &str,
        options: &SnapshotCreateOptions,
        context: VmSnapshotContext,
    ) -> Result<(), SnapshotError> {
        tracing::debug!(
            "Capturing VM snapshot for {} (vcpus={}, memory={}MB, compress={})",
            target_id,
            context.vcpu_snapshots.len(),
            context.memory_size / (1024 * 1024),
            options.compress
        );

        // 1. Save VM metadata (using arcbox-hypervisor VmSnapshot type).
        let vm_snapshot = VmSnapshot {
            version: 1,
            arch: context
                .vcpu_snapshots
                .first()
                .map(|v| v.arch)
                .unwrap_or(arcbox_hypervisor::CpuArch::native()),
            vcpus: context.vcpu_snapshots.clone(),
            devices: context
                .device_snapshots
                .iter()
                .map(|d| arcbox_hypervisor::DeviceSnapshot {
                    device_type: d.device_type.clone(),
                    name: d.name.clone(),
                    state: d.state.clone(),
                })
                .collect(),
            memory_regions: vec![arcbox_hypervisor::MemoryRegionSnapshot {
                guest_addr: 0,
                size: context.memory_size,
                read_only: false,
                file_offset: 0,
            }],
            total_memory: context.memory_size,
            compressed: options.compress,
            compression: if options.compress {
                Some("lz4".to_string())
            } else {
                None
            },
            parent_id: options.parent.clone(),
        };

        let state_file = snapshot_dir.join("vm_state.json");
        let state_json = serde_json::to_string_pretty(&vm_snapshot)
            .map_err(|e| SnapshotError::Internal(e.to_string()))?;
        fs::write(&state_file, state_json)?;

        // 2. Dump memory.
        let memory_file = if options.compress {
            snapshot_dir.join("memory.bin.lz4")
        } else {
            snapshot_dir.join("memory.bin")
        };

        // Allocate buffer and read memory.
        let mut memory_buffer = vec![0u8; context.memory_size as usize];
        (context.memory_reader)(&mut memory_buffer)?;

        // Write memory (with optional compression).
        if options.compress {
            compress_and_write(&memory_file, &memory_buffer)?;
            tracing::debug!(
                "Wrote compressed memory dump ({} bytes -> {} bytes)",
                memory_buffer.len(),
                fs::metadata(&memory_file).map(|m| m.len()).unwrap_or(0)
            );
        } else {
            fs::write(&memory_file, &memory_buffer)?;
            tracing::debug!("Wrote raw memory dump ({} bytes)", memory_buffer.len());
        }

        tracing::info!(
            "Captured VM snapshot for {}: {} vCPUs, {} devices, {} memory",
            target_id,
            vm_snapshot.vcpus.len(),
            vm_snapshot.devices.len(),
            format_size(context.memory_size)
        );

        Ok(())
    }

    /// Captures VM snapshot data (placeholder version without context).
    ///
    /// This creates a minimal snapshot without actual VM state.
    /// For production use, call `capture_vm_snapshot_with_context` instead.
    async fn capture_vm_snapshot(
        &self,
        snapshot_dir: &Path,
        target_id: &str,
        options: &SnapshotCreateOptions,
    ) -> Result<(), SnapshotError> {
        // Create VM state file with placeholder data.
        let state_file = snapshot_dir.join("vm_state.json");

        // NOTE: This is a placeholder implementation.
        // For actual VM snapshots, use capture_vm_snapshot_with_context() with
        // proper VmSnapshotContext from the caller.
        let vm_state = VmSnapshotState {
            target_id: target_id.to_string(),
            captured_at: Utc::now(),
            paused: options.pause_vm,
            vcpu_count: 0,
            memory_size: 0,
            devices: Vec::new(),
        };

        let state_json = serde_json::to_string_pretty(&vm_state)
            .map_err(|e| SnapshotError::Internal(e.to_string()))?;
        fs::write(state_file, state_json)?;

        // Create empty memory dump placeholder.
        let memory_file = snapshot_dir.join("memory.bin");
        fs::write(&memory_file, b"")?;

        tracing::warn!(
            "Captured placeholder VM snapshot for {} (use capture_vm_snapshot_with_context for real snapshots)",
            target_id
        );
        Ok(())
    }

    /// Captures container snapshot data (checkpoint) with CRIU.
    ///
    /// This uses CRIU (Checkpoint/Restore In Userspace) to checkpoint the container.
    /// CRIU must be installed and the `criu` feature must be enabled.
    #[cfg(all(target_os = "linux", feature = "criu"))]
    pub async fn capture_container_with_criu(
        &self,
        snapshot_dir: &Path,
        target_id: &str,
        container_pid: u32,
        options: &CriuCheckpointOptions,
    ) -> Result<(), SnapshotError> {
        use std::process::Command;

        tracing::info!(
            "Capturing container checkpoint for {} (pid={}) with CRIU",
            target_id,
            container_pid
        );

        // Create checkpoint directory for CRIU output.
        let criu_dir = snapshot_dir.join("criu");
        fs::create_dir_all(&criu_dir)?;

        // Build CRIU dump command.
        let mut cmd = Command::new("criu");
        cmd.arg("dump")
            .arg("-t")
            .arg(container_pid.to_string())
            .arg("-D")
            .arg(&criu_dir)
            .arg("--shell-job"); // Allow shell jobs

        if options.leave_running {
            cmd.arg("--leave-running");
        }

        if options.file_locks {
            cmd.arg("--file-locks");
        }

        if options.tcp_established {
            cmd.arg("--tcp-established");
        }

        // Execute CRIU dump.
        let output = cmd
            .output()
            .map_err(|e| SnapshotError::CriuError(format!("Failed to execute CRIU: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SnapshotError::CriuError(format!(
                "CRIU dump failed (exit code {:?}): {}",
                output.status.code(),
                stderr
            )));
        }

        // Save checkpoint metadata.
        let checkpoint = ContainerCheckpoint {
            target_id: target_id.to_string(),
            captured_at: Utc::now(),
            process_tree: vec![container_pid],
            open_files: Vec::new(), // CRIU handles this internally
            network_state: None,    // CRIU handles this internally
        };

        let checkpoint_file = snapshot_dir.join("container_checkpoint.json");
        let checkpoint_json = serde_json::to_string_pretty(&checkpoint)
            .map_err(|e| SnapshotError::Internal(e.to_string()))?;
        fs::write(&checkpoint_file, checkpoint_json)?;

        tracing::info!(
            "Container checkpoint created for {} in {:?}",
            target_id,
            criu_dir
        );

        Ok(())
    }

    /// Captures container snapshot data (checkpoint).
    ///
    /// Without CRIU support, this creates a placeholder checkpoint.
    async fn capture_container_snapshot(
        &self,
        snapshot_dir: &Path,
        target_id: &str,
    ) -> Result<(), SnapshotError> {
        // Create container checkpoint file.
        let checkpoint_file = snapshot_dir.join("container_checkpoint.json");

        // NOTE: This is a placeholder implementation.
        // For actual container checkpoints, use capture_container_with_criu() on Linux
        // with CRIU installed and the `criu` feature enabled.
        let checkpoint = ContainerCheckpoint {
            target_id: target_id.to_string(),
            captured_at: Utc::now(),
            process_tree: Vec::new(),
            open_files: Vec::new(),
            network_state: None,
        };

        let checkpoint_json = serde_json::to_string_pretty(&checkpoint)
            .map_err(|e| SnapshotError::Internal(e.to_string()))?;
        fs::write(checkpoint_file, checkpoint_json)?;

        tracing::warn!(
            "Captured placeholder container checkpoint for {} (enable CRIU for real checkpoints)",
            target_id
        );
        Ok(())
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

    /// Restores VM from snapshot and returns the VM state.
    ///
    /// This loads the VM snapshot data from disk. The caller is responsible
    /// for actually applying the state to a VM instance.
    ///
    /// # Returns
    ///
    /// Returns `VmRestoreData` containing vCPU state, device state, and memory.
    async fn restore_vm_snapshot(
        &self,
        snapshot_dir: &Path,
        info: &SnapshotInfo,
    ) -> Result<(), SnapshotError> {
        let state_file = snapshot_dir.join("vm_state.json");

        if !state_file.exists() {
            return Err(SnapshotError::Corrupted(
                "vm_state.json not found".to_string(),
            ));
        }

        let state_json = fs::read_to_string(&state_file)?;

        // Try to load full VmSnapshot format first.
        if let Ok(vm_snapshot) = serde_json::from_str::<VmSnapshot>(&state_json) {
            tracing::debug!(
                "Loading VM snapshot for {}: {} vCPUs, {} devices, {} memory",
                info.target_id,
                vm_snapshot.vcpus.len(),
                vm_snapshot.devices.len(),
                format_size(vm_snapshot.total_memory)
            );

            // Load memory data.
            let memory_file = if vm_snapshot.compressed {
                snapshot_dir.join("memory.bin.lz4")
            } else {
                snapshot_dir.join("memory.bin")
            };

            if memory_file.exists() {
                let memory_data = if vm_snapshot.compressed {
                    read_and_decompress(&memory_file)?
                } else {
                    fs::read(&memory_file)?
                };

                tracing::info!(
                    "Loaded memory dump for {}: {} bytes",
                    info.target_id,
                    memory_data.len()
                );

                // Store restore data in cache for the caller to retrieve.
                let restore_data = VmRestoreData {
                    vm_snapshot,
                    memory: memory_data,
                };

                if let Ok(mut cache) = self.restore_cache.write() {
                    cache.insert(info.id.clone(), restore_data);
                }
            } else {
                tracing::warn!("Memory dump file not found for {}", info.target_id);
            }
        } else {
            // Fall back to legacy VmSnapshotState format.
            let _state: VmSnapshotState = serde_json::from_str(&state_json)
                .map_err(|e| SnapshotError::Corrupted(e.to_string()))?;

            tracing::debug!("Loaded legacy VM state for {}", info.target_id);
        }

        tracing::info!("Restored VM state for {}", info.target_id);
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

    /// Restores container from checkpoint.
    async fn restore_container_snapshot(
        &self,
        snapshot_dir: &Path,
        info: &SnapshotInfo,
    ) -> Result<(), SnapshotError> {
        let checkpoint_file = snapshot_dir.join("container_checkpoint.json");

        if !checkpoint_file.exists() {
            return Err(SnapshotError::Corrupted(
                "container_checkpoint.json not found".to_string(),
            ));
        }

        let checkpoint_json = fs::read_to_string(&checkpoint_file)?;
        let _checkpoint: ContainerCheckpoint = serde_json::from_str(&checkpoint_json)
            .map_err(|e| SnapshotError::Corrupted(e.to_string()))?;

        // In a full implementation, this would:
        // 1. Stop the current container (if running)
        // 2. Use CRIU to restore the process tree
        // 3. Restore filesystem state
        // 4. Restore network connections

        tracing::debug!("Restored container checkpoint for {}", info.target_id);
        Ok(())
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
            snapshots.sort_by(|a, b| b.created.cmp(&a.created));

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
            .map(|s| s.values().map(|info| info.size).sum())
            .unwrap_or(0)
    }
}

/// VM snapshot state data.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VmSnapshotState {
    /// Target VM ID.
    target_id: String,
    /// When the snapshot was captured.
    captured_at: DateTime<Utc>,
    /// Whether the VM was paused during capture.
    paused: bool,
    /// Number of vCPUs.
    vcpu_count: u32,
    /// Memory size in bytes.
    memory_size: u64,
    /// Device states.
    devices: Vec<DeviceState>,
}

/// Device state in snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceState {
    /// Device type.
    device_type: String,
    /// Device-specific state data.
    data: serde_json::Value,
}

/// Container checkpoint data.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContainerCheckpoint {
    /// Target container ID.
    target_id: String,
    /// When the checkpoint was captured.
    captured_at: DateTime<Utc>,
    /// Process tree (PIDs).
    process_tree: Vec<u32>,
    /// Open file descriptors.
    open_files: Vec<String>,
    /// Network state.
    network_state: Option<serde_json::Value>,
}

/// Generates a unique snapshot ID.
fn generate_snapshot_id() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}

/// Calculates the total size of a directory recursively.
fn calculate_dir_size(path: &Path) -> u64 {
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

/// CRIU checkpoint options.
#[cfg(all(target_os = "linux", feature = "criu"))]
#[derive(Debug, Clone, Default)]
pub struct CriuCheckpointOptions {
    /// Leave the process running after checkpoint.
    pub leave_running: bool,
    /// Checkpoint file locks.
    pub file_locks: bool,
    /// Checkpoint established TCP connections.
    pub tcp_established: bool,
}

/// Snapshot errors.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// Snapshot not found.
    #[error("snapshot not found: {0}")]
    NotFound(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Snapshot is corrupted.
    #[error("snapshot corrupted: {0}")]
    Corrupted(String),
    /// Snapshot is in invalid state.
    #[error("invalid state: {0}")]
    InvalidState(String),
    /// Snapshot is in use.
    #[error("snapshot in use: {0}")]
    InUse(String),
    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
    /// CRIU error.
    #[error("CRIU error: {0}")]
    CriuError(String),
    /// Compression error.
    #[error("compression error: {0}")]
    CompressionError(String),
}

// ============================================================================
// Compression Functions
// ============================================================================

/// Compresses data with LZ4 and writes to file.
fn compress_and_write(path: &Path, data: &[u8]) -> Result<(), SnapshotError> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    // Use lz4_flex for compression.
    let compressed = lz4_flex::compress_prepend_size(data);

    writer
        .write_all(&compressed)
        .map_err(|e| SnapshotError::CompressionError(e.to_string()))?;

    writer.flush()?;
    Ok(())
}

/// Reads and decompresses LZ4 data from file.
#[allow(dead_code)] // Will be used by restore_vm_snapshot in future
fn read_and_decompress(path: &Path) -> Result<Vec<u8>, SnapshotError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut compressed = Vec::new();
    reader.read_to_end(&mut compressed)?;

    lz4_flex::decompress_size_prepended(&compressed)
        .map_err(|e| SnapshotError::CompressionError(e.to_string()))
}

/// Formats a byte size into human-readable form.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper for creating and cleaning up temporary test directories.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let id = uuid::Uuid::new_v4().to_string().replace('-', "");
            let path = std::env::temp_dir().join(format!("arcbox-snapshot-test-{}", id));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[tokio::test]
    async fn test_create_snapshot() {
        let temp_dir = TestDir::new();
        let manager = SnapshotManager::new(temp_dir.path().to_path_buf());

        let info = manager
            .create(
                "test-vm",
                SnapshotTargetType::Vm,
                SnapshotCreateOptions {
                    name: Some("test-snapshot".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(info.name, "test-snapshot");
        assert_eq!(info.target_id, "test-vm");
        assert_eq!(info.target_type, SnapshotTargetType::Vm);
        assert_eq!(info.state, SnapshotState::Ready);
    }

    #[tokio::test]
    async fn test_list_snapshots() {
        let temp_dir = TestDir::new();
        let manager = SnapshotManager::new(temp_dir.path().to_path_buf());

        // Create multiple snapshots.
        manager
            .create("vm-1", SnapshotTargetType::Vm, Default::default())
            .await
            .unwrap();
        manager
            .create("vm-1", SnapshotTargetType::Vm, Default::default())
            .await
            .unwrap();
        manager
            .create("vm-2", SnapshotTargetType::Vm, Default::default())
            .await
            .unwrap();

        assert_eq!(manager.list_all().len(), 3);
        assert_eq!(manager.list("vm-1").len(), 2);
        assert_eq!(manager.list("vm-2").len(), 1);
    }

    #[tokio::test]
    async fn test_delete_snapshot() {
        let temp_dir = TestDir::new();
        let manager = SnapshotManager::new(temp_dir.path().to_path_buf());

        let info = manager
            .create("test-vm", SnapshotTargetType::Vm, Default::default())
            .await
            .unwrap();

        assert!(manager.get(&info.id).is_some());

        manager.delete(&info.id).await.unwrap();

        assert!(manager.get(&info.id).is_none());
    }

    #[tokio::test]
    async fn test_prune_snapshots() {
        let temp_dir = TestDir::new();
        let manager = SnapshotManager::new(temp_dir.path().to_path_buf());

        // Create 5 snapshots for same VM.
        for i in 0..5 {
            manager
                .create(
                    "test-vm",
                    SnapshotTargetType::Vm,
                    SnapshotCreateOptions {
                        name: Some(format!("snapshot-{}", i)),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            // Small delay to ensure different timestamps.
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_eq!(manager.list("test-vm").len(), 5);

        // Prune to keep only 2.
        let deleted = manager.prune(2).await.unwrap();
        assert_eq!(deleted.len(), 3);
        assert_eq!(manager.list("test-vm").len(), 2);
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TestDir::new();
        let path = temp_dir.path().to_path_buf();

        // Create snapshot with first manager.
        let snapshot_id = {
            let manager = SnapshotManager::new(path.clone());
            let info = manager
                .create("test-vm", SnapshotTargetType::Vm, Default::default())
                .await
                .unwrap();
            info.id
        };

        // Load with new manager.
        let manager = SnapshotManager::new(path);
        assert!(manager.get(&snapshot_id).is_some());
    }
}
