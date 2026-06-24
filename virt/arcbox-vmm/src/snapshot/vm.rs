use super::compression::{compress_and_write, read_and_decompress};
use super::state::VmSnapshotState;
use super::util::format_size;
use super::{
    SnapshotCreateOptions, SnapshotError, SnapshotInfo, SnapshotManager, VmRestoreData,
    VmSnapshotContext,
};
use chrono::Utc;
use std::fs;
use std::path::Path;

use arcbox_hypervisor::VmSnapshot;

impl SnapshotManager {
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
                .map_or(arcbox_hypervisor::CpuArch::native(), |v| v.arch),
            vcpus: context.vcpu_snapshots.clone(),
            devices: context
                .device_snapshots
                .iter()
                .map(|d| arcbox_hypervisor::DeviceSnapshot {
                    device_type: d.device_type,
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
                fs::metadata(&memory_file).map_or(0, |m| m.len())
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
    pub(super) async fn capture_vm_snapshot(
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

    /// Restores VM from snapshot and returns the VM state.
    ///
    /// This loads the VM snapshot data from disk. The caller is responsible
    /// for actually applying the state to a VM instance.
    ///
    /// # Returns
    ///
    /// Returns `VmRestoreData` containing vCPU state, device state, and memory.
    pub(super) async fn restore_vm_snapshot(
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
}
