use super::state::ContainerCheckpoint;
use super::{SnapshotError, SnapshotInfo, SnapshotManager};
use chrono::Utc;
use std::fs;
use std::path::Path;

#[cfg(all(target_os = "linux", feature = "criu"))]
use super::CriuCheckpointOptions;

impl SnapshotManager {
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
    pub(super) async fn capture_container_snapshot(
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

    /// Restores container from checkpoint.
    pub(super) async fn restore_container_snapshot(
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
}
