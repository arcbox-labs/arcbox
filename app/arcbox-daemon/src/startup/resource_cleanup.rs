//! Startup resource-cleanup policy.

use std::path::{Path, PathBuf};

use arcbox_core::persistence::MachinePersistence;

const DISK_IMAGE_NAMES: [&str; 2] = ["docker.img", "docker-rosetta.img"];

/// Why startup must scan for stale disk-image holders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResourceCleanupReason {
    /// Lock acquisition displaced a live previous daemon.
    TookOverLockHolder,
    /// Persisted state says a previous daemon was interrupted while a VM ran.
    InterruptedMachineRun,
}

/// Whether startup should run the expensive disk-image holder scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResourceCleanupDecision {
    /// No disk image exists, or this is a true clean start.
    Skip,
    /// Scan disk-image holders before VM startup.
    ScanDiskImageHolders { reason: ResourceCleanupReason },
}

/// Returns existing persistent Docker disk images that may have stale holders.
pub(super) fn disk_image_paths(data_subdir: &Path) -> Vec<PathBuf> {
    DISK_IMAGE_NAMES
        .iter()
        .map(|name| data_subdir.join(name))
        .filter(|path| path.exists())
        .collect()
}

/// Detects whether the previous daemon may have crashed while a VM was running.
pub(super) fn has_interrupted_running_machine(data_dir: &Path) -> bool {
    let persistence = MachinePersistence::new(data_dir.join("machines"));
    persistence
        .load_all()
        .iter()
        .any(|machine| machine.state.needs_recovery())
}

/// Computes the startup cleanup policy from explicit recovery signals.
pub(super) const fn decide(
    displaced_lock_holder: bool,
    interrupted_machine_run: bool,
    disk_images_exist: bool,
) -> ResourceCleanupDecision {
    if !disk_images_exist {
        return ResourceCleanupDecision::Skip;
    }

    if displaced_lock_holder {
        return ResourceCleanupDecision::ScanDiskImageHolders {
            reason: ResourceCleanupReason::TookOverLockHolder,
        };
    }

    if interrupted_machine_run {
        return ResourceCleanupDecision::ScanDiskImageHolders {
            reason: ResourceCleanupReason::InterruptedMachineRun,
        };
    }

    ResourceCleanupDecision::Skip
}

#[cfg(test)]
mod tests {
    use super::{
        ResourceCleanupDecision, ResourceCleanupReason, decide, disk_image_paths,
        has_interrupted_running_machine,
    };

    fn write_machine_config(data_dir: &Path, name: &str, state: &str) {
        let machine_dir = data_dir.join("machines").join(name);
        std::fs::create_dir_all(&machine_dir).unwrap();
        std::fs::write(
            machine_dir.join("config.toml"),
            format!(
                r#"
name = "{name}"
cpus = 2
memory_mb = 2048
disk_gb = 10
state = "{state}"
vm_id = "vm-{name}"
"#
            ),
        )
        .unwrap();
    }

    use std::path::Path;

    #[test]
    fn clean_start_without_images_skips() {
        assert_eq!(decide(false, false, false), ResourceCleanupDecision::Skip);
    }

    #[test]
    fn clean_start_with_images_skips() {
        assert_eq!(decide(false, false, true), ResourceCleanupDecision::Skip);
    }

    #[test]
    fn takeover_with_images_scans() {
        assert_eq!(
            decide(true, false, true),
            ResourceCleanupDecision::ScanDiskImageHolders {
                reason: ResourceCleanupReason::TookOverLockHolder
            }
        );
    }

    #[test]
    fn interrupted_running_machine_with_images_scans() {
        assert_eq!(
            decide(false, true, true),
            ResourceCleanupDecision::ScanDiskImageHolders {
                reason: ResourceCleanupReason::InterruptedMachineRun
            }
        );
    }

    #[test]
    fn takeover_and_interrupted_prefers_takeover_reason() {
        assert_eq!(
            decide(true, true, true),
            ResourceCleanupDecision::ScanDiskImageHolders {
                reason: ResourceCleanupReason::TookOverLockHolder
            }
        );
    }

    #[test]
    fn interrupted_without_images_skips() {
        assert_eq!(decide(false, true, false), ResourceCleanupDecision::Skip);
    }

    #[test]
    fn disk_image_paths_returns_existing_images() {
        let temp = tempfile::tempdir().unwrap();
        let data_subdir = temp.path().join("data");
        std::fs::create_dir_all(&data_subdir).unwrap();
        std::fs::write(data_subdir.join("docker.img"), b"").unwrap();

        assert_eq!(
            disk_image_paths(&data_subdir),
            vec![data_subdir.join("docker.img")]
        );
    }

    #[test]
    fn interrupted_running_machine_detects_crash_recovery_signal() {
        let temp = tempfile::tempdir().unwrap();
        write_machine_config(temp.path(), "arcbox", "running");

        assert!(has_interrupted_running_machine(temp.path()));
    }

    #[test]
    fn stopped_machine_does_not_trigger_resource_scan() {
        let temp = tempfile::tempdir().unwrap();
        write_machine_config(temp.path(), "arcbox", "stopped");

        assert!(!has_interrupted_running_machine(temp.path()));
    }

    #[test]
    fn missing_machine_state_does_not_trigger_resource_scan() {
        let temp = tempfile::tempdir().unwrap();

        assert!(!has_interrupted_running_machine(temp.path()));
    }
}
