#[cfg(test)]
use super::*;
use std::fs;
use std::path::{Path, PathBuf};

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
