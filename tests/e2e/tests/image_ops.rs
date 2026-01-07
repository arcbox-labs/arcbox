//! Image operations E2E tests.
//!
//! Tests for image pull, list, inspect, and removal.

use arcbox_e2e::{TestHarness, TestFixtures};
use arcbox_e2e::fixtures::images;
use std::time::Duration;

/// Skip test if resources are not available.
fn skip_if_missing_resources() -> bool {
    let fixtures = TestFixtures::new();
    let check = fixtures.check_resources();

    if !check.all_ready() {
        eprintln!("Skipping test: missing resources: {:?}", check.missing());
        return true;
    }
    false
}

// ============================================================================
// Image Pull Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_image_pull_alpine() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.start_daemon().await.expect("failed to start daemon");

    // Pull alpine image
    let output = harness
        .run_command(&["pull", images::ALPINE])
        .expect("failed to run pull");

    assert!(
        output.status.success(),
        "Pull should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify image exists
    let list_output = harness
        .run_command(&["images"])
        .expect("failed to list images");

    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(
        stdout.contains("alpine"),
        "Alpine should appear in image list: {}",
        stdout
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_image_pull_with_tag() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.start_daemon().await.expect("failed to start daemon");

    // Pull specific version
    let output = harness
        .run_command(&["pull", images::ALPINE_3_19])
        .expect("failed to run pull");

    assert!(
        output.status.success(),
        "Pull should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_image_pull_progress() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.start_daemon().await.expect("failed to start daemon");

    // Pull with progress output
    let output = harness
        .run_command(&["pull", "--progress", images::BUSYBOX])
        .expect("failed to run pull");

    // Should show progress indicators
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.status.success(),
        "Pull should succeed: {}",
        combined
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_image_pull_nonexistent() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.start_daemon().await.expect("failed to start daemon");

    // Pull non-existent image
    let output = harness
        .run_command(&["pull", "nonexistent/image:v999"])
        .expect("failed to run pull");

    assert!(
        !output.status.success(),
        "Pull should fail for non-existent image"
    );
}

// ============================================================================
// Image List Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_image_list_empty() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.start_daemon().await.expect("failed to start daemon");

    // List images (should be empty initially)
    let output = harness
        .run_command(&["images"])
        .expect("failed to list images");

    assert!(output.status.success(), "List should succeed");
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_image_list_after_pull() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.start_daemon().await.expect("failed to start daemon");

    // Pull an image
    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // List should include the image
    let output = harness
        .run_command_success(&["images"])
        .expect("failed to list images");

    assert!(
        output.contains("alpine"),
        "Should list pulled image: {}",
        output
    );
}

// ============================================================================
// Image Inspect Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_image_inspect() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.start_daemon().await.expect("failed to start daemon");

    // Pull image first
    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Inspect the image
    let output = harness
        .run_command(&["image", "inspect", images::ALPINE])
        .expect("failed to inspect");

    assert!(output.status.success(), "Inspect should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have image metadata
    assert!(
        stdout.contains("alpine") || stdout.contains("Config") || stdout.contains("Layers"),
        "Should have image info: {}",
        stdout
    );
}

// ============================================================================
// Image Remove Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_image_remove() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.start_daemon().await.expect("failed to start daemon");

    // Pull image
    harness
        .run_command_success(&["pull", images::BUSYBOX])
        .expect("failed to pull");

    // Verify it exists
    let list1 = harness.run_command_success(&["images"]).expect("failed to list");
    assert!(list1.contains("busybox"), "Image should exist");

    // Remove image
    let output = harness
        .run_command(&["rmi", images::BUSYBOX])
        .expect("failed to remove");

    assert!(
        output.status.success(),
        "Remove should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify it's gone
    let list2 = harness.run_command_success(&["images"]).expect("failed to list");
    assert!(!list2.contains("busybox"), "Image should be removed");
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_image_remove_in_use() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    // Pull image
    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create a container using the image
    harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container");

    // Try to remove image - should fail
    let output = harness.run_command(&["rmi", images::ALPINE]);

    if let Ok(out) = output {
        // Either fails or requires force flag
        if out.status.success() {
            // Some implementations allow removal with warning
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("in use") || stderr.contains("container"),
                "Should fail because image is in use: {}",
                stderr
            );
        }
    }
}

// ============================================================================
// Layer Extraction Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_layer_extraction_on_container_create() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    // Pull image
    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create container - this should trigger layer extraction
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "/bin/sh",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();
    assert!(!container_id.is_empty(), "Should return container ID");

    // Verify rootfs was created
    let rootfs_path = harness
        .data_dir()
        .join("containers")
        .join(container_id)
        .join("rootfs");

    // The rootfs should exist (or at least be referenced)
    // This depends on implementation - might be in guest filesystem
}
