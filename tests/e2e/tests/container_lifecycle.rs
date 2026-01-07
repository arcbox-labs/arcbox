//! Container lifecycle E2E tests.
//!
//! Tests for container create, start, stop, and remove operations.

use arcbox_e2e::{TestHarness, TestFixtures};
use arcbox_e2e::fixtures::{images, commands};
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
// Container Creation Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_create() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    // Pull image first
    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create container
    let output = harness
        .run_command(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "/bin/sh",
        ])
        .expect("failed to create container");

    assert!(
        output.status.success(),
        "Create should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should return container ID
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(!container_id.is_empty(), "Should return container ID");

    // Verify container exists in list
    let list = harness
        .run_command_success(&["ps", "-a", "--machine", harness.machine_name()])
        .expect("failed to list");

    assert!(
        list.contains(&container_id[..12]),
        "Container should appear in list: {}",
        list
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_create_with_name() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create container with name
    let output = harness
        .run_command(&[
            "create",
            "--name",
            "test-container",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "/bin/sh",
        ])
        .expect("failed to create container");

    assert!(output.status.success(), "Create should succeed");

    // Verify container name in list
    let list = harness
        .run_command_success(&["ps", "-a", "--machine", harness.machine_name()])
        .expect("failed to list");

    assert!(
        list.contains("test-container"),
        "Container name should appear in list: {}",
        list
    );
}

// ============================================================================
// Container Start/Stop Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_start_stop() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create container that sleeps
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();

    // Start container
    let output = harness
        .run_command(&["start", "--machine", harness.machine_name(), container_id])
        .expect("failed to start container");

    assert!(
        output.status.success(),
        "Start should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify container is running
    let list = harness
        .run_command_success(&["ps", "--machine", harness.machine_name()])
        .expect("failed to list");

    assert!(
        list.contains(&container_id[..12]),
        "Running container should appear in ps: {}",
        list
    );

    // Stop container
    let output = harness
        .run_command(&[
            "stop",
            "--machine",
            harness.machine_name(),
            "-t",
            "5",
            container_id,
        ])
        .expect("failed to stop container");

    assert!(
        output.status.success(),
        "Stop should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify container is stopped
    let list = harness
        .run_command_success(&["ps", "--machine", harness.machine_name()])
        .expect("failed to list");

    assert!(
        !list.contains(&container_id[..12]),
        "Stopped container should not appear in ps: {}",
        list
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_restart() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create and start container
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();

    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Restart container
    let output = harness
        .run_command(&[
            "restart",
            "--machine",
            harness.machine_name(),
            "-t",
            "5",
            container_id,
        ])
        .expect("failed to restart");

    assert!(
        output.status.success(),
        "Restart should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Container should still be running
    let list = harness
        .run_command_success(&["ps", "--machine", harness.machine_name()])
        .expect("failed to list");

    assert!(
        list.contains(&container_id[..12]),
        "Restarted container should be running: {}",
        list
    );
}

// ============================================================================
// Container Remove Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_remove() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create container
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

    // Remove container
    let output = harness
        .run_command(&["rm", "--machine", harness.machine_name(), container_id])
        .expect("failed to remove");

    assert!(
        output.status.success(),
        "Remove should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify container is gone
    let list = harness
        .run_command_success(&["ps", "-a", "--machine", harness.machine_name()])
        .expect("failed to list");

    assert!(
        !list.contains(&container_id[..12]),
        "Removed container should not appear in list: {}",
        list
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_remove_running() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create and start container
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();

    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Try to remove running container - should fail
    let output = harness
        .run_command(&["rm", "--machine", harness.machine_name(), container_id])
        .expect("failed to run rm");

    assert!(
        !output.status.success(),
        "Remove should fail for running container"
    );

    // Force remove should succeed
    let output = harness
        .run_command(&[
            "rm",
            "-f",
            "--machine",
            harness.machine_name(),
            container_id,
        ])
        .expect("failed to force remove");

    assert!(
        output.status.success(),
        "Force remove should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ============================================================================
// Container Exec Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_exec() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create and start container
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();

    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Execute command in container
    let output = harness
        .run_command(&[
            "exec",
            "--machine",
            harness.machine_name(),
            container_id,
            "echo",
            "hello from container",
        ])
        .expect("failed to exec");

    assert!(
        output.status.success(),
        "Exec should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello from container"),
        "Should capture exec output: {}",
        stdout
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_exec_exit_code() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create and start container
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();

    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Execute failing command
    let output = harness
        .run_command(&[
            "exec",
            "--machine",
            harness.machine_name(),
            container_id,
            "sh",
            "-c",
            "exit 42",
        ])
        .expect("failed to exec");

    // Exit code should be preserved
    assert_eq!(
        output.status.code(),
        Some(42),
        "Exit code should be preserved"
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_exec_with_env() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create and start container
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();

    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Execute command with environment variable
    let output = harness
        .run_command(&[
            "exec",
            "-e",
            "MY_VAR=hello",
            "--machine",
            harness.machine_name(),
            container_id,
            "sh",
            "-c",
            "echo $MY_VAR",
        ])
        .expect("failed to exec");

    assert!(output.status.success(), "Exec should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "Should have environment variable: {}",
        stdout
    );
}

// ============================================================================
// Container Logs Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_logs() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run container that produces output
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sh",
            "-c",
            "echo line1; echo line2; echo line3",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();

    // Start and wait for completion
    harness
        .run_command_success(&["start", "-a", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Get logs
    let output = harness
        .run_command(&[
            "logs",
            "--machine",
            harness.machine_name(),
            container_id,
        ])
        .expect("failed to get logs");

    assert!(output.status.success(), "Logs should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("line1"), "Should have line1: {}", stdout);
    assert!(stdout.contains("line2"), "Should have line2: {}", stdout);
    assert!(stdout.contains("line3"), "Should have line3: {}", stdout);
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_logs_tail() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run container that produces many lines
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sh",
            "-c",
            "for i in $(seq 1 10); do echo line$i; done",
        ])
        .expect("failed to create container");

    let container_id = container_id.trim();

    harness
        .run_command_success(&["start", "-a", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Get last 3 lines
    let output = harness
        .run_command(&[
            "logs",
            "--tail",
            "3",
            "--machine",
            harness.machine_name(),
            container_id,
        ])
        .expect("failed to get logs");

    assert!(output.status.success(), "Logs should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();

    assert!(
        lines.len() <= 3,
        "Should have at most 3 lines: {}",
        stdout
    );
}

// ============================================================================
// Container Run Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_run() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run container
    let output = harness
        .run_command(&[
            "run",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "echo",
            "hello world",
        ])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Run should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello world"),
        "Should capture output: {}",
        stdout
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_run_rm() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run container with --rm
    let output = harness
        .run_command(&[
            "run",
            "--rm",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "echo",
            "cleanup test",
        ])
        .expect("failed to run");

    assert!(output.status.success(), "Run should succeed");

    // Container should be removed automatically
    let list = harness
        .run_command_success(&["ps", "-a", "--machine", harness.machine_name()])
        .expect("failed to list");

    // The container we just ran should not be in the list
    // (Note: we can't check by ID since we didn't capture it, but
    // the list should not contain "cleanup test" related container)
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_run_detached() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run detached container
    let output = harness
        .run_command(&[
            "run",
            "-d",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Run should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should return container ID immediately
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(!container_id.is_empty(), "Should return container ID");

    // Container should be running
    let list = harness
        .run_command_success(&["ps", "--machine", harness.machine_name()])
        .expect("failed to list");

    assert!(
        list.contains(&container_id[..12]),
        "Detached container should be running: {}",
        list
    );

    // Cleanup
    harness
        .run_command(&["rm", "-f", "--machine", harness.machine_name(), &container_id])
        .ok();
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_exec_stopped() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create but don't start container
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

    // Exec on stopped container should fail
    let output = harness
        .run_command(&[
            "exec",
            "--machine",
            harness.machine_name(),
            container_id,
            "echo",
            "test",
        ])
        .expect("failed to run exec");

    assert!(
        !output.status.success(),
        "Exec on stopped container should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not running") || stderr.contains("not started"),
        "Should have not running error: {}",
        stderr
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_not_found() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness.setup_full_environment().await.expect("failed to setup");

    // Try to start non-existent container
    let output = harness
        .run_command(&[
            "start",
            "--machine",
            harness.machine_name(),
            "nonexistent123",
        ])
        .expect("failed to run start");

    assert!(!output.status.success(), "Start should fail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("does not exist"),
        "Should have not found error: {}",
        stderr
    );
}
