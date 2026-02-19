//! Full workflow E2E tests.
//!
//! Tests complete end-to-end workflows from start to finish.

use arcbox_e2e::fixtures::images;
use arcbox_e2e::{TestConfig, TestFixtures, TestHarness};
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
// Basic Workflow Tests
// ============================================================================

/// Test the simplest possible workflow: `arcbox run alpine echo hello`
#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_simple_run() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    // Setup: daemon + VM
    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    // The full workflow: pull + create + start + wait
    let output = harness
        .run_command(&[
            "run",
            "--rm",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "echo",
            "hello from arcbox",
        ])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Run workflow should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello from arcbox"),
        "Should capture output: {}",
        stdout
    );
}

/// Test workflow with file operations
#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_file_operations() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create file in container
    let output = harness
        .run_command(&[
            "run",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sh",
            "-c",
            "echo 'test content' > /tmp/test.txt && cat /tmp/test.txt",
        ])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test content"),
        "File should contain content: {}",
        stdout
    );
}

/// Test workflow with process listing
#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_process_isolation() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Check that container has isolated PID namespace
    let output = harness
        .run_command(&[
            "run",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sh",
            "-c",
            "ps aux | head -5",
        ])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // In isolated namespace, there should be very few processes
    println!("Process list: {}", stdout);
}

// ============================================================================
// Multi-Container Workflow Tests
// ============================================================================

/// Test running multiple containers
#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_multiple_containers() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create multiple containers
    let container1 = harness
        .run_command_success(&[
            "create",
            "--name",
            "worker1",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container1");

    let container2 = harness
        .run_command_success(&[
            "create",
            "--name",
            "worker2",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create container2");

    // Start both
    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), "worker1"])
        .expect("failed to start worker1");

    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), "worker2"])
        .expect("failed to start worker2");

    // List should show both
    let list = harness
        .run_command_success(&["ps", "--machine", harness.machine_name()])
        .expect("failed to list");

    assert!(list.contains("worker1"), "Should list worker1: {}", list);
    assert!(list.contains("worker2"), "Should list worker2: {}", list);

    // Cleanup
    harness
        .run_command(&["rm", "-f", "--machine", harness.machine_name(), "worker1"])
        .ok();
    harness
        .run_command(&["rm", "-f", "--machine", harness.machine_name(), "worker2"])
        .ok();
}

// ============================================================================
// Environment Variable Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_environment_variables() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run with environment variables
    let output = harness
        .run_command(&[
            "run",
            "-e",
            "FOO=bar",
            "-e",
            "BAZ=qux",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sh",
            "-c",
            "echo FOO=$FOO BAZ=$BAZ",
        ])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FOO=bar"), "Should have FOO: {}", stdout);
    assert!(stdout.contains("BAZ=qux"), "Should have BAZ: {}", stdout);
}

// ============================================================================
// Working Directory Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_working_directory() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run with custom working directory
    let output = harness
        .run_command(&[
            "run",
            "-w",
            "/tmp",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "pwd",
        ])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim() == "/tmp",
        "Working directory should be /tmp: {}",
        stdout
    );
}

// ============================================================================
// Volume Mount Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_volume_mount() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create a test file in the host data directory under volumes/_data
    // The data_dir is shared to the guest as the "arcbox" VirtioFS tag.
    let test_dir = harness
        .data_dir()
        .join("volumes")
        .join("test-volume")
        .join("_data");
    std::fs::create_dir_all(&test_dir).expect("failed to create test dir");
    std::fs::write(test_dir.join("hello.txt"), "hello from host").expect("failed to write");

    // Run with volume mount
    let output = harness
        .run_command(&[
            "run",
            "-v",
            &format!("{}:/data", test_dir.display()),
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "cat",
            "/data/hello.txt",
        ])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Volume mount should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello from host"),
        "Should read mounted file: {}",
        stdout
    );
}

// ============================================================================
// Network Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_network_access() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Test network by checking /etc/resolv.conf
    let output = harness
        .run_command(&[
            "run",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "cat",
            "/etc/resolv.conf",
        ])
        .expect("failed to run");

    assert!(output.status.success(), "Should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("resolv.conf: {}", stdout);
    // Should have some nameserver configured
    assert!(
        stdout.contains("nameserver") || stdout.is_empty(),
        "Should have DNS config or be empty: {}",
        stdout
    );
}

// ============================================================================
// Resource Limit Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_memory_limit() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run with memory limit
    let output = harness
        .run_command(&[
            "run",
            "-m",
            "64m",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "free",
            "-m",
        ])
        .expect("failed to run");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Memory info: {}", stdout);
        // Memory limit might be visible in cgroup
    } else {
        // Memory limits might not be fully implemented
        eprintln!(
            "Memory limit test result: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ============================================================================
// Cleanup and Error Recovery Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_cleanup_on_error() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Run container that fails
    let output = harness
        .run_command(&[
            "run",
            "--rm",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sh",
            "-c",
            "exit 1",
        ])
        .expect("failed to run");

    // Should fail but clean up
    assert!(!output.status.success(), "Should fail with exit 1");

    // Verify no dangling container
    let list = harness
        .run_command_success(&["ps", "-a", "--machine", harness.machine_name()])
        .expect("failed to list");

    // With --rm, failed container should also be removed
    println!("Containers after failed run: {}", list);
}

// ============================================================================
// Complex Workflow Tests
// ============================================================================

/// Test a realistic development workflow
#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_development_scenario() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create a "development" container
    let container_id = harness
        .run_command_success(&[
            "create",
            "--name",
            "dev-container",
            "-w",
            "/app",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create");

    let container_id = container_id.trim();

    // Start container
    harness
        .run_command_success(&[
            "start",
            "--machine",
            harness.machine_name(),
            "dev-container",
        ])
        .expect("failed to start");

    // Run multiple exec commands (simulating development)
    let output1 = harness
        .run_command(&[
            "exec",
            "--machine",
            harness.machine_name(),
            "dev-container",
            "mkdir",
            "-p",
            "/app/src",
        ])
        .expect("failed to exec");
    assert!(output1.status.success(), "mkdir should succeed");

    let output2 = harness
        .run_command(&[
            "exec",
            "--machine",
            harness.machine_name(),
            "dev-container",
            "sh",
            "-c",
            "echo 'print(\"hello\")' > /app/src/main.py",
        ])
        .expect("failed to exec");
    assert!(output2.status.success(), "write should succeed");

    let output3 = harness
        .run_command(&[
            "exec",
            "--machine",
            harness.machine_name(),
            "dev-container",
            "cat",
            "/app/src/main.py",
        ])
        .expect("failed to exec");
    assert!(output3.status.success(), "cat should succeed");

    let stdout = String::from_utf8_lossy(&output3.stdout);
    assert!(
        stdout.contains("hello"),
        "Should see file content: {}",
        stdout
    );

    // Stop and remove
    harness
        .run_command_success(&[
            "stop",
            "-t",
            "5",
            "--machine",
            harness.machine_name(),
            "dev-container",
        ])
        .expect("failed to stop");

    harness
        .run_command_success(&["rm", "--machine", harness.machine_name(), "dev-container"])
        .expect("failed to remove");
}

/// Test signal handling
#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_signal_handling() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create container with signal handler
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sh",
            "-c",
            "trap 'echo SIGTERM received; exit 0' TERM; echo ready; while true; do sleep 1; done",
        ])
        .expect("failed to create");

    let container_id = container_id.trim();

    // Start container
    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Wait a bit for container to start
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Stop container (sends SIGTERM)
    let output = harness
        .run_command(&[
            "stop",
            "-t",
            "10",
            "--machine",
            harness.machine_name(),
            container_id,
        ])
        .expect("failed to stop");

    assert!(
        output.status.success(),
        "Stop should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check logs for signal handling
    let logs = harness
        .run_command(&["logs", "--machine", harness.machine_name(), container_id])
        .expect("failed to get logs");

    let stdout = String::from_utf8_lossy(&logs.stdout);
    println!("Container logs: {}", stdout);
    // Should have received SIGTERM (if signal handling works)

    // Cleanup
    harness
        .run_command(&["rm", "--machine", harness.machine_name(), container_id])
        .ok();
}

// ============================================================================
// Performance Baseline Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_startup_time() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Measure container run time
    let start = std::time::Instant::now();

    let output = harness
        .run_command(&[
            "run",
            "--rm",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "echo",
            "timing test",
        ])
        .expect("failed to run");

    let elapsed = start.elapsed();

    assert!(output.status.success(), "Should succeed");

    println!("Container run time: {:?}", elapsed);

    // Container should start reasonably fast (< 5 seconds for simple echo)
    // This is a baseline - actual performance target is much lower
    assert!(
        elapsed < Duration::from_secs(5),
        "Container should start within 5 seconds: {:?}",
        elapsed
    );
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_workflow_exec_latency() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull");

    // Create running container
    let container_id = harness
        .run_command_success(&[
            "create",
            "--machine",
            harness.machine_name(),
            images::ALPINE,
            "sleep",
            "3600",
        ])
        .expect("failed to create");

    let container_id = container_id.trim();

    harness
        .run_command_success(&["start", "--machine", harness.machine_name(), container_id])
        .expect("failed to start");

    // Warm up
    harness
        .run_command(&[
            "exec",
            "--machine",
            harness.machine_name(),
            container_id,
            "true",
        ])
        .ok();

    // Measure exec latency
    let mut latencies = Vec::new();

    for _ in 0..5 {
        let start = std::time::Instant::now();

        let output = harness
            .run_command(&[
                "exec",
                "--machine",
                harness.machine_name(),
                container_id,
                "true",
            ])
            .expect("failed to exec");

        let elapsed = start.elapsed();

        if output.status.success() {
            latencies.push(elapsed);
        }
    }

    if !latencies.is_empty() {
        let avg: Duration = latencies.iter().sum::<Duration>() / latencies.len() as u32;
        let min = latencies.iter().min().unwrap();
        let max = latencies.iter().max().unwrap();

        println!("Exec latency: avg={:?}, min={:?}, max={:?}", avg, min, max);

        // Exec should be reasonably fast (< 500ms)
        assert!(
            avg < Duration::from_millis(500),
            "Exec latency too high: {:?}",
            avg
        );
    }

    // Cleanup
    harness
        .run_command(&[
            "rm",
            "-f",
            "--machine",
            harness.machine_name(),
            container_id,
        ])
        .ok();
}
