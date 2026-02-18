//! VM lifecycle E2E tests.
//!
//! Tests for VM creation, startup, shutdown, and agent connectivity.

use arcbox_e2e::vm::MachineStatus;
use arcbox_e2e::{TestConfig, TestFixtures, TestHarness, VmController};
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
// VM Creation Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_machine_create() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    // Start daemon
    harness
        .start_daemon()
        .await
        .expect("failed to start daemon");

    // Create machine
    harness
        .create_machine()
        .await
        .expect("failed to create machine");

    // Verify machine exists
    let output = harness
        .run_command(&["machine", "list"])
        .expect("failed to list machines");
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(harness.machine_name()),
        "Machine should appear in list"
    );
}

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_machine_create_with_custom_resources() {
    if skip_if_missing_resources() {
        return;
    }

    let config = TestConfig {
        cpus: 4,
        memory_mb: 2048,
        ..TestConfig::default()
    };

    let mut harness = TestHarness::new(config).expect("failed to create harness");

    harness
        .start_daemon()
        .await
        .expect("failed to start daemon");
    harness
        .create_machine()
        .await
        .expect("failed to create machine");

    // Machine should be created with custom resources
    let output = harness
        .run_command(&["machine", "inspect", harness.machine_name()])
        .expect("failed to inspect machine");

    assert!(output.status.success());
}

// ============================================================================
// VM Startup Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_machine_start_stop() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .start_daemon()
        .await
        .expect("failed to start daemon");
    harness
        .create_machine()
        .await
        .expect("failed to create machine");

    // Start machine
    harness
        .start_machine()
        .await
        .expect("failed to start machine");

    // Verify machine is running
    let socket = harness.socket_path();
    let vm = VmController::new(
        &harness.config.arcbox_binary,
        &socket,
        harness.machine_name(),
    );

    assert!(
        vm.is_running().expect("failed to get status"),
        "Machine should be running"
    );

    // Stop machine
    harness
        .stop_machine()
        .await
        .expect("failed to stop machine");

    // Verify machine is stopped
    let status = vm.status().expect("failed to get status");
    assert!(
        matches!(status, MachineStatus::Stopped | MachineStatus::Created),
        "Machine should be stopped"
    );
}

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_machine_double_start() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .start_daemon()
        .await
        .expect("failed to start daemon");
    harness
        .create_machine()
        .await
        .expect("failed to create machine");
    harness
        .start_machine()
        .await
        .expect("failed to start machine");

    // Second start should be idempotent or return error
    let result = harness.start_machine().await;

    // Either succeeds (idempotent) or fails with "already running"
    if let Err(e) = result {
        assert!(
            e.to_string().contains("already running") || e.to_string().contains("already"),
            "Should fail with already running error: {}",
            e
        );
    }
}

// ============================================================================
// Agent Connectivity Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_agent_ping() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup environment");
    harness
        .create_machine()
        .await
        .expect("failed to create machine");
    harness
        .start_machine()
        .await
        .expect("failed to start machine");

    // Ping should succeed
    let output = harness
        .run_command(&["machine", "ping", harness.machine_name()])
        .expect("failed to run ping");

    assert!(
        output.status.success(),
        "Ping should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_agent_system_info() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup environment");
    harness
        .create_machine()
        .await
        .expect("failed to create machine");
    harness
        .start_machine()
        .await
        .expect("failed to start machine");

    // Get system info
    let socket = harness.socket_path();
    let vm = VmController::new(
        &harness.config.arcbox_binary,
        &socket,
        harness.machine_name(),
    );

    let info = vm.get_system_info().expect("failed to get system info");

    // Verify we got reasonable info
    assert!(
        !info.kernel_version.is_empty(),
        "Should have kernel version"
    );
    assert!(info.cpu_count > 0, "Should have CPUs");
    assert!(info.memory_total > 0, "Should have memory");
}

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_agent_ping_latency() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup environment");
    harness
        .create_machine()
        .await
        .expect("failed to create machine");
    harness
        .start_machine()
        .await
        .expect("failed to start machine");

    use arcbox_e2e::AgentClient;

    let socket = harness.socket_path();
    let agent = AgentClient::new(
        &harness.config.arcbox_binary,
        &socket,
        harness.machine_name(),
    );

    // Measure ping latency
    let mut latencies = Vec::new();
    for _ in 0..5 {
        let latency = agent.ping().expect("ping failed");
        latencies.push(latency);
    }

    // Calculate average
    let avg: Duration = latencies.iter().sum::<Duration>() / latencies.len() as u32;

    println!("Average ping latency: {:?}", avg);

    // Latency should be reasonable (< 100ms for local vsock)
    assert!(
        avg < Duration::from_millis(100),
        "Ping latency too high: {:?}",
        avg
    );
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_machine_not_found() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .start_daemon()
        .await
        .expect("failed to start daemon");

    // Try to start non-existent machine
    let output = harness.run_command(&["machine", "start", "nonexistent"]);

    if let Ok(out) = output {
        assert!(
            !out.status.success(),
            "Should fail for non-existent machine"
        );

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("not found") || stderr.contains("does not exist"),
            "Should have not found error: {}",
            stderr
        );
    }
}

#[tokio::test]
#[ignore = "requires VM resources"]
async fn test_machine_stop_when_not_running() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .start_daemon()
        .await
        .expect("failed to start daemon");
    harness
        .create_machine()
        .await
        .expect("failed to create machine");

    // Try to stop machine that's not running
    // This should either succeed (idempotent) or fail gracefully
    let result = harness.stop_machine().await;

    // Either succeeds or fails with "not running"
    if let Err(e) = result {
        let msg = e.to_string();
        assert!(
            msg.contains("not running") || msg.contains("already stopped"),
            "Should fail gracefully: {}",
            msg
        );
    }
}
