//! Smoke tests for the E2E combination matrix.
//!
//! Each backend x distro combination has at least one smoke test that runs
//! `docker run --rm <image> echo ok` (or equivalent via the arcbox CLI).
//!
//! Matrix dimensions:
//!   - backend:  native_control_plane, guest_docker
//!   - distro:   alpine, ubuntu
//!
//! The backend is selected via `ARCBOX_TEST_BACKEND` env var or the
//! `TestConfig::with_backend` helper. The distro is selected per-test.

use arcbox_e2e::fixtures::{TestBackend, TestDistro};
use arcbox_e2e::{TestConfig, TestFixtures, TestHarness};

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

/// Generic smoke test: run `echo ok` on the given backend + distro combination.
async fn smoke_run(backend: TestBackend, distro: TestDistro) {
    if skip_if_missing_resources() {
        return;
    }

    let config = TestConfig::with_backend(&backend);
    let mut harness = TestHarness::new(config).expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    // Run the minimal smoke command: echo ok
    let output = harness
        .run_command(&["run", "--rm", distro.image(), "echo", "ok"])
        .expect("failed to run");

    assert!(
        output.status.success(),
        "Smoke test failed for {:?} + {:?}: {}",
        backend,
        distro,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ok"),
        "Expected 'ok' in output for {:?} + {:?}: {}",
        backend,
        distro,
        stdout
    );
}

// ============================================================================
// native_control_plane x alpine
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_smoke_native_alpine() {
    smoke_run(TestBackend::NativeControlPlane, TestDistro::Alpine).await;
}

// ============================================================================
// native_control_plane x ubuntu
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_smoke_native_ubuntu() {
    smoke_run(TestBackend::NativeControlPlane, TestDistro::Ubuntu).await;
}

// ============================================================================
// guest_docker x alpine
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_smoke_guest_docker_alpine() {
    smoke_run(TestBackend::GuestDocker, TestDistro::Alpine).await;
}

// ============================================================================
// guest_docker x ubuntu
// ============================================================================

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_smoke_guest_docker_ubuntu() {
    smoke_run(TestBackend::GuestDocker, TestDistro::Ubuntu).await;
}

// ============================================================================
// Extended smoke: verify basic container lifecycle per backend
// ============================================================================

/// Verify container create + start + exec + stop + rm works on the given backend.
async fn smoke_lifecycle(backend: TestBackend, distro: TestDistro) {
    if skip_if_missing_resources() {
        return;
    }

    let config = TestConfig::with_backend(&backend);
    let mut harness = TestHarness::new(config).expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup");

    // Create container
    let container_id = harness
        .run_command_success(&["create", distro.image(), "sleep", "300"])
        .expect("failed to create container");
    let container_id = container_id.trim();

    // Start container
    harness
        .run_command_success(&["start", container_id])
        .expect("failed to start");

    // Exec into container
    let output = harness
        .run_command(&["exec", container_id, "echo", "lifecycle-ok"])
        .expect("failed to exec");
    assert!(
        output.status.success(),
        "Exec failed for {:?} + {:?}: {}",
        backend,
        distro,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("lifecycle-ok"),
        "Exec output mismatch for {:?} + {:?}: {}",
        backend,
        distro,
        stdout
    );

    // Stop + remove
    harness
        .run_command(&["rm", "-f", container_id])
        .expect("failed to rm");
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_lifecycle_native_alpine() {
    smoke_lifecycle(TestBackend::NativeControlPlane, TestDistro::Alpine).await;
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_lifecycle_native_ubuntu() {
    smoke_lifecycle(TestBackend::NativeControlPlane, TestDistro::Ubuntu).await;
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_lifecycle_guest_docker_alpine() {
    smoke_lifecycle(TestBackend::GuestDocker, TestDistro::Alpine).await;
}

#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_lifecycle_guest_docker_ubuntu() {
    smoke_lifecycle(TestBackend::GuestDocker, TestDistro::Ubuntu).await;
}
