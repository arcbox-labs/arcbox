//! Shared helpers for Docker API integration tests.

#[path = "mock_guest.rs"]
pub mod mock_guest;

pub use arcbox_docker::api::create_router;
pub use axum::body::Body;
pub use axum::http::{Request, StatusCode};
pub use mock_guest::MockRoute;
pub use std::sync::Arc;
pub use tower::ServiceExt;

use arcbox_core::{Config, Runtime, VmLifecycleConfig};
use arcbox_docker::proxy::VsockConnector;
use tempfile::TempDir;

/// Creates a test runtime with a temporary data directory.
/// Uses skip_vm_check=true to avoid needing actual VM boot assets.
#[allow(dead_code)] // used by the still-ignored end-to-end suites
pub async fn create_test_runtime() -> (Arc<Runtime>, Arc<VsockConnector>, TempDir) {
    let tmp_dir = TempDir::new().expect("Failed to create temp dir");
    let config = Config {
        data_dir: tmp_dir.path().to_path_buf(),
        ..Default::default()
    };
    let vm_lifecycle_config = VmLifecycleConfig {
        skip_vm_check: true,
        ..Default::default()
    };
    let runtime = Arc::new(
        Runtime::with_vm_lifecycle_config(config, vm_lifecycle_config)
            .expect("Failed to create runtime"),
    );
    runtime.init().await.expect("Failed to init runtime");
    let connector = Arc::new(VsockConnector::new(Arc::clone(&runtime)));
    (runtime, connector, tmp_dir)
}

/// Builds the real router wired to a mock guest dockerd serving `routes`,
/// with a `skip_vm_check` runtime — the full handler + readiness + proxy path
/// runs offline, no VM or daemon required.
///
/// Returns the runtime too so tests can assert host-side effects (DNS,
/// aliases) of handler runs.
#[allow(dead_code)] // each integration-test binary uses a subset of helpers
pub async fn router_with_mock_guest(
    routes: Vec<MockRoute>,
) -> (axum::Router, Arc<Runtime>, mock_guest::MockGuest, TempDir) {
    let tmp = TempDir::new().expect("Failed to create temp dir");
    let guest = mock_guest::start_with_routes(tmp.path(), routes).await;
    let config = Config {
        data_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let vm_lifecycle_config = VmLifecycleConfig {
        skip_vm_check: true,
        ..Default::default()
    };
    let runtime = Arc::new(
        Runtime::with_vm_lifecycle_config(config, vm_lifecycle_config)
            .expect("Failed to create runtime"),
    );
    let connector = Arc::new(mock_guest::UnixSocketConnector::new(
        guest.socket_path.clone(),
    ));
    let router = create_router(Arc::clone(&runtime), connector);
    (router, runtime, guest, tmp)
}
