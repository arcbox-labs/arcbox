//! Shared helpers for Docker API integration tests.

pub use arcbox_docker::api::create_router;
pub use axum::body::Body;
pub use axum::http::{Request, StatusCode};
pub use std::sync::Arc;
pub use tower::ServiceExt;

use arcbox_core::{Config, Runtime, VmLifecycleConfig};
use arcbox_docker::proxy::VsockConnector;
use tempfile::TempDir;

/// Creates a test runtime with a temporary data directory.
/// Uses skip_vm_check=true to avoid needing actual VM boot assets.
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
