use super::ContainerBackend;
use crate::config::ContainerBackendMode;
use crate::error::Result;
use crate::vm_lifecycle::VmLifecycleManager;
use async_trait::async_trait;
use std::sync::Arc;

/// Existing host control-plane backend.
pub struct NativeControlPlaneBackend {
    vm_lifecycle: Arc<VmLifecycleManager>,
}

impl NativeControlPlaneBackend {
    #[must_use]
    pub fn new(vm_lifecycle: Arc<VmLifecycleManager>) -> Self {
        Self { vm_lifecycle }
    }
}

#[async_trait]
impl ContainerBackend for NativeControlPlaneBackend {
    fn mode(&self) -> ContainerBackendMode {
        ContainerBackendMode::NativeControlPlane
    }

    fn name(&self) -> &'static str {
        "native_control_plane"
    }

    async fn ensure_ready(&self) -> Result<u32> {
        self.vm_lifecycle.ensure_ready().await
    }
}
