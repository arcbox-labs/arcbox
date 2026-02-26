use crate::config::ContainerRuntimeConfig;
use crate::error::Result;
use crate::machine::MachineManager;
use crate::vm_lifecycle::VmLifecycleManager;
use async_trait::async_trait;
use std::sync::Arc;

pub mod guest_docker;

/// Shared backend trait object.
pub type DynContainerBackend = Arc<dyn ContainerBackend>;

/// Container backend abstraction.
///
/// Ensures guest dockerd is ready before container operations.
#[async_trait]
pub trait ContainerBackend: Send + Sync {
    /// Human-readable backend name.
    fn name(&self) -> &'static str;

    /// Ensures backend is ready before container operations.
    async fn ensure_ready(&self) -> Result<u32>;
}

/// Creates guest docker backend from runtime config.
#[must_use]
pub fn create_backend(
    config: &ContainerRuntimeConfig,
    vm_lifecycle: Arc<VmLifecycleManager>,
    machine_manager: Arc<MachineManager>,
    machine_name: &'static str,
) -> DynContainerBackend {
    Arc::new(guest_docker::GuestDockerBackend::new(
        vm_lifecycle,
        machine_manager,
        machine_name,
        config.clone(),
    ))
}
