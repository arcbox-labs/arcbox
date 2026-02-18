use crate::config::{ContainerBackendMode, ContainerRuntimeConfig};
use crate::error::Result;
use crate::machine::MachineManager;
use crate::vm_lifecycle::VmLifecycleManager;
use async_trait::async_trait;
use std::sync::Arc;

pub mod guest_docker;
pub mod native;

/// Shared backend trait object.
pub type DynContainerBackend = Arc<dyn ContainerBackend>;

/// Container backend abstraction.
///
/// Runtime uses this trait to switch between native control-plane and
/// guest-docker mode without changing the upper API surface.
#[async_trait]
pub trait ContainerBackend: Send + Sync {
    /// Backend mode.
    fn mode(&self) -> ContainerBackendMode;

    /// Human-readable backend name.
    fn name(&self) -> &'static str;

    /// Ensures backend is ready before container operations.
    async fn ensure_ready(&self) -> Result<u32>;
}

/// Creates backend implementation from runtime config.
#[must_use]
pub fn create_backend(
    config: &ContainerRuntimeConfig,
    vm_lifecycle: Arc<VmLifecycleManager>,
    machine_manager: Arc<MachineManager>,
    machine_name: &'static str,
) -> DynContainerBackend {
    match config.backend {
        ContainerBackendMode::NativeControlPlane => {
            Arc::new(native::NativeControlPlaneBackend::new(vm_lifecycle))
        }
        ContainerBackendMode::GuestDocker => Arc::new(guest_docker::GuestDockerBackend::new(
            vm_lifecycle,
            machine_manager,
            machine_name,
            config.clone(),
        )),
    }
}
