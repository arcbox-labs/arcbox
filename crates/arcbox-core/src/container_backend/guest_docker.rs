use super::ContainerBackend;
use crate::config::{ContainerBackendMode, ContainerRuntimeConfig};
use crate::error::{CoreError, Result};
use crate::machine::MachineManager;
use crate::vm_lifecycle::VmLifecycleManager;
use async_trait::async_trait;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Guest Docker backend (dockerd/containerd/youki inside VM).
pub struct GuestDockerBackend {
    vm_lifecycle: Arc<VmLifecycleManager>,
    machine_manager: Arc<MachineManager>,
    machine_name: &'static str,
    config: ContainerRuntimeConfig,
}

impl GuestDockerBackend {
    #[must_use]
    pub fn new(
        vm_lifecycle: Arc<VmLifecycleManager>,
        machine_manager: Arc<MachineManager>,
        machine_name: &'static str,
        config: ContainerRuntimeConfig,
    ) -> Self {
        Self {
            vm_lifecycle,
            machine_manager,
            machine_name,
            config,
        }
    }

    async fn wait_guest_endpoint_ready(&self) -> Result<()> {
        const INITIAL_DELAY_MS: u64 = 120;
        const MAX_DELAY_MS: u64 = 1200;

        let port = self.config.guest_docker_vsock_port;
        let timeout = Duration::from_millis(self.config.startup_timeout_ms);
        let deadline = Instant::now() + timeout;
        let mut delay_ms = INITIAL_DELAY_MS;
        let mut start_requested = false;

        loop {
            match self
                .machine_manager
                .connect_vsock_port(self.machine_name, port)
            {
                Ok(fd) => {
                    let _owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
                    tracing::debug!(port, "guest docker endpoint is ready");
                    return Ok(());
                }
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(CoreError::Machine(format!(
                            "guest docker endpoint on vsock port {} not ready within {}ms: {}",
                            port, self.config.startup_timeout_ms, e
                        )));
                    }
                    tracing::trace!(
                        port,
                        retry_delay_ms = delay_ms,
                        "guest docker endpoint not ready yet: {}",
                        e
                    );
                }
            }

            if !start_requested {
                match self.machine_manager.connect_agent(self.machine_name) {
                    Ok(mut agent) => match agent.ensure_runtime(true).await {
                        Ok(resp) => {
                            start_requested = true;
                            tracing::debug!(
                                ready = resp.ready,
                                endpoint = resp.endpoint,
                                message = resp.message,
                                "requested guest runtime ensure"
                            );
                        }
                        Err(e) => {
                            tracing::trace!("failed to request guest runtime ensure: {}", e);
                        }
                    },
                    Err(e) => {
                        tracing::trace!("failed to connect agent for runtime ensure: {}", e);
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 3 / 2).min(MAX_DELAY_MS);
        }
    }
}

#[async_trait]
impl ContainerBackend for GuestDockerBackend {
    fn mode(&self) -> ContainerBackendMode {
        ContainerBackendMode::GuestDocker
    }

    fn name(&self) -> &'static str {
        "guest_docker"
    }

    async fn ensure_ready(&self) -> Result<u32> {
        let cid = self.vm_lifecycle.ensure_ready().await?;
        self.wait_guest_endpoint_ready().await?;
        Ok(cid)
    }
}
