use super::ContainerBackend;
use crate::config::ContainerRuntimeConfig;
use crate::error::{CoreError, Result};
use crate::machine::MachineManager;
use crate::vm_lifecycle::VmLifecycleManager;
use arcbox_connect::v1::readiness_event::Kind;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// Guest Docker backend (dockerd/containerd/runc inside VM).
pub struct GuestDockerBackend {
    vm_lifecycle: Arc<VmLifecycleManager>,
    machine_manager: Arc<MachineManager>,
    machine_name: &'static str,
    config: ContainerRuntimeConfig,
}

impl GuestDockerBackend {
    #[must_use]
    pub const fn new(
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
        let port = self.config.guest_docker_vsock_port;
        let timeout = Duration::from_millis(self.config.startup_timeout_ms);
        let agent = self.machine_manager.connect_agent(self.machine_name)?;

        // Correlate with the triggering Docker API request via its trace id.
        match agent
            .watch_readiness(true, timeout, &crate::trace::current_trace_id())
            .await
        {
            Ok(event) if event.kind == Kind::RuntimeReady => {
                validate_reported_vsock_endpoint(&event.endpoint, port)?;
                tracing::debug!(port, "guest docker runtime is ready");
                Ok(())
            }
            Ok(event) => Err(CoreError::Machine(format!(
                "guest docker endpoint on vsock port {} not ready within {}ms: {}",
                port, self.config.startup_timeout_ms, event.detail
            ))),
            Err(e) => Err(CoreError::Machine(format!(
                "guest readiness watch failed: {e}"
            ))),
        }
    }
}

fn parse_vsock_endpoint_port(endpoint: &str) -> Option<u32> {
    endpoint.strip_prefix("vsock:")?.parse::<u32>().ok()
}

fn validate_reported_vsock_endpoint(endpoint: &str, expected_port: u32) -> Result<()> {
    let endpoint_port = parse_vsock_endpoint_port(endpoint).ok_or_else(|| {
        CoreError::Machine(format!(
            "guest runtime endpoint format invalid: '{endpoint}'; expected 'vsock:<port>'"
        ))
    })?;

    if endpoint_port != expected_port {
        return Err(CoreError::Machine(format!(
            "guest runtime endpoint mismatch: guest reports vsock:{endpoint_port} but host is configured for vsock:{expected_port}"
        )));
    }

    Ok(())
}

#[async_trait]
impl ContainerBackend for GuestDockerBackend {
    fn name(&self) -> &'static str {
        "guest_docker"
    }

    async fn ensure_ready(&self) -> Result<u32> {
        let cid = self.vm_lifecycle.ensure_ready().await?;
        // Test mode: skip_vm_check registered a mock machine with no agent
        // behind it, so there is no guest readiness to watch. This lets the
        // Docker API handler tests run against a mock guest without a VM.
        if self.vm_lifecycle.config().skip_vm_check {
            return Ok(cid);
        }
        self.wait_guest_endpoint_ready().await?;
        Ok(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_vsock_endpoint_port, validate_reported_vsock_endpoint};

    #[test]
    fn test_parse_vsock_endpoint_port_ok() {
        assert_eq!(parse_vsock_endpoint_port("vsock:2375"), Some(2375));
    }

    #[test]
    fn test_parse_vsock_endpoint_port_invalid() {
        assert_eq!(
            parse_vsock_endpoint_port("unix:///var/run/docker.sock"),
            None
        );
        assert_eq!(parse_vsock_endpoint_port("vsock:not-a-number"), None);
        assert_eq!(parse_vsock_endpoint_port("2375"), None);
    }

    #[test]
    fn test_validate_reported_vsock_endpoint_ok() {
        assert!(validate_reported_vsock_endpoint("vsock:2375", 2375).is_ok());
    }

    #[test]
    fn test_validate_reported_vsock_endpoint_mismatch() {
        let err = validate_reported_vsock_endpoint("vsock:2375", 1234).unwrap_err();
        assert!(err.to_string().contains("endpoint mismatch"));
    }

    #[test]
    fn test_validate_reported_vsock_endpoint_invalid_format() {
        let err =
            validate_reported_vsock_endpoint("unix:///var/run/docker.sock", 2375).unwrap_err();
        assert!(err.to_string().contains("format invalid"));
    }
}
