//! `Runtime`'s implementation of the computer layer's [`SandboxHost`]
//! seam: the sandbox protocols sequence host state through this trait,
//! and the daemon-side ownership of listeners, DNS, and the generation
//! fence stays here.

use arcbox_computer::SandboxHost;
use arcbox_engine::agent_client::AgentClient;

use super::Runtime;

impl SandboxHost for Runtime {
    type StateGuard<'a> = tokio::sync::MutexGuard<'a, u64>;

    async fn lock_host_state(&self) -> Self::StateGuard<'_> {
        self.lock_sandbox_host_state().await
    }

    async fn clear_host_state(&self) {
        self.clear_sandbox_host_state().await;
    }

    async fn remove_ports(&self, sandbox_id: &str) {
        self.remove_sandbox_ports(sandbox_id).await;
    }

    async fn deregister_dns(&self, sandbox_id: &str) {
        self.deregister_sandbox_dns(sandbox_id).await;
    }

    async fn register_dns(&self, sandbox_id: &str, ip: std::net::IpAddr) {
        self.register_sandbox_dns(sandbox_id, ip).await;
    }

    async fn host_state_generation(&self) -> u64 {
        self.sandbox_host_state_generation().await
    }

    async fn expose_port(
        &self,
        machine: &str,
        exposure: &arcbox_computer::ports::SandboxPortExposure,
    ) -> arcbox_engine::Result<()> {
        use crate::error::CoreError;
        self.expose_sandbox_port(machine, exposure)
            .await
            .map_err(|e| match e {
                // Common/Net cover the non-macOS fallback (PortForwarder's
                // direct TCP/UDP connect can fail with either). On P0
                // macOS, `start_port_forwarding_macos` only ever
                // constructs `CoreError::Machine` — Common/Net are
                // unreachable there, and `other` is the sole arm that
                // fires. Kept as a match on the full error type, not a
                // cfg'd one, so a future macOS error path lands here
                // losslessly without a second edit site.
                CoreError::Common(c) => arcbox_engine::EngineError::Common(c),
                CoreError::Net(n) => arcbox_engine::EngineError::Net(n),
                other => arcbox_engine::EngineError::Machine(other.to_string()),
            })
    }

    async fn unexpose_port(&self, sandbox_id: &str, sandbox_port: u16, protocol_key: &str) {
        self.unexpose_sandbox_port(sandbox_id, sandbox_port, protocol_key)
            .await;
    }

    async fn port_mappings_if_unchanged(
        &self,
        sandbox_id: &str,
        expected_generation: u64,
    ) -> Option<Vec<arcbox_computer::ports::SandboxPortMapping>> {
        self.sandbox_port_mappings_if_unchanged(sandbox_id, expected_generation)
            .await
    }

    fn agent(&self, machine: &str) -> arcbox_engine::Result<AgentClient> {
        self.machine_manager().connect_agent(machine)
    }
}
