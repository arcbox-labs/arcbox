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

    fn agent(&self, machine: &str) -> arcbox_engine::Result<AgentClient> {
        self.machine_manager().connect_agent(machine)
    }
}
