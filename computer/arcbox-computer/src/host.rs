//! The seam between sandbox protocols and the composing runtime.

use std::ops::DerefMut;

use arcbox_engine::agent_client::AgentClient;

/// Host-side services the sandbox protocols need from whatever composes
/// them (in production, `arcbox_core::Runtime`).
///
/// The trait exists so protocol code stays daemon-free and
/// platform-neutral: host port bookkeeping, DNS registration, and the
/// host-state generation fence are owned by the composer; the protocols
/// only sequence them. Consumption is generic (`impl SandboxHost`), so
/// implementations keep their concrete guard types.
pub trait SandboxHost: Send + Sync {
    /// Guard over the sandbox host-state generation counter.
    ///
    /// Holding it serializes every host-state mutation (port exposure,
    /// cleanup, resume re-registration); bumping the value fences
    /// concurrent snapshots of derived state.
    type StateGuard<'a>: DerefMut<Target = u64> + Send
    where
        Self: 'a;

    /// Locks the sandbox host-state generation fence.
    fn lock_host_state(&self) -> impl Future<Output = Self::StateGuard<'_>> + Send;

    /// Drops every sandbox-owned host resource (listeners, DNS): the
    /// agent-startup handshake, when the guest has no sandboxes left.
    fn clear_host_state(&self) -> impl Future<Output = ()> + Send;

    /// Removes the host port listeners owned by one sandbox.
    fn remove_ports(&self, sandbox_id: &str) -> impl Future<Output = ()> + Send;

    /// Deregisters one sandbox's DNS records.
    fn deregister_dns(&self, sandbox_id: &str) -> impl Future<Output = ()> + Send;

    /// Registers a sandbox's DNS records at `ip`.
    fn register_dns(
        &self,
        sandbox_id: &str,
        ip: std::net::IpAddr,
    ) -> impl Future<Output = ()> + Send;

    /// Reads the host-state generation without locking it.
    fn host_state_generation(&self) -> impl Future<Output = u64> + Send;

    /// Binds the host listener half of one port exposure.
    ///
    /// # Errors
    ///
    /// Returns an error when the host listener cannot be bound.
    fn expose_port(
        &self,
        machine: &str,
        exposure: &crate::ports::SandboxPortExposure,
    ) -> impl Future<Output = arcbox_engine::Result<()>> + Send;

    /// Closes the host listener half of one exposure (idempotent).
    fn unexpose_port(
        &self,
        sandbox_id: &str,
        sandbox_port: u16,
        protocol_key: &str,
    ) -> impl Future<Output = ()> + Send;

    /// Snapshots one sandbox's mappings, or `None` if the host-state
    /// generation moved past `expected_generation`.
    fn port_mappings_if_unchanged(
        &self,
        sandbox_id: &str,
        expected_generation: u64,
    ) -> impl Future<Output = Option<Vec<crate::ports::SandboxPortMapping>>> + Send;

    /// Connects to a machine's guest agent, in the engine vocabulary.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine is not running or the agent is
    /// unreachable.
    fn agent(&self, machine: &str) -> arcbox_engine::Result<AgentClient>;
}

// Handlers hold the runtime behind an Arc; delegate so generic protocol
// functions accept it without a deref at every call site.
impl<H: SandboxHost> SandboxHost for std::sync::Arc<H> {
    type StateGuard<'a>
        = H::StateGuard<'a>
    where
        Self: 'a;

    async fn lock_host_state(&self) -> Self::StateGuard<'_> {
        (**self).lock_host_state().await
    }

    async fn clear_host_state(&self) {
        (**self).clear_host_state().await;
    }

    async fn remove_ports(&self, sandbox_id: &str) {
        (**self).remove_ports(sandbox_id).await;
    }

    async fn deregister_dns(&self, sandbox_id: &str) {
        (**self).deregister_dns(sandbox_id).await;
    }

    async fn register_dns(&self, sandbox_id: &str, ip: std::net::IpAddr) {
        (**self).register_dns(sandbox_id, ip).await;
    }

    async fn host_state_generation(&self) -> u64 {
        (**self).host_state_generation().await
    }

    async fn expose_port(
        &self,
        machine: &str,
        exposure: &crate::ports::SandboxPortExposure,
    ) -> arcbox_engine::Result<()> {
        (**self).expose_port(machine, exposure).await
    }

    async fn unexpose_port(&self, sandbox_id: &str, sandbox_port: u16, protocol_key: &str) {
        (**self)
            .unexpose_port(sandbox_id, sandbox_port, protocol_key)
            .await;
    }

    async fn port_mappings_if_unchanged(
        &self,
        sandbox_id: &str,
        expected_generation: u64,
    ) -> Option<Vec<crate::ports::SandboxPortMapping>> {
        (**self)
            .port_mappings_if_unchanged(sandbox_id, expected_generation)
            .await
    }

    fn agent(&self, machine: &str) -> arcbox_engine::Result<AgentClient> {
        (**self).agent(machine)
    }
}
