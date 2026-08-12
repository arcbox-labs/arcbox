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

    fn agent(&self, machine: &str) -> arcbox_engine::Result<AgentClient> {
        (**self).agent(machine)
    }
}
