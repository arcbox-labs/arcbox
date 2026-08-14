//! Sandbox port-exposure protocols, host half.
//!
//! An exposure has two halves installed in order: the guest agent
//! allocates a reserved relay port and installs the DNAT, then the host
//! binds a loopback listener. The protocols here keep the two halves
//! consistent against concurrent cleanup (the host-state generation
//! fence) and roll back the guest half when the host half cannot be
//! applied.

use arcbox_connect::sandbox_v1::InspectSandboxRequest;
use arcbox_connect::v1::{SandboxPortForwardRemoveRequest, SandboxPortForwardRequest};
use arcbox_engine::EngineError;

use crate::host::SandboxHost;

/// Parameters of one sandbox port exposure (the host listener half).
///
/// The guest half — DNAT from `guest_port` to the sandbox — is installed by
/// the guest agent before this is applied.
pub struct SandboxPortExposure {
    /// Sandbox that owns the mapping.
    pub sandbox_id: String,
    /// Port the workload listens on inside the sandbox.
    pub sandbox_port: u16,
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    /// Host port to bind (loopback-reachable).
    pub host_port: u16,
    /// Reserved-range guest relay port the agent allocated.
    pub guest_port: u16,
}

/// One sandbox mapping currently backed by a host listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxPortMapping {
    /// Port the workload listens on inside the sandbox.
    pub sandbox_port: u16,
    /// Loopback host port where the service is reachable.
    pub host_port: u16,
    /// Transport protocol.
    pub protocol: SandboxPortProtocol,
}

/// Transport protocol of an exposed sandbox port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SandboxPortProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl SandboxPortProtocol {
    /// The listener-registry key form (`"tcp"` / `"udp"`).
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// The host↔guest wire enum form.
    ///
    /// The vsock payloads carry their own protocol enum so the published
    /// contract is never imported by the internal wire (CORE-57).
    #[must_use]
    const fn wire(self) -> arcbox_connect::v1::SandboxPortProtocol {
        match self {
            Self::Tcp => arcbox_connect::v1::SandboxPortProtocol::Tcp,
            Self::Udp => arcbox_connect::v1::SandboxPortProtocol::Udp,
        }
    }
}

/// The two ports an exposure resolved to.
pub struct ExposedPortPair {
    /// Loopback host port where the service is reachable.
    pub host_port: u16,
    /// Reserved-range guest relay port the agent allocated.
    pub guest_port: u16,
}

/// Why an exposure did not happen.
#[derive(Debug)]
pub enum ExposePortError {
    /// Host cleanup raced the exposure; the guest DNAT was rolled back.
    /// Retryable: the caller should retry to confirm the result.
    Raced,
    /// The guest or host half failed with the engine's own error.
    Engine(EngineError),
}

impl From<EngineError> for ExposePortError {
    fn from(err: EngineError) -> Self {
        Self::Engine(err)
    }
}

/// Expose `sandbox_port` of `sandbox_id` on the host.
///
/// Guest half first (reserved relay port + DNAT), then the host listener,
/// fenced by the host-state generation: if a cleanup slips between the
/// two halves, or the host bind fails, the guest DNAT is rolled back so
/// no half rule survives. A `requested_host_port` of 0 defaults to the
/// relay port for a stable, collision-free mapping.
///
/// # Errors
///
/// [`ExposePortError::Raced`] when cleanup raced the exposure (guest half
/// rolled back); [`ExposePortError::Engine`] when either half failed.
pub async fn expose<H: SandboxHost>(
    host: &H,
    machine: &str,
    sandbox_id: &str,
    sandbox_port: u16,
    requested_host_port: u16,
    protocol: SandboxPortProtocol,
) -> Result<ExposedPortPair, ExposePortError> {
    let host_generation = host.host_state_generation().await;

    // Guest half: allocate the reserved relay port and install the DNAT.
    let mut agent = host.agent(machine)?;
    let forwarded = agent
        .sandbox_port_forward(SandboxPortForwardRequest {
            id: sandbox_id.to_owned(),
            sandbox_port: u32::from(sandbox_port),
            protocol: protocol.wire().into(),
            ..Default::default()
        })
        .await?;
    let guest_port = u16::try_from(forwarded.guest_port).map_err(|_| {
        ExposePortError::Engine(EngineError::Machine(
            "agent returned an invalid guest port".into(),
        ))
    })?;
    let rollback_request = || SandboxPortForwardRemoveRequest {
        id: sandbox_id.to_owned(),
        sandbox_port: u32::from(sandbox_port),
        protocol: protocol.wire().into(),
        ..Default::default()
    };
    let host_state = host.lock_host_state().await;
    if *host_state != host_generation {
        if let Err(rollback) = agent.sandbox_port_forward_remove(rollback_request()).await {
            tracing::warn!(
                sandbox_id,
                error = %rollback,
                "failed to roll back guest DNAT after host cleanup race"
            );
        }
        return Err(ExposePortError::Raced);
    }

    // Host half: bind the listener; default the host port to the relay
    // port for a stable, collision-free mapping.
    let host_port = if requested_host_port == 0 {
        guest_port
    } else {
        requested_host_port
    };
    let exposure = SandboxPortExposure {
        sandbox_id: sandbox_id.to_owned(),
        sandbox_port,
        protocol: protocol.key().to_owned(),
        host_port,
        guest_port,
    };
    if let Err(primary) = host.expose_port(machine, &exposure).await {
        // Roll back the guest DNAT so a failed bind leaves no half rule.
        if let Err(rollback) = agent.sandbox_port_forward_remove(rollback_request()).await {
            tracing::warn!(
                sandbox_id,
                error = %rollback,
                "failed to roll back guest DNAT after host bind failure"
            );
        }
        return Err(ExposePortError::Engine(primary));
    }

    Ok(ExposedPortPair {
        host_port,
        guest_port,
    })
}

/// Why a stable exposed-port snapshot could not be taken.
#[derive(Debug)]
pub enum ListExposedPortsError {
    /// The sandbox lookup itself failed with the agent's own error (the
    /// 404 boundary for a deleted sandbox).
    Sandbox(EngineError),
    /// The guest state was unreachable — retryable.
    Unavailable(EngineError),
    /// Concurrent cleanup kept invalidating the snapshot — retryable.
    Unstable,
}

/// Snapshot the host listeners backing `sandbox_id`, fenced against
/// concurrent cleanup.
///
/// A retry turns a concurrent TTL/idle deletion into the existing 404
/// boundary without holding host state across the guest RPC.
///
/// # Errors
///
/// See [`ListExposedPortsError`].
pub async fn list<H: SandboxHost>(
    host: &H,
    machine: &str,
    sandbox_id: &str,
) -> Result<Vec<SandboxPortMapping>, ListExposedPortsError> {
    let mut agent = host
        .agent(machine)
        .map_err(ListExposedPortsError::Unavailable)?;
    for _ in 0..2 {
        let host_generation = host.host_state_generation().await;
        agent
            .sandbox_inspect(InspectSandboxRequest {
                id: sandbox_id.to_owned(),
                ..Default::default()
            })
            .await
            .map_err(|error| match error {
                error @ EngineError::Agent { code: 404, .. } => {
                    ListExposedPortsError::Sandbox(error)
                }
                error => ListExposedPortsError::Unavailable(error),
            })?;

        if let Some(mappings) = host
            .port_mappings_if_unchanged(sandbox_id, host_generation)
            .await
        {
            return Ok(mappings);
        }
    }
    Err(ListExposedPortsError::Unstable)
}

/// Withdraw one exposure, host half first.
///
/// Close the host listener before freeing the guest relay port. If the
/// guest delete fails, the safe half is already closed and a retry can
/// finish it without a cross-sandbox forwarding window.
///
/// # Errors
///
/// Returns the agent's error when the guest half could not be removed.
pub async fn unexpose<H: SandboxHost>(
    host: &H,
    machine: &str,
    sandbox_id: &str,
    sandbox_port: u16,
    protocol: SandboxPortProtocol,
) -> arcbox_engine::Result<()> {
    host.unexpose_port(sandbox_id, sandbox_port, protocol.key())
        .await;

    let mut agent = host.agent(machine)?;
    agent
        .sandbox_port_forward_remove(SandboxPortForwardRemoveRequest {
            id: sandbox_id.to_owned(),
            sandbox_port: u32::from(sandbox_port),
            protocol: protocol.wire().into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}
