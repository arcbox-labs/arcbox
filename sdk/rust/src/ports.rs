//! Network reachability and readiness of one sandbox — publish guest
//! ports on host loopback, and wait for the workload to listen.

use std::time::Duration;

use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{SandboxProcessServiceClient, SandboxServiceClient};
use connectrpc::client::SharedHttp2Connection;

use crate::client::ClientContext;
use crate::error::{Error, ErrorKind, Result};
use crate::types::seconds_to_wire;

type ProcessClient = SandboxProcessServiceClient<SharedHttp2Connection>;
type SandboxClient = SandboxServiceClient<SharedHttp2Connection>;

/// Daemon default wait budget when no timeout is given (`process.proto`).
const DEFAULT_WAIT_FOR_PORT: Duration = Duration::from_secs(30);

/// Daemon cap on the wait budget — longer requests are clamped
/// server-side (each wait pins a guest exec-channel slot).
const MAX_WAIT_FOR_PORT: Duration = Duration::from_secs(600);

/// Transport protocol of an exposed port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

impl Protocol {
    fn to_wire(self) -> pb::PortProtocol {
        match self {
            Self::Tcp => pb::PortProtocol::PORT_PROTOCOL_TCP,
            Self::Udp => pb::PortProtocol::PORT_PROTOCOL_UDP,
        }
    }

    fn from_wire(protocol: buffa::EnumValue<pb::PortProtocol>) -> Self {
        match protocol.as_known() {
            Some(pb::PortProtocol::PORT_PROTOCOL_UDP) => Self::Udp,
            // The wire reserves UNSPECIFIED for TCP.
            _ => Self::Tcp,
        }
    }
}

/// One host listener currently forwarding into a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExposedPort {
    /// Port the workload listens on inside the sandbox.
    pub sandbox_port: u16,
    /// Loopback host port where the service is reachable.
    pub host_port: u16,
    pub protocol: Protocol,
}

/// Options for [`Ports::expose`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ExposeOptions {
    /// Specific host port to bind. Unset = the daemon allocates one —
    /// the allocated port is in the returned mapping. Ports below 1024
    /// fail under the unprivileged daemon.
    pub host_port: Option<u16>,
    pub protocol: Protocol,
}

/// The `sandbox.ports()` namespace: network reachability and readiness
/// of one sandbox.
#[derive(Clone)]
pub struct Ports {
    ctx: ClientContext,
    sandbox_id: String,
}

impl Ports {
    pub(crate) fn attached(ctx: ClientContext, sandbox_id: String) -> Self {
        Self { ctx, sandbox_id }
    }

    fn process(&self) -> ProcessClient {
        SandboxProcessServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
    }

    fn sandbox(&self) -> SandboxClient {
        SandboxServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
    }

    /// Wait until something inside the sandbox listens on the given TCP
    /// port. The guest agent watches its own listen table — no
    /// client-side polling. Returns as soon as a listener is up.
    ///
    /// `timeout` defaults to the daemon's 30 s and is capped at its
    /// 600 s limit; the wire's granularity is whole seconds, rounded up.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Timeout`] when the budget elapses first; otherwise
    /// any RPC failure.
    pub async fn wait_for_port(&self, port: u16, timeout: Option<Duration>) -> Result<()> {
        let requested = seconds_to_wire(timeout.map(|budget| budget.min(MAX_WAIT_FOR_PORT)));
        let effective = if requested == 0 {
            DEFAULT_WAIT_FOR_PORT
        } else {
            Duration::from_secs(u64::from(requested))
        };
        self.process()
            .wait_for_port(pb::WaitForPortRequest {
                sandbox_id: self.sandbox_id.clone(),
                port: u32::from(port),
                timeout_seconds: requested,
                ..Default::default()
            })
            .await
            .map_err(|error| {
                let mapped = Error::from_connect(error, "ports.wait_for_port");
                // A deadline expiry here is THIS wait's budget, not a
                // transport knob — name it, mirroring the sibling SDKs.
                if mapped.kind() == ErrorKind::Timeout {
                    Error::new(
                        ErrorKind::Timeout,
                        format!("wait_for_port(timeout) elapsed before port {port} was listening"),
                        "ports.wait_for_port",
                    )
                    .with_suggestion(
                        "increase the wait_for_port timeout, or check that the \
                         workload actually binds this port",
                    )
                    .with_context("port", port.to_string())
                    .with_context("timeout_seconds", effective.as_secs().to_string())
                } else {
                    mapped
                }
            })?;
        Ok(())
    }

    /// Publish a sandbox port on host loopback and return the mapping.
    /// Idempotent for an existing identical mapping. The daemon owns
    /// the host listener; it disappears with the sandbox (and on
    /// [`unexpose`](Self::unexpose)).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::PortInUse`] when the requested host port is taken;
    /// otherwise any RPC failure.
    pub async fn expose(&self, port: u16, options: ExposeOptions) -> Result<ExposedPort> {
        let response = self
            .sandbox()
            .expose_port(pb::ExposePortRequest {
                id: self.sandbox_id.clone(),
                sandbox_port: u32::from(port),
                host_port: options.host_port.map_or(0, u32::from),
                protocol: options.protocol.to_wire().into(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "ports.expose"))?
            .into_owned();
        Ok(ExposedPort {
            sandbox_port: port,
            host_port: u16::try_from(response.host_port).unwrap_or(0),
            protocol: options.protocol,
        })
    }

    /// Remove a previously exposed mapping and close its host listener.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn unexpose(&self, port: u16, protocol: Protocol) -> Result<()> {
        self.sandbox()
            .unexpose_port(pb::UnexposePortRequest {
                id: self.sandbox_id.clone(),
                sandbox_port: u32::from(port),
                protocol: protocol.to_wire().into(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "ports.unexpose"))?;
        Ok(())
    }

    /// The sandbox's current exposed-port mappings, from the daemon's
    /// authoritative live listener table — never a session-local cache.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn list(&self) -> Result<Vec<ExposedPort>> {
        let response = self
            .sandbox()
            .list_exposed_ports(pb::ListExposedPortsRequest {
                id: self.sandbox_id.clone(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "ports.list"))?
            .into_owned();
        Ok(response
            .ports
            .into_iter()
            .map(|port| ExposedPort {
                sandbox_port: u16::try_from(port.sandbox_port).unwrap_or(0),
                host_port: u16::try_from(port.host_port).unwrap_or(0),
                protocol: Protocol::from_wire(port.protocol),
            })
            .collect())
    }
}
