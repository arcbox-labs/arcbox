//! Sandbox lifecycle service — control plane.

use std::pin::Pin;

use arcbox_grpc::SandboxService;
use arcbox_protocol::pbjson_types::Empty;
use arcbox_protocol::sandbox_v1::{
    CreateSandboxRequest, CreateSandboxResponse, ExposePortRequest, ExposePortResponse,
    InspectSandboxRequest, KeepAlive, ListSandboxesRequest, ListSandboxesResponse,
    RemoveSandboxRequest, SandboxEventsRequest, SandboxInfo, StopSandboxRequest,
    UnexposePortRequest, WatchEventsResponse, watch_events_response,
};
use arcbox_protocol::v1::{SandboxPortForwardRemoveRequest, SandboxPortForwardRequest};
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use arcbox_core::SandboxPortExposure;

use crate::ApiError;

use super::super::{RequestExt, SharedRuntime, SharedRuntimeExt};
use super::{protocol_key, wire_protocol, with_keepalive};

/// Sandbox lifecycle service implementation.
///
/// These calls address the sandbox as a resource rather than its running
/// processes, so in a cloud deployment they are the half served by a
/// multi-tenant front door. Each routes to the `arcbox-agent` in the target
/// guest VM over the port-1024 vsock binary-frame protocol.
pub struct SandboxServiceImpl {
    runtime: SharedRuntime,
}

impl SandboxServiceImpl {
    /// Creates a new sandbox service with a deferred runtime.
    #[must_use]
    pub fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl SandboxService for SandboxServiceImpl {
    async fn create(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_create(request.into_inner())
            .await
            .map_err(ApiError::from)?;

        // Register sandbox DNS so the host can resolve sandbox-id.arcbox.local.
        if let Ok(ip) = resp.ip_address.parse() {
            self.runtime
                .ready()?
                .register_dns(&resp.id, std::slice::from_ref(&resp.id), ip)
                .await;
        }

        Ok(Response::new(resp))
    }

    async fn stop(&self, request: Request<StopSandboxRequest>) -> Result<Response<Empty>, Status> {
        let machine = request.machine_id()?;
        let sandbox_id = request.get_ref().id.clone();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_stop(request.into_inner())
            .await
            .map_err(ApiError::from)?;

        let runtime = self.runtime.ready()?;
        runtime.deregister_dns_by_id(&sandbox_id).await;
        runtime.remove_sandbox_ports(&sandbox_id).await;

        Ok(Response::new(Empty {}))
    }

    async fn remove(
        &self,
        request: Request<RemoveSandboxRequest>,
    ) -> Result<Response<Empty>, Status> {
        let machine = request.machine_id()?;
        let sandbox_id = request.get_ref().id.clone();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_remove(request.into_inner())
            .await
            .map_err(ApiError::from)?;

        let runtime = self.runtime.ready()?;
        runtime.deregister_dns_by_id(&sandbox_id).await;
        runtime.remove_sandbox_ports(&sandbox_id).await;

        Ok(Response::new(Empty {}))
    }

    async fn inspect(
        &self,
        request: Request<InspectSandboxRequest>,
    ) -> Result<Response<SandboxInfo>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let info = agent
            .sandbox_inspect(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(info))
    }

    async fn list(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_list(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(resp))
    }

    async fn expose_port(
        &self,
        request: Request<ExposePortRequest>,
    ) -> Result<Response<ExposePortResponse>, Status> {
        let machine = request.machine_id()?;
        let req = request.into_inner();
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| Status::invalid_argument("sandbox_port must be 1-65535"))?;
        let host_port = u16::try_from(req.host_port)
            .map_err(|_| Status::invalid_argument("host_port must be 0-65535"))?;
        let protocol = protocol_key(req.protocol()).to_owned();
        let wire = wire_protocol(req.protocol());

        // Guest half: allocate the reserved relay port and install the DNAT.
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let forwarded = agent
            .sandbox_port_forward(SandboxPortForwardRequest {
                id: req.id.clone(),
                sandbox_port: u32::from(sandbox_port),
                protocol: wire.into(),
            })
            .await
            .map_err(ApiError::from)?;
        let guest_port = u16::try_from(forwarded.guest_port)
            .map_err(|_| Status::internal("agent returned an invalid guest port"))?;

        // Host half: bind the listener; default the host port to the relay
        // port for a stable, collision-free mapping.
        let host_port = if host_port == 0 {
            guest_port
        } else {
            host_port
        };
        let exposure = SandboxPortExposure {
            sandbox_id: req.id.clone(),
            sandbox_port,
            protocol: protocol.clone(),
            host_port,
            guest_port,
        };
        if let Err(e) = self
            .runtime
            .ready()?
            .expose_sandbox_port(&machine, &exposure)
            .await
        {
            // Roll back the guest DNAT so a failed bind leaves no half rule.
            let mut agent = self
                .runtime
                .ready()?
                .get_agent(&machine)
                .map_err(ApiError::from)?;
            let _ = agent
                .sandbox_port_forward_remove(SandboxPortForwardRemoveRequest {
                    id: req.id,
                    sandbox_port: u32::from(sandbox_port),
                    protocol: wire.into(),
                })
                .await;
            return Err(ApiError::from(e).into());
        }

        Ok(Response::new(ExposePortResponse {
            host_port: u32::from(host_port),
            guest_port: u32::from(guest_port),
        }))
    }

    async fn unexpose_port(
        &self,
        request: Request<UnexposePortRequest>,
    ) -> Result<Response<Empty>, Status> {
        let machine = request.machine_id()?;
        let req = request.into_inner();
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| Status::invalid_argument("sandbox_port must be 1-65535"))?;
        let protocol = protocol_key(req.protocol());
        let wire = wire_protocol(req.protocol());

        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_port_forward_remove(SandboxPortForwardRemoveRequest {
                id: req.id.clone(),
                sandbox_port: u32::from(sandbox_port),
                protocol: wire.into(),
            })
            .await
            .map_err(ApiError::from)?;

        self.runtime
            .ready()?
            .unexpose_sandbox_port(&req.id, sandbox_port, protocol)
            .await;

        Ok(Response::new(Empty {}))
    }

    type EventsStream =
        Pin<Box<dyn Stream<Item = Result<WatchEventsResponse, Status>> + Send + 'static>>;

    async fn events(
        &self,
        request: Request<SandboxEventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        let machine = request.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_events(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        let stream = ReceiverStream::new(rx).map(|r| {
            r.map(|event| WatchEventsResponse {
                payload: Some(watch_events_response::Payload::Event(event)),
            })
            .map_err(|e| Status::from(ApiError::from(e)))
        });
        let stream = with_keepalive(stream, || WatchEventsResponse {
            payload: Some(watch_events_response::Payload::KeepAlive(KeepAlive {})),
        });
        Ok(Response::new(Box::pin(stream)))
    }
}
