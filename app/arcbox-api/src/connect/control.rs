//! Sandbox lifecycle service — control plane.

use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{KeepAlive, WatchEventsResponse, watch_events_response};
use arcbox_connect::v1::{SandboxPortForwardRemoveRequest, SandboxPortForwardRequest};
use buffa_types::google::protobuf::Empty;
use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;

use arcbox_core::SandboxPortExposure;

use super::SharedRuntime;
use crate::ApiError;

use super::{ConnectRuntimeExt as _, ContextExt as _, protocol_key, wire_protocol, with_keepalive};

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

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and these impls are registered on a \
              Router rather than named by callers"
)]
impl pb::SandboxService for SandboxServiceImpl {
    async fn create(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::CreateSandboxRequest>,
    ) -> ServiceResult<pb::CreateSandboxResponse> {
        let machine = ctx.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_create(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;

        // Register sandbox DNS so the host can resolve sandbox-id.arcbox.local.
        if let Ok(ip) = resp.ip_address.parse() {
            self.runtime
                .ready()?
                .register_dns(&resp.id, std::slice::from_ref(&resp.id), ip)
                .await;
        }

        Response::ok(resp)
    }

    async fn stop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::StopSandboxRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.machine_id()?;
        let req = request.to_owned_message();
        let sandbox_id = req.id.clone();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent.sandbox_stop(req).await.map_err(ApiError::from)?;

        let runtime = self.runtime.ready()?;
        runtime.deregister_dns_by_id(&sandbox_id).await;
        runtime.remove_sandbox_ports(&sandbox_id).await;

        Response::ok(Empty::default())
    }

    async fn remove(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::RemoveSandboxRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.machine_id()?;
        let req = request.to_owned_message();
        let sandbox_id = req.id.clone();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent.sandbox_remove(req).await.map_err(ApiError::from)?;

        let runtime = self.runtime.ready()?;
        runtime.deregister_dns_by_id(&sandbox_id).await;
        runtime.remove_sandbox_ports(&sandbox_id).await;

        Response::ok(Empty::default())
    }

    async fn inspect(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::InspectSandboxRequest>,
    ) -> ServiceResult<pb::SandboxInfo> {
        let machine = ctx.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let info = agent
            .sandbox_inspect(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(info)
    }

    async fn list(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListSandboxesRequest>,
    ) -> ServiceResult<pb::ListSandboxesResponse> {
        let machine = ctx.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_list(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(resp)
    }

    async fn expose_port(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ExposePortRequest>,
    ) -> ServiceResult<pb::ExposePortResponse> {
        let machine = ctx.machine_id()?;
        let req = request.to_owned_message();
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| ConnectError::invalid_argument("sandbox_port must be 1-65535"))?;
        let host_port = u16::try_from(req.host_port)
            .map_err(|_| ConnectError::invalid_argument("host_port must be 0-65535"))?;
        let requested = req.protocol.as_known().unwrap_or_default();
        let protocol = protocol_key(requested).to_owned();
        let wire = wire_protocol(requested);

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
                ..Default::default()
            })
            .await
            .map_err(ApiError::from)?;
        let guest_port = u16::try_from(forwarded.guest_port)
            .map_err(|_| ConnectError::internal("agent returned an invalid guest port"))?;

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
                    ..Default::default()
                })
                .await;
            return Err(ApiError::from(e).into());
        }

        let resp = pb::ExposePortResponse {
            host_port: u32::from(host_port),
            guest_port: u32::from(guest_port),
            ..Default::default()
        };
        Response::ok(resp)
    }

    async fn unexpose_port(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::UnexposePortRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.machine_id()?;
        let req = request.to_owned_message();
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| ConnectError::invalid_argument("sandbox_port must be 1-65535"))?;
        let requested = req.protocol.as_known().unwrap_or_default();
        let protocol = protocol_key(requested);
        let wire = wire_protocol(requested);

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
                ..Default::default()
            })
            .await
            .map_err(ApiError::from)?;

        self.runtime
            .ready()?
            .unexpose_sandbox_port(&req.id, sandbox_port, protocol)
            .await;

        Response::ok(Empty::default())
    }

    async fn events(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::SandboxEventsRequest>,
    ) -> ServiceResult<ServiceStream<WatchEventsResponse>> {
        let machine = ctx.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_events(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        let stream = ReceiverStream::new(rx).map(|r| {
            r.map(|event| WatchEventsResponse {
                payload: Some(watch_events_response::Payload::from(event)),
                ..Default::default()
            })
            .map_err(|e| ConnectError::from(ApiError::from(e)))
        });
        let stream = with_keepalive(stream, || WatchEventsResponse {
            payload: Some(watch_events_response::Payload::from(KeepAlive::default())),
            ..Default::default()
        });
        Response::ok(Box::pin(stream))
    }
}
