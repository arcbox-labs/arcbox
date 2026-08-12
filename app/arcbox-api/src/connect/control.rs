//! Sandbox lifecycle service — control plane.

use std::sync::Arc;

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

use super::exposed_port;
use super::sandbox_resume;
use super::{ConnectRuntimeExt as _, ContextExt as _, protocol_key, wire_protocol, with_keepalive};
use arcbox_computer::cleanup as sandbox_cleanup;
use arcbox_computer::locks::SandboxOperationLocks;

/// Sandbox lifecycle service implementation.
///
/// These calls address the sandbox as a resource rather than its running
/// processes, so in a cloud deployment they are the half served by a
/// multi-tenant front door. Each routes to the `arcbox-agent` in the target
/// guest VM over the port-1024 vsock binary-frame protocol.
pub struct SandboxServiceImpl {
    runtime: SharedRuntime,
    operations: Arc<SandboxOperationLocks>,
}

impl SandboxServiceImpl {
    /// Creates a new sandbox service with a deferred runtime.
    #[must_use]
    pub(super) fn new(runtime: SharedRuntime, operations: Arc<SandboxOperationLocks>) -> Self {
        Self {
            runtime,
            operations,
        }
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
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let sandbox_id = req.id.clone();
        let _operation = self.operations.lock(&machine, &sandbox_id).await;
        let runtime = self.runtime.ready()?;
        // CORE-13 fail-fast: refuse before dialing the guest instead of a
        // boot that wedges into FAILED with an opaque KVM error.
        let capability = runtime.sandbox_nested_virt();
        if !capability.supported {
            return Err(super::sandbox_errors::nested_virt_unsupported(&capability));
        }
        let mut agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        // The RPC error otherwise reaches only the caller; the daemon log
        // must record a failed lifecycle mutation on its own (CORE-82).
        let resp = agent
            .sandbox_create(req)
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, sandbox_id = %sandbox_id, %error, "sandbox create failed");
            })
            .map_err(ApiError::from)?;
        let _host_state = runtime.lock_sandbox_host_state().await;

        // Register sandbox DNS so the host can resolve sandbox-id.arcbox.local.
        // Replays retain the original result even after Stop, so always
        // confirm that the exact sandbox and IP are still live.
        if let Ok(ip) = resp.ip_address.parse()
            && sandbox_cleanup::live_sandbox_matches(runtime, &machine, &resp.id, ip).await
        {
            runtime.register_sandbox_dns(&resp.id, ip).await;
        }

        Response::ok(resp)
    }

    async fn stop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::StopSandboxRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let sandbox_id = req.id.clone();
        let _operation = self.operations.lock(&machine, &sandbox_id).await;
        let runtime = self.runtime.ready()?;
        let mut agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        let response = agent
            .sandbox_stop(req)
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, sandbox_id = %sandbox_id, %error, "sandbox stop failed");
            })
            .map_err(ApiError::from)?;
        if let Some(ticket) = response.ticket.as_option() {
            sandbox_cleanup::complete(runtime, &mut agent, ticket)
                .await
                .map_err(ApiError::from)?;
        }

        Response::ok(Empty::default())
    }

    async fn remove(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::RemoveSandboxRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let sandbox_id = req.id.clone();
        let _operation = self.operations.lock(&machine, &sandbox_id).await;
        let runtime = self.runtime.ready()?;
        let mut agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        let response = agent
            .sandbox_remove(req)
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, sandbox_id = %sandbox_id, %error, "sandbox remove failed");
            })
            .map_err(ApiError::from)?;
        if let Some(ticket) = response.ticket.as_option() {
            sandbox_cleanup::complete(runtime, &mut agent, ticket)
                .await
                .map_err(ApiError::from)?;
        }

        Response::ok(Empty::default())
    }

    /// Pause: checkpoint in the guest, release the VM, then complete the
    /// host half of the network release — the guest quarantines the TAP+IP
    /// exactly like Stop and hands back the same durable cleanup ticket
    /// (which also drops the sandbox's host DNS entry).
    async fn pause(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::PauseSandboxRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let sandbox_id = req.id.clone();
        let _operation = self.operations.lock(&machine, &sandbox_id).await;
        let runtime = self.runtime.ready()?;
        let mut agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        // Same reason as create/stop/remove: a failed lifecycle mutation must
        // reach the daemon log on its own, not only the caller (CORE-82).
        let response = agent
            .sandbox_pause(req)
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, sandbox_id = %sandbox_id, %error, "sandbox pause failed");
            })
            .map_err(ApiError::from)?;
        if let Some(ticket) = response.ticket.as_option() {
            sandbox_cleanup::complete(runtime, &mut agent, ticket)
                .await
                .map_err(ApiError::from)?;
        }

        Response::ok(Empty::default())
    }

    /// Explicit resume; data-plane RPCs resume transparently through the
    /// same routine (`sandbox_resume`), differing only in the event reason.
    async fn resume(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ResumeSandboxRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        sandbox_resume::resume(
            runtime,
            &self.operations,
            &machine,
            &req.id,
            sandbox_resume::REASON_RESUME,
        )
        .await?;
        Response::ok(Empty::default())
    }

    /// Replace lifecycle deadlines: `ttl_seconds` re-arms the hard cap
    /// from now (CORE-60), `idle_timeout_seconds`/`on_idle` replace the
    /// idle knobs (CORE-21). Absent fields are unchanged; works on paused
    /// sandboxes too (the TTL keeps applying to them).
    async fn set_lifecycle(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::SetLifecycleRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let _operation = self.operations.lock(&machine, &req.id).await;
        let runtime = self.runtime.ready()?;
        let mut agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        agent
            .sandbox_set_lifecycle(req)
            .await
            .map_err(ApiError::from)?;
        Response::ok(Empty::default())
    }

    /// Report what this daemon can do (CORE-13): version, sandbox protocol
    /// level, feature flags, and whether nested virtualization is available
    /// on the *current* backend and hardware — answered host-side without
    /// touching the guest, so the SDK handshake works before any sandbox
    /// exists.
    async fn get_capabilities(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetCapabilitiesRequest>,
    ) -> ServiceResult<pb::GetCapabilitiesResponse> {
        let runtime = self.runtime.ready()?;
        let nested = runtime.sandbox_nested_virt();
        Response::ok(pb::GetCapabilitiesResponse {
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: arcbox_constants::sandbox::SANDBOX_API_PROTOCOL,
            features: arcbox_constants::sandbox::SANDBOX_FEATURES
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
            nested_virt: pb::NestedVirtCapability {
                supported: nested.supported,
                reason: nested.reason,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
    }

    async fn inspect(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::InspectSandboxRequest>,
    ) -> ServiceResult<pb::SandboxInfo> {
        let machine = ctx.sandbox_machine_id()?;
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
        let machine = ctx.sandbox_machine_id()?;
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
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let _operation = self.operations.lock(&machine, &req.id).await;
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| ConnectError::invalid_argument("sandbox_port must be 1-65535"))?;
        let host_port = u16::try_from(req.host_port)
            .map_err(|_| ConnectError::invalid_argument("host_port must be 0-65535"))?;
        let requested = req.protocol.as_known().unwrap_or_default();
        let protocol = protocol_key(requested).to_owned();
        let wire = wire_protocol(requested);
        let runtime = self.runtime.ready()?;
        let host_generation = runtime.sandbox_host_state_generation().await;

        // Guest half: allocate the reserved relay port and install the DNAT.
        let mut agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
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
        let rollback_request = || SandboxPortForwardRemoveRequest {
            id: req.id.clone(),
            sandbox_port: u32::from(sandbox_port),
            protocol: wire.into(),
            ..Default::default()
        };
        let host_state = runtime.lock_sandbox_host_state().await;
        if *host_state != host_generation {
            let primary = ConnectError::unavailable(
                "sandbox host cleanup raced port exposure; retry to confirm the result",
            );
            if let Err(rollback) = agent.sandbox_port_forward_remove(rollback_request()).await {
                tracing::warn!(
                    sandbox_id = %req.id,
                    error = %rollback,
                    "failed to roll back guest DNAT after host cleanup race"
                );
            }
            return Err(primary);
        }

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
        if let Err(e) = runtime.expose_sandbox_port(&machine, &exposure).await {
            // Roll back the guest DNAT so a failed bind leaves no half rule.
            let primary = ConnectError::from(ApiError::from(e));
            if let Err(rollback) = agent.sandbox_port_forward_remove(rollback_request()).await {
                tracing::warn!(
                    sandbox_id = %req.id,
                    error = %rollback,
                    "failed to roll back guest DNAT after host bind failure"
                );
            }
            return Err(primary);
        }

        let resp = pb::ExposePortResponse {
            host_port: u32::from(host_port),
            guest_port: u32::from(guest_port),
            ..Default::default()
        };
        Response::ok(resp)
    }

    async fn list_exposed_ports(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListExposedPortsRequest>,
    ) -> ServiceResult<pb::ListExposedPortsResponse> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let _operation = self.operations.lock(&machine, &req.id).await;
        let runtime = self.runtime.ready()?;
        let mut agent = runtime.get_agent(&machine).map_err(|error| {
            ConnectError::unavailable(format!("sandbox state unavailable: {error}"))
        })?;
        // A retry turns a concurrent TTL/idle deletion into the existing 404
        // boundary without holding host state across the guest RPC.
        for _ in 0..2 {
            let host_generation = runtime.sandbox_host_state_generation().await;
            agent
                .sandbox_inspect(pb::InspectSandboxRequest {
                    id: req.id.clone(),
                    ..Default::default()
                })
                .await
                .map_err(|error| match error {
                    error @ arcbox_engine::EngineError::Agent { code: 404, .. } => {
                        ConnectError::from(ApiError::from(error))
                    }
                    error => {
                        ConnectError::unavailable(format!("sandbox state unavailable: {error}"))
                    }
                })?;

            if let Some(mappings) = runtime
                .sandbox_port_mappings_if_unchanged(&req.id, host_generation)
                .await
            {
                let ports = mappings.into_iter().map(exposed_port).collect();
                return Response::ok(pb::ListExposedPortsResponse {
                    ports,
                    ..Default::default()
                });
            }
        }
        Err(ConnectError::unavailable(
            "sandbox cleanup prevented a stable exposed-port snapshot; retry",
        ))
    }

    async fn unexpose_port(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::UnexposePortRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let _operation = self.operations.lock(&machine, &req.id).await;
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| ConnectError::invalid_argument("sandbox_port must be 1-65535"))?;
        let requested = req.protocol.as_known().unwrap_or_default();
        let protocol = protocol_key(requested);
        let wire = wire_protocol(requested);

        let runtime = self.runtime.ready()?;
        // Close the host listener before freeing the guest relay port. If the
        // guest delete fails, the safe half is already closed and a retry can
        // finish it without a cross-sandbox forwarding window.
        runtime
            .unexpose_sandbox_port(&req.id, sandbox_port, protocol)
            .await;

        let mut agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        agent
            .sandbox_port_forward_remove(SandboxPortForwardRemoveRequest {
                id: req.id.clone(),
                sandbox_port: u32::from(sandbox_port),
                protocol: wire.into(),
                ..Default::default()
            })
            .await
            .map_err(ApiError::from)?;

        Response::ok(Empty::default())
    }

    async fn events(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::SandboxEventsRequest>,
    ) -> ServiceResult<ServiceStream<WatchEventsResponse>> {
        let machine = ctx.sandbox_machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_events(request.to_owned_message())
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, %error, "sandbox events subscribe failed");
            })
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
