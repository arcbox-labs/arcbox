//! Sandbox template catalog service — control plane (CORE-107).
//!
//! Pure forwarders to the guest agent, mirroring `snapshot.rs`: the catalog
//! and every artifact it references live inside the System VM. `Build` alone
//! stays UNIMPLEMENTED until the build pipeline lands.

use arcbox_connect::sandbox_v1 as pb;
use buffa_types::google::protobuf::Empty;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};

use super::SharedRuntime;
use super::{ConnectRuntimeExt as _, ContextExt as _};
use crate::ApiError;

/// Template service implementation.
pub struct TemplateServiceImpl {
    runtime: SharedRuntime,
}

impl TemplateServiceImpl {
    /// Creates a new template service with a deferred runtime.
    #[must_use]
    pub(super) fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and these impls are registered on a \
              Router rather than named by callers"
)]
impl pb::TemplateService for TemplateServiceImpl {
    /// UNIMPLEMENTED until the build pipeline lands (CORE-107 PR3+); the
    /// rest of the catalog surface already answers.
    async fn build(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::BuildTemplateRequest>,
    ) -> ServiceResult<pb::Template> {
        Err(ConnectError::unimplemented(
            "template Build is not implemented yet (CORE-107 build pipeline); \
             Get/List/Publish/Delete already answer",
        ))
    }

    async fn publish(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::PublishTemplateRequest>,
    ) -> ServiceResult<pb::Template> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let name = req.name.clone();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        // The RPC error otherwise reaches only the caller; the daemon log
        // must record a failed catalog mutation on its own (CORE-82).
        let resp = agent
            .sandbox_template_publish(req)
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, template = %name, %error, "template publish failed");
            })
            .map_err(ApiError::from)?;
        Response::ok(resp)
    }

    async fn get(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::GetTemplateRequest>,
    ) -> ServiceResult<pb::Template> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_template_get(req)
            .await
            .map_err(ApiError::from)?;
        Response::ok(resp)
    }

    async fn list(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListTemplatesRequest>,
    ) -> ServiceResult<pb::ListTemplatesResponse> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_template_list(req)
            .await
            .map_err(ApiError::from)?;
        Response::ok(resp)
    }

    async fn delete(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::DeleteTemplateRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let reference = req.reference.clone();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_template_delete(req)
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, template = %reference, %error, "template delete failed");
            })
            .map_err(ApiError::from)?;
        Response::ok(Empty::default())
    }
}
