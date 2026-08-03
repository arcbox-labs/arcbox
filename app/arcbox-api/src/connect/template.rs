//! Sandbox template catalog service — control plane (CORE-21).

use arcbox_connect::sandbox_v1 as pb;
use buffa_types::google::protobuf::Empty;
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};

/// Template service implementation.
///
/// Contract-only stub (CORE-58 phase 1): every method answers
/// UNIMPLEMENTED until the template catalog lands with CORE-21. Build
/// additionally depends on the rootfs pipeline (CORE-5) and, for
/// pre-warmed snapshots, FC 1.16 network overrides (CORE-16).
#[derive(Default)]
pub struct TemplateServiceImpl;

impl TemplateServiceImpl {
    /// Creates a new template service.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and these impls are registered on a \
              Router rather than named by callers"
)]
impl pb::TemplateService for TemplateServiceImpl {
    /// Contract-only stub: the build pipeline lands with CORE-21
    /// (gated on CORE-5 rootfs builds and CORE-16 for `prewarm`).
    async fn build(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::BuildTemplateRequest>,
    ) -> ServiceResult<pb::Template> {
        Err(ConnectError::unimplemented(
            "template build is not implemented yet (CORE-21; build pipeline CORE-5/CORE-16)",
        ))
    }

    /// Contract-only stub: the template catalog lands with CORE-21.
    async fn publish(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::PublishTemplateRequest>,
    ) -> ServiceResult<pb::Template> {
        Err(ConnectError::unimplemented(
            "template publish is not implemented yet (CORE-21)",
        ))
    }

    /// Contract-only stub: the template catalog lands with CORE-21.
    async fn get(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetTemplateRequest>,
    ) -> ServiceResult<pb::Template> {
        Err(ConnectError::unimplemented(
            "template get is not implemented yet (CORE-21)",
        ))
    }

    /// Contract-only stub: the template catalog lands with CORE-21.
    async fn list(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListTemplatesRequest>,
    ) -> ServiceResult<pb::ListTemplatesResponse> {
        Err(ConnectError::unimplemented(
            "template list is not implemented yet (CORE-21)",
        ))
    }

    /// Contract-only stub: the template catalog lands with CORE-21.
    async fn delete(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::DeleteTemplateRequest>,
    ) -> ServiceResult<Empty> {
        Err(ConnectError::unimplemented(
            "template delete is not implemented yet (CORE-21)",
        ))
    }
}
