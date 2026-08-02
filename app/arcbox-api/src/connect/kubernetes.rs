//! Kubernetes service — cluster lifecycle inside the System VM.
//!
//! Every method delegates straight to the runtime, which already produces
//! the response message, so the handlers only pass it through.

use arcbox_connect::v1 as pb;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};

use super::SharedRuntime;

use super::ConnectRuntimeExt as _;

/// Kubernetes service implementation.
pub struct KubernetesServiceImpl {
    runtime: SharedRuntime,
}

impl KubernetesServiceImpl {
    /// Creates a new Kubernetes service with a deferred runtime.
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
impl pb::KubernetesService for KubernetesServiceImpl {
    async fn start(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::KubernetesStartRequest>,
    ) -> ServiceResult<pb::KubernetesStartResponse> {
        let runtime = self.runtime.ready()?;
        let response = runtime
            .start_kubernetes()
            .await
            .map_err(|e| ConnectError::internal(e.to_string()))?;
        Response::ok(response)
    }

    async fn stop(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::KubernetesStopRequest>,
    ) -> ServiceResult<pb::KubernetesStopResponse> {
        let runtime = self.runtime.ready()?;
        let response = runtime
            .stop_kubernetes()
            .await
            .map_err(|e| ConnectError::internal(e.to_string()))?;
        Response::ok(response)
    }

    async fn delete(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::KubernetesDeleteRequest>,
    ) -> ServiceResult<pb::KubernetesDeleteResponse> {
        let runtime = self.runtime.ready()?;
        let response = runtime
            .delete_kubernetes()
            .await
            .map_err(|e| ConnectError::internal(e.to_string()))?;
        Response::ok(response)
    }

    async fn status(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::KubernetesStatusRequest>,
    ) -> ServiceResult<pb::KubernetesStatusResponse> {
        let runtime = self.runtime.ready()?;
        let response = runtime
            .kubernetes_status()
            .await
            .map_err(|e| ConnectError::internal(e.to_string()))?;
        Response::ok(response)
    }

    async fn get_kubeconfig(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::KubernetesKubeconfigRequest>,
    ) -> ServiceResult<pb::KubernetesKubeconfigResponse> {
        let runtime = self.runtime.ready()?;
        let response = runtime
            .kubernetes_kubeconfig()
            .await
            .map_err(|e| ConnectError::internal(e.to_string()))?;
        Response::ok(response)
    }
}
