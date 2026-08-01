//! Migration service — host-side surface over the runtime's migration
//! manager.
//!
//! Moving here also drops a duplicated readiness helper: this module used to
//! carry its own copy of the `ready()` extension because the gRPC one was
//! `pub(super)`. It now shares [`super::ConnectRuntimeExt`].

use arcbox_connect::v1 as pb;
use arcbox_protocol::v1::RunMigrationEvent;
use connectrpc::{
    ConnectError, PreEncoded, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::UnboundedReceiverStream;

use super::SharedRuntime;
use crate::error::ApiError;

use super::ConnectRuntimeExt as _;
use super::bridge::{wire_request, wire_response};

/// Host-side migration service implementation.
pub struct MigrationServiceImpl {
    runtime: SharedRuntime,
}

impl MigrationServiceImpl {
    /// Creates a new migration service with a deferred runtime.
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
impl pb::MigrationService for MigrationServiceImpl {
    async fn prepare_migration(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::PrepareMigrationRequest>,
    ) -> ServiceResult<PreEncoded<pb::PrepareMigrationResponse>> {
        let response = self
            .runtime
            .ready()?
            .migration_manager()
            .prepare_migration(wire_request(&request)?)
            .await
            .map_err(ApiError::from)?;

        Response::ok(wire_response(&response))
    }

    async fn run_migration(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::RunMigrationRequest>,
    ) -> ServiceResult<ServiceStream<PreEncoded<pb::RunMigrationEvent>>> {
        let receiver = self
            .runtime
            .ready()?
            .migration_manager()
            .run_migration(wire_request(&request)?)
            .await
            .map_err(ApiError::from)?;

        fn stream_event(
            result: arcbox_core::Result<RunMigrationEvent>,
        ) -> Result<PreEncoded<pb::RunMigrationEvent>, ConnectError> {
            result
                .map(|event| wire_response(&event))
                .map_err(|e| ConnectError::internal(e.to_string()))
        }
        let stream = UnboundedReceiverStream::new(receiver).map(stream_event);

        Response::ok(Box::pin(stream))
    }
}
