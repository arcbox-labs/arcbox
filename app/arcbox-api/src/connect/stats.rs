//! Stats service — live machine and container samples.
//!
//! Bridges [`arcbox_core::stats_hub::StatsHub`]'s broadcast channel to a
//! server stream. Dropping the response stream drops the broadcast
//! receiver, which is what lets the hub stop the guest-side sampling when
//! the last watcher disconnects.

use arcbox_connect::v1 as pb;
use arcbox_core::{DEFAULT_MACHINE_NAME, Runtime};
use arcbox_protocol::v1::MachineStats;
use connectrpc::{
    ConnectError, PreEncoded, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};

use crate::grpc::SharedRuntime;

use super::ConnectRuntimeExt as _;
use super::bridge::{wire_request, wire_response};

/// Fills each container's display name from the runtime's registry,
/// leaving the ID-only entries untouched when no name is known (the
/// consumer falls back to the short ID). Skips the registry read entirely
/// when the frame carries no containers.
async fn enrich_container_names(runtime: &Runtime, sample: &mut MachineStats) {
    if sample.containers.is_empty() {
        return;
    }
    let names = runtime.container_names().await;
    for container in &mut sample.containers {
        if let Some(name) = names.get(&container.id) {
            container.name = name.clone();
        }
    }
}

/// Stats service implementation.
pub struct StatsServiceImpl {
    runtime: SharedRuntime,
}

impl StatsServiceImpl {
    /// Creates a new stats service with a deferred runtime.
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
impl pb::StatsService for StatsServiceImpl {
    async fn watch(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::StatsWatchRequest>,
    ) -> ServiceResult<ServiceStream<PreEncoded<pb::MachineStats>>> {
        let req: arcbox_protocol::v1::StatsWatchRequest = wire_request(&request)?;
        let machine_id = if req.machine_id.is_empty() {
            DEFAULT_MACHINE_NAME.to_string()
        } else {
            req.machine_id
        };
        let runtime = std::sync::Arc::clone(self.runtime.ready()?);
        if machine_id != DEFAULT_MACHINE_NAME && !runtime.machine_manager().exists(&machine_id) {
            return Err(ConnectError::not_found(format!("machine '{machine_id}'")));
        }
        let mut rx = runtime.subscribe_machine_stats_for(&machine_id).await;
        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(mut sample) => {
                        enrich_container_names(&runtime, &mut sample).await;
                        yield Ok(wire_response::<pb::MachineStats, _>(&sample));
                    }
                    // This subscriber lagged; newer samples follow, which
                    // is exactly what a live monitor wants.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        };
        Response::ok(Box::pin(stream))
    }
}
