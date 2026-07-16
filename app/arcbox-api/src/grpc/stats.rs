//! Stats service gRPC implementation.
//!
//! Bridges [`arcbox_core::stats_hub::StatsHub`]'s broadcast channel to a
//! tonic server stream. Dropping the response stream drops the broadcast
//! receiver, which is what lets the hub stop the guest-side sampling when
//! the last watcher disconnects.

use std::pin::Pin;

use arcbox_core::DEFAULT_MACHINE_NAME;
use arcbox_grpc::v1::stats_service_server;
use arcbox_protocol::v1::{MachineStats, StatsWatchRequest};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use super::{SharedRuntime, SharedRuntimeExt};

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

#[tonic::async_trait]
impl stats_service_server::StatsService for StatsServiceImpl {
    type WatchStream = Pin<Box<dyn Stream<Item = Result<MachineStats, Status>> + Send + 'static>>;

    async fn watch(
        &self,
        request: Request<StatsWatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = request.into_inner();
        if !req.machine_id.is_empty() && req.machine_id != DEFAULT_MACHINE_NAME {
            return Err(Status::unimplemented(
                "per-machine stats are not implemented yet; omit machine_id for the System VM",
            ));
        }
        let runtime = self.runtime.ready()?;
        let mut rx = runtime.subscribe_machine_stats();
        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(sample) => yield Ok(sample),
                    // This subscriber lagged; newer samples follow, which
                    // is exactly what a live monitor wants.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}
