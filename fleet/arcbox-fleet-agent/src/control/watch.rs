//! `FleetStateService` — streams [`AgentState`](crate::state::AgentState) to
//! subscribers. Same shape as `arcbox-api`'s `watch_setup_status`
//! (`app/arcbox-api/src/system.rs`).

use std::pin::Pin;

use arcbox_fleet_control_proto::v1::fleet_state_service_server::FleetStateService;
use arcbox_fleet_control_proto::v1::{WatchRequest, WatchResponse};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::state::AgentState;

pub struct WatchService {
    state: AgentState,
}

impl WatchService {
    pub fn new(state: AgentState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl FleetStateService for WatchService {
    type WatchStream = Pin<Box<dyn Stream<Item = Result<WatchResponse, Status>> + Send>>;

    async fn watch(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let mut rx = self.state.subscribe();
        let stream = async_stream::stream! {
            // Send the current snapshot immediately, then one per change —
            // the client holds no state of its own between messages.
            let snapshot = rx.borrow_and_update().clone();
            yield Ok(WatchResponse { snapshot: Some(snapshot) });
            while rx.changed().await.is_ok() {
                let snapshot = rx.borrow_and_update().clone();
                yield Ok(WatchResponse { snapshot: Some(snapshot) });
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}
