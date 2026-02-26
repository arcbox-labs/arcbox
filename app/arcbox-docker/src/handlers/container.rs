use super::proxy_upgrade;
use crate::api::AppState;
use crate::error::Result;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::Request;
use axum::response::Response;

crate::handlers::proxy_handler!(list_containers);
crate::handlers::proxy_handler!(inspect_container);
crate::handlers::proxy_handler!(container_logs);
crate::handlers::proxy_handler!(wait_container);
crate::handlers::proxy_handler!(pause_container);
crate::handlers::proxy_handler!(unpause_container);
crate::handlers::proxy_handler!(rename_container);
crate::handlers::proxy_handler!(container_top);
crate::handlers::proxy_handler!(container_stats);
crate::handlers::proxy_handler!(container_changes);
crate::handlers::proxy_handler!(prune_containers);
crate::handlers::proxy_handler!(create_container);
crate::handlers::proxy_handler!(start_container);
crate::handlers::proxy_handler!(stop_container);
crate::handlers::proxy_handler!(kill_container);
crate::handlers::proxy_handler!(restart_container);
crate::handlers::proxy_handler!(remove_container);

/// Attach to a container.
pub async fn attach_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy_upgrade(&state, &uri, req).await
}
