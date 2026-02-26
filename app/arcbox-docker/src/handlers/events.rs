use crate::api::AppState;
use crate::error::Result;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::Request;
use axum::response::Response;

/// Stream Docker events directly from guest dockerd.
pub async fn events(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    crate::handlers::proxy(&state, &uri, req).await
}
