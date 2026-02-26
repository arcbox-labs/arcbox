use super::{proxy as proxy_request, proxy_upgrade};
use crate::api::AppState;
use crate::error::Result;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{Request, header};
use axum::response::Response;

crate::handlers::proxy_handler!(exec_create);
crate::handlers::proxy_handler!(exec_resize);
crate::handlers::proxy_handler!(exec_inspect);

/// Start exec instance (proxy + upgrade for interactive mode).
pub async fn exec_start(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    let wants_upgrade = req.headers().get(header::UPGRADE).is_some()
        || req
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));

    if wants_upgrade {
        proxy_upgrade(&state, &uri, req).await
    } else {
        proxy_request(&state, &uri, req).await
    }
}
