//! Per-request Docker proxy context middleware.

use crate::api::AppState;
use crate::handlers::resolve_role_from_uri;
use crate::routing::UtilityVmRole;
use axum::extract::{OriginalUri, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Proxy dispatch metadata derived once for a Docker API request.
#[derive(Debug, Clone, Copy)]
pub struct ProxyRequestContext {
    /// Utility VM role that should receive this request if it is proxied.
    pub role: UtilityVmRole,
}

/// Resolves proxy dispatch context once and stores it in request extensions.
///
/// This keeps same-class routing decisions out of individual handlers. Explicit
/// handlers still own endpoint-specific behavior, while ordinary pass-through
/// requests and lifecycle handlers share the same URI-to-role decision.
pub async fn proxy_request_context_middleware(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    mut request: Request,
    next: Next,
) -> Response {
    match resolve_role_from_uri(&state, &uri).await {
        Ok(role) => {
            request
                .extensions_mut()
                .insert(ProxyRequestContext { role });
            next.run(request).await
        }
        Err(err) => err.into_response(),
    }
}
