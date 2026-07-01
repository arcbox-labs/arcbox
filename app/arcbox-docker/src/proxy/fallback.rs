//! Catch-all proxy handler for unmatched Docker API routes.

use super::headers::HeaderMapProxyExt;
use super::{forward, upgrade, upload};
use crate::api::AppState;
use crate::error::Result;
use crate::handlers::ensure_system_vm_ready;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::Response;

/// Catch-all handler that proxies unmatched requests to guest dockerd.
///
/// Ensures forward compatibility with newer Docker API versions — any
/// endpoint we don't explicitly handle gets forwarded transparently.
///
/// # Errors
///
/// Returns an error if VM readiness fails or guest proxying fails.
#[tracing::instrument(
    name = "docker.proxy.fallback",
    skip(state, req),
    fields(
        method = %req.method(),
        uri = %uri,
        utility_vm = "native",
        protocol = tracing::field::Empty,
    ),
    err
)]
pub async fn proxy_fallback(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: axum::http::Request<Body>,
) -> Result<Response<Body>> {
    ensure_system_vm_ready(&state).await?;

    if req.headers().wants_upgrade() {
        tracing::Span::current().record("protocol", "upgrade");
        return match upgrade::proxy_with_upgrade(state.proxy.connector(), req, &uri).await {
            Ok(response) => Ok(response),
            Err(e) => {
                state.proxy.invalidate_endpoint();
                Err(e)
            }
        };
    }

    if upload::is_streaming_upload_request(req.method(), &uri) {
        tracing::Span::current().record("protocol", "upload");
        return match upload::proxy_streaming_upload(state.proxy.connector(), &uri, req).await {
            Ok(response) => Ok(response),
            Err(e) => {
                state.proxy.invalidate_endpoint();
                Err(e)
            }
        };
    }

    tracing::Span::current().record("protocol", "http");
    match forward::proxy_to_guest_stream_pooled(state.proxy.client(), &uri, req).await {
        Ok(response) => Ok(response),
        Err(e) => {
            state.proxy.invalidate_endpoint();
            Err(e)
        }
    }
}
