//! Catch-all proxy handler for unmatched Docker API routes.

use super::headers::HeaderMapProxyExt;
use super::{forward, upgrade, upload};
use crate::api::AppState;
use crate::error::Result;
use crate::handlers::ensure_role_ready;
use crate::request_context::ProxyRequestContext;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::Response;

/// Catch-all handler that proxies unmatched requests to guest dockerd.
///
/// Ensures forward compatibility with newer Docker API versions — any
/// endpoint we don't explicitly handle gets forwarded transparently. When
/// the URI carries a known container or exec ID, the request is routed to
/// that workload's utility VM role so endpoints like
/// `/containers/{id}/archive` follow the same VM as their lifecycle calls.
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
        utility_vm = tracing::field::Empty,
        protocol = tracing::field::Empty,
    ),
    err
)]
pub async fn proxy_fallback(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: axum::http::Request<Body>,
) -> Result<Response<Body>> {
    let role = req
        .extensions()
        .get::<ProxyRequestContext>()
        .map_or_else(|| crate::routing::UtilityVmRole::Native, |ctx| ctx.role);
    tracing::Span::current().record("utility_vm", role.as_str());
    ensure_role_ready(&state, role).await?;

    if req.headers().wants_upgrade() {
        tracing::Span::current().record("protocol", "upgrade");
        return match upgrade::proxy_with_upgrade_for_role(state.proxy.connector(), role, req, &uri)
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                state.proxy.invalidate_endpoint(role);
                Err(e)
            }
        };
    }

    if upload::is_streaming_upload_request(req.method(), &uri) {
        tracing::Span::current().record("protocol", "upload");
        return match upload::proxy_streaming_upload_for_role(
            state.proxy.connector(),
            role,
            &uri,
            req,
        )
        .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                state.proxy.invalidate_endpoint(role);
                Err(e)
            }
        };
    }

    tracing::Span::current().record("protocol", "http");
    match forward::proxy_to_guest_stream_for_role_pooled(state.proxy.client(), role, &uri, req)
        .await
    {
        Ok(response) => Ok(response),
        Err(e) => {
            state.proxy.invalidate_endpoint(role);
            Err(e)
        }
    }
}
