//! Catch-all proxy handler for unmatched Docker API routes.

use super::headers::HeaderMapProxyExt;
use super::{forward, upgrade, upload};
use crate::api::AppState;
use crate::error::Result;
use crate::handlers::{ensure_system_vm_ready, hold_activity_for_response};
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
        return invalidate_on_guest_error(
            &state,
            upgrade::proxy_with_upgrade(state.proxy.connector(), req, &uri).await,
        );
    }

    if upload::is_streaming_upload_request(req.method(), &uri) {
        tracing::Span::current().record("protocol", "upload");
        return invalidate_on_guest_error(
            &state,
            upload::proxy_streaming_upload(state.proxy.connector(), &uri, req).await,
        )
        .map(|resp| hold_activity_for_response(&state, resp));
    }

    tracing::Span::current().record("protocol", "http");
    invalidate_on_guest_error(
        &state,
        forward::proxy_to_guest_stream_pooled(state.proxy.client(), &uri, req).await,
    )
    .map(|resp| hold_activity_for_response(&state, resp))
}

/// Drops the cached endpoint readiness when — and only when — the proxy error
/// was a guest-side transport failure. A client-side error (e.g. an aborted
/// upload body) says nothing about the guest, so re-verifying `_ping` on the
/// next request would be wasted work.
pub fn invalidate_on_guest_error<T>(state: &AppState, result: Result<T>) -> Result<T> {
    if let Err(e) = &result
        && e.is_guest_transport()
    {
        state.proxy.invalidate_endpoint();
    }
    result
}
