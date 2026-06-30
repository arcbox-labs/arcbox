//! Handler-level proxy dispatch helpers.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::proxy;
use axum::body::Body;
use axum::http::{Request, Uri};
use axum::response::Response;
use std::sync::Arc;

/// Ensures the system VM is up before any request reaches the connector, then
/// verifies guest dockerd with a real Docker `_ping`.
pub async fn ensure_system_vm_ready(state: &AppState) -> Result<()> {
    let runtime = Arc::clone(&state.runtime);
    let generation = runtime.system_vm_restart_generation();
    state
        .proxy
        .ensure_endpoint_verified(generation, async move {
            runtime
                .ensure_system_vm_ready()
                .await
                .map(|_| ())
                .map_err(|e| {
                    DockerError::Server(format!("failed to ensure system VM is ready: {e}"))
                })
        })
        .await
}

/// Forward a request to guest dockerd.
pub async fn proxy_to_system_vm(
    state: &AppState,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    ensure_system_vm_ready(state).await?;
    match proxy::proxy_to_guest_stream_pooled(state.proxy.client(), uri, req).await {
        Ok(response) => Ok(response),
        Err(e) => {
            state.proxy.invalidate_endpoint();
            Err(e)
        }
    }
}

/// Forward an upload request to guest dockerd.
pub async fn proxy_upload_to_system_vm(
    state: &AppState,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    ensure_system_vm_ready(state).await?;
    match proxy::proxy_streaming_upload(state.proxy.connector(), uri, req).await {
        Ok(response) => Ok(response),
        Err(e) => {
            state.proxy.invalidate_endpoint();
            Err(e)
        }
    }
}
