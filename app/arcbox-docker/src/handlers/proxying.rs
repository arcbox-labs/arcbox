//! Handler-level proxy dispatch helpers.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::proxy;
use crate::routing::UtilityVmRole;
use axum::body::Body;
use axum::http::{Request, Uri};
use axum::response::Response;
use std::sync::Arc;

/// Ensures the utility VM hosting `role` is up before any request reaches
/// the connector, then verifies guest dockerd with a real Docker `_ping`.
/// Surfaces the role in the error message so a Rosetta-VM failure can't be
/// confused with a native-VM failure.
///
/// Refuses requests for a role that is not configured on this host
/// (e.g. `Rosetta` on non-Apple-Silicon) with a clear platform-specific
/// error rather than silently routing to native — silently degrading
/// would land an `amd64` container on the HV native VM that cannot
/// translate x86.
pub async fn ensure_role_ready(state: &AppState, role: UtilityVmRole) -> Result<()> {
    if !state.runtime.role_is_distinct(role) && role != UtilityVmRole::Native {
        return Err(DockerError::Server(format!(
            "{} utility VM is not available on this host; \
             {} workloads require macOS Apple Silicon",
            role.as_str(),
            role.as_str(),
        )));
    }

    let runtime = Arc::clone(&state.runtime);
    state
        .proxy
        .ensure_endpoint_verified(role, async move {
            runtime
                .ensure_role_ready(role)
                .await
                .map(|_| ())
                .map_err(|e| {
                    DockerError::Server(format!(
                        "failed to ensure {} utility VM is ready: {e}",
                        role.as_str(),
                    ))
                })
        })
        .await
}

/// Forward a request to a selected utility VM's guest dockerd.
pub async fn proxy_to_role(
    state: &AppState,
    role: UtilityVmRole,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    ensure_role_ready(state, role).await?;
    match proxy::proxy_to_guest_stream_for_role_pooled(state.proxy.client(), role, uri, req).await {
        Ok(response) => Ok(response),
        Err(e) => {
            state.proxy.invalidate_endpoint(role);
            Err(e)
        }
    }
}

/// Forward an upload request to a selected utility VM's guest dockerd.
pub async fn proxy_upload_to_role(
    state: &AppState,
    role: UtilityVmRole,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    ensure_role_ready(state, role).await?;
    match proxy::proxy_streaming_upload_for_role(state.proxy.connector(), role, uri, req).await {
        Ok(response) => Ok(response),
        Err(e) => {
            state.proxy.invalidate_endpoint(role);
            Err(e)
        }
    }
}
