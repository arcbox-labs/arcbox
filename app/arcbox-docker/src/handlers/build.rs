/// Forwards `POST /build` to guest dockerd through the upload-specific proxy
/// path, which applies backpressure via a bounded channel so large build
/// contexts (monorepos, node_modules) don't OOM the proxy.
///
/// All build options (tags, target, build-args, platform, etc.) are passed as
/// query parameters and forwarded verbatim to guest dockerd's BuildKit.
///
/// Also records the BuildKit session UUID (carried by the
/// `X-Docker-Expose-Session-Uuid` header) so a parallel `/session`
/// request on the same UUID can be routed to the same utility VM. The
/// Docker CLI sends the two endpoints concurrently, and `/session` may
/// arrive first; the UUID binding lets that handler park on
/// [`WorkloadRoleRegistry::wait_for_role`] until this `/build` declares
/// the role.
pub async fn build_image(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    req: axum::http::Request<axum::body::Body>,
) -> crate::error::Result<axum::response::Response> {
    let route = crate::routing::route_build(&uri);
    let session_uuid = req
        .headers()
        .get("x-docker-expose-session-uuid")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    tracing::debug!(
        utility_vm = route.utility_vm.as_str(),
        platform = ?route.platform,
        session_uuid = session_uuid.as_deref().unwrap_or(""),
        "routing Docker build request"
    );
    if let Some(ref uuid) = session_uuid {
        state
            .workload_roles
            .record(uuid.clone(), route.utility_vm)
            .await;
    }
    crate::handlers::proxy_upload_to_role(&state, route.utility_vm, &uri, req).await
}

// Forwards `POST /build/prune` (prune build cache) to guest dockerd.
crate::handlers::proxy_handler!(build_prune);

/// Forwards `POST /session` to guest dockerd via the upgrade proxy.
///
/// BuildKit uses HTTP/1.1 upgrade to establish a gRPC multiplexed session
/// for features like build mounts, secrets, and SSH forwarding. The upgrade
/// proxy handles bidirectional stream bridging between client and guest.
///
/// The Docker CLI opens `/session` and the matching `/build` concurrently,
/// and the session itself carries no platform metadata — the role must
/// come from `/build`. We resolve the session's role via
/// [`WorkloadRoleRegistry::wait_for_role`], keyed by the BuildKit
/// `X-Docker-Expose-Session-Uuid` header:
///
/// 1. If `/build` already recorded the UUID, we forward immediately to
///    that role.
/// 2. If `/session` arrives first, we wait up to
///    [`SESSION_ROLE_WAIT_TIMEOUT`] for `/build` to declare the role.
/// 3. On timeout we forward to native so the session at least completes
///    its upgrade — the user gets a BuildKit-level error rather than a
///    hanging request.
pub async fn session(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    req: axum::http::Request<axum::body::Body>,
) -> crate::error::Result<axum::response::Response> {
    let session_uuid = req
        .headers()
        .get("x-docker-expose-session-uuid")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let role = match session_uuid {
        Some(uuid) => match state
            .workload_roles
            .wait_for_role(&uuid, SESSION_ROLE_WAIT_TIMEOUT)
            .await
        {
            Some(role) => {
                tracing::debug!(
                    session_uuid = %uuid,
                    utility_vm = role.as_str(),
                    "routing BuildKit /session to recorded role",
                );
                role
            }
            None => {
                tracing::warn!(
                    session_uuid = %uuid,
                    timeout_secs = SESSION_ROLE_WAIT_TIMEOUT.as_secs(),
                    "no matching /build arrived; routing /session to native",
                );
                crate::routing::UtilityVmRole::Native
            }
        },
        None => {
            tracing::debug!("BuildKit /session without UUID; defaulting to native");
            crate::routing::UtilityVmRole::Native
        }
    };
    crate::handlers::proxy_upgrade_to_role(&state, role, &uri, req).await
}

/// Maximum time `/session` parks waiting for `/build` to declare the
/// role for the same `X-Docker-Expose-Session-Uuid`.
///
/// 30 seconds matches BuildKit's own session-handshake timeout and
/// covers the worst-case CLI scheduling delay between the parallel
/// `/session` and `/build` connections.
const SESSION_ROLE_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
