/// Forwards `POST /build` to guest dockerd through the upload-specific proxy
/// path, which applies backpressure via a bounded channel so large build
/// contexts (monorepos, node_modules) don't OOM the proxy.
///
/// All build options (tags, target, build-args, platform, etc.) are passed as
/// query parameters and forwarded verbatim to guest dockerd's BuildKit.
pub async fn build_image(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    req: axum::http::Request<axum::body::Body>,
) -> crate::error::Result<axum::response::Response> {
    let route = crate::routing::route_build(&uri);
    tracing::debug!(
        utility_vm = route.utility_vm.as_str(),
        platform = ?route.platform,
        "routing Docker build request"
    );
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
/// Routing limitation: the Docker CLI opens `/session` *before* it sends
/// the matching `/build` that carries platform metadata, so the role
/// cannot be derived from the session itself. We forward `/session` to
/// the native (HV) utility VM by default; an amd64 build that needs
/// Rosetta-side BuildKit features will not see this session and the
/// build's side channels will fail. Routing both endpoints requires
/// lazy session forwarding keyed by `X-Docker-Expose-Session-Uuid`,
/// which is tracked as a follow-up to this PR.
pub async fn session(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    req: axum::http::Request<axum::body::Body>,
) -> crate::error::Result<axum::response::Response> {
    if let Some(uuid) = req
        .headers()
        .get("x-docker-expose-session-uuid")
        .and_then(|v| v.to_str().ok())
    {
        tracing::debug!(
            session_uuid = %uuid,
            "forwarding BuildKit /session to the native utility VM",
        );
    }
    crate::handlers::proxy_upgrade(&state, &uri, req).await
}
