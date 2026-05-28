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
pub async fn session(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    req: axum::http::Request<axum::body::Body>,
) -> crate::error::Result<axum::response::Response> {
    crate::handlers::proxy_upgrade(&state, &uri, req).await
}
