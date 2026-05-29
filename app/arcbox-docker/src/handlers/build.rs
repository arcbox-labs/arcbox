use crate::routing::{UtilityVmRole, route_build};

/// Forwards `POST /build` to guest dockerd through the upload-specific proxy
/// path, which applies backpressure via a bounded channel so large build
/// contexts (monorepos, node_modules) don't OOM the proxy.
///
/// ABX-375: builds run in the single HV utility VM. `--platform linux/amd64`
/// build steps execute via FEX64 inside that VM; if FEX64 is not provisioned
/// the build fails closed (no silent VZ/Rosetta or QEMU fallback). All build
/// options (tags, target, build-args, platform, etc.) are forwarded verbatim
/// to guest dockerd's BuildKit.
pub async fn build_image(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    req: axum::http::Request<axum::body::Body>,
) -> crate::error::Result<axum::response::Response> {
    let route = route_build(&uri);
    crate::handlers::require_amd64_runtime(&state, route).await?;
    tracing::debug!(
        backend = "hv",
        translator = route.translator.as_str(),
        platform = ?route.platform,
        "routing Docker build request"
    );
    crate::handlers::proxy_upload_to_role(&state, route.utility_vm(), &uri, req).await
}

// Forwards `POST /build/prune` (prune build cache) to guest dockerd.
crate::handlers::proxy_handler!(build_prune);

/// Forwards `POST /session` to guest dockerd via the upgrade proxy.
///
/// BuildKit uses HTTP/1.1 upgrade to establish a gRPC multiplexed session
/// for build mounts, secrets, and SSH forwarding. The upgrade proxy bridges
/// the bidirectional stream between client and guest.
///
/// ABX-375: there is a single HV utility VM, so the session always targets
/// it — no cross-VM `/session` role synchronization is required (unlike the
/// dual-VM ABX-374 path).
pub async fn session(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    req: axum::http::Request<axum::body::Body>,
) -> crate::error::Result<axum::response::Response> {
    crate::handlers::proxy_upgrade_to_role(&state, UtilityVmRole::Native, &uri, req).await
}
