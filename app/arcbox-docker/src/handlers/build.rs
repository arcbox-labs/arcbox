use crate::routing::route_build;

/// Forwards `POST /build` to guest dockerd through the upload-specific proxy
/// path, which applies backpressure via a bounded channel so large build
/// contexts (monorepos, node_modules) don't OOM the proxy.
///
/// ABX-375: builds run in the single HV utility VM. `--platform linux/amd64`
/// build steps execute via FEX inside that VM; if FEX is not provisioned
/// the build fails closed (no silent VZ/Rosetta or QEMU fallback). All build
/// options (tags, target, build-args, platform, etc.) are forwarded verbatim
/// to guest dockerd's BuildKit.
#[tracing::instrument(
    name = "docker.build",
    skip(state, req),
    fields(uri = %uri, utility_vm = tracing::field::Empty, translator = tracing::field::Empty),
    err
)]
pub async fn build_image(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    req: axum::http::Request<axum::body::Body>,
) -> crate::error::Result<axum::response::Response> {
    let route = route_build(&uri);
    tracing::Span::current().record("utility_vm", route.utility_vm().as_str());
    tracing::Span::current().record("translator", route.translator.as_str());
    crate::handlers::require_amd64_runtime(&state, route).await?;
    tracing::debug!(
        backend = "hv",
        translator = route.translator.as_str(),
        platform = ?route.platform,
        "routing Docker build request"
    );
    crate::handlers::proxy_upload_to_role(&state, route.utility_vm(), &uri, req).await
}
