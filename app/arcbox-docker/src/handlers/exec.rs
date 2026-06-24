use super::proxy_to_role;
use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::request_context::ProxyRequestContext;
use axum::body::Body;
use axum::extract::{Extension, OriginalUri, State};
use axum::http::Request;
use axum::response::Response;

/// Create an exec instance on a container, recording the resulting exec ID
/// against the container's utility VM role so follow-up
/// `start`/`resize`/`inspect` calls land on the same VM.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.exec.create",
    skip(state, req),
    fields(uri = %uri, utility_vm = tracing::field::Empty, exec_id = tracing::field::Empty),
    err
)]
pub async fn exec_create(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Extension(proxy_context): Extension<ProxyRequestContext>,
    req: Request<Body>,
) -> Result<Response> {
    let role = proxy_context.role;
    tracing::Span::current().record("utility_vm", role.as_str());
    let response = proxy_to_role(&state, role, &uri, req).await?;
    if !response.status().is_success() {
        return Ok(response);
    }

    // Buffer the create response so the exec ID can be recorded. Exec create
    // responses are small JSON (just `Id`).
    let (parts, body) = response.into_parts();
    let body_bytes = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|e| DockerError::Server(format!("failed to read exec create response: {e}")))?
        .to_bytes();

    if let Some(exec_id) = parse_exec_create_response_id(&body_bytes) {
        tracing::Span::current().record("exec_id", exec_id.as_str());
        tracing::debug!(
            utility_vm = role.as_str(),
            exec_id = %exec_id,
            "recorded exec role binding",
        );
        state.workload_roles.record(exec_id, role).await;
    } else {
        tracing::warn!(
            utility_vm = role.as_str(),
            "exec create response missing exec ID; follow-up calls will fall back to native"
        );
    }

    Ok(Response::from_parts(parts, Body::from(body_bytes)))
}

/// Parses the `Id` field from a `POST /containers/{id}/exec` JSON response.
fn parse_exec_create_response_id(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("Id")?.as_str().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exec_id_from_create_response() {
        let json = br#"{"Id":"exec-abc123"}"#;
        assert_eq!(
            parse_exec_create_response_id(json).as_deref(),
            Some("exec-abc123"),
        );
    }

    #[test]
    fn returns_none_when_exec_create_response_missing_id() {
        assert_eq!(parse_exec_create_response_id(b"{}"), None);
        assert_eq!(parse_exec_create_response_id(b"not json"), None);
    }
}
