//! Read-only guest dockerd queries shared by the container handlers, the
//! host-networking reconciler, and daemon cold-start recovery.
//!
//! Each caller previously hand-rolled the same HTTP round-trip + JSON parse;
//! this module owns that once, over the pooled guest client.

use crate::error::{DockerError, Result};
use crate::proxy::{GuestHttpClient, proxy_to_guest_pooled};
use axum::http::{HeaderMap, Method};
use bytes::Bytes;
use http_body_util::BodyExt;
use std::collections::HashSet;

/// Fetches the inspect JSON for a container (by name, short ID, or full ID).
///
/// Returns `None` on any failure — a missing container and a transport error
/// are equally "no inspect data" to the callers, which all degrade gracefully.
pub async fn inspect_container(client: &GuestHttpClient, token: &str) -> Option<Bytes> {
    let path = format!("/containers/{token}/json");
    let response = match proxy_to_guest_pooled(
        client,
        Method::GET,
        &path,
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            tracing::debug!(token, status = %response.status(), "container inspect not available");
            return None;
        }
        Err(e) => {
            tracing::debug!(token, error = %e, "container inspect failed");
            return None;
        }
    };

    match BodyExt::collect(response.into_body()).await {
        Ok(collected) => Some(collected.to_bytes()),
        Err(e) => {
            tracing::debug!(token, error = %e, "failed to read container inspect body");
            None
        }
    }
}

/// Queries guest dockerd for the IDs of currently-running containers.
///
/// Errors are surfaced (not swallowed) because callers treat "could not list"
/// differently from "empty list" — the reconciler skips its cycle fail-safe,
/// recovery skips marking the VM as running.
pub async fn list_running_container_ids(client: &GuestHttpClient) -> Result<HashSet<String>> {
    let response = proxy_to_guest_pooled(
        client,
        Method::GET,
        "/containers/json",
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await?;
    if !response.status().is_success() {
        return Err(DockerError::Server(format!(
            "guest /containers/json returned {}",
            response.status()
        )));
    }
    let body = BodyExt::collect(response.into_body())
        .await
        .map_err(|e| DockerError::Server(format!("read /containers/json body: {e}")))?
        .to_bytes();
    Ok(parse_container_ids(&body))
}

/// Extracts full container IDs from a `GET /containers/json` response body.
/// Malformed JSON yields an empty set (treated as a failed read upstream).
fn parse_container_ids(body: &[u8]) -> HashSet<String> {
    serde_json::from_slice::<Vec<serde_json::Value>>(body)
        .unwrap_or_default()
        .iter()
        .filter_map(|c| {
            c.get("Id")
                .and_then(serde_json::Value::as_str)
                .map(String::from)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ids_from_docker_list() {
        let body = br#"[{"Id":"aaa","Names":["/x"]},{"Id":"bbb"}]"#;
        assert_eq!(
            parse_container_ids(body),
            HashSet::from(["aaa".to_string(), "bbb".to_string()])
        );
        assert!(parse_container_ids(b"[]").is_empty());
        assert!(parse_container_ids(b"not json").is_empty());
    }
}
