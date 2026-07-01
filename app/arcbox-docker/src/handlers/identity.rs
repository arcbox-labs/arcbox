//! Docker URI identity extraction helpers.

use axum::http::Uri;

/// Extracts the `{id}` token from a `/containers/{id}/...` URI, ignoring
/// collection endpoints (`/containers/json|create|prune`).
#[must_use]
pub fn extract_container_id(uri: &Uri) -> Option<String> {
    extract_id_after_segment(uri, "containers", &["json", "create", "prune"])
}

fn extract_id_after_segment(uri: &Uri, segment: &str, skip_tokens: &[&str]) -> Option<String> {
    let segments: Vec<&str> = uri.path().split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in segments.iter().enumerate() {
        if *seg == segment && i + 1 < segments.len() {
            let id = segments[i + 1];
            if !skip_tokens.contains(&id) {
                return Some(id.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    #[test]
    fn extract_container_id_from_exec_subpath() {
        assert_eq!(
            extract_container_id(&uri("/containers/abc/exec")).as_deref(),
            Some("abc"),
        );
    }
}
