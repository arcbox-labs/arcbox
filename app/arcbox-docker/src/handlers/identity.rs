//! Docker URI identity extraction helpers.

use axum::http::Uri;

/// Extracts the `{id}` token from a `/containers/{id}/...` URI, ignoring
/// collection endpoints (`/containers/json|create|prune`).
#[must_use]
pub fn extract_container_id(uri: &Uri) -> Option<String> {
    extract_id_after_segment(uri, "containers", &["json", "create", "prune"])
}

/// Extracts the `{id}` token from an `/exec/{id}/...` URI.
#[must_use]
pub fn extract_exec_id(uri: &Uri) -> Option<String> {
    extract_id_after_segment(uri, "exec", &[])
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
    fn extract_exec_id_from_simple_path() {
        assert_eq!(
            extract_exec_id(&uri("/exec/exec-abc/start")).as_deref(),
            Some("exec-abc"),
        );
    }

    #[test]
    fn extract_exec_id_from_versioned_path() {
        assert_eq!(
            extract_exec_id(&uri("/v1.51/exec/exec-xyz/resize?w=80&h=24")).as_deref(),
            Some("exec-xyz"),
        );
    }

    #[test]
    fn extract_exec_id_ignores_non_exec_paths() {
        assert_eq!(extract_exec_id(&uri("/containers/abc/start")), None);
    }

    #[test]
    fn extract_container_id_from_exec_subpath() {
        assert_eq!(
            extract_container_id(&uri("/containers/abc/exec")).as_deref(),
            Some("abc"),
        );
    }
}
