//! Container name DNS resolution via /etc/hosts.
//!
//! When containers start, their names are added to /etc/hosts pointing to
//! the guest VM's IP (127.0.0.1 for loopback, since all containers share
//! the guest's network namespace). This enables docker-compose style
//! inter-container name resolution.
//!
//! For compose compatibility, both the full container name and the service
//! name (extracted from the compose naming pattern `project-service-N`) are
//! registered.

use std::collections::HashSet;

/// IP address used for container name resolution.
/// All containers share the guest network namespace, so localhost works.
const HOSTS_IP: &str = "127.0.0.1";

/// Marker comment appended to lines managed by arcbox.
const HOSTS_MARKER: &str = "# arcbox";

/// Path to the hosts file.
const HOSTS_PATH: &str = "/etc/hosts";

/// Adds a DNS entry for a container to /etc/hosts.
///
/// Registers the container name (and an extracted compose service alias, if
/// applicable) so that other containers can resolve it by name.
pub fn add_container_dns(container_name: &str) {
    if container_name.is_empty() {
        return;
    }

    let aliases = collect_aliases(container_name);
    if aliases.is_empty() {
        return;
    }

    let names = aliases.join(" ");
    let new_line = format!("{HOSTS_IP}\t{names} {HOSTS_MARKER}:{container_name}");

    let content = std::fs::read_to_string(HOSTS_PATH).unwrap_or_default();

    // Check if an entry for this container already exists.
    let marker_tag = format!("{HOSTS_MARKER}:{container_name}");
    if content.lines().any(|l| l.contains(&marker_tag)) {
        tracing::debug!(
            "DNS entry for container '{}' already exists in {}",
            container_name,
            HOSTS_PATH
        );
        return;
    }

    let updated = if content.ends_with('\n') || content.is_empty() {
        format!("{content}{new_line}\n")
    } else {
        format!("{content}\n{new_line}\n")
    };

    if let Err(e) = std::fs::write(HOSTS_PATH, &updated) {
        tracing::warn!(
            "Failed to add DNS entry for '{}' to {}: {}",
            container_name,
            HOSTS_PATH,
            e
        );
    } else {
        tracing::info!(
            "Added DNS entry for container '{}': {} -> {}",
            container_name,
            names,
            HOSTS_IP
        );
    }
}

/// Removes the DNS entry for a container from /etc/hosts.
pub fn remove_container_dns(container_name: &str) {
    if container_name.is_empty() {
        return;
    }

    let content = match std::fs::read_to_string(HOSTS_PATH) {
        Ok(c) => c,
        Err(_) => return,
    };

    let marker_tag = format!("{HOSTS_MARKER}:{container_name}");
    let filtered: Vec<&str> = content
        .lines()
        .filter(|line| !line.contains(&marker_tag))
        .collect();

    // Nothing changed.
    if filtered.len() == content.lines().count() {
        return;
    }

    let mut updated = filtered.join("\n");
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }

    if let Err(e) = std::fs::write(HOSTS_PATH, &updated) {
        tracing::warn!(
            "Failed to remove DNS entry for '{}' from {}: {}",
            container_name,
            HOSTS_PATH,
            e
        );
    } else {
        tracing::debug!("Removed DNS entry for container '{}'", container_name);
    }
}

/// Collects all name aliases for a container.
///
/// For a compose container named `project-service-1`, this returns:
/// `["project-service-1", "service"]`
///
/// For a plain container named `mycontainer`, this returns:
/// `["mycontainer"]`
fn collect_aliases(container_name: &str) -> Vec<String> {
    if container_name.is_empty() {
        return vec![];
    }

    let mut names = vec![container_name.to_string()];

    // Docker compose names containers as `project-service-N` (or
    // `project_service_N` with older versions). Extract the service name
    // by stripping the project prefix and the replica suffix.
    if let Some(service) = extract_compose_service(container_name) {
        if service != container_name {
            names.push(service);
        }
    }

    names
}

/// Extracts the compose service name from a container name.
///
/// Compose v2 names: `project-service-N` (hyphen separated)
/// Compose v1 names: `project_service_N` (underscore separated)
///
/// Returns the middle segment (service name) if the pattern matches.
fn extract_compose_service(name: &str) -> Option<String> {
    // Try hyphen-separated pattern first (compose v2).
    // Pattern: anything-SERVICE-digit(s)
    if let Some(pos) = name.rfind('-') {
        let suffix = &name[pos + 1..];
        if suffix.chars().all(|c| c.is_ascii_digit()) && pos > 0 {
            let prefix_and_service = &name[..pos];
            if let Some(first_sep) = prefix_and_service.find('-') {
                return Some(prefix_and_service[first_sep + 1..].to_string());
            }
        }
    }

    // Try underscore-separated pattern (compose v1).
    if let Some(pos) = name.rfind('_') {
        let suffix = &name[pos + 1..];
        if suffix.chars().all(|c| c.is_ascii_digit()) && pos > 0 {
            let prefix_and_service = &name[..pos];
            if let Some(first_sep) = prefix_and_service.find('_') {
                return Some(prefix_and_service[first_sep + 1..].to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_compose_service_v2() {
        assert_eq!(
            extract_compose_service("myproject-web-1"),
            Some("web".to_string())
        );
        assert_eq!(
            extract_compose_service("myproject-api-server-2"),
            Some("api-server".to_string())
        );
    }

    #[test]
    fn test_extract_compose_service_v1() {
        assert_eq!(
            extract_compose_service("myproject_web_1"),
            Some("web".to_string())
        );
        assert_eq!(
            extract_compose_service("myproject_api_server_2"),
            Some("api_server".to_string())
        );
    }

    #[test]
    fn test_extract_compose_service_plain() {
        assert_eq!(extract_compose_service("mycontainer"), None);
        assert_eq!(extract_compose_service("web"), None);
    }

    #[test]
    fn test_extract_compose_service_edge_cases() {
        // Single character project and service.
        assert_eq!(extract_compose_service("a-b-1"), Some("b".to_string()));
        // No digit suffix.
        assert_eq!(extract_compose_service("project-web-abc"), None);
        // Only project and suffix, no service.
        assert_eq!(extract_compose_service("1"), None);
        assert_eq!(extract_compose_service("-1"), None);
    }

    #[test]
    fn test_collect_aliases() {
        let aliases = collect_aliases("myproject-web-1");
        assert_eq!(aliases, vec!["myproject-web-1", "web"]);

        let aliases = collect_aliases("mycontainer");
        assert_eq!(aliases, vec!["mycontainer"]);
    }

    #[test]
    fn test_collect_aliases_empty() {
        let aliases = collect_aliases("");
        assert!(aliases.is_empty());
    }
}
