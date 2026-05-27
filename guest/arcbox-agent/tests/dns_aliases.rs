//! Integration tests for container DNS alias extraction.

use arcbox_agent::dns::{ComposeInfo, collect_aliases, extract_compose_info};

fn compose(project: &str, service: &str) -> ComposeInfo {
    ComposeInfo {
        project: project.to_string(),
        service: service.to_string(),
    }
}

#[test]
fn compose_v2_hierarchical_plus_flat() {
    let info = compose("myproject", "web");
    let aliases = collect_aliases("myproject-web-1", Some(&info));
    assert_eq!(aliases, vec!["web.myproject", "myproject-web-1"]);
}

#[test]
fn compose_v2_multi_segment_service() {
    let info = compose("myproject", "api-server");
    let aliases = collect_aliases("myproject-api-server-2", Some(&info));
    assert_eq!(
        aliases,
        vec!["api-server.myproject", "myproject-api-server-2"]
    );
}

#[test]
fn compose_v1_underscore() {
    let info = compose("myproject", "web");
    let aliases = collect_aliases("myproject_web_1", Some(&info));
    assert_eq!(aliases, vec!["web.myproject", "myproject_web_1"]);
}

#[test]
fn plain_container_no_alias() {
    let aliases = collect_aliases("mycontainer", None);
    assert_eq!(aliases, vec!["mycontainer"]);
}

#[test]
fn empty_name_no_aliases() {
    let aliases = collect_aliases("", None);
    assert!(aliases.is_empty());
}

#[test]
fn extract_compose_info_from_labels() {
    let mut labels = serde_json::Map::new();
    labels.insert(
        "com.docker.compose.project".to_string(),
        serde_json::Value::String("myproject".to_string()),
    );
    labels.insert(
        "com.docker.compose.service".to_string(),
        serde_json::Value::String("web".to_string()),
    );
    let info = extract_compose_info(&labels).unwrap();
    assert_eq!(info.project, "myproject");
    assert_eq!(info.service, "web");
}

#[test]
fn extract_compose_info_missing_labels() {
    let labels = serde_json::Map::new();
    assert!(extract_compose_info(&labels).is_none());
}
