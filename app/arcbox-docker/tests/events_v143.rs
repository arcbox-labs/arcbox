use arcbox_core::Runtime;
use arcbox_core::config::Config;
use arcbox_core::event::Event;
use arcbox_docker::DockerError;
use arcbox_docker::api::AppState;
use arcbox_docker::handlers::{EventsQuery, events};
use axum::extract::{OriginalUri, Query, State};
use axum::http::{HeaderMap, Uri, header};
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

struct TestContext {
    _temp_dir: tempfile::TempDir,
    runtime: Arc<Runtime>,
    state: AppState,
}

fn test_context() -> TestContext {
    let temp_dir = tempfile::tempdir().expect("tempdir failed");
    let mut config = Config::default();
    config.data_dir = temp_dir.path().to_path_buf();
    let runtime = Arc::new(Runtime::new(config).expect("runtime init"));
    let state = AppState {
        runtime: runtime.clone(),
    };

    TestContext {
        _temp_dir: temp_dir,
        runtime,
        state,
    }
}

#[tokio::test]
async fn events_v143_response_matches_schema_and_legacy_fields() {
    let ctx = test_context();

    let params = EventsQuery {
        since: None,
        until: None,
        filters: None,
    };
    let headers = HeaderMap::new();
    let uri: Uri = "/v1.43/events".parse().expect("uri parse");
    let response = events(State(ctx.state), Query(params), headers, OriginalUri(uri))
        .await
        .expect("events handler");

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert_eq!(content_type, "application/json");

    ctx.runtime.event_bus().publish(Event::ContainerStarted {
        id: "abc123".to_string(),
        name: "/demo".to_string(),
        image: "alpine:latest".to_string(),
        labels: HashMap::from([("com.example.label".to_string(), "true".to_string())]),
    });

    let mut stream = response.into_body().into_data_stream();
    let chunk = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("event timeout")
        .expect("no event")
        .expect("stream error");

    let value: serde_json::Value = serde_json::from_slice(&chunk).expect("json parse");

    assert_eq!(
        value.get("Type").and_then(|v| v.as_str()),
        Some("container")
    );
    assert_eq!(value.get("Action").and_then(|v| v.as_str()), Some("start"));
    assert_eq!(value.get("scope").and_then(|v| v.as_str()), Some("local"));
    assert!(value.get("time").and_then(|v| v.as_i64()).is_some());
    assert!(value.get("timeNano").and_then(|v| v.as_i64()).is_some());

    let actor = value.get("Actor").expect("actor");
    assert_eq!(actor.get("ID").and_then(|v| v.as_str()), Some("abc123"));
    assert_eq!(
        actor
            .get("Attributes")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str()),
        Some("demo")
    );
    assert_eq!(
        actor
            .get("Attributes")
            .and_then(|v| v.get("image"))
            .and_then(|v| v.as_str()),
        Some("alpine:latest")
    );
    assert_eq!(
        actor
            .get("Attributes")
            .and_then(|v| v.get("com.example.label"))
            .and_then(|v| v.as_str()),
        Some("true")
    );

    assert_eq!(value.get("id").and_then(|v| v.as_str()), Some("abc123"));
    assert_eq!(value.get("status").and_then(|v| v.as_str()), Some("start"));
    assert_eq!(
        value.get("from").and_then(|v| v.as_str()),
        Some("alpine:latest")
    );
}

#[tokio::test]
async fn events_v143_rejects_invalid_filters() {
    let ctx = test_context();
    let params = EventsQuery {
        since: None,
        until: None,
        filters: Some("not-json".to_string()),
    };
    let headers = HeaderMap::new();
    let uri: Uri = "/v1.43/events".parse().expect("uri parse");
    let err = events(State(ctx.state), Query(params), headers, OriginalUri(uri))
        .await
        .expect_err("expected bad request");

    assert!(matches!(err, DockerError::BadRequest(_)));
}

#[tokio::test]
async fn events_v143_filters_allow_matching_event() {
    let ctx = test_context();
    let filters = r#"{"type":["container"],"container":["abc123"],"event":["start"]}"#;
    let params = EventsQuery {
        since: None,
        until: None,
        filters: Some(filters.to_string()),
    };
    let headers = HeaderMap::new();
    let uri: Uri = "/v1.43/events".parse().expect("uri parse");
    let response = events(State(ctx.state), Query(params), headers, OriginalUri(uri))
        .await
        .expect("events handler");

    ctx.runtime.event_bus().publish(Event::ContainerStarted {
        id: "abc123".to_string(),
        name: "/demo".to_string(),
        image: "alpine:latest".to_string(),
        labels: HashMap::new(),
    });

    let mut stream = response.into_body().into_data_stream();
    let chunk = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("event timeout")
        .expect("no event")
        .expect("stream error");
    let value: serde_json::Value = serde_json::from_slice(&chunk).expect("json parse");
    assert_eq!(value.get("Action").and_then(|v| v.as_str()), Some("start"));
}

#[tokio::test]
async fn events_v143_filters_block_non_matching_event() {
    let ctx = test_context();
    let filters = r#"{"type":["container"],"event":["stop"]}"#;
    let params = EventsQuery {
        since: None,
        until: None,
        filters: Some(filters.to_string()),
    };
    let headers = HeaderMap::new();
    let uri: Uri = "/v1.43/events".parse().expect("uri parse");
    let response = events(State(ctx.state), Query(params), headers, OriginalUri(uri))
        .await
        .expect("events handler");

    ctx.runtime.event_bus().publish(Event::ContainerStarted {
        id: "abc123".to_string(),
        name: "/demo".to_string(),
        image: "alpine:latest".to_string(),
        labels: HashMap::new(),
    });

    let mut stream = response.into_body().into_data_stream();
    let result = tokio::time::timeout(Duration::from_millis(200), stream.next()).await;
    assert!(result.is_err(), "unexpected event received");
}
