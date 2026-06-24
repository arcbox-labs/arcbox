//! Docker API integration tests.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;
use http_body_util::BodyExt;

/// Test exec creation in a container.
///
/// This test requires a real image to be available in the local store.
/// Run `docker pull alpine:latest` before running this test.
#[tokio::test]
#[ignore = "requires image alpine:latest in local store"]
async fn test_exec_create() {
    let (runtime, connector, _tmp) = create_test_runtime().await;

    // Create and start container first
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let create_body = serde_json::json!({
        "Image": "alpine:latest"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/containers/create")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&create_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let container_id = json["Id"].as_str().unwrap().to_string();

    // Start container
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/containers/{}/start", container_id))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    // Create exec
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let exec_body = serde_json::json!({
        "Cmd": ["ls", "-la"],
        "AttachStdout": true,
        "AttachStderr": true
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/containers/{}/exec", container_id))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&exec_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("Id").is_some());
}
