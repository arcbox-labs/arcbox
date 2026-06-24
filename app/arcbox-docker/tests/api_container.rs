//! Docker API integration tests.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;
use http_body_util::BodyExt;

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_list_containers_empty() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/containers/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 0);
}

/// Test container creation.
///
/// This test requires a real image to be available in the local store.
/// Run `docker pull alpine:latest` before running this test.
#[tokio::test]
#[ignore = "requires image alpine:latest in local store"]
async fn test_create_container() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let body = serde_json::json!({
        "Image": "alpine:latest",
        "Cmd": ["echo", "hello"]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/containers/create?name=test-container")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("Id").is_some());
    assert!(json.get("Warnings").is_some());
}

/// Test full container lifecycle (create, start, stop, remove).
///
/// This test requires a real image to be available in the local store.
/// Run `docker pull nginx:latest` before running this test.
#[tokio::test]
#[ignore = "requires image nginx:latest in local store"]
async fn test_container_lifecycle() {
    let (runtime, connector, _tmp) = create_test_runtime().await;

    // Create container
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let create_body = serde_json::json!({
        "Image": "nginx:latest"
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

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let container_id = json["Id"].as_str().unwrap().to_string();

    // Start container
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/containers/{}/start", container_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // List containers (should show running)
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/containers/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);

    // Stop container
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/containers/{}/stop", container_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Remove container
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/containers/{}", container_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // List containers (should be empty)
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/containers/json?all=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 0);
}

/// Test container inspection.
///
/// This test requires a real image to be available in the local store.
/// Run `docker pull alpine:latest` before running this test.
#[tokio::test]
#[ignore = "requires image alpine:latest in local store"]
async fn test_inspect_container() {
    let (runtime, connector, _tmp) = create_test_runtime().await;

    // Create container
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let create_body = serde_json::json!({
        "Image": "alpine:latest"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/containers/create?name=inspect-test")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&create_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let container_id = json["Id"].as_str().unwrap().to_string();

    // Inspect container
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/containers/{}/json", container_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("Id").is_some());
    assert!(json.get("State").is_some());
    assert!(json.get("Config").is_some());
    assert!(json.get("Name").is_some());
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_container_not_found() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/containers/nonexistent/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_wait_container_invalid_condition_returns_bad_request() {
    let (runtime, connector, _tmp) = create_test_runtime().await;

    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/containers/nonexistent/wait?condition=invalid-condition")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(matches!(
        response.status(),
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
    ));
}
