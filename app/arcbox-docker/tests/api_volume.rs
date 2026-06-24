//! Docker API integration tests.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;
use http_body_util::BodyExt;

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_list_volumes() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/volumes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("Volumes").is_some());
    assert!(json.get("Warnings").is_some());
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_create_volume() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let body = serde_json::json!({
        "Name": "test-volume"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/volumes/create")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["Name"], "test-volume");
    assert!(json.get("Mountpoint").is_some());
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_volume_lifecycle() {
    let (runtime, connector, _tmp) = create_test_runtime().await;

    // Create volume
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let create_body = serde_json::json!({
        "Name": "lifecycle-volume"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/volumes/create")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&create_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Inspect volume
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/volumes/lifecycle-volume")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Remove volume
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/volumes/lifecycle-volume")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify removed
    let app = create_router(Arc::clone(&runtime), Arc::clone(&connector) as _);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/volumes/lifecycle-volume")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
