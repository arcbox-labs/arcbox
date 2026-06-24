//! Docker API integration tests.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_versioned_api() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    // Test v1.43 (current)
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1.43/_ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_older_api_version() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    // Test v1.24 (minimum supported)
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1.24/_ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
