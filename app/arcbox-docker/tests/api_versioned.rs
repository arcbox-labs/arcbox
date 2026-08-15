//! Docker API integration tests.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_versioned_api() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    // Any /v{major}.{minor} prefix is accepted; this one is an arbitrary
    // sample, not a supported ceiling.
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

    // A far older prefix, to show the parser has no floor either.
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
