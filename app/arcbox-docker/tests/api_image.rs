//! Docker API integration tests.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;
use http_body_util::BodyExt;

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_list_images() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/images/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
}
