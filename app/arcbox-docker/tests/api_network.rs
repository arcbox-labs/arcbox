//! Docker API integration tests.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;
use http_body_util::BodyExt;

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_list_networks() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/networks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have at least the default bridge network
    assert!(json.is_array());
    let networks = json.as_array().unwrap();
    assert!(networks.iter().any(|n| n["Name"] == "bridge"));
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_create_network() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let body = serde_json::json!({
        "Name": "test-network",
        "Driver": "bridge"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/networks/create")
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
}
