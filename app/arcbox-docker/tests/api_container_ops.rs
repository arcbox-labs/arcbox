//! Docker API integration tests.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;
use http_body_util::BodyExt;

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_prune_containers() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/containers/prune")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have ContainersDeleted and SpaceReclaimed fields.
    assert!(json.get("ContainersDeleted").is_some());
    assert!(json.get("SpaceReclaimed").is_some());
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_pause_container_not_found() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/containers/nonexistent/pause")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_unpause_container_not_found() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/containers/nonexistent/unpause")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_rename_container_not_found() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/containers/nonexistent/rename?name=newname")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_container_top_not_found() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/containers/nonexistent/top")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_container_stats_not_found() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/containers/nonexistent/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd"]
async fn test_container_changes_not_found() {
    let (runtime, connector, _tmp) = create_test_runtime().await;
    let app = create_router(runtime, connector);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/containers/nonexistent/changes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
