//! Integration tests for Docker API handlers.
//!
//! These tests verify the Docker Engine API compatibility layer works correctly.

use arcbox_core::{Config, ContainerBackendMode, Runtime, VmLifecycleConfig};
use arcbox_docker::api::create_router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::time::Duration;
use tower::ServiceExt;

/// Creates a test runtime with a temporary data directory.
/// Uses skip_vm_check=true to avoid needing actual VM boot assets.
async fn create_test_runtime() -> (Arc<Runtime>, TempDir) {
    let tmp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut config = Config {
        data_dir: tmp_dir.path().to_path_buf(),
        ..Default::default()
    };
    // API handler tests validate HTTP contract, not guest-docker provisioning.
    // Keep them on native backend to avoid boot-assets network dependency.
    config.container.backend = ContainerBackendMode::NativeControlPlane;

    let vm_lifecycle_config = VmLifecycleConfig {
        skip_vm_check: true,
        ..Default::default()
    };
    let runtime = Arc::new(
        Runtime::with_vm_lifecycle_config(config, vm_lifecycle_config)
            .expect("Failed to create runtime"),
    );
    runtime.init().await.expect("Failed to init runtime");
    (runtime, tmp_dir)
}

// ============================================================================
// System API Tests
// ============================================================================

#[tokio::test]
async fn test_ping() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/_ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_version() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("Version").is_some());
    assert!(json.get("ApiVersion").is_some());
    assert!(json.get("Os").is_some());
    assert!(json.get("Arch").is_some());
}

#[tokio::test]
async fn test_info() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

    let response = app
        .oneshot(Request::builder().uri("/info").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("Containers").is_some());
    assert!(json.get("Images").is_some());
    assert!(json.get("ServerVersion").is_some());
}

// ============================================================================
// Container API Tests
// ============================================================================

#[tokio::test]
async fn test_list_containers_empty() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
/// Run `arcbox pull alpine:latest` before running this test.
#[tokio::test]
#[ignore = "requires image alpine:latest in local store"]
async fn test_create_container() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
/// Run `arcbox pull nginx:latest` before running this test.
#[tokio::test]
#[ignore = "requires image nginx:latest in local store"]
async fn test_container_lifecycle() {
    let (runtime, _tmp) = create_test_runtime().await;

    // Create container
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
/// Run `arcbox pull alpine:latest` before running this test.
#[tokio::test]
#[ignore = "requires image alpine:latest in local store"]
async fn test_inspect_container() {
    let (runtime, _tmp) = create_test_runtime().await;

    // Create container
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
async fn test_container_not_found() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_wait_container_invalid_condition_returns_bad_request() {
    let (runtime, _tmp) = create_test_runtime().await;

    let container_id = runtime
        .container_manager()
        .create(arcbox_container::ContainerConfig {
            image: "alpine:latest".to_string(),
            ..Default::default()
        })
        .expect("failed to create container");

    let app = create_router(Arc::clone(&runtime));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/containers/{}/wait?condition=invalid-condition",
                    container_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let message = json["message"].as_str().unwrap_or_default();
    assert!(message.contains("invalid wait condition"));
}

#[tokio::test]
async fn test_wait_container_not_running_returns_cached_exit_code() {
    let (runtime, _tmp) = create_test_runtime().await;

    let container_id = runtime
        .container_manager()
        .create(arcbox_container::ContainerConfig {
            image: "alpine:latest".to_string(),
            ..Default::default()
        })
        .expect("failed to create container");
    runtime.container_manager().notify_exit(&container_id, 23);

    let app = create_router(Arc::clone(&runtime));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/containers/{}/wait", container_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["StatusCode"], 23);
}

#[tokio::test]
async fn test_wait_container_next_exit_waits_for_future_exit() {
    let (runtime, _tmp) = create_test_runtime().await;

    let container_id = runtime
        .container_manager()
        .create(arcbox_container::ContainerConfig {
            image: "alpine:latest".to_string(),
            ..Default::default()
        })
        .expect("failed to create container");

    // Place container in already-exited state first.
    runtime.container_manager().notify_exit(&container_id, 7);

    let app = create_router(Arc::clone(&runtime));
    let wait_task = tokio::spawn(async move {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/containers/{}/wait?condition=next-exit",
                    container_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !wait_task.is_finished(),
        "next-exit should wait for a future exit"
    );

    let container_id_for_transition = runtime
        .container_manager()
        .list()
        .first()
        .expect("container should exist")
        .id
        .clone();
    runtime
        .container_manager()
        .begin_start(&container_id_for_transition)
        .expect("begin_start should succeed");
    runtime
        .container_manager()
        .finish_start(&container_id_for_transition)
        .expect("finish_start should succeed");
    runtime
        .container_manager()
        .notify_exit(&container_id_for_transition, 42);

    let response = tokio::time::timeout(Duration::from_secs(1), wait_task)
        .await
        .expect("wait request timed out")
        .expect("wait task failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["StatusCode"], 42);
}

// ============================================================================
// Exec API Tests
// ============================================================================

/// Test exec creation in a container.
///
/// This test requires a real image to be available in the local store.
/// Run `arcbox pull alpine:latest` before running this test.
#[tokio::test]
#[ignore = "requires image alpine:latest in local store"]
async fn test_exec_create() {
    let (runtime, _tmp) = create_test_runtime().await;

    // Create and start container first
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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

// ============================================================================
// Network API Tests
// ============================================================================

#[tokio::test]
async fn test_list_networks() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_create_network() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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

// ============================================================================
// Volume API Tests
// ============================================================================

#[tokio::test]
async fn test_list_volumes() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_create_volume() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_volume_lifecycle() {
    let (runtime, _tmp) = create_test_runtime().await;

    // Create volume
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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
    let app = create_router(Arc::clone(&runtime));
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

// ============================================================================
// Image API Tests
// ============================================================================

#[tokio::test]
async fn test_list_images() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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

// ============================================================================
// Versioned API Tests
// ============================================================================

#[tokio::test]
async fn test_versioned_api() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_older_api_version() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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

// ============================================================================
// Additional Container Operation Tests
// ============================================================================

#[tokio::test]
async fn test_prune_containers() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_pause_container_not_found() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_unpause_container_not_found() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_rename_container_not_found() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_container_top_not_found() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_container_stats_not_found() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
async fn test_container_changes_not_found() {
    let (runtime, _tmp) = create_test_runtime().await;
    let app = create_router(runtime);

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
