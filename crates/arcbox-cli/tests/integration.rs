//! Integration tests for arcbox-cli.
//!
//! These tests verify the CLI client communicates correctly with a mock
//! Docker-compatible API server.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

// Needed for tower-hyper bridge.
#[allow(unused_imports)]
use hyper_util::service::TowerToHyperService;

// ============================================================================
// Mock Server Types
// ============================================================================

/// Mock container state for testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MockContainer {
    id: String,
    name: String,
    image: String,
    state: String,
    status: String,
    command: String,
    created: i64,
    exit_code: Option<i32>,
}

/// Mock server state.
#[derive(Debug, Default)]
struct MockState {
    containers: HashMap<String, MockContainer>,
    execs: HashMap<String, MockExec>,
    next_container_id: u64,
    next_exec_id: u64,
}

/// Mock exec instance.
#[derive(Debug, Clone)]
struct MockExec {
    id: String,
    container_id: String,
    cmd: Vec<String>,
    running: bool,
    exit_code: i32,
}

type SharedState = Arc<RwLock<MockState>>;

// ============================================================================
// Mock API Types (matching Docker API)
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerSummary {
    id: String,
    names: Vec<String>,
    image: String,
    image_id: String,
    command: String,
    created: i64,
    state: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateContainerRequest {
    image: String,
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(default)]
    tty: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct CreateContainerResponse {
    id: String,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct WaitResponse {
    status_code: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExecCreateRequest {
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(default)]
    tty: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ExecCreateResponse {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ExecInspectResponse {
    id: String,
    running: bool,
    exit_code: i32,
    container_id: String,
}

#[derive(Debug, Deserialize)]
struct ListContainersQuery {
    #[serde(default)]
    all: bool,
}

#[derive(Debug, Deserialize)]
struct CreateContainerQuery {
    name: Option<String>,
}

// ============================================================================
// Mock API Handlers
// ============================================================================

async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!("OK"))
}

async fn list_containers(
    State(state): State<SharedState>,
    Query(query): Query<ListContainersQuery>,
) -> Json<Vec<ContainerSummary>> {
    let state = state.read().await;
    let containers: Vec<ContainerSummary> = state
        .containers
        .values()
        .filter(|c| query.all || c.state == "running")
        .map(|c| ContainerSummary {
            id: c.id.clone(),
            names: vec![format!("/{}", c.name)],
            image: c.image.clone(),
            image_id: String::new(),
            command: c.command.clone(),
            created: c.created,
            state: c.state.clone(),
            status: c.status.clone(),
        })
        .collect();
    Json(containers)
}

async fn create_container(
    State(state): State<SharedState>,
    Query(params): Query<CreateContainerQuery>,
    Json(body): Json<CreateContainerRequest>,
) -> (StatusCode, Json<CreateContainerResponse>) {
    let mut state = state.write().await;
    state.next_container_id += 1;
    let id = format!("{:064x}", state.next_container_id);
    let name = params
        .name
        .unwrap_or_else(|| format!("container_{}", state.next_container_id));

    let container = MockContainer {
        id: id.clone(),
        name: name.clone(),
        image: body.image,
        state: "created".to_string(),
        status: "Created".to_string(),
        command: body.cmd.join(" "),
        created: chrono::Utc::now().timestamp(),
        exit_code: None,
    };

    state.containers.insert(id.clone(), container);

    (
        StatusCode::CREATED,
        Json(CreateContainerResponse {
            id,
            warnings: vec![],
        }),
    )
}

async fn start_container(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> StatusCode {
    let mut state = state.write().await;
    if let Some(container) = state.containers.get_mut(&id) {
        container.state = "running".to_string();
        container.status = "Up 1 second".to_string();
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn stop_container(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> StatusCode {
    let mut state = state.write().await;
    if let Some(container) = state.containers.get_mut(&id) {
        container.state = "exited".to_string();
        container.status = "Exited (0)".to_string();
        container.exit_code = Some(0);
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn remove_container(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> StatusCode {
    let mut state = state.write().await;
    if state.containers.remove(&id).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn wait_container(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<WaitResponse>, StatusCode> {
    let state = state.read().await;
    if let Some(container) = state.containers.get(&id) {
        Ok(Json(WaitResponse {
            status_code: container.exit_code.unwrap_or(0) as i64,
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn container_logs(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    let state = state.read().await;
    if state.containers.contains_key(&id) {
        // Return mock logs in Docker multiplexed format.
        let log_line = b"Hello from container\n";
        let mut output = vec![1u8, 0, 0, 0]; // stdout stream type
        output.extend_from_slice(&(log_line.len() as u32).to_be_bytes());
        output.extend_from_slice(log_line);

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/vnd.docker.raw-stream")
            .body(Body::from(output))
            .unwrap())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn exec_create(
    State(state): State<SharedState>,
    Path(container_id): Path<String>,
    Json(body): Json<ExecCreateRequest>,
) -> Result<(StatusCode, Json<ExecCreateResponse>), StatusCode> {
    let mut state = state.write().await;
    if !state.containers.contains_key(&container_id) {
        return Err(StatusCode::NOT_FOUND);
    }

    state.next_exec_id += 1;
    let exec_id = format!("exec_{:016x}", state.next_exec_id);

    let exec = MockExec {
        id: exec_id.clone(),
        container_id,
        cmd: body.cmd,
        running: false,
        exit_code: 0,
    };

    state.execs.insert(exec_id.clone(), exec);

    Ok((
        StatusCode::CREATED,
        Json(ExecCreateResponse { id: exec_id }),
    ))
}

async fn exec_start(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    let mut state = state.write().await;
    if let Some(exec) = state.execs.get_mut(&id) {
        exec.running = false;
        exec.exit_code = 0;

        // Return mock output.
        let output = b"exec output\n";
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/vnd.docker.raw-stream")
            .body(Body::from(output.to_vec()))
            .unwrap())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn exec_inspect(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<ExecInspectResponse>, StatusCode> {
    let state = state.read().await;
    if let Some(exec) = state.execs.get(&id) {
        Ok(Json(ExecInspectResponse {
            id: exec.id.clone(),
            running: exec.running,
            exit_code: exec.exit_code,
            container_id: exec.container_id.clone(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// ============================================================================
// Mock Server Setup
// ============================================================================

/// Creates a mock Docker API router.
fn create_mock_router(state: SharedState) -> Router {
    Router::new()
        // System endpoints
        .route("/_ping", get(ping))
        .route("/v1.43/_ping", get(ping))
        // Container endpoints
        .route("/v1.43/containers/json", get(list_containers))
        .route("/v1.43/containers/create", post(create_container))
        .route("/v1.43/containers/:id/start", post(start_container))
        .route("/v1.43/containers/:id/stop", post(stop_container))
        .route("/v1.43/containers/:id/wait", post(wait_container))
        .route("/v1.43/containers/:id/logs", get(container_logs))
        .route("/v1.43/containers/:id", delete(remove_container))
        // Exec endpoints
        .route("/v1.43/containers/:id/exec", post(exec_create))
        .route("/v1.43/exec/:id/start", post(exec_start))
        .route("/v1.43/exec/:id/json", get(exec_inspect))
        .with_state(state)
}

/// Starts a mock server on a Unix socket.
async fn start_mock_server(socket_path: PathBuf) -> SharedState {
    let state = Arc::new(RwLock::new(MockState::default()));
    let router = create_mock_router(Arc::clone(&state));

    // Remove socket if it exists.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).expect("Failed to bind Unix socket");

    // Spawn server task.
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let router = router.clone();
                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(stream);
                        // Use hyper_util's TowerToHyperService to adapt axum Router.
                        let service =
                            hyper_util::service::TowerToHyperService::new(router);
                        if let Err(e) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                        {
                            eprintln!("Server connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Accept error: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for server to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    state
}

// ============================================================================
// Integration Tests
// ============================================================================

mod client_tests {
    use super::*;
    use arcbox_cli::client::DaemonClient;

    #[tokio::test]
    async fn test_client_ping() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("arcbox.sock");

        let _state = start_mock_server(socket_path.clone()).await;

        let client = DaemonClient::with_socket(&socket_path);
        assert!(client.is_running().await);
    }

    #[tokio::test]
    async fn test_client_list_containers_empty() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("arcbox.sock");

        let _state = start_mock_server(socket_path.clone()).await;

        let client = DaemonClient::with_socket(&socket_path);
        let containers: Vec<serde_json::Value> =
            client.get("/v1.43/containers/json?all=true").await.unwrap();
        assert!(containers.is_empty());
    }

    #[tokio::test]
    async fn test_client_create_and_list_container() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("arcbox.sock");

        let _state = start_mock_server(socket_path.clone()).await;

        let client = DaemonClient::with_socket(&socket_path);

        // Create container.
        let create_req = serde_json::json!({
            "Image": "alpine:latest",
            "Cmd": ["echo", "hello"]
        });
        let response: serde_json::Value = client
            .post("/v1.43/containers/create?name=test-container", Some(&create_req))
            .await
            .unwrap();

        let container_id = response["Id"].as_str().unwrap();
        assert!(!container_id.is_empty());

        // List containers.
        let containers: Vec<serde_json::Value> =
            client.get("/v1.43/containers/json?all=true").await.unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0]["Image"], "alpine:latest");
    }

    #[tokio::test]
    async fn test_client_container_lifecycle() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("arcbox.sock");

        let _state = start_mock_server(socket_path.clone()).await;

        let client = DaemonClient::with_socket(&socket_path);

        // Create.
        let create_req = serde_json::json!({
            "Image": "nginx:latest"
        });
        let response: serde_json::Value = client
            .post("/v1.43/containers/create", Some(&create_req))
            .await
            .unwrap();
        let container_id = response["Id"].as_str().unwrap().to_string();

        // Start.
        client
            .post_empty::<()>(&format!("/v1.43/containers/{}/start", container_id), None)
            .await
            .unwrap();

        // Verify running.
        let containers: Vec<serde_json::Value> =
            client.get("/v1.43/containers/json").await.unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0]["State"], "running");

        // Stop.
        client
            .post_empty::<()>(&format!("/v1.43/containers/{}/stop", container_id), None)
            .await
            .unwrap();

        // Verify stopped (not shown in default list).
        let containers: Vec<serde_json::Value> =
            client.get("/v1.43/containers/json").await.unwrap();
        assert!(containers.is_empty());

        // Remove.
        client
            .delete(&format!("/v1.43/containers/{}", container_id))
            .await
            .unwrap();

        // Verify removed.
        let containers: Vec<serde_json::Value> =
            client.get("/v1.43/containers/json?all=true").await.unwrap();
        assert!(containers.is_empty());
    }

    #[tokio::test]
    async fn test_client_container_logs() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("arcbox.sock");

        let _state = start_mock_server(socket_path.clone()).await;

        let client = DaemonClient::with_socket(&socket_path);

        // Create and start container.
        let create_req = serde_json::json!({
            "Image": "alpine:latest"
        });
        let response: serde_json::Value = client
            .post("/v1.43/containers/create", Some(&create_req))
            .await
            .unwrap();
        let container_id = response["Id"].as_str().unwrap().to_string();

        client
            .post_empty::<()>(&format!("/v1.43/containers/{}/start", container_id), None)
            .await
            .unwrap();

        // Get logs.
        let logs = client
            .get_raw(&format!(
                "/v1.43/containers/{}/logs?stdout=true&stderr=true",
                container_id
            ))
            .await
            .unwrap();

        // Logs should contain the mock output.
        assert!(!logs.is_empty());
        // First 8 bytes are header, rest is content.
        if logs.len() > 8 {
            let content = String::from_utf8_lossy(&logs[8..]);
            assert!(content.contains("Hello from container"));
        }
    }

    #[tokio::test]
    async fn test_client_exec() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("arcbox.sock");

        let _state = start_mock_server(socket_path.clone()).await;

        let client = DaemonClient::with_socket(&socket_path);

        // Create and start container.
        let create_req = serde_json::json!({
            "Image": "alpine:latest"
        });
        let response: serde_json::Value = client
            .post("/v1.43/containers/create", Some(&create_req))
            .await
            .unwrap();
        let container_id = response["Id"].as_str().unwrap().to_string();

        client
            .post_empty::<()>(&format!("/v1.43/containers/{}/start", container_id), None)
            .await
            .unwrap();

        // Create exec.
        let exec_req = serde_json::json!({
            "Cmd": ["ls", "-la"],
            "AttachStdout": true,
            "AttachStderr": true
        });
        let response: serde_json::Value = client
            .post(
                &format!("/v1.43/containers/{}/exec", container_id),
                Some(&exec_req),
            )
            .await
            .unwrap();
        let exec_id = response["Id"].as_str().unwrap().to_string();

        // Start exec.
        let start_req = serde_json::json!({
            "Detach": false,
            "Tty": false
        });
        let output = client
            .post_raw(&format!("/v1.43/exec/{}/start", exec_id), Some(&start_req))
            .await
            .unwrap();
        assert!(!output.is_empty());

        // Inspect exec.
        let inspect: serde_json::Value = client
            .get(&format!("/v1.43/exec/{}/json", exec_id))
            .await
            .unwrap();
        assert_eq!(inspect["ExitCode"], 0);
        assert_eq!(inspect["Running"], false);
    }

    #[tokio::test]
    async fn test_client_wait_container() {
        let tmp_dir = TempDir::new().unwrap();
        let socket_path = tmp_dir.path().join("arcbox.sock");

        let _state = start_mock_server(socket_path.clone()).await;

        let client = DaemonClient::with_socket(&socket_path);

        // Create container.
        let create_req = serde_json::json!({
            "Image": "alpine:latest"
        });
        let response: serde_json::Value = client
            .post("/v1.43/containers/create", Some(&create_req))
            .await
            .unwrap();
        let container_id = response["Id"].as_str().unwrap().to_string();

        // Wait for container.
        let wait_response: serde_json::Value = client
            .post(
                &format!("/v1.43/containers/{}/wait", container_id),
                None::<()>,
            )
            .await
            .unwrap();

        assert_eq!(wait_response["StatusCode"], 0);
    }

    #[tokio::test]
    async fn test_client_connection_failure() {
        let client = DaemonClient::with_socket("/nonexistent/socket.sock");
        assert!(!client.is_running().await);
    }
}

mod helper_tests {
    use arcbox_cli::client::{short_id, truncate, relative_time};

    #[test]
    fn test_short_id() {
        assert_eq!(short_id("abc123def456789"), "abc123def456");
        assert_eq!(short_id("short"), "short");
        assert_eq!(
            short_id("sha256:abc123def456789"),
            "sha256:abc12" // still 12 chars from start
        );
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello world", 20), "hello world");
        assert_eq!(truncate("hello world this is a long string", 15), "hello world ...");
        assert_eq!(truncate("hi", 10), "hi");
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn test_relative_time() {
        let now = chrono::Utc::now().timestamp();

        // Just now.
        let result = relative_time(now - 5);
        assert!(result.contains("seconds"));

        // Minutes ago.
        let result = relative_time(now - 300);
        assert!(result.contains("minutes"));

        // Hours ago.
        let result = relative_time(now - 7200);
        assert!(result.contains("hours"));

        // Days ago.
        let result = relative_time(now - 172800);
        assert!(result.contains("days"));
    }
}

mod cli_parsing_tests {
    use std::process::Command;

    /// Helper to run arcbox CLI with arguments.
    fn arcbox_cmd() -> Command {
        Command::new(env!("CARGO_BIN_EXE_arcbox"))
    }

    #[test]
    fn test_cli_help() {
        let output = arcbox_cmd().arg("--help").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("ArcBox"));
    }

    #[test]
    fn test_cli_version() {
        let output = arcbox_cmd().arg("version").output().unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn test_cli_ps_help() {
        let output = arcbox_cmd().args(["ps", "--help"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("containers"));
    }

    #[test]
    fn test_cli_run_help() {
        let output = arcbox_cmd().args(["run", "--help"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Image"));
        assert!(stdout.contains("--detach"));
        assert!(stdout.contains("--tty"));
    }

    #[test]
    fn test_cli_exec_help() {
        let output = arcbox_cmd().args(["exec", "--help"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Container"));
        assert!(stdout.contains("--tty"));
        assert!(stdout.contains("--interactive"));
    }

    #[test]
    fn test_cli_logs_help() {
        let output = arcbox_cmd().args(["logs", "--help"]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--follow"));
        assert!(stdout.contains("--tail"));
    }
}
