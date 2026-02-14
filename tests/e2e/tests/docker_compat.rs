//! Docker API compatibility tests for exec hijack/attach streams.
//!
//! These tests talk to the Docker-compatible HTTP API over the daemon's Unix
//! socket and verify bidirectional attach for `docker exec`-style flows.

use anyhow::{Context, Result, anyhow};
use arcbox_e2e::TestHarness;
use arcbox_e2e::fixtures::{TestFixtures, images};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1;
use hyper::http::Request;
use hyper::{Response, StatusCode, upgrade};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

const DOCKER_API_VERSION: &str = "/v1.43";
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(data: impl Into<Bytes>) -> BoxBody {
    Full::new(data.into())
        .map_err::<_, hyper::Error>(|never| match never {})
        .boxed()
}

fn empty_body() -> BoxBody {
    Empty::new()
        .map_err::<_, hyper::Error>(|never| match never {})
        .boxed()
}

/// Skip test if resources are not available.
fn skip_if_missing_resources() -> bool {
    let fixtures = TestFixtures::new();
    let check = fixtures.check_resources();

    if !check.all_ready() {
        eprintln!("Skipping test: missing resources: {:?}", check.missing());
        return true;
    }
    false
}

async fn send_unix_request(
    socket: &Path,
    req: Request<BoxBody>,
) -> Result<(Response<Incoming>, tokio::task::JoinHandle<()>)> {
    let stream = tokio::net::UnixStream::connect(socket)
        .await
        .context("failed to connect to daemon socket")?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::Builder::new()
        .handshake(io)
        .await
        .context("handshake failed")?;
    let conn = conn.with_upgrades();

    let conn_task = tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!("docker compat connection error: {}", err);
        }
    });

    let resp = sender
        .send_request(req)
        .await
        .context("failed to send request")?;

    Ok((resp, conn_task))
}

async fn docker_create_container(socket: &Path, image: &str) -> Result<String> {
    let body = json!({
        "Image": image,
        "Cmd": ["sleep", "300"],
        "AttachStdout": true,
        "AttachStderr": true,
        "Tty": false
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!("{}/containers/create", DOCKER_API_VERSION))
        .header("Host", "localhost")
        .header("Content-Type", "application/json")
        .body(full_body(body.to_string()))
        .context("failed to build container create request")?;

    let (resp, conn_task) = send_unix_request(socket, req).await?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .context("failed to read container create response")?
        .to_bytes();
    let _ = conn_task.await;

    if status != StatusCode::CREATED {
        return Err(anyhow!(
            "container create failed ({}): {}",
            status,
            String::from_utf8_lossy(&bytes)
        ));
    }

    let id = serde_json::from_slice::<serde_json::Value>(&bytes)
        .context("decode container create response")?
        .get("Id")
        .and_then(|v| v.as_str())
        .context("missing container Id in response")?
        .to_string();

    Ok(id)
}

async fn docker_start_container(socket: &Path, id: &str) -> Result<()> {
    let req = Request::builder()
        .method("POST")
        .uri(format!("{}/containers/{}/start", DOCKER_API_VERSION, id))
        .header("Host", "localhost")
        .body(empty_body())
        .context("failed to build container start request")?;

    let (resp, conn_task) = send_unix_request(socket, req).await?;
    let status = resp.status();
    let _ = conn_task.await;

    if !(status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED) {
        return Err(anyhow!("container start failed with status {}", status));
    }

    Ok(())
}

async fn docker_create_exec(socket: &Path, container_id: &str) -> Result<String> {
    let body = json!({
        "AttachStdin": false,
        "AttachStdout": true,
        "AttachStderr": true,
        "Tty": true,
        "Cmd": ["sh", "-c", "echo hello-from-e2e"]
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "{}/containers/{}/exec",
            DOCKER_API_VERSION, container_id
        ))
        .header("Host", "localhost")
        .header("Content-Type", "application/json")
        .body(full_body(body.to_string()))
        .context("failed to build exec create request")?;

    let (resp, conn_task) = send_unix_request(socket, req).await?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .context("failed to read exec create response")?
        .to_bytes();
    let _ = conn_task.await;

    if status != StatusCode::CREATED {
        return Err(anyhow!(
            "exec create failed ({}): {}",
            status,
            String::from_utf8_lossy(&bytes)
        ));
    }

    let id = serde_json::from_slice::<serde_json::Value>(&bytes)
        .context("decode exec create response")?
        .get("Id")
        .and_then(|v| v.as_str())
        .context("missing exec Id in response")?
        .to_string();

    Ok(id)
}

async fn docker_exec_hijack_roundtrip(socket: &Path, exec_id: &str) -> Result<Vec<u8>> {
    let req = Request::builder()
        .method("POST")
        .uri(format!("{}/exec/{}/start", DOCKER_API_VERSION, exec_id))
        .header("Host", "localhost")
        .header("Connection", "Upgrade")
        .header("Upgrade", "tcp")
        .header("Content-Type", "application/json")
        .body(full_body(r#"{"Detach":false,"Tty":true}"#))
        .context("failed to build exec start request")?;

    let (mut resp, conn_task) = send_unix_request(socket, req).await?;
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .context("failed to read exec start error")?
            .to_bytes();
        let _ = conn_task.await;
        return Err(anyhow!(
            "exec start did not upgrade ({}): {}",
            status,
            String::from_utf8_lossy(&bytes)
        ));
    }

    let upgraded = upgrade::on(&mut resp)
        .await
        .context("failed to upgrade exec stream")?;

    let mut io = TokioIo::new(upgraded);

    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let mut chunk = [0u8; 4096];
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or_default();
        if remaining.is_zero() {
            anyhow::bail!("timed out waiting for exec output");
        }

        let n = timeout(remaining, io.read(&mut chunk)).await??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(b"hello-from-e2e".len()).any(|w| w == b"hello-from-e2e") {
            break;
        }
    }
    drop(io); // ensure connection closes
    let _ = conn_task.await;

    Ok(buf)
}

#[tokio::test]
#[ignore = "requires VM resources, network for image pulls, and Docker socket access"]
async fn test_docker_exec_hijack_stream_roundtrip() -> Result<()> {
    if skip_if_missing_resources() {
        return Ok(());
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");

    harness
        .setup_full_environment()
        .await
        .expect("failed to setup daemon");

    harness
        .run_command_success(&["pull", images::ALPINE])
        .expect("failed to pull image");

    let container_id = docker_create_container(&harness.socket_path(), images::ALPINE).await?;
    docker_start_container(&harness.socket_path(), &container_id).await?;

    let exec_id = docker_create_exec(&harness.socket_path(), &container_id).await?;
    let output = docker_exec_hijack_roundtrip(&harness.socket_path(), &exec_id).await?;

    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("hello-from-e2e"),
        "expected echoed payload, got: {}",
        output_str
    );

    // Best-effort cleanup; ignore errors to avoid masking test results.
    let _ = harness.run_command(&["rm", "-f", &container_id]);

    Ok(())
}
