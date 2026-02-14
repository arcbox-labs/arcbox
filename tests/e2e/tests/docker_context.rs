//! Docker context integration test using the Docker CLI.
//!
//! Verifies that `arcbox docker enable` wires the Docker CLI to the ArcBox
//! daemon and that core commands (ps/run/exec/logs/events) work.

use anyhow::{Context, Result, bail};
use arcbox_e2e::fixtures::{TestFixtures, images};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serial_test::serial;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const DOCKER_API_VERSION: &str = "1.43";

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

fn docker_cli_available() -> bool {
    Command::new("docker")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

struct DaemonGuard {
    child: Option<Child>,
}

impl DaemonGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let pid = child.id() as i32;
            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            let _ = child.wait();
        }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn wait_for_socket(path: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while !path.exists() {
        if start.elapsed() > timeout {
            bail!("timeout waiting for socket: {}", path.display());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

fn run_arcbox(arcbox: &Path, home: &Path, args: &[&str]) -> Result<Output> {
    Command::new(arcbox)
        .args(args)
        .env("HOME", home)
        .output()
        .context("failed to run arcbox command")
}

fn run_arcbox_success(arcbox: &Path, home: &Path, args: &[&str]) -> Result<String> {
    let output = run_arcbox(arcbox, home, args)?;
    if !output.status.success() {
        bail!(
            "arcbox {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_docker(home: &Path, args: &[&str]) -> Result<Output> {
    Command::new("docker")
        .args(args)
        .env("HOME", home)
        .env("DOCKER_CONFIG", home.join(".docker"))
        .env("DOCKER_API_VERSION", DOCKER_API_VERSION)
        .output()
        .context("failed to run docker command")
}

fn run_docker_success(home: &Path, args: &[&str]) -> Result<String> {
    let output = run_docker(home, args)?;
    if !output.status.success() {
        bail!(
            "docker {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tokio::test]
#[ignore = "requires VM resources, Docker CLI, and network access"]
#[serial]
async fn test_docker_context_cli_smoke() -> Result<()> {
    if skip_if_missing_resources() {
        return Ok(());
    }
    if !docker_cli_available() {
        eprintln!("Skipping test: docker CLI not available");
        return Ok(());
    }

    let fixtures = TestFixtures::new();
    let home_dir = TempDir::new().context("failed to create temp HOME")?;
    let home = home_dir.path();
    let data_dir = home.join(".arcbox");
    std::fs::create_dir_all(&data_dir).context("failed to create data dir")?;

    let socket_path = data_dir.join("docker.sock");
    let grpc_socket_path = data_dir.join("arcbox-grpc.sock");

    let mut daemon_cmd = Command::new(fixtures.arcbox_binary());
    daemon_cmd
        .arg("daemon")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--grpc-socket")
        .arg(&grpc_socket_path)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--kernel")
        .arg(fixtures.kernel_path())
        .arg("--initramfs")
        .arg(fixtures.initramfs_path())
        .env("HOME", home)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = daemon_cmd.spawn().context("failed to start daemon")?;
    let mut daemon = DaemonGuard::new(child);

    wait_for_socket(&socket_path, Duration::from_secs(15)).await?;

    run_arcbox_success(fixtures.arcbox_binary().as_path(), home, &["docker", "enable"])?;

    let context = run_docker_success(home, &["context", "show"])?;
    assert_eq!(context.trim(), "arcbox", "unexpected docker context");

    run_docker_success(home, &["pull", images::ALPINE])?;

    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock error")?
        .as_secs()
        .saturating_sub(1);
    let until = since + 30;

    let mut events_cmd = Command::new("docker");
    events_cmd
        .arg("events")
        .arg("--format")
        .arg("{{json .}}")
        .arg("--since")
        .arg(since.to_string())
        .arg("--until")
        .arg(until.to_string())
        .arg("--filter")
        .arg("type=network")
        .arg("--filter")
        .arg("type=volume")
        .arg("--filter")
        .arg("type=machine")
        .env("HOME", home)
        .env("DOCKER_CONFIG", home.join(".docker"))
        .env("DOCKER_API_VERSION", DOCKER_API_VERSION)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let events_child = events_cmd.spawn().context("failed to start docker events")?;
    sleep(Duration::from_millis(200)).await;

    let run_output = run_docker_success(home, &["run", "--rm", images::ALPINE, "echo", "ok"])?;
    assert!(run_output.contains("ok"), "unexpected run output");

    let run_name = format!("arcbox-e2e-{}", uuid::Uuid::new_v4().simple());
    let log_cmd = format!("echo log-ok && sleep 60");
    run_docker_success(
        home,
        &[
            "run",
            "-d",
            "--name",
            &run_name,
            images::ALPINE,
            "sh",
            "-c",
            &log_cmd,
        ],
    )?;

    wait_for_log(home, &run_name, "log-ok", Duration::from_secs(10)).await?;

    let exec_output = run_docker_success(home, &["exec", &run_name, "echo", "exec-ok"])?;
    assert!(
        exec_output.contains("exec-ok"),
        "unexpected exec output"
    );

    let logs_output = run_docker_success(home, &["logs", &run_name])?;
    assert!(
        logs_output.contains("log-ok"),
        "unexpected logs output"
    );

    let network_name = format!("arcbox-e2e-net-{}", uuid::Uuid::new_v4().simple());
    let volume_name = format!("arcbox-e2e-vol-{}", uuid::Uuid::new_v4().simple());
    run_docker_success(home, &["network", "create", &network_name])?;
    run_docker_success(home, &["network", "rm", &network_name])?;
    run_docker_success(home, &["volume", "create", &volume_name])?;
    run_docker_success(home, &["volume", "rm", &volume_name])?;

    let _ = run_docker(home, &["rm", "-f", &run_name]);

    let events_output = events_child
        .wait_with_output()
        .context("failed to read docker events output")?;
    if !events_output.status.success() {
        bail!(
            "docker events failed: {}",
            String::from_utf8_lossy(&events_output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&events_output.stdout);
    let mut types = HashSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .context("failed to parse docker event json")?;
        if let Some(event_type) = value.get("Type").and_then(|v| v.as_str()) {
            types.insert(event_type.to_string());
        }
    }

    assert!(
        types.contains("machine"),
        "missing machine events: {}",
        stdout
    );
    assert!(
        types.contains("network"),
        "missing network events: {}",
        stdout
    );
    assert!(
        types.contains("volume"),
        "missing volume events: {}",
        stdout
    );

    daemon.stop();
    Ok(())
}

async fn wait_for_log(
    home: &Path,
    container: &str,
    needle: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let output = run_docker_success(home, &["logs", container])?;
        if output.contains(needle) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timeout waiting for logs: {}", needle);
        }
        sleep(Duration::from_millis(200)).await;
    }
}
