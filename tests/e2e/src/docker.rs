//! Docker CLI helpers for daemon-level scenarios.
//!
//! Every daemon under test exposes its own Docker socket under
//! `<data_dir>/run/docker.sock`. These helpers always target that socket
//! via `DOCKER_HOST`, so the developer's Docker context and any host
//! daemon stay untouched (see tests/e2e/README.md on isolation).

use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

/// `DOCKER_HOST` value addressing the daemon's per-data-dir socket.
#[must_use]
pub fn docker_host(data_dir: &Path) -> String {
    // Default HostLayout: the Docker socket lives under <data_dir>/run.
    format!("unix://{}", data_dir.join("run/docker.sock").display())
}

/// Runs `docker <args>` against the daemon under `data_dir`, returning
/// combined stdout+stderr. Fails on non-zero exit or after `timeout`.
pub fn docker_output(data_dir: &Path, args: &[&str], timeout: Duration) -> Result<String> {
    let output = run_with_timeout(
        Command::new("docker")
            .env("DOCKER_HOST", docker_host(data_dir))
            .args(args),
        timeout,
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Ok(format!("{stdout}{stderr}"))
    } else {
        bail!(
            "docker {} failed with {}\n{}{}",
            args.join(" "),
            output.status,
            stdout,
            stderr
        );
    }
}

/// Best-effort `docker <args>` for cleanup paths; failures are ignored.
pub fn docker_ignore(data_dir: &Path, args: &[String]) {
    let _ = Command::new("docker")
        .env("DOCKER_HOST", docker_host(data_dir))
        .args(args)
        .status();
}

/// Runs a command, killing it once `timeout` passes.
pub fn run_with_timeout(command: &mut Command, timeout: Duration) -> Result<std::process::Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    while start.elapsed() < timeout {
        if child.try_wait()?.is_some() {
            return child
                .wait_with_output()
                .context("collecting command output");
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    let _ = child.wait();
    Err(anyhow!("command timed out after {}s", timeout.as_secs()))
}
