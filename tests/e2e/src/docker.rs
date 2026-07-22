//! Docker CLI helpers for daemon-level scenarios.
//!
//! Every daemon under test exposes its own Docker socket under
//! `<data_dir>/run/docker.sock`. These helpers always target that socket
//! via `DOCKER_HOST`, so the developer's Docker context and any host
//! daemon stay untouched (see tests/e2e/README.md on isolation).

use std::io::Read as _;
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

/// A long-lived `docker <args>` child (an `/events` subscription, a log
/// follow) held open across a scenario, mimicking a persistent observer
/// like the desktop UI. Killed on drop.
pub struct DockerStream {
    child: std::process::Child,
    args: String,
}

/// Spawns `docker <args>` against the daemon under `data_dir` and leaves it
/// running. Output is discarded — callers assert on daemon behavior, not on
/// the stream's content.
pub fn docker_stream(data_dir: &Path, args: &[&str]) -> Result<DockerStream> {
    let child = Command::new("docker")
        .env("DOCKER_HOST", docker_host(data_dir))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning docker {}", args.join(" ")))?;
    Ok(DockerStream {
        child,
        args: args.join(" "),
    })
}

impl DockerStream {
    /// Fails if the stream exited: a dead subscriber would silently weaken
    /// any scenario using it as a persistent-observer regression guard.
    pub fn assert_alive(&mut self) -> Result<()> {
        match self.child.try_wait()? {
            None => Ok(()),
            Some(status) => bail!("docker {} exited early with {status}", self.args),
        }
    }
}

impl Drop for DockerStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Best-effort `docker <args>` for cleanup paths; failures are ignored.
pub fn docker_ignore(data_dir: &Path, args: &[String]) {
    let _ = Command::new("docker")
        .env("DOCKER_HOST", docker_host(data_dir))
        .args(args)
        .status();
}

/// Makes `image` available in the daemon under test.
///
/// Avoids depending on registry reachability more than once per machine:
/// the first successful pull is cached as a tarball under `target/`, and
/// later runs `docker load` it (guest registry access is
/// environment-dependent; pulls here have been observed to black-hole
/// intermittently).
pub fn ensure_image(data_dir: &Path, image: &str) -> Result<()> {
    let cache_dir = crate::repo_root().join("target/e2e-image-cache");
    let tar = cache_dir.join(format!(
        "{}.tar",
        image.replace(['/', ':'], "_").replace('.', "-")
    ));
    if tar.exists() {
        docker_output(
            data_dir,
            &["load", "-i", &tar.display().to_string()],
            Duration::from_secs(60),
        )
        .context("docker load from cache")?;
        return Ok(());
    }

    let mut last_err = None;
    for attempt in 1..=3 {
        match docker_output(data_dir, &["pull", image], Duration::from_secs(90)) {
            Ok(_) => {
                std::fs::create_dir_all(&cache_dir)?;
                docker_output(
                    data_dir,
                    &["save", "-o", &tar.display().to_string(), image],
                    Duration::from_secs(60),
                )
                .context("docker save to cache")?;
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(attempt, "docker pull failed: {e:#}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("loop ran at least once")).context("docker pull (3 attempts)")
}

/// Runs a command, killing it once `timeout` passes.
///
/// Both pipes are drained on background threads for the whole run: an
/// undrained pipe fills at ~64 KiB and blocks the child, which turns any
/// chatty command (a `--progress=plain` build, a large pull) into a bogus
/// timeout. On a real timeout the error carries the output tail, so a
/// killed command still leaves forensics.
pub fn run_with_timeout(command: &mut Command, timeout: Duration) -> Result<std::process::Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let drain = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buf);
            }
            buf
        })
    };
    let stdout_thread = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
    );
    let stderr_thread = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
    );

    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();
            return Ok(std::process::Output {
                status,
                stdout,
                stderr,
            });
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    let _ = child.wait();
    // Killing the child EOFs the pipes, so the drain threads finish.
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    let mut tail_start = combined.len().saturating_sub(2000);
    while !combined.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    Err(anyhow!(
        "command timed out after {}s; output tail:\n{}",
        timeout.as_secs(),
        &combined[tail_start..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command whose output exceeds the OS pipe buffer must complete: an
    /// undrained pipe blocks the child at ~64 KiB and the old implementation
    /// turned every chatty command into a bogus timeout (caught by the
    /// docker_build D9 streaming scenario).
    #[test]
    fn chatty_command_is_drained_not_deadlocked() {
        let output = run_with_timeout(
            Command::new("sh").args([
                "-c",
                "dd if=/dev/zero bs=1024 count=256 2>/dev/null | base64",
            ]),
            Duration::from_secs(20),
        )
        .expect("chatty command must not time out");
        assert!(output.status.success());
        assert!(output.stdout.len() > 64 * 1024);
    }

    /// A genuine timeout must surface the output tail for forensics.
    #[test]
    fn timeout_error_carries_output_tail() {
        let error = run_with_timeout(
            Command::new("sh").args(["-c", "echo tail-marker; sleep 30"]),
            Duration::from_secs(1),
        )
        .expect_err("command must time out");
        assert!(error.to_string().contains("tail-marker"));
    }
}
