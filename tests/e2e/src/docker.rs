//! Docker CLI helpers for daemon-level scenarios.
//!
//! Every daemon under test exposes its own Docker socket under
//! `<data_dir>/run/docker.sock`. These helpers always target that socket
//! via `DOCKER_HOST`, so the developer's Docker context and any host
//! daemon stay untouched (see tests/e2e/README.md on isolation).

use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
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
        // A corrupt cache must not poison every subsequent run (an HV
        // `docker save` can truncate the streamed response — issue #256):
        // discard it and fall through to a fresh pull.
        match docker_output(
            data_dir,
            &["load", "-i", &tar.display().to_string()],
            Duration::from_secs(60),
        ) {
            Ok(_) => return Ok(()),
            Err(e) => {
                tracing::warn!("cached image load failed ({e:#}); discarding cache, re-pulling");
                let _ = std::fs::remove_file(&tar);
            }
        }
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
                // Validate before trusting: a truncated save (#256) only
                // surfaces as "invalid byte in chunk length" on the NEXT
                // run's load — catch it now instead.
                let listing = std::process::Command::new("tar")
                    .args(["-tf", &tar.display().to_string()])
                    .output();
                if !listing.map(|o| o.status.success()).unwrap_or(false) {
                    tracing::warn!("saved image cache fails tar validation; discarding");
                    let _ = std::fs::remove_file(&tar);
                }
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

/// SIGKILLs the process group led by `pgid`, which `process_group(0)` made
/// equal to the spawned child's pid. Safe to call after the leader has been
/// reaped: POSIX forbids reusing a pid while it is still the group id of an
/// existing group, so this either reaches that group or nothing at all
/// (`ESRCH`), never an unrelated one.
fn kill_process_group(pgid: i32) {
    // SAFETY: `killpg` takes no pointers and cannot fail unsoundly; a stale
    // or empty group yields ESRCH, which we ignore.
    unsafe { libc::killpg(pgid, libc::SIGKILL) };
}

/// Runs a command, killing it once `timeout` passes.
///
/// Both pipes are drained on background threads for the whole run: an
/// undrained pipe fills at ~64 KiB and blocks the child, which turns any
/// chatty command (a `--progress=plain` build, a large pull) into a bogus
/// timeout. On a real timeout the error carries the output tail, so a
/// killed command still leaves forensics.
///
/// The child leads its own process group and **both** exit paths signal the
/// whole group before joining. Killing just the direct child is not enough:
/// `docker build` runs the build in a `docker-buildx` grandchild that
/// inherits these pipes, so the write end stays open and the drain-thread
/// joins block past the deadline — indefinitely if that descendant is itself
/// wedged, which is exactly what this suite exists to catch. The same holds
/// when the command *succeeds* while leaving a descendant behind, so the
/// group kill is not conditional on timing out: once the direct child is
/// gone, nothing else may hold pipes this function is about to join on.
pub fn run_with_timeout(command: &mut Command, timeout: Duration) -> Result<std::process::Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;
    // Captured before any reap: `Child::id` is not meaningful afterwards.
    let pgid = i32::try_from(child.id()).expect("pid fits in i32");
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
            kill_process_group(pgid);
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

    kill_process_group(pgid);
    let _ = child.wait();
    // The whole group is gone, so every inherited write end is closed and the
    // drain threads see EOF.
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

    /// The success path has the same hazard as the timeout path: a command
    /// can exit promptly while leaving a descendant holding the inherited
    /// pipes, and the drain-thread joins would then block on that descendant
    /// with no deadline left to enforce. Returns in ~0s once the group is
    /// killed, ~30s if the success branch stops doing so.
    #[test]
    fn success_returns_promptly_despite_surviving_descendant() {
        let start = Instant::now();
        let output = run_with_timeout(
            Command::new("sh").args(["-c", "echo done; sleep 30 & exit 0"]),
            Duration::from_secs(60),
        )
        .expect("command must succeed");
        let elapsed = start.elapsed();
        assert!(output.status.success());
        assert!(
            elapsed < Duration::from_secs(10),
            "success took {elapsed:?}; a descendant outlived the command and \
             held the pipes open"
        );
    }

    /// A genuine timeout must surface the output tail for forensics, and
    /// must return at the deadline even though the shell leaves a `sleep`
    /// descendant holding the inherited pipes. Killing only the direct child
    /// leaves that write end open, so the drain-thread joins block until the
    /// descendant exits — ~30s here, unbounded when the survivor is a wedged
    /// `docker-buildx`, which is the shape this suite hits for real.
    ///
    /// `sleep 30 & wait` is deliberate: with a plain `sleep 30` the shell
    /// `exec`s it as the last command, so there is no grandchild and the bug
    /// hides. Backgrounding forces the shell to stay alive as a real parent.
    /// The elapsed bound is the regression; the tail is the original contract.
    #[test]
    fn timeout_returns_at_deadline_despite_surviving_descendant() {
        let start = Instant::now();
        let error = run_with_timeout(
            Command::new("sh").args(["-c", "echo tail-marker; sleep 30 & wait"]),
            Duration::from_secs(1),
        )
        .expect_err("command must time out");
        let elapsed = start.elapsed();
        assert!(error.to_string().contains("tail-marker"));
        assert!(
            elapsed < Duration::from_secs(10),
            "timeout took {elapsed:?}; the `sleep` descendant outlived the \
             kill and held the pipes open"
        );
    }
}
