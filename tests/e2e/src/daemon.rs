//! Spawns and supervises an `arcbox-daemon` under test.
//!
//! Readiness comes from the daemon's own `WatchSetupStatus` gRPC stream
//! instead of log grepping: the harness connects to the gRPC socket as
//! soon as it appears, then follows the phase progression until READY —
//! failing fast on a FAILED phase or a daemon exit, with the log tail
//! attached to the error.
//!
//! Every handle gets an isolated `--data-dir`, so lock file, sockets, and
//! logs never collide with a developer's `~/.arcbox` daemon and multiple
//! harnesses can run in parallel.

use std::fs::File;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_constants::paths::ArcboxProfile;
use arcbox_grpc::v1::system_service_client::SystemServiceClient;
use arcbox_protocol::v1::{Empty, setup_status};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::Service;
use tracing::info;

use crate::signing::ensure_signed;

/// Interval between liveness / stream polls while waiting for readiness.
const POLL_TICK: Duration = Duration::from_millis(200);
/// Grace period for SIGTERM before falling back to SIGKILL.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// Launch parameters for a daemon under test.
pub struct DaemonConfig {
    /// Path to the `arcbox-daemon` binary; signed in place on spawn when
    /// it lacks the virtualization entitlement.
    pub binary: PathBuf,
    /// Isolated data directory. Lock file, both sockets, and logs live
    /// under it (`run/`, `log/`), per the default `HostLayout`.
    pub data_dir: PathBuf,
    /// Extra CLI arguments appended after `--data-dir`.
    pub args: Vec<String>,
    /// Extra environment variables for the daemon process.
    pub env: Vec<(String, String)>,
}

/// When each setup phase was first observed on the readiness stream,
/// relative to the start of [`DaemonHandle::wait_ready`].
///
/// Only the FIRST sighting of a phase is kept: the daemon republishes the
/// current phase to every new subscriber and may re-send one unchanged, and
/// a span should measure when a stage began, not when it was last echoed.
///
/// A phase the daemon had already left before the harness subscribed is
/// never observed, so every lookup is fallible — callers must treat a
/// missing mark as "unknown", never as zero.
#[derive(Debug, Default)]
pub struct PhaseMarks {
    marks: Vec<(setup_status::Phase, Duration)>,
}

impl PhaseMarks {
    fn mark(&mut self, phase: setup_status::Phase, elapsed: Duration) {
        if self.marks.iter().any(|(seen, _)| *seen == phase) {
            return;
        }
        self.marks.push((phase, elapsed));
    }

    /// When `phase` was first observed, if it was.
    #[must_use]
    pub fn at(&self, phase: setup_status::Phase) -> Option<Duration> {
        self.marks
            .iter()
            .find(|(seen, _)| *seen == phase)
            .map(|(_, at)| *at)
    }

    /// Elapsed time between two observed phases.
    ///
    /// `None` when either was missed, or when `to` was seen before `from` —
    /// an out-of-order pair is a caller error, and a saturating zero would
    /// read as a suspiciously fast stage.
    #[must_use]
    pub fn span(&self, from: setup_status::Phase, to: setup_status::Phase) -> Option<Duration> {
        self.at(to)?.checked_sub(self.at(from)?)
    }

    /// Observed phases in sighting order, as `(name, elapsed)` — suitable
    /// for recording into `metrics.json`.
    pub fn timeline(&self) -> impl Iterator<Item = (&'static str, Duration)> + '_ {
        self.marks.iter().map(|(p, at)| (p.as_str_name(), *at))
    }
}

/// A running daemon owned by the harness. Dropping the handle terminates
/// the daemon (SIGTERM, then SIGKILL after a grace period).
pub struct DaemonHandle {
    child: Child,
    data_dir: PathBuf,
    log_path: PathBuf,
    phase_marks: PhaseMarks,
}

impl DaemonHandle {
    /// Signs the binary if needed and spawns it with an isolated
    /// `--data-dir` and `--foreground`, capturing stdout/stderr to
    /// `harness-daemon.log` inside the data directory.
    pub fn spawn(config: DaemonConfig) -> Result<Self> {
        assert_isolated(&config.data_dir)?;
        ensure_signed(&config.binary)?;
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("creating {}", config.data_dir.display()))?;

        // Separate from the daemon's own rotating log/daemon.log: this file
        // captures the process's stdout/stderr (panics, early failures that
        // precede logging init).
        let log_path = config.data_dir.join("harness-daemon.log");
        let log =
            File::create(&log_path).with_context(|| format!("creating {}", log_path.display()))?;
        let stderr = log.try_clone()?;

        let mut command = Command::new(&config.binary);
        command
            .arg("--data-dir")
            .arg(&config.data_dir)
            .arg("--foreground")
            // Keep the guest-data NFS mount off the shared ~/ArcBox by pointing
            // it inside the isolated data dir. A caller can override via env.
            .env("ARCBOX_HOST_MOUNT_DIR", config.data_dir.join("ArcBox"))
            .args(&config.args)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr));
        // The DNS service binds a fixed localhost port (5553 by default) —
        // the one host-global a test daemon would still fight an installed
        // ArcBox (or a sibling test) over. Give each daemon its own port
        // unless the scenario pinned one.
        if !config.env.iter().any(|(key, _)| key == "ARCBOX_DNS_PORT") {
            command.env("ARCBOX_DNS_PORT", ephemeral_udp_port()?.to_string());
        }
        for (key, value) in &config.env {
            command.env(key, value);
        }

        let child = command
            .spawn()
            .with_context(|| format!("spawning arcbox-daemon from {}", config.binary.display()))?;
        info!(pid = child.id(), data_dir = %config.data_dir.display(), "daemon spawned");

        Ok(Self {
            child,
            data_dir: config.data_dir,
            log_path,
            phase_marks: PhaseMarks::default(),
        })
    }

    /// Setup-phase timings observed during [`Self::wait_ready`].
    ///
    /// Empty before a readiness wait. The span most callers want is
    /// `VmStarting → VmReady`: guest binaries are already staged when the
    /// daemon publishes `VmStarting`, and the guest agent has answered by
    /// `VmReady`, so it isolates the guest boot itself (CORE-67).
    #[must_use]
    pub fn phase_marks(&self) -> &PhaseMarks {
        &self.phase_marks
    }

    /// The daemon's process ID (for external diagnostics such as `sample`).
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The Docker API socket under the handle's data directory.
    pub fn docker_socket(&self) -> PathBuf {
        self.data_dir.join("run/docker.sock")
    }

    /// The gRPC API socket under the handle's data directory.
    pub fn grpc_socket(&self) -> PathBuf {
        self.data_dir.join("run/arcbox.sock")
    }

    /// Blocking wrapper around [`Self::wait_ready`] for synchronous tests.
    pub fn wait_ready_blocking(&mut self, timeout: Duration) -> Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building tokio runtime for readiness wait")?
            .block_on(self.wait_ready(timeout))
    }

    /// Follows `WatchSetupStatus` until the daemon reports READY.
    ///
    /// Fails fast when the daemon publishes FAILED (with the reported
    /// error), exits (with its status and log tail), or `timeout` passes.
    pub async fn wait_ready(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let socket = self.grpc_socket();

        // First the socket must appear and accept a connection; the gRPC
        // server starts early in the daemon's startup sequence.
        let channel = loop {
            self.check_alive()?;
            if Instant::now() >= deadline {
                bail!(
                    "timed out after {timeout:?} waiting for gRPC socket {} (log: {})",
                    socket.display(),
                    self.log_path.display()
                );
            }
            if socket.exists() {
                if let Ok(channel) = connect_unix(&socket).await {
                    break channel;
                }
            }
            tokio::time::sleep(POLL_TICK).await;
        };

        let mut client = SystemServiceClient::new(channel);
        let mut stream = client
            .watch_setup_status(Empty {})
            .await
            .context("opening WatchSetupStatus stream")?
            .into_inner();

        // Phase marks are relative to the subscription, not to spawn: the
        // socket-wait above is unmeasured, so an absolute "time since
        // spawn" would silently fold it in. Spans between two observed
        // phases are unaffected by the offset.
        let stream_start = Instant::now();
        self.phase_marks = PhaseMarks::default();

        loop {
            self.check_alive()?;
            if Instant::now() >= deadline {
                bail!(
                    "timed out after {timeout:?} waiting for READY (log: {})",
                    self.log_path.display()
                );
            }
            match tokio::time::timeout(POLL_TICK, stream.message()).await {
                // Poll tick elapsed without an update: re-check liveness.
                Err(_) => {}
                Ok(Ok(Some(status))) => {
                    let phase = status.phase();
                    self.phase_marks.mark(phase, stream_start.elapsed());
                    match phase {
                        setup_status::Phase::Ready => {
                            info!("daemon reported READY");
                            return Ok(());
                        }
                        setup_status::Phase::Failed => {
                            bail!(
                                "daemon startup failed: {} (log: {})",
                                status.error,
                                self.log_path.display()
                            );
                        }
                        phase => info!(?phase, message = %status.message, "setup phase"),
                    }
                }
                // Stream ended or errored — the daemon is going away; the
                // next liveness check reports its exit status and log tail.
                Ok(Ok(None) | Err(_)) => {
                    tokio::time::sleep(POLL_TICK).await;
                }
            }
        }
    }

    /// Terminates the daemon: SIGTERM, wait for the grace period, then
    /// SIGKILL. Returns the exit status.
    pub fn shutdown(mut self) -> Result<ExitStatus> {
        self.terminate()
    }

    /// Fetches the daemon's virtio queue debug snapshot and writes it to
    /// `virtio-debug.json` under the data dir. Meant for failure paths:
    /// one structured record per device (kicks, interrupts, live ring
    /// indices) instead of log archaeology. Empty device list under VZ.
    pub fn dump_virtio_debug(&self) -> Result<PathBuf> {
        let socket = self.grpc_socket();
        let info = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building tokio runtime for virtio debug dump")?
            .block_on(async {
                let channel = connect_unix(&socket).await?;
                let mut client = SystemServiceClient::new(channel);
                anyhow::Ok(client.get_virtio_debug(Empty {}).await?.into_inner())
            })?;
        let path = self.data_dir.join("virtio-debug.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&info)?)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }

    /// Errors with the exit status and log tail if the daemon has exited.
    fn check_alive(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait().context("polling daemon")? {
            bail!(
                "arcbox-daemon exited with {status} before becoming ready\n--- log tail ({}) ---\n{}",
                self.log_path.display(),
                self.log_tail(40)
            );
        }
        Ok(())
    }

    /// Last `lines` lines of the captured daemon output.
    fn log_tail(&self, lines: usize) -> String {
        let Ok(contents) = std::fs::read_to_string(&self.log_path) else {
            return String::from("<log unreadable>");
        };
        let all: Vec<&str> = contents.lines().collect();
        let start = all.len().saturating_sub(lines);
        all[start..].join("\n")
    }

    fn terminate(&mut self) -> Result<ExitStatus> {
        if let Some(status) = self.child.try_wait()? {
            return Ok(status);
        }
        // SAFETY: the pid belongs to a child we own; SIGTERM to a dead pid
        // is harmless (kill(2) returns ESRCH).
        unsafe { libc::kill(self.child.id().cast_signed(), libc::SIGTERM) };

        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        tracing::warn!("daemon ignored SIGTERM for {SHUTDOWN_GRACE:?}; killing");
        let _ = self.child.kill();
        Ok(self.child.wait()?)
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

/// Rejects a data dir that is (or lives inside) a real profile root
/// (`~/.arcbox`, `~/.arcbox-dev`).
///
/// A daemon under test pointed there would contend with the developer's
/// own daemon for the flock, sockets, and machine state. Every harness
/// daemon gets its own throwaway data dir — one data dir per daemon is
/// what makes parallel fixes independent (see tests/e2e/README.md).
fn assert_isolated(data_dir: &Path) -> Result<()> {
    // Resolve symlinks where possible so `~/.arcbox` aliases are caught
    // too; fall back to the literal path when it does not exist yet.
    let resolved = data_dir.canonicalize().unwrap_or_else(|_| {
        data_dir
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .and_then(|p| data_dir.file_name().map(|n| p.join(n)))
            .unwrap_or_else(|| data_dir.to_path_buf())
    });
    for profile in [ArcboxProfile::Production, ArcboxProfile::Development] {
        let root = profile.default_data_dir();
        // A profile root that is itself a symlink (e.g. ~/.arcbox →
        // another volume) must match by its canonical form too, or a
        // data dir given via the symlink target would slip through.
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        if resolved.starts_with(&root) || resolved.starts_with(&canonical_root) {
            bail!(
                "refusing to run a daemon under test in {} — it is inside the default \
                 {profile} data dir {} and would clobber a real daemon's state; \
                 use an isolated per-test data dir (e.g. a tempdir)",
                data_dir.display(),
                root.display()
            );
        }
    }
    Ok(())
}

/// Connects a tonic channel over a Unix domain socket.
pub async fn connect_unix(socket: &Path) -> Result<Channel> {
    // The URI is required by the HTTP/2 layer but unused: the connector
    // below ignores it and dials the Unix socket.
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(UnixConnector {
            socket_path: socket.to_path_buf(),
        })
        .await?;
    Ok(channel)
}

/// Minimal tower connector dialing a fixed Unix socket (same shape as the
/// CLI's connector in `arcbox-cli`).
struct UnixConnector {
    socket_path: PathBuf,
}

impl Service<Uri> for UnixConnector {
    type Response = TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let socket_path = self.socket_path.clone();
        Box::pin(async move {
            let stream = UnixStream::connect(socket_path).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

/// Reserves an OS-assigned localhost UDP port and releases it for the
/// daemon's DNS service to claim. Racy in principle; in practice ephemeral
/// ports don't collide within the spawn window.
fn ephemeral_udp_port() -> Result<u16> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").context("probing for a free UDP port")?;
    Ok(socket.local_addr()?.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_roots_are_rejected() {
        for profile in [ArcboxProfile::Production, ArcboxProfile::Development] {
            let root = profile.default_data_dir();
            assert!(assert_isolated(&root).is_err(), "{}", root.display());
            assert!(assert_isolated(&root.join("nested/dir")).is_err());
        }
    }

    #[test]
    fn tempdirs_are_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_isolated(dir.path()).expect("tempdir must be accepted");
        // Not-yet-created children are fine too — spawn creates them.
        assert_isolated(&dir.path().join("does-not-exist-yet")).expect("child of tempdir");
    }

    /// A republished phase must not move its mark: the daemon re-sends the
    /// current phase to every subscriber, and a span has to measure when a
    /// stage began, not when it was last echoed.
    #[test]
    fn phase_marks_keep_the_first_sighting() {
        let mut marks = PhaseMarks::default();
        marks.mark(setup_status::Phase::AssetsReady, Duration::from_secs(1));
        marks.mark(setup_status::Phase::AssetsReady, Duration::from_secs(9));
        assert_eq!(
            marks.at(setup_status::Phase::AssetsReady),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn phase_span_measures_between_sightings() {
        let mut marks = PhaseMarks::default();
        marks.mark(setup_status::Phase::AssetsReady, Duration::from_secs(2));
        marks.mark(setup_status::Phase::Ready, Duration::from_secs(5));
        assert_eq!(
            marks.span(setup_status::Phase::AssetsReady, setup_status::Phase::Ready),
            Some(Duration::from_secs(3))
        );
    }

    /// An unobserved phase yields `None`, never zero — the harness
    /// subscribes after the socket appears, so an early phase can be missed
    /// entirely, and a zero would read as an implausibly fast stage.
    #[test]
    fn phase_span_is_none_when_a_mark_was_missed() {
        let mut marks = PhaseMarks::default();
        marks.mark(setup_status::Phase::Ready, Duration::from_secs(5));
        assert_eq!(
            marks.span(setup_status::Phase::AssetsReady, setup_status::Phase::Ready),
            None
        );
        assert_eq!(marks.at(setup_status::Phase::AssetsReady), None);
    }

    /// Out-of-order pairs are a caller error; saturating to zero would hide
    /// it behind a plausible-looking number.
    #[test]
    fn phase_span_is_none_when_reversed() {
        let mut marks = PhaseMarks::default();
        marks.mark(setup_status::Phase::AssetsReady, Duration::from_secs(2));
        marks.mark(setup_status::Phase::Ready, Duration::from_secs(5));
        assert_eq!(
            marks.span(setup_status::Phase::Ready, setup_status::Phase::AssetsReady),
            None
        );
    }

    #[test]
    fn timeline_reports_sighting_order_with_names() {
        let mut marks = PhaseMarks::default();
        marks.mark(setup_status::Phase::Initializing, Duration::from_millis(10));
        marks.mark(setup_status::Phase::AssetsReady, Duration::from_millis(20));
        marks.mark(setup_status::Phase::Ready, Duration::from_millis(30));
        let names: Vec<&str> = marks.timeline().map(|(name, _)| name).collect();
        assert_eq!(names, ["INITIALIZING", "ASSETS_READY", "READY"]);
    }
}
