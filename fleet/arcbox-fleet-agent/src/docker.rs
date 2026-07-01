//! Docker API-based execution of Linux runner jobs.
//!
//! Talks to any Docker-compatible runtime (ArcBox on macOS, Docker Engine on
//! Linux/Windows) via the local socket. Each Linux job runs inside a container
//! launched from the configured runner image.

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{
    CreateContainerOptions, CreateImageOptions, RemoveContainerOptions, WaitContainerOptions,
};
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};

use crate::host;

/// Everything the Docker runner needs to execute one job.
pub struct RunSpec<'a> {
    /// Job identifier, used as the container name suffix.
    pub job_id: &'a str,
    /// Base64-encoded JIT runner config, passed through to `run.sh`.
    pub encoded_jit_config: &'a str,
    /// Target CPU architecture (`arm64` or `amd64`).
    pub arch: &'a str,
    /// Image to run this job in — the live-settable `runner_image`, read
    /// fresh by the caller for each job rather than fixed at construction.
    pub runner_image: &'a str,
}

/// A container that has been created and started. Held by the caller while the
/// job runs: [`wait`](Self::wait) observes the exit, then [`remove`](Self::remove)
/// or [`cancel`](Self::cancel) tears the container down — both awaited, so the
/// caller's bookkeeping settles only after the container is actually gone. The
/// embedded [`ContainerGuard`] is a panic safety net, not the teardown path.
pub struct RunningContainer {
    client: Docker,
    id: String,
    guard: ContainerGuard,
}

impl RunningContainer {
    /// Block until the container exits and return its exit code. No cleanup —
    /// follow with [`remove`](Self::remove). The agent reports no outcome
    /// upstream (the GitHub webhook is authoritative); the code is for logging.
    pub async fn wait(&self) -> Result<i64> {
        let wait = self
            .client
            .wait_container(
                &self.id,
                Some(WaitContainerOptions {
                    condition: "not-running".to_owned(),
                }),
            )
            .next()
            .await
            .context("container wait stream ended unexpectedly")?
            .with_context(|| format!("waiting on container {}", self.id))?;
        Ok(wait.status_code)
    }

    /// Remove the (exited) container, awaited. Failures are logged, not
    /// propagated: the job itself already concluded.
    pub async fn remove(self) {
        let Self { client, id, guard } = self;
        guard.defuse();
        let options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        if let Err(e) = client.remove_container(&id, Some(options)).await {
            warn!(container = %id, error = %e, "failed to remove container");
        }
    }

    /// Kill and remove the container, awaited — the cancellation/shutdown
    /// teardown. Once this returns the container is gone (or its removal
    /// failed loudly), so a shutdown that awaits it leaves no orphan behind.
    pub async fn cancel(self) {
        // The container may have exited on its own in the cancel race; a failed
        // kill is expected then, and the forced remove below handles both cases.
        if let Err(e) = self.client.kill_container(&self.id, None).await {
            debug!(container = %self.id, error = %e, "kill on cancel failed (may have exited)");
        }
        self.remove().await;
    }
}

/// Wraps the Docker Engine API for running GitHub Actions jobs in containers.
#[derive(Clone)]
pub struct DockerRunner {
    client: Docker,
    /// Linux arches verified pullable at startup, advertised as capacity pools.
    linux_arches: Vec<String>,
}

/// Deterministic per-job container name, so redeliveries and interrupted
/// startups can always find (and remove) whatever an earlier attempt created.
fn container_name(job_id: &str) -> String {
    format!("arcbox-{job_id}")
}

/// ArcBox's Docker-compatible socket path on macOS (`~/.arcbox/docker.sock`).
fn arcbox_socket_path() -> Option<String> {
    if std::env::consts::OS != "macos" {
        return None;
    }
    dirs::home_dir().map(|home| {
        home.join(".arcbox")
            .join("docker.sock")
            .to_string_lossy()
            .into_owned()
    })
}

/// Connect to a Docker-compatible runtime and verify it answers a ping.
///
/// On macOS, prefers ArcBox's own socket and falls back to the system default
/// if ArcBox is absent or its socket is unresponsive (the ping is what proves
/// reachability — building the client does no I/O). On other platforms it uses
/// the system default directly.
async fn connect() -> Result<Docker> {
    if let Some(addr) = arcbox_socket_path() {
        match connect_arcbox(&addr).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                warn!(error = %e, "ArcBox runtime unavailable; falling back to local Docker");
            }
        }
    }
    let client = Docker::connect_with_local_defaults().context("connecting to Docker runtime")?;
    client
        .ping()
        .await
        .context("Docker-compatible runtime is not reachable (ping failed)")?;
    Ok(client)
}

/// Connect to ArcBox's socket and confirm it responds to a ping.
///
/// A short timeout keeps a present-but-hung socket from stalling startup before
/// the local-Docker fallback kicks in — a live socket answers a ping promptly.
async fn connect_arcbox(addr: &str) -> Result<Docker> {
    let client = Docker::connect_with_unix(addr, 15, bollard::API_DEFAULT_VERSION)
        .with_context(|| format!("connecting to ArcBox runtime at {addr}"))?;
    client
        .ping()
        .await
        .with_context(|| format!("ArcBox runtime at {addr} is not reachable (ping failed)"))?;
    Ok(client)
}

/// Linux arches this host could serve, before verifying they can be pulled.
///
/// The native arch always, plus amd64 on Apple Silicon macOS, where ArcBox's
/// runtime provides Rosetta-backed emulation.
fn candidate_arches() -> Vec<String> {
    let native = host::map_arch(std::env::consts::ARCH);
    let mut arches = vec![native.to_owned()];
    if std::env::consts::OS == "macos" && native == "arm64" {
        arches.push("amd64".to_owned());
    }
    arches
}

impl DockerRunner {
    /// Connect to the Docker-compatible runtime and prove it works by pulling
    /// the default runner image for each candidate arch.
    ///
    /// On macOS, prefers ArcBox's own socket (`~/.arcbox/docker.sock`) and falls
    /// back to the system default (Docker Desktop, Colima, …) when ArcBox is
    /// absent or unresponsive. On other platforms it uses the system default
    /// directly (e.g. `/var/run/docker.sock` on Linux, named pipe on Windows).
    ///
    /// The pull is the readiness check: an arch is advertised only if its image
    /// pulls, so a host that cannot realize `linux/amd64` (no working emulation)
    /// never advertises it. Docker counts as available only if at least one arch
    /// pulls; otherwise this returns an error and the caller proceeds without it
    /// (`Auto`) or fails startup (`Enabled`).
    ///
    /// `default_image` is a local bootstrap parameter, not stored: it is
    /// only used to verify readiness here. Live jobs use whatever
    /// `runner_image` is current at dispatch time (`RunSpec::runner_image`),
    /// which may since have changed via `UpdateSettings`.
    pub async fn new(default_image: &str) -> Result<Self> {
        let client = connect().await?;

        let mut linux_arches = Vec::new();
        for arch in candidate_arches() {
            let platform = format!("linux/{arch}");
            match Self::pull_image(&client, default_image, &platform).await {
                Ok(()) => linux_arches.push(arch),
                Err(e) => warn!(arch, error = %e, "skipping arch: default image pull failed"),
            }
        }
        if linux_arches.is_empty() {
            anyhow::bail!("docker reachable but could not pull {default_image} for any arch");
        }

        info!(?linux_arches, "docker runtime available");
        Ok(Self {
            client,
            linux_arches,
        })
    }

    /// Linux architectures this Docker host serves, verified pullable at startup.
    pub fn linux_arches(&self) -> Vec<String> {
        self.linux_arches.clone()
    }

    /// Create and start a container for `spec`, returning a handle to await.
    ///
    /// Returning `Ok` means the container is running — the caller can then
    /// accept the offer. Any failure up to here (image pull, create, start) is
    /// an error so the caller rejects and the platform re-offers. A failure
    /// after the guard is armed kills and removes the container on drop.
    pub async fn start(&self, spec: RunSpec<'_>) -> Result<RunningContainer> {
        let platform = format!("linux/{}", spec.arch);

        Self::pull_image(&self.client, spec.runner_image, &platform).await?;

        let container_name = container_name(spec.job_id);

        // The name is deterministic per job, so a redelivery after a crash that
        // left an orphan would otherwise collide on create. Remove any leftover
        // first (remove-before-bind); a missing container is the normal case.
        self.remove_job_container(spec.job_id).await;

        let config = ContainerCreateBody {
            image: Some(spec.runner_image.to_owned()),
            cmd: Some(vec![
                "./run.sh".to_owned(),
                "--jitconfig".to_owned(),
                spec.encoded_jit_config.to_owned(),
            ]),
            working_dir: Some("/home/runner".to_owned()),
            ..Default::default()
        };

        let id = self
            .client
            .create_container(
                Some(CreateContainerOptions {
                    name: Some(container_name.clone()),
                    platform: platform.clone(),
                }),
                config,
            )
            .await
            .context("creating container")?
            .id;

        let guard = ContainerGuard::new(self.client.clone(), id.clone());

        self.client
            .start_container(&id, None)
            .await
            .with_context(|| format!("starting container {id}"))?;
        debug!(job_id = spec.job_id, container = %id, "container started");

        Ok(RunningContainer {
            client: self.client.clone(),
            id,
            guard,
        })
    }

    /// Force-remove the container named for `job_id`, if any — awaited and
    /// idempotent. Used as remove-before-bind ahead of a create, and as the
    /// cleanup when a cancellation interrupts [`start`](Self::start) mid-flight
    /// (the deterministic name reaches whatever the dropped start created).
    pub async fn remove_job_container(&self, job_id: &str) {
        let _ = self
            .client
            .remove_container(
                &container_name(job_id),
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }

    /// Pull an image for a specific platform.
    async fn pull_image(client: &Docker, image: &str, platform: &str) -> Result<()> {
        debug!(image, platform, "pulling image");
        let options = CreateImageOptions {
            from_image: Some(image.to_owned()),
            platform: platform.to_owned(),
            ..Default::default()
        };
        let mut stream = client.create_image(Some(options), None, None);
        while let Some(info) = stream.next().await {
            info.with_context(|| format!("pulling {image} for {platform}"))?;
        }
        info!(image, platform, "image ready");
        Ok(())
    }
}

/// Kills and removes a container on drop — the panic safety net.
///
/// Every deliberate exit ([`RunningContainer::remove`]/[`cancel`]) defuses the
/// guard and awaits the teardown itself, so this drop path only fires when the
/// runner task dies without reaching one — a panic, or the future dropped
/// without cancellation. The spawned cleanup is fire-and-forget by necessity
/// (drop cannot await); it must never be the path a correctness guarantee
/// rides on.
struct ContainerGuard {
    client: Docker,
    container_id: String,
    defused: bool,
}

impl ContainerGuard {
    fn new(client: Docker, container_id: String) -> Self {
        Self {
            client,
            container_id,
            defused: false,
        }
    }

    /// Disarm the guard after normal completion.
    fn defuse(mut self) {
        self.defused = true;
    }
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        if self.defused {
            return;
        }
        let client = self.client.clone();
        let id = self.container_id.clone();
        tokio::spawn(async move {
            let _ = client.kill_container(&id, None).await;
            let options = RemoveContainerOptions {
                force: true,
                ..Default::default()
            };
            let _ = client.remove_container(&id, Some(options)).await;
        });
    }
}
