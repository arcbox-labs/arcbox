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
}

/// A container that has been created and started. Held by the caller while the
/// job runs; [`wait`](RunningContainer::wait) drives it to completion, and a
/// drop before then (e.g. `CancelRunner` aborting the task) kills and removes it
/// via the embedded [`ContainerGuard`].
pub struct RunningContainer {
    client: Docker,
    id: String,
    guard: ContainerGuard,
}

impl RunningContainer {
    /// Block until the container exits, then remove it. The agent reports no
    /// outcome upstream (the GitHub webhook is authoritative); the outcome here
    /// is for logging only.
    pub async fn wait(self) -> Result<DockerOutcome> {
        let Self { client, id, guard } = self;
        let wait = client
            .wait_container(
                &id,
                Some(WaitContainerOptions {
                    condition: "not-running".to_owned(),
                }),
            )
            .next()
            .await
            .context("container wait stream ended unexpectedly")?
            .with_context(|| format!("waiting on container {id}"))?;

        let exit_code = wait.status_code;
        guard.defuse();
        let options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        if let Err(e) = client.remove_container(&id, Some(options)).await {
            warn!(container = %id, error = %e, "failed to remove container");
        }

        Ok(DockerOutcome {
            success: exit_code == 0,
            detail: format!("container exited with code {exit_code}"),
        })
    }
}

/// Terminal outcome of a containerized job.
pub struct DockerOutcome {
    pub success: bool,
    pub detail: String,
}

/// Wraps the Docker Engine API for running GitHub Actions jobs in containers.
#[derive(Clone)]
pub struct DockerRunner {
    client: Docker,
    /// Image used when the platform sends no image override.
    default_image: String,
    /// Linux arches verified pullable at startup, advertised as capacity pools.
    linux_arches: Vec<String>,
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
    /// On macOS, connects to ArcBox's own socket (`~/.arcbox/docker.sock`); on
    /// other platforms the system default (e.g. `/var/run/docker.sock` on
    /// Linux, named pipe on Windows).
    ///
    /// The pull is the readiness check: an arch is advertised only if its image
    /// pulls, so a host that cannot realize `linux/amd64` (no working emulation)
    /// never advertises it. Docker counts as available only if at least one arch
    /// pulls; otherwise this returns an error and the caller proceeds without it
    /// (`Auto`) or fails startup (`Enabled`).
    pub async fn new(default_image: String) -> Result<Self> {
        let client = if let Some(addr) = arcbox_socket_path() {
            Docker::connect_with_unix(&addr, 120, bollard::API_DEFAULT_VERSION)
                .with_context(|| format!("connecting to ArcBox runtime at {addr}"))?
        } else {
            Docker::connect_with_local_defaults().context("connecting to Docker runtime")?
        };
        client
            .ping()
            .await
            .context("Docker-compatible runtime is not reachable (ping failed)")?;

        let mut linux_arches = Vec::new();
        for arch in candidate_arches() {
            let platform = format!("linux/{arch}");
            match Self::pull_image(&client, &default_image, &platform).await {
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
            default_image,
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

        Self::pull_image(&self.client, &self.default_image, &platform).await?;

        let container_name = format!("arcbox-{}", spec.job_id);

        // The name is deterministic per job, so a redelivery after a crash that
        // left an orphan would otherwise collide on create. Remove any leftover
        // first (remove-before-bind); a missing container is the normal case.
        let _ = self
            .client
            .remove_container(
                &container_name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;

        let config = ContainerCreateBody {
            image: Some(self.default_image.clone()),
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

/// Kills and removes a container on drop — the cancellation safety net.
///
/// On normal completion the caller calls [`defuse`](Self::defuse) and handles
/// cleanup explicitly (where errors can be logged). On task abort, the guard
/// spawns a fire-and-forget cleanup task.
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
