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
    /// Resolved container image (never empty — caller must fall back to the
    /// default before constructing this).
    pub image: &'a str,
    /// Base64-encoded JIT runner config, passed through to `run.sh`.
    pub encoded_jit_config: &'a str,
    /// Target CPU architecture (`arm64` or `amd64`).
    pub arch: &'a str,
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

impl DockerRunner {
    /// Connect to the Docker-compatible runtime and verify reachability.
    ///
    /// On macOS, connects to ArcBox's own socket (`~/.arcbox/docker.sock`).
    /// On other platforms, uses the system default (e.g. `/var/run/docker.sock`
    /// on Linux, named pipe on Windows).
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
        info!("docker runtime available");
        Ok(Self {
            client,
            default_image,
        })
    }

    /// Linux architectures this Docker host can run as containers.
    ///
    /// Always includes the host's native arch. On Linux this is the same pool
    /// the host would otherwise serve directly, but Docker still runs it for
    /// isolation. On Apple Silicon macOS, amd64 is also included because
    /// ArcBox's runtime provides Rosetta-backed emulation.
    pub fn linux_arches(&self) -> Vec<String> {
        let native = host::map_arch(std::env::consts::ARCH);
        let mut arches = vec![native.to_owned()];
        if std::env::consts::OS == "macos" && native == "arm64" {
            arches.push("amd64".to_owned());
        }
        arches
    }

    /// Resolve the image for a job: prefer the platform-supplied value, fall
    /// back to the configured default.
    pub fn resolve_image<'a>(&'a self, platform_image: &'a str) -> &'a str {
        if platform_image.is_empty() {
            &self.default_image
        } else {
            platform_image
        }
    }

    /// Run a job inside a container. Returns the terminal outcome.
    ///
    /// If the future is canceled (e.g. `CancelRunner` aborting the task), the
    /// [`ContainerGuard`] kills and removes the container on drop.
    pub async fn run_job(&self, spec: RunSpec<'_>) -> Result<DockerOutcome> {
        let platform = format!("linux/{}", spec.arch);

        self.pull_image(spec.image, &platform).await?;

        let container_name = format!("arcbox-{}", spec.job_id);
        let config = ContainerCreateBody {
            image: Some(spec.image.to_owned()),
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

        let wait = self
            .client
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
        self.cleanup_container(&id).await;

        Ok(DockerOutcome {
            success: exit_code == 0,
            detail: format!("container exited with code {exit_code}"),
        })
    }

    /// Pull an image for a specific platform.
    async fn pull_image(&self, image: &str, platform: &str) -> Result<()> {
        debug!(image, platform, "pulling image");
        let options = CreateImageOptions {
            from_image: Some(image.to_owned()),
            platform: platform.to_owned(),
            ..Default::default()
        };
        let mut stream = self.client.create_image(Some(options), None, None);
        while let Some(info) = stream.next().await {
            info.with_context(|| format!("pulling {image} for {platform}"))?;
        }
        info!(image, platform, "image ready");
        Ok(())
    }

    /// Best-effort container removal.
    async fn cleanup_container(&self, id: &str) {
        let options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        if let Err(e) = self.client.remove_container(id, Some(options)).await {
            warn!(container = %id, error = %e, "failed to remove container");
        }
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
