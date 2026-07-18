//! Live check for `SystemService.ResolveContainerFs` / `ResolveImageFs`
//! and the containerd child NFS export: boots the System VM through a real
//! daemon, runs a container that writes a marker into its rootfs, resolves
//! the container's snapshot layer directories over gRPC, reads the marker
//! back through the host NFS mount (`<data_dir>/ArcBox/containerd/...`),
//! then resolves the image's layers by top chain ID and checks they are
//! visible through the same mount.

use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use arcbox_e2e::docker::docker_output;
use arcbox_grpc::SystemServiceClient;
use arcbox_protocol::v1::{ResolveContainerFsRequest, ResolveImageFsRequest};
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(120);
/// The NFS mount is established by a background reconcile task and the
/// browse mount caches attributes (`actimeo=10`), so give reads a window.
const NFS_VISIBLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Guest prefix every resolved layer directory must live under.
const CONTAINERD_PREFIX: &str = "/var/lib/containerd/";

#[test]
#[ignore = "boots a System VM through a real daemon"]
fn container_fs_paths_resolve_and_read_through_nfs() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-container-fs-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version)],
    })?;
    if let Err(error) = daemon.wait_ready_blocking(READY_TIMEOUT) {
        let kept = data_dir.keep();
        bail!(
            "daemon not ready: {error:#} (data dir preserved at {})",
            kept.display()
        );
    }

    let result = scenario(data_dir.path());
    if result.is_err() {
        let kept = data_dir.keep();
        tracing::warn!(path = %kept.display(), "preserving test directory");
    }
    drop(daemon);
    result
}

fn scenario(data_dir: &Path) -> Result<()> {
    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());

    // Write a marker into the container rootfs (its overlay upper layer),
    // then idle so the snapshot stays active for the whole scenario.
    docker_output(
        data_dir,
        &[
            "run",
            "-d",
            "--name",
            "fs-probe",
            &image,
            "sh",
            "-c",
            "echo arcbox-fs-probe > /probe.txt && sleep 300",
        ],
        DOCKER_TIMEOUT,
    )?;
    let container_id = docker_output(
        data_dir,
        &["inspect", "-f", "{{.Id}}", "fs-probe"],
        DOCKER_TIMEOUT,
    )?
    .trim()
    .to_owned();

    let paths = resolve_container_fs(data_dir, &container_id)?;
    tracing::info!(
        upper = %paths.upper_dir,
        lowers = paths.lower_dirs.len(),
        "resolved container fs paths"
    );

    if !paths.upper_dir.starts_with(CONTAINERD_PREFIX) {
        bail!(
            "upper_dir {} not under {CONTAINERD_PREFIX}",
            paths.upper_dir
        );
    }
    if paths.lower_dirs.is_empty() {
        bail!("expected at least one lower layer for {image}");
    }
    for lower in &paths.lower_dirs {
        if !lower.starts_with(CONTAINERD_PREFIX) {
            bail!("lower_dir {lower} not under {CONTAINERD_PREFIX}");
        }
    }

    // Guest → host mapping: /var/lib/containerd/X → <mount>/containerd/X.
    let upper_host = host_path(data_dir, &paths.upper_dir)?;
    let marker = upper_host.join("probe.txt");
    let contents = read_when_visible(&marker, NFS_VISIBLE_TIMEOUT)?;
    if contents.trim() != "arcbox-fs-probe" {
        bail!("marker file carried {contents:?}");
    }

    let lower_host = host_path(data_dir, &paths.lower_dirs[0])?;
    if !lower_host.is_dir() {
        bail!("lower layer not visible at {}", lower_host.display());
    }

    image_scenario(data_dir, &image)?;

    tracing::info!("container fs resolution + NFS read-through check passed");
    Ok(())
}

/// Resolves the pulled image's layers by top chain ID and checks the top
/// layer directory is visible through the NFS mount.
fn image_scenario(data_dir: &Path, image: &str) -> Result<()> {
    let layers_json = docker_output(
        data_dir,
        &["image", "inspect", "-f", "{{json .RootFS.Layers}}", image],
        DOCKER_TIMEOUT,
    )?;
    let diff_ids: Vec<String> =
        serde_json::from_str(layers_json.trim()).context("parsing image RootFS.Layers")?;
    let top_chain_id = top_chain_id(&diff_ids)?;

    let image_paths = resolve_image_fs(data_dir, &top_chain_id)?;
    tracing::info!(
        %top_chain_id,
        lowers = image_paths.lower_dirs.len(),
        "resolved image fs paths"
    );

    if image_paths.lower_dirs.len() != diff_ids.len() {
        bail!(
            "expected {} image layers, got {:?}",
            diff_ids.len(),
            image_paths.lower_dirs
        );
    }
    for lower in &image_paths.lower_dirs {
        if !lower.starts_with(CONTAINERD_PREFIX) {
            bail!("image lower_dir {lower} not under {CONTAINERD_PREFIX}");
        }
    }
    let top_host = host_path(data_dir, &image_paths.lower_dirs[0])?;
    if !top_host.is_dir() {
        bail!("image top layer not visible at {}", top_host.display());
    }
    Ok(())
}

/// Chain ID of the last layer, per the OCI image spec: the first chain ID
/// is the first diff ID; each next one is `sha256(prev + " " + diff)`.
fn top_chain_id(diff_ids: &[String]) -> Result<String> {
    let (first, rest) = diff_ids
        .split_first()
        .context("image reports no rootfs layers")?;
    let mut chain = first.clone();
    for diff in rest {
        let digest = Sha256::digest(format!("{chain} {diff}").as_bytes());
        chain = format!("sha256:{digest:x}");
    }
    Ok(chain)
}

fn resolve_image_fs(
    data_dir: &Path,
    top_chain_id: &str,
) -> Result<arcbox_protocol::v1::ResolveImageFsResponse> {
    let socket = data_dir.join("run/arcbox.sock");
    let top_chain_id = top_chain_id.to_owned();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime for ResolveImageFs")?
        .block_on(async {
            let channel = connect_unix(&socket).await?;
            let mut client = SystemServiceClient::new(channel);
            anyhow::Ok(
                client
                    .resolve_image_fs(ResolveImageFsRequest { top_chain_id })
                    .await?
                    .into_inner(),
            )
        })
}

fn resolve_container_fs(
    data_dir: &Path,
    container_id: &str,
) -> Result<arcbox_protocol::v1::ResolveContainerFsResponse> {
    let socket = data_dir.join("run/arcbox.sock");
    let container_id = container_id.to_owned();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime for ResolveContainerFs")?
        .block_on(async {
            let channel = connect_unix(&socket).await?;
            let mut client = SystemServiceClient::new(channel);
            anyhow::Ok(
                client
                    .resolve_container_fs(ResolveContainerFsRequest { container_id })
                    .await?
                    .into_inner(),
            )
        })
}

/// Rewrites a guest `/var/lib/containerd/...` path onto the host NFS mount
/// (`<data_dir>/ArcBox/containerd/...`, per the harness
/// `ARCBOX_HOST_MOUNT_DIR`).
fn host_path(data_dir: &Path, guest_path: &str) -> Result<PathBuf> {
    let relative = guest_path
        .strip_prefix(CONTAINERD_PREFIX)
        .with_context(|| format!("guest path {guest_path} not under {CONTAINERD_PREFIX}"))?;
    Ok(data_dir.join("ArcBox/containerd").join(relative))
}

fn read_when_visible(path: &Path, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::read_to_string(path) {
            Ok(contents) => return Ok(contents),
            Err(e) if Instant::now() >= deadline => {
                return Err(e).with_context(|| format!("reading {} via NFS", path.display()));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

fn init_tracing() {
    TRACING.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .init();
    });
}
