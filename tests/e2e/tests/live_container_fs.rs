//! ABX-424 acceptance: a **running** container's filesystem is browsable from
//! the macOS host through `~/ArcBox`, live.
//!
//! Committed layers have been visible under `~/ArcBox/containerd` since
//! ABX-425, but those are the immutable parents. What a running container
//! actually sees — its merged overlay, including everything it has written
//! since it started — was not reachable at all: the in-kernel nfsd could not
//! encode file handles for an overlay mounted without `nfs_export=on`, and the
//! mountpoint had no export entry of its own.
//!
//! The test deliberately does no `exportfs` work itself. Everything it needs
//! must come from the guest agent reconciling exports on its own, which is the
//! behaviour under test; a version of this that set up its own export would
//! pass without the feature existing.
//!
//! Three properties, in order of what they would tell you when one breaks:
//!
//! 1. the host can read a file the container wrote **before** the read — the
//!    view exists at all;
//! 2. the host can read a file the container writes **after** that — it is a
//!    live view rather than a one-shot snapshot;
//! 3. `docker rm -f` still succeeds afterwards — exporting a container's
//!    rootfs has not made it un-removable, which is the regression this
//!    feature could plausibly introduce.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::docker::docker_output;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(120);
/// The agent reconciles exports off a mount-table change and the host mount
/// caches attributes (`actimeo=10`), so a read needs a window before it counts
/// as a failure.
const VISIBLE_TIMEOUT: Duration = Duration::from_secs(60);
const BOOT_MARKER: &str = "arcbox-live-fs-at-start";
const LIVE_MARKER: &str = "arcbox-live-fs-after-start";

#[test]
#[ignore = "boots a System VM through a real daemon"]
fn a_running_containers_filesystem_is_readable_from_the_host() -> Result<()> {
    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-live-fs-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version)],
    })?;
    // Readiness failures need the same forensics as scenario failures: the
    // daemon log explaining why boot stalled lives in the data dir, and `?`
    // here would drop it (tests/e2e/AGENTS.md).
    if let Err(error) = daemon.wait_ready_blocking(READY_TIMEOUT) {
        let kept = data_dir.keep();
        drop(daemon);
        bail!(
            "daemon not ready: {error:#} (data dir preserved at {})",
            kept.display()
        );
    }

    let result = scenario(data_dir.path());
    if result.is_err() {
        let kept = data_dir.keep();
        println!("preserving test directory path={}", kept.display());
    }
    drop(daemon);
    result
}

fn scenario(data_dir: &Path) -> Result<()> {
    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());

    docker_output(
        data_dir,
        &[
            "run",
            "-d",
            "--name",
            "live-fs",
            &image,
            "sh",
            "-c",
            &format!("echo {BOOT_MARKER} > /at-start.txt && sleep 300"),
        ],
        DOCKER_TIMEOUT,
    )?;
    let container_id = docker_output(
        data_dir,
        &["inspect", "-f", "{{.Id}}", "live-fs"],
        DOCKER_TIMEOUT,
    )?
    .trim()
    .to_owned();

    let host_root = live_fs_root(data_dir, &container_id);
    println!("expecting the live rootfs at {}", host_root.display());

    // (1) exists at all
    let at_start = read_with_retry(&host_root.join("at-start.txt")).with_context(|| {
        format!(
            "the live rootfs of {container_id} was not readable through the host mount.\n\
             guest overlay mounts were:\n{}",
            overlay_mounts(data_dir, &image).unwrap_or_else(|e| format!("<unavailable: {e:#}>"))
        )
    })?;
    if !at_start.contains(BOOT_MARKER) {
        bail!("at-start.txt read back as {at_start:?}, expected {BOOT_MARKER}");
    }

    // (2) live, not a snapshot taken when the export was created
    docker_output(
        data_dir,
        &[
            "exec",
            "live-fs",
            "sh",
            "-c",
            &format!("echo {LIVE_MARKER} > /after-start.txt"),
        ],
        DOCKER_TIMEOUT,
    )?;
    let after_start = read_with_retry(&host_root.join("after-start.txt"))
        .context("a file written after the export existed never became visible")?;
    if !after_start.contains(LIVE_MARKER) {
        bail!("after-start.txt read back as {after_start:?}, expected {LIVE_MARKER}");
    }

    // (3) exporting it has not made the container un-removable
    docker_output(data_dir, &["rm", "-f", "live-fs"], DOCKER_TIMEOUT)
        .context("docker rm -f failed while the rootfs was exported")?;

    Ok(())
}

/// Where the host sees a container's live rootfs.
///
/// The guest mounts it inside the NFS export root at
/// `/run/arcbox/nfs-export/docker/rootfs/overlayfs/<id>`, and that export root
/// is `fsid=0` — the NFSv4 pseudo-root — so the host path is the same tail
/// under the mount. Asserting the ID is the container's own, rather than
/// discovering the path by scanning, is deliberate: a path a caller cannot
/// derive from something it already knows is not a browsable view, and the
/// desktop Files tabs would have nothing to open.
fn live_fs_root(data_dir: &Path, container_id: &str) -> PathBuf {
    data_dir
        .join("ArcBox")
        .join("rootfs/overlayfs")
        .join(container_id)
}

fn overlay_mounts(data_dir: &Path, image: &str) -> Result<String> {
    let mounts = docker_output(
        data_dir,
        &[
            "run",
            "--rm",
            "--privileged",
            "--pid=host",
            image,
            "cat",
            "/proc/1/mounts",
        ],
        DOCKER_TIMEOUT,
    )?;
    Ok(mounts
        .lines()
        .filter(|line| line.starts_with("overlay "))
        .collect::<Vec<_>>()
        .join("\n"))
}

fn read_with_retry(path: &Path) -> Result<String> {
    let deadline = Instant::now() + VISIBLE_TIMEOUT;
    loop {
        let last = match std::fs::read_to_string(path) {
            Ok(contents) => return Ok(contents),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            bail!("{} never became readable: {last}", path.display());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
