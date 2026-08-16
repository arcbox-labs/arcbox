//! Proves the overlayfs snapshotter's configured mount options reach the
//! kernel, rather than merely reaching `/etc/containerd/config.toml`.
//!
//! A container's rootfs must be mounted with `index=on,nfs_export=on` for the
//! in-kernel nfsd to be able to encode file handles for it — the precondition
//! for browsing a live container through `~/ArcBox` (ABX-424). Configuring
//! them is not the same as getting them: until arcboxlabs/boot-assets#52 the
//! stock overlay snapshotter appended `index=off` after the configured
//! options, and the kernel rejects `index=off,nfs_export=on` on a read-write
//! mount outright.
//!
//! This reads the guest's own `/proc/mounts` through a privileged container in
//! the host PID namespace, because that is the only place the *effective*
//! options are visible. Note `/proc/mounts` omits options equal to the
//! kernel default, which is why the assertions target `index=on` and
//! `nfs_export=on` (both non-default) rather than the absence of `index=off`.

use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::docker::docker_output;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(120);

#[test]
#[ignore = "boots a System VM through a real daemon"]
fn container_rootfs_is_mounted_with_nfs_exportable_options() -> Result<()> {
    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
        // The subject of this test is config the *guest agent* writes, and
        // `stage_dev_boot_assets` stages whichever agent has the newest mtime
        // across the dev tree, the musl target and ~/.arcbox/bin. Without
        // building it here, a machine holding any older agent can boot one
        // that predates the change entirely (ABX-385 class).
        xshell::cmd!(
            shell,
            "cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release"
        )
        .run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-overlay-opts-")
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
        eprintln!("preserving test directory path={}", kept.display());
    }
    drop(daemon);
    result
}

fn scenario(data_dir: &Path) -> Result<()> {
    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());

    docker_output(
        data_dir,
        &["run", "-d", "--name", "ovl-probe", &image, "sleep", "300"],
        DOCKER_TIMEOUT,
    )?;

    // Read PID 1's mount table rather than our own: a container's
    // `/proc/mounts` shows its rootfs as `/` with the overlay options already
    // stripped. `--pid=host` makes `/proc/1` the guest init, and `/proc/N/mounts`
    // is readable without entering its mount namespace — which matters,
    // because `nsenter -m` would resolve every subsequent binary against the
    // guest's EROFS root instead of this image.
    let mounts = docker_output(
        data_dir,
        &[
            "run",
            "--rm",
            "--privileged",
            "--pid=host",
            &image,
            "cat",
            "/proc/1/mounts",
        ],
        DOCKER_TIMEOUT,
    )?;

    println!("guest overlay mounts:\n{mounts}");

    let overlay_lines: Vec<&str> = mounts
        .lines()
        .filter(|line| line.starts_with("overlay "))
        .collect();
    if overlay_lines.is_empty() {
        bail!("no overlay mount in the guest's /proc/mounts:\n{mounts}");
    }

    // Both options on *one* mount. Scanning for each independently would pass
    // when one mount carries `index=on` and a different one carries
    // `nfs_export=on` — never checking the pairing this exists to guarantee.
    // It also masks the sharpest signature there is: a mount with `index=on`
    // and no `nfs_export=on` is what the kernel leaves behind when it drops
    // nfs_export on its own.
    let paired = overlay_lines
        .iter()
        .any(|line| line.contains("index=on") && line.contains("nfs_export=on"));
    if !paired {
        bail!(
            "no single overlay mount carries both index=on and nfs_export=on; \
             the snapshotter's configured mount_options did not reach the kernel \
             intact:\n{}",
            overlay_lines.join("\n")
        );
    }

    let _ = docker_output(data_dir, &["rm", "-f", "ovl-probe"], DOCKER_TIMEOUT);
    Ok(())
}
