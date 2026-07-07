//! Live check for `SystemService.GetVirtioDebug`: boots the System VM
//! on the HV backend through a real daemon and asserts the snapshot
//! carries per-device queue state — devices present, boot-time kicks
//! counted, at least one queue ready with live ring indices.

use std::sync::Once;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use tracing_subscriber::EnvFilter;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);

#[test]
#[ignore = "boots an HV System VM through a real daemon"]
fn virtio_debug_snapshot_from_live_hv_daemon() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-virtio-debug-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "hv".to_owned()),
        ],
    })?;
    if let Err(error) = daemon.wait_ready_blocking(READY_TIMEOUT) {
        // The snapshot matters most right here — the VM may still be up
        // while the daemon never reached READY. Best effort: the daemon
        // may already be exiting.
        match daemon.dump_virtio_debug() {
            Ok(path) => tracing::warn!(path = %path.display(), "virtio debug snapshot captured"),
            Err(dump_error) => tracing::warn!("virtio debug dump failed: {dump_error:#}"),
        }
        let kept = data_dir.keep();
        bail!(
            "daemon not ready: {error:#} (data dir preserved at {})",
            kept.display()
        );
    }

    let path = daemon.dump_virtio_debug()?;
    let text = std::fs::read_to_string(&path)?;
    let info: serde_json::Value = serde_json::from_str(&text)?;
    tracing::info!(path = %path.display(), "virtio debug snapshot:\n{text}");

    let devices = info["devices"]
        .as_array()
        .context("snapshot has no devices array")?;
    if devices.is_empty() {
        bail!("HV daemon returned an empty virtio device list");
    }

    let total_kicks: u64 = devices
        .iter()
        .flat_map(|d| d["queues"].as_array().into_iter().flatten())
        .filter_map(|q| q["kicks"].as_u64())
        .sum();
    if total_kicks == 0 {
        bail!("no guest kicks counted across any queue after a full boot");
    }

    let has_live_ring = devices
        .iter()
        .flat_map(|d| d["queues"].as_array().into_iter().flatten())
        .any(|q| q["ready"].as_bool() == Some(true) && q["availIdx"].is_u64());
    if !has_live_ring {
        bail!("no ready queue exposed live ring indices");
    }

    tracing::info!(
        devices = devices.len(),
        total_kicks,
        "GetVirtioDebug live check passed"
    );
    drop(daemon);
    Ok(())
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
