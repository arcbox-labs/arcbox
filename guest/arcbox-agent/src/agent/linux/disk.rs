//! Disk-space reclamation: periodic and on-demand `fstrim` on the guest data
//! mount points so the host-side sparse image can release freed blocks.

use std::time::Duration;

use tokio::process::Command;
use tokio::time::MissedTickBehavior;

use arcbox_connect::v1::DiskTrimResponse;
use arcbox_constants::paths::{CONTAINERD_DATA_MOUNT_POINT, DOCKER_DATA_MOUNT_POINT};

use crate::rpc::{ErrorResponse, RpcResponse};

/// Interval between successive periodic trims.
const FSTRIM_INTERVAL: Duration = Duration::from_secs(3600);

/// Mount points trimmed by both the periodic loop and the on-demand RPC.
const FSTRIM_MOUNTS: [&str; 2] = [DOCKER_DATA_MOUNT_POINT, CONTAINERD_DATA_MOUNT_POINT];

/// Periodically runs `fstrim` on data mount points to reclaim sparse file
/// space on the host. First tick fires immediately to trim historical waste.
///
/// `MissedTickBehavior::Skip` collapses ticks the VM missed while paused so
/// resume doesn't immediately run several trims back-to-back.
pub(super) async fn fstrim_loop() {
    let mut interval = tokio::time::interval(FSTRIM_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        for mount in FSTRIM_MOUNTS {
            match Command::new("fstrim").arg(mount).status().await {
                Ok(s) if s.success() => {
                    tracing::info!("fstrim {} completed", mount);
                }
                Ok(s) => {
                    tracing::warn!(
                        "fstrim {} exited with code {}",
                        mount,
                        s.code().unwrap_or(-1)
                    );
                }
                Err(e) => {
                    tracing::warn!("fstrim {} failed: {}", mount, e);
                }
            }
        }
    }
}

/// Runs `fstrim -v` once on each data mount. Returns `Ok(summary)` when every
/// mount trimmed, or `Err(summary)` if any mount failed. The summary lists the
/// per-mount outcome either way.
async fn run_fstrim_now() -> Result<String, String> {
    let mut results = Vec::new();
    let mut all_ok = true;
    for mount in FSTRIM_MOUNTS {
        match Command::new("fstrim").arg("-v").arg(mount).output().await {
            Ok(output) if output.status.success() => {
                let msg = String::from_utf8_lossy(&output.stdout);
                results.push(format!("{}: {}", mount, msg.trim()));
            }
            Ok(output) => {
                all_ok = false;
                let msg = String::from_utf8_lossy(&output.stderr);
                results.push(format!("{}: failed ({})", mount, msg.trim()));
            }
            Err(e) => {
                all_ok = false;
                results.push(format!("{}: error ({})", mount, e));
            }
        }
    }
    let summary = results.join("; ");
    if all_ok { Ok(summary) } else { Err(summary) }
}

/// Handles a `DiskTrim` RPC: triggers an immediate trim. Returns the per-mount
/// summary on success, or a generic error response if any mount failed — so the
/// daemon's `disk_trim()` surfaces a real `Err` rather than a success-looking
/// summary string the caller would have to parse.
pub(super) async fn handle_disk_trim() -> RpcResponse {
    match run_fstrim_now().await {
        Ok(result) => RpcResponse::DiskTrim(DiskTrimResponse {
            result,
            ..Default::default()
        }),
        Err(summary) => RpcResponse::Error(ErrorResponse::new(
            500,
            format!("disk trim failed: {summary}"),
        )),
    }
}
