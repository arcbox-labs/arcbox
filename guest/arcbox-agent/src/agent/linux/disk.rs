//! Disk-space reclamation: periodic and on-demand `fstrim` on the guest data
//! mount points so the host-side sparse image can release freed blocks.

use std::time::Duration;

use tokio::process::Command;
use tokio::time::MissedTickBehavior;

use arcbox_constants::paths::{CONTAINERD_DATA_MOUNT_POINT, DOCKER_DATA_MOUNT_POINT};
use arcbox_protocol::agent::DiskTrimResponse;

use crate::rpc::RpcResponse;

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
                    tracing::debug!(
                        "fstrim {} exited with code {}",
                        mount,
                        s.code().unwrap_or(-1)
                    );
                }
                Err(e) => {
                    tracing::debug!("fstrim {} failed: {}", mount, e);
                }
            }
        }
    }
}

/// Runs `fstrim -v` once on each data mount, returning a per-mount summary.
async fn run_fstrim_now() -> String {
    let mut results = Vec::new();
    for mount in FSTRIM_MOUNTS {
        match Command::new("fstrim").arg("-v").arg(mount).output().await {
            Ok(output) if output.status.success() => {
                let msg = String::from_utf8_lossy(&output.stdout);
                results.push(format!("{}: {}", mount, msg.trim()));
            }
            Ok(output) => {
                let msg = String::from_utf8_lossy(&output.stderr);
                results.push(format!("{}: failed ({})", mount, msg.trim()));
            }
            Err(e) => {
                results.push(format!("{}: error ({})", mount, e));
            }
        }
    }
    results.join("; ")
}

/// Handles a `DiskTrim` RPC: triggers an immediate trim and returns the
/// per-mount summary.
pub(super) async fn handle_disk_trim() -> RpcResponse {
    let result = run_fstrim_now().await;
    RpcResponse::DiskTrim(DiskTrimResponse { result })
}
