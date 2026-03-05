//! Firecracker process spawn helpers — shared between `manager` and `sandbox`.

use std::path::Path;
use std::time::Duration;

use fc_sdk::process::{FirecrackerProcessBuilder, JailerProcessBuilder};

use crate::config::{FirecrackerConfig, JailerConfig};
use crate::error::{Result, VmmError};

/// Configure and spawn a Firecracker process via the Jailer.
///
/// Returns the spawned process. The caller can query `process.socket_path()`
/// to obtain the API socket inside the chroot.
pub async fn spawn_jailer(
    jc: &JailerConfig,
    fc_cfg: &FirecrackerConfig,
    id: &str,
) -> Result<fc_sdk::FirecrackerProcess> {
    let mut jb = JailerProcessBuilder::new(&jc.binary, &fc_cfg.binary, id, jc.uid, jc.gid);
    if let Some(ref base) = jc.chroot_base_dir {
        jb = jb.chroot_base_dir(base);
    }
    if let Some(ref ns) = jc.netns {
        jb = jb.netns(ns);
    }
    if jc.new_pid_ns {
        jb = jb.new_pid_ns(true);
    }
    if let Some(ref ver) = jc.cgroup_version {
        jb = jb.cgroup_version(ver);
    }
    if let Some(ref parent) = jc.parent_cgroup {
        jb = jb.parent_cgroup(parent);
    }
    for limit in &jc.resource_limits {
        jb = jb.resource_limit(limit);
    }
    if let Some(secs) = fc_cfg.socket_timeout_secs {
        jb = jb.socket_timeout(Duration::from_secs(secs));
    }
    jb.spawn()
        .await
        .map_err(|e| VmmError::Process(e.to_string()))
}

/// Configure and spawn a Firecracker process directly (no Jailer).
pub async fn spawn_direct(
    fc_cfg: &FirecrackerConfig,
    id: &str,
    socket_path: &Path,
    log_path: &Path,
    metrics_path: &Path,
) -> Result<fc_sdk::FirecrackerProcess> {
    let mut fb = FirecrackerProcessBuilder::new(&fc_cfg.binary, socket_path).id(id);
    fb = fb.log_path(log_path).metrics_path(metrics_path);
    if let Some(ref level) = fc_cfg.log_level {
        fb = fb.log_level(level);
    }
    if fc_cfg.no_seccomp {
        fb = fb.no_seccomp(true);
    }
    if let Some(ref filter) = fc_cfg.seccomp_filter {
        fb = fb.seccomp_filter(filter);
    }
    if let Some(size) = fc_cfg.http_api_max_payload_size {
        fb = fb.http_api_max_payload_size(size);
    }
    if let Some(size) = fc_cfg.mmds_size_limit {
        fb = fb.mmds_size_limit(size);
    }
    if let Some(secs) = fc_cfg.socket_timeout_secs {
        fb = fb.socket_timeout(Duration::from_secs(secs));
    }
    fb.spawn()
        .await
        .map_err(|e| VmmError::Process(e.to_string()))
}
