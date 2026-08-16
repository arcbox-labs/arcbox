//! Firecracker process spawn helpers — shared between `manager` and `sandbox`.

use std::path::Path;

use arcbox_vm_driver::{Error, IsolationSpec, Result};
use fc_sdk::process::{FirecrackerProcessBuilder, JailerProcessBuilder};

use crate::config::FcDriverConfig;
use crate::error::FcError;

/// Configure and spawn a Firecracker process via the Jailer.
///
/// Returns the spawned process. The caller can query `process.socket_path()`
/// to obtain the API socket inside the chroot.
pub async fn spawn_jailer(
    fc_cfg: &FcDriverConfig,
    isolation: &IsolationSpec,
    id: &str,
) -> Result<fc_sdk::FirecrackerProcess> {
    let IsolationSpec::Jailer {
        uid,
        gid,
        chroot_base,
        netns,
        new_pid_ns,
        cgroup,
    } = isolation
    else {
        return Err(Error::InvalidSpec(
            "a jailer spawn needs IsolationSpec::Jailer".into(),
        ));
    };
    let jailer = fc_cfg.jailer_binary.as_deref().ok_or(FcError::NoJailer)?;
    let mut jb = JailerProcessBuilder::new(jailer, &fc_cfg.firecracker_binary, id, *uid, *gid);
    jb = jb.chroot_base_dir(chroot_base);
    if let Some(ns) = netns {
        jb = jb.netns(ns.display().to_string());
    }
    if *new_pid_ns {
        jb = jb.new_pid_ns(true);
    }
    if let Some(cg) = cgroup {
        jb = jb.cgroup_version(cg.version.to_string());
        if let Some(parent) = &cg.parent {
            jb = jb.parent_cgroup(parent);
        }
    }
    for limit in &fc_cfg.resource_limits {
        jb = jb.resource_limit(limit);
    }
    jb = jb.socket_timeout(fc_cfg.socket_timeout);
    jb.spawn().await.map_err(|e| Error::from(FcError::Spawn(e)))
}

/// Configure and spawn a Firecracker process directly (no Jailer).
pub async fn spawn_direct(
    fc_cfg: &FcDriverConfig,
    id: &str,
    socket_path: &Path,
    log_path: &Path,
    metrics_path: &Path,
) -> Result<fc_sdk::FirecrackerProcess> {
    let mut fb = FirecrackerProcessBuilder::new(&fc_cfg.firecracker_binary, socket_path).id(id);
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
    fb = fb.socket_timeout(fc_cfg.socket_timeout);
    tracing::debug!(
        id,
        socket = %socket_path.display(),
        log = %log_path.display(),
        metrics = %metrics_path.display(),
        binary = %fc_cfg.firecracker_binary.display(),
        "spawning firecracker (direct mode)"
    );
    fb.spawn().await.map_err(|e| Error::from(FcError::Spawn(e)))
}
