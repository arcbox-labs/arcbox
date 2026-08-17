//! Firecracker process spawn helpers — from a rendered [`SpawnPlan`], or
//! directly by mode.

use std::path::Path;

use arcbox_vm_driver::{Error, IsolationSpec, Result};
use fc_sdk::process::{FirecrackerProcessBuilder, JailerProcessBuilder};

use crate::config::FcDriverConfig;
use crate::error::FcError;
use crate::render::{SpawnMode, SpawnPlan};

/// Spawn the process a plan describes and wait for its API socket.
///
/// The vsock socket's directory (`{runtime_dir}`, or `{jail}/run`) is
/// created and a stale socket from an earlier VM in the same place is
/// cleared first, so the device can bind where the plan says. Direct mode
/// also pre-creates the log and metrics files (some Firecracker builds
/// expect `--log-path`/`--metrics-path` targets to exist).
pub async fn spawn(
    plan: &SpawnPlan,
    fc_cfg: &FcDriverConfig,
) -> Result<fc_sdk::FirecrackerProcess> {
    if let Some(parent) = plan.vsock_uds.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(Error::Io)?;
    }
    if let Err(e) = tokio::fs::remove_file(&plan.vsock_uds).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(e));
    }
    match &plan.mode {
        SpawnMode::Direct { log, metrics } => {
            for target in [log, metrics] {
                tokio::fs::File::create(target).await.map_err(Error::Io)?;
            }
            spawn_direct(fc_cfg, plan.id.as_str(), &plan.api_socket, log, metrics).await
        }
        SpawnMode::Jailer { isolation, .. } => {
            spawn_jailer(fc_cfg, isolation, plan.id.as_str()).await
        }
    }
}

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
