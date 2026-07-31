//! ABX-426 restart validation — NOT part of the suite. Run manually:
//!   cargo test -p arcbox-e2e --test nfs_restart_probe -- --ignored --nocapture
//!
//! The guest no longer starts nfsd on its own, so the export has to be rebuilt
//! for every VM incarnation. This drives the motivating case end to end — a
//! System VM backend switch, i.e. `shutdown` → `set_backend` → `ensure_ready`
//! — and asserts `~/ArcBox` serves the *new* guest afterwards.
//!
//! The host-side assertion deliberately reads a path that did not exist when
//! the first mount was made (a container directory created after the switch),
//! so neither the page cache nor a stale mount left over from the dead guest
//! can satisfy it. The guest-side check then names the mechanism directly:
//! kernel nfsd is running again in the new guest.
//!
//! Sibling probes: `nfs_gate_probe` covers the negative direction
//! (`--no-mount-nfs` ⇒ no guest nfsd at all); `boot_assets` covers the first
//! incarnation's export. The arrival-vs-departure edge semantics this relies
//! on are unit-tested in `arcbox-daemon`'s `nfs_mount` tests.

use std::env;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_grpc::v1::system_service_client::SystemServiceClient;
use arcbox_protocol::v1::{SetSystemVmBackendRequest, SystemVmBackend};
use tonic::Request;
use tracing_subscriber::EnvFilter;

use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets, wait_for_nfs_mount};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use arcbox_e2e::docker::docker_output;
use arcbox_e2e::repo_root;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(120);
/// The re-established mount has to clear a VM boot plus the export request.
const REMOUNT_TIMEOUT: Duration = Duration::from_secs(180);

#[test]
#[ignore = "ABX-426 restart probe: boots a VM on both backends, needs registry access"]
fn nfs_restart_probe() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let root = repo_root();
    let version = resolve_boot_version(&root)?;
    let image = env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());

    let temp = tempfile::Builder::new()
        .prefix("arcbox-nfs-restart-")
        .tempdir()?;
    let test_dir = temp.path().to_owned();

    // Keep the data dir (daemon log, guest logs) when something fails — the
    // probe spans two VM incarnations, so a post-mortem needs the timeline.
    let result = run_probe(&root, &test_dir, &version, &image);
    if result.is_err() {
        let kept = temp.keep();
        eprintln!("preserving test directory path={}", kept.display());
    }
    result
}

fn run_probe(root: &Path, test_dir: &Path, version: &str, image: &str) -> Result<()> {
    let test_dir = test_dir.to_owned();
    let image = image.to_owned();
    stage_dev_boot_assets(root, &test_dir, version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: test_dir.clone(),
        args: vec!["--guest-docker-vsock-port".into(), "2375".into()],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".into(), version.to_owned()),
            ("ARCBOX_VM_BACKEND".into(), "vz".into()),
        ],
    })?;
    daemon.wait_ready_blocking(READY_TIMEOUT)?;

    let docker = |args: &[&str]| docker_output(&test_dir, args, DOCKER_TIMEOUT);
    let mount_dir = test_dir.join("ArcBox");

    println!("=== incarnation 1 (vz): export established ===");
    wait_for_nfs_mount(&mount_dir)?;
    println!("OK: {} is populated", mount_dir.display());

    // Pull now so the post-switch steps do not depend on the registry — the
    // guest is about to be replaced and a slow pull would muddy the timings.
    let mut pulled = false;
    for attempt in 1..=3 {
        match docker(&["pull", &image]) {
            Ok(_) => {
                println!("pulled {image} (attempt {attempt})");
                pulled = true;
                break;
            }
            Err(e) => println!("pull attempt {attempt} failed: {e:#}"),
        }
    }
    if !pulled {
        bail!("registry unreachable from guest; the probe needs to run containers");
    }
    assert_guest_nfsd(&docker, &image, "before the switch")?;

    // The restart. `SetSystemVmBackend` is `shutdown` → `set_backend` →
    // `ensure_ready`: the export dies with the old guest, and only a fresh
    // request rebuilds it on the new one.
    println!("=== switching System VM backend vz -> hv (restarts the VM) ===");
    switch_backend(&daemon, SystemVmBackend::Hv)?;
    println!("backend switch returned");

    println!("=== incarnation 2 (hv): export must be back ===");
    // Cache-immune host assertion: this container's data directory is created
    // by the *new* guest, so it cannot be served from the page cache or from
    // the stale mount that pointed at the dead one.
    docker(&["run", "-d", "--name", "post-switch", &image, "sleep", "300"])
        .context("running a container on the restarted VM")?;
    let id = docker(&["inspect", "--format", "{{.Id}}", "post-switch"])?
        .trim()
        .to_owned();
    if id.is_empty() {
        bail!("could not read the post-switch container id");
    }
    wait_for_path(&mount_dir.join("containers").join(&id), REMOUNT_TIMEOUT).with_context(|| {
        format!("container {id} created after the restart never appeared under the host mount")
    })?;
    println!(
        "OK: post-restart container data is readable through {}",
        mount_dir.display()
    );

    // And the mechanism itself: the new guest is running kernel nfsd because
    // the daemon asked it to, not because the agent starts one on its own.
    assert_guest_nfsd(&docker, &image, "after the switch")?;

    println!("=== cleanup ===");
    let _ = docker(&["rm", "-f", "post-switch"]);
    daemon.shutdown()?;
    Ok(())
}

/// Sends `SetSystemVmBackend`, which restarts the System VM.
fn switch_backend(daemon: &DaemonHandle, backend: SystemVmBackend) -> Result<()> {
    let socket = daemon.grpc_socket();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let channel = connect_unix(&socket).await?;
            SystemServiceClient::new(channel)
                .set_system_vm_backend(Request::new(SetSystemVmBackendRequest {
                    backend: backend as i32,
                }))
                .await
                .context("SetSystemVmBackend")?;
            Ok(())
        })
}

/// Asserts kernel nfsd is running in the guest, read from the guest's own
/// mount namespace. A `SANITY_OVERLAY` positive control rules out a probe that
/// is looking at the wrong namespace and reporting absence for the wrong reason.
fn assert_guest_nfsd(
    docker: &impl Fn(&[&str]) -> Result<String>,
    image: &str,
    when: &str,
) -> Result<()> {
    let script = r#"B=/bin/busybox
echo "NFSD_THREADS=$($B cat /proc/fs/nfsd/threads 2>/dev/null || echo MISSING)"
echo "EXPORT_BINDS=$($B grep -c 'arcbox/nfs-export' /proc/mounts 2>/dev/null || echo 0)"
echo "SANITY_OVERLAY=$($B grep -c 'overlay' /proc/mounts 2>/dev/null || echo 0)"
"#;
    let out = docker(&[
        "run",
        "--rm",
        "--privileged",
        "--pid=host",
        image,
        "nsenter",
        "-t",
        "1",
        "-m",
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        script,
    ])
    .with_context(|| format!("nsenter guest nfsd probe {when}"))?;
    println!("{out}");

    let field = |key: &str| -> String {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or("")
            .trim()
            .to_string()
    };

    if field("SANITY_OVERLAY").parse::<u32>().unwrap_or(0) == 0 {
        bail!("sanity control failed {when}: no overlay mount in the guest mount namespace");
    }
    let threads = field("NFSD_THREADS");
    if threads.is_empty() || threads == "MISSING" || threads.starts_with('0') {
        bail!("guest has no nfsd threads {when} (threads={threads:?})");
    }
    if field("EXPORT_BINDS") == "0" {
        bail!("guest has no export bind mount {when}");
    }
    println!("OK: guest nfsd is running {when} (threads={threads})");
    Ok(())
}

/// Polls until `path` exists, or the deadline passes.
fn wait_for_path(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{} did not appear within {timeout:?}", path.display());
        }
        thread::sleep(Duration::from_millis(500));
    }
}
