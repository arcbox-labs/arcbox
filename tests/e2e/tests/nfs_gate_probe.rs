//! ABX-426 negative validation — NOT part of the suite. Run manually:
//!   cargo test -p arcbox-e2e --test nfs_gate_probe -- --ignored --nocapture
//!
//! Proves the control inversion: a daemon started with `--no-mount-nfs` leaves
//! the guest running **no** nfsd at all — not merely an unmounted host side.
//! Before this change the agent brought the export up unconditionally on every
//! boot, so `--no-mount-nfs` still left kernel nfsd, rpc.mountd, and the export
//! bind alive in the guest.
//!
//! Method, on a real VZ boot: start a `--no-mount-nfs` daemon, let the runtime
//! start fully (dockerd up ⇒ the old unconditional export site would have run),
//! then nsenter the guest mount namespace and confirm nfsd is absent. A sanity
//! probe (the container's own overlay mount must be present) rules out a broken
//! grep. The positive direction — export up and readable — is covered by the
//! `boot_assets` suite's `verify_nfs_export`.

use std::env;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::docker::docker_output;
use arcbox_e2e::repo_root;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(120);

#[test]
#[ignore = "ABX-426 negative probe: boots a VM, needs registry access"]
fn nfs_gate_probe() -> Result<()> {
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
        .prefix("arcbox-nfs-gate-")
        .tempdir()?;
    let test_dir = temp.path().to_owned();
    stage_dev_boot_assets(&root, &test_dir, &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: test_dir.clone(),
        args: vec![
            "--no-mount-nfs".into(),
            "--guest-docker-vsock-port".into(),
            "2375".into(),
        ],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".into(), version),
            ("ARCBOX_DNS_PORT".into(), "5555".into()),
        ],
    })?;
    daemon.wait_ready_blocking(READY_TIMEOUT)?;

    let docker = |args: &[&str]| docker_output(&test_dir, args, DOCKER_TIMEOUT);

    // Run a container: this drives the runtime-start path to completion, i.e.
    // past the point where the agent used to set the export up unconditionally.
    println!("=== pull + run a container (drive runtime start to completion) ===");
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
        bail!("registry unreachable from guest; the probe needs a running container");
    }
    docker(&["run", "-d", "--name", "gate-live", &image, "sleep", "120"])?;

    // ---- inspect the guest: nfsd must be entirely absent ----
    println!("=== guest state (nsenter mount ns) ===");
    let script = r#"B=/bin/busybox
echo "NFSD_THREADS=$($B cat /proc/fs/nfsd/threads 2>/dev/null || echo MISSING)"
echo "MOUNTD=$($B pidof rpc.mountd 2>/dev/null || echo NONE)"
echo "EXPORT_BINDS=$($B grep -c 'arcbox/nfs-export' /proc/mounts 2>/dev/null || echo 0)"
echo "NFSD_PSEUDOFS=$($B grep -c ' nfsd ' /proc/mounts 2>/dev/null || echo 0)"
echo "SANITY_OVERLAY=$($B grep -c 'overlay' /proc/mounts 2>/dev/null || echo 0)"
"#;
    let out = docker(&[
        "run",
        "--rm",
        "--privileged",
        "--pid=host",
        &image,
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
    .context("nsenter guest state probe")?;
    println!("{out}");

    let field = |key: &str| -> String {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let nfsd_threads = field("NFSD_THREADS");
    let mountd = field("MOUNTD");
    let export_binds = field("EXPORT_BINDS");
    let nfsd_pseudofs = field("NFSD_PSEUDOFS");
    let sanity_overlay = field("SANITY_OVERLAY");

    // Positive control: the grep pipeline works and we are in the right ns.
    if sanity_overlay.parse::<u32>().unwrap_or(0) == 0 {
        bail!(
            "sanity control failed: no overlay mount seen in the guest — the probe is not \
             reading the guest mount namespace, so the nfsd-absence assertions are meaningless"
        );
    }

    // The assertions: nothing nfsd may exist.
    let mut failures = Vec::new();
    if !(nfsd_threads == "MISSING" || nfsd_threads == "0") {
        failures.push(format!("nfsd has running threads: {nfsd_threads}"));
    }
    if mountd != "NONE" {
        failures.push(format!("rpc.mountd is running (pid {mountd})"));
    }
    if export_binds != "0" {
        failures.push(format!("export bind mount present ({export_binds})"));
    }
    if nfsd_pseudofs != "0" {
        failures.push(format!("nfsd pseudo-fs is mounted ({nfsd_pseudofs})"));
    }
    if !failures.is_empty() {
        bail!(
            "--no-mount-nfs still left nfsd running in the guest: {}",
            failures.join("; ")
        );
    }
    println!(
        "OK: guest has no nfsd under --no-mount-nfs \
         (threads={nfsd_threads}, mountd={mountd}, export_binds={export_binds}, \
         nfsd_pseudofs={nfsd_pseudofs}; overlay sanity={sanity_overlay})"
    );

    // Host side: DaemonHandle::spawn points ARCBOX_HOST_MOUNT_DIR at
    // <data_dir>/ArcBox, so a daemon that ignored --no-mount-nfs would populate
    // this isolated dir (never the developer's real ~/ArcBox). It must stay empty.
    let arcbox = test_dir.join("ArcBox");
    let populated = arcbox.join("volumes").is_dir() || arcbox.join("overlay2").is_dir();
    if populated {
        bail!("host ~/ArcBox unexpectedly populated under --no-mount-nfs");
    }
    println!("OK: host {} is not a populated NFS mount", arcbox.display());

    println!("=== cleanup ===");
    let _ = docker(&["rm", "-f", "gate-live"]);
    daemon.shutdown()?;
    Ok(())
}
