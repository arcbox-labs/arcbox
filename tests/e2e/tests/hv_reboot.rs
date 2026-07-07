//! End-to-end guest-initiated reboot on the HV backend (ABX-402).
//!
//! Boots the System VM through a real daemon on the custom-HV backend and
//! issues `reboot -f` inside the guest. The daemon's lifecycle actor must
//! observe the PSCI SYSTEM_RESET verdict (2s liveness poll) and reboot the
//! VM in place: the guest comes back with a new kernel `boot_id`, the
//! agent reconnects, and the Docker path recovers — all within one daemon
//! process. A final `poweroff -f` guards the opposite verdict: SYSTEM_OFF
//! must stop the VM without triggering a reboot.
//!
//! Both the trigger and the observation ride the Docker path, so no guest
//! shell is needed (the debug-console rcS shell exists only on newer
//! rootfs generations): `/proc/sys/kernel/random/boot_id` is kernel-global
//! (not namespaced), so a container reads the guest's boot identity, and a
//! `--privileged --pid=host` container's `reboot(2)` reboots the guest
//! kernel — `--pid=host` is load-bearing, since in a non-initial PID
//! namespace `reboot(2)` merely kills that namespace's init.

use std::path::Path;
use std::sync::Once;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::docker::docker_output;
use arcbox_e2e::metrics::RunMetrics;
use tracing_subscriber::EnvFilter;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Budget for the full round trip after `reboot -f`: ≤2s liveness-poll
/// detection + in-place VMM teardown + fresh HV boot + agent reconnect +
/// runtime restart + Docker proxy reconciliation.
const REBOOT_TIMEOUT: Duration = Duration::from_secs(180);
/// Watch window after `poweroff -f` during which no new boot identity may
/// appear. Sized well above the observed reboot round trip, so a misread
/// SYSTEM_OFF would surface within it.
const POWEROFF_QUIET: Duration = Duration::from_secs(90);
/// Ceiling for one docker CLI invocation.
const DOCKER_ATTEMPT: Duration = Duration::from_secs(30);

#[test]
#[ignore = "boots an HV System VM through a real daemon and reboots it from inside"]
fn guest_reboot_is_detected_and_rebooted_in_place() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-hv-reboot-")
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

    let mut metrics = RunMetrics::new("hv_reboot", Some("hv"));
    let result = scenario(&mut daemon, data_dir.path(), &mut metrics);
    metrics.passed = result.is_ok();
    if let Err(error) = metrics.write(Some(data_dir.path())) {
        tracing::warn!("writing run metrics failed: {error:#}");
    }
    if result.is_err() {
        match daemon.dump_virtio_debug() {
            Ok(path) => tracing::warn!(path = %path.display(), "virtio debug snapshot captured"),
            Err(error) => tracing::warn!("virtio debug dump failed: {error:#}"),
        }
        let kept = data_dir.keep();
        tracing::warn!(path = %kept.display(), "preserving test directory");
    }
    result
}

fn scenario(daemon: &mut DaemonHandle, data_dir: &Path, metrics: &mut RunMetrics) -> Result<()> {
    metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;

    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());

    metrics.time("docker_baseline", || {
        docker_output(data_dir, &["pull", &image], Duration::from_secs(90)).context("docker pull")
    })?;

    let first = metrics.time("first_boot_id", || {
        guest_boot_id(data_dir, &image).context("capturing the pre-reboot boot identity")
    })?;
    tracing::info!(boot_id = %first, "guest boot identity captured");

    // The trigger. The docker call dies with the guest (the container never
    // exits normally), so its error is expected and only logged.
    let trigger = docker_output(
        data_dir,
        &[
            "run",
            "--rm",
            "--privileged",
            "--pid=host",
            &image,
            "reboot",
            "-f",
        ],
        DOCKER_ATTEMPT,
    );
    tracing::info!(outcome = ?trigger.map(|o| o.trim().to_owned()), "issued reboot -f inside the guest");

    let second = metrics.time("reboot_roundtrip", || {
        wait_for_new_boot_id(data_dir, &image, &first, REBOOT_TIMEOUT)
    })?;
    tracing::info!(boot_id = %second, "guest rebooted in place and the docker path recovered");

    // Guard the opposite verdict: SYSTEM_OFF must never read as a reboot.
    metrics.time("poweroff_guard", || -> Result<()> {
        let trigger = docker_output(
            data_dir,
            &["run", "--rm", "--privileged", "--pid=host", &image, "poweroff", "-f"],
            DOCKER_ATTEMPT,
        );
        tracing::info!(outcome = ?trigger.map(|o| o.trim().to_owned()), "issued poweroff -f inside the guest");

        let quiet_until = Instant::now() + POWEROFF_QUIET;
        while Instant::now() < quiet_until {
            match guest_boot_id(data_dir, &image) {
                Ok(id) if id != second => {
                    bail!("SYSTEM_OFF was answered by a reboot (boot_id {id})")
                }
                Ok(_) => {} // still going down
                Err(error) => tracing::debug!("guest unreachable (expected): {error:#}"),
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        // After the window the guest must actually be down.
        match guest_boot_id(data_dir, &image) {
            Ok(id) if id == second => {
                bail!("guest still running {POWEROFF_QUIET:?} after poweroff -f")
            }
            Ok(id) => bail!("SYSTEM_OFF was answered by a reboot (boot_id {id})"),
            Err(_) => {
                tracing::info!("SYSTEM_OFF honored: guest stayed down");
                Ok(())
            }
        }
    })?;

    // The daemon itself must have survived the whole dance.
    let snapshot = daemon
        .dump_virtio_debug()
        .context("daemon gRPC no longer answering after the poweroff guard")?;
    tracing::info!(path = %snapshot.display(), "daemon alive; final virtio snapshot written");
    Ok(())
}

/// Reads the guest kernel's boot identity through the Docker path.
fn guest_boot_id(data_dir: &Path, image: &str) -> Result<String> {
    let out = docker_output(
        data_dir,
        &[
            "run",
            "--rm",
            image,
            "cat",
            "/proc/sys/kernel/random/boot_id",
        ],
        DOCKER_ATTEMPT,
    )?;
    out.lines()
        .map(str::trim)
        .find(|line| is_boot_id(line))
        .map(str::to_owned)
        .with_context(|| format!("no boot_id in docker output: {out}"))
}

/// A kernel boot_id: a lowercase hyphenated UUID.
fn is_boot_id(s: &str) -> bool {
    s.len() == 36
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'))
}

/// Polls the guest's boot identity until it differs from `previous`,
/// tolerating the unreachable window while the VM reboots in place and
/// the runtime recovers.
fn wait_for_new_boot_id(
    data_dir: &Path,
    image: &str,
    previous: &str,
    timeout: Duration,
) -> Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        match guest_boot_id(data_dir, image) {
            Ok(id) if id != previous => return Ok(id),
            Ok(_) => tracing::debug!("guest still reports the old boot identity"),
            Err(error) => tracing::debug!("docker path not recovered yet: {error:#}"),
        }
        if Instant::now() >= deadline {
            bail!("guest did not come back with a new boot identity within {timeout:?}");
        }
        std::thread::sleep(Duration::from_secs(3));
    }
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
