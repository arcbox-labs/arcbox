use std::{
    env,
    fs::{self},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tempfile::TempDir;
use toml_edit::DocumentMut;
use tracing::{info, warn};

use crate::daemon::{DaemonConfig, DaemonHandle};
use crate::metrics::RunMetrics;
use crate::{env_flag, repo_root};

const DOCKER_TIMEOUT: Duration = Duration::from_secs(30);
/// Generous ceiling for the daemon's full startup (asset seeding + VM boot
/// + agent readiness), observed via `WatchSetupStatus`.
const READY_TIMEOUT: Duration = Duration::from_secs(180);

pub struct BootAssetsConfig {
    pub skip_build: bool,
    pub keep_test_dir: bool,
    pub version: Option<String>,
    pub guest_docker_vsock_port: u32,
    /// System VM backend for the daemon under test. `None` leaves the
    /// daemon's own default (VZ) in effect.
    pub backend: Option<arcbox_vmm::VmBackend>,
    /// Container image the lifecycle tests pull and run. Override via
    /// `ARCBOX_E2E_IMAGE` (e.g. a mirror ref) on networks where
    /// docker.io is unreachable from the guest.
    pub image: String,
}

impl BootAssetsConfig {
    pub fn from_env() -> Result<Self> {
        let backend = match env::var("ARCBOX_VM_BACKEND") {
            Ok(value) => Some(
                arcbox_vmm::VmBackend::from_str_ascii(&value)
                    .with_context(|| format!("invalid ARCBOX_VM_BACKEND '{value}'"))?,
            ),
            Err(env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("reading ARCBOX_VM_BACKEND"),
        };
        Ok(Self {
            skip_build: env_flag("SKIP_BUILD"),
            keep_test_dir: env_flag("KEEP_TEST_DIR"),
            version: env::var("ARCBOX_BOOT_ASSET_VERSION").ok(),
            guest_docker_vsock_port: match env::var("ARCBOX_GUEST_DOCKER_VSOCK_PORT") {
                Ok(value) => value
                    .parse()
                    .context("parsing ARCBOX_GUEST_DOCKER_VSOCK_PORT")?,
                Err(env::VarError::NotPresent) => 2375,
                Err(error) => return Err(error).context("reading ARCBOX_GUEST_DOCKER_VSOCK_PORT"),
            },
            backend,
            image: env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned()),
        })
    }
}

struct TestContext {
    root: PathBuf,
    temp_dir: Option<TempDir>,
    test_dir: PathBuf,
    version: String,
    label: String,
    guest_docker_vsock_port: u32,
    backend: Option<arcbox_vmm::VmBackend>,
    image: String,
    keep_test_dir: bool,
    daemon: Option<DaemonHandle>,
}

impl TestContext {
    fn new(config: BootAssetsConfig) -> Result<Self> {
        let root = repo_root();
        let version = match config.version {
            Some(version) => version,
            None => boot_version(&root.join("assets.lock"))?,
        };
        let temp_dir = tempfile::Builder::new()
            .prefix("arcbox-boot-test-")
            .tempdir()
            .context("creating boot assets test directory")?;
        let test_dir = temp_dir.path().to_owned();
        let label = format!("arcbox.e2e.run={}", std::process::id());

        Ok(Self {
            root,
            temp_dir: Some(temp_dir),
            test_dir,
            version,
            label,
            guest_docker_vsock_port: config.guest_docker_vsock_port,
            backend: config.backend,
            image: config.image,
            keep_test_dir: config.keep_test_dir,
            daemon: None,
        })
    }

    fn docker_host(&self) -> String {
        crate::docker::docker_host(&self.test_dir)
    }

    fn docker_output(&self, args: &[&str], timeout: Duration) -> Result<String> {
        crate::docker::docker_output(&self.test_dir, args, timeout)
    }

    fn docker_ignore(&self, args: &[String]) {
        crate::docker::docker_ignore(&self.test_dir, args);
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        info!("cleaning up");
        if let Ok(output) = Command::new("docker")
            .env("DOCKER_HOST", self.docker_host())
            .args(["ps", "-aq", "--filter"])
            .arg(format!("label={}", self.label))
            .output()
        {
            let ids = String::from_utf8_lossy(&output.stdout);
            let ids = ids
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if !ids.is_empty() {
                let mut args = vec!["rm".to_owned(), "-f".to_owned()];
                args.extend(ids);
                self.docker_ignore(&args);
            }
        }

        if let Some(daemon) = self.daemon.take() {
            match daemon.shutdown() {
                Ok(status) => info!(%status, "daemon stopped"),
                Err(error) => warn!("daemon shutdown failed: {error:#}"),
            }
        }

        if self.keep_test_dir {
            if let Some(temp_dir) = self.temp_dir.take() {
                let path = temp_dir.keep();
                warn!(path = %path.display(), "preserving test directory");
            }
        }
    }
}

/// Builds the release binaries the daemon-level scenarios spawn.
pub fn build_release_binaries() -> Result<()> {
    info!("building latest release binaries");
    let shell = xshell::Shell::new()?;
    shell.change_dir(repo_root());
    xshell::cmd!(
        shell,
        "cargo build --release -p arcbox-cli -p arcbox-daemon"
    )
    .run()?;
    Ok(())
}

pub fn run(config: BootAssetsConfig) -> Result<()> {
    info!(backend = ?config.backend, "starting boot assets integration test");

    if !config.skip_build {
        build_release_binaries()?;
    }

    let backend_label = config.backend.map(arcbox_vmm::VmBackend::as_str);
    let mut metrics = RunMetrics::new("boot_assets", backend_label);
    let mut ctx = TestContext::new(config)?;
    let result = run_scenario(&mut ctx, &mut metrics);
    metrics.passed = result.is_ok();
    match metrics.write(Some(&ctx.test_dir)) {
        Ok(paths) => {
            for path in paths {
                info!(path = %path.display(), "run metrics written");
            }
        }
        Err(error) => warn!("writing run metrics failed: {error:#}"),
    }
    if result.is_err() {
        // Preserve the workspace (daemon + guest logs, disk images) so the
        // failure can be inspected; the path is logged by TestContext::drop.
        ctx.keep_test_dir = true;
        // Best-effort virtio queue snapshot while the daemon still runs —
        // ring wedges are invisible once the VM is gone.
        if let Some(daemon) = &ctx.daemon {
            match daemon.dump_virtio_debug() {
                Ok(path) => info!(path = %path.display(), "virtio debug snapshot captured"),
                Err(error) => warn!("virtio debug dump failed: {error:#}"),
            }
        }
    }
    result
}

fn run_scenario(ctx: &mut TestContext, metrics: &mut RunMetrics) -> Result<()> {
    check_prerequisites(ctx)?;
    setup_test_env(ctx)?;
    metrics.time("daemon_ready", || start_daemon(ctx))?;
    metrics.time("nfs_export", || {
        verify_nfs_export(ctx).context("guest data NFS export read-through test")
    })?;

    metrics.time("image_pull", || pull_image(ctx))?;
    metrics.time("container_create_smoke", || smoke_container_create(ctx))?;

    metrics.time("container_run", || {
        test_container_run(ctx).context("container run lifecycle test")
    })?;
    metrics.time("background_container", || {
        test_background_container(ctx).context("background container lifecycle test")
    })?;
    metrics.time("docker_logs", || {
        test_docker_logs(ctx).context("docker logs lifecycle test")
    })?;
    metrics.time("docker_exec", || {
        test_docker_exec(ctx).context("docker exec lifecycle test")
    })?;
    metrics.time("docker_stop_rm", || {
        test_stop_rm(ctx).context("docker stop/rm lifecycle test")
    })?;

    info!(daemon_log = %ctx.test_dir.join("log/daemon.log").display(), "boot assets integration test passed");
    Ok(())
}

/// Verifies the guest-data NFS export end to end by reading the guest's docker
/// data root through the host mount the daemon established (isolated at
/// `<data_dir>/ArcBox` via `ARCBOX_HOST_MOUNT_DIR`). Registry-independent — it
/// reads data dockerd creates on startup, so it does not need a pulled image.
fn verify_nfs_export(ctx: &TestContext) -> Result<()> {
    info!("[test] nfs export: read guest docker data through the host ~/ArcBox mount");
    let mount_dir = ctx.test_dir.join("ArcBox");
    wait_for_nfs_mount(&mount_dir)?;

    // Strongest signal: read a real guest file's contents through NFS. dockerd
    // writes engine-id (0644) on startup; fall back to a directory read-through
    // in case a future dockerd stops writing it. The agent ends the NFSv4
    // grace period as soon as nfsd starts, so opens normally succeed at once;
    // the window covers the 10s fallback grace if that ever fails, plus
    // attribute-cache propagation.
    let engine_id = mount_dir.join("engine-id");
    if let Ok(content) = read_file_with_retry(&engine_id, Duration::from_secs(20)) {
        if content.trim().is_empty() {
            bail!("engine-id read through ~/ArcBox was empty");
        }
        info!(path = %engine_id.display(), "nfs export file read-through OK");
        return Ok(());
    }

    let entries = fs::read_dir(&mount_dir)
        .with_context(|| format!("reading {} via NFS", mount_dir.display()))?
        .count();
    if entries < 2 {
        bail!("~/ArcBox export listed only {entries} entries; expected the docker data root");
    }
    info!(entries, "nfs export directory read-through OK");
    Ok(())
}

/// Waits until the daemon's NFS mount is populated with docker's data root.
fn wait_for_nfs_mount(mount_dir: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if mount_dir.join("volumes").is_dir() || mount_dir.join("overlay2").is_dir() {
            info!(mount = %mount_dir.display(), "host NFS mount is populated");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "guest data NFS mount not populated at {} within timeout",
                mount_dir.display()
            );
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Reads `path`, retrying briefly while the just-written file propagates
/// through the NFS attribute cache.
fn read_file_with_retry(path: &Path, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::read_to_string(path) {
            Ok(content) => return Ok(content),
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(300)),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", path.display()));
            }
        }
    }
}

pub fn boot_version(lockfile: &Path) -> Result<String> {
    let text = fs::read_to_string(lockfile)
        .with_context(|| format!("reading asset lockfile {}", lockfile.display()))?;
    let doc = text
        .parse::<DocumentMut>()
        .with_context(|| format!("parsing {}", lockfile.display()))?;
    doc["boot"]["version"]
        .as_str()
        .map(str::to_owned)
        .context("assets.lock is missing [boot].version")
}

fn check_prerequisites(ctx: &TestContext) -> Result<()> {
    info!("checking prerequisites");
    let daemon = ctx.root.join("target/release/arcbox-daemon");
    if !daemon.is_file() {
        bail!("arcbox-daemon binary not found at {}", daemon.display());
    }
    info!("prerequisites OK");
    Ok(())
}

/// Resolves the boot asset version for a test run: the
/// `ARCBOX_BOOT_ASSET_VERSION` override, or `assets.lock`.
pub fn resolve_boot_version(root: &Path) -> Result<String> {
    match env::var("ARCBOX_BOOT_ASSET_VERSION") {
        Ok(version) => Ok(version),
        Err(_) => boot_version(&root.join("assets.lock")),
    }
}

/// Stages the development boot assets under `<data_dir>/boot/<version>`.
///
/// A daemon pointed at `data_dir` then boots without downloading.
/// Refreshes `boot-assets/dev` via xtask if incomplete.
pub fn stage_dev_boot_assets(root: &Path, data_dir: &Path, version: &str) -> Result<()> {
    let test_boot_dir = data_dir.join("boot").join(version);
    fs::create_dir_all(&test_boot_dir)
        .with_context(|| format!("creating {}", test_boot_dir.display()))?;

    let dev_boot_dir = root.join("boot-assets/dev");
    if !dev_boot_dir.join("kernel").is_file()
        || !dev_boot_dir.join("rootfs.erofs").is_file()
        || !dev_boot_dir.join("manifest.json").is_file()
    {
        warn!("development boot assets incomplete; refreshing");
        let shell = xshell::Shell::new()?;
        shell.change_dir(root);
        xshell::cmd!(shell, "cargo xtask dev boot-assets --version {version}").run()?;
    }

    copy_file(&dev_boot_dir.join("kernel"), &test_boot_dir.join("kernel"))?;
    copy_file(
        &dev_boot_dir.join("rootfs.erofs"),
        &test_boot_dir.join("rootfs.erofs"),
    )?;
    copy_file(
        &dev_boot_dir.join("manifest.json"),
        &test_boot_dir.join("manifest.json"),
    )?;

    // The daemon installs `boot/<version>/arcbox-agent` into `bin/` at
    // startup (its boot-cache fallback; the bundle path doesn't apply to
    // a bare test daemon, and the CDN ships no standalone agent). Stage
    // the freshest agent found locally: the dev tree, a local
    // cross-compile, or the one an installed ArcBox app seeded — newest
    // mtime wins, since a stale agent fails the boot in confusing ways.
    if !stage_freshest_binary(root, &dev_boot_dir, "arcbox-agent", &test_boot_dir)? {
        warn!(
            "no arcbox-agent found (looked in boot-assets/dev, musl target, ~/.arcbox/bin); \
             the daemon will fail at runtime init"
        );
    }

    // The sandbox service execs the microVM init at `/arcbox/bin/vm-agent`
    // (= `<data_dir>/bin/vm-agent` through the VirtioFS data-dir mount), so
    // stage it straight into the test data dir. Missing vm-agent degrades
    // only sandbox scenarios, not the Docker lifecycle.
    if !stage_freshest_binary(root, &dev_boot_dir, "vm-agent", &data_dir.join("bin"))? {
        warn!("no vm-agent found; sandbox create will fail inside the guest");
    }

    // Seed the guest runtime binaries from an installed ArcBox so a bare test
    // daemon boots without reaching the CDN. Best-effort: prepare_binaries
    // downloads anything still missing.
    stage_runtime_binaries(&data_dir.join("runtime/bin"));

    info!(dev_boot_dir = %dev_boot_dir.display(), "using development boot assets");
    Ok(())
}

/// Copies every guest runtime binary from the installed ArcBox's data dir into
/// the test data dir, so the daemon's binary prepare finds them locally instead
/// of downloading. Best-effort — anything still missing or version-mismatched
/// falls back to the daemon's own download.
fn stage_runtime_binaries(dest_dir: &Path) {
    let src_dir = arcbox_constants::paths::ArcboxProfile::Production
        .default_data_dir()
        .join("runtime/bin");
    let Ok(entries) = fs::read_dir(&src_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let src = entry.path();
        if src.is_file() {
            if let Err(error) = copy_file(&src, &dest_dir.join(entry.file_name())) {
                warn!(binary = %entry.file_name().to_string_lossy(), %error, "failed to stage runtime binary");
            }
        }
    }
}

/// Copy the newest-mtime copy of `name` (dev boot dir, musl target dir, or an
/// installed ArcBox data dir) into `dest_dir`. Returns false when no
/// candidate exists.
fn stage_freshest_binary(
    root: &Path,
    dev_boot_dir: &Path,
    name: &str,
    dest_dir: &Path,
) -> Result<bool> {
    let candidates = [
        dev_boot_dir.join(name),
        root.join("target/aarch64-unknown-linux-musl/release")
            .join(name),
        arcbox_constants::paths::ArcboxProfile::Production
            .default_data_dir()
            .join("bin")
            .join(name),
    ];
    let freshest = candidates
        .iter()
        .filter_map(|path| {
            let mtime = fs::metadata(path).ok()?.modified().ok()?;
            Some((path, mtime))
        })
        .max_by_key(|(_, mtime)| *mtime)
        .map(|(path, _)| path);
    match freshest {
        Some(binary) => {
            copy_file(binary, &dest_dir.join(name))?;
            info!(binary = %binary.display(), name, "staged guest binary");
            Ok(true)
        }
        None => Ok(false),
    }
}

fn copy_file(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory {}", parent.display()))?;
    }
    fs::copy(from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    Ok(())
}

fn setup_test_env(ctx: &TestContext) -> Result<()> {
    info!(test_dir = %ctx.test_dir.display(), "setting up test environment");
    stage_dev_boot_assets(&ctx.root, &ctx.test_dir, &ctx.version)
}

/// Spawns the daemon and blocks until it reports READY on the setup
/// status stream — VM booted, agent up, services started.
fn start_daemon(ctx: &mut TestContext) -> Result<()> {
    info!(backend = ?ctx.backend, "starting daemon");
    let mut env = vec![("ARCBOX_BOOT_ASSET_VERSION".to_owned(), ctx.version.clone())];
    if let Some(backend) = ctx.backend {
        // First-boot backend selection; the data dir is fresh, so no
        // persisted machine backend can override it.
        env.push(("ARCBOX_VM_BACKEND".to_owned(), backend.as_str().to_owned()));
    }
    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: ctx.root.join("target/release/arcbox-daemon"),
        data_dir: ctx.test_dir.clone(),
        args: vec![
            "--guest-docker-vsock-port".to_owned(),
            ctx.guest_docker_vsock_port.to_string(),
        ],
        env,
    })?;

    let started = Instant::now();
    daemon.wait_ready_blocking(READY_TIMEOUT)?;
    info!(
        elapsed_seconds = started.elapsed().as_secs(),
        "daemon is ready"
    );
    ctx.daemon = Some(daemon);
    Ok(())
}

fn pull_image(ctx: &TestContext) -> Result<()> {
    info!(image = %ctx.image, "pulling test image");
    match ctx.docker_output(&["pull", &ctx.image], Duration::from_secs(90)) {
        Ok(output) => {
            fs::write(ctx.test_dir.join("pull.log"), output)
                .with_context(|| format!("writing {}", ctx.test_dir.join("pull.log").display()))?;
            info!("docker pull completed");
            Ok(())
        }
        Err(error) => {
            fs::write(ctx.test_dir.join("pull.log"), format!("{error:#}"))
                .with_context(|| format!("writing {}", ctx.test_dir.join("pull.log").display()))?;
            Err(error).context("docker pull")
        }
    }
}

/// First `docker create` against the ready daemon — exercises the full
/// API → runtime → guest agent path once before the lifecycle tests.
fn smoke_container_create(ctx: &TestContext) -> Result<()> {
    info!("creating container against the ready daemon");
    let cid = ctx
        .docker_output(
            &["create", "--label", &ctx.label, &ctx.image, "echo", "test"],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    info!(
        container_id = cid_prefix(&cid),
        "container create completed"
    );
    Ok(())
}

fn test_container_run(ctx: &TestContext) -> Result<()> {
    info!("[test] container run: docker run alpine echo hello");
    let cid = ctx
        .docker_output(
            &["create", "--label", &ctx.label, &ctx.image, "echo", "hello"],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    ctx.docker_output(&["start", &cid], DOCKER_TIMEOUT)?;
    ctx.docker_output(&["wait", &cid], DOCKER_TIMEOUT)?;
    let output = ctx.docker_output(&["logs", &cid], Duration::from_secs(10))?;
    remove_container(ctx, &cid);
    if output.contains("hello") {
        info!("container run OK");
        Ok(())
    } else {
        bail!("expected 'hello' in output, got: {output}");
    }
}

fn test_background_container(ctx: &TestContext) -> Result<()> {
    info!("[test] background container: docker run -d + docker ps");
    let cid = ctx
        .docker_output(
            &[
                "run", "-d", "--label", &ctx.label, &ctx.image, "sleep", "300",
            ],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    info!(
        container_id = cid_prefix(&cid),
        "started background container"
    );
    thread::sleep(Duration::from_secs(2));
    let running = ctx.docker_output(
        &["inspect", "-f", "{{.State.Running}}", &cid],
        Duration::from_secs(10),
    )?;
    remove_container(ctx, &cid);
    if running.trim() == "true" {
        info!("background container is running");
        Ok(())
    } else {
        bail!("container is not running (inspect output: {running})");
    }
}

fn test_docker_logs(ctx: &TestContext) -> Result<()> {
    info!("[test] docker logs: verify container output");
    let cid = ctx
        .docker_output(
            &[
                "run",
                "-d",
                "--label",
                &ctx.label,
                &ctx.image,
                "sh",
                "-c",
                "echo 'log-output-test'; sleep 10",
            ],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    info!(
        container_id = cid_prefix(&cid),
        "started log-test container"
    );

    let mut last_output = String::new();
    for _ in 0..10 {
        last_output = ctx.docker_output(&["logs", &cid], Duration::from_secs(10))?;
        if last_output.contains("log-output-test") {
            remove_container(ctx, &cid);
            info!("docker logs contains expected output");
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }

    remove_container(ctx, &cid);
    bail!("expected 'log-output-test' in logs, got: {last_output}");
}

fn test_docker_exec(ctx: &TestContext) -> Result<()> {
    info!("[test] docker exec: run command in running container");
    let cid = ctx
        .docker_output(
            &[
                "run", "-d", "--label", &ctx.label, &ctx.image, "sleep", "300",
            ],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    info!(
        container_id = cid_prefix(&cid),
        "started exec-test container"
    );
    thread::sleep(Duration::from_secs(2));
    let output = ctx.docker_output(&["exec", &cid, "ls", "/"], Duration::from_secs(10))?;
    remove_container(ctx, &cid);
    if output.contains("bin") || output.contains("etc") || output.contains("usr") {
        info!("docker exec ls / succeeded");
        Ok(())
    } else {
        bail!("docker exec ls / returned unexpected output: {output}");
    }
}

fn test_stop_rm(ctx: &TestContext) -> Result<()> {
    info!("[test] stop/rm: graceful stop and remove");
    let cid = ctx
        .docker_output(
            &[
                "run", "-d", "--label", &ctx.label, &ctx.image, "sleep", "300",
            ],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    info!(
        container_id = cid_prefix(&cid),
        "started stop-test container"
    );
    thread::sleep(Duration::from_secs(2));
    ctx.docker_output(&["stop", &cid], Duration::from_secs(15))?;
    info!("docker stop OK");
    ctx.docker_output(&["rm", &cid], Duration::from_secs(10))?;
    info!("docker rm OK");
    if Command::new("docker")
        .env("DOCKER_HOST", ctx.docker_host())
        .args(["inspect", &cid])
        .status()
        .is_ok_and(|status| status.success())
    {
        bail!("container still exists after rm: {cid}");
    }
    info!("container fully removed");
    Ok(())
}

fn remove_container(ctx: &TestContext, cid: &str) {
    ctx.docker_ignore(&["rm".to_owned(), "-f".to_owned(), cid.to_owned()]);
}

fn cid_prefix(cid: &str) -> &str {
    cid.get(..12).unwrap_or(cid)
}
