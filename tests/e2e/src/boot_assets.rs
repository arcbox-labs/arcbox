use std::{
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use tempfile::TempDir;
use toml_edit::DocumentMut;

use crate::{BootAssetsArgs, repo_root};

const DOCKER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum TestResult {
    Pass,
    Fail,
    Skip,
}

impl TestResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

struct Results {
    vm_boot: TestResult,
    vsock: TestResult,
    agent: TestResult,
    container_create: TestResult,
    container_run: TestResult,
    background_container: TestResult,
    docker_logs: TestResult,
    docker_exec: TestResult,
    stop_rm: TestResult,
}

impl Results {
    fn new() -> Self {
        Self {
            vm_boot: TestResult::Skip,
            vsock: TestResult::Skip,
            agent: TestResult::Skip,
            container_create: TestResult::Skip,
            container_run: TestResult::Skip,
            background_container: TestResult::Skip,
            docker_logs: TestResult::Skip,
            docker_exec: TestResult::Skip,
            stop_rm: TestResult::Skip,
        }
    }

    fn entries(&self) -> [(&'static str, TestResult); 9] {
        [
            ("VM Boot", self.vm_boot),
            ("vsock", self.vsock),
            ("Agent", self.agent),
            ("Container Create", self.container_create),
            ("Container Run", self.container_run),
            ("Background Container", self.background_container),
            ("Docker Logs", self.docker_logs),
            ("Docker Exec", self.docker_exec),
            ("Stop/Rm", self.stop_rm),
        ]
    }
}

struct TestContext {
    root: PathBuf,
    temp_dir: Option<TempDir>,
    test_dir: PathBuf,
    version: String,
    label: String,
    guest_docker_vsock_port: u32,
    keep_test_dir: bool,
    daemon: Option<Child>,
}

impl TestContext {
    fn new(args: BootAssetsArgs) -> Result<Self> {
        let root = repo_root();
        let version = match args.version {
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
            guest_docker_vsock_port: args.guest_docker_vsock_port,
            keep_test_dir: args.keep_test_dir,
            daemon: None,
        })
    }

    fn docker_host(&self) -> String {
        format!("unix://{}", self.test_dir.join("docker.sock").display())
    }

    fn docker_output(&self, args: &[&str], timeout: Duration) -> Result<String> {
        let output = run_with_timeout(
            Command::new("docker")
                .env("DOCKER_HOST", self.docker_host())
                .args(args),
            timeout,
        )?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            Ok(format!("{stdout}{stderr}"))
        } else {
            bail!(
                "docker {} failed with {}\n{}{}",
                args.join(" "),
                output.status,
                stdout,
                stderr
            );
        }
    }

    fn docker_ignore(&self, args: &[String]) {
        let _ = Command::new("docker")
            .env("DOCKER_HOST", self.docker_host())
            .args(args)
            .status();
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        println!("[INFO] Cleaning up...");
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

        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }

        if self.keep_test_dir {
            if let Some(temp_dir) = self.temp_dir.take() {
                let path = temp_dir.keep();
                println!("[WARN] KEEP_TEST_DIR set, preserving: {}", path.display());
            }
        }
    }
}

pub fn run(args: BootAssetsArgs) -> Result<()> {
    println!("==========================================");
    println!("ArcBox Boot Assets Integration Test");
    println!("==========================================");
    println!();

    let args = BootAssetsArgs {
        skip_build: args.skip_build || env_flag("SKIP_BUILD"),
        keep_test_dir: args.keep_test_dir || env_flag("KEEP_TEST_DIR"),
        ..args
    };

    if !args.skip_build {
        println!("[INFO] Building latest release binaries...");
        let shell = xshell::Shell::new()?;
        shell.change_dir(repo_root());
        xshell::cmd!(
            shell,
            "cargo build --release -p arcbox-cli -p arcbox-daemon"
        )
        .run()?;
    }

    let mut ctx = TestContext::new(args)?;
    check_prerequisites(&ctx)?;
    setup_test_env(&ctx)?;
    start_daemon(&mut ctx)?;

    let mut results = Results::new();

    println!("[INFO] Pulling alpine image...");
    match ctx.docker_output(&["pull", "alpine:latest"], Duration::from_secs(90)) {
        Ok(output) => {
            fs::write(ctx.test_dir.join("pull.log"), output)
                .with_context(|| format!("writing {}", ctx.test_dir.join("pull.log").display()))?;
            println!("[INFO] docker pull: OK");
        }
        Err(error) => {
            fs::write(ctx.test_dir.join("pull.log"), format!("{error:#}"))
                .with_context(|| format!("writing {}", ctx.test_dir.join("pull.log").display()))?;
            println!("[ERROR] docker pull failed");
            print_summary(&ctx, &results)?;
            return Err(error);
        }
    }

    println!("[INFO] Creating container (triggers VM boot)...");
    let container_id_path = ctx.test_dir.join("container_id");
    let container_err_path = ctx.test_dir.join("container_create.err");
    let mut create = Command::new("docker")
        .env("DOCKER_HOST", ctx.docker_host())
        .args(["create", "--label", &ctx.label, "alpine", "echo", "test"])
        .stdout(File::create(&container_id_path)?)
        .stderr(File::create(&container_err_path)?)
        .spawn()
        .context("starting docker create")?;

    if wait_for_agent(&ctx)? {
        results.vm_boot = TestResult::Pass;
        results.vsock = TestResult::Pass;
        results.agent = TestResult::Pass;
        if create.wait()?.success() {
            let cid = fs::read_to_string(&container_id_path)
                .unwrap_or_default()
                .trim()
                .to_owned();
            println!("[INFO] container create: OK (ID: {})", cid_prefix(&cid));
            results.container_create = TestResult::Pass;
        } else {
            println!("[WARN] container create: FAILED");
            results.container_create = TestResult::Fail;
        }
    } else {
        results.vm_boot = TestResult::Fail;
        results.vsock = TestResult::Fail;
        results.agent = TestResult::Fail;
        let _ = create.kill();
        let _ = create.wait();
        print_summary(&ctx, &results)?;
        bail!("agent connection timeout");
    }

    println!();
    println!("[INFO] === Container Lifecycle Tests (Phase 1.2 / 1.4) ===");
    println!();

    results.container_run = pass_fail(test_container_run(&ctx));
    results.background_container = pass_fail(test_background_container(&ctx));
    results.docker_logs = pass_fail(test_docker_logs(&ctx));
    results.docker_exec = pass_fail(test_docker_exec(&ctx));
    results.stop_rm = pass_fail(test_stop_rm(&ctx));

    print_summary(&ctx, &results)?;
    if results
        .entries()
        .iter()
        .any(|(_, result)| matches!(result, TestResult::Fail))
    {
        bail!("boot assets integration test failed");
    }
    Ok(())
}

fn env_flag(name: &str) -> bool {
    env::var(name).is_ok_and(|value| {
        value.is_empty()
            || matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
    })
}

fn boot_version(lockfile: &Path) -> Result<String> {
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
    println!("[INFO] Checking prerequisites...");
    let daemon = ctx.root.join("target/release/arcbox-daemon");
    if !daemon.is_file() {
        bail!("arcbox-daemon binary not found at {}", daemon.display());
    }

    let output = Command::new("codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(&daemon)
        .output()
        .with_context(|| format!("reading entitlements from {}", daemon.display()))?;
    let entitlements = String::from_utf8_lossy(&output.stderr);
    if !entitlements.contains("com.apple.security.virtualization") {
        println!("[WARN] Binary not signed with virtualization entitlement. Signing...");
        let entitlements_file = ctx.root.join("bundle/arcbox.entitlements");
        let status = Command::new("codesign")
            .arg("--entitlements")
            .arg(&entitlements_file)
            .args(["--force", "-s", "-"])
            .arg(&daemon)
            .status()
            .with_context(|| format!("signing {}", daemon.display()))?;
        if !status.success() {
            bail!("codesign failed for {}", daemon.display());
        }
    }

    println!("[INFO] Prerequisites OK");
    Ok(())
}

fn prepare_dev_boot_assets(ctx: &TestContext) -> Result<()> {
    let shell = xshell::Shell::new()?;
    shell.change_dir(&ctx.root);
    let version = &ctx.version;
    xshell::cmd!(shell, "cargo xtask dev boot-assets --version {version}").run()?;
    Ok(())
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
    println!(
        "[INFO] Setting up test environment: {}",
        ctx.test_dir.display()
    );
    let test_boot_dir = ctx.test_dir.join("boot").join(&ctx.version);
    fs::create_dir_all(&test_boot_dir)
        .with_context(|| format!("creating {}", test_boot_dir.display()))?;

    let dev_boot_dir = ctx.root.join("boot-assets/dev");
    if !dev_boot_dir.join("kernel").is_file()
        || !dev_boot_dir.join("rootfs.erofs").is_file()
        || !dev_boot_dir.join("manifest.json").is_file()
    {
        println!("[WARN] Development boot assets incomplete, refreshing...");
        prepare_dev_boot_assets(ctx)?;
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
    println!(
        "[INFO] Using development boot assets from {}",
        dev_boot_dir.display()
    );
    Ok(())
}

fn start_daemon(ctx: &mut TestContext) -> Result<()> {
    println!("[INFO] Starting daemon...");
    let log = File::create(ctx.test_dir.join("daemon.log"))?;
    let stderr = log.try_clone()?;
    let daemon = Command::new(ctx.root.join("target/release/arcbox-daemon"))
        .env("ARCBOX_BOOT_ASSET_VERSION", &ctx.version)
        .arg("--data-dir")
        .arg(&ctx.test_dir)
        .arg("--socket")
        .arg(ctx.test_dir.join("docker.sock"))
        .arg("--guest-docker-vsock-port")
        .arg(ctx.guest_docker_vsock_port.to_string())
        .stdout(log)
        .stderr(stderr)
        .spawn()
        .context("starting arcbox-daemon")?;
    let pid = daemon.id();
    fs::write(ctx.test_dir.join("daemon.pid"), pid.to_string())?;
    ctx.daemon = Some(daemon);
    thread::sleep(Duration::from_secs(2));

    if let Some(daemon) = ctx.daemon.as_mut() {
        if let Some(status) = daemon.try_wait()? {
            println!("[ERROR] Daemon failed to start");
            print_file(&ctx.test_dir.join("daemon.log"));
            bail!("arcbox-daemon exited with {status}");
        }
    }

    println!("[INFO] Daemon started (PID: {pid})");
    Ok(())
}

fn wait_for_agent(ctx: &TestContext) -> Result<bool> {
    println!("[INFO] Waiting for agent connection...");
    for elapsed in 0..60 {
        if fs::read_to_string(ctx.test_dir.join("daemon.log"))
            .unwrap_or_default()
            .contains("Agent is ready")
        {
            println!();
            println!("[INFO] Agent connected in {elapsed}s");
            return Ok(true);
        }
        thread::sleep(Duration::from_secs(1));
        print!(".");
        std::io::stdout().flush()?;
    }

    println!();
    println!("[ERROR] Agent connection timeout (60s)");
    println!("[ERROR] Daemon log:");
    print_file(&ctx.test_dir.join("daemon.log"));
    Ok(false)
}

fn test_container_run(ctx: &TestContext) -> Result<()> {
    println!("[INFO] [test] Container run: docker run alpine echo hello");
    let cid = ctx
        .docker_output(
            &["create", "--label", &ctx.label, "alpine", "echo", "hello"],
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
        println!("[INFO] container run: OK");
        Ok(())
    } else {
        bail!("expected 'hello' in output, got: {output}");
    }
}

fn test_background_container(ctx: &TestContext) -> Result<()> {
    println!("[INFO] [test] Background container: docker run -d + docker ps");
    let cid = ctx
        .docker_output(
            &["run", "-d", "--label", &ctx.label, "alpine", "sleep", "300"],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    println!("[INFO] Started background container: {}", cid_prefix(&cid));
    thread::sleep(Duration::from_secs(2));
    let running = ctx.docker_output(
        &["inspect", "-f", "{{.State.Running}}", &cid],
        Duration::from_secs(10),
    )?;
    remove_container(ctx, &cid);
    if running.trim() == "true" {
        println!("[INFO] background container is running: OK");
        Ok(())
    } else {
        bail!("container is not running (inspect output: {running})");
    }
}

fn test_docker_logs(ctx: &TestContext) -> Result<()> {
    println!("[INFO] [test] Docker logs: verify container output");
    let cid = ctx
        .docker_output(
            &[
                "run",
                "-d",
                "--label",
                &ctx.label,
                "alpine",
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
    println!("[INFO] Started log-test container: {}", cid_prefix(&cid));

    let mut last_output = String::new();
    for _ in 0..10 {
        last_output = ctx.docker_output(&["logs", &cid], Duration::from_secs(10))?;
        if last_output.contains("log-output-test") {
            remove_container(ctx, &cid);
            println!("[INFO] docker logs contains expected output: OK");
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }

    remove_container(ctx, &cid);
    bail!("expected 'log-output-test' in logs, got: {last_output}");
}

fn test_docker_exec(ctx: &TestContext) -> Result<()> {
    println!("[INFO] [test] Docker exec: run command in running container");
    let cid = ctx
        .docker_output(
            &["run", "-d", "--label", &ctx.label, "alpine", "sleep", "300"],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    println!("[INFO] Started exec-test container: {}", cid_prefix(&cid));
    thread::sleep(Duration::from_secs(2));
    let output = ctx.docker_output(&["exec", &cid, "ls", "/"], Duration::from_secs(10))?;
    remove_container(ctx, &cid);
    if output.contains("bin") || output.contains("etc") || output.contains("usr") {
        println!("[INFO] docker exec ls / succeeded: OK");
        Ok(())
    } else {
        bail!("docker exec ls / returned unexpected output: {output}");
    }
}

fn test_stop_rm(ctx: &TestContext) -> Result<()> {
    println!("[INFO] [test] Stop/rm: graceful stop and remove");
    let cid = ctx
        .docker_output(
            &["run", "-d", "--label", &ctx.label, "alpine", "sleep", "300"],
            DOCKER_TIMEOUT,
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    println!("[INFO] Started stop-test container: {}", cid_prefix(&cid));
    thread::sleep(Duration::from_secs(2));
    ctx.docker_output(&["stop", &cid], Duration::from_secs(15))?;
    println!("[INFO] docker stop: OK");
    ctx.docker_output(&["rm", &cid], Duration::from_secs(10))?;
    println!("[INFO] docker rm: OK");
    if Command::new("docker")
        .env("DOCKER_HOST", ctx.docker_host())
        .args(["inspect", &cid])
        .status()
        .is_ok_and(|status| status.success())
    {
        bail!("container still exists after rm: {cid}");
    }
    println!("[INFO] Container fully removed: OK");
    Ok(())
}

fn pass_fail(result: Result<()>) -> TestResult {
    match result {
        Ok(()) => TestResult::Pass,
        Err(error) => {
            println!("[ERROR] {error:#}");
            TestResult::Fail
        }
    }
}

fn remove_container(ctx: &TestContext, cid: &str) {
    ctx.docker_ignore(&["rm".to_owned(), "-f".to_owned(), cid.to_owned()]);
}

fn print_summary(ctx: &TestContext, results: &Results) -> Result<()> {
    println!();
    println!("==========================================");
    println!("Boot Assets Test Summary");
    println!("==========================================");

    println!(
        "Kernel:     {}",
        kernel_version(&ctx.test_dir.join("boot").join(&ctx.version).join("kernel"))?
    );
    let rootfs = ctx
        .test_dir
        .join("boot")
        .join(&ctx.version)
        .join("rootfs.erofs");
    if let Ok(metadata) = fs::metadata(&rootfs) {
        println!("Rootfs:     {} bytes", metadata.len());
    } else {
        println!("Rootfs:     N/A");
    }
    println!();

    let mut pass = 0;
    let mut fail = 0;
    let mut skip = 0;
    for (label, result) in results.entries() {
        match result {
            TestResult::Pass => pass += 1,
            TestResult::Fail => fail += 1,
            TestResult::Skip => skip += 1,
        }
        println!("  {label:<22} {}", result.as_str());
    }
    println!();
    println!("Results: {pass} passed, {fail} failed, {skip} skipped / 9 total");
    println!("Log: {}", ctx.test_dir.join("daemon.log").display());
    println!("==========================================");
    Ok(())
}

fn kernel_version(kernel: &Path) -> Result<String> {
    if !kernel.is_file() {
        return Ok("N/A".to_owned());
    }
    let output = Command::new("strings")
        .arg(kernel)
        .output()
        .with_context(|| format!("reading strings from {}", kernel.display()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .find(|line| line.chars().next().is_some_and(|ch| ch.is_ascii_digit()))
        .unwrap_or("N/A")
        .to_owned())
}

fn run_with_timeout(command: &mut Command, timeout: Duration) -> Result<std::process::Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    while start.elapsed() < timeout {
        if child.try_wait()?.is_some() {
            return child
                .wait_with_output()
                .context("collecting command output");
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    let _ = child.wait();
    Err(anyhow!("command timed out after {}s", timeout.as_secs()))
}

fn print_file(path: &Path) {
    if let Ok(contents) = fs::read_to_string(path) {
        print!("{contents}");
    }
}

fn cid_prefix(cid: &str) -> &str {
    cid.get(..12).unwrap_or(cid)
}
