//! One-time privileged setup for ArcBox (CLI-only users).
//!
//! Installs the helper binary (requires sudo) and registers the daemon as
//! a launchd user agent. Everything else — DNS resolver, Docker socket,
//! boot assets, runtime binaries, Docker CLI tools — is handled by the
//! daemon during startup via self-setup.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Arguments for the install command.
#[derive(clap::Args)]
pub struct InstallArgs {
    /// Skip the daemon launchd service registration.
    #[arg(long)]
    pub no_daemon: bool,

    /// Skip shell integration setup.
    #[arg(long)]
    pub no_shell: bool,

    /// Path to the arcbox-helper binary to install.
    /// Defaults to looking next to the current executable.
    #[arg(long)]
    pub helper_path: Option<PathBuf>,
}

/// Executes the install command.
pub async fn execute(args: InstallArgs) -> Result<()> {
    println!("ArcBox Install");
    println!("==============");
    println!();

    // 1. Install helper binary (requires sudo).
    print_step(1, 3, "Installing arcbox-helper...");
    install_helper(args.helper_path.as_deref())?;
    print_done();

    // 2. Register daemon service.
    print_step(2, 3, "Registering daemon service...");
    if args.no_daemon {
        print_skipped();
    } else {
        register_daemon_service()?;
        print_done();
    }

    // 3. Shell integration.
    // Under sudo, dirs::home_dir() returns /var/root, so setup would
    // install to root's home instead of the real user's. Skip and hint.
    print_step(3, 3, "Setting up shell integration...");
    if args.no_shell {
        print_skipped();
    } else if std::env::var("SUDO_USER").is_ok() {
        println!("skipped (sudo)");
        println!();
        println!("  Run as your normal user: abctl setup install");
    } else {
        super::setup::execute(
            super::setup::SetupCommands::Install,
            super::OutputFormat::Quiet,
        )
        .await?;
        print_done();
    }

    println!();
    println!("ArcBox installed. The daemon will start automatically.");
    println!("DNS, Docker socket, and boot assets are configured on first daemon start.");

    Ok(())
}

fn print_step(n: u32, total: u32, msg: &str) {
    print!("[{n}/{total}] {msg:<40}");
}

fn print_done() {
    println!("done");
}

fn print_skipped() {
    println!("skipped");
}

// =============================================================================
// Step 1: Install helper binary + launchd service
// =============================================================================

use arcbox_constants::paths::{ArcboxProfile, privileged};

/// Installs the arcbox-helper binary and registers it as a launchd system
/// daemon with socket activation.
///
/// launchd creates the socket at `/var/run/arcbox-helper.sock` and starts
/// the helper on-demand when the main daemon connects.
fn install_helper(custom_path: Option<&std::path::Path>) -> Result<()> {
    let dest = PathBuf::from(privileged::HELPER_BINARY);

    // Use custom path if provided, otherwise look next to our own executable.
    let helper_src = if let Some(path) = custom_path {
        path.to_path_buf()
    } else {
        let exe = std::env::current_exe().context("could not determine current executable")?;
        let exe_dir = exe.parent().context("executable has no parent directory")?;
        exe_dir.join("arcbox-helper")
    };

    if !helper_src.exists() {
        bail!(
            "arcbox-helper not found at {}. Build it first with: cargo build -p arcbox-helper",
            helper_src.display()
        );
    }

    // Create target directory.
    std::fs::create_dir_all("/usr/local/libexec").context("failed to create /usr/local/libexec")?;

    // Copy binary.
    std::fs::copy(&helper_src, &dest).with_context(|| {
        format!(
            "failed to copy {} -> {}",
            helper_src.display(),
            dest.display()
        )
    })?;

    // Ensure root ownership (macOS copyfile preserves source ownership).
    let status = Command::new("chown")
        .args(["root:wheel", privileged::HELPER_BINARY])
        .status()
        .context("failed to chown helper binary")?;
    if !status.success() {
        bail!("chown root:wheel failed (are you running with sudo?)");
    }

    // Install bundled launchd plist (socket activation config is static).
    std::fs::write(
        privileged::HELPER_PLIST,
        include_bytes!("../../../../bundle/com.arcboxlabs.desktop.helper.plist"),
    )
    .with_context(|| format!("failed to write {}", privileged::HELPER_PLIST))?;

    // Bootout existing service (ignore errors if not loaded).
    let _ = Command::new("launchctl")
        .args(["bootout", "system", privileged::HELPER_PLIST])
        .output();

    // Bootstrap the service into the system domain.
    let status = Command::new("launchctl")
        .args(["bootstrap", "system", privileged::HELPER_PLIST])
        .status()
        .context("failed to run launchctl bootstrap")?;

    if !status.success() {
        bail!("launchctl bootstrap failed for helper service");
    }

    Ok(())
}

// =============================================================================
// Step 2: Daemon service
// =============================================================================

/// Registers the daemon as a launchd user agent.
///
/// Under `sudo`, `dirs::home_dir()` returns `/var/root` and `getuid()`
/// returns 0. We detect this via `SUDO_USER` / `SUDO_UID` and resolve
/// the real user's home and UID instead.
fn register_daemon_service() -> Result<()> {
    let (home, uid) = resolve_real_user()?;
    let profile = ArcboxProfile::from_env_or_default();
    let daemon_label = profile.daemon_label();
    let data_dir = std::env::var(arcbox_constants::env::DATA_DIR)
        .ok()
        .filter(|value| !value.is_empty())
        .map_or_else(
            || match profile {
                ArcboxProfile::Production => home.join(".arcbox"),
                ArcboxProfile::Development => home.join(".arcbox-dev"),
            },
            PathBuf::from,
        );
    let plist_dir = home.join("Library/LaunchAgents");
    std::fs::create_dir_all(&plist_dir).context("failed to create LaunchAgents directory")?;

    // Create log directory so launchd's stdout/stderr redirection works
    // on fresh installs where the profile log directory doesn't exist yet.
    let log_dir = data_dir.join("log");
    std::fs::create_dir_all(&log_dir).context("failed to create log directory")?;

    // Under sudo, the directory is created as root. Chown to the real user
    // so the daemon (running as user) can write logs.
    let _ = Command::new("chown")
        .args(["-R", &format!("{uid}:staff"), &data_dir.to_string_lossy()])
        .status();

    let plist_path = plist_dir.join(format!("{daemon_label}.plist"));

    // Find the daemon binary.
    let exe = std::env::current_exe().context("could not determine current executable")?;
    let exe_dir = exe.parent().context("executable has no parent directory")?;
    let daemon_bin = exe_dir.join("arcbox-daemon");

    let daemon_path = if daemon_bin.exists() {
        daemon_bin.to_string_lossy().to_string()
    } else {
        let alt = data_dir.join("bin/arcbox-daemon");
        if alt.exists() {
            alt.to_string_lossy().to_string()
        } else {
            "arcbox-daemon".to_string()
        }
    };

    // Daemon manages its own log files via tracing-appender, so we no
    // longer set StandardOutPath / StandardErrorPath. Stdout/stderr are
    // discarded to avoid launchd writing duplicate output.
    let data_dir_env = arcbox_constants::env::DATA_DIR;
    let data_dir_str = data_dir.display();
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{daemon_label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{daemon_path}</string>
        <string>--profile</string>
        <string>{profile}</string>
        <string>--data-dir</string>
        <string>{data_dir_str}</string>
    </array>
    <!--
      Mirror the data dir into the daemon environment: recovery's host-global
      self-setup treats {data_dir_env} as the machine-wide canonical layout,
      so a relocated install keeps ownership of /var/run/docker.sock (the
      argv flag alone reads as a scoped per-instance override there).
    -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>{data_dir_env}</key>
        <string>{data_dir_str}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <!--
      ExitTimeOut: seconds launchd waits after SIGTERM before sending SIGKILL.
      Daemon shutdown can use all 45s (two 5s NFS unmount attempts + 5s service
      drain + 30s VM graceful stop). This preserves the full VM stop budget;
      only final best-effort cleanup may run up against the deadline.
    -->
    <key>ExitTimeOut</key>
    <integer>45</integer>
</dict>
</plist>
"#
    );

    std::fs::write(&plist_path, plist_content)
        .with_context(|| format!("failed to write {}", plist_path.display()))?;

    let domain_target = format!("gui/{uid}");

    // Bootout first to handle re-install (ignore errors if not loaded).
    let _ = Command::new("launchctl")
        .args(["bootout", &domain_target, &plist_path.to_string_lossy()])
        .output();

    let status = Command::new("launchctl")
        .args(["bootstrap", &domain_target, &plist_path.to_string_lossy()])
        .status()
        .context("failed to run launchctl bootstrap")?;

    if !status.success() {
        bail!("launchctl bootstrap failed");
    }

    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Resolves the real user's home directory and UID.
///
/// When running under `sudo`, `dirs::home_dir()` returns `/var/root` and
/// `libc::getuid()` returns 0. We use `SUDO_USER` to look up the home
/// directory and `SUDO_UID` for the UID. Falls back to the current process
/// values when not running under sudo.
fn resolve_real_user() -> Result<(PathBuf, u32)> {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let uid: u32 = std::env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse().ok())
            .context("SUDO_USER is set but SUDO_UID is missing or invalid")?;

        // Resolve home directory from the password database.
        let home = home_for_user(&sudo_user)
            .unwrap_or_else(|| PathBuf::from(format!("/Users/{sudo_user}")));

        return Ok((home, uid));
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    // SAFETY: getuid() is a trivial POSIX syscall with no preconditions.
    let uid = unsafe { libc::getuid() };
    Ok((home, uid))
}

/// Looks up a user's home directory via the POSIX password database.
fn home_for_user(username: &str) -> Option<PathBuf> {
    let c_name = std::ffi::CString::new(username).ok()?;
    // SAFETY: getpwnam is a standard POSIX function. We pass a valid
    // null-terminated string and check the return value before
    // dereferencing. The returned pointer is to static storage.
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: pw is non-null and pw_dir is a valid C string.
    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
    Some(PathBuf::from(dir.to_string_lossy().into_owned()))
}
