//! Internal commands for package manager integration.
//!
//! These commands are called by Homebrew Cask postflight/uninstall scripts
//! and are not intended for direct user invocation. They mirror OrbStack's
//! `orbctl _internal` pattern.
//!
//! Both hooks are idempotent and share the same code paths as the desktop
//! app's first-launch setup, so the result is identical regardless of
//! whether the user opens the app first or installs via `brew`.

use anyhow::{Context, Result};
use arcbox_constants::paths::{DOCKER_CLI_TOOLS, HostLayout};
use clap::Subcommand;

use super::OutputFormat;

/// Internal subcommands (hidden from help).
#[derive(Subcommand)]
pub enum InternalCommands {
    /// Homebrew Cask post-install hook.
    ///
    /// Runs the same first-launch setup that the desktop app performs:
    /// data directories, shell integration, and Docker CLI context.
    /// All operations are idempotent — if the app has already run,
    /// this is a no-op.
    #[command(name = "brew-postflight")]
    BrewPostflight,

    /// Homebrew Cask pre-uninstall hook.
    ///
    /// Stops the daemon, removes Docker context, and cleans up shell
    /// integration. Privileged components (helper, DNS resolver) require
    /// separate `sudo abctl _uninstall` cleanup.
    #[command(name = "brew-uninstall")]
    BrewUninstall,
}

pub async fn execute(cmd: InternalCommands) -> Result<()> {
    match cmd {
        InternalCommands::BrewPostflight => brew_postflight().await,
        InternalCommands::BrewUninstall => brew_uninstall().await,
    }
}

/// Post-install hook for Homebrew Cask.
///
/// Shares the same setup code paths as the desktop app's first launch.
/// Every step is idempotent — running after the app has already set up
/// is harmless.
async fn brew_postflight() -> Result<()> {
    let layout = HostLayout::from_env_or_default();

    // 1. Create data directories (same layout as daemon's init_early phase).
    for dir in [
        &layout.run_dir,
        &layout.log_dir,
        &layout.data_subdir,
        &layout.data_dir.join("boot"),
        &layout.data_dir.join("bin"),
    ] {
        tokio::fs::create_dir_all(dir).await?;
    }

    // 2. Shell integration — same code path as `abctl setup install`.
    super::setup::execute(super::setup::SetupCommands::Install, OutputFormat::Quiet).await?;

    // 3. Docker context — `enable()` always creates/updates the context metadata
    //    (including the socket path) then sets it as default. This ensures upgrades
    //    that change the socket path don't leave a stale context behind.
    if let Err(e) = setup_docker_context() {
        eprintln!("Note: Docker context setup skipped ({e})");
    }

    // Note: `/usr/local/bin/docker*` symlinks are handled by the daemon's
    // self-setup (`CliTools` task) via `arcbox-helper` at first app launch.
    // Doing it here would EACCES on Apple Silicon since postflight runs
    // unprivileged and `/usr/local/bin` is `root:wheel`. The ~/.arcbox/bin
    // path written by `setup install` above is the user-space fallback.

    Ok(())
}

/// Pre-uninstall hook for Homebrew Cask.
///
/// Cleans up non-privileged, user-level state that the Cask `zap` stanza
/// does not cover. The existing `_uninstall` is too heavy here: it requires
/// sudo, removes the app bundle (Cask already does that), and deletes user
/// data (belongs to `brew zap`).
async fn brew_uninstall() -> Result<()> {
    let profile = arcbox_constants::paths::ArcboxProfile::from_env_or_default();
    let daemon_label = profile.daemon_label();
    let layout = HostLayout::from_env_or_default();

    // 1. Stop the daemon via launchctl, then best-effort pkill fallback.
    // SAFETY: getuid() is a trivial POSIX syscall.
    let uid = unsafe { libc::getuid() };
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}/{daemon_label}")])
        .output();
    // bootout may not immediately stop an already-running process.
    // Mirror the `_uninstall` flow with a pkill fallback + short wait.
    let _ = std::process::Command::new("pkill")
        .args(["-f", daemon_label])
        .status();
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Remove the daemon plist so launchd doesn't try to restart.
    let plist_path = dirs::home_dir()
        .context("could not determine home directory")?
        .join(format!("Library/LaunchAgents/{daemon_label}.plist"));
    let _ = tokio::fs::remove_file(plist_path).await;

    // 2. Remove Docker context via DockerContextManager — `remove_context()`
    //    restores the user's previous default context (e.g. desktop-linux)
    //    instead of hard-coding "default".
    if let Ok(manager) = super::docker::context_manager() {
        let _ = manager.remove_context();
    }

    // 3. Remove shell integration — same code path as `abctl setup uninstall`.
    super::setup::execute(super::setup::SetupCommands::Uninstall, OutputFormat::Quiet).await?;

    // 4. Remove `/usr/local/bin/docker*` via the helper. The helper plist
    //    survives this hook (its full removal belongs to `sudo abctl _uninstall`),
    //    so its launchd-activated socket is still reachable here. Best-effort:
    //    a missing or incompatible helper makes the checked connection fail;
    //    the full sudo uninstall removes any remaining owned links directly.
    //    The helper's `cli_unlink` is gated on `is_arcbox_owned`, so foreign
    //    symlinks are left alone.
    if let Ok(client) = arcbox_helper::client::Client::connect().await {
        for name in DOCKER_CLI_TOOLS {
            let _ = client.cli_unlink(name).await;
        }
    }

    // 5. Remove run directory contents (sockets, pid, lock) so stale files
    //    don't confuse a future reinstall.
    let _ = tokio::fs::remove_dir_all(&layout.run_dir).await;

    Ok(())
}

/// Enables the ArcBox Docker context, always refreshing metadata.
/// Uses `DockerContextManager::enable()` — same path as `abctl docker enable`.
fn setup_docker_context() -> Result<()> {
    let manager = super::docker::context_manager()?;
    manager.enable().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use arcbox_docker::DockerContextManager;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn postflight_enable_always_refreshes_socket_path() {
        let temp = tempdir().unwrap();
        let docker_dir = temp.path().join(".docker");

        // First install — create context with old socket path.
        let old_socket = temp.path().join("old.sock");
        let mgr = DockerContextManager::with_config_dir(old_socket, docker_dir.clone());
        mgr.enable().unwrap();
        assert!(mgr.context_exists());
        assert!(mgr.is_default().unwrap());

        // Upgrade — enable() with new socket path must overwrite metadata.
        let new_socket = temp.path().join("new.sock");
        let mgr = DockerContextManager::with_config_dir(new_socket.clone(), docker_dir.clone());
        mgr.enable().unwrap();

        assert!(mgr.context_exists());
        assert!(mgr.is_default().unwrap());

        // Verify meta.json actually references the new socket path.
        let meta_json = std::fs::read_dir(docker_dir.join("contexts/meta"))
            .unwrap()
            .filter_map(|e| e.ok())
            .find_map(|e| std::fs::read_to_string(e.path().join("meta.json")).ok())
            .expect("meta.json not found");
        assert!(
            meta_json.contains(&new_socket.to_string_lossy().to_string()),
            "meta.json should reference new socket path, got: {meta_json}"
        );
    }

    #[test]
    fn uninstall_remove_context_restores_previous() {
        let temp = tempdir().unwrap();
        let socket = temp.path().join("docker.sock");
        let docker_dir = temp.path().join(".docker");

        let mgr = DockerContextManager::with_config_dir(socket, docker_dir);

        // Simulate: user had "desktop-linux" active, then ArcBox was enabled.
        std::fs::create_dir_all(mgr.docker_config_dir()).unwrap();
        std::fs::write(
            mgr.docker_config_dir().join("config.json"),
            r#"{"currentContext":"desktop-linux"}"#,
        )
        .unwrap();
        mgr.enable().unwrap();
        assert!(mgr.is_default().unwrap());

        // Brew uninstall calls remove_context() — should restore "desktop-linux".
        mgr.remove_context().unwrap();
        assert!(!mgr.context_exists());
        assert_eq!(
            mgr.current_context().unwrap(),
            Some("desktop-linux".to_string())
        );
    }

    #[test]
    fn host_layout_directories_are_consistent() {
        let layout = arcbox_constants::paths::HostLayout::from_env_or_default();
        assert!(layout.run_dir.ends_with("run"));
        assert!(layout.log_dir.ends_with("log"));
        assert!(layout.data_subdir.ends_with("data"));
    }

    #[test]
    fn remove_context_is_safe_when_docker_not_configured() {
        let temp = tempdir().unwrap();
        let socket = temp.path().join("docker.sock");
        let docker_dir = temp.path().join(".docker");

        // No .docker/ directory exists — remove_context() should not panic.
        let mgr = DockerContextManager::with_config_dir(socket, docker_dir);
        mgr.remove_context().unwrap();
    }

    #[test]
    fn context_manager_constructs_with_default_socket() {
        // Verify the factory helper resolves a path (doesn't panic).
        let socket = arcbox_constants::paths::HostLayout::from_env_or_default().docker_socket;
        assert!(socket.to_string_lossy().contains("docker.sock"));
    }

    /// Verify that `context_meta_path()` exists via the public `context_exists()` API.
    #[test]
    fn context_meta_accessible_via_public_api() {
        let temp = tempdir().unwrap();
        let mgr = DockerContextManager::with_config_dir(
            PathBuf::from("/tmp/test.sock"),
            temp.path().to_path_buf(),
        );
        assert!(!mgr.context_exists());
        mgr.create_context().unwrap();
        assert!(mgr.context_exists());
    }
}
