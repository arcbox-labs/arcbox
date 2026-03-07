//! Docker CLI integration commands.
//!
//! Manages the integration between Docker CLI and ArcBox by controlling
//! Docker contexts and installing bundled Docker CLI tools.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_docker::DockerContextManager;
use arcbox_docker_tools::{DockerToolManager, parse_tools};
use clap::Subcommand;

/// Embedded `assets.lock` (same copy used by boot_assets).
const LOCK_TOML: &str = include_str!("../../../../assets.lock");

/// Docker integration commands.
#[derive(Subcommand)]
pub enum DockerCommands {
    /// Enable Docker CLI integration
    ///
    /// Creates an 'arcbox' Docker context and sets it as the default.
    /// After enabling, all `docker` commands will use ArcBox.
    Enable,

    /// Disable Docker CLI integration
    ///
    /// Restores the previous default Docker context.
    /// The 'arcbox' context is kept but no longer default.
    Disable,

    /// Show Docker integration status
    Status,

    /// Download and install Docker CLI tools (docker, buildx, compose)
    ///
    /// Downloads Docker CLI binaries to ~/.arcbox/runtime/bin/ and creates
    /// symlinks in ~/.arcbox/bin/. Also generates shell completions for the
    /// Docker CLI.
    Setup,
}

/// Executes a docker subcommand.
pub async fn execute(cmd: DockerCommands) -> Result<()> {
    match cmd {
        DockerCommands::Enable => {
            let manager = context_manager()?;
            execute_enable(&manager)
        }
        DockerCommands::Disable => {
            let manager = context_manager()?;
            execute_disable(&manager)
        }
        DockerCommands::Status => {
            let manager = context_manager()?;
            execute_status(&manager);
            Ok(())
        }
        DockerCommands::Setup => execute_setup().await,
    }
}

fn context_manager() -> Result<DockerContextManager> {
    DockerContextManager::new(default_socket_path())
        .context("Failed to initialize Docker context manager")
}

/// Downloads and installs Docker CLI tools.
async fn execute_setup() -> Result<()> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let runtime_bin = home.join(".arcbox/runtime/bin");
    let user_bin = home.join(".arcbox/bin");

    // Parse tool entries from lockfile.
    let tools = parse_tools(LOCK_TOML).context("failed to parse assets.lock")?;
    if tools.is_empty() {
        println!("No Docker tools configured in assets.lock.");
        return Ok(());
    }

    let arch = arcbox_asset::current_arch().to_string();

    println!("Installing Docker CLI tools...");
    println!();

    let manager = DockerToolManager::new(tools, &arch, runtime_bin.clone());

    // Progress callback.
    let progress_cb: arcbox_asset::ProgressCallback =
        Box::new(|p: arcbox_asset::PrepareProgress| match &p.phase {
            arcbox_asset::PreparePhase::Checking => {
                eprint!("  [{}/{}] {} checking...", p.current, p.total, p.name);
            }
            arcbox_asset::PreparePhase::Downloading { downloaded, total } => {
                let pct = total
                    .map(|t| if t > 0 { downloaded * 100 / t } else { 0 })
                    .unwrap_or(0);
                eprint!(
                    "\r  [{}/{}] {} downloading... {}%",
                    p.current, p.total, p.name, pct
                );
            }
            arcbox_asset::PreparePhase::Verifying => {
                eprint!(
                    "\r  [{}/{}] {} verifying...       ",
                    p.current, p.total, p.name
                );
            }
            arcbox_asset::PreparePhase::Ready => {
                eprintln!(
                    "\r  [{}/{}] {} installed          ",
                    p.current, p.total, p.name
                );
            }
            arcbox_asset::PreparePhase::Cached => {
                eprintln!(
                    "\r  [{}/{}] {} up to date         ",
                    p.current, p.total, p.name
                );
            }
        });

    manager
        .install_all(Some(&Arc::new(progress_cb)))
        .await
        .context("failed to install Docker tools")?;

    // Create symlinks in ~/.arcbox/bin/.
    tokio::fs::create_dir_all(&user_bin).await?;
    for tool in manager.tools() {
        let target = runtime_bin.join(&tool.name);
        let link = user_bin.join(&tool.name);
        create_or_update_symlink(&target, &link).await?;
    }

    println!();
    println!("Docker tools installed to {}", runtime_bin.display());
    println!("Symlinks created in {}", user_bin.display());

    // Generate Docker shell completions.
    generate_docker_completions(&home, &runtime_bin).await?;

    println!();
    println!("Restart your shell or re-source your profile to use Docker completions.");

    Ok(())
}

/// Generate Docker CLI completions by running the installed docker binary.
async fn generate_docker_completions(home: &Path, runtime_bin: &Path) -> Result<()> {
    let comp_dir = home.join(".arcbox/completions");

    let docker_bin = runtime_bin.join("docker");
    if !docker_bin.exists() {
        return Ok(());
    }

    println!("Generating Docker shell completions...");

    let shells = [
        ("zsh", comp_dir.join("zsh/_docker")),
        ("bash", comp_dir.join("bash/docker")),
        ("fish", comp_dir.join("fish/docker.fish")),
    ];

    for (shell, dest) in &shells {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let output = tokio::process::Command::new(&docker_bin)
            .arg("completion")
            .arg(shell)
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                tokio::fs::write(dest, &out.stdout).await?;
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                eprintln!("  Warning: docker completion {shell} failed: {stderr}");
            }
            Err(e) => {
                eprintln!("  Warning: could not run docker completion: {e}");
            }
        }
    }

    // Also try docker compose completion.
    let compose_bin = runtime_bin.join("docker-compose");
    if compose_bin.exists() {
        let compose_shells = [
            ("zsh", comp_dir.join("zsh/_docker-compose")),
            ("bash", comp_dir.join("bash/docker-compose")),
            ("fish", comp_dir.join("fish/docker-compose.fish")),
        ];

        for (shell, dest) in &compose_shells {
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            let output = tokio::process::Command::new(&compose_bin)
                .arg("completion")
                .arg(shell)
                .output()
                .await;

            if let Ok(out) = output {
                if out.status.success() {
                    tokio::fs::write(dest, &out.stdout).await?;
                }
            }
        }
    }

    println!("  Completions saved to {}", comp_dir.display());
    Ok(())
}

/// Create or update a symlink, removing any stale one first.
async fn create_or_update_symlink(target: &Path, link: &Path) -> Result<()> {
    if tokio::fs::symlink_metadata(link).await.is_ok() {
        tokio::fs::remove_file(link).await.ok();
    }

    #[cfg(unix)]
    tokio::fs::symlink(target, link).await.with_context(|| {
        format!(
            "failed to create symlink {} -> {}",
            link.display(),
            target.display()
        )
    })?;

    Ok(())
}

/// Enables Docker CLI integration.
fn execute_enable(manager: &DockerContextManager) -> Result<()> {
    // Check if already enabled.
    if manager.context_exists() && manager.is_default()? {
        println!("Docker integration is already enabled.");
        return Ok(());
    }

    manager
        .enable()
        .context("Failed to enable Docker integration")?;

    println!("Docker integration enabled.");
    println!();
    println!("You can now use the docker CLI with ArcBox:");
    println!("  docker ps");
    println!("  docker run alpine echo hello");
    println!();
    println!("To disable, run: arcbox docker disable");

    // Warn if socket doesn't exist.
    if !manager.socket_path().exists() {
        println!();
        println!(
            "Warning: ArcBox Docker socket not found at {}",
            manager.socket_path().display()
        );
        println!("Make sure the ArcBox daemon is running.");
    }

    Ok(())
}

/// Disables Docker CLI integration.
fn execute_disable(manager: &DockerContextManager) -> Result<()> {
    if !manager.is_default()? {
        println!("Docker integration is not currently enabled.");
        return Ok(());
    }

    manager
        .disable()
        .context("Failed to disable Docker integration")?;

    println!("Docker integration disabled.");
    println!("The previous default Docker context has been restored.");

    Ok(())
}

/// Shows Docker integration status.
fn execute_status(manager: &DockerContextManager) {
    let status = manager.status();

    println!("Docker Integration Status");
    println!("=========================");
    println!();
    println!(
        "Context exists:  {}",
        if status.context_exists { "yes" } else { "no" }
    );
    println!(
        "Is default:      {}",
        if status.is_default { "yes" } else { "no" }
    );
    println!("Socket path:     {}", status.socket_path.display());
    println!(
        "Socket exists:   {}",
        if status.socket_exists { "yes" } else { "no" }
    );

    println!();
    if status.is_default && status.socket_exists {
        println!("Status: Ready - docker commands will use ArcBox");
    } else if status.is_default && !status.socket_exists {
        println!("Status: Enabled but daemon not running");
        println!("        Start the ArcBox daemon to use docker commands");
    } else if status.context_exists {
        println!("Status: Context exists but not default");
        println!("        Run 'arcbox docker enable' to activate");
    } else {
        println!("Status: Not configured");
        println!("        Run 'arcbox docker enable' to set up");
    }
}

/// Returns the default socket path for the Docker-compatible API.
fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".arcbox")
        .join("docker.sock")
}
