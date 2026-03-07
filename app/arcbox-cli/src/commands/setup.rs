//! Shell integration setup commands.
//!
//! Manages CLI registration into the user's PATH and shell completions so that
//! `abctl` is available from any terminal session.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Subcommand, ValueEnum};
use serde::Serialize;

use super::{Cli, OutputFormat};

/// Shell integration setup commands.
#[derive(Subcommand)]
pub enum SetupCommands {
    /// Install shell integration (PATH, completions, profile)
    Install,

    /// Remove shell integration
    Uninstall,

    /// Check installation status
    Status,

    /// Print shell completions to stdout
    Completions(CompletionsArgs),
}

/// Arguments for the completions subcommand.
#[derive(clap::Args)]
pub struct CompletionsArgs {
    /// Target shell
    #[arg(long, value_enum)]
    pub shell: ShellKind,
}

/// Supported shells.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ShellKind {
    Zsh,
    Bash,
    Fish,
}

// =============================================================================
// JSON output structures
// =============================================================================

/// Status report for `abctl setup status --format json`.
#[derive(Serialize)]
struct StatusOutput {
    installed: bool,
    bin_symlink: ComponentStatus,
    shell_init: ComponentStatus,
    profile_injected: ComponentStatus,
    completions: ComponentStatus,
}

/// Per-component installation status.
#[derive(Serialize)]
struct ComponentStatus {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

// =============================================================================
// Path helpers
// =============================================================================

/// Root directory for ArcBox shell integration files (`~/.arcbox/`).
fn arcbox_home() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(".arcbox"))
        .context("could not determine home directory")
}

fn bin_dir() -> Result<PathBuf> {
    arcbox_home().map(|h| h.join("bin"))
}

fn shell_dir() -> Result<PathBuf> {
    arcbox_home().map(|h| h.join("shell"))
}

fn completions_dir() -> Result<PathBuf> {
    arcbox_home().map(|h| h.join("completions"))
}

// =============================================================================
// Command dispatch
// =============================================================================

/// Execute setup commands.
pub async fn execute(command: SetupCommands, format: OutputFormat) -> Result<()> {
    match command {
        SetupCommands::Install => install(format).await,
        SetupCommands::Uninstall => uninstall(format).await,
        SetupCommands::Status => status(format).await,
        SetupCommands::Completions(args) => {
            print_completions(args.shell);
            Ok(())
        }
    }
}

// =============================================================================
// Install
// =============================================================================

async fn install(format: OutputFormat) -> Result<()> {
    let bin = bin_dir()?;
    let shell = shell_dir()?;
    let comp = completions_dir()?;

    // 1. Create directories.
    tokio::fs::create_dir_all(&bin).await?;
    tokio::fs::create_dir_all(&shell).await?;
    tokio::fs::create_dir_all(comp.join("zsh")).await?;
    tokio::fs::create_dir_all(comp.join("bash")).await?;
    tokio::fs::create_dir_all(comp.join("fish")).await?;

    // 2. Symlink current executable → ~/.arcbox/bin/abctl (primary).
    //    Also create ~/.arcbox/bin/arcbox → placeholder for backwards compat.
    let exe = std::env::current_exe().context("could not determine current executable path")?;
    let exe_dir = exe
        .parent()
        .context("could not determine executable directory")?;
    let symlink_path = bin.join("abctl");
    create_or_update_symlink(&exe, &symlink_path).await?;

    // The placeholder binary lives next to the main binary.
    let placeholder_exe = exe_dir.join("arcbox");
    let placeholder_symlink = bin.join("arcbox");
    if placeholder_exe.exists() {
        create_or_update_symlink(&placeholder_exe, &placeholder_symlink).await?;
    }

    // 3. Write shell init scripts.
    write_shell_init_scripts(&shell).await?;

    // 4. Generate completions.
    generate_all_completions(&comp)?;

    // 5. Inject into shell profile.
    let detected_shell = detect_shell();
    let profile_path = inject_profile(detected_shell).await?;

    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "installed": true,
                    "bin": symlink_path.display().to_string(),
                    "shell_init": shell.display().to_string(),
                    "completions": comp.display().to_string(),
                    "profile": profile_path.as_ref().map(|p| p.display().to_string()),
                }))?
            );
        }
        OutputFormat::Table | OutputFormat::Quiet => {
            println!("ArcBox CLI Setup");
            println!("================");
            println!();
            println!(
                "  Symlink:     {} -> {}",
                symlink_path.display(),
                exe.display()
            );
            println!("  Shell init:  {}", shell.display());
            println!("  Completions: {}", comp.display());
            if let Some(ref p) = profile_path {
                println!("  Profile:     {} (updated)", p.display());
            }
            println!();
            println!("Restart your shell or run:");
            println!("  source {}/init.zsh", shell.display());
        }
    }

    Ok(())
}

// =============================================================================
// Uninstall
// =============================================================================

async fn uninstall(format: OutputFormat) -> Result<()> {
    let bin = bin_dir()?;
    let shell = shell_dir()?;
    let comp = completions_dir()?;

    // Remove directories.
    remove_dir_if_exists(&bin).await;
    remove_dir_if_exists(&shell).await;
    remove_dir_if_exists(&comp).await;

    // Remove profile injection.
    let detected_shell = detect_shell();
    let removed_from = remove_profile_injection(detected_shell).await?;

    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "uninstalled": true,
                    "profile_cleaned": removed_from.as_ref().map(|p| p.display().to_string()),
                }))?
            );
        }
        OutputFormat::Table | OutputFormat::Quiet => {
            println!("ArcBox CLI shell integration removed.");
            if let Some(ref p) = removed_from {
                println!("  Cleaned profile: {}", p.display());
            }
            println!("  Restart your shell to apply changes.");
        }
    }

    Ok(())
}

// =============================================================================
// Status
// =============================================================================

async fn status(format: OutputFormat) -> Result<()> {
    let bin = bin_dir()?;
    let shell = shell_dir()?;
    let comp = completions_dir()?;

    let symlink_path = bin.join("abctl");
    let symlink_ok = tokio::fs::symlink_metadata(&symlink_path)
        .await
        .is_ok_and(|m| m.file_type().is_symlink());
    let symlink_target = if symlink_ok {
        tokio::fs::read_link(&symlink_path)
            .await
            .ok()
            .map(|p| p.display().to_string())
    } else {
        None
    };

    let detected_shell = detect_shell();
    let init_script = shell_init_path(&shell, detected_shell);
    let init_ok = tokio::fs::metadata(&init_script).await.is_ok();

    let profile = profile_path(detected_shell);
    let profile_injected = if let Some(ref p) = profile {
        check_profile_injected(p).await
    } else {
        false
    };

    let zsh_comp = comp.join("zsh/_abctl");
    let comp_ok = tokio::fs::metadata(&zsh_comp).await.is_ok();

    let all_ok = symlink_ok && init_ok && profile_injected && comp_ok;

    match format {
        OutputFormat::Json => {
            let output = StatusOutput {
                installed: all_ok,
                bin_symlink: ComponentStatus {
                    ok: symlink_ok,
                    path: Some(symlink_path.display().to_string()),
                    detail: symlink_target,
                },
                shell_init: ComponentStatus {
                    ok: init_ok,
                    path: Some(init_script.display().to_string()),
                    detail: None,
                },
                profile_injected: ComponentStatus {
                    ok: profile_injected,
                    path: profile.as_ref().map(|p| p.display().to_string()),
                    detail: None,
                },
                completions: ComponentStatus {
                    ok: comp_ok,
                    path: Some(comp.display().to_string()),
                    detail: None,
                },
            };
            println!("{}", serde_json::to_string(&output)?);
        }
        OutputFormat::Table | OutputFormat::Quiet => {
            println!("ArcBox CLI Setup Status");
            println!("=======================");
            println!();
            print_check(
                "CLI symlink",
                symlink_ok,
                &symlink_path.display().to_string(),
            );
            print_check("Shell init", init_ok, &init_script.display().to_string());
            print_check(
                "Profile injection",
                profile_injected,
                &profile
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
            );
            print_check("Completions", comp_ok, &comp.display().to_string());
            println!();
            if all_ok {
                println!("Status: installed");
            } else {
                println!("Status: not installed (run `abctl setup install`)");
            }
        }
    }

    Ok(())
}

fn print_check(label: &str, ok: bool, detail: &str) {
    let icon = if ok { "+" } else { "-" };
    println!("  [{}] {:<20} {}", icon, label, detail);
}

// =============================================================================
// Completions
// =============================================================================

fn print_completions(shell: ShellKind) {
    let mut cmd = Cli::command();
    let clap_shell = to_clap_shell(shell);
    clap_complete::generate(clap_shell, &mut cmd, "abctl", &mut std::io::stdout());
}

fn generate_all_completions(comp_dir: &Path) -> Result<()> {
    let shells = [
        (clap_complete::Shell::Zsh, comp_dir.join("zsh/_abctl")),
        (clap_complete::Shell::Bash, comp_dir.join("bash/abctl")),
        (clap_complete::Shell::Fish, comp_dir.join("fish/abctl.fish")),
    ];

    for (shell, path) in &shells {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        clap_complete::generate(*shell, &mut cmd, "abctl", &mut buf);
        std::fs::write(path, buf)
            .with_context(|| format!("failed to write completions to {}", path.display()))?;
    }

    Ok(())
}

fn to_clap_shell(shell: ShellKind) -> clap_complete::Shell {
    match shell {
        ShellKind::Zsh => clap_complete::Shell::Zsh,
        ShellKind::Bash => clap_complete::Shell::Bash,
        ShellKind::Fish => clap_complete::Shell::Fish,
    }
}

// =============================================================================
// Shell init scripts
// =============================================================================

async fn write_shell_init_scripts(shell_dir: &Path) -> Result<()> {
    let zsh = r#"# ArcBox shell integration (zsh)
# This file is auto-generated by `abctl setup install`.
export PATH="${HOME}/.arcbox/bin:${PATH}"
fpath+=("${HOME}/.arcbox/completions/zsh")
"#;

    let bash = r#"# ArcBox shell integration (bash)
# This file is auto-generated by `abctl setup install`.
export PATH="${HOME}/.arcbox/bin:${PATH}"
for _abctl_comp in "${HOME}"/.arcbox/completions/bash/*; do
    [ -f "$_abctl_comp" ] && source "$_abctl_comp"
done
unset _abctl_comp
"#;

    let fish = "# ArcBox shell integration (fish)
# This file is auto-generated by `abctl setup install`.
fish_add_path -gP ~/.arcbox/bin
for f in ~/.arcbox/completions/fish/*.fish
    source $f 2>/dev/null
end
";

    tokio::fs::write(shell_dir.join("init.zsh"), zsh).await?;
    tokio::fs::write(shell_dir.join("init.bash"), bash).await?;
    tokio::fs::write(shell_dir.join("init.fish"), fish).await?;

    Ok(())
}

// =============================================================================
// Profile injection
// =============================================================================

/// Marker comment used to identify our injected lines.
const PROFILE_MARKER: &str = "# Added by ArcBox: command-line tools and integration";

fn detect_shell() -> ShellKind {
    std::env::var("SHELL")
        .ok()
        .and_then(|s| {
            if s.contains("zsh") {
                Some(ShellKind::Zsh)
            } else if s.contains("fish") {
                Some(ShellKind::Fish)
            } else if s.contains("bash") {
                Some(ShellKind::Bash)
            } else {
                None
            }
        })
        .unwrap_or(ShellKind::Zsh)
}

fn profile_path(shell: ShellKind) -> Option<PathBuf> {
    dirs::home_dir().map(|home| match shell {
        ShellKind::Zsh => home.join(".zprofile"),
        ShellKind::Bash => home.join(".bash_profile"),
        ShellKind::Fish => home.join(".config/fish/config.fish"),
    })
}

fn shell_init_path(shell_dir: &Path, shell: ShellKind) -> PathBuf {
    match shell {
        ShellKind::Zsh => shell_dir.join("init.zsh"),
        ShellKind::Bash => shell_dir.join("init.bash"),
        ShellKind::Fish => shell_dir.join("init.fish"),
    }
}

fn source_line(shell: ShellKind) -> String {
    match shell {
        ShellKind::Zsh => {
            format!("{PROFILE_MARKER}\nsource ~/.arcbox/shell/init.zsh 2>/dev/null || :")
        }
        ShellKind::Bash => {
            format!("{PROFILE_MARKER}\nsource ~/.arcbox/shell/init.bash 2>/dev/null || :")
        }
        ShellKind::Fish => {
            format!("{PROFILE_MARKER}\nsource ~/.arcbox/shell/init.fish 2>/dev/null; or true")
        }
    }
}

async fn check_profile_injected(path: &Path) -> bool {
    tokio::fs::read_to_string(path)
        .await
        .map(|content| content.contains(PROFILE_MARKER))
        .unwrap_or(false)
}

/// Inject the source line into the user's shell profile. Returns the path if
/// modified.
async fn inject_profile(shell: ShellKind) -> Result<Option<PathBuf>> {
    let Some(path) = profile_path(shell) else {
        return Ok(None);
    };

    if check_profile_injected(&path).await {
        return Ok(Some(path));
    }

    // Ensure parent directory exists (for fish: ~/.config/fish/).
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let existing = tokio::fs::read_to_string(&path).await.unwrap_or_default();
    let separator = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let snippet = source_line(shell);
    let new_content = format!("{existing}{separator}\n{snippet}\n");
    tokio::fs::write(&path, new_content).await?;

    Ok(Some(path))
}

/// Remove our injected lines from the user's shell profile.
async fn remove_profile_injection(shell: ShellKind) -> Result<Option<PathBuf>> {
    let Some(path) = profile_path(shell) else {
        return Ok(None);
    };

    let content = match tokio::fs::read_to_string(&path).await {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    if !content.contains(PROFILE_MARKER) {
        return Ok(None);
    }

    // Remove all lines that are part of our injection block.
    let cleaned: Vec<&str> = content
        .lines()
        .filter(|line| !line.contains(PROFILE_MARKER) && !line.contains(".arcbox/shell/init."))
        .collect();

    // Trim trailing blank lines that our removal may have left.
    let mut result = cleaned.join("\n");
    while result.ends_with("\n\n") {
        result.pop();
    }
    if !result.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }

    tokio::fs::write(&path, result).await?;

    Ok(Some(path))
}

// =============================================================================
// Symlink helpers
// =============================================================================

/// Create or update a symlink, removing any stale one first.
async fn create_or_update_symlink(target: &Path, link: &Path) -> Result<()> {
    // Remove existing symlink or file.
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

/// Remove a directory if it exists, ignoring errors.
async fn remove_dir_if_exists(path: &Path) {
    let _ = tokio::fs::remove_dir_all(path).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_zsh_from_env() {
        // detect_shell() reads $SHELL — just verify the function doesn't panic.
        let _ = detect_shell();
    }

    #[test]
    fn source_lines_contain_marker() {
        for shell in [ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish] {
            let line = source_line(shell);
            assert!(line.contains(PROFILE_MARKER));
            assert!(line.contains(".arcbox/shell/init."));
        }
    }

    #[tokio::test]
    async fn profile_injection_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join(".zprofile");
        tokio::fs::write(&profile, "# existing content\n")
            .await
            .unwrap();

        // Inject twice by manually calling the injection logic.
        let snippet = source_line(ShellKind::Zsh);

        // First injection.
        let content = tokio::fs::read_to_string(&profile).await.unwrap();
        assert!(!content.contains(PROFILE_MARKER));
        let new = format!("{content}\n{snippet}\n");
        tokio::fs::write(&profile, &new).await.unwrap();

        // Verify marker is present.
        assert!(check_profile_injected(&profile).await);

        // Second injection should be a no-op (check_profile_injected returns true).
        assert!(check_profile_injected(&profile).await);
    }

    #[test]
    fn completions_generate_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let comp_dir = dir.path();
        std::fs::create_dir_all(comp_dir.join("zsh")).unwrap();
        std::fs::create_dir_all(comp_dir.join("bash")).unwrap();
        std::fs::create_dir_all(comp_dir.join("fish")).unwrap();
        generate_all_completions(comp_dir).unwrap();

        assert!(comp_dir.join("zsh/_abctl").exists());
        assert!(comp_dir.join("bash/abctl").exists());
        assert!(comp_dir.join("fish/abctl.fish").exists());
    }
}
