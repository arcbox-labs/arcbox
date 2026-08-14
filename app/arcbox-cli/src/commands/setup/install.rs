use std::path::Path;

use anyhow::{Context, Result};

use super::super::OutputFormat;
use super::{bin_dir, completions, completions_dir, profile, shell_dir};

pub(super) async fn install(format: OutputFormat) -> Result<()> {
    let selected_shell = profile::detect_shell();
    let profile_path = profile::profile_path(selected_shell).await?;
    let bin = bin_dir();
    let shell = shell_dir();
    let completions = completions_dir();

    tokio::fs::create_dir_all(&bin).await?;
    tokio::fs::create_dir_all(&shell).await?;
    for name in ["zsh", "bash", "fish"] {
        tokio::fs::create_dir_all(completions.join(name)).await?;
    }

    let executable = std::env::current_exe().context("could not determine current executable")?;
    let abctl_link = bin.join("abctl");
    create_or_update_symlink(&executable, &abctl_link).await?;

    // Older installs linked ~/.arcbox/bin/arcbox to the rename shim, which no
    // longer ships — the link would dangle on PATH. Drop it here rather than in
    // `uninstall`, so an upgrade heals without the user removing anything.
    remove_stale_shim_link(&bin.join("arcbox")).await;

    let docker_tools = link_docker_tools(&executable, &bin).await;
    let (docker_plugins, plugin_error) = register_docker_plugins(&bin).await;
    write_init_scripts(&shell).await?;
    completions::generate_all(&completions)?;

    let profile_path = profile::inject(selected_shell, profile_path).await?;

    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "installed": true,
                "bin": abctl_link,
                "docker_tools": docker_tools,
                "docker_plugins": docker_plugins,
                "docker_plugins_error": plugin_error,
                "shell_init": shell,
                "completions": completions,
                "profile": profile_path,
            }))?
        ),
        OutputFormat::Quiet => {}
        OutputFormat::Table => {
            println!("ArcBox CLI Setup");
            println!("================\n");
            println!(
                "  Symlink:     {} -> {}",
                abctl_link.display(),
                executable.display()
            );
            if docker_tools > 0 {
                println!(
                    "  Docker:      {docker_tools} tools linked to {}",
                    bin.display()
                );
            }
            if !docker_plugins.symlinks.is_empty() || docker_plugins.config_updated {
                println!(
                    "  CLI plugins: {} registered (`docker compose` / `docker buildx`)",
                    docker_plugins.symlinks.len()
                );
            }
            if let Some(error) = plugin_error {
                println!("  CLI plugins: WARN: {error}");
            }
            println!("  Shell init:  {}", shell.display());
            println!("  Completions: {}", completions.display());
            println!("  Profile:     {} (updated)", profile_path.display());
            println!("\nRestart your shell or run:");
            println!("  source {}", profile::init_path(selected_shell).display());
        }
    }
    Ok(())
}

pub(super) async fn uninstall(format: OutputFormat) -> Result<()> {
    let selected_shell = profile::detect_shell();
    let profile_path = profile::profile_path(selected_shell).await?;
    let bin = bin_dir();
    let (docker_plugins, plugin_error) = unregister_docker_plugins(&bin).await;
    for path in [bin, shell_dir(), completions_dir()] {
        if tokio::fs::try_exists(&path).await? {
            tokio::fs::remove_dir_all(&path)
                .await
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    let cleaned_profile = profile::remove(selected_shell, profile_path).await?;

    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "uninstalled": true,
                "docker_plugins": docker_plugins,
                "docker_plugins_error": plugin_error,
                "profile_cleaned": cleaned_profile,
            }))?
        ),
        OutputFormat::Quiet => {}
        OutputFormat::Table => {
            println!("ArcBox CLI shell integration removed.");
            if !docker_plugins.symlinks.is_empty() || docker_plugins.config_updated {
                println!(
                    "  CLI plugins:  {} symlinks removed",
                    docker_plugins.symlinks.len()
                );
            }
            if let Some(error) = plugin_error {
                println!("  CLI plugins:  WARN: {error}");
            }
            if let Some(path) = cleaned_profile {
                println!("  Cleaned profile: {}", path.display());
            }
            println!("  Restart your shell to apply changes.");
        }
    }
    Ok(())
}

async fn register_docker_plugins(
    bin: &Path,
) -> (super::super::cli_plugins::Outcome, Option<String>) {
    match super::super::cli_plugins::default_docker_config_dir() {
        Ok(config) => match super::super::cli_plugins::register(bin, &config).await {
            Ok(outcome) => (outcome, None),
            Err(error) => (Default::default(), Some(format!("{error:#}"))),
        },
        Err(error) => (Default::default(), Some(format!("{error:#}"))),
    }
}

async fn unregister_docker_plugins(
    bin: &Path,
) -> (super::super::cli_plugins::Outcome, Option<String>) {
    match super::super::cli_plugins::default_docker_config_dir() {
        Ok(config) => match super::super::cli_plugins::unregister(bin, &config).await {
            Ok(outcome) => (outcome, None),
            Err(error) => (Default::default(), Some(format!("{error:#}"))),
        },
        Err(error) => (Default::default(), Some(format!("{error:#}"))),
    }
}

async fn write_init_scripts(directory: &Path) -> Result<()> {
    let root = directory
        .parent()
        .context("shell directory has no profile data directory parent")?;
    let bin = root.join("bin");
    let completions = root.join("completions");
    tokio::fs::write(
        directory.join("init.zsh"),
        format!(
            "# ArcBox shell integration (zsh)\nexport PATH=\"{}:${{PATH}}\"\nfpath+=(\"{}\")\n",
            bin.display(),
            completions.join("zsh").display()
        ),
    )
    .await?;
    tokio::fs::write(
        directory.join("init.bash"),
        format!(
            "# ArcBox shell integration (bash)\nexport PATH=\"{}:${{PATH}}\"\nfor _abctl_comp in \"{}\"/*; do\n    [ -f \"$_abctl_comp\" ] && source \"$_abctl_comp\"\ndone\nunset _abctl_comp\n",
            bin.display(),
            completions.join("bash").display()
        ),
    )
    .await?;
    tokio::fs::write(
        directory.join("init.fish"),
        format!(
            "# ArcBox shell integration (fish)\nfish_add_path -gP \"{}\"\nfor f in \"{}\"/*.fish\n    source $f 2>/dev/null\nend\n",
            bin.display(),
            completions.join("fish").display()
        ),
    )
    .await?;
    Ok(())
}

async fn link_docker_tools(executable: &Path, bin: &Path) -> usize {
    let mut candidates = Vec::new();
    if let Some(xbin) = super::super::symlink::detect_bundle_xbin() {
        candidates.push(xbin);
    } else if let Some(xbin) = executable
        .parent()
        .and_then(Path::parent)
        .map(|parent| parent.join("xbin"))
        .filter(|path| path.is_dir())
    {
        candidates.push(xbin);
    }
    let runtime_bin = super::arcbox_home().join("runtime/bin");
    if runtime_bin.is_dir() {
        candidates.push(runtime_bin);
    }

    let mut linked = 0;
    for name in arcbox_constants::paths::DOCKER_CLI_TOOLS {
        let link = bin.join(name);
        if valid_symlink(&link).await {
            linked += 1;
            continue;
        }
        if let Some(source) = candidates
            .iter()
            .map(|directory| directory.join(name))
            .find(|path| path.is_file())
        {
            if create_or_update_symlink(&source, &link).await.is_ok() {
                linked += 1;
            }
        }
    }
    linked
}

async fn valid_symlink(path: &Path) -> bool {
    tokio::fs::symlink_metadata(path)
        .await
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
        && tokio::fs::read_link(path)
            .await
            .is_ok_and(|target| target.exists())
}

/// Remove the retired `arcbox` shim link left by an older `setup install`.
///
/// Only symlinks are touched: this directory holds nothing but links we
/// created, so a regular file here is the user's and is left alone.
async fn remove_stale_shim_link(link: &Path) {
    let Ok(metadata) = tokio::fs::symlink_metadata(link).await else {
        return;
    };
    if metadata.file_type().is_symlink() {
        let _ = tokio::fs::remove_file(link).await;
    }
}

async fn create_or_update_symlink(target: &Path, link: &Path) -> Result<()> {
    if tokio::fs::symlink_metadata(link).await.is_ok() {
        tokio::fs::remove_file(link)
            .await
            .with_context(|| format!("failed to remove {}", link.display()))?;
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

#[cfg(test)]
mod tests {
    use super::{remove_stale_shim_link, write_init_scripts};

    #[tokio::test]
    async fn stale_shim_link_is_removed_but_a_real_file_is_kept() {
        let dir = tempfile::tempdir().unwrap();

        // A dangling link to the retired shim: the upgrade case.
        let link = dir.path().join("arcbox");
        tokio::fs::symlink(dir.path().join("gone"), &link)
            .await
            .unwrap();
        remove_stale_shim_link(&link).await;
        assert!(tokio::fs::symlink_metadata(&link).await.is_err());

        // A regular file of the same name is not ours to delete.
        let file = dir.path().join("arcbox-file");
        tokio::fs::write(&file, b"user data").await.unwrap();
        remove_stale_shim_link(&file).await;
        assert_eq!(tokio::fs::read(&file).await.unwrap(), b"user data");

        // Absent path is a no-op, not an error.
        remove_stale_shim_link(&dir.path().join("absent")).await;
    }

    #[tokio::test]
    async fn init_scripts_reference_the_selected_profile_root() {
        let root = tempfile::tempdir().unwrap();
        let shell = root.path().join("shell");
        tokio::fs::create_dir(&shell).await.unwrap();
        write_init_scripts(&shell).await.unwrap();

        let zsh = tokio::fs::read_to_string(shell.join("init.zsh"))
            .await
            .unwrap();
        assert!(zsh.contains(&root.path().join("bin").display().to_string()));
        assert!(zsh.contains(&root.path().join("completions/zsh").display().to_string()));
    }
}
