use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::super::OutputFormat;
use super::{bin_dir, profile};

#[derive(Debug, Clone, Serialize)]
pub(in crate::commands) struct ShellIntegrationStatus {
    pub(in crate::commands) shell: String,
    pub(in crate::commands) profile_path: Option<String>,
    pub(in crate::commands) profile_injected: bool,
    pub(in crate::commands) path_ok: bool,
    pub(in crate::commands) completion_ok: bool,
    pub(in crate::commands) detail: Option<String>,
}

#[derive(Serialize)]
struct StatusOutput {
    installed: bool,
    bin_symlink: ComponentStatus,
    shell_init: ComponentStatus,
    profile_injected: ComponentStatus,
    login_path: ComponentStatus,
    completions: ComponentStatus,
    docker_plugins: ComponentStatus,
    repair: Option<&'static str>,
}

#[derive(Serialize)]
struct ComponentStatus {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl ComponentStatus {
    fn at(ok: bool, path: impl Into<String>) -> Self {
        Self {
            ok,
            path: Some(path.into()),
            detail: None,
        }
    }
}

pub(in crate::commands) async fn shell_integration_status() -> ShellIntegrationStatus {
    let shell = profile::detect_shell();
    let (profile_path, profile_injected, path_error) = match profile::profile_path(shell).await {
        Ok(path) => match profile::is_injected(&path, shell).await {
            Ok(injected) => (Some(path.display().to_string()), injected, None),
            Err(error) => (
                Some(path.display().to_string()),
                false,
                Some(format!("{error:#}")),
            ),
        },
        Err(error) => (None, false, Some(format!("{error:#}"))),
    };
    let probe = profile::probe_login(shell).await;
    let (binary_ok, binary_detail) = match inspect_bin_link(&bin_dir().join("abctl")).await {
        Ok(status) => status,
        Err(error) => (false, Some(format!("{error:#}"))),
    };
    ShellIntegrationStatus {
        shell: shell.as_str().to_owned(),
        profile_path,
        profile_injected,
        path_ok: probe.path_ok && binary_ok,
        completion_ok: probe.completion_ok,
        detail: probe.detail.or(path_error).or_else(|| {
            (!binary_ok).then(|| {
                binary_detail.unwrap_or_else(|| "ArcBox abctl symlink is missing".to_owned())
            })
        }),
    }
}

pub(super) async fn status(format: OutputFormat) -> Result<()> {
    let bin_link = bin_dir().join("abctl");
    let (symlink_ok, symlink_detail) = inspect_bin_link(&bin_link).await?;

    let shell = profile::detect_shell();
    let init_path = profile::init_path(shell);
    let init_ok = tokio::fs::try_exists(&init_path).await?;
    let integration = shell_integration_status().await;
    let completion_path = profile::completion_path(shell);
    let (plugins_ok, plugin_detail) = docker_plugin_status().await;
    let installed = symlink_ok
        && init_ok
        && integration.profile_injected
        && integration.path_ok
        && integration.completion_ok
        && plugins_ok;
    let output = StatusOutput {
        installed,
        bin_symlink: ComponentStatus {
            ok: symlink_ok,
            path: Some(bin_link.display().to_string()),
            detail: symlink_detail,
        },
        shell_init: ComponentStatus::at(init_ok, init_path.display().to_string()),
        profile_injected: ComponentStatus {
            ok: integration.profile_injected,
            path: integration.profile_path.clone(),
            detail: integration.detail.clone(),
        },
        login_path: ComponentStatus {
            ok: integration.path_ok,
            path: Some(bin_dir().display().to_string()),
            detail: integration.detail.clone().or_else(|| {
                (!integration.path_ok)
                    .then(|| "effective login shell does not resolve ArcBox abctl".to_owned())
            }),
        },
        completions: ComponentStatus {
            ok: integration.completion_ok,
            path: Some(completion_path.display().to_string()),
            detail: integration.detail.or_else(|| {
                (!integration.completion_ok)
                    .then(|| "completion is not discoverable in the login shell".to_owned())
            }),
        },
        docker_plugins: ComponentStatus {
            ok: plugins_ok,
            path: None,
            detail: plugin_detail,
        },
        repair: (!installed).then_some("Run `abctl setup install` and restart your shell."),
    };

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(&output)?),
        OutputFormat::Quiet => println!("{}", if installed { "installed" } else { "partial" }),
        OutputFormat::Table => print_table(&output),
    }
    if !installed {
        bail!("ArcBox shell integration is incomplete");
    }
    Ok(())
}

async fn inspect_bin_link(path: &Path) -> Result<(bool, Option<String>)> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((false, None)),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_symlink() {
        return Ok((false, Some("not a symlink".to_owned())));
    }

    let target = tokio::fs::read_link(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    let resolved = match tokio::fs::canonicalize(path).await {
        Ok(resolved) => resolved,
        Err(error) => {
            return Ok((
                false,
                Some(format!("{} (unresolvable: {error})", target.display())),
            ));
        }
    };
    let current = tokio::fs::canonicalize(std::env::current_exe()?)
        .await
        .context("failed to resolve the running abctl executable")?;
    if resolved == current {
        Ok((true, Some(target.display().to_string())))
    } else {
        Ok((
            false,
            Some(format!(
                "{} resolves to {}, expected {}",
                target.display(),
                resolved.display(),
                current.display()
            )),
        ))
    }
}

async fn docker_plugin_status() -> (bool, Option<String>) {
    let bin = bin_dir();
    let present = arcbox_constants::paths::DOCKER_CLI_PLUGINS
        .iter()
        .any(|name| bin.join(name).exists());
    if !present {
        return (
            true,
            Some("skipped (no Docker CLI plugin binaries present)".to_owned()),
        );
    }
    let config = match super::super::cli_plugins::default_docker_config_dir() {
        Ok(config) => config,
        Err(error) => return (false, Some(format!("{error:#}"))),
    };
    let status = super::super::cli_plugins::status(&bin, &config).await;
    let ok = !status.symlinked.is_empty() || status.extra_dirs_entry_present;
    (
        ok,
        Some(format!(
            "{} symlinks, extraDirs: {}",
            status.symlinked.len(),
            if status.extra_dirs_entry_present {
                "yes"
            } else {
                "no"
            }
        )),
    )
}

fn print_table(output: &StatusOutput) {
    println!("ArcBox CLI Setup Status");
    println!("=======================\n");
    print_component("CLI symlink", &output.bin_symlink);
    print_component("Shell init", &output.shell_init);
    print_component("Profile injection", &output.profile_injected);
    print_component("Login PATH", &output.login_path);
    print_component("Completions", &output.completions);
    print_component("Docker plugins", &output.docker_plugins);
    println!(
        "\nStatus: {}",
        if output.installed {
            "installed"
        } else {
            "partial"
        }
    );
    if let Some(repair) = output.repair {
        println!("Repair: {repair}");
    }
}

fn print_component(label: &str, component: &ComponentStatus) {
    let detail = match (&component.path, &component.detail) {
        (Some(path), Some(detail)) => format!("{path} ({detail})"),
        (Some(path), None) => path.clone(),
        (None, Some(detail)) => detail.clone(),
        (None, None) => String::new(),
    };
    println!(
        "  [{}] {:<20} {}",
        if component.ok { "+" } else { "-" },
        label,
        detail
    );
}

#[cfg(all(test, unix))]
mod tests {
    use super::inspect_bin_link;

    #[tokio::test]
    async fn bin_link_must_resolve_to_the_running_executable() {
        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("abctl");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &link).unwrap();
        assert!(inspect_bin_link(&link).await.unwrap().0);

        std::fs::remove_file(&link).unwrap();
        let foreign = directory.path().join("foreign");
        std::fs::write(&foreign, "not ArcBox").unwrap();
        std::os::unix::fs::symlink(&foreign, &link).unwrap();
        assert!(!inspect_bin_link(&link).await.unwrap().0);
    }
}
