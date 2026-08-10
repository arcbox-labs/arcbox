use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::super::OutputFormat;
use super::{bin_dir, profile};

#[derive(Debug, Clone, Serialize)]
pub(in crate::commands) struct ShellIntegrationStatus {
    pub(in crate::commands) shell: String,
    pub(in crate::commands) bin_symlink: ComponentStatus,
    pub(in crate::commands) profile: ComponentStatus,
    pub(in crate::commands) login_path: ComponentStatus,
    pub(in crate::commands) completions: ComponentStatus,
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

/// A check's outcome. `Unknown` means the check could not be run at all —
/// distinct from `Failed`, which means it ran and the component is broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(in crate::commands) enum CheckState {
    Ok,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::commands) struct ComponentStatus {
    pub(in crate::commands) state: CheckState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::commands) path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::commands) detail: Option<String>,
}

impl ComponentStatus {
    pub(in crate::commands) fn is_ok(&self) -> bool {
        self.state == CheckState::Ok
    }

    pub(in crate::commands) fn is_failed(&self) -> bool {
        self.state == CheckState::Failed
    }

    fn at(ok: bool, path: impl Into<String>) -> Self {
        Self {
            state: if ok {
                CheckState::Ok
            } else {
                CheckState::Failed
            },
            path: Some(path.into()),
            detail: None,
        }
    }

    fn checked(
        ok: bool,
        path: Option<String>,
        detail: Option<String>,
        failure: &'static str,
    ) -> Self {
        Self {
            state: if ok {
                CheckState::Ok
            } else {
                CheckState::Failed
            },
            path,
            detail: (!ok).then(|| detail.unwrap_or_else(|| failure.to_owned())),
        }
    }

    fn unknown(path: Option<String>, detail: String) -> Self {
        Self {
            state: CheckState::Unknown,
            path,
            detail: Some(detail),
        }
    }
}

pub(in crate::commands) async fn shell_integration_status() -> ShellIntegrationStatus {
    let shell = profile::detect_shell();
    let (profile_path, profile_injected, profile_error) = match profile::profile_path(shell).await {
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
    let bin_path = bin_dir().join("abctl");
    let (binary_ok, binary_detail) = match inspect_bin_link(&bin_path).await {
        Ok(status) => status,
        Err(error) => (false, Some(format!("{error:#}"))),
    };
    let (login_path, completions) = login_components(
        probe,
        Some(bin_dir().display().to_string()),
        Some(profile::completion_path(shell).display().to_string()),
    );
    ShellIntegrationStatus {
        shell: shell.as_str().to_owned(),
        bin_symlink: ComponentStatus {
            state: if binary_ok {
                CheckState::Ok
            } else {
                CheckState::Failed
            },
            path: Some(bin_path.display().to_string()),
            detail: binary_detail,
        },
        profile: ComponentStatus::checked(
            profile_injected,
            profile_path,
            profile_error,
            "effective shell profile does not contain ArcBox integration",
        ),
        login_path,
        completions,
    }
}

/// Splits one login-shell probe into the two components it answers for.
///
/// A probe that never ran leaves both `Unknown`: it observed neither the PATH
/// nor the completion, and calling that "not installed" both misreports a
/// healthy setup and offers a repair that cannot fix a probe failure.
fn login_components(
    probe: profile::LoginProbe,
    login_bin: Option<String>,
    completion: Option<String>,
) -> (ComponentStatus, ComponentStatus) {
    match probe {
        profile::LoginProbe::Verified {
            path_ok,
            completion_ok,
        } => (
            ComponentStatus::checked(
                path_ok,
                login_bin,
                None,
                "effective login shell does not resolve ArcBox abctl",
            ),
            ComponentStatus::checked(
                completion_ok,
                completion,
                None,
                "completion is not discoverable in the login shell",
            ),
        ),
        profile::LoginProbe::Unverified { detail } => (
            ComponentStatus::unknown(login_bin, format!("login shell probe failed: {detail}")),
            ComponentStatus::unknown(completion, format!("login shell probe failed: {detail}")),
        ),
    }
}

pub(super) async fn status(format: OutputFormat) -> Result<()> {
    let shell = profile::detect_shell();
    let init_path = profile::init_path(shell);
    let init_ok = tokio::fs::try_exists(&init_path).await?;
    let integration = shell_integration_status().await;
    let (plugins_ok, plugin_detail) = docker_plugin_status().await;
    let components = [
        integration.bin_symlink.clone(),
        ComponentStatus::at(init_ok, init_path.display().to_string()),
        integration.profile.clone(),
        integration.login_path.clone(),
        integration.completions.clone(),
        ComponentStatus {
            state: if plugins_ok {
                CheckState::Ok
            } else {
                CheckState::Failed
            },
            path: None,
            detail: plugin_detail.clone(),
        },
    ];
    let installed = components.iter().all(ComponentStatus::is_ok);
    // A check that could not run is not a broken integration: report it, but
    // do not claim the setup is partial or exit nonzero over it.
    let broken = components.iter().any(ComponentStatus::is_failed);
    let output = StatusOutput {
        installed,
        bin_symlink: integration.bin_symlink,
        shell_init: ComponentStatus::at(init_ok, init_path.display().to_string()),
        profile_injected: integration.profile,
        login_path: integration.login_path,
        completions: integration.completions,
        docker_plugins: ComponentStatus {
            state: if plugins_ok {
                CheckState::Ok
            } else {
                CheckState::Failed
            },
            path: None,
            detail: plugin_detail,
        },
        repair: broken.then_some("Run `abctl setup install` and restart your shell."),
    };

    let summary = if installed {
        "installed"
    } else if broken {
        "partial"
    } else {
        "unknown"
    };
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(&output)?),
        OutputFormat::Quiet => println!("{summary}"),
        OutputFormat::Table => print_table(&output, summary),
    }
    if broken {
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

fn print_table(output: &StatusOutput, summary: &str) {
    println!("ArcBox CLI Setup Status");
    println!("=======================\n");
    print_component("CLI symlink", &output.bin_symlink);
    print_component("Shell init", &output.shell_init);
    print_component("Profile injection", &output.profile_injected);
    print_component("Login PATH", &output.login_path);
    print_component("Completions", &output.completions);
    print_component("Docker plugins", &output.docker_plugins);
    println!("\nStatus: {summary}");
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
    let mark = match component.state {
        CheckState::Ok => "+",
        CheckState::Failed => "-",
        CheckState::Unknown => "?",
    };
    println!("  [{mark}] {label:<20} {detail}");
}

#[cfg(all(test, unix))]
mod tests {
    use super::{CheckState, ComponentStatus, inspect_bin_link, login_components, profile};

    #[test]
    fn a_probe_that_could_not_run_is_unknown_rather_than_failed() {
        let (path, completion) = login_components(
            profile::LoginProbe::Unverified {
                detail: "login shell probe timed out".to_owned(),
            },
            Some("/bin".to_owned()),
            Some("/completions/_abctl".to_owned()),
        );

        for component in [&path, &completion] {
            assert_eq!(component.state, CheckState::Unknown);
            assert!(!component.is_failed());
            assert!(!component.is_ok());
            assert_eq!(
                component.detail.as_deref(),
                Some("login shell probe failed: login shell probe timed out")
            );
        }

        let (path, completion) = login_components(
            profile::LoginProbe::Verified {
                path_ok: true,
                completion_ok: false,
            },
            None,
            None,
        );
        assert!(path.is_ok());
        assert!(completion.is_failed());
    }

    #[test]
    fn component_detail_is_scoped_to_a_failed_check() {
        let passing = ComponentStatus::checked(
            true,
            Some("completion".to_owned()),
            Some("unrelated failure".to_owned()),
            "missing completion",
        );
        let failing = ComponentStatus::checked(
            false,
            Some("completion".to_owned()),
            None,
            "missing completion",
        );

        assert_eq!(passing.detail, None);
        assert_eq!(failing.detail.as_deref(), Some("missing completion"));
    }

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
