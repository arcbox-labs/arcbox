//! Kubernetes integration and lifecycle commands.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use arcbox_connect::v1 as pb;
use arcbox_connect::v1::KubernetesServiceClient;
use arcbox_constants::paths::{ArcboxProfile, HostLayout};
use arcbox_docker_tools::{HostToolManager, ToolGroup, parse_tools_for_group};
use clap::Subcommand;

use crate::connect;

/// Embedded `assets.lock` (same copy used by Docker/Kubernetes host tools).
const LOCK_TOML: &str = include_str!("../../../../assets.lock");

#[derive(Debug, Subcommand)]
pub enum KubernetesCommands {
    /// Start the native Kubernetes cluster
    Start,
    /// Stop the native Kubernetes cluster
    Stop,
    /// Restart the native Kubernetes cluster
    Restart,
    /// Delete the native Kubernetes cluster state
    Delete,
    /// Show cluster and integration status
    Status,
    /// Enable ArcBox Kubernetes host integration
    Enable,
    /// Disable ArcBox Kubernetes host integration
    Disable,
    /// Print the ArcBox-managed kubeconfig
    Kubeconfig,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct KubernetesIntegrationState {
    enabled: bool,
    previous_context: Option<String>,
    managed_context: Option<String>,
}

pub async fn execute(cmd: KubernetesCommands) -> Result<()> {
    match cmd {
        KubernetesCommands::Start => execute_start().await,
        KubernetesCommands::Stop => execute_stop().await,
        KubernetesCommands::Restart => execute_restart().await,
        KubernetesCommands::Delete => execute_delete().await,
        KubernetesCommands::Status => execute_status().await,
        KubernetesCommands::Enable => execute_enable().await,
        KubernetesCommands::Disable => execute_disable().await,
        KubernetesCommands::Kubeconfig => execute_kubeconfig().await,
    }
}

fn kubernetes_client() -> KubernetesServiceClient<connectrpc::client::SharedHttp2Connection> {
    let (transport, config) = connect::daemon(&super::resolve_grpc_socket_path());
    KubernetesServiceClient::new(transport, config)
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().context("could not determine home directory")
}

fn profile_dir() -> PathBuf {
    HostLayout::from_env_or_default().data_dir
}

fn managed_context_name() -> &'static str {
    ArcboxProfile::from_env_or_default().docker_context_name()
}

fn managed_kubeconfig_path(_home: &Path) -> PathBuf {
    profile_dir().join("kube").join("arcbox.yaml")
}

fn integration_state_path(_home: &Path) -> PathBuf {
    profile_dir().join("kube").join("state.json")
}

fn user_kubeconfig_path(home: &Path) -> PathBuf {
    home.join(".kube").join("config")
}

fn runtime_bin_dir(_home: &Path) -> PathBuf {
    profile_dir().join("runtime").join("bin")
}

fn kubectl_bin(home: &Path) -> PathBuf {
    runtime_bin_dir(home).join("kubectl")
}

async fn load_state(home: &Path) -> Result<KubernetesIntegrationState> {
    let path = integration_state_path(home);
    if !path.exists() {
        return Ok(KubernetesIntegrationState::default());
    }

    let bytes = tokio::fs::read(&path).await?;
    serde_json::from_slice(&bytes).context("failed to parse Kubernetes integration state")
}

#[cfg(unix)]
async fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::write(path, contents.as_ref()).await?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    tokio::fs::write(path, contents.as_ref()).await?;
    Ok(())
}

async fn save_state(home: &Path, state: &KubernetesIntegrationState) -> Result<()> {
    let path = integration_state_path(home);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let bytes = serde_json::to_vec_pretty(state)?;
    tokio::fs::write(path, bytes).await?;
    Ok(())
}

async fn install_kubernetes_tools(home: &Path) -> Result<()> {
    let tools = parse_tools_for_group(LOCK_TOML, ToolGroup::Kubernetes)
        .context("failed to parse assets.lock")?;
    if tools.is_empty() {
        return Ok(());
    }

    let runtime_bin = runtime_bin_dir(home);
    let arch = arcbox_asset::current_arch().to_string();
    let manager = HostToolManager::new(tools, arch, runtime_bin.clone());
    manager
        .install_all(None)
        .await
        .context("failed to install kubectl")?;

    let user_bin = profile_dir().join("bin");
    tokio::fs::create_dir_all(&user_bin).await?;
    let target = runtime_bin.join("kubectl");
    let link = user_bin.join("kubectl");
    if tokio::fs::symlink_metadata(&link).await.is_ok() {
        tokio::fs::remove_file(&link).await.ok();
    }
    #[cfg(unix)]
    tokio::fs::symlink(&target, &link).await.with_context(|| {
        format!(
            "failed to create symlink {} -> {}",
            link.display(),
            target.display()
        )
    })?;

    Ok(())
}

async fn current_context(home: &Path) -> Result<Option<String>> {
    let kubectl = kubectl_bin(home);
    let kubeconfig = user_kubeconfig_path(home);
    if !kubectl.exists() || !kubeconfig.exists() {
        return Ok(None);
    }

    let output = tokio::process::Command::new(&kubectl)
        .arg("config")
        .arg("current-context")
        .arg("--kubeconfig")
        .arg(&kubeconfig)
        .output()
        .await
        .context("failed to query current kube context")?;

    if !output.status.success() {
        return Ok(None);
    }

    let context = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if context.is_empty() {
        Ok(None)
    } else {
        Ok(Some(context))
    }
}

async fn merge_managed_kubeconfig(home: &Path) -> Result<()> {
    let kubectl = kubectl_bin(home);
    let managed = managed_kubeconfig_path(home);
    let user = user_kubeconfig_path(home);

    if let Some(parent) = user.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    if !user.exists() {
        let bytes = tokio::fs::read(&managed).await?;
        write_private_file(&user, bytes).await?;
        return Ok(());
    }

    let output = tokio::process::Command::new(&kubectl)
        .arg("config")
        .arg("view")
        .arg("--flatten")
        .env(
            "KUBECONFIG",
            format!("{}:{}", user.display(), managed.display()),
        )
        .output()
        .await
        .context("failed to merge kubeconfig")?;

    if !output.status.success() {
        bail!(
            "kubectl config view failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    write_private_file(&user, &output.stdout).await?;
    Ok(())
}

/// What the global current-context owes after a kubeconfig merge.
#[derive(Debug, PartialEq, Eq)]
enum CurrentContextFix<'a> {
    /// The merge left the selection where it was.
    Keep,
    /// Put back the selection the merge displaced.
    Restore(&'a str),
    /// The merge created a selection where the user had none.
    Clear,
}

/// Decides [`CurrentContextFix`] for a profile that may not own the selection.
///
/// Not writing the current-context is not the same as not changing it.
/// `merge_managed_kubeconfig` copies the managed kubeconfig verbatim when the
/// user has none, and that file carries `current-context: <managed>`
/// (`rewrite_kubeconfig` puts it there); the merge path inherits it too,
/// because `kubectl config view --flatten` takes the current-context from the
/// first file that sets one. So a development instance activates its own
/// context globally just by writing the file — the very thing skipping
/// `set_current_context` was meant to prevent. Comparing before against after
/// covers all three shapes (no user kubeconfig, one without a
/// current-context, one with) and never asks kubectl to unset a key that is
/// not there.
fn current_context_restore<'a>(
    owns_global: bool,
    before: Option<&'a str>,
    after: Option<&str>,
) -> CurrentContextFix<'a> {
    if owns_global || before == after {
        CurrentContextFix::Keep
    } else {
        before.map_or(CurrentContextFix::Clear, CurrentContextFix::Restore)
    }
}

/// Applies [`current_context_restore`] after a merge.
async fn restore_current_context(home: &Path, before: Option<&str>) -> Result<()> {
    let after = current_context(home).await?;
    match current_context_restore(false, before, after.as_deref()) {
        CurrentContextFix::Keep => Ok(()),
        CurrentContextFix::Restore(previous) => set_current_context(home, previous).await,
        CurrentContextFix::Clear => unset_current_context(home).await,
    }
}

async fn unset_current_context(home: &Path) -> Result<()> {
    let kubectl = kubectl_bin(home);
    let kubeconfig = user_kubeconfig_path(home);
    let output = tokio::process::Command::new(&kubectl)
        .arg("config")
        .arg("unset")
        .arg("current-context")
        .arg("--kubeconfig")
        .arg(&kubeconfig)
        .output()
        .await
        .context("failed to clear the current kube context")?;

    if !output.status.success() {
        bail!(
            "kubectl config unset current-context failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

async fn set_current_context(home: &Path, context: &str) -> Result<()> {
    let kubectl = kubectl_bin(home);
    let kubeconfig = user_kubeconfig_path(home);
    let output = tokio::process::Command::new(&kubectl)
        .arg("config")
        .arg("use-context")
        .arg(context)
        .arg("--kubeconfig")
        .arg(&kubeconfig)
        .output()
        .await
        .context("failed to switch kube context")?;

    if !output.status.success() {
        bail!(
            "kubectl config use-context failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

async fn delete_context_entries(home: &Path, managed_context: &str) -> Result<()> {
    let kubectl = kubectl_bin(home);
    let kubeconfig = user_kubeconfig_path(home);
    if !kubectl.exists() || !kubeconfig.exists() {
        return Ok(());
    }

    for args in [
        vec!["config", "delete-context", managed_context],
        vec!["config", "delete-cluster", managed_context],
        vec!["config", "delete-user", managed_context],
    ] {
        let _ = tokio::process::Command::new(&kubectl)
            .args(&args)
            .arg("--kubeconfig")
            .arg(&kubeconfig)
            .output()
            .await;
    }

    Ok(())
}

async fn refresh_managed_kubeconfig(home: &Path) -> Result<String> {
    let client = kubernetes_client();
    let response: pb::KubernetesKubeconfigResponse = client
        .get_kubeconfig(pb::KubernetesKubeconfigRequest::default())
        .await
        .context("failed to get ArcBox kubeconfig; run 'abctl k8s start' first")?
        .into_owned();

    let managed = managed_kubeconfig_path(home);
    if let Some(parent) = managed.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    write_private_file(&managed, response.kubeconfig).await?;
    Ok(resolve_managed_context_name(
        response.context_name,
        managed_context_name(),
    ))
}

fn resolve_managed_context_name(context_name: String, profile_default: &str) -> String {
    if context_name.is_empty() {
        profile_default.to_owned()
    } else {
        context_name
    }
}

async fn refresh_if_enabled(home: &Path) -> Result<()> {
    let state = load_state(home).await?;
    if !state.enabled {
        return Ok(());
    }

    let current_context = current_context(home).await?;
    let owns_current_context = owns_global_current_context(ArcboxProfile::from_env_or_default());
    let restore_managed_context = owns_current_context
        && should_restore_managed_context(
            current_context.as_deref(),
            state.managed_context.as_deref(),
            managed_context_name(),
        );
    let managed_context = refresh_managed_kubeconfig(home).await?;
    delete_context_entries(home, &managed_context).await?;
    merge_managed_kubeconfig(home).await?;
    if restore_managed_context {
        set_current_context(home, &managed_context).await?;
    } else if !owns_current_context {
        // The refresh merges too, so it can activate the development context
        // on a host with no user kubeconfig exactly like `enable` can.
        restore_current_context(home, current_context.as_deref()).await?;
    }
    save_state(
        home,
        &KubernetesIntegrationState {
            managed_context: Some(managed_context),
            ..state
        },
    )
    .await?;
    Ok(())
}

fn owns_global_current_context(profile: ArcboxProfile) -> bool {
    profile == ArcboxProfile::Production
}

fn should_restore_managed_context(
    current_context: Option<&str>,
    previous_managed_context: Option<&str>,
    profile_default: &str,
) -> bool {
    current_context == Some(previous_managed_context.unwrap_or(profile_default))
}

async fn execute_start() -> Result<()> {
    let client = kubernetes_client();
    let response: pb::KubernetesStartResponse = client
        .start(pb::KubernetesStartRequest::default())
        .await
        .context("failed to start Kubernetes")?
        .into_owned();

    println!(
        "Kubernetes: {}",
        if response.api_ready {
            "ready"
        } else {
            "starting"
        }
    );
    println!("Endpoint: {}", response.endpoint);
    if !response.detail.is_empty() {
        println!("Detail:   {}", response.detail);
    }

    let home = home_dir()?;
    refresh_if_enabled(&home).await?;
    Ok(())
}

async fn execute_stop() -> Result<()> {
    let client = kubernetes_client();
    let response: pb::KubernetesStopResponse = client
        .stop(pb::KubernetesStopRequest::default())
        .await
        .context("failed to stop Kubernetes")?
        .into_owned();

    println!("Kubernetes stopped: {}", response.stopped);
    if !response.detail.is_empty() {
        println!("Detail: {}", response.detail);
    }
    Ok(())
}

async fn execute_restart() -> Result<()> {
    execute_stop().await?;
    execute_start().await
}

async fn execute_delete() -> Result<()> {
    let client = kubernetes_client();
    let response: pb::KubernetesDeleteResponse = client
        .delete(pb::KubernetesDeleteRequest::default())
        .await
        .context("failed to delete Kubernetes")?
        .into_owned();

    println!("Kubernetes cluster deleted.");
    if !response.detail.is_empty() {
        println!("Detail: {}", response.detail);
    }
    Ok(())
}

async fn execute_status() -> Result<()> {
    let home = home_dir()?;
    let state = load_state(&home).await?;
    let kubectl_installed = kubectl_bin(&home).exists();

    let client = kubernetes_client();
    let status: pb::KubernetesStatusResponse = client
        .status(pb::KubernetesStatusRequest::default())
        .await
        .context("failed to get Kubernetes status")?
        .into_owned();

    println!(
        "Cluster:      {}",
        if status.running { "running" } else { "stopped" }
    );
    println!(
        "API:          {}",
        if status.api_ready {
            "reachable"
        } else {
            "not ready"
        }
    );
    println!("Endpoint:     {}", status.endpoint);
    println!(
        "Integration:  {}",
        if state.enabled { "enabled" } else { "disabled" }
    );
    println!(
        "kubectl:      {}",
        if kubectl_installed {
            "installed"
        } else {
            "not installed"
        }
    );
    if !status.detail.is_empty() {
        println!("Detail:       {}", status.detail);
    }
    for svc in status.services {
        println!("Service {}: {} ({})", svc.name, svc.status, svc.detail);
    }

    Ok(())
}

async fn execute_enable() -> Result<()> {
    let home = home_dir()?;
    install_kubernetes_tools(&home).await?;

    let owns_current_context = owns_global_current_context(ArcboxProfile::from_env_or_default());
    // Read unconditionally: a profile that does not own the global
    // current-context still has to know what it was, to put it back after the
    // merge writes one (see `current_context_restore`).
    let previous_context = current_context(&home).await?;
    let managed_context = refresh_managed_kubeconfig(&home).await?;
    delete_context_entries(&home, &managed_context).await?;
    merge_managed_kubeconfig(&home).await?;
    if owns_current_context {
        set_current_context(&home, &managed_context).await?;
    } else {
        restore_current_context(&home, previous_context.as_deref()).await?;
    }

    save_state(
        &home,
        &KubernetesIntegrationState {
            enabled: true,
            previous_context: previous_context.filter(|ctx| ctx != &managed_context),
            managed_context: Some(managed_context.clone()),
        },
    )
    .await?;

    println!("Kubernetes integration enabled.");
    if owns_current_context {
        println!("Current context: {managed_context}");
    } else {
        println!("Context added: {managed_context}");
        println!("Select it explicitly with 'kubectl config use-context {managed_context}'.");
    }
    println!("kubectl installed to {}", kubectl_bin(&home).display());
    Ok(())
}

async fn execute_disable() -> Result<()> {
    let home = home_dir()?;
    let state = load_state(&home).await?;
    let managed_context = state
        .managed_context
        .clone()
        .unwrap_or_else(|| managed_context_name().to_owned());
    let current_context = current_context(&home).await?;

    delete_context_entries(&home, &managed_context).await?;
    if current_context.as_deref() == Some(managed_context.as_str())
        && let Some(previous) = state.previous_context.as_deref()
    {
        let _ = set_current_context(&home, previous).await;
    }

    save_state(
        &home,
        &KubernetesIntegrationState {
            enabled: false,
            previous_context: state.previous_context,
            managed_context: state.managed_context,
        },
    )
    .await?;

    println!("Kubernetes integration disabled.");
    Ok(())
}

async fn execute_kubeconfig() -> Result<()> {
    let client = kubernetes_client();
    let response: pb::KubernetesKubeconfigResponse = client
        .get_kubeconfig(pb::KubernetesKubeconfigRequest::default())
        .await
        .context("failed to get kubeconfig")?
        .into_owned();
    print!("{}", response.kubeconfig);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CurrentContextFix, current_context_restore, owns_global_current_context,
        resolve_managed_context_name, should_restore_managed_context,
    };
    use arcbox_constants::paths::ArcboxProfile;

    #[test]
    fn context_name_uses_old_daemon_fallback_only_when_missing() {
        assert_eq!(
            resolve_managed_context_name(String::new(), "arcbox"),
            "arcbox"
        );
        assert_eq!(
            resolve_managed_context_name("arcbox-dev-instance-1".to_owned(), "arcbox-dev"),
            "arcbox-dev-instance-1"
        );
    }

    #[test]
    fn refresh_restores_only_the_context_owned_by_this_instance() {
        assert!(should_restore_managed_context(
            Some("arcbox-dev-a"),
            Some("arcbox-dev-a"),
            "arcbox-dev"
        ));
        assert!(should_restore_managed_context(
            Some("arcbox-dev"),
            None,
            "arcbox-dev"
        ));
        assert!(!should_restore_managed_context(
            Some("arcbox-dev-b"),
            Some("arcbox-dev-a"),
            "arcbox-dev"
        ));
        assert!(!should_restore_managed_context(
            None,
            Some("arcbox-dev-a"),
            "arcbox-dev"
        ));
    }

    #[test]
    fn only_production_owns_the_global_current_context() {
        assert!(owns_global_current_context(ArcboxProfile::Production));
        assert!(!owns_global_current_context(ArcboxProfile::Development));
    }

    /// The merge writes a `current-context` whether or not `enable` asks it
    /// to — verbatim when the user had no kubeconfig, inherited from the
    /// managed file when their own set none. A profile that does not own the
    /// global selection has to put back what was there, including "nothing".
    #[test]
    fn a_foreign_profile_puts_the_current_context_back() {
        // No user kubeconfig: the merge created one pointing at the managed
        // context, so it has to be cleared rather than left pointing there.
        assert_eq!(
            current_context_restore(false, None, Some("arcbox-dev")),
            CurrentContextFix::Clear
        );
        // A user context the merge displaced goes back.
        assert_eq!(
            current_context_restore(false, Some("docker-desktop"), Some("arcbox-dev")),
            CurrentContextFix::Restore("docker-desktop")
        );
        // The merge left it alone — including the case where the user had
        // deliberately selected the managed context themselves.
        assert_eq!(
            current_context_restore(false, Some("arcbox-dev"), Some("arcbox-dev")),
            CurrentContextFix::Keep
        );
        assert_eq!(
            current_context_restore(false, None, None),
            CurrentContextFix::Keep
        );
        // Production owns the selection and sets it explicitly.
        assert_eq!(
            current_context_restore(true, None, Some("arcbox")),
            CurrentContextFix::Keep
        );
    }
}
