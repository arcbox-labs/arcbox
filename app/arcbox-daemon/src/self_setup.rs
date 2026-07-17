//! Best-effort self-setup tasks that the daemon runs during startup.
//!
//! Each task follows the check → apply pattern: if the precondition is
//! already met, skip; otherwise ask `arcbox-helper` to configure it.
//! Failures are logged as warnings — they never block daemon readiness.
//! For CLI-only users, `abctl _install` performs the initial helper setup.
//!
//! Adding a new task: implement [`SetupTask`] in a new file under
//! `self_setup/`, then add it to the `run()` call in `main.rs`.

mod cli_tools;
mod dns_resolver;
mod docker_socket;
mod hosts_alias;

pub use cli_tools::CliTools;
pub use dns_resolver::DnsResolver;
pub use docker_socket::DockerSocket;
pub use hosts_alias::HostsAlias;

use arcbox_helper::client::{Client, ClientError};

/// A self-setup task that can be checked and applied via the helper daemon.
#[async_trait::async_trait]
pub trait SetupTask: Send + Sync {
    /// Human-readable name for log messages.
    fn name(&self) -> &'static str;

    /// Returns `true` if the task is already satisfied (no work needed).
    fn is_satisfied(&self) -> bool;

    /// Applies the task via the helper client.
    async fn apply(&self, client: &Client) -> Result<(), ClientError>;
}

/// Runs all setup tasks on a shared helper connection.
///
/// Connects once and runs tasks sequentially — this keeps the helper alive
/// for the duration (launchd socket activation starts it on first connect).
/// If the helper is unreachable, all tasks are skipped.
pub async fn run(tasks: &[&dyn SetupTask]) {
    let client = match Client::connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(
                error = %e,
                "arcbox-helper not reachable, skipping self-setup"
            );
            return;
        }
    };

    let expected_version = env!("CARGO_PKG_VERSION");
    match client.version().await {
        Ok(version) if version == expected_version => {}
        Ok(version) => tracing::warn!(
            helper_version = %version,
            daemon_version = expected_version,
            "arcbox-helper version differs from daemon; run 'sudo abctl _install --no-daemon --no-shell'"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "failed to check arcbox-helper version"
        ),
    }

    for task in tasks {
        let name = task.name();

        if task.is_satisfied() {
            tracing::debug!(task = name, "already satisfied");
            continue;
        }

        match task.apply(&client).await {
            Ok(()) => tracing::info!(task = name, "configured"),
            Err(e) => tracing::warn!(
                task = name,
                error = %e,
                "failed (run 'sudo arcbox install' to fix)"
            ),
        }
    }
}
