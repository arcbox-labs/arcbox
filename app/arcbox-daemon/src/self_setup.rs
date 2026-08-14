//! Host self-setup tasks that the daemon runs during startup.
//!
//! Each task follows the check → apply pattern: if the precondition is
//! already met, skip; otherwise ask `arcbox-helper` to configure it.
//! [`run`] preserves best-effort production setup, while [`run_required`]
//! makes an explicitly requested task part of the startup contract.
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

use anyhow::Context as _;
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

/// Runs one startup-critical setup task and verifies its postcondition.
pub async fn run_required(task: &dyn SetupTask) -> anyhow::Result<()> {
    if task.is_satisfied() {
        return Ok(());
    }

    let client = Client::connect()
        .await
        .with_context(|| format!("{} requires a compatible arcbox-helper", task.name()))?;
    task.apply(&client)
        .await
        .with_context(|| format!("failed to configure {}", task.name()))?;
    anyhow::ensure!(
        task.is_satisfied(),
        "{} was not satisfied after helper configuration",
        task.name()
    );
    tracing::info!(task = task.name(), "configured");
    Ok(())
}

/// Runs all setup tasks on a shared helper connection.
///
/// Connects once and runs tasks sequentially — this keeps the helper alive
/// for the duration (launchd socket activation starts it on first connect).
/// If the helper is unreachable **or older than
/// [`arcbox_constants::helper::MIN_HELPER_VERSION`]**, all tasks are skipped so
/// we never drive new RPCs (e.g. `hosts_alias_*`) into a legacy binary that
/// misdecodes tarpc ordinals. [`Client::connect`] enforces that invariant for
/// every helper consumer, including route reconciliation.
pub async fn run(tasks: &[&dyn SetupTask]) {
    let client = match Client::connect().await {
        Ok(c) => c,
        Err(ClientError::UnrecognizedVersion(version)) => {
            tracing::warn!(
                version = %version,
                "arcbox-helper returned an unrecognized version; run 'sudo abctl _install --no-daemon --no-shell' to replace it"
            );
            return;
        }
        Err(ClientError::IncompatibleVersion {
            installed,
            required,
        }) => {
            tracing::warn!(
                installed = %installed,
                required,
                "arcbox-helper is incompatible; run 'sudo abctl _install --no-daemon --no-shell' to replace it"
            );
            return;
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                "arcbox-helper unavailable, skipping self-setup"
            );
            return;
        }
    };

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
                "failed (run 'sudo abctl _install --no-daemon --no-shell' to fix)"
            ),
        }
    }
}
