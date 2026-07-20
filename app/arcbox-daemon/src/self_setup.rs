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
/// If the helper is unreachable **or older than
/// [`arcbox_constants::helper::MIN_HELPER_VERSION`]**, all tasks are skipped so
/// we never drive new RPCs (e.g. `hosts_alias_*`) into a legacy binary that
/// misdecodes tarpc ordinals.
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

    if !helper_version_ok(&client).await {
        return;
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
                "failed (run 'sudo abctl _install --no-daemon --no-shell' to fix)"
            ),
        }
    }
}

/// Returns `true` when the connected helper meets
/// [`arcbox_constants::helper::MIN_HELPER_VERSION`].
///
/// On failure logs a warning and returns `false` so callers skip privileged
/// tasks rather than hammering an incompatible helper.
async fn helper_version_ok(client: &Client) -> bool {
    let min = arcbox_constants::helper::MIN_HELPER_VERSION;
    let Ok(version) = client.version().await else {
        tracing::warn!("failed to check arcbox-helper version; skipping self-setup");
        return false;
    };

    let Some(installed) = arcbox_constants::helper::parse_helper_version(&version) else {
        tracing::warn!(
            helper_version = %version,
            "unrecognized arcbox-helper version; run 'sudo abctl _install --no-daemon --no-shell'"
        );
        return false;
    };

    let Some(minimum) = arcbox_constants::helper::parse_semver_triple(min) else {
        tracing::warn!(
            min_helper_version = min,
            "invalid MIN_HELPER_VERSION constant"
        );
        return false;
    };

    if arcbox_constants::helper::helper_version_satisfies(installed, minimum) {
        tracing::debug!(
            helper_version = %version,
            min_helper_version = min,
            "arcbox-helper version ok"
        );
        true
    } else {
        tracing::warn!(
            helper_version = %version,
            min_helper_version = min,
            "arcbox-helper too old; skipping self-setup — run 'sudo abctl _install --no-daemon --no-shell'"
        );
        false
    }
}
