//! Termination-signal handling: the `CancellationToken` every long-running
//! subcommand shuts down on.
//!
//! `serve` shares that token with its own restart path, so the signal handler
//! takes a hook that runs *before* the cancellation — that is where a
//! termination signal vetoes a pending restart, so a shutdown can never be
//! mistaken for one (see [`crate::control::RestartIntent::terminate`]).

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Build a `CancellationToken` cancelled on the first termination signal (see
/// [`signal`]), logging `message` when it fires.
pub fn spawn(message: &'static str) -> CancellationToken {
    spawn_with(message, || {})
}

/// As [`spawn`], running `on_signal` before the token is cancelled, so a task
/// waiting on the token cannot observe the cancellation before the hook's
/// effects.
pub fn spawn_with(
    message: &'static str,
    on_signal: impl FnOnce() + Send + 'static,
) -> CancellationToken {
    let shutdown = CancellationToken::new();
    let signal_token = shutdown.clone();
    tokio::spawn(async move {
        signal().await;
        info!("{message}");
        on_signal();
        signal_token.cancel();
    });
    shutdown
}

/// Resolve when the process receives a termination signal: Ctrl-C, or
/// SIGTERM (e.g. a service-manager stop) — every supported target (macOS,
/// Linux) is Unix, so SIGTERM handling is unconditional. If a listener
/// cannot be installed, that signal simply never fires rather than aborting
/// startup.
async fn signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "failed to listen for Ctrl-C; ignoring");
            std::future::pending::<()>().await;
        }
    };

    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                warn!(error = %e, "failed to listen for SIGTERM; ignoring");
                std::future::pending::<()>().await;
            }
        }
    };

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
