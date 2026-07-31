//! Termination-signal handling.
//!
//! The signal does not cancel the shutdown token directly: it goes through
//! [`Handover::terminate`], which records the veto *before* it cancels. Every
//! long-running subcommand shuts down on that one token, so without the veto a
//! SIGTERM landing on an agent waiting out its last job would be
//! indistinguishable from the restart it was waiting for.

use std::sync::Arc;

use tracing::{info, warn};

use crate::handover::Handover;

/// Terminate `handover` on the first termination signal (see [`signal`]),
/// logging `message` when it fires.
pub fn arm(handover: Arc<Handover>, message: &'static str) {
    tokio::spawn(async move {
        signal().await;
        info!("{message}");
        handover.terminate();
    });
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
