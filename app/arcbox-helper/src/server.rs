//! tarpc server: accept loop, launchd integration, idle shutdown.

mod handler;
mod launchd;
mod mutations;
mod peer_auth;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use futures::prelude::*;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_serde::formats::Bincode;
use tokio::task::JoinSet;

use arcbox_helper::HelperService as _;
use handler::HelperServer;

/// Exit after this many seconds with zero active connections.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Check interval for the idle watchdog.
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Tracks active connections for idle-exit decisions.
struct ConnectionTracker {
    active: AtomicU32,
}

impl ConnectionTracker {
    fn new() -> Self {
        Self {
            active: AtomicU32::new(0),
        }
    }

    fn connect(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    fn disconnect(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    fn is_idle(&self) -> bool {
        self.active.load(Ordering::Relaxed) == 0
    }
}

/// Watches for idle timeout and signals shutdown so the log guard can
/// flush before the process exits. launchd will re-launch on next connect.
async fn idle_watchdog(tracker: Arc<ConnectionTracker>, shutdown: CancellationToken) {
    let mut idle_since: Option<tokio::time::Instant> = None;

    loop {
        tokio::time::sleep(IDLE_CHECK_INTERVAL).await;

        if tracker.is_idle() {
            let start = *idle_since.get_or_insert_with(tokio::time::Instant::now);
            if start.elapsed() >= IDLE_TIMEOUT {
                tracing::info!("idle timeout, shutting down");
                shutdown.cancel();
                return;
            }
        } else {
            idle_since = None;
        }
    }
}

/// Accept loop: dispatches incoming connections to the tarpc handler and
/// tracks connection count for idle-exit.
async fn accept_loop(
    listener: tokio::net::UnixListener,
    tracker: Arc<ConnectionTracker>,
    shutdown: CancellationToken,
) {
    let codec = tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec::builder();

    loop {
        let conn = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((conn, _addr)) => conn,
                    Err(e) => {
                        tracing::warn!("accept error: {e}");
                        continue;
                    }
                }
            }
            () = shutdown.cancelled() => {
                return;
            }
        };

        if !peer_auth::verify(&conn) {
            continue;
        }

        tracker.connect();
        let tracker_clone = Arc::clone(&tracker);

        let transport = tarpc::serde_transport::new(codec.new_framed(conn), Bincode::default());

        tokio::spawn(async move {
            let mut in_flight = JoinSet::new();

            BaseChannel::with_defaults(transport)
                .execute(HelperServer.serve())
                .for_each(|resp| {
                    in_flight.spawn(resp);
                    futures::future::ready(())
                })
                .await;

            // Wait for all in-flight responses to complete before marking
            // the connection as idle, so idle_watchdog never kills the
            // process while work is still running.
            while in_flight.join_next().await.is_some() {}

            tracker_clone.disconnect();
        });
    }
}

/// Starts the tarpc server.
///
/// Uses launchd socket activation if available, otherwise falls back to
/// binding its own socket (for development).
pub async fn run(idle_exit: bool) -> Result<(), Box<dyn std::error::Error>> {
    let listener = if let Some(l) = launchd::listener() {
        tracing::info!("using launchd socket activation");
        l
    } else {
        // Fallback: bind our own socket (development / manual start).
        //
        // Mode 0o666 matches the production launchd plist (`SockPathMode`
        // 438). Auth is **not** the filesystem mode — release builds always
        // run `peer_auth::verify` (code signature + Team ID allow-list) before
        // any RPC is dispatched. Manual mode is for dev machines; do not
        // disable peer auth in release to "make local testing easier".
        let path = arcbox_helper::socket_path();
        let _ = std::fs::remove_file(&path);

        let l = tokio::net::UnixListener::bind(&path)?;

        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
        }

        tracing::info!("listening on {path} (manual mode)");
        l
    };

    let tracker = Arc::new(ConnectionTracker::new());
    let shutdown = CancellationToken::new();
    if idle_exit {
        tracing::info!("idle-exit enabled ({}s timeout)", IDLE_TIMEOUT.as_secs());
        tokio::spawn(idle_watchdog(Arc::clone(&tracker), shutdown.clone()));
    }
    accept_loop(listener, tracker, shutdown).await;

    Ok(())
}
