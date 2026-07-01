//! Periodic reconciliation of host-side container networking against guest
//! dockerd's live container set.
//!
//! Host port forwarding and DNS are set up by `start_container` and torn down
//! by the `stop`/`kill`/`remove` handlers. But a container can stop without any
//! of those API calls — a natural exit, `--rm` auto-remove, `docker prune`, a
//! non-fatal `kill` signal that still ends it, an OOM kill, or a `docker stop`
//! issued directly against the guest. Each of those leaks the container's host
//! port-forward rules and DNS entries. This task periodically lists the guest's
//! running containers and tears down host state for any registered container no
//! longer running — a backstop for the immediate, handler-driven teardown.

use crate::error::Result;
use crate::guest_query::list_running_container_ids;
use crate::proxy::ProxyState;
use arcbox_core::Runtime;
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Spawns the background reconciler, cancelled via `shutdown`.
///
/// Shares the router's [`ProxyState`] so queries go through the same pooled
/// client, and observes the System VM restart generation before each cycle so
/// a query right after a backend switch dials the fresh VM instead of failing
/// once on a stale pooled connection.
pub fn spawn(runtime: Arc<Runtime>, proxy: Arc<ProxyState>, shutdown: CancellationToken) {
    drop(tokio::spawn(async move {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(RECONCILE_INTERVAL) => {
                    proxy.reset_if_restarted(runtime.system_vm_restart_generation());
                    if let Err(e) =
                        reconcile(&runtime, || list_running_container_ids(proxy.client())).await
                    {
                        // Fail-safe: a guest query error skips teardown this
                        // cycle rather than risk tearing down live containers.
                        tracing::debug!(error = %e, "host networking reconcile skipped");
                    }
                }
            }
        }
    }));
}

/// Tears down host networking for every registered container not in the guest's
/// running set.
///
/// Generic over the "list running" step so the decision logic is unit-testable
/// without a guest. When the query fails the error propagates and NO teardown
/// happens, so a transient guest hiccup can't strip live containers.
async fn reconcile<F, Fut>(runtime: &Runtime, list_running: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<HashSet<String>>>,
{
    let registered = runtime.registered_container_ids().await;
    if registered.is_empty() {
        return Ok(()); // Nothing registered; don't even query the guest.
    }
    let running = list_running().await?;
    for id in registered.difference(&running) {
        tracing::info!(
            container_id = %id,
            "reconciler tearing down host networking for a container no longer running"
        );
        runtime.stop_port_forwarding_by_id(id).await;
        runtime.deregister_dns_by_id(id).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DockerError;
    use arcbox_core::{Config, Runtime, VmLifecycleConfig};
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    fn test_runtime() -> (Arc<Runtime>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let config = Config {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let vlc = VmLifecycleConfig {
            skip_vm_check: true,
            ..Default::default()
        };
        let runtime = Arc::new(Runtime::with_vm_lifecycle_config(config, vlc).expect("runtime"));
        (runtime, tmp)
    }

    #[tokio::test]
    async fn reconcile_tears_down_only_orphans() {
        let (runtime, _tmp) = test_runtime();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        runtime
            .register_dns("alive", &["alive.local".into()], ip)
            .await;
        runtime
            .register_dns("dead", &["dead.local".into()], ip)
            .await;
        assert_eq!(runtime.registered_container_ids().await.len(), 2);

        // Only "alive" is running in the guest.
        reconcile(&runtime, || async {
            Ok(HashSet::from(["alive".to_string()]))
        })
        .await
        .unwrap();

        let remaining = runtime.registered_container_ids().await;
        assert!(remaining.contains("alive"));
        assert!(!remaining.contains("dead"));
    }

    #[tokio::test]
    async fn reconcile_is_fail_safe_on_query_error() {
        let (runtime, _tmp) = test_runtime();
        runtime
            .register_dns("c", &["c.local".into()], IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await;

        let result = reconcile(&runtime, || async {
            Err(DockerError::Server("guest unreachable".into()))
        })
        .await;

        assert!(result.is_err());
        // Nothing torn down on a query failure.
        assert!(runtime.registered_container_ids().await.contains("c"));
    }

    #[tokio::test]
    async fn reconcile_skips_guest_query_when_nothing_registered() {
        let (runtime, _tmp) = test_runtime();
        let called = std::cell::Cell::new(false);
        reconcile(&runtime, || {
            called.set(true);
            async { Ok(HashSet::new()) }
        })
        .await
        .unwrap();
        assert!(
            !called.get(),
            "guest must not be queried with no host state"
        );
    }
}
