//! Host route ownership for the System VM's container networks.

use std::sync::Arc;
use std::time::Duration;

use arcbox_api::SetupState;
use arcbox_core::bridge_discovery::BridgeTarget;
use arcbox_core::route_reconciler::{RouteError, RouteMode};
use arcbox_core::{Runtime, VmLifecycleState};

const POLL_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(2);
const EVENT_DEBOUNCE: Duration = Duration::from_millis(250);

#[derive(Default)]
struct ControllerState {
    generation: u64,
    bridge: Option<BridgeTarget>,
    mode: Option<RouteMode>,
}

impl ControllerState {
    fn observe_vm(&mut self, generation: u64, lifecycle: VmLifecycleState) -> bool {
        if !lifecycle.is_ready() || self.generation != generation {
            self.generation = generation;
            self.bridge = None;
            self.mode = None;
        }
        lifecycle.is_ready()
    }

    fn clear_bridge(&mut self) {
        self.bridge = None;
        self.mode = None;
    }

    fn accept_result(
        &mut self,
        expected_generation: u64,
        current_generation: u64,
        lifecycle: VmLifecycleState,
    ) -> bool {
        if expected_generation == current_generation && lifecycle.is_ready() {
            return true;
        }
        self.observe_vm(current_generation, lifecycle);
        false
    }
}

pub fn spawn(
    runtime: Arc<Runtime>,
    setup_state: Arc<SetupState>,
    shutdown: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(runtime, setup_state, shutdown))
}

async fn run(
    runtime: Arc<Runtime>,
    setup_state: Arc<SetupState>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let mut vm_state = runtime.subscribe_system_vm_state();
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut watcher = open_route_watcher();
    let mut state = ControllerState::default();
    let mut consecutive_failures = 0u32;

    loop {
        let route_event = tokio::select! {
            () = shutdown.cancelled() => break,
            _ = ticker.tick() => false,
            changed = vm_state.changed() => {
                if changed.is_err() {
                    break;
                }
                false
            }
            event = next_managed_route_event(watcher.as_ref()) => {
                match event {
                    Ok(()) => true,
                    Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                        tracing::debug!(
                            "route event queue overflowed; reconciling current state"
                        );
                        true
                    }
                    Err(error) => {
                        tracing::warn!(%error, "route event watcher failed; polling remains active");
                        watcher = None;
                        false
                    }
                }
            }
        };

        if route_event {
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(EVENT_DEBOUNCE) => {}
            }
            if let Some(watcher) = watcher.as_ref() {
                drain_route_events(watcher);
            }
        } else if watcher.is_none() {
            watcher = open_route_watcher();
        }

        let lifecycle = *vm_state.borrow_and_update();
        let generation = runtime.system_vm_restart_generation();
        if !state.observe_vm(generation, lifecycle) {
            setup_state.set_route_installed(false);
            consecutive_failures = 0;
            ticker.reset_after(POLL_INTERVAL);
            continue;
        }

        if state
            .bridge
            .as_ref()
            .is_some_and(|bridge| !bridge.is_current())
        {
            state.clear_bridge();
        }

        if state.bridge.is_none() {
            let runtime_for_bridge = Arc::clone(&runtime);
            let bridge = match tokio::task::spawn_blocking(move || {
                resolve_container_bridge(&runtime_for_bridge)
            })
            .await
            {
                Ok(bridge) => bridge,
                Err(error) => {
                    tracing::warn!(%error, "container bridge discovery task failed");
                    None
                }
            };
            let current_lifecycle = *vm_state.borrow();
            let current_generation = runtime.system_vm_restart_generation();
            if !state.accept_result(generation, current_generation, current_lifecycle) {
                setup_state.set_route_installed(false);
                consecutive_failures = 0;
                ticker.reset_after(RETRY_INTERVAL);
                continue;
            }
            state.bridge = bridge;
        }

        let Some(bridge) = state.bridge.clone() else {
            setup_state.set_route_installed(false);
            consecutive_failures = 0;
            ticker.reset_after(RETRY_INTERVAL);
            continue;
        };

        let result = match state.mode {
            Some(mode) => {
                arcbox_core::route_reconciler::reconcile_route_for_target(&bridge, mode).await
            }
            None => arcbox_core::route_reconciler::initialize_route_for_target(&bridge).await,
        };

        let current_lifecycle = *vm_state.borrow();
        let current_generation = runtime.system_vm_restart_generation();
        if !state.accept_result(generation, current_generation, current_lifecycle) {
            setup_state.set_route_installed(false);
            consecutive_failures = 0;
            ticker.reset_after(RETRY_INTERVAL);
            continue;
        }

        match result {
            Ok(mode) => {
                state.mode = Some(mode);
                setup_state.set_route_installed(true);
                consecutive_failures = 0;
                ticker.reset_after(POLL_INTERVAL);
            }
            Err(error) => {
                setup_state.set_route_installed(false);
                consecutive_failures = consecutive_failures.saturating_add(1);
                if matches!(&error, RouteError::BridgeNotReady) {
                    state.clear_bridge();
                }
                let retry_after = if matches!(&error, RouteError::RouteConflict { .. }) {
                    POLL_INTERVAL
                } else {
                    RETRY_INTERVAL
                };
                ticker.reset_after(retry_after);
                if should_log_failure(consecutive_failures) {
                    tracing::warn!(
                        %error,
                        bridge = %bridge.name,
                        consecutive_failures,
                        "container route reconciliation failed"
                    );
                }
            }
        }
    }
}

fn open_route_watcher() -> Option<tokio::io::unix::AsyncFd<arcbox_route::RouteWatcher>> {
    match arcbox_route::RouteWatcher::open().and_then(tokio::io::unix::AsyncFd::new) {
        Ok(watcher) => Some(watcher),
        Err(error) => {
            tracing::warn!(%error, "route event watcher unavailable; using polling");
            None
        }
    }
}

async fn next_managed_route_event(
    watcher: Option<&tokio::io::unix::AsyncFd<arcbox_route::RouteWatcher>>,
) -> std::io::Result<()> {
    let Some(watcher) = watcher else {
        return std::future::pending().await;
    };

    loop {
        let mut ready = watcher.readable().await?;
        match ready.try_io(|inner| inner.get_ref().read_event()) {
            Ok(Ok(Some(event))) if event.network.is_some_and(is_managed_route) => return Ok(()),
            Ok(Ok(_)) => {}
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                tracing::debug!(%error, "ignored malformed route event");
            }
            Ok(Err(error)) => return Err(error),
            Err(_would_block) => {}
        }
    }
}

fn drain_route_events(watcher: &tokio::io::unix::AsyncFd<arcbox_route::RouteWatcher>) {
    for _ in 0..256 {
        match watcher.get_ref().read_event() {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn is_managed_route(network: arcbox_route::Ipv4Net) -> bool {
    let network = network.to_string();
    network == arcbox_core::route_reconciler::CONTAINER_SUBNET
        || arcbox_core::route_reconciler::CONTAINER_SPLIT_SUBNETS
            .iter()
            .any(|candidate| network == *candidate)
}

#[cfg(feature = "vmnet")]
fn resolve_container_bridge(runtime: &Runtime) -> Option<BridgeTarget> {
    runtime
        .machine_manager()
        .vmnet_bridge_target(arcbox_core::DEFAULT_MACHINE_NAME)
}

#[cfg(not(feature = "vmnet"))]
fn resolve_container_bridge(runtime: &Runtime) -> Option<BridgeTarget> {
    let mac = runtime
        .machine_manager()
        .bridge_mac(arcbox_core::DEFAULT_MACHINE_NAME)?;
    arcbox_core::bridge_discovery::resolve_bridge_by_mac(&mac)
}

fn should_log_failure(consecutive_failures: u32) -> bool {
    consecutive_failures == 1 || consecutive_failures.is_multiple_of(30)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge() -> BridgeTarget {
        BridgeTarget {
            name: "bridge100".to_string(),
            ifindex: 42,
        }
    }

    #[test]
    fn bridge_identity_is_cached_for_one_vm_generation() {
        let mut state = ControllerState::default();

        assert!(state.observe_vm(7, VmLifecycleState::Running));
        state.bridge = Some(bridge());
        state.mode = Some(RouteMode::SplitFallback);

        assert!(state.observe_vm(7, VmLifecycleState::Idle));
        assert_eq!(state.bridge, Some(bridge()));
        assert_eq!(state.mode, Some(RouteMode::SplitFallback));

        assert!(state.observe_vm(8, VmLifecycleState::Running));
        assert!(state.bridge.is_none());
        assert!(state.mode.is_none());

        state.bridge = Some(bridge());
        assert!(!state.observe_vm(8, VmLifecycleState::Stopped));
        assert!(state.bridge.is_none());
    }

    #[test]
    fn result_from_replaced_vm_is_discarded() {
        let mut state = ControllerState {
            generation: 7,
            bridge: Some(bridge()),
            mode: Some(RouteMode::Preferred),
        };

        assert!(!state.accept_result(7, 8, VmLifecycleState::Starting));
        assert_eq!(state.generation, 8);
        assert!(state.bridge.is_none());
        assert!(state.mode.is_none());
    }
}
