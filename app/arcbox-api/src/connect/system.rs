//! System service — daemon readiness, version, and diagnostics.
//!
//! Provides setup status queries so the desktop app (or any client) can
//! observe daemon readiness without managing its lifecycle.
//!
//! `GetVirtioDebug` is deliberately served from `early_runtime` rather than
//! the ready handle: a boot that never reaches READY is its main use case.

use std::sync::Arc;

use arcbox_connect::v1 as pb;
use arcbox_connect::v1::{SetupStatus, SystemVmBackend, setup_status};
use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use tokio::sync::{broadcast, watch};

use super::SharedRuntime;

use super::ConnectRuntimeExt as _;

/// Buffered updates per streaming client. Startup publishes on the order of a
/// dozen; the margin covers a client that stalls briefly mid-boot without
/// dropping a phase.
const UPDATE_BUFFER: usize = 64;

/// Shared state tracking daemon startup progress.
///
/// Updated by the daemon as it progresses through startup phases.
/// Observed by `SystemServiceImpl` to serve gRPC queries.
#[derive(Debug, Clone)]
pub struct SetupState {
    /// Latest snapshot, for `GetSetupStatus` and for seeding a new stream.
    tx: Arc<watch::Sender<SetupStatus>>,
    /// Every update, in order.
    ///
    /// A `watch` keeps only the newest value, so two updates in quick
    /// succession collapse into one for a subscriber that has not polled in
    /// between — and a phase a client never receives is indistinguishable
    /// from one the daemon never published. `NETWORK_READY` and `READY` are
    /// ~300 µs apart with no await point between them, so on that pair the
    /// collapse is a live race rather than a theoretical one.
    updates: broadcast::Sender<SetupStatus>,
}

impl SetupState {
    /// Creates a new setup state starting in the INITIALIZING phase.
    pub fn new() -> Self {
        let initial = SetupStatus {
            phase: setup_status::Phase::Initializing.into(),
            message: "Daemon starting...".to_string(),
            ..Default::default()
        };
        let (tx, _) = watch::channel(initial);
        Self {
            tx: Arc::new(tx),
            updates: broadcast::channel(UPDATE_BUFFER).0,
        }
    }

    /// Applies an update to the snapshot and publishes it to every stream.
    ///
    /// The broadcast happens inside `send_modify`, under the write lock, so a
    /// concurrent publisher cannot interleave the two halves and deliver
    /// updates in an order the snapshot never passed through — recovery and
    /// the route loop write flags while startup writes phases.
    fn publish(&self, update: impl FnOnce(&mut SetupStatus)) {
        self.tx.send_modify(|status| {
            update(status);
            // Fails only when nobody is streaming, which is the common case.
            let _ = self.updates.send(status.clone());
        });
    }

    /// Updates the current setup phase.
    pub fn set_phase(&self, phase: setup_status::Phase, message: &str) {
        self.publish(|s| {
            s.phase = phase.into();
            message.clone_into(&mut s.message);
        });
    }

    /// Marks startup as fatally failed. The daemon exits shortly after;
    /// the error rides the final update so streaming clients learn
    /// the cause instead of seeing a bare disconnect.
    pub fn set_failed(&self, error: &str) {
        self.publish(|s| {
            s.phase = setup_status::Phase::Failed.into();
            "Daemon startup failed".clone_into(&mut s.message);
            error.clone_into(&mut s.error);
        });
    }

    /// Updates a specific infrastructure flag.
    pub fn set_dns_installed(&self, installed: bool) {
        self.publish(|s| s.dns_resolver_installed = installed);
    }

    pub fn set_docker_socket_linked(&self, linked: bool) {
        self.publish(|s| s.docker_socket_linked = linked);
    }

    pub fn set_route_installed(&self, installed: bool) {
        self.publish(|s| s.route_installed = installed);
    }

    pub fn set_vm_running(&self, running: bool) {
        self.publish(|s| s.vm_running = running);
    }

    pub fn set_docker_tools_installed(&self, installed: bool) {
        self.publish(|s| s.docker_tools_installed = installed);
    }

    /// Returns the current snapshot plus a receiver for every update after it.
    ///
    /// Both are taken while holding the snapshot's read lock, which excludes
    /// [`Self::publish`]'s write lock. Subscribing after reading the snapshot
    /// would drop an update landing between the two; reading the snapshot
    /// after subscribing could replay one already folded into it, walking a
    /// client's phase backwards.
    fn subscribe(&self) -> (SetupStatus, broadcast::Receiver<SetupStatus>) {
        let snapshot = self.tx.borrow();
        let updates = self.updates.subscribe();
        (snapshot.clone(), updates)
    }

    /// Returns the current status snapshot.
    pub fn current(&self) -> SetupStatus {
        self.tx.borrow().clone()
    }
}

impl Default for SetupState {
    fn default() -> Self {
        Self::new()
    }
}

/// SystemService gRPC implementation.
pub struct SystemServiceImpl {
    setup_state: Arc<SetupState>,
    runtime: SharedRuntime,
    /// Diagnostics handle, filled as soon as the runtime is constructed
    /// (before the VM boots) so `GetVirtioDebug` can observe a stuck
    /// boot while `runtime` is still empty.
    early_runtime: SharedRuntime,
}

impl SystemServiceImpl {
    /// Creates a new system service.
    pub fn new(
        setup_state: Arc<SetupState>,
        runtime: SharedRuntime,
        early_runtime: SharedRuntime,
    ) -> Self {
        Self {
            setup_state,
            runtime,
            early_runtime,
        }
    }
}

/// Maps the wire enum to the core backend, or `None` for the unspecified value.
fn backend_from_proto(backend: SystemVmBackend) -> Option<arcbox_core::VmBackend> {
    match backend {
        SystemVmBackend::Hv => Some(arcbox_core::VmBackend::Hv),
        SystemVmBackend::Vz => Some(arcbox_core::VmBackend::Vz),
        SystemVmBackend::Unspecified => None,
    }
}

/// Maps the core backend to the wire enum.
fn backend_to_proto(backend: arcbox_core::VmBackend) -> SystemVmBackend {
    match backend {
        arcbox_core::VmBackend::Hv => SystemVmBackend::Hv,
        arcbox_core::VmBackend::Vz => SystemVmBackend::Vz,
    }
}

/// Maps a core virtio device snapshot to the wire message. (A `From`
/// impl is impossible here — both types are foreign to this crate.)
fn device_debug_to_proto(device: arcbox_core::DeviceDebug) -> pb::VirtioDeviceDebug {
    pb::VirtioDeviceDebug {
        id: device.id,
        device_type: device.device_type,
        name: device.name,
        status: u32::from(device.status),
        interrupt_status: device.interrupt_status,
        event_idx: device.event_idx,
        interrupts: device.interrupts,
        queues: device
            .queues
            .into_iter()
            .map(|queue| pb::VirtioQueueDebug {
                index: u32::from(queue.index),
                size: u32::from(queue.size),
                ready: queue.ready,
                kicks: queue.kicks,
                avail_idx: queue.avail_idx.map(u32::from),
                used_idx: queue.used_idx.map(u32::from),
                avail_flags: queue.avail_flags.map(u32::from),
                used_flags: queue.used_flags.map(u32::from),
                used_event: queue.used_event.map(u32::from),
                avail_event: queue.avail_event.map(u32::from),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and these impls are registered on a \
              Router rather than named by callers"
)]
impl pb::SystemService for SystemServiceImpl {
    async fn get_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetInfoRequest>,
    ) -> ServiceResult<pb::GetInfoResponse> {
        // TODO: Populate from runtime.
        Err(ConnectError::unimplemented("get_info not yet implemented"))
    }

    async fn get_version(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetVersionRequest>,
    ) -> ServiceResult<pb::GetVersionResponse> {
        let resp = pb::GetVersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: "1.0".to_string(),
            min_api_version: "1.0".to_string(),
            ..Default::default()
        };
        Response::ok(resp)
    }

    async fn ping(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::SystemPingRequest>,
    ) -> ServiceResult<pb::SystemPingResponse> {
        let resp = pb::SystemPingResponse {
            api_version: "1.0".to_string(),
            build_version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        };
        Response::ok(resp)
    }

    async fn events(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::EventsRequest>,
    ) -> ServiceResult<ServiceStream<pb::Event>> {
        // TODO: Implement event streaming.
        Err(ConnectError::unimplemented("events not yet implemented"))
    }

    async fn prune(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::PruneRequest>,
    ) -> ServiceResult<pb::PruneResponse> {
        // TODO: Implement resource pruning.
        Err(ConnectError::unimplemented("prune not yet implemented"))
    }

    async fn get_setup_status(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::Empty>,
    ) -> ServiceResult<pb::SetupStatus> {
        Response::ok(self.setup_state.current())
    }

    async fn watch_setup_status(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::Empty>,
    ) -> ServiceResult<ServiceStream<pb::SetupStatus>> {
        let (initial, mut updates) = self.setup_state.subscribe();
        let stream = async_stream::stream! {
            // Send current state immediately, then every update after it.
            yield Ok(initial);
            loop {
                match updates.recv().await {
                    Ok(status) => yield Ok(status),
                    // Too slow to keep up: the next recv resumes from the
                    // oldest retained update, so the client stays live and
                    // converges — it has only missed intermediate phases.
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "setup status client lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };
        Response::ok(Box::pin(stream))
    }

    async fn get_system_vm_backend(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::Empty>,
    ) -> ServiceResult<pb::SystemVmBackendInfo> {
        let runtime = self.runtime.ready()?;
        let info = pb::SystemVmBackendInfo {
            backend: backend_to_proto(runtime.system_vm_backend()).into(),
            ..Default::default()
        };
        Response::ok(info)
    }

    async fn get_virtio_debug(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::Empty>,
    ) -> ServiceResult<pb::VirtioDebugInfo> {
        // The early handle exists as soon as the runtime is constructed —
        // a boot that never reaches READY is this RPC's main use case.
        let runtime = self.early_runtime.ready()?;
        let snapshot = runtime
            .system_vm_debug_snapshot()
            .map_err(|e| ConnectError::failed_precondition(e.to_string()))?;
        let info = pb::VirtioDebugInfo {
            devices: snapshot
                .devices
                .into_iter()
                .map(device_debug_to_proto)
                .collect(),
            vcpus: snapshot
                .vcpus
                .into_iter()
                .map(|v| pb::VcpuDebug {
                    vcpu: v.vcpu,
                    mmio_reads: v.mmio_reads,
                    mmio_writes: v.mmio_writes,
                    wfi: v.wfi,
                    hvc: v.hvc,
                    smc: v.smc,
                    vtimer: v.vtimer,
                    kicks_received: v.kicks_received,
                    sysreg: v.sysreg,
                    other: v.other,
                    ..Default::default()
                })
                .collect(),
            kick_broadcasts: snapshot.kick_broadcasts,
            unpark_broadcasts: snapshot.unpark_broadcasts,
            ..Default::default()
        };
        Response::ok(info)
    }

    async fn resolve_container_fs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::ResolveContainerFsRequest>,
    ) -> ServiceResult<pb::ResolveContainerFsResponse> {
        let runtime = self.runtime.ready()?;
        let req = request.to_owned_message();
        if req.container_id.is_empty() {
            return Err(ConnectError::invalid_argument(
                "container_id must not be empty",
            ));
        }
        let paths = runtime
            .container_fs_paths(&req.container_id)
            .await
            .map_err(|e| ConnectError::failed_precondition(e.to_string()))?;
        let resp = pb::ResolveContainerFsResponse {
            upper_dir: paths.upper_dir,
            lower_dirs: paths.lower_dirs,
            ..Default::default()
        };
        Response::ok(resp)
    }

    async fn resolve_image_fs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::ResolveImageFsRequest>,
    ) -> ServiceResult<pb::ResolveImageFsResponse> {
        let runtime = self.runtime.ready()?;
        let req = request.to_owned_message();
        if req.top_chain_id.is_empty() {
            return Err(ConnectError::invalid_argument(
                "top_chain_id must not be empty",
            ));
        }
        let paths = runtime
            .image_fs_paths(&req.top_chain_id)
            .await
            .map_err(|e| ConnectError::failed_precondition(e.to_string()))?;
        let resp = pb::ResolveImageFsResponse {
            lower_dirs: paths.lower_dirs,
            ..Default::default()
        };
        Response::ok(resp)
    }

    async fn set_system_vm_backend(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::SetSystemVmBackendRequest>,
    ) -> ServiceResult<pb::SystemVmBackendInfo> {
        let req = request.to_owned_message();
        let backend = backend_from_proto(req.backend.as_known().unwrap_or_default())
            .ok_or_else(|| ConnectError::invalid_argument("backend must be HV or VZ"))?;
        let runtime = self.runtime.ready()?;
        runtime
            .switch_system_vm_backend(backend)
            .await
            .map_err(|e| ConnectError::internal(e.to_string()))?;
        let info = pb::SystemVmBackendInfo {
            backend: backend_to_proto(runtime.system_vm_backend()).into(),
            ..Default::default()
        };
        Response::ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every update currently buffered for `updates`, as phases.
    fn drain(updates: &mut broadcast::Receiver<SetupStatus>) -> Vec<setup_status::Phase> {
        std::iter::from_fn(|| updates.try_recv().ok())
            .map(|status| status.phase.as_known().unwrap_or_default())
            .collect()
    }

    /// The regression this exists for: `NETWORK_READY` and `READY` are
    /// published ~300 µs apart with no await point between them, so a
    /// snapshot-only channel hands a client just the last one — a phase that
    /// was published but never observed, which is exactly what CORE-67 set
    /// out to make impossible.
    #[test]
    fn back_to_back_phases_are_all_delivered() {
        let state = SetupState::new();
        let (_snapshot, mut updates) = state.subscribe();

        state.set_phase(setup_status::Phase::NetworkReady, "network");
        state.set_phase(setup_status::Phase::Ready, "ready");

        assert_eq!(
            drain(&mut updates),
            [
                setup_status::Phase::NetworkReady,
                setup_status::Phase::Ready
            ]
        );
    }

    /// A subscriber's snapshot already folds in every earlier update, so
    /// replaying one would walk the client's phase backwards.
    #[test]
    fn the_snapshot_is_not_replayed_as_an_update() {
        let state = SetupState::new();
        state.set_phase(setup_status::Phase::AssetsReady, "assets");

        let (snapshot, mut updates) = state.subscribe();

        assert_eq!(snapshot.phase, setup_status::Phase::AssetsReady);
        assert!(drain(&mut updates).is_empty());
    }

    /// Flags travel the same path as phases: a client watching for the route
    /// must not have to wait for an unrelated phase change to learn of it.
    #[test]
    fn flag_updates_reach_subscribers() {
        let state = SetupState::new();
        let (_snapshot, mut updates) = state.subscribe();

        state.set_route_installed(true);

        let update = updates.try_recv().expect("flag update delivered");
        assert!(update.route_installed);
    }
}
