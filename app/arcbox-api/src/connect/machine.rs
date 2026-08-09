//! Machine service gRPC implementation.

use arcbox_connect::v1 as pb;
use arcbox_connect::v1::machine_exec_input;
use arcbox_core::ExecSessionInput;
use arcbox_core::machine_image;
use connectrpc::{
    ConnectError, InboundStream, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};
use tokio_stream::StreamExt as _;

use crate::error::ApiError;

use super::SharedRuntime;

use super::ConnectRuntimeExt as _;

/// The NAT gateway every machine's primary interface routes through; it also
/// serves DNS (same literal the guest agent's DHCP path documents).
const NAT_GATEWAY: &str = "10.0.2.1";

/// Converts a chrono timestamp to the wire `Timestamp`.
fn timestamp(t: chrono::DateTime<chrono::Utc>) -> pb::Timestamp {
    pb::Timestamp {
        seconds: t.timestamp(),
        nanos: i32::try_from(t.timestamp_subsec_nanos()).unwrap_or(0),
        ..Default::default()
    }
}

/// Machine service implementation.
pub struct MachineServiceImpl {
    runtime: SharedRuntime,
}

impl MachineServiceImpl {
    /// Creates a new machine service with a deferred runtime.
    #[must_use]
    pub fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and these impls are registered on a \
              Router rather than named by callers"
)]
impl pb::MachineService for MachineServiceImpl {
    async fn create(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::CreateMachineRequest>,
    ) -> ServiceResult<pb::CreateMachineResponse> {
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;

        // Convert bytes to MB for internal config.
        let memory_mb = req.memory / (1024 * 1024);
        let disk_gb = req.disk_size / (1024 * 1024 * 1024);

        // Distro machines boot a published rootfs image: resolve and pull it
        // (a cached image is a no-op) before registering the machine.
        let rootfs = if req.distro.is_empty() {
            None
        } else {
            let arch = if req.arch.is_empty() {
                machine_image::host_image_arch().to_string()
            } else {
                machine_image::image_arch(&req.arch).to_string()
            };
            let selector = machine_image::ImageSelector::Distro {
                distro: req.distro.clone(),
                release: (!req.version.is_empty()).then(|| req.version.clone()),
                arch,
            };
            let image = runtime
                .machine_image_manager()
                .pull(&selector, |done, total| {
                    tracing::debug!(machine = %req.name, done, total, "machine image pull");
                })
                .await
                .map_err(|e| match &e {
                    arcbox_core::error::CoreError::Common(c) if c.is_not_found() => {
                        ConnectError::not_found(e.to_string())
                    }
                    _ => ConnectError::internal(e.to_string()),
                })?;
            tracing::info!(
                machine = %req.name,
                image = %format!("{}@{}", image.manifest.name, image.manifest.version),
                "machine image ready"
            );

            // Resolve the boot shim (kernel + EROFS with
            // /sbin/arcbox-machine-init) from the same boot-assets cache the
            // daemon populates for the System VM; a warm cache is a no-op.
            let shim = async {
                let provider = arcbox_core::boot_assets::BootAssetProvider::new(
                    runtime.config().data_dir.join("boot"),
                )?;
                let assets = provider.get_assets().await?;
                Ok::<_, arcbox_core::error::CoreError>(arcbox_core::machine::BootShim {
                    kernel: assets.kernel,
                    rootfs: assets.rootfs_image,
                })
            }
            .await
            .map_err(|e| ConnectError::internal(format!("resolve boot shim: {e}")))?;

            Some(arcbox_core::machine::MachineRootfs {
                path: image.rootfs_path(),
                format: image.manifest.rootfs.format,
                shim: Some(shim),
            })
        };

        let config = arcbox_core::machine::MachineConfig {
            name: req.name.clone(),
            // 0 on the wire means "use the daemon-configured default".
            cpus: if req.cpus == 0 {
                runtime.config().vm.effective_cpus()
            } else {
                req.cpus
            },
            memory_mb,
            disk_gb,
            kernel: if req.kernel.is_empty() {
                None
            } else {
                Some(req.kernel)
            },
            cmdline: if req.cmdline.is_empty() {
                None
            } else {
                Some(req.cmdline)
            },
            distro: if req.distro.is_empty() {
                None
            } else {
                Some(req.distro)
            },
            distro_version: if req.version.is_empty() {
                None
            } else {
                Some(req.version)
            },
            block_devices: Vec::new(),
            rootfs,
            mounts: req
                .mounts
                .iter()
                .map(|m| arcbox_core::machine::MachineMount {
                    host_path: m.host_path.clone(),
                    guest_path: m.guest_path.clone(),
                    read_only: m.readonly,
                })
                .collect(),
            backend: arcbox_core::VmBackend::default(),
            enable_rosetta: false,
        };

        runtime
            .machine_manager()
            .create(config)
            .await
            .map_err(ApiError::from)?;

        Response::ok(pb::CreateMachineResponse {
            id: req.name,
            ..Default::default()
        })
    }

    async fn start(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::StartMachineRequest>,
    ) -> ServiceResult<pb::Empty> {
        let id = request.to_owned_message().id;
        let runtime = self.runtime.ready()?;

        runtime
            .machine_manager()
            .start(&id)
            .await
            .map_err(ApiError::from)?;

        Response::ok(pb::Empty::default())
    }

    async fn stop(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::StopMachineRequest>,
    ) -> ServiceResult<pb::Empty> {
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        let manager = std::sync::Arc::clone(runtime.machine_manager());

        // Graceful stop (guest ACPI) with a force fallback, unless the caller
        // asked for an immediate force stop. Both are synchronous VM calls
        // that can block up to the shutdown window; keep them off the async
        // workers.
        let force = req.force;
        let id = req.id;
        tokio::task::spawn_blocking(move || {
            if force {
                return manager.stop(&id);
            }
            match manager.graceful_stop(
                &id,
                std::time::Duration::from_secs(
                    arcbox_constants::timeouts::HOST_SHUTDOWN_TIMEOUT_SECS,
                ),
            ) {
                Ok(true) => Ok(()),
                Ok(false) => {
                    tracing::warn!(machine = %id, "graceful stop timed out; force stopping");
                    manager.stop(&id)
                }
                Err(e) => Err(e),
            }
        })
        .await
        .map_err(|e| ConnectError::internal(format!("stop task panicked: {e}")))?
        .map_err(ApiError::from)?;

        Response::ok(pb::Empty::default())
    }

    async fn remove(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::RemoveMachineRequest>,
    ) -> ServiceResult<pb::Empty> {
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;

        runtime
            .machine_manager()
            .remove(&req.id, req.force)
            .map_err(ApiError::from)?;

        Response::ok(pb::Empty::default())
    }

    async fn list(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListMachinesRequest>,
    ) -> ServiceResult<pb::ListMachinesResponse> {
        let runtime = self.runtime.ready()?;

        let summaries: Vec<pb::MachineSummary> = runtime
            .machine_manager()
            .list()
            .into_iter()
            .map(|m| pb::MachineSummary {
                id: m.name.clone(),
                name: m.name,
                state: format!("{:?}", m.state).to_lowercase(),
                cpus: m.cpus,
                memory: m.memory_mb * 1024 * 1024,
                disk_size: m.disk_gb * 1024 * 1024 * 1024,
                ip_address: m.ip_address.unwrap_or_default(),
                created: m.created_at.timestamp(),
                distro: m.distro.unwrap_or_default(),
                distro_version: m.distro_version.unwrap_or_default(),
                ..Default::default()
            })
            .collect();

        Response::ok(pb::ListMachinesResponse {
            machines: summaries,
            ..Default::default()
        })
    }

    async fn inspect(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::InspectMachineRequest>,
    ) -> ServiceResult<pb::MachineInfo> {
        let id = request.to_owned_message().id;
        let runtime = self.runtime.ready()?;

        let machine = runtime
            .machine_manager()
            .get(&id)
            .ok_or_else(|| ConnectError::not_found("machine not found"))?;

        let resp = pb::MachineInfo {
            id: machine.name.clone(),
            name: machine.name,
            state: format!("{:?}", machine.state).to_lowercase(),
            hardware: pb::MachineHardware {
                cpus: machine.cpus,
                memory: machine.memory_mb * 1024 * 1024,
                arch: std::env::consts::ARCH.to_string(),
                ..Default::default()
            }
            .into(),
            network: pb::MachineNetwork {
                // Gateway/DNS only exist once the guest has an address; both
                // are the NAT gateway (which also serves DNS — the same
                // topology the agent's DHCP path configures).
                gateway: machine
                    .ip_address
                    .as_ref()
                    .map(|_| NAT_GATEWAY.to_string())
                    .unwrap_or_default(),
                dns_servers: machine
                    .ip_address
                    .as_ref()
                    .map(|_| vec![NAT_GATEWAY.to_string()])
                    .unwrap_or_default(),
                ip_address: machine.ip_address.clone().unwrap_or_default(),
                mac_address: String::new(),
                bridge_mac_address: arcbox_core::vm::bridge_nic_mac_for_vm_id(&machine.vm_id),
                ..Default::default()
            }
            .into(),
            storage: pb::MachineStorage {
                disk_size: machine.disk_gb * 1024 * 1024 * 1024,
                disk_format: "raw".to_string(),
                disk_path: machine
                    .disk_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                ..Default::default()
            }
            .into(),
            os: pb::MachineOS {
                distro: machine
                    .distro
                    .clone()
                    .unwrap_or_else(|| "linux".to_string()),
                version: machine.distro_version.clone().unwrap_or_default(),
                kernel: machine.kernel.unwrap_or_default(),
                ..Default::default()
            }
            .into(),
            created: timestamp(machine.created_at).into(),
            started_at: machine.started_at.map(timestamp).into(),
            mounts: machine
                .mounts
                .iter()
                .map(|m| pb::DirectoryMount {
                    host_path: m.host_path.clone(),
                    guest_path: m.guest_path.clone(),
                    readonly: m.read_only,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        Response::ok(resp)
    }

    async fn ping(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::MachineAgentRequest>,
    ) -> ServiceResult<pb::MachinePingResponse> {
        let id = request.to_owned_message().id;

        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&id)
            .map_err(ApiError::from)?;
        let response = agent.ping().await.map_err(ApiError::from)?;

        Response::ok(pb::MachinePingResponse {
            message: response.message,
            version: response.version,
            ..Default::default()
        })
    }

    async fn get_system_info(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::MachineAgentRequest>,
    ) -> ServiceResult<pb::MachineSystemInfo> {
        let id = request.to_owned_message().id;

        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&id)
            .map_err(ApiError::from)?;
        let info = agent.get_system_info().await.map_err(ApiError::from)?;

        Response::ok(pb::MachineSystemInfo {
            kernel_version: info.kernel_version,
            os_name: info.os_name,
            os_version: info.os_version,
            arch: info.arch,
            total_memory: info.total_memory,
            available_memory: info.available_memory,
            cpu_count: info.cpu_count,
            load_average: info.load_average,
            hostname: info.hostname,
            uptime: info.uptime,
            ip_addresses: info.ip_addresses,
            ..Default::default()
        })
    }

    async fn compact_disk(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::MachineAgentRequest>,
    ) -> ServiceResult<pb::Empty> {
        let id = request.to_owned_message().id;

        // Trigger an immediate fstrim in the guest. The discards flow through
        // virtio-blk, which punches holes in the host data image, shrinking its
        // physical footprint. The caller measures host usage before/after.
        //
        // If fstrim fails in the guest, the agent replies with a generic error
        // response, so `disk_trim()` surfaces it as an `Err` here — no need to
        // inspect the result text.
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&id)
            .map_err(ApiError::from)?;
        let resp = agent.disk_trim().await.map_err(ApiError::from)?;
        tracing::debug!(machine = %id, result = %resp.result, "disk compact: fstrim done");

        Response::ok(pb::Empty::default())
    }

    /// Runs a command in the machine root via the guest agent, streaming
    /// stdout/stderr frames and a final exit-code frame.
    ///
    /// Non-interactive: the agent rejects `tty` requests until the bidi exec
    /// session lands. Streaming requires the async agent transport (VZ);
    /// the HV blocking transport shares the sandbox-streaming limitation.
    async fn exec(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::MachineExecRequest>,
    ) -> ServiceResult<ServiceStream<pb::MachineExecOutput>> {
        let req = request.to_owned_message();
        let agent = self
            .runtime
            .ready()?
            .get_agent(&req.id)
            .map_err(ApiError::from)?;

        let mut rx = agent.machine_exec(req).await.map_err(ApiError::from)?;

        let stream = async_stream::stream! {
            while let Some(item) = rx.recv().await {
                match item {
                    Ok(output) => {
                        let done = output.done;
                        yield Ok(output);
                        if done {
                            break;
                        }
                    }
                    Err(e) => {
                        yield Err(ConnectError::from(ApiError::from(e)));
                        break;
                    }
                }
            }
        };
        Response::ok(Box::pin(stream))
    }

    async fn ssh_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::SSHInfoRequest>,
    ) -> ServiceResult<pb::SSHInfoResponse> {
        // TODO: Implement SSH info.
        Err(ConnectError::unimplemented("ssh_info not implemented"))
    }

    /// Interactive machine exec: a bidi PTY session bridged to the agent's
    /// machine-exec frames. The first client message must carry Init; stdin
    /// and resize messages follow on the same stream.
    async fn exec_session(
        &self,
        _ctx: RequestContext,
        requests: InboundStream<pb::MachineExecInput>,
    ) -> ServiceResult<ServiceStream<pb::MachineExecOutput>> {
        let mut stream = requests;

        let first = stream.next().await.ok_or_else(|| {
            ConnectError::invalid_argument("exec session: stream closed before Init message")
        })??;
        let exec_req = match first.to_owned_message().payload {
            Some(machine_exec_input::Payload::Init(req)) => *req,
            _ => {
                return Err(ConnectError::invalid_argument(
                    "exec session: first message must be Init",
                ));
            }
        };

        let agent = self
            .runtime
            .ready()?
            .get_agent(&exec_req.id)
            .map_err(ApiError::from)?;

        // Feed remaining gRPC input (stdin + TTY resizes) into a channel for
        // the core layer. Stream end sends the empty-stdin EOF sentinel.
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(Ok(item)) = stream.next().await {
                let msg = match item.to_owned_message().payload {
                    Some(machine_exec_input::Payload::Stdin(data)) => ExecSessionInput::Stdin(data),
                    Some(machine_exec_input::Payload::Resize(size)) => ExecSessionInput::Resize {
                        width: u16::try_from(size.width).unwrap_or(u16::MAX),
                        height: u16::try_from(size.height).unwrap_or(u16::MAX),
                    },
                    _ => continue,
                };
                if in_tx.send(msg).await.is_err() {
                    return;
                }
            }
            let _ = in_tx.send(ExecSessionInput::Stdin(Vec::new())).await;
        });

        let mut out_rx = agent
            .machine_exec_session(exec_req, in_rx)
            .await
            .map_err(ApiError::from)?;

        let out_stream = async_stream::stream! {
            while let Some(item) = out_rx.recv().await {
                match item {
                    Ok(output) => {
                        let done = output.done;
                        yield Ok(output);
                        if done {
                            break;
                        }
                    }
                    Err(e) => {
                        yield Err(ConnectError::from(ApiError::from(e)));
                        break;
                    }
                }
            }
        };
        Response::ok(Box::pin(out_stream))
    }

    async fn events(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::MachineEventsRequest>,
    ) -> ServiceResult<ServiceStream<pb::MachineEvent>> {
        use tokio::sync::broadcast::error::RecvError;

        let req = request.to_owned_message();
        let mut rx = self.runtime.ready()?.event_bus().subscribe();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let Some(machine_event) = to_machine_event(&event) else {
                            continue;
                        };
                        if !req.id.is_empty() && machine_event.name != req.id {
                            continue;
                        }
                        if !req.action.is_empty() && machine_event.action != req.action {
                            continue;
                        }
                        yield Ok(machine_event);
                    }
                    // Dropped events under load: emit a resync signal so the
                    // client re-lists even if the missed event would have been
                    // filtered out here (otherwise a filtered `stopped` could be
                    // lost with no later matching event to recover from).
                    Err(RecvError::Lagged(_)) => {
                        yield Ok(resync_event());
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        };

        Response::ok(Box::pin(stream))
    }
}

/// Current wall-clock time as Unix nanoseconds (saturating).
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// Maps a system event to its machine-lifecycle wire form, or `None` for
/// events that are not machine lifecycle transitions.
fn to_machine_event(event: &arcbox_core::event::Event) -> Option<pb::MachineEvent> {
    use arcbox_core::event::Event;

    let (name, action) = match event {
        Event::MachineCreated { name } => (name, "created"),
        Event::MachineStarted { name } => (name, "started"),
        Event::MachineIdle { name } => (name, "idle"),
        Event::MachineStopped { name } => (name, "stopped"),
        Event::MachineRemoved { name } => (name, "removed"),
        _ => return None,
    };
    Some(pb::MachineEvent {
        name: name.clone(),
        action: action.to_owned(),
        timestamp: now_unix_nanos(),
        ..Default::default()
    })
}

/// A filter-independent signal that the client should re-list because events
/// were dropped. Carries no machine name and the reserved `resync` action.
fn resync_event() -> pb::MachineEvent {
    pb::MachineEvent {
        name: String::new(),
        action: "resync".to_owned(),
        timestamp: now_unix_nanos(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{resync_event, to_machine_event};
    use arcbox_core::event::Event;

    #[test]
    fn maps_each_machine_lifecycle_event() {
        let cases = [
            (Event::MachineCreated { name: "m".into() }, "created"),
            (Event::MachineStarted { name: "m".into() }, "started"),
            (Event::MachineIdle { name: "m".into() }, "idle"),
            (Event::MachineStopped { name: "m".into() }, "stopped"),
            (Event::MachineRemoved { name: "m".into() }, "removed"),
        ];
        for (event, action) in cases {
            let mapped = to_machine_event(&event).expect("machine event maps");
            assert_eq!(mapped.name, "m");
            assert_eq!(mapped.action, action);
        }
    }

    #[test]
    fn ignores_non_machine_events() {
        assert!(to_machine_event(&Event::VmStarted { id: "vm".into() }).is_none());
        assert!(to_machine_event(&Event::ContainerRouteInstalled { name: "m".into() }).is_none());
    }

    #[test]
    fn resync_event_carries_no_name() {
        let event = resync_event();
        assert_eq!(event.action, "resync");
        assert!(event.name.is_empty());
    }
}
