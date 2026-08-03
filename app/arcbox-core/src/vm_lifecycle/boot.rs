//! Boot and stop sub-tasks: the slow I/O side of the lifecycle.
//!
//! These run in `tokio::spawn`ed tasks owned by the actor (`actor.rs`), which
//! keeps the actor itself non-blocking so `ForceStop` can preempt at any time.
//! Completion is reported back as an [`InternalEvent`]; the bodies are ports
//! of the pre-actor `start_default_vm` / `wait_for_agent` / `shutdown`.

use std::fs::OpenOptions;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::error::{CoreError, Result};
use crate::event::Event;
use crate::machine::MachineConfig;
use arcbox_constants::cmdline::{
    DEBUG_CONSOLE_KEY, DOCKER_METADATA_DEVICE_KEY, GUEST_DOCKER_VSOCK_PORT_KEY,
    HV_EARLYCON_DIRECTIVE, RUNTIME_IMAGE_DEVICE_KEY,
};
use arcbox_constants::devices::{DOCKER_METADATA_BLOCK_DEVICE, RUNTIME_IMAGE_BLOCK_DEVICE};
use arcbox_error::CommonError;

use super::actor::{Completion, InternalEvent, LifecycleShared};
use super::types::{DesiredBoot, machine_drift_reason, metadata_image_filename};
use super::{DOCKER_DATA_IMAGE_SIZE_BYTES, DOCKER_METADATA_IMAGE_SIZE_BYTES, RecoveryAction};

impl LifecycleShared {
    /// Boots the VM end-to-end (create if needed, start with retries, wait for
    /// the agent) and reports the outcome to the actor, tagged with the epoch
    /// this sub-task was spawned under.
    pub(super) async fn run_boot(
        self: Arc<Self>,
        create: bool,
        timeout: Duration,
        epoch: u64,
        events: &mpsc::UnboundedSender<Completion>,
    ) {
        let outcome = match self.boot(create, timeout).await {
            Ok(()) => InternalEvent::AgentReady,
            Err(e) => InternalEvent::BootFailed(e.to_string()),
        };
        let _ = events.send(Completion { epoch, outcome });
    }

    /// Gracefully stops the VM (force-stop fallback) and reports the outcome,
    /// tagged with the epoch this sub-task was spawned under.
    pub(super) async fn run_stop(
        self: Arc<Self>,
        epoch: u64,
        events: &mpsc::UnboundedSender<Completion>,
    ) {
        // Stop health monitoring before tearing the VM down.
        self.health_monitor.stop();

        let mm = Arc::clone(&self.machine_manager);
        let name = self.machine_name.clone();
        // `graceful_stop` and `stop` are synchronous VM calls that can block up
        // to the host shutdown timeout; keep them off the async workers.
        let stop_result = tokio::task::spawn_blocking(move || {
            match mm.graceful_stop(
                &name,
                Duration::from_secs(arcbox_constants::timeouts::HOST_SHUTDOWN_TIMEOUT_SECS),
            ) {
                Ok(true) => Ok(()),
                Ok(false) => {
                    tracing::warn!(
                        "Graceful stop timed out for '{}', falling back to force stop",
                        name
                    );
                    mm.stop(&name)
                }
                Err(e) => {
                    tracing::warn!(
                        "Graceful stop failed for '{}': {}, falling back to force stop",
                        name,
                        e
                    );
                    mm.stop(&name)
                }
            }
        })
        .await
        .map_err(|e| CoreError::Vm(format!("stop task panicked: {e}")))
        .and_then(|r| r);

        let outcome = match stop_result {
            Ok(()) => {
                tracing::info!("Default VM stopped");
                InternalEvent::Stopped
            }
            Err(e) => InternalEvent::StopFailed(e.to_string()),
        };
        let _ = events.send(Completion { epoch, outcome });
    }

    /// Reboots the VM in place (guest PSCI SYSTEM_RESET), then waits for the
    /// agent, reporting the outcome tagged with this sub-task's epoch. Mirrors
    /// [`run_boot`](Self::run_boot) so the actor treats a reboot exactly like a
    /// boot (AgentReady promotes back to running; BootFailed lands in failed).
    pub(super) async fn run_reboot(
        self: Arc<Self>,
        timeout: Duration,
        epoch: u64,
        events: &mpsc::UnboundedSender<Completion>,
    ) {
        let outcome = match self.reboot(timeout).await {
            Ok(()) => InternalEvent::AgentReady,
            Err(e) => InternalEvent::BootFailed(e.to_string()),
        };
        let _ = events.send(Completion { epoch, outcome });
    }

    /// Reboot body: a full teardown + fresh boot of the VMM (blocking), then
    /// agent readiness + clock sync — the tail of `boot` without the
    /// create/drift step, since the machine record and disks are unchanged.
    async fn reboot(&self, timeout: Duration) -> Result<()> {
        let mm = Arc::clone(&self.machine_manager);
        let name = self.machine_name.clone();
        // `reboot` is a synchronous stop + re-init + start; keep it off the
        // async workers.
        tokio::task::spawn_blocking(move || mm.reboot(&name))
            .await
            .map_err(|e| CoreError::Vm(format!("reboot task panicked: {e}")))??;
        // The teardown dropped the bridge along with the VMM; the fresh boot
        // created a new one, so the host container-subnet route must be
        // reinstalled exactly like after a normal start.
        self.spawn_route_reconciler();
        self.wait_for_agent(timeout).await?;
        self.sync_guest_clock().await;
        Ok(())
    }

    /// The boot body: drift check, optional (re)create, start loop with
    /// recovery retries, then agent readiness.
    async fn boot(&self, create_hint: bool, timeout: Duration) -> Result<()> {
        let existing_machine = self.machine_manager.get(&self.machine_name);
        let machine_exists = existing_machine.is_some();
        if !create_hint && !machine_exists {
            tracing::warn!(
                "default machine missing while lifecycle state indicates existing VM; recreating"
            );
        }

        // Recreate the persisted machine if any daemon-overridable field has
        // drifted from the desired config. The desired kernel + cmdline are
        // resolved through the same `resolve_desired_boot` path that
        // `create_default_machine` uses, so drift detection can never disagree
        // with what would actually be created. Resolving assets may download,
        // which is why the whole check lives in this sub-task rather than the
        // actor.
        let desired_boot = match self.resolve_desired_boot().await {
            Ok(boot) => Some(boot),
            Err(e) => {
                tracing::warn!(error = %e, "could not resolve desired boot params; skipping drift check");
                None
            }
        };
        let drift_reason = match (existing_machine.as_ref(), desired_boot.as_ref()) {
            (Some(m), Some(boot)) => machine_drift_reason(m, &self.config.default_vm, boot),
            _ => None,
        };
        if let Some(field) = drift_reason {
            let m = existing_machine.as_ref().unwrap();
            tracing::warn!(
                drifted_field = field,
                persisted_cpus = m.cpus,
                persisted_memory = m.memory_mb,
                persisted_kernel = m.kernel.as_deref().unwrap_or("none"),
                desired_cpus = self.config.default_vm.cpus,
                desired_memory = self.config.default_vm.memory_mb,
                "default machine config drifted from desired defaults; recreating"
            );
            let _ = self.machine_manager.remove(&self.machine_name, true);
        }

        if create_hint || !machine_exists || drift_reason.is_some() {
            self.create_default_machine().await?;
            self.event_bus.publish(Event::MachineCreated {
                name: self.machine_name.clone(),
            });
        }

        // Time the fresh boot (VM start -> agent ready) so the boot latency is
        // one greppable structured event against the <1.5s cold / <500ms warm
        // targets. `boot` only runs on a fresh start, so no boot is ever
        // double-counted.
        let boot_start = std::time::Instant::now();
        self.start_with_retries(timeout).await?;
        self.wait_for_agent(timeout).await?;
        tracing::info!(
            boot_ms = boot_start.elapsed().as_millis() as u64,
            "guest boot ready"
        );
        self.sync_guest_clock().await;

        // Reset recovery counters on a fully successful boot.
        self.recovery.reset();
        self.health_monitor.reset();

        Ok(())
    }

    /// Pushes the host wall clock into the guest right after readiness.
    ///
    /// The ping request carries `timestamp_secs`, which the agent applies
    /// via `clock_settime`. VZ guests read wall time from the platform
    /// RTC, but the HV backend exposes no RTC device — without this push
    /// the guest clock stays at the kernel default epoch and every TLS
    /// handshake fails certificate validity checks. Best effort: a failed
    /// sync only warns (readiness already proved the agent reachable, and
    /// the guest can also be synced by any later ping).
    async fn sync_guest_clock(&self) {
        let machine_manager = self.machine_manager.clone();
        let machine_name = self.machine_name.clone();
        // `connect_agent` yields a blocking transport on the HV AF_UNIX
        // socketpair and an async one on AF_VSOCK (VZ) / Linux; ping over
        // whichever the client actually has.
        let connected =
            tokio::task::spawn_blocking(move || machine_manager.connect_agent(&machine_name)).await;
        let result = match connected {
            Ok(Ok(mut agent)) => {
                if agent.is_blocking() {
                    tokio::task::spawn_blocking(move || agent.ping_blocking().map(|_| ()))
                        .await
                        .unwrap_or_else(|e| {
                            Err(CoreError::Vm(format!("clock sync task panicked: {e}")))
                        })
                } else {
                    agent.ping().await.map(|_| ())
                }
            }
            Ok(Err(e)) => Err(e),
            Err(e) => Err(CoreError::Vm(format!("clock sync task panicked: {e}"))),
        };
        match result {
            Ok(()) => tracing::info!("guest wall clock synced from host"),
            Err(e) => tracing::warn!(error = %e, "guest clock sync ping failed"),
        }
    }

    /// Starts the machine, retrying per the recovery policy within `timeout`,
    /// recreating the machine if it disappeared underneath us.
    async fn start_with_retries(&self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            match self.machine_manager.start(&self.machine_name).await {
                Ok(()) => {
                    tracing::info!("Default VM started successfully");
                    self.spawn_route_reconciler();
                    return Ok(());
                }
                Err(e) => {
                    if is_not_found_error(&e) {
                        tracing::warn!(
                            "default machine disappeared before start; recreating and retrying"
                        );
                        self.create_default_machine().await?;
                        self.event_bus.publish(Event::MachineCreated {
                            name: self.machine_name.clone(),
                        });
                        continue;
                    }

                    tracing::warn!("Failed to start VM: {}", e);

                    // Check if we should retry.
                    // Avoid wrapping "VM error: ..." multiple times when propagating.
                    let recovery_error = match &e {
                        CoreError::Vm(msg) => msg.as_str(),
                        _ => &e.to_string(),
                    };
                    match self.recovery.handle_failure(recovery_error) {
                        RecoveryAction::RetryAfter(delay) => {
                            if tokio::time::Instant::now() + delay > deadline {
                                return Err(CoreError::Vm(format!(
                                    "VM startup timeout after {} retries",
                                    self.recovery.retry_count()
                                )));
                            }

                            tracing::info!("Retrying VM start in {:?}", delay);
                            tokio::time::sleep(delay).await;
                        }
                        RecoveryAction::GiveUp(err) => {
                            return Err(CoreError::Vm(err));
                        }
                    }
                }
            }
        }
    }

    /// Installs the host route for container subnets via the bridge NIC.
    ///
    /// Non-blocking: retries transient failures (helper not ready, bridge FDB
    /// not populated) but does not gate VM readiness.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    fn spawn_route_reconciler(&self) {
        if let Some(bridge) = self.machine_manager.vmnet_bridge_name(&self.machine_name) {
            // vmnet path: bridge name is known instantly, only need
            // helper retry (1-2 attempts for XPC readiness).
            let event_bus = self.event_bus.clone();
            let name = self.machine_name.clone();
            drop(tokio::spawn(async move {
                match crate::route_reconciler::ensure_route_for_bridge(&bridge).await {
                    Ok(()) => {
                        event_bus.publish(Event::ContainerRouteInstalled { name });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to install container route (vmnet)");
                    }
                }
            }));
        }
    }

    /// See the vmnet variant; this path discovers the bridge by scanning the
    /// kernel FDB (retries up to ~10s for FDB learning).
    #[cfg(all(target_os = "macos", not(feature = "vmnet")))]
    fn spawn_route_reconciler(&self) {
        if let Some(mac) = self.machine_manager.bridge_mac(&self.machine_name) {
            let event_bus = self.event_bus.clone();
            let name = self.machine_name.clone();
            drop(tokio::spawn(async move {
                match crate::route_reconciler::ensure_route_with_retry(&mac).await {
                    Ok(()) => {
                        event_bus.publish(Event::ContainerRouteInstalled { name });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to install container route");
                    }
                }
            }));
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn spawn_route_reconciler(&self) {}

    /// Creates the default machine with EROFS rootfs and no initramfs.
    ///
    /// Block devices:
    /// - vda: rootfs.erofs (read-only)
    /// - vdb: docker-data.img (read-write, btrfs bulk data)
    /// - vdc: docker-meta.img (read-write, ext4 metadata volume)
    async fn create_default_machine(&self) -> Result<()> {
        let boot = self.resolve_desired_boot().await?;
        let rootfs_path = boot.rootfs_image.to_string_lossy().to_string();

        // Block devices: vda = EROFS rootfs (read-only), vdb = Docker data (read-write).
        let mut block_devices = vec![crate::vm::BlockDeviceConfig {
            path: rootfs_path.clone(),
            read_only: true,
        }];

        // Attach persistent Docker data disk.
        let docker_data_image = self
            .data_dir
            .join(arcbox_constants::paths::host::DATA)
            .join(&self.data_image_filename);
        ensure_sparse_block_image(&docker_data_image, DOCKER_DATA_IMAGE_SIZE_BYTES)?;

        // Don't inject docker_data_device into cmdline — let the agent
        // auto-detect. It prefers /dev/arcboxhvc1 (HVC fast path) when
        // available, falling back to /dev/vdb (VirtIO block).
        block_devices.push(crate::vm::BlockDeviceConfig {
            path: docker_data_image.to_string_lossy().to_string(),
            read_only: false,
        });

        // Attach the ext4 metadata volume (vdc): the fsync-hot boltdb
        // metadata lives there while bulk data stays on the btrfs data disk.
        // The two images are a paired set — see
        // internal-docs/plans/ext4-metadata-volume.md.
        let metadata_image = self
            .data_dir
            .join(arcbox_constants::paths::host::DATA)
            .join(metadata_image_filename(&self.data_image_filename));
        ensure_sparse_block_image(&metadata_image, DOCKER_METADATA_IMAGE_SIZE_BYTES)?;
        block_devices.push(crate::vm::BlockDeviceConfig {
            path: metadata_image.to_string_lossy().to_string(),
            read_only: false,
        });

        // Attach the read-only runtime image when the pinned boot release
        // ships one: the guest execs dockerd/containerd/the shim/runc from
        // this block device instead of over VirtioFS, which costs a FUSE
        // round-trip per exec (~7-10x more, measured) on every container
        // start. Releases predating it leave this None and the guest keeps
        // using the VirtioFS copies (ABX-498).
        if let Some(ref runtime_image) = boot.runtime_image {
            block_devices.push(crate::vm::BlockDeviceConfig {
                path: runtime_image.to_string_lossy().to_string(),
                read_only: true,
            });
        }

        let config = MachineConfig {
            name: self.machine_name.clone(),
            cpus: self.config.default_vm.cpus,
            memory_mb: self.config.default_vm.memory_mb,
            disk_gb: self.config.default_vm.disk_gb,
            kernel: Some(boot.kernel),
            cmdline: Some(boot.cmdline),
            block_devices,
            rootfs: None,
            mounts: Vec::new(),
            distro: None,
            distro_version: None,
            backend: self.backend(),
            // Host Rosetta capability. Whether the Rosetta share is actually
            // wired is decided per-backend at VM build time (VZ only), so the
            // value stays correct across a backend switch — see
            // `VmManager::build_vmm_config`.
            enable_rosetta: self.config.default_vm.rosetta,
        };

        tracing::info!(
            "Creating default machine: cpus={}, memory={}MB, kernel={}, rootfs={}",
            config.cpus,
            config.memory_mb,
            config.kernel.as_deref().unwrap_or("default"),
            rootfs_path,
        );

        self.machine_manager.create(config).await?;

        Ok(())
    }

    /// Resolves the default VM's boot parameters (kernel image, final kernel
    /// command line, and rootfs image) from config + boot assets.
    ///
    /// Shared by [`Self::create_default_machine`] and the drift check in
    /// [`Self::boot`] so machine creation and drift detection always agree on
    /// the desired kernel and cmdline. The cmdline is the base (explicit
    /// override or the boot manifest default) with `quiet` stripped,
    /// `earlycon` ensured, the guest docker vsock port injected, and the
    /// HV debug-console token attached.
    async fn resolve_desired_boot(&self) -> Result<DesiredBoot> {
        let assets = self.boot_assets.get_assets().await?;
        let mut cmdline = self
            .config
            .default_vm
            .cmdline
            .clone()
            .unwrap_or(assets.cmdline);

        // Strip "quiet" so kernel boot messages are visible on the serial console.
        cmdline = cmdline
            .split_whitespace()
            .filter(|t| *t != "quiet")
            .collect::<Vec<_>>()
            .join(" ");

        // Ensure an explicit earlycon directive so early boot output reaches the
        // host `guest_serial` log — but only on the custom-HV backend, whose PL011
        // emulator the directive targets (VZ has no such device). See
        // `ensure_earlycon`.
        cmdline = ensure_earlycon(cmdline, self.backend());

        // Inject guest docker vsock port if configured.
        if let Some(port) = self.config.guest_docker_vsock_port {
            if !cmdline
                .split_whitespace()
                .any(|token| token.starts_with(GUEST_DOCKER_VSOCK_PORT_KEY))
            {
                cmdline.push(' ');
                cmdline.push_str(GUEST_DOCKER_VSOCK_PORT_KEY);
                cmdline.push_str(&port.to_string());
            }
        }

        // Declare the ext4 metadata device this machine attaches as vdc.
        // Unlike the data device (auto-detected for its HVC fast path), the
        // declaration is authoritative: key present → the agent waits for
        // the node and hard-fails if it never appears; key absent (older
        // daemon) → the agent skips the metadata volume without probing.
        if !cmdline
            .split_whitespace()
            .any(|token| token.starts_with(DOCKER_METADATA_DEVICE_KEY))
        {
            cmdline.push(' ');
            cmdline.push_str(DOCKER_METADATA_DEVICE_KEY);
            cmdline.push_str(DOCKER_METADATA_BLOCK_DEVICE);
        }

        // Declare the runtime-image device only when this release ships one.
        // Its presence is the guest's signal to mount the image and exec the
        // runtime from it; its absence means "keep using VirtioFS". Injecting
        // it here (rather than at create time) also makes the cmdline drift
        // check recreate the machine when a release starts or stops shipping
        // the image, which is exactly when the disk set changes.
        if assets.runtime_image.is_some()
            && !cmdline
                .split_whitespace()
                .any(|token| token.starts_with(RUNTIME_IMAGE_DEVICE_KEY))
        {
            cmdline.push(' ');
            cmdline.push_str(RUNTIME_IMAGE_DEVICE_KEY);
            cmdline.push_str(RUNTIME_IMAGE_BLOCK_DEVICE);
        }

        // Always attach an interactive debug console on the custom-HV backend.
        // An operator can `socat - UNIX-CONNECT:<sock>` to get a serial root
        // shell into the guest even when early boot hangs before networking
        // (the dominant HV cold-boot failure mode). This token is the single
        // source of truth: the host opens the socket at `<sock>` and the guest
        // rcS keys off the same token to spawn the shell. HV-only — the token
        // targets the HV virtio-console wiring; VZ owns its console internally.
        // The socket lives under the per-user data dir (same-user access only).
        // Escape hatch to A/B-test the console's effect on the flaky HV cold
        // boot: `ARCBOX_NO_DEBUG_CONSOLE=1` strips any token (host attaches no
        // console, guest rcS spawns no shell). Default: console always attached.
        if std::env::var_os("ARCBOX_NO_DEBUG_CONSOLE").is_some() {
            cmdline = cmdline
                .split_whitespace()
                .filter(|t| !t.starts_with(DEBUG_CONSOLE_KEY))
                .collect::<Vec<_>>()
                .join(" ");
        } else if matches!(self.backend(), arcbox_vmm::VmBackend::Hv)
            && !cmdline
                .split_whitespace()
                .any(|t| t.starts_with(DEBUG_CONSOLE_KEY))
        {
            let sock = self.data_dir.join("run").join("console.sock");
            if let Some(parent) = sock.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            cmdline.push(' ');
            cmdline.push_str(DEBUG_CONSOLE_KEY);
            cmdline.push_str(&sock.to_string_lossy());
        }

        Ok(DesiredBoot {
            kernel: assets.kernel.to_string_lossy().to_string(),
            cmdline,
            rootfs_image: assets.rootfs_image,
            runtime_image: assets.runtime_image,
        })
    }

    /// Waits for the agent to become ready.
    async fn wait_for_agent(&self, timeout: Duration) -> Result<()> {
        // Per-boot correlation id: stamped on every readiness RPC so the host's
        // wait logs and the guest's RPC-dispatch logs can be matched for one boot.
        let boot_id = uuid::Uuid::new_v4().to_string();
        tracing::debug!(boot_id = %boot_id, "Waiting for agent to become ready...");

        enum AgentProbe {
            Ready,
            Watch(crate::agent_client::AgentClient),
        }

        let mm = Arc::clone(&self.machine_manager);
        let machine_name = self.machine_name.clone();
        let boot_id_blocking = boot_id.clone();

        // Run the entire probe loop on a blocking thread. On macOS HV backend,
        // the agent transport is AF_UNIX socketpair → BlockingVsockTransport.
        // Rapid connect/teardown of these fds stalls the tokio kqueue reactor's
        // timer wheel, so neither tokio::time::sleep nor tokio::time::timeout
        // can be used reliably inside this loop. spawn_blocking isolates the
        // probe from the async runtime entirely.
        let probe_result = tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + timeout;
            // Failed probes are ~1ms (vsock RST via the event-driven RX
            // path), so a tight interval costs little and bounds the
            // discovery overshoot once the agent starts listening.
            let poll_interval = Duration::from_millis(25);
            // Remember the last genuine readiness error so an exhausted deadline
            // surfaces it instead of a bare "timeout" (a guest-reported failure
            // also arrives here as an Err).
            let mut last_readiness_err: Option<String> = None;

            while std::time::Instant::now() < deadline {
                // Console output (best-effort, non-blocking).
                #[cfg(target_os = "macos")]
                if let Ok(output) = mm.read_console_output(&machine_name) {
                    let trimmed = output.trim_matches('\0');
                    if !trimmed.is_empty() {
                        tracing::info!("{}", trimmed.trim_end());
                    }
                }

                // connect_agent discovers when the guest starts listening on
                // the agent vsock port, then the readiness event stream waits
                // for the guest to report a terminal state.
                //
                // On the HV AF_UNIX socketpair, connect_agent can succeed
                // optimistically *before* the guest agent is actually listening
                // (the guest's /sbin/init has not even run yet at this point),
                // so the readiness read then fails with EOF. That is a normal
                // "not ready yet" race, not a fatal protocol error — keep
                // polling until a genuine readiness event arrives or the
                // deadline elapses. HV's AF_UNIX transport stays on this
                // blocking thread; async transports are handed back to tokio.
                match mm.connect_agent(&machine_name) {
                    Ok(mut agent) if agent.is_blocking() => {
                        // Protocol handshake before the readiness watch: Ping
                        // is understood by every agent generation, so a stale
                        // staged agent fails the boot here with an actionable
                        // protocol error instead of an opaque readiness
                        // timeout (the ABX-385 failure mode). A ping transport
                        // error is the usual "not listening yet" race — retry.
                        match agent.ping_blocking() {
                            Ok(resp) => {
                                crate::agent_client::AgentClient::check_agent_protocol(&resp)?;
                                // Record the handshake result so later
                                // connect_agent clients carry it (the
                                // sandbox gate reads it) — the System VM
                                // never runs wait_for_machine_ready.
                                mm.record_agent_protocol(&machine_name, resp.protocol_version)?;
                            }
                            Err(e) => {
                                tracing::debug!("agent not answering ping yet: {e}");
                                last_readiness_err = Some(e.to_string());
                                std::thread::sleep(poll_interval);
                                continue;
                            }
                        }
                        let remaining =
                            deadline.saturating_duration_since(std::time::Instant::now());
                        if remaining.is_zero() {
                            return Err(agent_timeout_error(last_readiness_err.as_deref()));
                        }
                        match agent.watch_readiness_blocking(false, remaining, &boot_id_blocking) {
                            Ok(_) => return Ok(AgentProbe::Ready),
                            Err(e) => {
                                tracing::debug!("agent not ready yet: {e}");
                                last_readiness_err = Some(e.to_string());
                            }
                        }
                    }
                    Ok(agent) => return Ok(AgentProbe::Watch(agent)),
                    Err(e) => tracing::debug!("Agent connection failed: {e}"),
                }

                std::thread::sleep(poll_interval);
            }

            Err(agent_timeout_error(last_readiness_err.as_deref()))
        })
        .await
        .map_err(|e| CoreError::Vm(format!("probe task panicked: {e}")))?;

        match probe_result? {
            AgentProbe::Ready => {}
            AgentProbe::Watch(first_agent) => {
                // Mirror the blocking path's tolerance: an async transport may
                // also connect before the guest agent is listening, so retry
                // both the connect and the readiness watch (reconnecting each
                // round) until it yields a genuine event or the timeout elapses.
                let deadline = tokio::time::Instant::now() + timeout;
                let mut next_agent = Some(first_agent);
                let mut last_readiness_err: Option<String> = None;
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(agent_timeout_error(last_readiness_err.as_deref()));
                    }
                    // Reuse the connection from the probe loop on the first
                    // iteration, then reconnect on each retry.
                    let mut agent = match next_agent.take() {
                        Some(agent) => agent,
                        None => match self.machine_manager.connect_agent(&self.machine_name) {
                            Ok(agent) => agent,
                            Err(e) => {
                                tracing::debug!("agent reconnect failed: {e}");
                                tokio::time::sleep(Duration::from_millis(25)).await;
                                continue;
                            }
                        },
                    };
                    // Protocol handshake before the readiness watch — mirrors
                    // the blocking arm: a stale agent fails loudly here, a
                    // ping transport error is a "not listening yet" retry.
                    // The async unary ping has no native deadline (the
                    // blocking transport does), so bound it by the remaining
                    // boot budget or a silent agent could hang the handshake
                    // past the startup timeout.
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(agent_timeout_error(last_readiness_err.as_deref()));
                    }
                    match tokio::time::timeout(remaining, agent.ping()).await {
                        Ok(Ok(resp)) => {
                            crate::agent_client::AgentClient::check_agent_protocol(&resp)?;
                            // Mirror the blocking arm: record the handshake
                            // result for the sandbox gate.
                            self.machine_manager
                                .record_agent_protocol(&self.machine_name, resp.protocol_version)?;
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("agent not answering ping yet: {e}");
                            last_readiness_err = Some(e.to_string());
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            continue;
                        }
                        Err(_) => {
                            return Err(agent_timeout_error(Some(
                                "handshake ping timed out before the agent answered",
                            )));
                        }
                    }
                    // Recompute the budget after a potentially slow reconnect so
                    // watch_readiness doesn't block past the deadline.
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(agent_timeout_error(last_readiness_err.as_deref()));
                    }
                    match agent.watch_readiness(false, remaining, &boot_id).await {
                        Ok(_) => break,
                        Err(e) => {
                            tracing::debug!("agent not ready yet: {e}");
                            last_readiness_err = Some(e.to_string());
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                    }
                }
            }
        }

        // Back on async context — do async follow-up work.
        tracing::info!(boot_id = %boot_id, "Agent is ready");
        self.health_monitor.record_success();
        #[cfg(target_os = "macos")]
        {
            let mm = Arc::clone(&self.machine_manager);
            tokio::spawn(super::serial::serial_read_adaptive(mm));
        }

        Ok(())
    }
}

/// Ensures an explicit `earlycon=` directive on the custom-HV backend.
///
/// A bare `earlycon` relies on the device-tree `stdout-path` and produces nothing
/// on the custom-HV PL011 emulator, so on `Hv` it is upgraded to the pinned
/// `earlycon=pl011,<base>` form. The `Vz` backend has no PL011 MMIO device (it
/// uses a VirtIO console), so pointing the kernel at that address would break VZ
/// early boot — its cmdline is left untouched. An explicit operator `earlycon=`
/// is always respected.
pub(super) fn ensure_earlycon(cmdline: String, backend: arcbox_vmm::VmBackend) -> String {
    if !matches!(backend, arcbox_vmm::VmBackend::Hv) {
        return cmdline;
    }
    if cmdline
        .split_whitespace()
        .any(|t| t.starts_with("earlycon="))
    {
        return cmdline;
    }
    let mut tokens: Vec<&str> = cmdline
        .split_whitespace()
        .filter(|t| *t != "earlycon")
        .collect();
    tokens.push(HV_EARLYCON_DIRECTIVE);
    tokens.join(" ")
}

/// Builds the "timeout waiting for agent" error, folding in the last observed
/// readiness error so a genuine guest-reported failure isn't masked as a plain
/// timeout (per-iteration errors are otherwise only logged at debug level).
pub(super) fn agent_timeout_error(last_error: Option<&str>) -> CoreError {
    match last_error {
        Some(e) => CoreError::Vm(format!("timeout waiting for agent (last error: {e})")),
        None => CoreError::Vm("timeout waiting for agent".to_string()),
    }
}

/// Ensures a sparse, thin-provisioned block image of `size_bytes` virtual
/// size exists at `path`, creating parent directories as needed.
///
/// `set_len` extends only the logical size (EOF); it reserves no physical
/// blocks, so the host file stays sparse and consumes disk only for blocks
/// the guest actually writes — matching OrbStack's thin data image.
///
/// We deliberately do NOT pre-allocate physical space. An upfront macOS
/// `F_PREALLOCATE` reservation (previously capped at 64 GiB) made a fresh
/// install report tens of GiB of disk usage with zero containers — wasteful
/// and a regression against OrbStack on idle footprint. APFS/Btrfs allocate
/// on write lazily, so the working set still benefits from CoW without the
/// upfront cost. An existing image is never shrunk.
#[allow(
    clippy::redundant_pub_crate,
    reason = "re-exported at the vm_lifecycle root so MachineManager can provision per-machine data disks"
)]
pub(crate) fn ensure_sparse_block_image(path: &Path, size_bytes: u64) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CoreError::config(format!(
                "failed to create block image directory '{}': {}",
                parent.display(),
                e
            ))
        })?;
    }

    let file_exists = path.exists();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| {
            CoreError::config(format!(
                "failed to open block image '{}': {}",
                path.display(),
                e
            ))
        })?;

    let current_len = file.metadata().map_err(|e| {
        CoreError::config(format!(
            "failed to stat block image '{}': {}",
            path.display(),
            e
        ))
    })?;

    // Extend the logical size only — `set_len` leaves the file sparse, so
    // no physical disk is consumed until the guest writes. Never shrink an
    // existing image (guards against a smaller `size_bytes` truncating
    // user data).
    if current_len.len() < size_bytes {
        file.set_len(size_bytes).map_err(|e| {
            CoreError::config(format!(
                "failed to resize block image '{}': {}",
                path.display(),
                e
            ))
        })?;
    }

    if !file_exists {
        tracing::info!(
            path = %path.display(),
            size_bytes,
            "created persistent docker data image"
        );
    }

    Ok(())
}

const fn is_not_found_error(err: &CoreError) -> bool {
    matches!(err, CoreError::Common(CommonError::NotFound(_)))
}
