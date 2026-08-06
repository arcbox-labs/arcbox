//! Sandbox service for the guest agent.
//!
//! Wraps [`SandboxManager`] from `arcbox-vm` and translates between the
//! `sandbox_v1` protobuf types (from `arcbox-connect`) and the native Rust
//! types used by `arcbox-vm`. Lifecycle CRUD lives here; executions, events,
//! file I/O, and snapshots live in the submodules.

mod convert;
mod events;
mod execution;
mod files;
mod snapshots;
mod template;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use arcbox_connect::sandbox_v1;
use arcbox_vm::{
    SandboxManager, SandboxMountSpec, SandboxNetworkSpec, SandboxSpec, SandboxState, VmmConfig,
    VmmError,
};
use buffa::Message;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::create_registry::{CreateRegistry, Reserve as CreateReserve};
use crate::error::SandboxError;

const STARTUP_CLEANUP_ID: &str = "$startup";

/// Verify the nested-virtualization prerequisite for sandboxes.
///
/// Firecracker needs `/dev/kvm`, which exists in this guest only when the
/// host enabled nested virtualization (VZ backend on Apple Silicon M3+ with
/// macOS 15+). Returns an actionable reason when the prerequisite is missing
/// so `Create` can fail fast with `FAILED_PRECONDITION` instead of an opaque
/// asynchronous boot failure.
pub fn probe_kvm() -> Result<(), String> {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(
            "sandboxes require nested virtualization (/dev/kvm is missing in the guest): \
             use the VZ backend on Apple Silicon M3 or newer with macOS 15+; \
             the HV backend and Intel/M1/M2 hosts cannot run sandboxes"
                .into(),
        ),
        Err(e) => Err(format!(
            "/dev/kvm exists but cannot be opened ({e}); sandboxes are unavailable"
        )),
    }
}

/// Thin wrapper around [`SandboxManager`] for use in the agent's RPC layer.
pub struct SandboxService {
    manager: Arc<SandboxManager>,
    creates: Arc<CreateRegistry>,
    operations: SandboxOperationLocks,
    /// Default rootfs image path; auto-built on first use when missing.
    default_rootfs: String,
}

#[derive(Default)]
struct SandboxOperationLocks {
    entries: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
}

impl SandboxOperationLocks {
    async fn lock(&self, id: &str) -> Option<OwnedMutexGuard<()>> {
        if id.is_empty() {
            return None;
        }
        let lock = {
            let mut entries = self.entries.lock().unwrap();
            entries.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = entries.get(id).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(AsyncMutex::new(()));
                entries.insert(id.to_owned(), Arc::downgrade(&lock));
                lock
            }
        };
        Some(lock.lock_owned().await)
    }
}

impl SandboxService {
    pub(crate) async fn lock_operation(&self, id: &str) -> Option<OwnedMutexGuard<()>> {
        self.operations.lock(id).await
    }

    pub(crate) fn is_terminal_or_absent(&self, id: &str) -> bool {
        match self.manager.inspect_sandbox(&id.to_owned()) {
            Ok(info) => matches!(info.state, SandboxState::Stopped | SandboxState::Failed),
            Err(VmmError::NotFound(_)) => true,
            Err(_) => false,
        }
    }

    /// Create a new [`SandboxService`] from the given config.
    pub fn new(config: VmmConfig) -> anyhow::Result<Self> {
        let default_rootfs = config.defaults.rootfs.clone();
        // `into_shared` starts the lifecycle monitor driving the idle/TTL
        // expiry timers (CORE-21/60).
        let manager = SandboxManager::new(config)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .into_shared();
        let creates = Arc::new(CreateRegistry::default());
        Ok(Self {
            manager,
            creates,
            operations: SandboxOperationLocks::default(),
            default_rootfs,
        })
    }

    /// Create a sandbox.
    ///
    /// The request names what boots with an opaque template reference; the
    /// boot recipe (kernel, rootfs, cmdline) is resolved here and never
    /// crosses the API (CORE-54). A `docker:<ref>` template is exported from
    /// the guest's own dockerd, converted to ext4 via the `oci2rootfs`
    /// library, and gets `vm-agent` injected before booting; the empty
    /// template selects the built-in busybox image, built on first use.
    pub async fn create(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::CreateSandboxResponse, SandboxError> {
        let request = sandbox_v1::CreateSandboxRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        if create_uses_network(&request) {
            self.manager.wait_startup_cleanup_complete().await;
        }
        let _operation = self.operations.lock(&request.id).await;
        let create_key = crate::create_key::create_key(&request);
        if request.id.is_empty() {
            return self.create_once(request, &create_key).await;
        }

        let id = request.id.clone();
        loop {
            self.clear_stale_completed_create(&id);
            match self.creates.reserve(&request).map_err(|_| {
                SandboxError::AlreadyExists(format!(
                    "sandbox '{id}' (id reused for a different create request)"
                ))
            })? {
                CreateReserve::Existing(response) => return Ok(response),
                CreateReserve::Slot(slot) => {
                    let response = self.create_once(request, &create_key).await?;
                    slot.commit(&response);
                    return Ok(response);
                }
                CreateReserve::AwaitPending(mut done) => {
                    let _ = done.changed().await;
                }
            }
        }
    }

    async fn create_once(
        &self,
        request: sandbox_v1::CreateSandboxRequest,
        create_key: &str,
    ) -> Result<sandbox_v1::CreateSandboxResponse, SandboxError> {
        if !request.id.is_empty()
            && let Some((id, ip_address)) = self
                .manager
                .replay_sandbox_create(&request.id, create_key)
                .await
                .map_err(SandboxError::from)?
        {
            return Ok(sandbox_v1::CreateSandboxResponse {
                id,
                ip_address,
                state: sandbox_v1::SandboxState::Starting.into(),
                ..Default::default()
            });
        }

        let template = template::Template::parse(&request.template)?;
        let mut spec = proto_to_spec(request);

        // V1 contract: reject declared-but-unimplemented spec fields
        // explicitly instead of silently ignoring them.
        if !spec.mounts.is_empty() {
            return Err(SandboxError::Unsupported(
                "mounts are not supported in Sandbox V1; copy files in with \
                 WriteFile (`abctl sandbox cp`) instead"
                    .into(),
            ));
        }
        if spec.ssh_public_key.is_some() {
            return Err(SandboxError::Unsupported(
                "ssh_public_key is not supported in Sandbox V1; use executions \
                 for interactive access"
                    .into(),
            ));
        }

        spec.rootfs = self.resolve_template(&template).await?;

        let (id, ip_address) = self
            .manager
            .create_sandbox_keyed(spec, create_key)
            .await
            .map_err(SandboxError::from)?;
        register_sandbox_dns(&id, &ip_address);
        Ok(sandbox_v1::CreateSandboxResponse {
            id,
            ip_address,
            state: sandbox_v1::SandboxState::Starting.into(),
            ..Default::default()
        })
    }

    /// Resolve a template to the guest path of a bootable ext4 rootfs.
    async fn resolve_template(
        &self,
        template: &template::Template,
    ) -> Result<String, SandboxError> {
        match template {
            template::Template::Default => {
                // Built on first use, and rebuilt when the staged vm-agent is
                // newer than the cached image.
                crate::rootfs_builder::ensure_default_rootfs(&self.default_rootfs)
                    .await
                    .map_err(|e| SandboxError::Internal(format!("default template: {e}")))?;
                Ok(self.default_rootfs.clone())
            }
            template::Template::DockerImage(image) => {
                let layout = template::export_docker_image(image)
                    .await
                    .map_err(|e| SandboxError::Internal(format!("template {image}: {e:#}")))?;
                // Pass the images snapshots depend on so the conversion's
                // cache sweep leaves them alone — a restore has no way to
                // rebuild its dm-snapshot origin.
                let pinned = self
                    .manager
                    .pinned_rootfs_paths()
                    .map_err(SandboxError::from)?;
                crate::rootfs_builder::convert_layer_to_rootfs(&layout, &pinned)
                    .await
                    .map_err(|e| SandboxError::Internal(format!("template {image}: {e:#}")))
            }
        }
    }

    /// Stop a sandbox.
    pub async fn stop(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::StopSandboxRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let _operation = self.operations.lock(&req.id).await;
        self.stop_request(req).await
    }

    pub(crate) async fn stop_request(
        &self,
        req: sandbox_v1::StopSandboxRequest,
    ) -> Result<(), SandboxError> {
        self.manager
            .stop_sandbox(&req.id, req.timeout_seconds)
            .await
            .map_err(SandboxError::from)?;
        deregister_sandbox_dns(&req.id);
        Ok(())
    }

    /// Pause a sandbox: checkpoint, then release its VM while keeping the
    /// record and disk under the same id (CORE-21). The sandbox's DNS entry
    /// is dropped with its released IP; Resume re-registers the fresh one.
    pub(crate) async fn pause_request(
        &self,
        req: sandbox_v1::PauseSandboxRequest,
    ) -> Result<(), SandboxError> {
        self.manager
            .pause_sandbox(&req.id)
            .await
            .map_err(SandboxError::from)?;
        deregister_sandbox_dns(&req.id);
        Ok(())
    }

    /// Resume a paused sandbox in place and re-register its fresh IP.
    ///
    /// The wire reason is constrained to the two values the contract
    /// documents; anything else (including empty) reads as an explicit
    /// resume rather than injecting arbitrary event attributes.
    pub(crate) async fn resume_request(
        &self,
        req: arcbox_connect::v1::SandboxResumeCommand,
    ) -> Result<arcbox_connect::v1::SandboxResumeResponse, SandboxError> {
        let reason = if req.reason == arcbox_vm::pause_reason::AUTO_RESUME {
            arcbox_vm::pause_reason::AUTO_RESUME
        } else {
            arcbox_vm::pause_reason::RESUME
        };
        let ip_address = self
            .manager
            .resume_sandbox(&req.id, reason)
            .await
            .map_err(SandboxError::from)?;
        if !ip_address.is_empty() {
            register_sandbox_dns(&req.id, &ip_address);
        }
        Ok(arcbox_connect::v1::SandboxResumeResponse {
            ip_address,
            ..Default::default()
        })
    }

    /// Remove a sandbox.
    pub async fn remove(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::RemoveSandboxRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let _operation = self.operations.lock(&req.id).await;
        self.remove_request(req).await
    }

    pub(crate) async fn remove_request(
        &self,
        req: sandbox_v1::RemoveSandboxRequest,
    ) -> Result<(), SandboxError> {
        self.manager
            .remove_sandbox(&req.id, req.force)
            .await
            .map_err(SandboxError::from)?;
        deregister_sandbox_dns(&req.id);
        self.clear_stale_completed_create(&req.id);
        Ok(())
    }

    /// Inspect a sandbox.
    pub fn inspect(&self, payload: &[u8]) -> Result<sandbox_v1::SandboxInfo, SandboxError> {
        let req = sandbox_v1::InspectSandboxRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let info = self
            .manager
            .inspect_sandbox(&req.id)
            .map_err(SandboxError::from)?;
        Ok(convert::info_to_proto(info))
    }

    /// List sandboxes (id-ordered, paginated).
    pub fn list(&self, payload: &[u8]) -> Result<sandbox_v1::ListSandboxesResponse, SandboxError> {
        let req = sandbox_v1::ListSandboxesRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let state_filter = convert::state_filter(req.state.as_known().unwrap_or_default());
        let labels: std::collections::HashMap<String, String> = req.labels.into_iter().collect();
        let summaries = self
            .manager
            .list_sandboxes(state_filter, &labels)
            .map_err(SandboxError::from)?;
        let (page, next_page_token) =
            convert::paginate(summaries, |s| &s.id, req.page_size, &req.page_token);
        Ok(sandbox_v1::ListSandboxesResponse {
            sandboxes: page.into_iter().map(convert::summary_to_proto).collect(),
            next_page_token,
            ..Default::default()
        })
    }

    /// Return the active generation's network identity (external pool IP,
    /// cleanup token, and addressing mode).
    pub(crate) fn sandbox_network_identity(
        &self,
        sandbox_id: &str,
    ) -> Result<arcbox_vm::SandboxNetworkIdentity, SandboxError> {
        self.manager
            .sandbox_network_identity(sandbox_id)
            .map_err(SandboxError::from)
    }

    pub(crate) async fn wait_startup_cleanup_complete(&self) {
        self.manager.wait_startup_cleanup_complete().await;
    }

    /// Return the durable cleanup ticket for a terminal generation, if its
    /// sandbox had networking enabled.
    pub(crate) async fn pending_cleanup_ticket(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<arcbox_connect::v1::SandboxCleanupTicket>, SandboxError> {
        Ok(self
            .manager
            .pending_network_cleanups()
            .await
            .map_err(SandboxError::from)?
            .into_iter()
            .find_map(|(id, token)| {
                (id == sandbox_id).then_some(arcbox_connect::v1::SandboxCleanupTicket {
                    id,
                    token,
                    startup: false,
                    ..Default::default()
                })
            }))
    }

    /// Snapshot every durable cleanup generation after startup reconciliation.
    pub(crate) async fn pending_cleanup_tickets(
        &self,
    ) -> Result<Vec<arcbox_connect::v1::SandboxCleanupTicket>, SandboxError> {
        let mut tickets = self
            .manager
            .pending_network_cleanups()
            .await
            .map_err(SandboxError::from)?
            .into_iter()
            .map(|(id, token)| arcbox_connect::v1::SandboxCleanupTicket {
                id,
                token,
                startup: false,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        if let Some(token) = self
            .manager
            .startup_cleanup_token()
            .await
            .map_err(SandboxError::from)?
        {
            tickets.push(arcbox_connect::v1::SandboxCleanupTicket {
                id: STARTUP_CLEANUP_ID.into(),
                token,
                startup: true,
                ..Default::default()
            });
        }
        Ok(tickets)
    }

    /// Validate one exact cleanup generation before host-side deletion.
    pub(crate) async fn prepare_cleanup(
        &self,
        ticket: &arcbox_connect::v1::SandboxCleanupTicket,
    ) -> Result<std::net::Ipv4Addr, SandboxError> {
        if ticket.startup {
            if ticket.id != STARTUP_CLEANUP_ID {
                return Err(SandboxError::Decode(
                    "invalid sandbox startup cleanup ticket".into(),
                ));
            }
            self.manager
                .validate_startup_cleanup(&ticket.token)
                .await
                .map_err(SandboxError::from)?;
            return Ok(std::net::Ipv4Addr::UNSPECIFIED);
        }
        self.manager
            .validate_network_cleanup(&ticket.id, &ticket.token)
            .await
            .map(|allocation| allocation.ip_address)
            .map_err(SandboxError::from)
    }

    /// Revalidate and recycle one exact generation after guest DNAT cleanup.
    pub(crate) async fn finalize_cleanup(
        &self,
        ticket: &arcbox_connect::v1::SandboxCleanupTicket,
    ) -> Result<(), SandboxError> {
        if ticket.startup {
            if ticket.id != STARTUP_CLEANUP_ID {
                return Err(SandboxError::Decode(
                    "invalid sandbox startup cleanup ticket".into(),
                ));
            }
            return self
                .manager
                .finalize_startup_cleanup(&ticket.token)
                .await
                .map_err(SandboxError::from);
        }
        self.manager
            .finalize_network_cleanup(&ticket.id, &ticket.token)
            .await
            .map_err(SandboxError::from)?;
        deregister_sandbox_dns(&ticket.id);
        Ok(())
    }

    pub(crate) fn clear_stale_completed_create(&self, id: &str) {
        self.creates.clear_completed_if(id, || {
            completed_create_is_stale(
                self.manager
                    .inspect_sandbox(&id.to_owned())
                    .map(|info| info.state),
            )
        });
    }
}

fn completed_create_is_stale(state: Result<SandboxState, VmmError>) -> bool {
    match state {
        Ok(SandboxState::Stopped | SandboxState::Failed) | Err(VmmError::NotFound(_)) => true,
        // A paused sandbox is logically alive: the same-id create replay
        // must keep answering until it is actually removed.
        Ok(
            SandboxState::Starting
            | SandboxState::Ready
            | SandboxState::Running
            | SandboxState::Stopping
            | SandboxState::Pausing
            | SandboxState::Paused,
        )
        | Err(_) => false,
    }
}

/// Register a sandbox in the guest DNS server registry.
fn register_sandbox_dns(id: &str, ip: &str) {
    let Ok(ipv4) = ip.parse::<std::net::Ipv4Addr>() else {
        tracing::warn!(id, ip, "invalid sandbox IP for DNS registration");
        return;
    };
    let registry = crate::dns_server::sandbox_registry();
    if let Ok(mut map) = registry.write() {
        map.insert(id.to_lowercase(), ipv4);
    }
}

/// Deregister a sandbox from the guest DNS server registry.
fn deregister_sandbox_dns(id: &str) {
    let registry = crate::dns_server::sandbox_registry();
    if let Ok(mut map) = registry.write() {
        map.remove(&id.to_lowercase());
    }
}

/// Convert a `CreateSandboxRequest` proto to a [`SandboxSpec`].
fn proto_to_spec(req: sandbox_v1::CreateSandboxRequest) -> SandboxSpec {
    // An unset `limits`/`network` field derefs to the default instance, and
    // an unknown wire value falls back to UNSPECIFIED — the proto3 defaults.
    let (vcpus, memory_mib) = (req.limits.vcpus, req.limits.memory_mib);
    let mode = match req.network.mode.as_known().unwrap_or_default() {
        sandbox_v1::NetworkMode::None => "none",
        // UNSPECIFIED defaults to a networked sandbox.
        sandbox_v1::NetworkMode::Enabled | sandbox_v1::NetworkMode::Unspecified => "tap",
    };
    SandboxSpec {
        id: if req.id.is_empty() {
            None
        } else {
            Some(req.id)
        },
        labels: req.labels.into_iter().collect(),
        // Boot recipe fields are resolved from the template, never from the
        // request (CORE-54); the manager fills kernel/boot_args defaults.
        kernel: String::new(),
        rootfs: String::new(),
        boot_args: String::new(),
        vcpus,
        memory_mib,
        cmd: req.cmd,
        env: req.env.into_iter().collect(),
        working_dir: req.working_dir,
        user: req.user,
        mounts: req
            .mounts
            .into_iter()
            .map(|m| SandboxMountSpec {
                source: m.source,
                target: m.target,
                readonly: m.readonly,
            })
            .collect(),
        network: SandboxNetworkSpec { mode: mode.into() },
        ttl_seconds: req.ttl_seconds,
        ssh_public_key: req.ssh_public_key,
        idle_timeout_seconds: req.idle_timeout_seconds,
        on_idle: idle_action_to_spec(req.on_idle.as_known().unwrap_or_default()),
    }
}

/// Map the wire idle policy onto the manager's; `UNSPECIFIED` (and unknown
/// future values) resolve to the daemon default, KILL.
fn idle_action_to_spec(action: sandbox_v1::IdleAction) -> arcbox_vm::IdleAction {
    match action {
        sandbox_v1::IdleAction::Pause => arcbox_vm::IdleAction::Pause,
        sandbox_v1::IdleAction::Kill | sandbox_v1::IdleAction::Unspecified => {
            arcbox_vm::IdleAction::Kill
        }
    }
}

fn create_uses_network(request: &sandbox_v1::CreateSandboxRequest) -> bool {
    !matches!(
        request.network.mode.as_known().unwrap_or_default(),
        sandbox_v1::NetworkMode::None
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_networked_create_waits_for_startup_cleanup() {
        assert!(create_uses_network(
            &sandbox_v1::CreateSandboxRequest::default()
        ));
        assert!(!create_uses_network(&sandbox_v1::CreateSandboxRequest {
            network: sandbox_v1::NetworkSpec {
                mode: sandbox_v1::NetworkMode::None.into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }));
    }

    #[test]
    fn completed_create_is_stale_only_after_terminal_or_removed_state() {
        for state in [
            SandboxState::Starting,
            SandboxState::Ready,
            SandboxState::Running,
            SandboxState::Stopping,
        ] {
            assert!(!completed_create_is_stale(Ok(state)));
        }
        for state in [SandboxState::Stopped, SandboxState::Failed] {
            assert!(completed_create_is_stale(Ok(state)));
        }
        assert!(completed_create_is_stale(Err(VmmError::NotFound(
            "removed".into()
        ))));
        assert!(!completed_create_is_stale(Err(VmmError::Config(
            "inspect failed".into()
        ))));
    }
}
