//! Sandbox service for the guest agent.
//!
//! Wraps [`ComputerManager`] from `arcbox-computer-runtime` and translates
//! between the `sandbox_v1` protobuf types (from `arcbox-connect`) and the
//! native Rust types used by `arcbox-computer-runtime`. Lifecycle CRUD
//! lives here; executions, events, file I/O, and snapshots live in the
//! submodules.

mod convert;
mod events;
mod execution;
mod files;
mod snapshots;
mod template;
mod templates;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use arcbox_computer_runtime::agent::VmProtoAgentFactory;
use arcbox_computer_runtime::{
    ComputerError, ComputerManager, ComputerMountSpec, ComputerNetworkSpec, ComputerSpec,
    ComputerState, NodeEnvironment, RootfsBuilder, RootfsPaths,
};
use arcbox_connect::sandbox_v1;
use arcbox_fc_driver::{FcDriver, FcDriverConfig};
use arcbox_snapshot::snapshot_cow::{BlockTools, BusyboxBlockTools, CowManager, CowOptions};
use arcbox_tap_net::{IptablesLegacy, TapNetwork};
use buffa::Message;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::config::GuestConfig;
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

/// Thin wrapper around [`ComputerManager`] for use in the agent's RPC layer.
pub struct SandboxService {
    manager: Arc<ComputerManager>,
    creates: Arc<CreateRegistry>,
    operations: SandboxOperationLocks,
    /// Template names with a Build in flight; a second Build on a busy name
    /// errors instead of silently queueing behind a long conversion
    /// (CORE-107). See `templates.rs`.
    template_builds: Mutex<std::collections::HashSet<String>>,
    /// Default rootfs image path; auto-built on first use when missing.
    default_rootfs: String,
    /// Builds template rootfs images and the default image, from the guest's
    /// staged `vm-agent` and busybox into the writable data volume.
    rootfs: RootfsBuilder,
}

/// The `vm-agent` binary as the host daemon stages it (host `~/.arcbox/bin`
/// via VirtioFS).
const VM_AGENT_BIN: &str = "/arcbox/bin/vm-agent";

/// Static busybox shipped in the guest EROFS rootfs.
const GUEST_BUSYBOX: &str = "/bin/busybox";

/// Directory for generated rootfs images (btrfs data volume, writable).
const ROOTFS_CACHE_DIR: &str = "/var/lib/arcbox/sandbox";

/// The System VM's loop-device and block-size tooling: the busybox its
/// EROFS rootfs ships, at [`BusyboxBlockTools::DEFAULT_PATH`].
///
/// One value per composition, shared by the copy-on-write rootfs manager in
/// [`node_environment`] and by [`rootfs_builder`], so both mount through the
/// same busybox.
pub fn block_tools() -> Arc<dyn BlockTools> {
    Arc::new(BusyboxBlockTools::default())
}

/// The rootfs builder over the System VM's layout. Standalone so the
/// startup sweep of half-written images can run whether or not the sandbox
/// service comes up.
pub fn rootfs_builder(block_tools: Arc<dyn BlockTools>) -> RootfsBuilder {
    RootfsBuilder::new(
        RootfsPaths {
            vm_agent: VM_AGENT_BIN.into(),
            cache_dir: ROOTFS_CACHE_DIR.into(),
            busybox: GUEST_BUSYBOX.into(),
        },
        block_tools,
    )
}

/// The environment-specific components the sandbox stack runs on inside
/// the System VM. This is where they are built: `ComputerManager::new`
/// builds none of them, so the choice of VMM is made here.
///
/// Four components, out of the two halves of `config`:
///
/// - the Firecracker driver over the adapter half's binaries and
///   process-level flags ([`FcDriverConfig`]);
/// - the Linux TAP network over the runtime half's `[network]` pool, with
///   its quarantine ledger under the data dir, the adapter half's
///   datapath, and iptables-legacy for the netfilter rendering of the
///   invariant translation — which is the `Filter` datapath itself and
///   what the `Ebpf` one falls back to;
/// - the `arcbox-vm-proto` guest-agent client, which every Firecracker
///   sandbox speaks;
/// - the copy-on-write rootfs manager over the data dir, `block_tools`, and
///   the runtime half's `dmsetup` search list.
pub fn node_environment(
    config: &GuestConfig,
    block_tools: Arc<dyn BlockTools>,
) -> anyhow::Result<NodeEnvironment> {
    let runtime = &config.runtime;
    let data_dir = std::path::Path::new(&runtime.firecracker.data_dir);
    let network = TapNetwork::with_quarantine_dir(
        &runtime.network.cidr,
        &runtime.network.gateway,
        runtime.network.dns.clone(),
        data_dir.join("sandbox-network-quarantine"),
        config.adapters.sandbox_datapath,
        Arc::new(IptablesLegacy::default()),
    )?;
    let mut cow_options = CowOptions::new(data_dir);
    cow_options.block_tools = block_tools;
    if let Some(candidates) = &runtime.firecracker.dmsetup_candidates {
        cow_options.dmsetup_candidates = candidates.iter().map(std::path::PathBuf::from).collect();
    }
    Ok(NodeEnvironment {
        driver: Arc::new(FcDriver::new(FcDriverConfig::from(&config.adapters))),
        network: Arc::new(network),
        agent: Arc::new(VmProtoAgentFactory::default()),
        cow_manager: Arc::new(CowManager::new(cow_options)?),
    })
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
        match self.manager.inspect_computer(&id.to_owned()) {
            Ok(info) => matches!(info.state, ComputerState::Stopped | ComputerState::Failed),
            Err(ComputerError::NotFound(_)) => true,
            Err(_) => false,
        }
    }

    /// Create a new [`SandboxService`] from the given config.
    pub fn new(config: GuestConfig) -> anyhow::Result<Self> {
        let default_rootfs = config.runtime.defaults.rootfs.clone();
        // The rootfs builder shares the environment's block tooling so both
        // mount through the same busybox.
        let block_tools = block_tools();
        let rootfs = rootfs_builder(Arc::clone(&block_tools));
        let environment = node_environment(&config, block_tools)?;
        // `into_shared` starts the lifecycle monitor driving the idle/TTL
        // expiry timers (CORE-21/60).
        let manager = ComputerManager::new(config.runtime, environment)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .into_shared();
        let creates = Arc::new(CreateRegistry::default());
        Ok(Self {
            manager,
            creates,
            operations: SandboxOperationLocks::default(),
            template_builds: Mutex::new(std::collections::HashSet::new()),
            default_rootfs,
            rootfs,
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
        let mut request = sandbox_v1::CreateSandboxRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        if create_uses_network(&request) {
            self.manager.wait_startup_cleanup_complete().await;
        }
        // Catalog resolution runs BEFORE both idempotency layers: the pinned
        // canonical ref (`name:version@digest`) is substituted into the
        // request itself, so the durable create key AND the in-process
        // registry (which compares whole requests) both diverge on a retry
        // after a Publish changed what the reference means — instead of
        // silently replaying the old content. Template defaults are folded
        // in here too, so the key hashes the effective workload and the
        // `no_default_*` flags need no key-domain change.
        let source = self.resolve_template_source(&mut request)?;
        let _operation = self.operations.lock(&request.id).await;
        let create_key = crate::create_key::create_key(&request);
        if request.id.is_empty() {
            return self.create_once(request, source, &create_key).await;
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
                    let response = self.create_once(request, source, &create_key).await?;
                    slot.commit(&response);
                    return Ok(response);
                }
                CreateReserve::AwaitPending(mut done) => {
                    let _ = done.changed().await;
                }
            }
        }
    }

    /// Classify `request.template` and, for catalog references, pin and
    /// default-merge the request in place (see `create` for why this happens
    /// before the idempotency layers).
    fn resolve_template_source(
        &self,
        request: &mut sandbox_v1::CreateSandboxRequest,
    ) -> Result<templates::TemplateSource, SandboxError> {
        match template::Template::parse(&request.template) {
            Ok(template::Template::Default) => return Ok(templates::TemplateSource::Default),
            Ok(template::Template::DockerImage(image)) => {
                return Ok(templates::TemplateSource::DockerImage(image));
            }
            // Not one of the two local forms — a catalog-shaped reference,
            // whose grammar and existence the catalog itself decides.
            Err(_) => {}
        }
        let resolved = self
            .manager
            .get_template(request.template.trim())
            .map_err(SandboxError::from)?;
        templates::validate_template_overrides(request)?;
        request.template = resolved.canonical_ref();
        templates::merge_template_defaults(request, &resolved.entry.defaults);
        Ok(templates::TemplateSource::Catalog(resolved))
    }

    async fn create_once(
        &self,
        request: sandbox_v1::CreateSandboxRequest,
        source: templates::TemplateSource,
        create_key: &str,
    ) -> Result<sandbox_v1::CreateSandboxResponse, SandboxError> {
        if !request.id.is_empty()
            && let Some((id, ip_address)) = self
                .manager
                .replay_computer_create(&request.id, create_key)
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

        spec.rootfs = self.resolve_template(&source).await?;
        if let templates::TemplateSource::Catalog(resolved) = &source {
            // The template's pre-warmed snapshot rides the spec so the
            // manager can restore instead of cold-booting when eligible.
            spec.template_warm =
                resolved
                    .entry
                    .warm
                    .as_ref()
                    .map(|warm| arcbox_computer_runtime::TemplateWarmRef {
                        snapshot_id: warm.snapshot_id.clone(),
                        vcpus: warm.vcpus,
                        memory_mib: warm.memory_mib,
                    });
            spec.ready_probe = resolved.entry.defaults.ready_probe.clone();
        }

        let (id, ip_address) = self
            .manager
            .create_computer_keyed(spec, create_key)
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

    /// Resolve a template source to the guest path of a bootable ext4 rootfs.
    async fn resolve_template(
        &self,
        source: &templates::TemplateSource,
    ) -> Result<String, SandboxError> {
        match source {
            templates::TemplateSource::Default => {
                // Built on first use, and rebuilt when the staged vm-agent is
                // newer than the cached image.
                self.rootfs
                    .ensure_default_rootfs(&self.default_rootfs)
                    .await
                    .map_err(|e| SandboxError::Internal(format!("default template: {e}")))?;
                Ok(self.default_rootfs.clone())
            }
            templates::TemplateSource::DockerImage(image) => {
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
                self.rootfs
                    .convert_layer_to_rootfs(&layout, &pinned)
                    .await
                    .map_err(|e| SandboxError::Internal(format!("template {image}: {e}")))
            }
            templates::TemplateSource::Catalog(resolved) => {
                let path = &resolved.entry.rootfs_path;
                if !std::path::Path::new(path).is_file() {
                    // Distinguish the caller-visible race — a concurrent
                    // Delete unpinned the rootfs and a build's sweep
                    // reclaimed it — from genuine pin corruption. Neither is
                    // a rebuild trigger.
                    return Err(match self.manager.get_template(&resolved.name) {
                        Err(ComputerError::TemplateNotFound(_)) => {
                            SandboxError::from(ComputerError::TemplateNotFound(format!(
                                "{} (deleted while this create was resolving it)",
                                resolved.name
                            )))
                        }
                        _ => SandboxError::Internal(format!(
                            "template {} rootfs {path} is missing; the catalog pin failed",
                            resolved.name
                        )),
                    });
                }
                Ok(path.clone())
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
            .stop_computer(&req.id, req.timeout_seconds)
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
            .pause_computer(&req.id)
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
        let reason = if req.reason == arcbox_computer_runtime::pause_reason::AUTO_RESUME {
            arcbox_computer_runtime::pause_reason::AUTO_RESUME
        } else {
            arcbox_computer_runtime::pause_reason::RESUME
        };
        let ip_address = self
            .manager
            .resume_computer(&req.id, reason)
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

    /// Replace a sandbox's lifecycle deadlines (CORE-60): TTL re-armed from
    /// now, idle timeout/policy replaced. Absent fields are unchanged; an
    /// explicit `UNSPECIFIED` policy restores the daemon default (KILL).
    pub(crate) async fn set_lifecycle_request(
        &self,
        req: sandbox_v1::SetLifecycleRequest,
    ) -> Result<(), SandboxError> {
        let update = arcbox_computer_runtime::LifecycleUpdate {
            ttl_seconds: req.ttl_seconds,
            idle_timeout_seconds: req.idle_timeout_seconds,
            on_idle: req
                .on_idle
                .map(|value| idle_action_to_spec(value.as_known().unwrap_or_default())),
        };
        self.manager
            .set_computer_lifecycle(&req.id, update)
            .await
            .map_err(SandboxError::from)
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
            .remove_computer(&req.id, req.force)
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
            .inspect_computer(&req.id)
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
            .list_computers(state_filter, &labels)
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
    ) -> Result<arcbox_computer_runtime::ComputerNetworkIdentity, SandboxError> {
        self.manager
            .computer_network_identity(sandbox_id)
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
    ///
    /// The address comes back as v4 because that is what the rules it
    /// gates are written in: the System VM's DNAT and fwmark rules are
    /// iptables, not ip6tables. A lease from another dataplane would be
    /// one this cleanup path could not express.
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
        let lease = self
            .manager
            .validate_network_cleanup(&ticket.id, &ticket.token)
            .await
            .map_err(SandboxError::from)?;
        match lease.ip {
            std::net::IpAddr::V4(ip) => Ok(ip),
            std::net::IpAddr::V6(ip) => Err(SandboxError::Internal(format!(
                "sandbox {} holds {ip}; host cleanup here is IPv4-only",
                ticket.id
            ))),
        }
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
                    .inspect_computer(&id.to_owned())
                    .map(|info| info.state),
            )
        });
    }
}

fn completed_create_is_stale(state: Result<ComputerState, ComputerError>) -> bool {
    match state {
        Ok(ComputerState::Stopped | ComputerState::Failed) | Err(ComputerError::NotFound(_)) => {
            true
        }
        // A paused sandbox is logically alive: the same-id create replay
        // must keep answering until it is actually removed.
        Ok(
            ComputerState::Starting
            | ComputerState::Ready
            | ComputerState::Running
            | ComputerState::Stopping
            | ComputerState::Pausing
            | ComputerState::Paused,
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

/// Convert a `CreateSandboxRequest` proto to a [`ComputerSpec`].
fn proto_to_spec(req: sandbox_v1::CreateSandboxRequest) -> ComputerSpec {
    // An unset `limits`/`network` field derefs to the default instance, and
    // an unknown wire value falls back to UNSPECIFIED — the proto3 defaults.
    let (vcpus, memory_mib) = (req.limits.vcpus, req.limits.memory_mib);
    let mode = match req.network.mode.as_known().unwrap_or_default() {
        sandbox_v1::NetworkMode::None => "none",
        // UNSPECIFIED defaults to a networked sandbox.
        sandbox_v1::NetworkMode::Enabled | sandbox_v1::NetworkMode::Unspecified => "tap",
    };
    ComputerSpec {
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
            .map(|m| ComputerMountSpec {
                source: m.source,
                target: m.target,
                readonly: m.readonly,
            })
            .collect(),
        network: ComputerNetworkSpec { mode: mode.into() },
        ttl_seconds: req.ttl_seconds,
        ssh_public_key: req.ssh_public_key,
        idle_timeout_seconds: req.idle_timeout_seconds,
        on_idle: idle_action_to_spec(req.on_idle.as_known().unwrap_or_default()),
        // Filled by create_once from the resolved catalog entry; a request
        // never names a snapshot or a probe directly (CORE-54).
        template_warm: None,
        ready_probe: None,
    }
}

/// Map the wire idle policy onto the manager's; `UNSPECIFIED` (and unknown
/// future values) resolve to the daemon default, KILL.
fn idle_action_to_spec(action: sandbox_v1::IdleAction) -> arcbox_computer_runtime::IdleAction {
    match action {
        sandbox_v1::IdleAction::Pause => arcbox_computer_runtime::IdleAction::Pause,
        sandbox_v1::IdleAction::Kill | sandbox_v1::IdleAction::Unspecified => {
            arcbox_computer_runtime::IdleAction::Kill
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
            ComputerState::Starting,
            ComputerState::Ready,
            ComputerState::Running,
            ComputerState::Stopping,
        ] {
            assert!(!completed_create_is_stale(Ok(state)));
        }
        for state in [ComputerState::Stopped, ComputerState::Failed] {
            assert!(completed_create_is_stale(Ok(state)));
        }
        assert!(completed_create_is_stale(Err(ComputerError::NotFound(
            "removed".into()
        ))));
        assert!(!completed_create_is_stale(Err(ComputerError::Config(
            "inspect failed".into()
        ))));
    }
}
