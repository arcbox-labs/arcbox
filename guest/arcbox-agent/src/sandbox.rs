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

use std::sync::Arc;

use arcbox_connect::sandbox_v1;
use arcbox_vm::{SandboxManager, SandboxMountSpec, SandboxNetworkSpec, SandboxSpec, VmmConfig};
use buffa::Message;

use crate::error::SandboxError;

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
    /// Default rootfs image path; auto-built on first use when missing.
    default_rootfs: String,
}

impl SandboxService {
    /// Create a new [`SandboxService`] from the given config.
    pub fn new(config: VmmConfig) -> anyhow::Result<Self> {
        let default_rootfs = config.defaults.rootfs.clone();
        let manager = SandboxManager::new(config).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Self {
            manager: Arc::new(manager),
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
        let req = sandbox_v1::CreateSandboxRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let template = template::Template::parse(&req.template)?;
        let mut spec = proto_to_spec(req);

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
            .create_sandbox(spec)
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
        self.manager
            .stop_sandbox(&req.id, req.timeout_seconds)
            .await
            .map_err(SandboxError::from)?;
        deregister_sandbox_dns(&req.id);
        Ok(())
    }

    /// Remove a sandbox.
    pub async fn remove(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::RemoveSandboxRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        self.manager
            .remove_sandbox(&req.id, req.force)
            .await
            .map_err(SandboxError::from)?;
        deregister_sandbox_dns(&req.id);
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
        let summaries = self.manager.list_sandboxes(state_filter, &labels);
        let (page, next_page_token) =
            convert::paginate(summaries, |s| &s.id, req.page_size, &req.page_token);
        Ok(sandbox_v1::ListSandboxesResponse {
            sandboxes: page.into_iter().map(convert::summary_to_proto).collect(),
            next_page_token,
            ..Default::default()
        })
    }

    /// Return the IP address of a sandbox, or an error if not found.
    pub fn sandbox_ip(&self, sandbox_id: &str) -> Result<std::net::Ipv4Addr, SandboxError> {
        let info = self
            .manager
            .inspect_sandbox(&sandbox_id.to_string())
            .map_err(SandboxError::from)?;
        info.network
            .and_then(|n| n.ip_address.parse().ok())
            .ok_or_else(|| {
                SandboxError::Internal(format!("sandbox '{sandbox_id}' has no network allocation"))
            })
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
    }
}
