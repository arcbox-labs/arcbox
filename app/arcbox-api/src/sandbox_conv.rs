//! Proto ↔ `arcbox-vm` type conversions for the sandbox service (Linux only).

use arcbox_protocol::sandbox_v1::{
    self, CheckpointResponse, CreateSandboxRequest, ListSandboxesRequest, ListSandboxesResponse,
    SandboxInfo, SandboxNetwork, SandboxSummary as ProtoSandboxSummary,
    SnapshotSummary as ProtoSnapshotSummary,
};
use arcbox_vm::{
    CheckpointInfo, RestoreSandboxSpec, SandboxMountSpec, SandboxNetworkSpec, SandboxSpec,
    SandboxSummary,
};

/// Converts a proto `CreateSandboxRequest` to an `arcbox-vm` `SandboxSpec`.
pub fn proto_to_sandbox_spec(req: CreateSandboxRequest) -> SandboxSpec {
    let network = req.network.map_or_else(SandboxNetworkSpec::default, |n| {
        SandboxNetworkSpec { mode: n.mode }
    });

    let limits = req.limits.as_ref();

    SandboxSpec {
        id: if req.id.is_empty() {
            None
        } else {
            Some(req.id)
        },
        labels: req.labels,
        kernel: req.kernel,
        rootfs: req.rootfs,
        boot_args: req.boot_args,
        vcpus: limits.map_or(0, |l| l.vcpus),
        memory_mib: limits.map_or(0, |l| l.memory_mib),
        image: req.image,
        cmd: req.cmd,
        env: req.env,
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
        network,
        ttl_seconds: req.ttl_seconds,
        ssh_public_key: req.ssh_public_key,
    }
}

/// Converts a proto `RestoreRequest` to an `arcbox-vm` `RestoreSandboxSpec`.
pub fn proto_to_restore_spec(req: sandbox_v1::RestoreRequest) -> RestoreSandboxSpec {
    RestoreSandboxSpec {
        id: if req.id.is_empty() {
            None
        } else {
            Some(req.id)
        },
        snapshot_id: req.snapshot_id,
        labels: req.labels,
        network_override: req.network_override,
        ttl_seconds: req.ttl_seconds,
    }
}

/// Converts an `arcbox-vm` `SandboxInfo` to a proto `SandboxInfo`.
pub fn sandbox_info_to_proto(info: arcbox_vm::SandboxInfo) -> SandboxInfo {
    let network = info.network.map_or_else(
        || SandboxNetwork {
            ip_address: String::new(),
            gateway: String::new(),
            tap_name: String::new(),
        },
        |n| SandboxNetwork {
            ip_address: n.ip_address,
            gateway: n.gateway,
            tap_name: n.tap_name,
        },
    );

    SandboxInfo {
        id: info.id,
        state: info.state.to_string(),
        labels: info.labels,
        limits: Some(sandbox_v1::ResourceLimits {
            vcpus: info.vcpus,
            memory_mib: info.memory_mib,
        }),
        network: Some(network),
        created_at: info.created_at.timestamp(),
        ready_at: info.ready_at.map_or(0, |t| t.timestamp()),
        last_exited_at: info.last_exited_at.map_or(0, |t| t.timestamp()),
        last_exit_code: info.last_exit_code.unwrap_or(0),
        error: info.error.unwrap_or_default(),
    }
}

/// Converts an `arcbox-vm` `SandboxSummary` to a proto `SandboxSummary`.
fn sandbox_summary_to_proto(s: SandboxSummary) -> ProtoSandboxSummary {
    ProtoSandboxSummary {
        id: s.id,
        state: s.state.to_string(),
        labels: s.labels,
        ip_address: s.ip_address,
        created_at: s.created_at.timestamp(),
    }
}

/// Converts sandbox list results to a proto response.
pub fn sandbox_list_to_proto(sandboxes: Vec<SandboxSummary>) -> ListSandboxesResponse {
    ListSandboxesResponse {
        sandboxes: sandboxes.into_iter().map(sandbox_summary_to_proto).collect(),
    }
}

/// Converts an `arcbox-vm` `CheckpointInfo` to a proto `CheckpointResponse`.
pub fn checkpoint_to_proto(info: CheckpointInfo) -> CheckpointResponse {
    CheckpointResponse {
        snapshot_id: info.snapshot_id,
        snapshot_dir: info.snapshot_dir,
        created_at: info.created_at,
    }
}

/// Converts an `arcbox-vm` `CheckpointSummary` to a proto `SnapshotSummary`.
pub fn checkpoint_summary_to_proto(s: arcbox_vm::CheckpointSummary) -> ProtoSnapshotSummary {
    ProtoSnapshotSummary {
        id: s.id,
        sandbox_id: s.sandbox_id,
        name: s.name,
        labels: s.labels,
        snapshot_dir: s.snapshot_dir,
        created_at: s.created_at,
    }
}
