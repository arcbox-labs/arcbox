//! One computer's runtime state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arcbox_vm_driver::net::{NetworkIdentity, NetworkLease};
use arcbox_vm_driver::{PreparedVm, VmHandle};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::agent::ExitStatus;
use crate::sandbox::{SandboxId, SandboxSpec, SandboxState};
use crate::snapshot_cow::CowHandle;

/// A computer's runtime state as its actor and its sub-tasks share it.
pub type Runtime = Arc<Mutex<ComputerRuntime>>;

/// One computer's runtime state: the resources it holds and the timestamps
/// its readers report, shared between its actor and the sub-tasks the actor
/// spawns.
///
/// Reachable only from the actor that owns the computer and from the flows it
/// spawns, never from a caller: a verb reaches the computer through its
/// mailbox and a read through the `watch` snapshot the actor projects from
/// here. The map lock, the per-computer mutex a caller had to take, and the
/// generation re-checks every site needed after taking it are all gone.
///
/// The `Mutex` around it is not a serialization mechanism — the mailbox is
/// that. It is what lets a boot hand a `CowHandle` over mid-flight, which is
/// the one thing an abort must not be able to strand.
pub struct ComputerRuntime {
    /// Unique identifier.
    pub id: SandboxId,
    /// Durable lifecycle record generation.
    pub(crate) record_generation: Option<Uuid>,
    /// User-supplied labels.
    pub labels: HashMap<String, String>,
    /// Original creation spec.
    pub spec: SandboxSpec,
    /// The public lifecycle state, mirrored here from the actor's machine on
    /// every transition. A sub-task reads it to see a teardown that started
    /// while it was running — the cooperative half of preemption, which an
    /// abort alone cannot cover before the resource handoff has landed.
    pub state: SandboxState,
    /// The VMM process this sandbox's VM runs on, as the driver prepared
    /// it (`arcbox_vm_driver::PreparedVm`): pid and API socket known,
    /// shared with the boot task, taken by cleanup to kill and reap it.
    pub prepared: Option<Arc<dyn PreparedVm>>,
    /// The running VM behind the driver port (`arcbox_vm_driver::VmHandle`),
    /// present once a boot or restore succeeded; shared with the tasks that
    /// checkpoint or shut it down.
    pub handle: Option<Arc<dyn VmHandle>>,
    /// The address the guest network reserved for this sandbox, absent
    /// when the sandbox is networkless or its lease has been handed back.
    /// The NIC that activating it produced is not kept: the VM was booted
    /// with it and nothing here reads it again.
    pub network: Option<NetworkLease>,
    /// What the guest was told over that interface, as the boot, restore or
    /// resume that produced [`Self::handle`] read it. Kept rather than
    /// re-derived: the mode a lease is read under is not recoverable from
    /// the instance alone (a caller-supplied `ip=` leaves `net_invariant`
    /// false on a guest whose interface was activated invariant), so the
    /// agent the exec and file paths build would otherwise describe the
    /// guest differently from the one its boot built. Cleared with the
    /// handle.
    pub(crate) net_identity: Option<NetworkIdentity>,
    /// Directory holding the VM's runtime files (socket, logs, metrics).
    pub vm_dir: PathBuf,
    /// When the sandbox record was created.
    pub created_at: DateTime<Utc>,
    /// When the sandbox first became ready.
    pub ready_at: Option<DateTime<Utc>>,
    /// When the last workload exited.
    pub last_exited_at: Option<DateTime<Utc>>,
    /// How the last workload terminated.
    pub last_exit_status: Option<ExitStatus>,
    /// Human-readable error (only set when state == `Failed`).
    pub error: Option<String>,
    /// dm-snapshot CoW handle (present when snapshot-based rootfs is active).
    pub cow_handle: Option<CowHandle>,
    /// When this sandbox adopted a pre-warmed restore slot's resources
    /// (CORE-78), the slot id (`pool-<uuid>`) its VM and its dm/CoW names
    /// are keyed by. `None` for resources created under the sandbox's own
    /// id.
    ///
    /// Cleared by pause: releasing a paused sandbox discards the slot's VM
    /// (which takes the area its files were staged into) and renames its
    /// retained overlay to the sandbox-id path, so a resumed sandbox owns
    /// everything under its own id again.
    pub(crate) pool_slot_id: Option<String>,
    /// Whether this guest runs the fixed invariant network identity
    /// (CORE-81). Set by the create path when the boot bakes the invariant
    /// `ip=` parameter, and inherited from [`crate::snapshot::SnapshotMeta`]
    /// on restore so chained checkpoints record the guest's actual addressing.
    pub(crate) net_invariant: bool,
    /// When the sandbox reached `Paused` (None otherwise).
    pub paused_at: Option<DateTime<Utc>>,
    /// Catalog id of the internal pause checkpoint (state == `Paused` only).
    pub pause_snapshot_id: Option<String>,
    /// When the hard maximum lifetime fires (None = no limit). Seeded from
    /// `spec.ttl_seconds` at creation; replaced from-now by `SetLifecycle`
    /// (CORE-60).
    pub ttl_deadline: Option<DateTime<Utc>>,
}

impl ComputerRuntime {
    pub(crate) fn new(
        id: SandboxId,
        spec: SandboxSpec,
        network: Option<NetworkLease>,
        vm_dir: PathBuf,
    ) -> Self {
        Self::new_inner(id, spec, network, vm_dir, None)
    }

    pub(crate) fn new_with_generation(
        id: SandboxId,
        spec: SandboxSpec,
        network: Option<NetworkLease>,
        vm_dir: PathBuf,
        generation: Uuid,
    ) -> Self {
        Self::new_inner(id, spec, network, vm_dir, Some(generation))
    }

    fn new_inner(
        id: SandboxId,
        spec: SandboxSpec,
        network: Option<NetworkLease>,
        vm_dir: PathBuf,
        record_generation: Option<Uuid>,
    ) -> Self {
        Self {
            id,
            record_generation,
            labels: spec.labels.clone(),
            spec,
            state: SandboxState::Starting,
            prepared: None,
            handle: None,
            net_identity: None,
            network,
            vm_dir,
            created_at: Utc::now(),
            ready_at: None,
            last_exited_at: None,
            last_exit_status: None,
            error: None,
            cow_handle: None,
            pool_slot_id: None,
            net_invariant: false,
            paused_at: None,
            pause_snapshot_id: None,
            ttl_deadline: None,
        }
    }
}
