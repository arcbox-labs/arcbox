//! The boot flow's sub-tasks: bringing the VM up, and the readiness gate
//! READY is withheld for.
//!
//! Moved here from `sandbox::boot` by R3 PR-F1b, unchanged: these are the
//! bodies `Effect::SpawnBoot` and `Effect::SpawnGate` name, and the actor
//! will run them through [`ComputerTasks`](super::ComputerTasks) once PR-F2
//! flips the manager. Until then `sandbox::boot::boot_sandbox` is still the
//! caller.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arcbox_fc_driver::jail::{
    chroot_root, stage_kernel_for_jailer, stage_rootfs_copy_for_jailer,
    stage_rootfs_device_for_jailer,
};
use arcbox_snapshot::SnapshotError;
use arcbox_vm_driver::{IsolationSpec, PreparedVm, VmDriver, VmHandle, VmId};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::agent::{ClockSync, GuestAgent, GuestAgentFactory, ReadyGate};
use crate::config::VmmConfig;
use crate::error::{Result, VmmError};
use crate::sandbox::boot::create_rootfs_symlink;
use crate::sandbox::spec::build_vm_spec;
use crate::sandbox::{self, NetworkAttachment, SandboxSpec, SandboxState};
use crate::snapshot_cow::{CowHandle, CowManager};

pub type BootOutput = (Arc<dyn VmHandle>, Box<dyn ReadyGate>);

/// How long the readiness gate waits for the guest agent to announce
/// itself before the boot is declared failed. Covers guest kernel boot plus
/// agent startup.
const AGENT_GATE_TIMEOUT: Duration = Duration::from_secs(35);

/// Cap on the non-gating cold-boot clock sync: `sync_clock`'s internal
/// connect loop can retry for up to 30 s, pointlessly long for an agent
/// that has already dialed out. Mirrors the restore path's cap.
const CLOCK_SYNC_TIMEOUT: Duration = Duration::from_secs(10);

pub struct BootFailure {
    pub error: VmmError,
    pub prepared: Option<Arc<dyn PreparedVm>>,
    pub cow_handle: Option<CowHandle>,
}

/// Wait for the guest agent to announce itself, then start its clock sync.
///
/// The wait is what `Effect::SpawnBoot` ends on: a boot is not "up" when the
/// VM starts, it is up when the agent answers.
pub async fn wait_for_agent(
    id: &str,
    handle: &Arc<dyn VmHandle>,
    net: Option<&NetworkAttachment>,
    mut ready_gate: Box<dyn ReadyGate>,
    agents: &dyn GuestAgentFactory,
) -> Result<Arc<dyn GuestAgent>> {
    // READY promises "accepting executions", but InstanceStart returns
    // while the guest kernel is still booting and the agent is not yet
    // serving. Under the vm-proto agent the gate is an event, not a
    // poll: once its exec and file listeners are up, vm-agent dials
    // the host back, and the accept on the listener do_boot pre-armed
    // IS the signal.
    //
    // Compat: an OLD vm-agent (no dial-out) under this host would sit
    // out the full gate timeout — but the template freshness keys
    // (the vm-agent binary among them) rebuild the default template
    // and re-inject it into docker templates automatically, so a
    // guest always carries the agent from the same build as its host.
    //
    // The agent client is built first: `connect` performs no I/O, and
    // a gate that observes at the agent level rather than the
    // transport's (`Readiness::Probe`) has nothing to wait on
    // without it.
    let gated = match agents.connect(Arc::clone(handle), net.map(|n| &n.identity)) {
        Ok(agent) => {
            match tokio::time::timeout(AGENT_GATE_TIMEOUT, ready_gate.wait(handle, &agent)).await {
                Ok(Ok(())) => Ok(agent),
                Ok(Err(error)) => Err(VmmError::Vsock(format!("agent readiness gate: {error}"))),
                Err(_) => Err(VmmError::Vsock(format!(
                    "agent readiness gate: the guest agent did not answer within {}s",
                    AGENT_GATE_TIMEOUT.as_secs()
                ))),
            }
        }
        Err(error) => Err(error),
    };
    // The observer is per-boot; the gate has consumed its one event.
    drop(ready_gate);
    let agent = gated?;

    // The guest clock still needs setting on cold boot (no RTC — the
    // guest wakes at the kernel default epoch), but it must not delay
    // readiness either: the agent is already accepting executions, so
    // a slow or retrying sync holding the Ready publication back
    // would recreate the latency this gate exists to remove. Fire it
    // detached; any failure is a warn, mirroring the restore path.
    // Belt-and-braces alongside vm-agent's ptp_kvm self-sync;
    // retires once ptp is proven in production.
    {
        let id = id.to_owned();
        let agent = Arc::clone(&agent);
        tokio::spawn(async move {
            match tokio::time::timeout(CLOCK_SYNC_TIMEOUT, agent.sync_clock()).await {
                Ok(Ok(ClockSync::Synced)) => {}
                Ok(Ok(ClockSync::AgentError(code))) => {
                    warn!(
                        sandbox_id = %id, code,
                        "agent could not set the clock; continuing with a possibly skewed clock"
                    );
                }
                Ok(Err(error)) => {
                    warn!(sandbox_id = %id, %error, "cold-boot clock sync failed; continuing");
                }
                Err(_) => {
                    warn!(sandbox_id = %id, "cold-boot clock sync timed out; continuing");
                }
            }
        });
    }

    Ok(agent)
}

/// Perform the actual boot: prepare the VMM through the driver, stage,
/// configure, start the VM.
///
/// The prepared VMM is transferred to its [`SandboxInstance`] immediately.
/// Cleanup is allowed to abort this task only after the paths/CoW phase has
/// finished and every live `CowHandle` has also been transferred.
///
/// **No `await` may sit between transferring the CoW handle and completing
/// the handoff signal** (see the comment at that site). The signal is what
/// tells a teardown it may abort this task; an await in between is a point
/// where an abort lands with the handle owned by neither side, which strands
/// a dm device, its loop device and its COW file with nothing left to name
/// them. The waiter is the actor's `abort_inflight` — today
/// `cleanup::cancel_and_join_boot` — and its bounded wait is the only reason
/// a Remove during a boot is safe at all. Re-stated here because moving code
/// is exactly when an invariant carried by a single comment gets lost.
///
/// [`SandboxInstance`]: crate::sandbox::SandboxInstance
#[allow(
    clippy::too_many_arguments,
    reason = "boot owns one exact sandbox generation and its handoff signal"
)]
pub async fn do_boot(
    id: &str,
    spec: &SandboxSpec,
    net: Option<&NetworkAttachment>,
    vm_dir: &Path,
    driver: &dyn VmDriver,
    agents: &dyn GuestAgentFactory,
    config: &VmmConfig,
    cow_manager: &CowManager,
    instances: &sandbox::InstanceMap,
    generation: Uuid,
    resource_handoff: tokio::sync::oneshot::Sender<()>,
) -> std::result::Result<BootOutput, BootFailure> {
    let mut resource_handoff = Some(resource_handoff);
    let fc_cfg = &config.firecracker;

    // Spawn the VMM ahead of the guest: the driver's prepared VM owns the
    // process, pre-creates whatever its spawn needs (log and metrics files
    // in direct mode, the jail's `run/`), and knows the pid to journal.
    let prepared: Result<(Arc<dyn PreparedVm>, IsolationSpec)> = async {
        let vm_id = VmId::new(id)?;
        let isolation = sandbox::isolation_spec(config)?;
        let prepared = sandbox::prepare_capability(driver)
            .prepare(&vm_id, &isolation, vm_dir)
            .await?;
        Ok((Arc::from(prepared), isolation))
    }
    .await;
    let (prepared, isolation) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            complete_resource_handoff(&mut resource_handoff);
            return Err(BootFailure {
                error,
                prepared: None,
                cow_handle: None,
            });
        }
    };

    let process_pid = sandbox::journaled_pid(&*prepared);
    let journal_error = sandbox::reconcile::SandboxStateRecord::new(
        id,
        process_pid,
        net.map(NetworkAttachment::journaled),
        None,
        config,
        None,
    )
    .and_then(|record| sandbox::reconcile::write_state_record(vm_dir, &record))
    .err();

    // Once the VMM is up, make it immediately owned by the instance. Cleanup
    // still waits for the paths/CoW phase before it may abort boot.
    let state = {
        let map = instances.read().unwrap();
        map.get(id).and_then(|instance| {
            let mut instance = instance.lock().unwrap();
            (instance.record_generation == Some(generation)).then(|| {
                instance.prepared = Some(Arc::clone(&prepared));
                instance.state
            })
        })
    };

    let Some(state) = state else {
        // Closing the channel without the explicit signal makes cleanup join
        // this task instead of aborting it, so the outer failure path can tear
        // down these unhanded resources.
        return Err(BootFailure {
            error: VmmError::WrongState {
                id: id.to_owned(),
                expected: "the current sandbox generation".into(),
                actual: "replaced or removed".into(),
            },
            prepared: Some(prepared),
            cow_handle: None,
        });
    };
    if matches!(state, SandboxState::Stopping | SandboxState::Stopped) {
        complete_resource_handoff(&mut resource_handoff);
        return Err(BootFailure {
            error: VmmError::WrongState {
                id: id.to_owned(),
                expected: "a sandbox still booting".into(),
                actual: state.to_string(),
            },
            prepared: None,
            cow_handle: None,
        });
    }
    if let Some(error) = journal_error {
        complete_resource_handoff(&mut resource_handoff);
        return Err(BootFailure {
            error,
            prepared: None,
            cow_handle: None,
        });
    }

    // Determine the kernel and rootfs paths.
    //
    // In jailer mode the files must exist inside the chroot: they are staged
    // there and named to the driver by their in-jail host path, which it
    // passes to the VMM chroot-relative. In direct mode the host-absolute
    // paths from the spec are used as-is.
    let mut cow_handle = None;
    let paths: Result<(PathBuf, PathBuf)> = async {
        if let Some(ref jc) = fc_cfg.jailer {
            // Jailer mode: stage kernel + rootfs into chroot.
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, id);

            // Kernel is always copied (small, ~16MB).
            let k = stage_kernel_for_jailer(&cr, &spec.kernel, jc.uid, jc.gid).await?;

            // Rootfs: try dm-snapshot + mknod, fall back to full copy.
            let r = match cow_manager.setup(id, &spec.rootfs).await {
                Ok(handle) => {
                    cow_handle = Some(handle);
                    let record = sandbox::reconcile::SandboxStateRecord::new(
                        id,
                        process_pid,
                        net.map(NetworkAttachment::journaled),
                        cow_handle.as_ref(),
                        config,
                        None,
                    )?;
                    sandbox::reconcile::write_state_record(vm_dir, &record)?;
                    match stage_rootfs_device_for_jailer(
                        &cr,
                        &cow_handle.as_ref().unwrap().dm_device,
                        jc.uid,
                        jc.gid,
                    )
                    .await
                    {
                        Ok(path) => path,
                        Err(e) => {
                            debug!(
                                sandbox_id = %id,
                                error = %e,
                                "mknod failed, falling back to rootfs copy"
                            );
                            cow_manager
                                .teardown_checked(cow_handle.as_ref().unwrap())
                                .await?;
                            cow_handle = None;
                            let record = sandbox::reconcile::SandboxStateRecord::new(
                                id,
                                process_pid,
                                net.map(NetworkAttachment::journaled),
                                None,
                                config,
                                None,
                            )?;
                            sandbox::reconcile::write_state_record(vm_dir, &record)?;
                            stage_rootfs_copy_for_jailer(&cr, &spec.rootfs, jc.uid, jc.gid).await?
                        }
                    }
                }
                Err(e) => {
                    if matches!(e, SnapshotError::Unavailable(_)) {
                        return Err(e.into());
                    }
                    debug!(
                        sandbox_id = %id,
                        error = %e,
                        "dm-snapshot unavailable, copying rootfs into chroot"
                    );
                    stage_rootfs_copy_for_jailer(&cr, &spec.rootfs, jc.uid, jc.gid).await?
                }
            };

            Ok((in_jail(&cr, &k), in_jail(&cr, &r)))
        } else {
            // Direct mode: try dm-snapshot CoW, fall back to using rootfs directly.
            // When CoW is active, create a stable `{vm_dir}/rootfs.link` symlink
            // pointing at the dm device.  Firecracker records the symlink path
            // (not the ephemeral dm device name) in the vmstate, so a restored
            // sandbox can recreate a new dm-snapshot and retarget the symlink
            // transparently.
            let rootfs = match cow_manager.setup(id, &spec.rootfs).await {
                Ok(handle) => {
                    cow_handle = Some(handle);
                    let record = sandbox::reconcile::SandboxStateRecord::new(
                        id,
                        process_pid,
                        net.map(NetworkAttachment::journaled),
                        cow_handle.as_ref(),
                        config,
                        None,
                    )?;
                    sandbox::reconcile::write_state_record(vm_dir, &record)?;
                    create_rootfs_symlink(vm_dir, &cow_handle.as_ref().unwrap().dm_device)?
                }
                Err(e) => {
                    if matches!(e, SnapshotError::Unavailable(_)) {
                        return Err(e.into());
                    }
                    debug!(
                        sandbox_id = %id,
                        error = %e,
                        "dm-snapshot unavailable, using rootfs directly"
                    );
                    spec.rootfs.clone()
                }
            };
            Ok((PathBuf::from(&spec.kernel), PathBuf::from(rootfs)))
        }
    }
    .await;

    // No await may occur between transferring a successful CoW handle and
    // completing this signal. Once signalled, Remove is allowed to abort us.
    let state = {
        let map = instances.read().unwrap();
        map.get(id).and_then(|instance| {
            let mut instance = instance.lock().unwrap();
            (instance.record_generation == Some(generation)).then(|| {
                if cow_handle.is_some() {
                    debug_assert!(instance.cow_handle.is_none());
                    instance.cow_handle = cow_handle.take();
                }
                instance.state
            })
        })
    };
    let Some(state) = state else {
        return Err(BootFailure {
            error: VmmError::WrongState {
                id: id.to_owned(),
                expected: "the current sandbox generation".into(),
                actual: "replaced or removed during boot setup".into(),
            },
            prepared: None,
            cow_handle,
        });
    };
    complete_resource_handoff(&mut resource_handoff);

    let (kernel_path, rootfs_path) = paths.map_err(|error| BootFailure {
        error,
        prepared: None,
        cow_handle: None,
    })?;
    if matches!(state, SandboxState::Stopping | SandboxState::Stopped) {
        return Err(BootFailure {
            error: VmmError::WrongState {
                id: id.to_owned(),
                expected: "a sandbox still booting".into(),
                actual: state.to_string(),
            },
            prepared: None,
            cow_handle: None,
        });
    }

    // Arm the readiness observer BEFORE the guest starts: a guest that
    // announces itself by dialing the host does so the moment it is
    // serving, and the VMM forwards that connect only if someone is already
    // listening — otherwise the guest is reset and the one readiness event
    // is lost. Which observer that is, and whether there is one at all, is
    // the agent port's business.
    let failed = |error: VmmError| BootFailure {
        error,
        prepared: None,
        cow_handle: None,
    };
    let ready_gate = agents
        .arm_readiness(prepared.as_ref())
        .await
        .map_err(failed)?;

    let vm_spec =
        build_vm_spec(id, spec, net, kernel_path, rootfs_path, isolation).map_err(failed)?;
    let handle = prepared
        .boot(vm_spec)
        .await
        .map_err(|error| failed(error.into()))?;
    Ok((Arc::from(handle), ready_gate))
}

/// A staged file's host path inside the jail, from the chroot-relative name
/// the staging helpers return (`/vmlinux` → `{chroot}/vmlinux`).
fn in_jail(chroot: &Path, name: &str) -> PathBuf {
    chroot.join(name.trim_start_matches('/'))
}

fn complete_resource_handoff(signal: &mut Option<tokio::sync::oneshot::Sender<()>>) {
    if let Some(signal) = signal.take() {
        let _ = signal.send(());
    }
}
