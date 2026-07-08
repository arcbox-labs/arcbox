//! PSCI (Power State Coordination Interface) handling.
//!
//! Implements the subset of PSCI a Linux guest exercises: VERSION, FEATURES,
//! SYSTEM_OFF, SYSTEM_RESET, CPU_ON, CPU_OFF, AFFINITY_INFO, and
//! MIGRATE_INFO_TYPE. Called from the vCPU run loop on HVC/SMC exits whose
//! function ID is in the SMCCC PSCI range.
//!
//! The decision logic lives in the pure [`resolve_psci`] so it can be unit
//! tested without a live vCPU or the power registry; [`handle_psci`] applies
//! the resulting effect (write X0, request shutdown, dispatch CPU_ON, mark
//! the calling CPU off).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};

use arcbox_hv::reg::{HV_REG_X0 as X0, HV_REG_X1 as X1, HV_REG_X2 as X2, HV_REG_X3 as X3};

/// PSCI PSCI_VERSION: return the implemented PSCI version.
const PSCI_VERSION: u64 = 0x8400_0000;
/// PSCI CPU_OFF: power down the calling CPU.
const PSCI_CPU_OFF: u64 = 0x8400_0002;
/// PSCI CPU_ON (64-bit): power up a secondary CPU.
const PSCI_CPU_ON_64: u64 = 0xC400_0003;
/// PSCI AFFINITY_INFO (64-bit): query a CPU's power state.
const PSCI_AFFINITY_INFO_64: u64 = 0xC400_0004;
/// PSCI AFFINITY_INFO (32-bit alias).
const PSCI_AFFINITY_INFO_32: u64 = 0x8400_0004;
/// PSCI MIGRATE_INFO_TYPE: describe Trusted-OS migration requirements.
const PSCI_MIGRATE_INFO_TYPE: u64 = 0x8400_0006;
/// PSCI SYSTEM_OFF: shut the system down.
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
/// PSCI SYSTEM_RESET: reset the system.
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
/// PSCI PSCI_FEATURES: query whether a given PSCI function is implemented.
const PSCI_FEATURES: u64 = 0x8400_000A;

/// PSCI return code: success.
const PSCI_SUCCESS: u64 = 0;
/// PSCI return code: function not supported (-1).
const PSCI_NOT_SUPPORTED: u64 = (-1_i64) as u64;
/// PSCI return code: invalid parameters (-2).
const PSCI_INVALID_PARAMS: u64 = (-2_i64) as u64;
/// PSCI return code: the request is denied (-3). CPU_OFF on the BSP.
const PSCI_DENIED: u64 = (-3_i64) as u64;
/// PSCI return code: the target CPU is already on (-4).
const PSCI_ALREADY_ON: u64 = (-4_i64) as u64;

/// AFFINITY_INFO state: the affinity instance is ON.
const AFFINITY_INFO_ON: u64 = 0;
/// AFFINITY_INFO state: the affinity instance is OFF.
const AFFINITY_INFO_OFF: u64 = 1;

/// MIGRATE_INFO_TYPE: Trusted-OS not present / migration not required.
const MIGRATE_TYPE_NOT_REQUIRED: u64 = 2;

/// PSCI v1.0 (major=1, minor=0).
const PSCI_VERSION_1_0: u64 = 1 << 16;

/// Request to power on a secondary vCPU via PSCI CPU_ON.
/// Fields are written by the originating vCPU and read by the target's thread.
pub struct CpuOnRequest {
    /// Target MPIDR (CPU affinity identifier). Logged for diagnostics;
    /// the actual target is determined by channel routing in start_darwin_hv.
    pub _target_cpu: u64,
    /// Guest IPA where the secondary CPU begins executing.
    pub entry_point: u64,
    /// Value passed as X0 to the secondary CPU.
    pub context_id: u64,
}

/// Per-vCPU power slot in the [`CpuPowerRegistry`].
struct CpuSlot {
    /// Whether the CPU is currently powered on.
    on: bool,
    /// Wake-up channel to the vCPU's (re-armable) thread. `None` for the
    /// BSP, which boots directly and can never be powered off (CPU_OFF on
    /// it is DENIED).
    tx: Option<mpsc::Sender<CpuOnRequest>>,
}

/// Power state + wake-up channels for every vCPU, indexed by vCPU id.
///
/// Each secondary's sender is persistent: CPU_ON sends a [`CpuOnRequest`]
/// and marks the slot on; CPU_OFF marks it off and the vCPU thread parks
/// back on its receiver, ready for the next CPU_ON. The registry is shared
/// with every vCPU thread so any CPU can power any other CPU on.
pub struct CpuPowerRegistry {
    slots: Mutex<Vec<CpuSlot>>,
}

/// Shared handle to the power registry.
pub type CpuPower = Arc<CpuPowerRegistry>;

impl CpuPowerRegistry {
    /// Builds a registry from per-vCPU senders (index = vCPU id). Slot 0
    /// (BSP, `None`) starts on; every slot with a sender starts off.
    pub fn from_senders(senders: Vec<Option<mpsc::Sender<CpuOnRequest>>>) -> CpuPower {
        Arc::new(Self {
            slots: Mutex::new(
                senders
                    .into_iter()
                    .map(|tx| CpuSlot {
                        on: tx.is_none(),
                        tx,
                    })
                    .collect(),
            ),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<CpuSlot>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Snapshots each CPU's power state (index = vCPU id).
    fn snapshot(&self) -> Vec<bool> {
        self.lock().iter().map(|slot| slot.on).collect()
    }

    /// Powers `target` on: marks the slot on and wakes its thread. Resolves
    /// the race with a concurrent CPU_ON for the same target under the lock.
    /// Returns the PSCI return code for X0.
    fn cpu_on(&self, target: usize, request: CpuOnRequest) -> u64 {
        let mut slots = self.lock();
        let Some(slot) = slots.get_mut(target) else {
            return PSCI_INVALID_PARAMS;
        };
        if slot.on {
            return PSCI_ALREADY_ON;
        }
        let Some(tx) = slot.tx.as_ref() else {
            // Off but no wake channel — only reachable for the BSP, which
            // never turns off; treat defensively as already on.
            return PSCI_ALREADY_ON;
        };
        match tx.send(request) {
            Ok(()) => {
                slot.on = true;
                PSCI_SUCCESS
            }
            // Receiver gone — the target thread exited (shutdown teardown).
            Err(_) => PSCI_ALREADY_ON,
        }
    }

    /// Marks the calling CPU off (CPU_OFF). The caller's thread must then
    /// leave the run loop and park on its receiver. A CPU_ON arriving
    /// between this mark and the park simply queues on the channel.
    fn mark_off(&self, vcpu_id: usize) {
        if let Some(slot) = self.lock().get_mut(vcpu_id) {
            slot.on = false;
        }
    }

    /// Drops every wake-up sender so parked vCPU threads see their `recv()`
    /// fail and exit. Called from the stop path; works no matter how many
    /// registry handles the vCPU threads themselves still hold (each thread
    /// keeps one, so merely dropping the VMM's `Arc` would never close the
    /// channels — ABX-364).
    pub fn close(&self) {
        for slot in self.lock().iter_mut() {
            slot.tx = None;
        }
    }
}

/// The side effect a resolved PSCI call asks the caller to perform. Kept
/// separate from the X0 return value so the decision logic stays pure.
#[derive(Debug, PartialEq, Eq)]
enum PsciEffect {
    /// No effect beyond writing the return value.
    None,
    /// Power the whole system off.
    SystemOff,
    /// Reset (reboot) the whole system.
    SystemReset,
    /// Bring a secondary CPU online at `entry_point` with `context_id` in X0.
    CpuOn {
        target: usize,
        entry_point: u64,
        context_id: u64,
    },
    /// Power the calling CPU off: mark it off and leave the run loop.
    CpuOff,
}

/// What the vCPU run loop must do after a PSCI call.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::vmm) enum PsciExit {
    /// Keep running the guest.
    Continue,
    /// The calling CPU powered itself off: leave the run loop and park
    /// awaiting the next CPU_ON (secondaries only).
    CpuOff,
}

/// Whether PSCI_FEATURES should report a function as implemented.
fn psci_feature_supported(func_id: u64) -> bool {
    matches!(
        func_id,
        PSCI_VERSION
            | PSCI_FEATURES
            | PSCI_CPU_OFF
            | PSCI_CPU_ON_64
            | PSCI_AFFINITY_INFO_64
            | PSCI_AFFINITY_INFO_32
            | PSCI_MIGRATE_INFO_TYPE
            | PSCI_SYSTEM_OFF
            | PSCI_SYSTEM_RESET
    )
}

/// Resolves a PSCI call to an `(X0 return value, effect)` pair without touching
/// the vCPU or the power registry. `caller` is the calling vCPU (CPU_OFF
/// applies to it); `cpu_on` gives each CPU's power state (index = CPU,
/// `true` = on) so CPU_ON / AFFINITY_INFO can be decided and tested in
/// isolation. The CPU_ON result is optimistic: the caller resolves the race
/// with a concurrent CPU_ON when applying the effect.
fn resolve_psci(
    caller: usize,
    func_id: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    cpu_on: &[bool],
) -> (u64, PsciEffect) {
    match func_id {
        PSCI_VERSION => (PSCI_VERSION_1_0, PsciEffect::None),
        PSCI_FEATURES => {
            let ret = if psci_feature_supported(x1) {
                PSCI_SUCCESS
            } else {
                PSCI_NOT_SUPPORTED
            };
            (ret, PsciEffect::None)
        }
        PSCI_SYSTEM_OFF => (PSCI_SUCCESS, PsciEffect::SystemOff),
        PSCI_SYSTEM_RESET => (PSCI_SUCCESS, PsciEffect::SystemReset),
        PSCI_MIGRATE_INFO_TYPE => (MIGRATE_TYPE_NOT_REQUIRED, PsciEffect::None),
        PSCI_CPU_OFF => {
            // The BSP boots the machine and has no re-arm channel; denying
            // its CPU_OFF matches what Linux expects for a non-offlinable
            // boot CPU. Secondaries power off and can be CPU_ON'd again.
            if caller == 0 {
                (PSCI_DENIED, PsciEffect::None)
            } else {
                (PSCI_SUCCESS, PsciEffect::CpuOff)
            }
        }
        PSCI_CPU_ON_64 => {
            let target = (x1 & 0xFF) as usize;
            match cpu_on.get(target).copied() {
                None => (PSCI_INVALID_PARAMS, PsciEffect::None),
                Some(true) => (PSCI_ALREADY_ON, PsciEffect::None),
                Some(false) => (
                    PSCI_SUCCESS,
                    PsciEffect::CpuOn {
                        target,
                        entry_point: x2,
                        context_id: x3,
                    },
                ),
            }
        }
        PSCI_AFFINITY_INFO_64 | PSCI_AFFINITY_INFO_32 => {
            let target = (x1 & 0xFF) as usize;
            match cpu_on.get(target).copied() {
                None => (PSCI_INVALID_PARAMS, PsciEffect::None),
                Some(true) => (AFFINITY_INFO_ON, PsciEffect::None),
                Some(false) => (AFFINITY_INFO_OFF, PsciEffect::None),
            }
        }
        _ => (PSCI_NOT_SUPPORTED, PsciEffect::None),
    }
}

/// Snapshots each CPU's power state from the registry. A single-vCPU VM has
/// no registry — just CPU 0, always on.
fn cpu_on_snapshot(cpu_power: Option<&CpuPower>) -> Vec<bool> {
    match cpu_power {
        Some(registry) => registry.snapshot(),
        None => vec![true],
    }
}

/// Reads registers X1–X3, resolves the PSCI call, applies its effect (shutdown
/// or reboot flag, CPU_ON dispatch, CPU_OFF mark), and writes the return value
/// into X0. Returns whether the calling vCPU must leave its run loop.
///
/// SYSTEM_RESET sets `reset_requested` in addition to clearing `running`, so
/// the lifecycle driver reboots the guest rather than powering the machine off.
pub(in crate::vmm) fn handle_psci(
    vcpu_id: u32,
    func_id: u64,
    vcpu: &arcbox_hv::HvVcpu,
    running: &Arc<AtomicBool>,
    reset_requested: &Arc<AtomicBool>,
    cpu_power: Option<&CpuPower>,
) -> PsciExit {
    let x1 = vcpu.get_reg(X1).unwrap_or(0);
    let x2 = vcpu.get_reg(X2).unwrap_or(0);
    let x3 = vcpu.get_reg(X3).unwrap_or(0);

    let cpu_on = cpu_on_snapshot(cpu_power);
    let (mut ret, effect) = resolve_psci(vcpu_id as usize, func_id, x1, x2, x3, &cpu_on);
    let mut exit = PsciExit::Continue;

    match effect {
        PsciEffect::None => {
            if ret == PSCI_NOT_SUPPORTED {
                tracing::debug!("vCPU {vcpu_id}: unhandled PSCI func {func_id:#x}");
            }
        }
        PsciEffect::SystemOff => {
            tracing::info!("vCPU {vcpu_id}: PSCI SYSTEM_OFF");
            running.store(false, Ordering::SeqCst);
        }
        PsciEffect::SystemReset => {
            tracing::info!("vCPU {vcpu_id}: PSCI SYSTEM_RESET");
            reset_requested.store(true, Ordering::SeqCst);
            running.store(false, Ordering::SeqCst);
        }
        PsciEffect::CpuOn {
            target,
            entry_point,
            context_id,
        } => {
            // The decision above was optimistic (target seen as off). The
            // registry re-checks and marks the slot under its lock, so a
            // concurrent CPU_ON for the same target reports ALREADY_ON.
            ret = match cpu_power {
                Some(registry) => registry.cpu_on(
                    target,
                    CpuOnRequest {
                        _target_cpu: x1,
                        entry_point,
                        context_id,
                    },
                ),
                // Unreachable: a CpuOn effect requires an off CPU, and the
                // registry-less single-vCPU snapshot has none.
                None => PSCI_INVALID_PARAMS,
            };
            if ret == PSCI_SUCCESS {
                tracing::info!(
                    "vCPU {vcpu_id}: PSCI CPU_ON target={target} \
                     entry={entry_point:#x} ctx={context_id:#x}"
                );
            } else {
                tracing::debug!("vCPU {vcpu_id}: PSCI CPU_ON target={target} ret={:#x}", ret);
            }
        }
        PsciEffect::CpuOff => {
            // Mark the slot off before leaving the run loop: a CPU_ON that
            // races in right after simply queues on the channel and the
            // parked thread picks it up.
            if let Some(registry) = cpu_power {
                registry.mark_off(vcpu_id as usize);
            }
            tracing::info!("vCPU {vcpu_id}: PSCI CPU_OFF");
            exit = PsciExit::CpuOff;
        }
    }

    let _ = vcpu.set_reg(X0, ret);
    exit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_reports_1_0() {
        let (ret, eff) = resolve_psci(0, PSCI_VERSION, 0, 0, 0, &[true]);
        assert_eq!(ret, PSCI_VERSION_1_0);
        assert_eq!(eff, PsciEffect::None);
    }

    #[test]
    fn features_reports_supported_and_unsupported() {
        for f in [
            PSCI_CPU_OFF,
            PSCI_CPU_ON_64,
            PSCI_AFFINITY_INFO_64,
            PSCI_SYSTEM_OFF,
            PSCI_SYSTEM_RESET,
            PSCI_MIGRATE_INFO_TYPE,
            PSCI_VERSION,
            PSCI_FEATURES,
        ] {
            assert_eq!(
                resolve_psci(0, PSCI_FEATURES, f, 0, 0, &[true]).0,
                PSCI_SUCCESS
            );
        }
        // CPU_SUSPEND (0xC400_0001) is not implemented.
        assert_eq!(
            resolve_psci(0, PSCI_FEATURES, 0xC400_0001, 0, 0, &[true]).0,
            PSCI_NOT_SUPPORTED
        );
    }

    #[test]
    fn system_off_and_reset_effects() {
        assert_eq!(
            resolve_psci(0, PSCI_SYSTEM_OFF, 0, 0, 0, &[true]).1,
            PsciEffect::SystemOff
        );
        assert_eq!(
            resolve_psci(0, PSCI_SYSTEM_RESET, 0, 0, 0, &[true]).1,
            PsciEffect::SystemReset
        );
    }

    #[test]
    fn migrate_info_type_not_required() {
        assert_eq!(
            resolve_psci(0, PSCI_MIGRATE_INFO_TYPE, 0, 0, 0, &[true]),
            (MIGRATE_TYPE_NOT_REQUIRED, PsciEffect::None)
        );
    }

    #[test]
    fn cpu_on_off_target_yields_dispatch() {
        // CPU 0 on (BSP), CPU 1 off.
        let (ret, eff) = resolve_psci(0, PSCI_CPU_ON_64, 1, 0x4020_0000, 0x1234, &[true, false]);
        assert_eq!(ret, PSCI_SUCCESS);
        assert_eq!(
            eff,
            PsciEffect::CpuOn {
                target: 1,
                entry_point: 0x4020_0000,
                context_id: 0x1234,
            }
        );
    }

    #[test]
    fn cpu_on_already_on_and_invalid() {
        // Target already on.
        assert_eq!(
            resolve_psci(0, PSCI_CPU_ON_64, 0, 0, 0, &[true, false]).0,
            PSCI_ALREADY_ON
        );
        // Target out of range.
        assert_eq!(
            resolve_psci(0, PSCI_CPU_ON_64, 5, 0, 0, &[true, false]).0,
            PSCI_INVALID_PARAMS
        );
    }

    #[test]
    fn affinity_info_reports_state() {
        assert_eq!(
            resolve_psci(0, PSCI_AFFINITY_INFO_64, 0, 0, 0, &[true, false]).0,
            AFFINITY_INFO_ON
        );
        assert_eq!(
            resolve_psci(0, PSCI_AFFINITY_INFO_64, 1, 0, 0, &[true, false]).0,
            AFFINITY_INFO_OFF
        );
        assert_eq!(
            resolve_psci(0, PSCI_AFFINITY_INFO_32, 9, 0, 0, &[true, false]).0,
            PSCI_INVALID_PARAMS
        );
    }

    #[test]
    fn cpu_off_denied_for_bsp_allowed_for_secondary() {
        assert_eq!(
            resolve_psci(0, PSCI_CPU_OFF, 0, 0, 0, &[true, true]),
            (PSCI_DENIED, PsciEffect::None)
        );
        assert_eq!(
            resolve_psci(1, PSCI_CPU_OFF, 0, 0, 0, &[true, true]),
            (PSCI_SUCCESS, PsciEffect::CpuOff)
        );
    }

    #[test]
    fn unknown_function_not_supported() {
        // SYSTEM_RESET2 (0xC400_0012) is not implemented.
        assert_eq!(
            resolve_psci(0, 0xC400_0012, 0, 0, 0, &[true]),
            (PSCI_NOT_SUPPORTED, PsciEffect::None)
        );
    }

    /// A secondary can be onlined, offlined, and re-onlined; the registry
    /// state and the wake channel stay consistent across the cycle.
    #[test]
    fn registry_online_offline_reonline_roundtrip() {
        let (tx, rx) = mpsc::channel::<CpuOnRequest>();
        let registry = CpuPowerRegistry::from_senders(vec![None, Some(tx)]);
        assert_eq!(registry.snapshot(), vec![true, false]);

        let req = |entry| CpuOnRequest {
            _target_cpu: 1,
            entry_point: entry,
            context_id: 0,
        };
        assert_eq!(registry.cpu_on(1, req(0x1000)), PSCI_SUCCESS);
        assert_eq!(rx.try_recv().unwrap().entry_point, 0x1000);
        assert_eq!(registry.snapshot(), vec![true, true]);
        assert_eq!(registry.cpu_on(1, req(0x1000)), PSCI_ALREADY_ON);

        registry.mark_off(1);
        assert_eq!(registry.snapshot(), vec![true, false]);

        assert_eq!(registry.cpu_on(1, req(0x2000)), PSCI_SUCCESS);
        assert_eq!(rx.try_recv().unwrap().entry_point, 0x2000);
        assert_eq!(registry.snapshot(), vec![true, true]);

        // Out-of-range target and the BSP slot (no channel).
        assert_eq!(registry.cpu_on(9, req(0)), PSCI_INVALID_PARAMS);
        registry.mark_off(0); // BSP has no channel: off but not wakeable
        assert_eq!(registry.cpu_on(0, req(0)), PSCI_ALREADY_ON);
    }

    /// `close()` drops the senders even while other registry handles are
    /// alive, so a parked `recv()` fails and the thread can exit (the
    /// stop-path contract; ABX-364).
    #[test]
    fn registry_close_disconnects_parked_receivers() {
        let (tx, rx) = mpsc::channel::<CpuOnRequest>();
        let registry = CpuPowerRegistry::from_senders(vec![None, Some(tx)]);
        let thread_handle = registry.clone(); // simulates a vCPU thread's Arc
        registry.close();
        assert!(rx.recv().is_err());
        drop(thread_handle);
    }
}
