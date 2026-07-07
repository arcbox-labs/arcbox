//! PSCI (Power State Coordination Interface) handling.
//!
//! Implements the subset of PSCI a Linux guest exercises: VERSION, FEATURES,
//! SYSTEM_OFF, SYSTEM_RESET, CPU_ON, AFFINITY_INFO, and MIGRATE_INFO_TYPE.
//! Called from the vCPU run loop on HVC/SMC exits whose function ID is in the
//! SMCCC PSCI range.
//!
//! The decision logic lives in the pure [`resolve_psci`] so it can be unit
//! tested without a live vCPU or the channel registry; [`handle_psci`] applies
//! the resulting effect (write X0, request shutdown, dispatch CPU_ON).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};

use arcbox_hv::reg::{HV_REG_X0 as X0, HV_REG_X1 as X1, HV_REG_X2 as X2, HV_REG_X3 as X3};

/// PSCI PSCI_VERSION: return the implemented PSCI version.
const PSCI_VERSION: u64 = 0x8400_0000;
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

/// Shared state for secondary vCPU wake-up channels.
///
/// Index `i` corresponds to vCPU `i` (0-based). Slot 0 (BSP) is always `None`.
/// Each secondary's `Option<Sender>` is `take()`-n exactly once when the guest
/// calls PSCI CPU_ON for that vCPU, so a taken (`None`) slot means the CPU is
/// on, and a present (`Some`) slot means it is still off.
pub type CpuOnSenders = Arc<Mutex<Vec<Option<mpsc::Sender<CpuOnRequest>>>>>;

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
}

/// Whether PSCI_FEATURES should report a function as implemented.
fn psci_feature_supported(func_id: u64) -> bool {
    matches!(
        func_id,
        PSCI_VERSION
            | PSCI_FEATURES
            | PSCI_CPU_ON_64
            | PSCI_AFFINITY_INFO_64
            | PSCI_AFFINITY_INFO_32
            | PSCI_MIGRATE_INFO_TYPE
            | PSCI_SYSTEM_OFF
            | PSCI_SYSTEM_RESET
    )
}

/// Resolves a PSCI call to an `(X0 return value, effect)` pair without touching
/// the vCPU or the channel registry. `cpu_on` gives each CPU's power state
/// (index = CPU, `true` = on) so CPU_ON / AFFINITY_INFO can be decided and
/// tested in isolation. The CPU_ON result is optimistic: the caller resolves
/// the take-once race with a concurrent CPU_ON when applying the effect.
fn resolve_psci(func_id: u64, x1: u64, x2: u64, x3: u64, cpu_on: &[bool]) -> (u64, PsciEffect) {
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

/// Snapshots each CPU's power state from the channel registry: a present
/// (`Some`) sender means the CPU has not been started (off), a taken (`None`)
/// slot means it is on. A single-vCPU VM has just CPU 0, always on.
fn cpu_on_snapshot(cpu_on_senders: Option<&CpuOnSenders>) -> Vec<bool> {
    match cpu_on_senders {
        Some(senders) => senders
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(Option::is_none)
            .collect(),
        None => vec![true],
    }
}

/// Reads registers X1–X3, resolves the PSCI call, applies its effect (shutdown
/// or reboot flag, CPU_ON dispatch), and writes the return value into X0.
///
/// SYSTEM_RESET sets `reset_requested` in addition to clearing `running`, so
/// the lifecycle driver reboots the guest rather than powering the machine off.
pub fn handle_psci(
    vcpu_id: u32,
    func_id: u64,
    vcpu: &arcbox_hv::HvVcpu,
    running: &Arc<AtomicBool>,
    reset_requested: &Arc<AtomicBool>,
    cpu_on_senders: Option<&CpuOnSenders>,
) {
    let x1 = vcpu.get_reg(X1).unwrap_or(0);
    let x2 = vcpu.get_reg(X2).unwrap_or(0);
    let x3 = vcpu.get_reg(X3).unwrap_or(0);

    let cpu_on = cpu_on_snapshot(cpu_on_senders);
    let (mut ret, effect) = resolve_psci(func_id, x1, x2, x3, &cpu_on);

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
            // The decision above was optimistic (target seen as off). Take the
            // sender under the lock to resolve the race with a concurrent
            // CPU_ON for the same target: a taken slot means someone already
            // started it, so report ALREADY_ON.
            let sender = cpu_on_senders.and_then(|s| {
                s.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get_mut(target)
                    .and_then(Option::take)
            });
            match sender {
                Some(tx) => match tx.send(CpuOnRequest {
                    _target_cpu: x1,
                    entry_point,
                    context_id,
                }) {
                    Ok(()) => {
                        tracing::info!(
                            "vCPU {vcpu_id}: PSCI CPU_ON target={target} \
                             entry={entry_point:#x} ctx={context_id:#x}"
                        );
                        ret = PSCI_SUCCESS;
                    }
                    Err(_) => {
                        // Receiver gone — the target thread exited before we
                        // could send. Treat as already on.
                        tracing::warn!(
                            "vCPU {vcpu_id}: PSCI CPU_ON target={target} channel closed"
                        );
                        ret = PSCI_ALREADY_ON;
                    }
                },
                None => {
                    tracing::debug!("vCPU {vcpu_id}: PSCI CPU_ON target={target} already on");
                    ret = PSCI_ALREADY_ON;
                }
            }
        }
    }

    let _ = vcpu.set_reg(X0, ret);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_reports_1_0() {
        let (ret, eff) = resolve_psci(PSCI_VERSION, 0, 0, 0, &[true]);
        assert_eq!(ret, PSCI_VERSION_1_0);
        assert_eq!(eff, PsciEffect::None);
    }

    #[test]
    fn features_reports_supported_and_unsupported() {
        for f in [
            PSCI_CPU_ON_64,
            PSCI_AFFINITY_INFO_64,
            PSCI_SYSTEM_OFF,
            PSCI_SYSTEM_RESET,
            PSCI_MIGRATE_INFO_TYPE,
            PSCI_VERSION,
            PSCI_FEATURES,
        ] {
            assert_eq!(
                resolve_psci(PSCI_FEATURES, f, 0, 0, &[true]).0,
                PSCI_SUCCESS
            );
        }
        // CPU_SUSPEND (0xC400_0001) is not implemented.
        assert_eq!(
            resolve_psci(PSCI_FEATURES, 0xC400_0001, 0, 0, &[true]).0,
            PSCI_NOT_SUPPORTED
        );
    }

    #[test]
    fn system_off_and_reset_effects() {
        assert_eq!(
            resolve_psci(PSCI_SYSTEM_OFF, 0, 0, 0, &[true]).1,
            PsciEffect::SystemOff
        );
        assert_eq!(
            resolve_psci(PSCI_SYSTEM_RESET, 0, 0, 0, &[true]).1,
            PsciEffect::SystemReset
        );
    }

    #[test]
    fn migrate_info_type_not_required() {
        assert_eq!(
            resolve_psci(PSCI_MIGRATE_INFO_TYPE, 0, 0, 0, &[true]),
            (MIGRATE_TYPE_NOT_REQUIRED, PsciEffect::None)
        );
    }

    #[test]
    fn cpu_on_off_target_yields_dispatch() {
        // CPU 0 on (BSP), CPU 1 off.
        let (ret, eff) = resolve_psci(PSCI_CPU_ON_64, 1, 0x4020_0000, 0x1234, &[true, false]);
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
            resolve_psci(PSCI_CPU_ON_64, 0, 0, 0, &[true, false]).0,
            PSCI_ALREADY_ON
        );
        // Target out of range.
        assert_eq!(
            resolve_psci(PSCI_CPU_ON_64, 5, 0, 0, &[true, false]).0,
            PSCI_INVALID_PARAMS
        );
    }

    #[test]
    fn affinity_info_reports_state() {
        assert_eq!(
            resolve_psci(PSCI_AFFINITY_INFO_64, 0, 0, 0, &[true, false]).0,
            AFFINITY_INFO_ON
        );
        assert_eq!(
            resolve_psci(PSCI_AFFINITY_INFO_64, 1, 0, 0, &[true, false]).0,
            AFFINITY_INFO_OFF
        );
        assert_eq!(
            resolve_psci(PSCI_AFFINITY_INFO_32, 9, 0, 0, &[true, false]).0,
            PSCI_INVALID_PARAMS
        );
    }

    #[test]
    fn unknown_function_not_supported() {
        // CPU_OFF (0x8400_0002) is not implemented yet.
        assert_eq!(
            resolve_psci(0x8400_0002, 0, 0, 0, &[true]),
            (PSCI_NOT_SUPPORTED, PsciEffect::None)
        );
    }
}
