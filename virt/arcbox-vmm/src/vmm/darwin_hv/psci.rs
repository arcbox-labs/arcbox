//! PSCI (Power State Coordination Interface) handling.
//!
//! Implements the subset of PSCI needed by Linux guests: VERSION, SYSTEM_OFF,
//! SYSTEM_RESET, and CPU_ON. Called from the vCPU run loop on HVC exits
//! whose immediate number matches the SMCCC PSCI function ID range.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};

use arcbox_hv::reg::{HV_REG_X0 as X0, HV_REG_X1 as X1, HV_REG_X2 as X2, HV_REG_X3 as X3};

/// PSCI CPU_ON (64-bit): power up a secondary CPU.
const PSCI_CPU_ON_64: u64 = 0xC400_0003;

/// PSCI SYSTEM_OFF: shut the system down.
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;

/// PSCI SYSTEM_RESET: reset the system.
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

/// PSCI PSCI_VERSION: return PSCI version.
const PSCI_VERSION: u64 = 0x8400_0000;

/// PSCI return code: success.
const PSCI_SUCCESS: u64 = 0;

/// PSCI return code: the target CPU is already on (-4 in two's complement).
const PSCI_ALREADY_ON: u64 = (-4_i64) as u64;

/// Request to power on a secondary vCPU via PSCI CPU_ON.
/// Fields are written by the BSP and read by the secondary vCPU thread.
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
/// Index `i` corresponds to vCPU `i` (0-based). The BSP (vCPU 0) does not
/// have an entry. Each `Option<Sender>` is `take()`-n exactly once when the
/// guest calls PSCI CPU_ON for that vCPU, preventing double-start.
pub type CpuOnSenders = Arc<Mutex<Vec<Option<mpsc::Sender<CpuOnRequest>>>>>;

/// Reads registers X1–X3 as needed and writes the return value into X0.
/// For SYSTEM_OFF / SYSTEM_RESET, sets `running` to `false` so the caller
/// can break out of its run loop.
pub fn handle_psci(
    vcpu_id: u32,
    func_id: u64,
    vcpu: &arcbox_hv::HvVcpu,
    running: &Arc<AtomicBool>,
    cpu_on_senders: Option<&CpuOnSenders>,
) {
    match func_id {
        PSCI_VERSION => {
            // Return PSCI v1.0 (major=1, minor=0).
            let _ = vcpu.set_reg(X0, 1 << 16);
        }

        PSCI_SYSTEM_OFF => {
            tracing::info!("vCPU {vcpu_id}: PSCI SYSTEM_OFF");
            running.store(false, Ordering::SeqCst);
        }

        PSCI_SYSTEM_RESET => {
            tracing::info!("vCPU {vcpu_id}: PSCI SYSTEM_RESET");
            running.store(false, Ordering::SeqCst);
        }

        PSCI_CPU_ON_64 => {
            let target_mpidr = vcpu.get_reg(X1).unwrap_or(0);
            let entry_point = vcpu.get_reg(X2).unwrap_or(0);
            let context_id = vcpu.get_reg(X3).unwrap_or(0);

            // Extract CPU index from MPIDR Aff0 field (simple linear topology).
            let target_cpu = (target_mpidr & 0xFF) as usize;

            if let Some(senders) = cpu_on_senders {
                let mut senders_guard = senders.lock().unwrap_or_else(PoisonError::into_inner);

                // Take the sender so it can only be used once (CPU_ON is
                // idempotent in the PSCI spec — a second call for the same
                // target returns ALREADY_ON).
                if let Some(sender) = senders_guard.get_mut(target_cpu).and_then(|s| s.take()) {
                    match sender.send(CpuOnRequest {
                        _target_cpu: target_mpidr,
                        entry_point,
                        context_id,
                    }) {
                        Ok(()) => {
                            tracing::info!(
                                "vCPU {vcpu_id}: PSCI CPU_ON target={target_cpu} \
                                 entry={entry_point:#x} ctx={context_id:#x}"
                            );
                            let _ = vcpu.set_reg(X0, PSCI_SUCCESS);
                        }
                        Err(_) => {
                            // Receiver gone — secondary thread exited before
                            // we could send. Treat as ALREADY_ON.
                            tracing::warn!(
                                "vCPU {vcpu_id}: PSCI CPU_ON target={target_cpu} \
                                 channel closed"
                            );
                            let _ = vcpu.set_reg(X0, PSCI_ALREADY_ON);
                        }
                    }
                } else {
                    // No sender for this CPU — either already started or
                    // invalid target.
                    tracing::debug!("vCPU {vcpu_id}: PSCI CPU_ON target={target_cpu} already on");
                    let _ = vcpu.set_reg(X0, PSCI_ALREADY_ON);
                }
            } else {
                // Single-vCPU VM — CPU_ON is not supported.
                tracing::debug!("vCPU {vcpu_id}: PSCI CPU_ON ignored (single-vCPU VM)");
                let _ = vcpu.set_reg(X0, u64::MAX); // NOT_SUPPORTED
            }
        }

        _ => {
            tracing::debug!("vCPU {vcpu_id}: unhandled PSCI func {func_id:#x}");
            // Return NOT_SUPPORTED (-1) in X0.
            let _ = vcpu.set_reg(X0, u64::MAX);
        }
    }
}
