//! Per-vCPU run loop.
//!
//! Each vCPU thread calls [`vcpu_run_loop`], which creates an `HvVcpu` on
//! the calling thread (required because `HvVcpu` is `!Send`), programs the
//! ARM64 boot register state, and enters an exit-dispatch loop. Exits are
//! dispatched to the PL011 UART, the `DeviceManager` for VirtIO MMIO, or
//! to the HVC/PSCI handlers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arcbox_hv::{ExceptionClass, HvVcpu, MmioInfo, VcpuExit};

use super::hvc_blk::{
    ARCBOX_HVC_BLK_FLUSH, ARCBOX_HVC_BLK_READ, ARCBOX_HVC_BLK_WRITE, ARCBOX_HVC_PROBE,
    handle_hvc_blk_flush, handle_hvc_blk_io,
};
use super::psci::{CpuOnSenders, handle_psci};
use super::{HvVcpuIds, Pl011, VcpuThreadHandles};

/// ARM64 register IDs re-exported from arcbox-hv.
pub(super) mod reg {
    pub use arcbox_hv::reg::{
        HV_REG_CPSR as CPSR, HV_REG_PC as PC, HV_REG_X0 as X0, HV_REG_X1 as X1, HV_REG_X2 as X2,
        HV_REG_X3 as X3,
    };
}

/// CPSR value: EL1h with DAIF masked (all interrupts masked at boot).
const CPSR_EL1H: u64 = 0x3C5;

/// ARM64 boot protocol: MMU off, caches off, plus ARMv8 RES1 bits.
const SCTLR_EL1_RESET: u64 = (1 << 11) // RES1
    | (1 << 20) // RES1
    | (1 << 22) // RES1
    | (1 << 23) // RES1
    | (1 << 28) // RES1
    | (1 << 29); // RES1

/// Shared state passed to each vCPU thread.
///
/// Groups the resources that every vCPU needs access to, replacing what
/// was previously 6 separate function parameters.
pub(super) struct VcpuContext {
    /// Shared device manager for MMIO dispatch.
    pub device_manager: Arc<crate::device::DeviceManager>,
    /// Shared flag; the loop exits when this is set to `false`.
    pub running: Arc<AtomicBool>,
    /// Set (with `running=false`) when the guest issues PSCI SYSTEM_RESET, so
    /// the lifecycle driver reboots the guest instead of powering it off.
    pub reset_requested: Arc<AtomicBool>,
    /// Cooperative pause flag. When `true`, the vCPU parks itself after its
    /// next `vcpu.run()` return instead of re-entering guest execution.
    /// Cleared by `resume`, which also unparks the thread.
    pub paused: Arc<AtomicBool>,
    /// Shared PL011 UART emulator for early console output.
    pub pl011: Arc<std::sync::Mutex<Pl011>>,
    /// Channel senders for waking secondary vCPUs via PSCI CPU_ON.
    /// `None` when the VM has only one vCPU.
    pub cpu_on_senders: Option<CpuOnSenders>,
    /// Registry of vCPU thread handles used by the IRQ callback to
    /// unpark WFI-blocked threads.
    pub vcpu_thread_handles: VcpuThreadHandles,
    /// Registry of Hypervisor.framework vCPU IDs. Populated by this loop
    /// after `HvVcpu::new()`; read by `pause`/`stop` when calling
    /// `hv_vcpus_exit` (which on arm64 requires a concrete list, not NULL).
    pub hv_vcpu_ids: HvVcpuIds,
    /// Per-block-device file descriptors and sector sizes for HVC fast path.
    pub hvc_blk_fds: Arc<Vec<(i32, u32, u64)>>,
    /// This vCPU's exit counters (diagnostics; written Relaxed by this
    /// thread only).
    pub stats: Arc<crate::vcpu_stats::VcpuStats>,
}

/// Reads the value of an MMIO write source register, handling the ARM64
/// XZR (register 31) special case.
///
/// On ARM64, register 31 in a load/store encoding is XZR (always zero),
/// not SP. `HvVcpu::get_reg(31)` returns SP, so we intercept it here.
fn read_mmio_write_reg(vcpu: &HvVcpu, vcpu_id: u32, register: u8) -> Option<u64> {
    if register == 31 {
        return Some(0);
    }
    match vcpu.get_reg(u32::from(register)) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!("vCPU {vcpu_id}: get_reg(X{register}) failed: {e}");
            None
        }
    }
}

/// Sign-extends an MMIO load result from `access_size` bytes to the transfer
/// register width. `sixty_four` selects the AArch64 target: `true` → 64-bit Xt
/// (`LDRSB/H/W` into X), `false` → 32-bit Wt (`LDRSB/H` into W, whose write
/// zero-extends into the 64-bit register). Zero-extending loads never set
/// `sign_extend`, so they never reach this.
fn sign_extend_mmio(value: u64, access_size: u8, sixty_four: bool) -> u64 {
    let bits = u32::from(access_size) * 8;
    // Nothing to extend once the loaded width already fills the register.
    if bits == 0 || bits >= 64 {
        return value;
    }
    if sixty_four {
        let shift = 64 - bits;
        #[allow(clippy::cast_possible_wrap)]
        let signed = (value << shift) as i64 >> shift;
        signed as u64
    } else if bits >= 32 {
        // 32-bit target loading 32 bits: no extension, zero-extend to 64.
        u64::from(value as u32)
    } else {
        // Sign-extend within 32 bits, then zero-extend the W-register write.
        let shift = 32 - bits;
        #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
        let signed = ((value as u32) << shift) as i32 >> shift;
        u64::from(signed as u32)
    }
}

/// Completes an MMIO read: applies sign-extension when the faulting load
/// requested it, honors the `Rt == 31` zero-register discard, and writes the
/// result into the guest's transfer register.
fn complete_mmio_read(vcpu: &HvVcpu, vcpu_id: u32, mmio: &MmioInfo, raw: u64) {
    // Rt == 31 in a load is the zero register (XZR/WZR): the result is
    // discarded. `set_reg(31, _)` would instead clobber SP.
    if mmio.register == 31 {
        return;
    }
    let value = if mmio.sign_extend {
        sign_extend_mmio(raw, mmio.access_size, mmio.sixty_four)
    } else {
        raw
    };
    if let Err(e) = vcpu.set_reg(u32::from(mmio.register), value) {
        tracing::error!("vCPU {vcpu_id}: set_reg(X{}) failed: {e}", mmio.register);
    }
}

/// Runs a single vCPU in a loop, dispatching MMIO traps to the device manager.
///
/// This function is intended to be called from a dedicated thread per vCPU.
/// `HvVcpu` is `!Send`, so it must be created inside this function on the
/// thread that will run it.
///
/// # Arguments
///
/// * `vcpu_id` — Logical vCPU index (0-based, for logging).
/// * `entry_addr` — Guest IPA where execution begins. For the BSP this is
///   the kernel entry point; for a secondary vCPU it is the address passed
///   in PSCI CPU_ON.
/// * `x0_value` — Initial value of X0. For the BSP this is the FDT address;
///   for a secondary vCPU it is the context_id from PSCI CPU_ON.
/// * `ctx` — Shared resources for the vCPU (device manager, IRQ state, etc.).
pub(super) fn vcpu_run_loop(vcpu_id: u32, entry_addr: u64, x0_value: u64, ctx: VcpuContext) {
    let VcpuContext {
        device_manager,
        running,
        reset_requested,
        paused,
        pl011,
        cpu_on_senders,
        vcpu_thread_handles,
        hv_vcpu_ids,
        hvc_blk_fds,
        stats,
    } = ctx;

    let vcpu = match HvVcpu::new() {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("vCPU {vcpu_id}: creation failed: {e}");
            return;
        }
    };

    // Set initial register state for ARM64 Linux boot protocol:
    //   PC   = entry address (kernel entry for BSP, PSCI entry for secondary)
    //   X0   = parameter (FDT address for BSP, context_id for secondary)
    //   X1-X3 = 0 (reserved per ARM64 boot protocol)
    //   CPSR = EL1h, DAIF masked
    if let Err(e) = vcpu.set_reg(reg::PC, entry_addr) {
        tracing::error!("vCPU {vcpu_id}: set PC failed: {e}");
        return;
    }
    if let Err(e) = vcpu.set_reg(reg::X0, x0_value) {
        tracing::error!("vCPU {vcpu_id}: set X0 failed: {e}");
        return;
    }
    let _ = vcpu.set_reg(reg::X1, 0);
    let _ = vcpu.set_reg(reg::X2, 0);
    let _ = vcpu.set_reg(reg::X3, 0);
    if let Err(e) = vcpu.set_reg(reg::CPSR, CPSR_EL1H) {
        tracing::error!("vCPU {vcpu_id}: set CPSR failed: {e}");
        return;
    }

    // ARM64 boot protocol: MMU must be off, caches can be on or off.
    if let Err(e) = vcpu.set_sys_reg(arcbox_hv::sys_reg::HV_SYS_REG_SCTLR_EL1, SCTLR_EL1_RESET) {
        tracing::warn!("vCPU {vcpu_id}: set SCTLR_EL1 failed: {e}");
    }

    // Set MPIDR_EL1 for this vCPU (Aff0 = vcpu_id, other affinity fields 0).
    // GIC affinity routing and the FDT `reg` values both depend on it, so the
    // write must stick: if MPIDR is silently non-writable on some macOS version
    // every vCPU reports Aff0 = 0 and interrupts misroute in a subtle,
    // hard-to-debug way. Verify the readback and abort the boot rather than run
    // with corrupted affinity. Done *before* the registry pushes below so a
    // failure early-returns without leaving a stale vCPU id / thread handle
    // (ABX-367). The readback only distinguishes a rejected write on
    // secondaries — the BSP's Aff0 is 0 whether or not the write took.
    let mpidr = u64::from(vcpu_id) & 0xFF;
    if let Err(e) = vcpu.set_sys_reg(arcbox_hv::sys_reg::HV_SYS_REG_MPIDR_EL1, mpidr) {
        tracing::error!("vCPU {vcpu_id}: set MPIDR_EL1 failed: {e}; aborting boot");
        running.store(false, Ordering::SeqCst);
        return;
    }
    match vcpu.get_sys_reg(arcbox_hv::sys_reg::HV_SYS_REG_MPIDR_EL1) {
        Ok(v) if v & 0xFF == u64::from(vcpu_id) => {}
        Ok(v) => {
            tracing::error!(
                "vCPU {vcpu_id}: MPIDR_EL1 Aff0 readback {:#x} != {vcpu_id}; aborting boot \
                 (GIC affinity would be wrong)",
                v & 0xFF,
            );
            running.store(false, Ordering::SeqCst);
            return;
        }
        Err(e) => {
            tracing::error!("vCPU {vcpu_id}: MPIDR_EL1 readback failed: {e}; aborting boot");
            running.store(false, Ordering::SeqCst);
            return;
        }
    }

    // Register this vCPU's framework ID and this thread's handle after all
    // register-setup calls succeed. If any setup call fails above, the
    // early return drops `HvVcpu` (triggering `hv_vcpu_destroy`) and the
    // thread exits without leaving either a stale ID or a dead `Thread`
    // in the shared registries. A stale ID would make `hv_vcpus_exit`
    // pass a dangling handle to Apple's framework (UB per its contract,
    // ABX-367); a dead thread handle would grow the registry unboundedly
    // across failed boots.
    {
        let mut ids = hv_vcpu_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ids.push(vcpu.raw_handle());
    }
    {
        let mut handles = vcpu_thread_handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.push(std::thread::current());
    }

    tracing::info!(
        "vCPU {vcpu_id}: starting at PC={:#x}, X0={:#x}, SCTLR={:#x}",
        entry_addr,
        x0_value,
        SCTLR_EL1_RESET,
    );

    loop {
        if !running.load(Ordering::Relaxed) {
            tracing::info!("vCPU {vcpu_id}: shutdown requested");
            break;
        }

        // Cooperative pause: if the host has requested a pause, park here
        // until resume clears the flag. Check after each `vcpu.run()` return
        // so the vCPU never re-enters guest execution while paused. The
        // host calls `hv_vcpus_exit` to kick us out of `vcpu.run()`, we
        // observe `paused`, and park. `resume` unparks every registered
        // vCPU thread via `vcpu_thread_handles`.
        while paused.load(Ordering::Acquire) && running.load(Ordering::Relaxed) {
            std::thread::park();
        }
        if !running.load(Ordering::Relaxed) {
            tracing::info!("vCPU {vcpu_id}: shutdown observed after pause");
            break;
        }

        // BSP (vCPU 0) handles bridge polling to avoid lock contention.
        // poll_net_rx removed — handled by net-io worker thread.
        // poll_vsock_rx removed — handled by vsock-io worker thread.
        if vcpu_id == 0 && device_manager.poll_bridge_rx() {
            if let Some(bid) = device_manager.bridge_device_id() {
                device_manager.raise_interrupt_for_device(bid, 1);
            }
        }

        // ABX-367 instrumentation: retained at trace level for future
        // diagnosis of vCPUs stuck inside or between `vcpu.run()` calls
        // during shutdown. Gated on `running=false` so normal operation
        // is unaffected. Not live debug logging — use RUST_LOG=trace to see.
        if !running.load(Ordering::Relaxed) {
            tracing::trace!("vCPU {vcpu_id}: iteration during shutdown (before vcpu.run)");
        }
        let exit = match vcpu.run() {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("vCPU {vcpu_id}: run failed: {e}");
                running.store(false, Ordering::SeqCst);
                break;
            }
        };
        if !running.load(Ordering::Relaxed) {
            tracing::trace!(
                "vCPU {vcpu_id}: vcpu.run returned during shutdown, exit={:?}",
                core::mem::discriminant(&exit)
            );
        }

        match exit {
            VcpuExit::Exception {
                class: ExceptionClass::DataAbort(ref mmio),
                ..
            } => {
                crate::vcpu_stats::VcpuStats::bump(if mmio.is_write {
                    &stats.mmio_writes
                } else {
                    &stats.mmio_reads
                });

                // ISV=0: the syndrome carries no valid transfer register or
                // access size (LDP/STP, atomics, some writeback-addressing
                // forms). We cannot service the access correctly and must not
                // fabricate a decode — that silently corrupts guest registers
                // or MMIO state. Refuse loudly and skip the instruction rather
                // than act on garbage. Linux's virtio-mmio driver only issues
                // single-register `readl`/`writel` (ISV=1), so this is a
                // defensive path; correct handling would single-step re-execute.
                if !mmio.isv {
                    tracing::error!(
                        "vCPU {vcpu_id}: undecodable MMIO {} at {:#x} (ESR ISV=0) — skipping instruction",
                        if mmio.is_write { "write" } else { "read" },
                        mmio.address,
                    );
                    let pc = vcpu.get_reg(reg::PC).unwrap_or(0);
                    let _ = vcpu.set_reg(reg::PC, pc.wrapping_add(4));
                    continue;
                }

                // Check PL011 UART region first, then fall through to DeviceManager.
                let handled_by_pl011 = {
                    let uart_match = {
                        let guard = pl011.lock().unwrap();
                        guard.contains(mmio.address)
                    };
                    if uart_match {
                        if mmio.is_write {
                            let value =
                                read_mmio_write_reg(&vcpu, vcpu_id, mmio.register).unwrap_or(0);
                            pl011.lock().unwrap().write(
                                mmio.address,
                                mmio.access_size as usize,
                                value,
                            );
                        } else {
                            let value = pl011
                                .lock()
                                .unwrap()
                                .read(mmio.address, mmio.access_size as usize);
                            complete_mmio_read(&vcpu, vcpu_id, mmio, value);
                        }
                        true
                    } else {
                        false
                    }
                };

                if !handled_by_pl011 {
                    // Dispatch to DeviceManager for VirtIO MMIO devices.
                    if mmio.is_write {
                        let Some(value) = read_mmio_write_reg(&vcpu, vcpu_id, mmio.register) else {
                            let pc = vcpu.get_reg(reg::PC).unwrap_or(0);
                            let _ = vcpu.set_reg(reg::PC, pc + 4);
                            continue;
                        };
                        tracing::trace!(
                            "MMIO write: addr={:#x} offset={:#x} X{}={:#x} size={}",
                            mmio.address,
                            mmio.address.saturating_sub(
                                mmio.address & !0xFFF // base = addr & ~0xFFF
                            ),
                            mmio.register,
                            value,
                            mmio.access_size,
                        );
                        if let Err(e) = device_manager.handle_mmio_write(
                            mmio.address,
                            mmio.access_size as usize,
                            value,
                        ) {
                            tracing::warn!(
                                "vCPU {vcpu_id}: MMIO write {:#x} failed: {e}",
                                mmio.address
                            );
                        }
                    } else {
                        let value = match device_manager
                            .handle_mmio_read(mmio.address, mmio.access_size as usize)
                        {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(
                                    "vCPU {vcpu_id}: MMIO read {:#x} failed: {e}",
                                    mmio.address
                                );
                                0 // Return 0 for unknown reads.
                            }
                        };
                        complete_mmio_read(&vcpu, vcpu_id, mmio, value);
                    }
                }

                // Advance PC past the trapped instruction (ARM64 = fixed 4 bytes).
                // Hypervisor.framework does NOT auto-advance PC on data aborts.
                let pc = vcpu.get_reg(reg::PC).unwrap_or(0);
                let _ = vcpu.set_reg(reg::PC, pc + 4);
            }

            VcpuExit::Exception {
                class: ExceptionClass::WaitForInterrupt,
                ..
            } => {
                crate::vcpu_stats::VcpuStats::bump(&stats.wfi);
                // Guest executed WFI — it is idle and waiting for an interrupt.
                // Before parking, poll the bridge for incoming data. vsock and
                // net injection are handled by their dedicated worker threads.
                let wfi_has_bridge = device_manager.poll_bridge_rx();
                if wfi_has_bridge {
                    if let Some(bid) = device_manager.bridge_device_id() {
                        device_manager.raise_interrupt_for_device(bid, 1);
                    }
                    continue; // Re-enter run loop immediately.
                }
                // No pending data — park with timeout.
                std::thread::park_timeout(std::time::Duration::from_millis(1));
                // Re-check `running` immediately after the park returns so
                // that `stop_darwin_hv` does not have to race a fresh
                // `vcpu.run()` re-entry. Without this, a vCPU parked in WFI
                // could consume an `exit_all_vcpus` cancel intended for a
                // different vCPU and then slip back into `vcpu.run()`
                // unguarded. See ABX-367.
                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }

            VcpuExit::Exception {
                class: ExceptionClass::HypercallHvc(_imm),
                ..
            } => {
                crate::vcpu_stats::VcpuStats::bump(&stats.hvc);
                let func_id = match vcpu.get_reg(reg::X0) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                match func_id {
                    ARCBOX_HVC_PROBE => {
                        // Return number of block devices available for fast path.
                        // NOTE: Hypervisor.framework auto-advances PC on HVC exit.
                        // Do NOT manually advance PC — that would skip an instruction.
                        let _ = vcpu.set_reg(reg::X0, hvc_blk_fds.len() as u64);
                    }
                    ARCBOX_HVC_BLK_READ => {
                        let result = handle_hvc_blk_io(&vcpu, &hvc_blk_fds, &device_manager, false);
                        let _ = vcpu.set_reg(reg::X0, result);
                    }
                    ARCBOX_HVC_BLK_WRITE => {
                        let result = handle_hvc_blk_io(&vcpu, &hvc_blk_fds, &device_manager, true);
                        let _ = vcpu.set_reg(reg::X0, result);
                    }
                    ARCBOX_HVC_BLK_FLUSH => {
                        let result = handle_hvc_blk_flush(&vcpu, &hvc_blk_fds);
                        let _ = vcpu.set_reg(reg::X0, result);
                    }
                    _ => {
                        // PSCI and other standard calls.
                        handle_psci(
                            vcpu_id,
                            func_id,
                            &vcpu,
                            &running,
                            &reset_requested,
                            cpu_on_senders.as_ref(),
                        );
                        if !running.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            }

            VcpuExit::Exception {
                class: ExceptionClass::SmcCall(_),
                ..
            } => {
                crate::vcpu_stats::VcpuStats::bump(&stats.smc);
                // Some guests route PSCI through SMC instead of HVC.
                let func_id = match vcpu.get_reg(reg::X0) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                handle_psci(
                    vcpu_id,
                    func_id,
                    &vcpu,
                    &running,
                    &reset_requested,
                    cpu_on_senders.as_ref(),
                );
                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }

            VcpuExit::VtimerActivated => {
                crate::vcpu_stats::VcpuStats::bump(&stats.vtimer);
                // Virtual timer fired. Unmask it so the guest sees the interrupt.
                let _ = vcpu.set_vtimer_mask(false);
            }

            VcpuExit::Canceled => {
                crate::vcpu_stats::VcpuStats::bump(&stats.kicks_received);
                if running.load(Ordering::Relaxed) {
                    // Woken by net-io thread for interrupt delivery.
                    continue;
                }
                tracing::info!("vCPU {vcpu_id}: canceled (shutdown)");
                break;
            }

            VcpuExit::Exception {
                class:
                    ExceptionClass::SystemRegister {
                        op0,
                        op1,
                        crn,
                        crm,
                        op2,
                        is_write,
                        rt,
                    },
                ..
            } => {
                crate::vcpu_stats::VcpuStats::bump(&stats.sysreg);
                // Apple's framework forwards unknown sysreg accesses as
                // EC=0x18 without auto-advancing ELR_EL2. If we re-enter
                // guest execution with PC unchanged, the same MSR/MRS
                // traps again — infinite loop (observed: Linux early boot
                // writes OSDLR_EL1 = S2_0_C1_C3_4 and wedges).
                //
                // Treat every unhandled sysreg as read-as-zero /
                // write-ignored: Linux boot touches debug regs
                // (OSDLR_EL1, MDSCR_EL1, DBGBCR*, etc.) that are safe
                // to silently drop, and reads of unknown regs yield 0.
                if !is_write && rt != 31 {
                    // MRS into Xrt. HV_REG_X0..X30 are 0..30 numerically,
                    // so rt maps directly to the register ID. rt==31 is
                    // XZR — the discard register; nothing to write.
                    let _ = vcpu.set_reg(u32::from(rt), 0);
                }
                // Advance PC past the trapping instruction (A64 = 4 bytes).
                if let Ok(pc) = vcpu.get_reg(reg::PC) {
                    let _ = vcpu.set_reg(reg::PC, pc.wrapping_add(4));
                }
                tracing::trace!(
                    vcpu_id,
                    is_write,
                    encoding = %format_args!("S{op0}_{op1}_C{crn}_C{crm}_{op2}"),
                    rt,
                    "sysreg access treated as RAZ/WI; PC advanced"
                );
            }

            VcpuExit::Exception {
                class: ref other, ..
            } => {
                crate::vcpu_stats::VcpuStats::bump(&stats.other);
                tracing::warn!("vCPU {vcpu_id}: unhandled exception: {other:?}");
            }

            VcpuExit::Unknown(reason) => {
                crate::vcpu_stats::VcpuStats::bump(&stats.other);
                tracing::warn!("vCPU {vcpu_id}: unknown exit reason {reason}");
            }
        }
    }

    // Flush any remaining UART output.
    pl011.lock().unwrap().flush();

    tracing::info!("vCPU {vcpu_id}: exited");
}

#[cfg(test)]
mod tests {
    use super::sign_extend_mmio;

    #[test]
    fn ldrsb_to_x_sign_extends_to_64() {
        // LDRSB Xt, [..]: 1 byte, 64-bit target. 0x80 -> -128 in all 64 bits.
        assert_eq!(sign_extend_mmio(0x80, 1, true), 0xFFFF_FFFF_FFFF_FF80);
        assert_eq!(sign_extend_mmio(0x7F, 1, true), 0x7F);
    }

    #[test]
    fn ldrsb_to_w_sign_extends_within_32_then_zero_extends() {
        // LDRSB Wt, [..]: 1 byte, 32-bit target. 0x80 -> 0xFFFF_FF80, and the
        // W-register write zero-extends the upper 32 bits.
        assert_eq!(sign_extend_mmio(0x80, 1, false), 0x0000_0000_FFFF_FF80);
        assert_eq!(sign_extend_mmio(0x7F, 1, false), 0x7F);
    }

    #[test]
    fn ldrsh_sign_extends_halfword() {
        assert_eq!(sign_extend_mmio(0x8000, 2, true), 0xFFFF_FFFF_FFFF_8000);
        assert_eq!(sign_extend_mmio(0x8000, 2, false), 0x0000_0000_FFFF_8000);
        assert_eq!(sign_extend_mmio(0x1234, 2, true), 0x1234);
    }

    #[test]
    fn ldrsw_sign_extends_word_to_64() {
        // LDRSW is always 32-bit source into a 64-bit register.
        assert_eq!(
            sign_extend_mmio(0x8000_0000, 4, true),
            0xFFFF_FFFF_8000_0000
        );
        assert_eq!(sign_extend_mmio(0x0000_0001, 4, true), 0x1);
    }

    #[test]
    fn full_and_wide_widths_are_passthrough() {
        // 8-byte load: nothing above bit 63 to extend into.
        assert_eq!(
            sign_extend_mmio(0xFFFF_FFFF_FFFF_FF80, 8, true),
            0xFFFF_FFFF_FFFF_FF80
        );
        // 4-byte load into a 32-bit register is not sign-extended (no SSE):
        // this helper only runs when sign_extend is set, but the width-fills-
        // register branch must still zero-extend cleanly.
        assert_eq!(
            sign_extend_mmio(0x8000_0000, 4, false),
            0x0000_0000_8000_0000
        );
    }
}
