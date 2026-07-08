//! Per-vCPU exit accounting for the custom-VMM backends.
//!
//! R2 (interrupt-injection rebuild) and R3 (tickless WFI) of the HV
//! campaign are "reduce exits and wakeups" work — without per-vCPU exit
//! counts by reason and a broadcast-kick counter, neither can prove an
//! improvement. Counters are written by each vCPU's own thread with
//! `Relaxed` stores (readers only snapshot), and each instance is
//! cache-line aligned so adjacent vCPUs never share a line.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Cumulative exit counters for one vCPU.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct VcpuStats {
    /// MMIO read exits (data abort, `is_write == false`).
    pub mmio_reads: AtomicU64,
    /// MMIO write exits — includes every virtio QUEUE_NOTIFY doorbell.
    pub mmio_writes: AtomicU64,
    /// WFI exits — the guest going idle.
    pub wfi: AtomicU64,
    /// HVC exits (PSCI + ArcBox hypercalls).
    pub hvc: AtomicU64,
    /// SMC exits (PSCI via SMC conduit).
    pub smc: AtomicU64,
    /// Virtual-timer activations.
    pub vtimer: AtomicU64,
    /// Cancellation exits — this vCPU was kicked out of `hv_vcpu_run`
    /// by `hv_vcpus_exit` (interrupt delivery or shutdown).
    pub kicks_received: AtomicU64,
    /// Trapped system-register accesses (treated RAZ/WI).
    pub sysreg: AtomicU64,
    /// Anything else (unhandled exception classes, unknown exits).
    pub other: AtomicU64,
}

/// Point-in-time copy of one vCPU's counters.
#[derive(Debug, Clone, Serialize)]
pub struct VcpuStatsSnapshot {
    pub vcpu: u32,
    pub mmio_reads: u64,
    pub mmio_writes: u64,
    pub wfi: u64,
    pub hvc: u64,
    pub smc: u64,
    pub vtimer: u64,
    pub kicks_received: u64,
    pub sysreg: u64,
    pub other: u64,
}

impl VcpuStats {
    /// Relaxed increment helper for the owning vCPU thread.
    #[inline]
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Captures a point-in-time copy of the counters.
    #[must_use]
    pub fn snapshot(&self, vcpu: u32) -> VcpuStatsSnapshot {
        VcpuStatsSnapshot {
            vcpu,
            mmio_reads: self.mmio_reads.load(Ordering::Relaxed),
            mmio_writes: self.mmio_writes.load(Ordering::Relaxed),
            wfi: self.wfi.load(Ordering::Relaxed),
            hvc: self.hvc.load(Ordering::Relaxed),
            smc: self.smc.load(Ordering::Relaxed),
            vtimer: self.vtimer.load(Ordering::Relaxed),
            kicks_received: self.kicks_received.load(Ordering::Relaxed),
            sysreg: self.sysreg.load(Ordering::Relaxed),
            other: self.other.load(Ordering::Relaxed),
        }
    }
}

/// Full VM scheduling/debug snapshot: virtio device state plus per-vCPU
/// exit counters and the broadcast-kick total.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VmDebugSnapshot {
    /// Per-device virtio queue state (see [`crate::device::DeviceDebug`]).
    pub devices: Vec<crate::device::DeviceDebug>,
    /// Per-vCPU exit counters. Empty under VZ.
    pub vcpus: Vec<VcpuStatsSnapshot>,
    /// Times any component broadcast `hv_vcpus_exit` to ALL vCPUs (the
    /// R2 target: replace with targeted kicks).
    pub kick_broadcasts: u64,
    /// Times the IRQ callback unparked ALL vCPU threads on an SPI
    /// assertion (the other half of the broadcast-wakeup pattern).
    pub unpark_broadcasts: u64,
    /// Cumulative WFI-parked threads unparked by the targeted IRQ wake
    /// path (replaces the unpark broadcast; ABX-397).
    pub targeted_unparks: u64,
    /// Cumulative in-guest vCPUs kicked out of `hv_vcpu_run` by a targeted
    /// `hv_vcpus_exit` (replaces the kick broadcast; ABX-397).
    pub targeted_kicks: u64,
}
