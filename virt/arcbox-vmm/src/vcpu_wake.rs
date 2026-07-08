//! Per-vCPU run-state tracking and targeted interrupt wakeups (ABX-397).
//!
//! Delivering one device interrupt used to unpark every vCPU thread and
//! broadcast `hv_vcpus_exit` to every vCPU — the dominant host-side cost
//! under multi-flow network load (docs/net-perf-limits.md). This registry
//! lets the IRQ path wake only the vCPUs that need waking: each vCPU
//! publishes what it is doing (in guest, in the VMM, or parked in the WFI
//! idle wait), and the wake path unparks just the parked ones.
//!
//! A vCPU inside `hv_vcpu_run` is interrupted by the in-kernel GICv3 when
//! the SPI is set; a vCPU in the VMM observes the pending interrupt on its
//! next `hv_vcpu_run` entry. Neither needs a wake. The 1 ms WFI
//! `park_timeout` bounds the race where a vCPU transitions into the park
//! between the wake path's state read and the park itself (the stored
//! unpark permit covers the other interleaving); the tickless work (R3)
//! will replace that bound with an explicit sleep/wake handshake.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// What a vCPU thread is doing right now.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VcpuRunState {
    /// In the VMM: dispatching an exit, powered off, or not yet started.
    InVmm = 0,
    /// Inside `hv_vcpu_run`, executing guest code.
    InGuest = 1,
    /// Parked in the WFI idle wait.
    ParkedWfi = 2,
}

/// One cache line per vCPU so the hot IRQ path and 18 vCPU threads don't
/// false-share.
#[repr(C, align(64))]
struct WakeCell {
    state: AtomicU8,
    thread: OnceLock<std::thread::Thread>,
    /// The vCPU's Hypervisor.framework handle, for targeted `hv_vcpus_exit`.
    raw_handle: OnceLock<u64>,
}

/// Registry of per-vCPU run states and thread handles, indexed by vCPU id.
///
/// Created once per VM start; each vCPU registers its thread handle after
/// one-time setup succeeds and updates its state around `hv_vcpu_run` and
/// the WFI park. Entries stay valid across CPU_OFF/CPU_ON cycles (the
/// thread and its `HvVcpu` are reused).
pub struct VcpuWakeRegistry {
    cells: Box<[WakeCell]>,
    /// Cumulative count of targeted unparks performed by the IRQ path.
    /// Never reset — post-mortems need history (see AGENTS.md).
    targeted_unparks: AtomicU64,
    /// Cumulative count of targeted in-guest kicks (`hv_vcpus_exit` on a
    /// concrete subset). Never reset.
    targeted_kicks: AtomicU64,
}

impl VcpuWakeRegistry {
    /// Creates a registry for `vcpu_count` vCPUs, all starting `InVmm`.
    #[must_use]
    pub fn new(vcpu_count: usize) -> Self {
        let cells = (0..vcpu_count)
            .map(|_| WakeCell {
                state: AtomicU8::new(VcpuRunState::InVmm as u8),
                thread: OnceLock::new(),
                raw_handle: OnceLock::new(),
            })
            .collect();
        Self {
            cells,
            targeted_unparks: AtomicU64::new(0),
            targeted_kicks: AtomicU64::new(0),
        }
    }

    /// Registers the calling thread and its framework vCPU handle as vCPU
    /// `vcpu_id`. Called once from `vcpu_run_loop` after setup succeeds;
    /// later calls are no-ops (the thread and handle never change across
    /// power cycles — the `HvVcpu` is reused).
    pub fn register_current_thread(&self, vcpu_id: u32, raw_handle: u64) {
        if let Some(cell) = self.cells.get(vcpu_id as usize) {
            let _ = cell.thread.set(std::thread::current());
            let _ = cell.raw_handle.set(raw_handle);
        }
    }

    /// Publishes vCPU `vcpu_id`'s run state.
    ///
    /// Release ordering pairs with the Acquire load in [`Self::wake_parked`]:
    /// a wake that observes `ParkedWfi` sees a thread that has either parked
    /// or is about to (in which case the unpark permit is consumed by that
    /// imminent park).
    #[inline]
    pub fn set_state(&self, vcpu_id: u32, state: VcpuRunState) {
        if let Some(cell) = self.cells.get(vcpu_id as usize) {
            cell.state.store(state as u8, Ordering::Release);
        }
    }

    /// Computes the targeted wake set for an interrupt: unparks every vCPU
    /// parked in the WFI idle wait, and appends the framework handle of
    /// every vCPU currently inside `hv_vcpu_run` to `kick` (the caller
    /// passes the list to one `hv_vcpus_exit` call — the in-kernel GIC does
    /// NOT interrupt a running vCPU by itself; verified empirically, see
    /// ABX-420). vCPUs in the VMM are left alone: they observe the pending
    /// interrupt on their next `hv_vcpu_run` entry.
    ///
    /// Returns the number of threads unparked. `kick` is not cleared.
    pub fn wake_targets(&self, kick: &mut Vec<u64>) -> u32 {
        let mut woken = 0;
        for cell in &self.cells {
            match cell.state.load(Ordering::Acquire) {
                s if s == VcpuRunState::ParkedWfi as u8 => {
                    if let Some(thread) = cell.thread.get() {
                        thread.unpark();
                        woken += 1;
                    }
                }
                s if s == VcpuRunState::InGuest as u8 => {
                    if let Some(&handle) = cell.raw_handle.get() {
                        kick.push(handle);
                    }
                }
                _ => {}
            }
        }
        if woken > 0 {
            self.targeted_unparks
                .fetch_add(u64::from(woken), Ordering::Relaxed);
        }
        woken
    }

    /// Records `n` vCPUs kicked out of `hv_vcpu_run` by a targeted exit.
    pub fn note_kicked(&self, n: u64) {
        self.targeted_kicks.fetch_add(n, Ordering::Relaxed);
    }

    /// Cumulative targeted unparks (diagnostics; never reset).
    #[must_use]
    pub fn targeted_unparks(&self) -> u64 {
        self.targeted_unparks.load(Ordering::Relaxed)
    }

    /// Cumulative targeted in-guest kicks (diagnostics; never reset).
    #[must_use]
    pub fn targeted_kicks(&self) -> u64 {
        self.targeted_kicks.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    #[test]
    fn wake_targets_unparks_parked_and_kicks_in_guest() {
        let registry = Arc::new(VcpuWakeRegistry::new(3));
        // No threads registered yet: nothing to wake even if marked parked.
        registry.set_state(0, VcpuRunState::ParkedWfi);
        let mut kick = Vec::new();
        assert_eq!(registry.wake_targets(&mut kick), 0);
        assert!(kick.is_empty());

        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for id in 0..3u32 {
            let reg = registry.clone();
            let stop = stop.clone();
            handles.push(std::thread::spawn(move || {
                reg.register_current_thread(id, u64::from(0x1000_u32 + id));
                if id == 1 {
                    // vCPU 1 parks (WFI); vCPU 2 runs "in guest"; vCPU 0
                    // stays in the VMM.
                    reg.set_state(id, VcpuRunState::ParkedWfi);
                    while !stop.load(Ordering::Acquire) {
                        std::thread::park_timeout(Duration::from_secs(5));
                    }
                } else {
                    reg.set_state(
                        id,
                        if id == 2 {
                            VcpuRunState::InGuest
                        } else {
                            VcpuRunState::InVmm
                        },
                    );
                    while !stop.load(Ordering::Acquire) {
                        std::thread::park_timeout(Duration::from_millis(10));
                    }
                }
            }));
        }
        // Wait until vCPU 1 reports parked and vCPU 2 reports in-guest.
        for _ in 0..100 {
            if registry.cells[1].state.load(Ordering::Acquire) == VcpuRunState::ParkedWfi as u8
                && registry.cells[1].thread.get().is_some()
                && registry.cells[2].state.load(Ordering::Acquire) == VcpuRunState::InGuest as u8
                && registry.cells[2].raw_handle.get().is_some()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        let mut kick = Vec::new();
        assert_eq!(
            registry.wake_targets(&mut kick),
            1,
            "only the parked vCPU is unparked"
        );
        assert_eq!(kick.len(), 1, "only the in-guest vCPU is kicked");
        assert_eq!(registry.targeted_unparks(), 1);
        registry.note_kicked(kick.len() as u64);
        assert_eq!(registry.targeted_kicks(), 1);

        stop.store(true, Ordering::Release);
        for handle in handles {
            handle.thread().unpark();
            handle.join().unwrap();
        }
    }

    #[test]
    fn state_roundtrip_and_out_of_range_ignored() {
        let registry = VcpuWakeRegistry::new(1);
        registry.set_state(0, VcpuRunState::InGuest);
        assert_eq!(
            registry.cells[0].state.load(Ordering::Acquire),
            VcpuRunState::InGuest as u8
        );
        // Out-of-range ids are ignored, not a panic.
        registry.set_state(9, VcpuRunState::ParkedWfi);
        registry.register_current_thread(9, 0);
        let mut kick = Vec::new();
        // vCPU 0 is InGuest but has no registered handle: nothing to kick.
        assert_eq!(registry.wake_targets(&mut kick), 0);
        assert!(kick.is_empty());
    }
}
