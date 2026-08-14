//! Idle balloon policy (pure logic) and the controller that applies it.
//!
//! Numeric policy lives here; [`controller`] owns the balloon as a
//! message-driven task. The split keeps every decision unit-testable.
//!
//! Invariants (from the 2026-07-15 idle-thrash incident, where a blind
//! shrink to 128 MB starved a running compose stack for 18 hours):
//!
//! - Never shrink without a fresh guest memory reading. An unreachable
//!   agent means we know nothing about guest load — keep the balloon.
//! - The idle target tracks actual guest usage plus headroom; it is never
//!   an unconditional constant. A guest that is actively *working* (load)
//!   is not idle at all, no matter how quiet the host-side API is.
//! - Entry-time stats are the only ones used for sizing: they are taken
//!   while the balloon is empty, the one state where `/proc/meminfo` is
//!   unambiguous under both virtio-balloon accounting modes (with and
//!   without `DEFLATE_ON_OOM`). While shrunk, the balloon perturbs the
//!   very numbers a host-side re-computation would need, so pressure
//!   detection is delegated to the guest (see `WatchMemoryPressure`)
//!   and the only moves are "keep" or "give it all back".
//! - **Idle shrinking runs only on reclaim-capable backends — and no macOS
//!   backend is one today** (2026-07-29 measurements, macOS 26.4). VZ:
//!   Apple neither deallocates nor `madvise`s the pages the guest gives up
//!   — a 15.35 GB inflation left the daemon's `phys_footprint`
//!   byte-identical, and under real host memory pressure the kernel
//!   *compressed* the ballooned pages as live data (calibrated against a
//!   `MADV_FREE` probe, which the same pressure discards within seconds).
//!   HV: its device inflates with `MADV_DONTNEED`, which Darwin treats as
//!   a deactivation hint — calibrated footprint-inert, contents preserved
//!   (compressed, never discarded, under pressure); real Darwin reclaim
//!   needs `MADV_FREE_REUSABLE` (calibrated: footprint drops instantly).
//!   So shrinking is guest starvation with zero host benefit on either
//!   backend. See [`controller::BalloonDeps::reclaim_capable`]; flip a
//!   backend only with a measured host footprint drop on inflate.
//! - **What the host actually pays is the high-water mark of guest-touched
//!   pages, not the configured `memory_mb`** (2026-08-01, VZ, macOS 26.4).
//!   A fresh idle 16 GB VM costs ~718 MB of host `phys_footprint`; the
//!   guest allocating 3 GB of tmpfs takes it to 3717 MB, and the guest
//!   freeing that memory leaves it at 3717 MB. Absent any reclaim path the
//!   mark only ratchets upward, which is precisely the cost a working
//!   balloon would release. Measure the XPC helper process
//!   (`com.apple.Virtualization.VirtualMachine`) on VZ, not the daemon —
//!   guest RAM lives there, which is also why VZ can never be made
//!   reclaim-capable: that memory is not ours to `madvise`.
//!
//! # Before re-enabling the host-driven descent, read this
//!
//! The descent below (probe → stage a target → watch guest pressure) is
//! dormant, not merely unused, and two independent attempts to tune it
//! (2026-07-21, 2026-07-31) were abandoned for the same reason: **it has
//! no backend to serve.** VZ can never be reclaim-capable (above). HV
//! already advertises `VIRTIO_BALLOON_F_REPORTING` and its guest kernel
//! enables page reporting, so an HV guest hands back free ranges *on its
//! own, continuously* — the host side only has to release them, and today
//! it `madvise(MADV_DONTNEED)`s, which is footprint-inert on Darwin
//! (`virt/arcbox-virtio-balloon/src/lib.rs`). So the work that would make
//! HV reclaim is `MADV_FREE_REUSABLE` on the reporting path, and once
//! that lands the guest is already driving; a host-side idle descent is
//! the wrong shape for it, not a missing piece. Delete this machinery
//! before you tune it.
//!
//! If a descent is nevertheless the answer for some future backend, both
//! measured failure modes must be designed out first:
//!
//! - **`used + IDLE_BALLOON_HEADROOM` degenerates in exactly the idle case
//!   it exists for.** An idle guest has `MemAvailable ≈ total`, so
//!   `used ≈ 0` and the target collapses onto [`IDLE_BALLOON_FLOOR`] — an
//!   unconditional constant, which is what the invariant above forbids.
//!   Measured 2026-07-29 (VZ, 16 GB, before the gate closed): the descent
//!   asked the guest for 15.8 GB of its 15.96 GB available, pinned
//!   `MemAvailable` at literally 0 for ~98 s, pressure-restored, and
//!   repeated every ~8.5 min — ~2.8 cores averaged while "idle", with every
//!   running container an OOM candidate inside each zero-available window.
//!   A target that cannot walk the guest to the edge needs two floors, not
//!   one: a working reserve above `used` (~1 GiB) *and* a cap on how much
//!   of the observed slack a single entry may take (~half). A reclaim too
//!   small to repay its guest-side cost (~512 MB) should not happen at all.
//! - **On a memory-pressured host the descent oscillates, and macOS gives
//!   no signal to gate on.** Inflation churns guest pages through exhausted
//!   host swap and stalls, the guest floods `Out of puff!`, the pressure
//!   watch times out, the controller fails open (restore + note activity),
//!   and the 5-minute idle timeout starts the cycle again. Measured
//!   2026-07-21: an idle 16 GiB System VM on a host at 113/128 GiB with swap
//!   full oscillated every 5 minutes for over an hour — 5477 `Out of puff`
//!   lines in one daemon log — while `kern.memorystatus_vm_pressure_level`
//!   read *normal* throughout. A host-pressure gate is therefore not
//!   available; the only signal-agnostic answer measured was backing off on
//!   consecutive fail-opens (10 min, doubling to an hour) and clearing the
//!   streak when a shrink holds.

pub(super) mod controller;

/// Bytes per MiB.
const MIB: u64 = 1024 * 1024;

/// Headroom added above observed guest usage when computing an idle target.
pub(super) const IDLE_BALLOON_HEADROOM: u64 = 256 * MIB;

/// Absolute floor for a computed idle target. Below this the guest kernel
/// itself becomes unstable regardless of workload.
pub(super) const IDLE_BALLOON_FLOOR: u64 = 384 * MIB;

/// A guest with at least this 1-minute load average is doing real work —
/// it is not idle, regardless of host-side API silence (in-guest workloads
/// such as published-port services never cross the host).
pub(super) const IDLE_BUSY_LOADAVG: f64 = 1.0;

/// Budget for the agent stats query. A guest that cannot answer within
/// this window is treated as unreachable.
pub(super) const GUEST_STATS_TIMEOUT_SECS: u64 = 3;

/// Maximum balloon movement per shrink step.
///
/// Inflation pins guest `MemAvailable` near zero until it converges, and its
/// speed is not under host control — a 15 GB single-step shrink was measured
/// to stay unsettled for minutes on VZ. Stepping bounds each scarcity window
/// to a couple of seconds and lets the pressure detector arm between steps,
/// so the fast (armed) pressure path guards nearly the whole descent.
pub(super) const SHRINK_STEP: u64 = 2 * 1024 * MIB;

/// Next target when stepping the balloon from `current` toward
/// `final_target`.
pub(super) fn next_step(current: u64, final_target: u64) -> u64 {
    current.saturating_sub(SHRINK_STEP).max(final_target)
}

/// Guest memory + load snapshot, taken from the agent's `GetSystemInfo`
/// reply while the balloon is empty.
#[derive(Debug, Clone, Copy)]
pub(super) struct GuestStats {
    /// Total guest memory in bytes.
    pub total: u64,
    /// Available guest memory in bytes (free + reclaimable).
    pub available: u64,
    /// 1-minute load average.
    pub loadavg1: f64,
}

/// The move to make when the VM enters idle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum EntryDecision {
    /// Set the balloon target to this many bytes and start pressure watching.
    Shrink(u64),
    /// The guest is actively working — exit idle instead of shrinking.
    NotIdle,
    /// Leave the balloon alone (no stats, or nothing worth reclaiming);
    /// retry later.
    Keep,
}

/// Computes the idle balloon target for the observed guest usage:
/// used memory plus [`IDLE_BALLOON_HEADROOM`], clamped to
/// [`IDLE_BALLOON_FLOOR`] and the full configured size.
pub(super) fn idle_target(stats: GuestStats, full: u64) -> u64 {
    let used = stats.total.saturating_sub(stats.available);
    used.saturating_add(IDLE_BALLOON_HEADROOM)
        .clamp(IDLE_BALLOON_FLOOR, full)
}

/// Decides the balloon move when the VM enters idle.
///
/// `stats` is `None` when the agent could not be queried — in that case the
/// balloon must be kept, never shrunk blind.
pub(super) fn entry_decision(stats: Option<GuestStats>, full: u64) -> EntryDecision {
    let Some(stats) = stats else {
        return EntryDecision::Keep;
    };
    // A zero total is not a reading (the agent reports 0 when /proc/meminfo
    // is unreadable); without one, "used + headroom" would degenerate to
    // the floor and shrink a guest of unknown load.
    if stats.total == 0 {
        return EntryDecision::Keep;
    }
    if stats.loadavg1 >= IDLE_BUSY_LOADAVG {
        return EntryDecision::NotIdle;
    }
    let target = idle_target(stats, full);
    if target >= full {
        EntryDecision::Keep
    } else {
        EntryDecision::Shrink(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * MIB;
    const FULL: u64 = 16 * GIB;

    fn stats(total: u64, available: u64) -> GuestStats {
        GuestStats {
            total,
            available,
            loadavg1: 0.1,
        }
    }

    #[test]
    fn idle_target_tracks_guest_usage() {
        // 12 GiB used → target must follow usage, not a constant.
        let t = idle_target(stats(FULL, 4 * GIB), FULL);
        assert_eq!(t, 12 * GIB + IDLE_BALLOON_HEADROOM);
    }

    #[test]
    fn idle_target_clamps_to_floor() {
        // Near-empty guest: 100 MiB used + headroom is below the floor.
        let t = idle_target(stats(FULL, FULL - 100 * MIB), FULL);
        assert_eq!(t, IDLE_BALLOON_FLOOR);
    }

    #[test]
    fn idle_target_clamps_to_full() {
        // Guest uses almost everything: no shrink beyond full.
        let t = idle_target(stats(FULL, 128 * MIB), FULL);
        assert_eq!(t, FULL);
    }

    #[test]
    fn idle_target_saturates_on_inconsistent_stats() {
        // available > total must not underflow.
        let t = idle_target(stats(4 * GIB, 8 * GIB), FULL);
        assert_eq!(t, IDLE_BALLOON_FLOOR);
    }

    /// Incident guard #1: the 2026-07-15 thrash began with an unconditional
    /// shrink while guest state was unknown. No stats ⇒ no shrink, ever.
    #[test]
    fn entry_without_stats_never_shrinks() {
        assert_eq!(entry_decision(None, FULL), EntryDecision::Keep);
    }

    #[test]
    fn entry_shrinks_to_usage_aware_target() {
        // 4 GiB used: shrink, but to usage + headroom — not to a constant.
        let d = entry_decision(Some(stats(FULL, 12 * GIB)), FULL);
        assert_eq!(d, EntryDecision::Shrink(4 * GIB + IDLE_BALLOON_HEADROOM));
    }

    #[test]
    fn entry_with_no_reclaimable_memory_keeps() {
        // Usage + headroom ≥ full: nothing to reclaim.
        let d = entry_decision(Some(stats(FULL, 100 * MIB)), FULL);
        assert_eq!(d, EntryDecision::Keep);
    }

    #[test]
    fn next_step_descends_by_step_size() {
        assert_eq!(next_step(16 * GIB, 4 * GIB), 14 * GIB);
        assert_eq!(next_step(14 * GIB, 4 * GIB), 12 * GIB);
    }

    #[test]
    fn next_step_clamps_at_final_target() {
        assert_eq!(next_step(5 * GIB, 4 * GIB), 4 * GIB);
        assert_eq!(next_step(4 * GIB, 4 * GIB), 4 * GIB);
    }

    #[test]
    fn entry_zero_total_is_not_a_reading() {
        let d = entry_decision(Some(stats(0, 0)), FULL);
        assert_eq!(d, EntryDecision::Keep);
    }

    /// Incident guard #3: the compose stack was *running* the whole time —
    /// a guest with real load is not idle, however quiet the host API is.
    #[test]
    fn entry_busy_guest_is_not_idle() {
        let busy = GuestStats {
            total: FULL,
            available: 12 * GIB,
            loadavg1: 2.5,
        };
        assert_eq!(entry_decision(Some(busy), FULL), EntryDecision::NotIdle);
    }
}
