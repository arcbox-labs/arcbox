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
//! - The idle target tracks actual guest usage plus a reserve; it is never
//!   an unconditional constant, and it never plans the guest's
//!   `MemAvailable` to zero — a policy that walks the guest to the cliff
//!   edge needs a millisecond-class rescue path to survive, and one that
//!   stays clear of it does not. A guest that is actively *working* (load)
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

pub(super) mod controller;

/// Bytes per MiB.
const MIB: u64 = 1024 * 1024;

/// Guest `MemAvailable` that an idle shrink must leave behind.
///
/// The target is never planned below `used + this`, so an idle guest keeps a
/// working reserve instead of being walked to the edge. The predecessor
/// constant was 256 MiB, which for an idle guest (`used ≈ 0`) collapsed the
/// target onto the absolute floor: measured 2026-07-29 on a 16 GB VM, the
/// descent asked for 15.8 GB of the guest's 15.96 GB available and pinned
/// `MemAvailable` at literally 0 for ~98 s per cycle, which is both an OOM
/// hazard for running containers and ~14 cores of reclaim spin.
pub(super) const IDLE_MIN_RESERVE: u64 = 1024 * MIB;

/// Divisor bounding how much of the guest's available memory a single idle
/// entry may reclaim (2 ⇒ at most half).
///
/// The reserve alone still permits a violent single step — on that same 16 GB
/// idle guest it would allow reclaiming 14.9 GB. Leaving as much as we take
/// bounds the guest-side reclaim cost of any one entry.
pub(super) const IDLE_RECLAIM_DIVISOR: u64 = 2;

/// Smallest reclaim worth a shrink at all. Below this the guest-side reclaim
/// cost is not repaid by the memory returned.
pub(super) const MIN_WORTHWHILE_RECLAIM: u64 = 512 * MIB;

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

/// Computes the idle balloon target for the observed guest usage.
///
/// Two independent caps on the reclaim, whichever is smaller:
///
/// - `available` minus [`IDLE_MIN_RESERVE`] — the guest keeps a working
///   reserve;
/// - `available` over [`IDLE_RECLAIM_DIVISOR`] — one entry reclaims at most a
///   bounded share of the slack.
///
/// Both are expressed as a *reclaim* subtracted from `full`, never from the
/// guest's `MemTotal`. The two are not the same number — the guest kernel
/// reserves memory at boot, so `MemTotal` sits below the configured size (a
/// 16384 MB VM reports 15.6 GiB) — and the balloon target the controller
/// applies is in the configured domain. Computing a target from `MemTotal`
/// and applying it against `full` reclaims that gap *on top of* the intended
/// amount, eating into the very reserve this function exists to protect.
/// `available` is used only as a delta, which is domain-free.
///
/// The reserve also subsumes the old absolute floor — no computed target can
/// land near the level where the guest kernel itself destabilises.
pub(super) fn idle_target(stats: GuestStats, full: u64) -> u64 {
    // `available` cannot exceed the guest's own total, nor the configured
    // size; an inconsistent reading must not turn into a larger reclaim.
    let available = stats.available.min(stats.total).min(full);
    let by_reserve = available.saturating_sub(IDLE_MIN_RESERVE);
    let by_share = available / IDLE_RECLAIM_DIVISOR;
    full.saturating_sub(by_reserve.min(by_share))
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
    if full.saturating_sub(target) < MIN_WORTHWHILE_RECLAIM {
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
        // 12 GiB used, 4 GiB available → the share floor binds: reclaim at
        // most half the slack (2 GiB), never a constant.
        let t = idle_target(stats(FULL, 4 * GIB), FULL);
        assert_eq!(t, FULL - 2 * GIB);
    }

    #[test]
    fn idle_target_reserve_binds_when_slack_is_small() {
        // 1.5 GiB available: half of it (768 MiB) would leave the guest under
        // the 1 GiB reserve, so the reserve cap wins at 512 MiB.
        let t = idle_target(stats(FULL, GIB + 512 * MIB), FULL);
        assert_eq!(t, FULL - 512 * MIB);
    }

    /// The guest's `MemTotal` is always below the configured size (kernel
    /// reservations at boot: a 16384 MB VM reports ~15.6 GiB). Computing the
    /// target in the guest's domain and applying it against `full` would
    /// reclaim that gap on top of the intended share.
    #[test]
    fn reclaim_ignores_the_memtotal_to_configured_gap() {
        let mem_total = FULL - 400 * MIB;
        let available = 15 * GIB;
        let t = idle_target(
            GuestStats {
                total: mem_total,
                available,
                loadavg1: 0.1,
            },
            FULL,
        );
        assert_eq!(
            FULL - t,
            available / 2,
            "reclaim must be the promised share, not the share plus the gap"
        );
        assert!(available - (FULL - t) >= IDLE_MIN_RESERVE);
    }

    /// CORE-45: the defect this policy replaced. With `used + 256 MiB` an
    /// idle guest collapsed onto the floor — the descent asked for nearly
    /// all of `MemAvailable` and pinned it at zero for ~98 s per cycle.
    #[test]
    fn idle_guest_is_never_walked_to_the_floor() {
        let available = FULL - 100 * MIB;
        let t = idle_target(stats(FULL, available), FULL);

        assert!(
            t >= FULL / 2,
            "an idle guest must not be squeezed to a sliver, got {t}"
        );
        // Reclaim is bounded by the share cap ...
        assert_eq!(FULL - t, available / 2);
        // ... and what the guest keeps available stays far above the reserve.
        assert!(available - (FULL - t) >= IDLE_MIN_RESERVE);
    }

    /// The planned reclaim must never eat into the reserve, at any usage.
    #[test]
    fn planned_reclaim_always_leaves_the_reserve() {
        for available_gib in 0..=16 {
            let available = available_gib * GIB;
            let t = idle_target(stats(FULL, available), FULL);
            let reclaim = FULL.saturating_sub(t);
            assert!(
                available.saturating_sub(reclaim) >= IDLE_MIN_RESERVE.min(available),
                "available {available} reclaim {reclaim} breaches the reserve"
            );
        }
    }

    #[test]
    fn idle_target_never_exceeds_a_tiny_configured_size() {
        // A configured size below the reserve must not produce a target above
        // it (the old `clamp(floor, full)` would have panicked here).
        let t = idle_target(stats(256 * MIB, 200 * MIB), 256 * MIB);
        assert_eq!(t, 256 * MIB);
    }

    #[test]
    fn idle_target_clamps_to_full() {
        // Guest uses almost everything: no shrink beyond full.
        let t = idle_target(stats(FULL, 128 * MIB), FULL);
        assert_eq!(t, FULL);
    }

    #[test]
    fn idle_target_saturates_on_inconsistent_stats() {
        // available > total is not a real reading; it must be clamped down
        // rather than inflate the reclaim.
        let t = idle_target(stats(4 * GIB, 8 * GIB), FULL);
        assert_eq!(t, FULL - 2 * GIB);
    }

    /// Incident guard #1: the 2026-07-15 thrash began with an unconditional
    /// shrink while guest state was unknown. No stats ⇒ no shrink, ever.
    #[test]
    fn entry_without_stats_never_shrinks() {
        assert_eq!(entry_decision(None, FULL), EntryDecision::Keep);
    }

    #[test]
    fn entry_shrinks_to_usage_aware_target() {
        // 4 GiB used, 12 GiB available: reclaim half the slack, not a constant.
        let d = entry_decision(Some(stats(FULL, 12 * GIB)), FULL);
        assert_eq!(d, EntryDecision::Shrink(FULL - 6 * GIB));
    }

    #[test]
    fn entry_with_no_reclaimable_memory_keeps() {
        // Usage + reserve ≥ full: nothing to reclaim.
        let d = entry_decision(Some(stats(FULL, 100 * MIB)), FULL);
        assert_eq!(d, EntryDecision::Keep);
    }

    #[test]
    fn entry_keeps_when_the_reclaim_is_not_worth_it() {
        // 1.25 GiB available ⇒ the reserve caps the reclaim at 256 MiB,
        // below the worthwhile bar.
        let d = entry_decision(Some(stats(FULL, GIB + 256 * MIB)), FULL);
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
