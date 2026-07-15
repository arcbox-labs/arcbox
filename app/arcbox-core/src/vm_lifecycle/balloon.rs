//! Idle balloon sizing policy.
//!
//! Pure decision logic for the memory balloon while the System VM is idle.
//! Extracted from the actor so the policy is unit-testable; the actor owns
//! the agent query and the hypervisor call, this module owns the numbers.
//!
//! Invariants (from the 2026-07-15 idle-thrash incident, where a blind
//! shrink to 128 MB starved a running compose stack for 18 hours):
//!
//! - Never shrink without a fresh guest memory reading. An unreachable
//!   agent means we know nothing about guest load — keep the balloon.
//! - The idle target tracks actual guest usage plus headroom; it is never
//!   an unconditional constant.
//! - While shrunk, the policy is re-evaluated periodically. If the agent
//!   becomes unreachable then (a thrashing guest cannot answer), the only
//!   safe move is to give all memory back.

/// Bytes per MiB.
const MIB: u64 = 1024 * 1024;

/// Headroom added above observed guest usage when computing an idle target.
pub(super) const IDLE_BALLOON_HEADROOM: u64 = 256 * MIB;

/// Absolute floor for a computed idle target. Below this the guest kernel
/// itself becomes unstable regardless of workload.
pub(super) const IDLE_BALLOON_FLOOR: u64 = 384 * MIB;

/// Minimum difference from the current target worth acting on. Damps
/// oscillation from ordinary guest memory churn between re-evaluations.
pub(super) const IDLE_BALLOON_HYSTERESIS: u64 = 128 * MIB;

/// Interval between idle re-evaluations of the balloon target.
pub(super) const IDLE_RETARGET_INTERVAL_SECS: u64 = 30;

/// Budget for the agent memory query. A guest that cannot answer within
/// this window is treated as unreachable.
pub(super) const GUEST_STATS_TIMEOUT_SECS: u64 = 3;

/// Why an idle balloon probe was started; selects the policy applied to
/// its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProbePurpose {
    /// The VM just entered idle ([`on_idle_entry`]).
    IdleEntry,
    /// Periodic re-evaluation while idle ([`on_idle_retarget`]).
    IdleRetarget,
}

/// Guest memory snapshot, taken from the agent's `GetSystemInfo` reply.
#[derive(Debug, Clone, Copy)]
pub(super) struct MemStats {
    /// Total guest memory in bytes.
    pub total: u64,
    /// Available guest memory in bytes (free + reclaimable).
    pub available: u64,
}

/// A balloon move decided by the policy, applied by the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BalloonDecision {
    /// Set the balloon target to this many bytes.
    Set(u64),
    /// Restore the full configured memory size.
    RestoreFull,
    /// Leave the balloon where it is.
    Keep,
}

/// Computes the idle balloon target for the observed guest usage:
/// used memory plus [`IDLE_BALLOON_HEADROOM`], clamped to
/// [`IDLE_BALLOON_FLOOR`] and the full configured size.
pub(super) fn idle_target(stats: MemStats, full: u64) -> u64 {
    let used = stats.total.saturating_sub(stats.available);
    used.saturating_add(IDLE_BALLOON_HEADROOM)
        .clamp(IDLE_BALLOON_FLOOR, full)
}

/// Decides the balloon move when the VM first enters idle.
///
/// `stats` is `None` when the agent could not be queried — in that case the
/// balloon must be kept, never shrunk blind.
pub(super) fn on_idle_entry(stats: Option<MemStats>, full: u64) -> BalloonDecision {
    let Some(stats) = stats else {
        return BalloonDecision::Keep;
    };
    let target = idle_target(stats, full);
    if target >= full {
        BalloonDecision::Keep
    } else {
        BalloonDecision::Set(target)
    }
}

/// Decides the balloon move on a periodic re-evaluation while idle.
///
/// `stats` is `None` when the agent could not be queried. With the balloon
/// already shrunk that is the thrash signature — the decision must be
/// [`BalloonDecision::RestoreFull`].
pub(super) fn on_idle_retarget(
    stats: Option<MemStats>,
    current_target: u64,
    full: u64,
) -> BalloonDecision {
    let Some(stats) = stats else {
        return BalloonDecision::RestoreFull;
    };
    let target = idle_target(stats, full);
    if target >= full {
        BalloonDecision::RestoreFull
    } else if target.abs_diff(current_target) < IDLE_BALLOON_HYSTERESIS {
        BalloonDecision::Keep
    } else {
        BalloonDecision::Set(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * MIB;
    const FULL: u64 = 16 * GIB;

    fn stats(total: u64, available: u64) -> MemStats {
        MemStats { total, available }
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

    /// Incident guard #1: the 2026-07-15 thrash began with an unconditional
    /// shrink while guest state was unknown. No stats ⇒ no shrink, ever.
    #[test]
    fn entry_without_stats_never_shrinks() {
        assert_eq!(on_idle_entry(None, FULL), BalloonDecision::Keep);
    }

    #[test]
    fn entry_shrinks_to_usage_aware_target() {
        // 4 GiB used: shrink, but to usage + headroom — not to a constant.
        let d = on_idle_entry(Some(stats(FULL, 12 * GIB)), FULL);
        assert_eq!(d, BalloonDecision::Set(4 * GIB + IDLE_BALLOON_HEADROOM));
    }

    #[test]
    fn entry_with_no_reclaimable_memory_keeps() {
        // Usage + headroom ≥ full: nothing to reclaim.
        let d = on_idle_entry(Some(stats(FULL, 100 * MIB)), FULL);
        assert_eq!(d, BalloonDecision::Keep);
    }

    /// Incident guard #2: once shrunk, a guest thrashing in reclaim cannot
    /// answer the agent query — exactly then the balloon must deflate. This
    /// is the self-heal that was missing for 18 hours.
    #[test]
    fn retarget_agent_unreachable_restores_full() {
        let current = 4 * GIB;
        assert_eq!(
            on_idle_retarget(None, current, FULL),
            BalloonDecision::RestoreFull
        );
    }

    #[test]
    fn retarget_raises_target_under_pressure() {
        // Load grew from 2 GiB to 8 GiB while idle: raise the target.
        let current = 2 * GIB + IDLE_BALLOON_HEADROOM;
        let d = on_idle_retarget(Some(stats(FULL, 8 * GIB)), current, FULL);
        assert_eq!(d, BalloonDecision::Set(8 * GIB + IDLE_BALLOON_HEADROOM));
    }

    #[test]
    fn retarget_lowers_target_when_guest_frees_memory() {
        let current = 8 * GIB;
        let d = on_idle_retarget(Some(stats(FULL, 14 * GIB)), current, FULL);
        assert_eq!(d, BalloonDecision::Set(2 * GIB + IDLE_BALLOON_HEADROOM));
    }

    #[test]
    fn retarget_hysteresis_keeps_small_deltas() {
        // Computed target within the hysteresis band of the current one.
        let current = 4 * GIB + IDLE_BALLOON_HEADROOM + IDLE_BALLOON_HYSTERESIS / 2;
        let d = on_idle_retarget(Some(stats(FULL, 12 * GIB)), current, FULL);
        assert_eq!(d, BalloonDecision::Keep);
    }

    #[test]
    fn retarget_at_full_restores_full() {
        // Usage grew to fill the machine: stop shrinking entirely.
        let d = on_idle_retarget(Some(stats(FULL, 64 * MIB)), 4 * GIB, FULL);
        assert_eq!(d, BalloonDecision::RestoreFull);
    }

    #[test]
    fn idle_target_saturates_on_inconsistent_stats() {
        // available > total must not underflow.
        let t = idle_target(stats(4 * GIB, 8 * GIB), FULL);
        assert_eq!(t, IDLE_BALLOON_FLOOR);
    }
}
