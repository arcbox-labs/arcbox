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
