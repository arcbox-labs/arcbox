//! Warm-slot pool policy (CORE-78): which snapshot ids are worth keeping
//! slots for, how many prepares a refill owes, and what an eviction hands
//! back for teardown.
//!
//! Generic over the slot type so the policy is unit-testable without
//! spawning a VMM; `super::super::pool` owns the staging and teardown the
//! decisions here drive.

use std::collections::HashMap;
use std::sync::Mutex;

// Only the default type parameter: the policy never touches a slot's
// contents, and every test drives it over `SlotPool<u32>`.
use crate::sandbox::pool::PreparedSlot;

/// Most distinct snapshot ids pooled at once. The least recently restored
/// id is evicted — its slots torn down — when a third id starts filling.
const MAX_POOLED_SNAPSHOTS: usize = 2;

/// Refill work computed under the pool lock: how many slot prepares to
/// spawn and which evicted slots to tear down.
pub(in crate::sandbox) struct FillPlan<S> {
    pub spawn: usize,
    pub evicted: Vec<S>,
}

/// Slot storage and policy: keyed by snapshot id, capped to
/// [`MAX_POOLED_SNAPSHOTS`] distinct ids (LRU), with in-flight refill
/// accounting. Generic over the slot type so the policy is unit-testable
/// without spawning a VMM; the lock is never held across an await.
pub(in crate::sandbox) struct SlotPool<S = PreparedSlot> {
    inner: Mutex<PoolInner<S>>,
}

struct PoolInner<S> {
    /// Ready slots per snapshot id.
    ready: HashMap<String, Vec<S>>,
    /// In-flight prepare tasks per snapshot id.
    filling: HashMap<String, usize>,
    /// Pooled snapshot ids, least recently restored first. Membership is
    /// the pooling permission: an offer for an id not listed here (evicted
    /// or drained while its fill was in flight) is rejected.
    lru: Vec<String>,
}

impl<S> Default for SlotPool<S> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                ready: HashMap::new(),
                filling: HashMap::new(),
                lru: Vec::new(),
            }),
        }
    }
}

impl<S> SlotPool<S> {
    /// Pop a ready slot for `snapshot_id`, refreshing its recency.
    pub fn claim(&self, snapshot_id: &str) -> Option<S> {
        let mut inner = self.inner.lock().unwrap();
        let slot = inner.ready.get_mut(snapshot_id)?.pop()?;
        inner.touch(snapshot_id);
        inner.prune(snapshot_id);
        Some(slot)
    }

    /// Plan a refill of `snapshot_id` up to `target` spare slots,
    /// refreshing its recency and evicting beyond the LRU cap. The caller
    /// must run one prepare per `spawn` (finishing each with [`Self::offer`]
    /// or [`Self::abandon_fill`]) and tear down every evicted slot.
    pub fn begin_fill(&self, snapshot_id: &str, target: usize) -> FillPlan<S> {
        if target == 0 {
            return FillPlan {
                spawn: 0,
                evicted: Vec::new(),
            };
        }
        let mut inner = self.inner.lock().unwrap();
        inner.touch(snapshot_id);
        let ready = inner.ready.get(snapshot_id).map_or(0, Vec::len);
        let filling = inner.filling.get(snapshot_id).copied().unwrap_or(0);
        let spawn = target.saturating_sub(ready + filling);
        if spawn > 0 {
            *inner.filling.entry(snapshot_id.to_owned()).or_default() += spawn;
        }
        let mut evicted = Vec::new();
        while inner.lru.len() > MAX_POOLED_SNAPSHOTS {
            let stale = inner.lru.remove(0);
            evicted.extend(inner.ready.remove(&stale).unwrap_or_default());
            // In-flight fills for the evicted id keep their accounting and
            // get rejected at offer time (the id is no longer listed).
        }
        FillPlan { spawn, evicted }
    }

    /// Deliver a prepared slot. Returns it back for teardown when its
    /// snapshot was evicted or drained while the fill was in flight.
    pub fn offer(&self, snapshot_id: &str, slot: S) -> Option<S> {
        let mut inner = self.inner.lock().unwrap();
        inner.finish_fill(snapshot_id);
        if inner.lru.iter().any(|id| id == snapshot_id) {
            inner
                .ready
                .entry(snapshot_id.to_owned())
                .or_default()
                .push(slot);
            None
        } else {
            Some(slot)
        }
    }

    /// Account a failed fill for `snapshot_id`.
    pub fn abandon_fill(&self, snapshot_id: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.finish_fill(snapshot_id);
        inner.prune(snapshot_id);
    }

    /// Remove every ready slot for `snapshot_id` (or for all snapshots)
    /// and stop pooling it until the next restore refills.
    pub fn drain(&self, snapshot_id: Option<&str>) -> Vec<S> {
        let mut inner = self.inner.lock().unwrap();
        match snapshot_id {
            Some(id) => {
                inner.lru.retain(|entry| entry != id);
                inner.ready.remove(id).unwrap_or_default()
            }
            None => {
                inner.lru.clear();
                inner.ready.drain().flat_map(|(_, slots)| slots).collect()
            }
        }
    }
}

impl<S> PoolInner<S> {
    /// Move `snapshot_id` to the most-recent end of the LRU list.
    fn touch(&mut self, snapshot_id: &str) {
        self.lru.retain(|id| id != snapshot_id);
        self.lru.push(snapshot_id.to_owned());
    }

    /// Drop the LRU entry when nothing is pooled or filling for the id.
    fn prune(&mut self, snapshot_id: &str) {
        let ready = self.ready.get(snapshot_id).is_some_and(|s| !s.is_empty());
        let filling = self.filling.get(snapshot_id).copied().unwrap_or(0) > 0;
        if !ready && !filling {
            self.ready.remove(snapshot_id);
            self.lru.retain(|id| id != snapshot_id);
        }
    }

    fn finish_fill(&mut self, snapshot_id: &str) {
        if let Some(count) = self.filling.get_mut(snapshot_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.filling.remove(snapshot_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Policy tests run against `SlotPool<u32>` — the slot type is opaque
    // to the policy, so no VMM process is needed.

    /// Refill `snapshot` to `target` and deliver every planned slot as
    /// consecutive values starting at `base`.
    fn fill_and_offer(pool: &SlotPool<u32>, snapshot: &str, target: usize, base: u32) {
        let plan = pool.begin_fill(snapshot, target);
        assert!(plan.evicted.is_empty(), "unexpected eviction while filling");
        for offset in 0..plan.spawn {
            assert!(
                pool.offer(snapshot, base + u32::try_from(offset).unwrap())
                    .is_none()
            );
        }
    }

    #[test]
    fn claims_are_keyed_by_snapshot_id() {
        let pool = SlotPool::<u32>::default();
        fill_and_offer(&pool, "a", 1, 10);

        assert_eq!(pool.claim("other"), None);
        assert_eq!(pool.claim("a"), Some(10));
        assert_eq!(pool.claim("a"), None);
    }

    #[test]
    fn refill_accounts_for_ready_and_in_flight_slots() {
        let pool = SlotPool::<u32>::default();
        let plan = pool.begin_fill("a", 2);
        assert_eq!(plan.spawn, 2);

        // Nothing delivered yet: a concurrent refill must not over-spawn.
        assert_eq!(pool.begin_fill("a", 2).spawn, 0);
        assert!(pool.offer("a", 10).is_none());
        assert!(pool.offer("a", 11).is_none());
        assert_eq!(pool.begin_fill("a", 2).spawn, 0);

        // A claim frees one spare; the next refill replaces exactly it.
        assert_eq!(pool.claim("a"), Some(11));
        assert_eq!(pool.begin_fill("a", 2).spawn, 1);

        // A failed fill releases its accounting for the next refill.
        pool.abandon_fill("a");
        assert_eq!(pool.begin_fill("a", 2).spawn, 1);
    }

    #[test]
    fn pool_size_zero_disables_pooling() {
        let pool = SlotPool::<u32>::default();
        let plan = pool.begin_fill("a", 0);
        assert_eq!(plan.spawn, 0);
        assert!(plan.evicted.is_empty());
        assert_eq!(pool.claim("a"), None);
    }

    #[test]
    fn a_third_snapshot_evicts_the_least_recently_restored() {
        let pool = SlotPool::<u32>::default();
        fill_and_offer(&pool, "a", 1, 10);
        fill_and_offer(&pool, "b", 1, 20);

        let plan = pool.begin_fill("c", 1);
        assert_eq!(plan.spawn, 1);
        assert_eq!(plan.evicted, vec![10], "a's slot must be handed back");
        assert_eq!(pool.claim("a"), None);
        assert_eq!(pool.claim("b"), Some(20));
    }

    #[test]
    fn claiming_refreshes_recency() {
        let pool = SlotPool::<u32>::default();
        fill_and_offer(&pool, "a", 2, 10);
        fill_and_offer(&pool, "b", 1, 20);

        // Restoring from `a` again makes `b` the eviction candidate.
        assert_eq!(pool.claim("a"), Some(11));
        let plan = pool.begin_fill("c", 1);
        assert_eq!(plan.evicted, vec![20]);
        assert_eq!(pool.claim("b"), None);
        assert_eq!(pool.claim("a"), Some(10));
    }

    #[test]
    fn late_offers_for_an_evicted_snapshot_are_rejected() {
        let pool = SlotPool::<u32>::default();
        let plan = pool.begin_fill("a", 1);
        assert_eq!(plan.spawn, 1);
        fill_and_offer(&pool, "b", 1, 20);
        fill_and_offer(&pool, "c", 1, 30); // evicts "a" while its fill is in flight

        assert_eq!(pool.offer("a", 10), Some(10), "must come back for teardown");
        assert_eq!(pool.claim("a"), None);
    }

    #[test]
    fn drain_scopes_to_one_snapshot_or_all() {
        let pool = SlotPool::<u32>::default();
        fill_and_offer(&pool, "a", 2, 10);
        fill_and_offer(&pool, "b", 1, 20);

        let mut drained = pool.drain(Some("a"));
        drained.sort_unstable();
        assert_eq!(drained, vec![10, 11]);
        assert_eq!(pool.claim("a"), None);

        // A fill in flight across the drain is rejected on delivery.
        let plan = pool.begin_fill("a", 1);
        assert_eq!(plan.spawn, 1);
        assert!(pool.drain(Some("a")).is_empty());
        assert_eq!(pool.offer("a", 12), Some(12));

        assert_eq!(pool.drain(None), vec![20]);
        assert_eq!(pool.claim("b"), None);
    }
}
