//! The lifecycle event feed: one broadcast bus per manager, stamping every
//! event with a monotonic sequence number (CORE-147).
//!
//! Delivery is best-effort by design — an absent subscriber loses the event
//! outright, a lagging one gets `RecvError::Lagged` — so the feed is a
//! latency optimization over polling, never an authoritative log. What the
//! sequence adds is that loss is *detectable*: a subscriber that sees a
//! non-contiguous jump knows it missed events and can fall back to a
//! reconcile pass instead of silently carrying stale state.

use std::sync::Mutex;

use tokio::sync::broadcast;

use super::SandboxEvent;

/// Broadcasts [`SandboxEvent`]s to subscribers, stamping each with the next
/// sequence number as it goes out.
///
/// The counter is global across all sandboxes of one manager and lives only
/// as long as the manager: numbering starts at 1 and a new manager starts
/// over. `0` is never assigned, so on the wire — where proto3 decodes an
/// absent field as `0` — it means "emitted by a daemon that predates
/// sequencing", not "the first event".
pub struct EventBus {
    tx: broadcast::Sender<SandboxEvent>,
    /// The last sequence stamped. The lock deliberately spans the send:
    /// stamping and broadcasting under one guard is what makes the order
    /// subscribers observe identical to the numbering, so a gap in received
    /// sequences always means loss and never reordering.
    last: Mutex<u64>,
}

impl EventBus {
    /// A bus whose subscribers each buffer up to `capacity` events.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            last: Mutex::new(0),
        }
    }

    /// A new subscription, receiving every event published after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<SandboxEvent> {
        self.tx.subscribe()
    }

    /// Stamp `event` with the next sequence number and broadcast it.
    ///
    /// Fire-and-forget: with no subscriber attached the event is discarded
    /// (and its sequence number consumed, which is correct — a subscriber
    /// that attaches later sees the jump and knows it missed history).
    pub fn publish(&self, mut event: SandboxEvent) {
        let mut last = self.last.lock().unwrap();
        *last += 1;
        event.sequence = *last;
        let _ = self.tx.send(event);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::sandbox::types::action;

    /// Sequences are contiguous in the order a subscriber receives them,
    /// even under concurrent publishers — the property gap detection rests
    /// on: `received[n].sequence + 1 != received[n + 1].sequence` must mean
    /// loss, never that two publishes crossed between stamping and sending.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_publishes_arrive_in_sequence_order() {
        let bus = Arc::new(EventBus::new(1024));
        let mut rx = bus.subscribe();
        let publishers: Vec<_> = (0..8)
            .map(|p| {
                let bus = Arc::clone(&bus);
                tokio::spawn(async move {
                    for _ in 0..64 {
                        bus.publish(SandboxEvent::new(&format!("box-{p}"), action::READY));
                    }
                })
            })
            .collect();
        for publisher in publishers {
            publisher.await.unwrap();
        }

        let mut expected = 1;
        while let Ok(event) = rx.try_recv() {
            assert_eq!(
                event.sequence, expected,
                "a subscriber that lost nothing sees contiguous sequences"
            );
            expected += 1;
        }
        assert_eq!(expected, 8 * 64 + 1, "every publish was received");
    }

    /// Events published with no subscriber consume sequence numbers, so a
    /// late subscriber can tell there was history before it attached.
    #[tokio::test]
    async fn a_late_subscriber_sees_the_history_it_missed_as_a_gap() {
        let bus = EventBus::new(16);
        bus.publish(SandboxEvent::new("early", action::CREATED));
        bus.publish(SandboxEvent::new("early", action::READY));

        let mut rx = bus.subscribe();
        bus.publish(SandboxEvent::new("late", action::CREATED));
        let first = rx.try_recv().unwrap();
        assert_eq!(
            first.sequence, 3,
            "the first received sequence exceeds 1, disclosing the missed history"
        );
    }
}
