//! Shared machine-stats fan-out.
//!
//! One guest `WatchStats` stream serves every subscriber (desktop monitor,
//! `abctl top`, …), and no stream — no guest-side sampling at all — exists
//! while nobody subscribes. The pump starts on the first subscriber, stops
//! shortly after the last one drops, and re-issues the agent watch each
//! time its window elapses.
//!
//! Monitoring is passive observation: nothing in this module records VM
//! activity, so an always-on monitor never holds the VM out of idle
//! reclaim (the balloon is transparent to `/proc` readers).

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcbox_connect::v1::WatchStatsRequest;
// `MachineStats` stays on the prost side of the CORE-73 split: samples flow
// through `Runtime::subscribe_machine_stats*`, whose receivers `arcbox-api`
// forwards as prost values (Phase B3 worklist).
use arcbox_protocol::agent::MachineStats;
use tokio::sync::broadcast;

use crate::error::Result;
use crate::machine::MachineManager;

/// Sample cadence requested from the agent.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Watch window requested per agent stream; the pump re-issues the watch
/// when it elapses.
const WATCH_WINDOW: Duration = Duration::from_secs(300);

/// Patience for one frame before the stream counts as stale. Frames arrive
/// every [`SAMPLE_INTERVAL`] and double as keepalives, so this only trips
/// on a window boundary or a dead agent.
const FRAME_PATIENCE: Duration = Duration::from_secs(5);

/// Backoff between watch-open attempts while subscribers are waiting
/// (VM restarting, agent briefly unreachable).
const RECONNECT_BACKOFF: Duration = Duration::from_secs(3);

/// Broadcast depth per subscriber. A lagging reader misses old samples and
/// resumes at the newest — exactly right for a live monitor.
const CHANNEL_DEPTH: usize = 8;

/// Opens guest stats streams. Abstracted so the hub's lifecycle is
/// unit-testable without a VM.
pub trait StatsSource: Send + Sync + 'static {
    /// The stream type produced by [`Self::open`].
    type Stream: StatsStream;

    /// Opens a fresh guest stats stream on a dedicated agent connection.
    fn open(&self) -> impl Future<Output = Result<Self::Stream>> + Send;
}

/// One open guest stats stream.
pub trait StatsStream: Send {
    /// Receives the next sample, waiting at most `max_wait`.
    fn next(&mut self, max_wait: Duration) -> impl Future<Output = Result<MachineStats>> + Send;
}

/// Fan-out hub: one pump task per subscribed period, N broadcast readers.
pub struct StatsHub<S: StatsSource> {
    source: S,
    state: Mutex<PumpSlot>,
}

/// The currently live pump, if any. `generation` lets an exiting pump tell
/// whether it is still the live one (a new subscriber may have replaced it
/// while it was winding down).
struct PumpSlot {
    generation: u64,
    sender: Option<broadcast::Sender<MachineStats>>,
}

impl<S: StatsSource> StatsHub<S> {
    /// Creates a hub over `source`. No guest traffic until someone
    /// subscribes.
    pub fn new(source: S) -> Arc<Self> {
        Arc::new(Self {
            source,
            state: Mutex::new(PumpSlot {
                generation: 0,
                sender: None,
            }),
        })
    }

    /// Subscribes to machine stats, starting the pump when it is the first
    /// live subscription. Samples are cumulative counters; consumers
    /// derive rates from deltas between consecutive samples.
    pub fn subscribe(self: &Arc<Self>) -> broadcast::Receiver<MachineStats> {
        let mut state = self.state.lock().expect("stats hub lock poisoned");
        if let Some(sender) = &state.sender
            && sender.receiver_count() > 0
        {
            return sender.subscribe();
        }
        // First subscriber (or the previous pump is winding down with zero
        // receivers): start a fresh pump on a fresh channel.
        let (tx, rx) = broadcast::channel(CHANNEL_DEPTH);
        state.generation += 1;
        state.sender = Some(tx.clone());
        let hub = Arc::clone(self);
        let generation = state.generation;
        drop(tokio::spawn(async move { hub.pump(tx, generation).await }));
        rx
    }

    /// Streams samples from the guest into the broadcast channel until the
    /// last receiver is gone.
    async fn pump(self: Arc<Self>, tx: broadcast::Sender<MachineStats>, generation: u64) {
        tracing::info!("stats pump started");
        'reopen: while tx.receiver_count() > 0 {
            let mut stream = match self.source.open().await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!("stats watch open failed: {e}; retrying");
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                    continue;
                }
            };
            let window_started = tokio::time::Instant::now();
            loop {
                if tx.receiver_count() == 0 {
                    break 'reopen;
                }
                match stream.next(FRAME_PATIENCE).await {
                    Ok(sample) => {
                        // Send fails only with zero receivers; the loop
                        // condition handles that on the next pass.
                        let _ = tx.send(sample);
                    }
                    Err(e) => {
                        // A clean window end goes quiet right around
                        // WATCH_WINDOW; anything earlier is a real failure
                        // and deserves a backoff before reconnecting.
                        if window_started.elapsed() < WATCH_WINDOW.saturating_sub(FRAME_PATIENCE) {
                            tracing::debug!("stats stream interrupted: {e}; reopening");
                            tokio::time::sleep(RECONNECT_BACKOFF).await;
                        }
                        continue 'reopen;
                    }
                }
            }
        }
        let mut state = self.state.lock().expect("stats hub lock poisoned");
        if state.generation == generation {
            state.sender = None;
        }
        tracing::info!("stats pump stopped");
    }
}

/// Production [`StatsSource`]: a dedicated agent connection per stream,
/// mirroring how the idle-balloon pressure watch connects.
pub struct AgentStatsSource {
    machine_manager: Arc<MachineManager>,
    machine_name: String,
}

impl AgentStatsSource {
    /// A source for the named machine's agent.
    pub fn new(machine_manager: Arc<MachineManager>, machine_name: impl Into<String>) -> Self {
        Self {
            machine_manager,
            machine_name: machine_name.into(),
        }
    }
}

impl StatsSource for AgentStatsSource {
    type Stream = AgentStatsStream;

    async fn open(&self) -> Result<AgentStatsStream> {
        let mut agent = self.machine_manager.connect_agent(&self.machine_name)?;
        agent
            .watch_stats(WatchStatsRequest {
                timeout_ms: u32::try_from(WATCH_WINDOW.as_millis()).unwrap_or(u32::MAX),
                interval_ms: u32::try_from(SAMPLE_INTERVAL.as_millis()).unwrap_or(u32::MAX),
                ..Default::default()
            })
            .await?;
        Ok(AgentStatsStream { agent })
    }
}

/// [`StatsStream`] over the agent's `WatchStats` frames.
pub struct AgentStatsStream {
    agent: crate::agent_client::AgentClient,
}

impl StatsStream for AgentStatsStream {
    async fn next(&mut self, max_wait: Duration) -> Result<MachineStats> {
        self.agent.next_machine_stats(max_wait).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Source whose streams yield a fixed sample per call, counting opens.
    struct FakeSource {
        opens: Arc<AtomicUsize>,
    }

    struct FakeStream;

    impl StatsSource for FakeSource {
        type Stream = FakeStream;

        async fn open(&self) -> Result<FakeStream> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(FakeStream)
        }
    }

    impl StatsStream for FakeStream {
        async fn next(&mut self, _max_wait: Duration) -> Result<MachineStats> {
            // Pace the fake so a pump doesn't spin the executor.
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok(MachineStats {
                monotonic_ms: 1,
                ..Default::default()
            })
        }
    }

    fn hub_with_counter() -> (Arc<StatsHub<FakeSource>>, Arc<AtomicUsize>) {
        let opens = Arc::new(AtomicUsize::new(0));
        let hub = StatsHub::new(FakeSource {
            opens: Arc::clone(&opens),
        });
        (hub, opens)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_subscribers_share_one_stream() {
        let (hub, opens) = hub_with_counter();

        let mut a = hub.subscribe();
        let mut b = hub.subscribe();
        let sample_a = a.recv().await.unwrap();
        let sample_b = b.recv().await.unwrap();
        assert_eq!(sample_a.monotonic_ms, 1);
        assert_eq!(sample_b.monotonic_ms, 1);
        assert_eq!(opens.load(Ordering::SeqCst), 1, "one guest stream shared");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pump_stops_after_last_subscriber_and_restarts_on_next() {
        let (hub, opens) = hub_with_counter();

        let mut rx = hub.subscribe();
        rx.recv().await.unwrap();
        drop(rx);

        // The pump notices the empty channel on its next send/check and
        // clears the slot.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            {
                let state = hub.state.lock().unwrap();
                if state.sender.is_none() {
                    break;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "pump did not stop after last subscriber"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // A later subscriber gets a fresh pump (and a fresh guest stream).
        let mut rx = hub.subscribe();
        rx.recv().await.unwrap();
        assert_eq!(opens.load(Ordering::SeqCst), 2);
    }
}
