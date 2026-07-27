//! Per-job capture of runner output, shipped to the gateway as
//! [`RunnerLogChunk`]s for live viewing while the job runs.
//!
//! This is the one lossy path in the agent, and deliberately so. The attach
//! stream is a control plane: its heartbeat writes to a 64-slot egress channel
//! with a blocking send, and the gateway flips a machine `Offline` after 60s
//! without one — which stops placement offering it work. Runner output can
//! arrive orders of magnitude faster than that channel drains, so a sink that
//! queued or awaited would trade a machine's liveness for its logs. Instead
//! every write is admitted through a per-job rate budget and a non-blocking
//! `try_send`, and anything that does not fit is dropped and counted.
//!
//! Backpressure therefore never propagates back to the runner: a chatty job
//! loses log lines, not throughput, and the consumer sees the loss as a `seq`
//! gap plus a `dropped_bytes` count on the next chunk.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arcbox_fleet_proto::v1::{AttachRequest, RunnerLogChunk, attach_request};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

/// Largest payload a single chunk carries. Sized so one chunk is a comfortable
/// gRPC message and a burst of them still fits the egress channel.
const MAX_CHUNK_BYTES: usize = 32 * 1024;

/// Sustained per-job output rate. Well above what a normal CI job produces
/// (a verbose build is a few KiB/s), low enough that a runaway job printing in
/// a tight loop cannot saturate the machine's control stream.
const BUDGET_BYTES_PER_SEC: u64 = 256 * 1024;

/// Burst allowance on top of the sustained rate, so the bulk output of a
/// single build step is not shed just for arriving all at once.
const BUDGET_BURST_BYTES: u64 = 1024 * 1024;

/// Read buffer for [`JobLogSink::pipe`]. Matches the chunk size so a full read
/// maps to exactly one chunk.
const PIPE_BUFFER_BYTES: usize = MAX_CHUNK_BYTES;

/// Captures one job's output and ships it as [`RunnerLogChunk`]s.
///
/// Cheap to clone — a job's stdout and stderr readers share one sink, so their
/// interleaving on the wire matches the order the agent observed, and `seq`
/// stays monotonic across both.
#[derive(Clone)]
pub struct JobLogSink {
    inner: Arc<Inner>,
}

struct Inner {
    /// Prefixed runner job id (`rjob_...`) stamped on every chunk.
    job_id: String,
    /// Log-only egress channel, separate from the supervisor's event channel so
    /// output can never occupy a slot a verdict or heartbeat needs.
    tx: mpsc::Sender<AttachRequest>,
    /// Next chunk's sequence number. Consumed even by a chunk that fails to
    /// send, so a drop shows up downstream as a gap.
    seq: AtomicU64,
    /// Bytes shed since the last chunk that went out, reported on the next one.
    dropped: AtomicU64,
    budget: Mutex<TokenBucket>,
}

impl JobLogSink {
    /// Open a sink for `job_id` feeding `tx`.
    pub fn new(job_id: &str, tx: mpsc::Sender<AttachRequest>) -> Self {
        Self {
            inner: Arc::new(Inner {
                job_id: job_id.to_owned(),
                tx,
                seq: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                budget: Mutex::new(TokenBucket::new()),
            }),
        }
    }

    /// A sink with no receiver, so every write is shed. For tests that drive a
    /// runner path without asserting on its output.
    #[cfg(test)]
    pub fn discarding() -> Self {
        let (tx, _) = mpsc::channel(1);
        Self::new("rjob_test", tx)
    }

    /// Ship `data` as one or more chunks. Never blocks and never fails: bytes
    /// that exceed the rate budget, or that meet a full channel, are counted
    /// into the next chunk's `dropped_bytes` instead.
    pub fn write(&self, data: &[u8]) {
        for slice in data.chunks(MAX_CHUNK_BYTES) {
            self.write_chunk(slice);
        }
    }

    fn write_chunk(&self, slice: &[u8]) {
        let len = slice.len() as u64;
        if !self
            .inner
            .budget
            .lock()
            .expect("budget mutex poisoned")
            .take(len)
        {
            self.inner.dropped.fetch_add(len, Ordering::Relaxed);
            return;
        }
        // Read rather than swap: the count must survive a failed send, and
        // only the chunk that actually goes out may clear it.
        let reported = self.inner.dropped.load(Ordering::Relaxed);
        let chunk = RunnerLogChunk {
            job_id: self.inner.job_id.clone(),
            seq: self.inner.seq.fetch_add(1, Ordering::Relaxed),
            data: slice.to_vec(),
            dropped_bytes: reported,
        };
        let message = AttachRequest {
            msg: Some(attach_request::Msg::RunnerLog(chunk)),
        };
        match self.inner.tx.try_send(message) {
            // Subtract rather than store 0: a concurrent writer may have added
            // to the count between the load above and here.
            Ok(()) => {
                self.inner.dropped.fetch_sub(reported, Ordering::Relaxed);
            }
            Err(_) => {
                self.inner.dropped.fetch_add(len, Ordering::Relaxed);
            }
        }
    }

    /// Drain `reader` into this sink until EOF, in a detached task.
    ///
    /// Detaching is deliberate and matches the lifetime of what is being read:
    /// the reader is a pipe from the runner process, so it reaches EOF when
    /// that process exits or is torn down, and the task ends with it. A read
    /// error ends the task too — a broken pipe is teardown, not a fault.
    pub fn pipe<R>(&self, mut reader: R)
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let sink = self.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; PIPE_BUFFER_BYTES];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => sink.write(&buffer[..read]),
                }
            }
        });
    }
}

/// Leaky-bucket rate limiter over bytes, refilled continuously from elapsed
/// wall time. Holding the lock never spans an await — every caller is the
/// synchronous [`JobLogSink::write_chunk`].
struct TokenBucket {
    tokens: u64,
    last: Instant,
}

impl TokenBucket {
    fn new() -> Self {
        Self {
            // Start full so a short job's entire output is admitted.
            tokens: BUDGET_BURST_BYTES,
            last: Instant::now(),
        }
    }

    /// Admit `want` bytes, or refuse them outright. Never partially admits:
    /// a chunk is shed whole so the reported byte count stays exact.
    fn take(&mut self, want: u64) -> bool {
        self.refill(Instant::now());
        if self.tokens >= want {
            self.tokens -= want;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        let refilled = (elapsed * BUDGET_BYTES_PER_SEC as f64) as u64;
        self.tokens = self.tokens.saturating_add(refilled).min(BUDGET_BURST_BYTES);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pull every chunk currently queued, as `(seq, data, dropped_bytes)`.
    fn drain(rx: &mut mpsc::Receiver<AttachRequest>) -> Vec<(u64, Vec<u8>, u64)> {
        let mut chunks = Vec::new();
        while let Ok(message) = rx.try_recv() {
            match message.msg {
                Some(attach_request::Msg::RunnerLog(chunk)) => {
                    chunks.push((chunk.seq, chunk.data, chunk.dropped_bytes));
                }
                other => panic!("expected RunnerLog, got {other:?}"),
            }
        }
        chunks
    }

    #[tokio::test]
    async fn splits_oversized_writes_and_numbers_them_in_order() {
        let (tx, mut rx) = mpsc::channel(16);
        let sink = JobLogSink::new("rjob_a", tx);

        sink.write(&vec![b'x'; MAX_CHUNK_BYTES + 1]);

        let chunks = drain(&mut rx);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1.len(), MAX_CHUNK_BYTES);
        assert_eq!(chunks[1].0, 1);
        assert_eq!(chunks[1].1.len(), 1);
        assert!(chunks.iter().all(|(_, _, dropped)| *dropped == 0));
    }

    /// A full channel must not block or error — the bytes are shed and
    /// reported on the next chunk that gets through, and the burnt sequence
    /// number leaves the gap that tells the consumer output was lost.
    #[tokio::test]
    async fn full_channel_sheds_and_reports_on_the_next_chunk() {
        let (tx, mut rx) = mpsc::channel(1);
        let sink = JobLogSink::new("rjob_a", tx);

        sink.write(b"first");
        sink.write(b"lost");

        // Free the single slot, then send again: the drop is now reportable.
        let queued = drain(&mut rx);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0], (0, b"first".to_vec(), 0));

        sink.write(b"third");
        let chunks = drain(&mut rx);
        assert_eq!(chunks.len(), 1);
        let (seq, data, dropped) = &chunks[0];
        assert_eq!(*seq, 2, "the shed chunk burnt seq 1, leaving a gap");
        assert_eq!(data, b"third");
        assert_eq!(*dropped, 4, "the shed \"lost\" bytes are reported here");
    }

    /// Sustained output past the burst allowance is shed rather than queued,
    /// so a runaway job cannot grow the agent's memory or stall the stream.
    #[tokio::test]
    async fn output_beyond_the_burst_allowance_is_shed() {
        let (tx, mut rx) = mpsc::channel(1024);
        let sink = JobLogSink::new("rjob_a", tx);

        let over_budget = (BUDGET_BURST_BYTES as usize) + (4 * MAX_CHUNK_BYTES);
        sink.write(&vec![b'x'; over_budget]);

        let chunks = drain(&mut rx);
        let admitted: usize = chunks.iter().map(|(_, data, _)| data.len()).sum();
        assert!(
            admitted <= BUDGET_BURST_BYTES as usize + MAX_CHUNK_BYTES,
            "admitted {admitted} bytes, above the burst allowance"
        );
        assert!(admitted > 0, "the burst allowance must admit something");

        // The shed bytes are pending, reported once the budget refills.
        assert_eq!(
            sink.inner.dropped.load(Ordering::Relaxed) as usize,
            over_budget - admitted
        );
    }

    #[tokio::test]
    async fn pipe_forwards_reader_contents_until_eof() {
        let (tx, mut rx) = mpsc::channel(16);
        let sink = JobLogSink::new("rjob_a", tx.clone());

        sink.pipe(std::io::Cursor::new(b"runner output".to_vec()));
        // Drop the local sender so the channel closes once the piped task
        // finishes, making the drain below deterministic.
        drop(tx);
        drop(sink);

        let mut seen = Vec::new();
        while let Some(message) = rx.recv().await {
            match message.msg {
                Some(attach_request::Msg::RunnerLog(chunk)) => seen.extend(chunk.data),
                other => panic!("expected RunnerLog, got {other:?}"),
            }
        }
        assert_eq!(seen, b"runner output");
    }
}
