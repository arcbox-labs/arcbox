//! Addressable, resumable workload executions (CORE-55).
//!
//! An execution is a workload started inside a sandbox that outlives any
//! particular client connection. The manager retains offset-addressed
//! stdout/stderr per execution so a client can disconnect, reconnect, and
//! resume both streams without loss, and gives the process an identity that
//! can be written to, signalled, resized, and awaited independently of any
//! stream. Stdin writes are offset-idempotent: a retried write of already
//! accepted bytes is deduplicated instead of double-fed to the process.

use std::collections::VecDeque;

use tokio::sync::{mpsc, watch};

use super::types::action;
use super::*;

/// Retained bytes per stdio channel. Older bytes are dropped and the buffer's
/// base offset advances; an attach below the base resumes from the earliest
/// retained byte (chunk offsets expose the gap to the client).
const CHANNEL_RETENTION: usize = 8 * 1024 * 1024;

/// How long an exited execution stays attachable/awaitable before it is
/// dropped from the registry.
const EXITED_RETENTION: Duration = Duration::from_secs(5 * 60);

/// Largest single chunk forwarded on an attach stream.
const ATTACH_CHUNK: usize = 64 * 1024;

/// Buffered chunks between an execution's buffers and one attach consumer.
const ATTACH_QUEUE: usize = 64;

/// How many times a start re-checks the registry after awaiting an identical
/// in-flight start. One round is the normal case.
const MAX_START_RESERVE_ROUNDS: usize = 8;

/// Parameters for starting an execution.
#[derive(Debug, Clone, Default)]
pub struct ExecutionSpec {
    /// Caller-supplied id for idempotent retry (auto-generated when `None`).
    pub id: Option<String>,
    /// Command and arguments.
    pub cmd: Vec<String>,
    /// Environment variable overrides.
    pub env: HashMap<String, String>,
    /// Working directory (empty = rootfs default).
    pub working_dir: String,
    /// User to run as (empty = root).
    pub user: String,
    /// Allocate a pseudo-TTY (stdout carries the merged PTY stream).
    pub tty: bool,
    /// Initial terminal size when `tty` is set.
    pub tty_size: Option<(u16, u16)>,
    /// Kill the process after this many seconds (0 = no timeout).
    pub timeout_seconds: u32,
    /// Keep stdin open for [`SandboxManager::write_stdin`]. When false the
    /// process starts with stdin already at EOF (run semantics).
    pub stdin: bool,
}

/// Point-in-time view of an execution.
#[derive(Debug, Clone)]
pub struct ExecutionSnapshot {
    /// Execution id, unique within its sandbox.
    pub id: String,
    /// Owning sandbox.
    pub sandbox_id: SandboxId,
    /// Whether the workload runs on a pseudo-TTY.
    pub tty: bool,
    /// When the workload was dispatched.
    pub started_at: DateTime<Utc>,
    /// When the workload terminated (`None` while running).
    pub exited_at: Option<DateTime<Utc>>,
    /// How the process terminated. `None` while running, and also when the
    /// session broke before an exit was observed (see `error`).
    pub exit_status: Option<ExitStatus>,
    /// Set when the session broke before the process reported an exit.
    pub error: Option<String>,
    /// Total bytes ever produced on stdout (monotonic, beyond retention).
    pub stdout_len: u64,
    /// Total bytes ever produced on stderr.
    pub stderr_len: u64,
    /// Stdin acceptance state.
    pub stdin: StdinState,
}

impl ExecutionSnapshot {
    /// True until the workload exits (or its session breaks).
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.exited_at.is_none()
    }
}

/// Which stdio channel an attach chunk belongs to. For TTY executions the
/// merged PTY stream arrives on `Stdout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionChannel {
    /// Standard output (or the PTY stream for `tty` executions).
    Stdout,
    /// Standard error (never produced by `tty` executions).
    Stderr,
}

/// One offset-addressed chunk delivered on an attach stream.
#[derive(Debug, Clone)]
pub struct ExecutionOutput {
    /// Source channel.
    pub channel: ExecutionChannel,
    /// Absolute offset of `data[0]` within the channel's byte stream. May be
    /// greater than the requested resume offset when retention dropped bytes.
    pub offset: u64,
    /// Raw output bytes.
    pub data: Vec<u8>,
}

/// Stdin acceptance state, the anchor for offset-resumable writes.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdinState {
    /// Bytes accepted and forwarded so far — the offset at which the next
    /// write must start.
    pub bytes_written: u64,
    /// Whether stdin has been closed.
    pub closed: bool,
}

/// Retained suffix of one stdio channel, addressed by absolute offsets.
#[derive(Default)]
struct ChannelBuffer {
    /// Absolute offset of `data[0]`.
    base: u64,
    data: VecDeque<u8>,
}

impl ChannelBuffer {
    /// One past the last retained byte — the channel's total length so far.
    fn end(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    fn append(&mut self, bytes: &[u8]) {
        self.data.extend(bytes);
        if self.data.len() > CHANNEL_RETENTION {
            let drop = self.data.len() - CHANNEL_RETENTION;
            self.data.drain(..drop);
            self.base += drop as u64;
        }
    }

    /// Read up to `max` bytes starting at `offset`, clamped to the retained
    /// range. Returns the actual start offset alongside the bytes.
    fn read_from(&self, offset: u64, max: usize) -> (u64, Vec<u8>) {
        let start = offset.max(self.base);
        if start >= self.end() {
            return (start, Vec::new());
        }
        // The buffer is capped at CHANNEL_RETENTION, so the skip fits usize.
        let skip = usize::try_from(start - self.base).expect("offset within retained buffer");
        let take = (self.data.len() - skip).min(max);
        let (front, back) = self.data.as_slices();
        let mut out = Vec::with_capacity(take);
        if skip < front.len() {
            let n = (front.len() - skip).min(take);
            out.extend_from_slice(&front[skip..skip + n]);
            out.extend_from_slice(&back[..take - n]);
        } else {
            let off = skip - front.len();
            out.extend_from_slice(&back[off..off + take]);
        }
        (start, out)
    }
}

/// Mutable state of one execution. Guarded by a std mutex; never held across
/// an await point.
#[derive(Default)]
struct ExecState {
    stdout: ChannelBuffer,
    stderr: ChannelBuffer,
    stdin_written: u64,
    stdin_closed: bool,
    exited_at: Option<DateTime<Utc>>,
    exit_status: Option<ExitStatus>,
    error: Option<String>,
}

/// A live or recently-exited execution.
pub(super) struct Execution {
    id: String,
    sandbox_id: SandboxId,
    tty: bool,
    started_at: DateTime<Utc>,
    /// The started command, kept to distinguish an idempotent start retry
    /// (same id, same command) from an id collision.
    cmd: Vec<String>,
    state: Mutex<ExecState>,
    /// Bumped after every state mutation; attach and wait subscribers park on
    /// it instead of polling.
    version: watch::Sender<u64>,
    /// Session input queue (stdin bytes / resize / signal / EOF).
    input_tx: mpsc::Sender<ExecInputMsg>,
    /// Serialises `write_stdin` offset accounting across concurrent callers.
    stdin_gate: tokio::sync::Mutex<()>,
}

impl Execution {
    fn new(
        id: String,
        sandbox_id: SandboxId,
        spec: &ExecutionSpec,
        input_tx: mpsc::Sender<ExecInputMsg>,
    ) -> Self {
        Self {
            id,
            sandbox_id,
            tty: spec.tty,
            started_at: Utc::now(),
            cmd: spec.cmd.clone(),
            state: Mutex::new(ExecState {
                stdin_closed: !spec.stdin,
                ..ExecState::default()
            }),
            version: watch::channel(0).0,
            input_tx,
            stdin_gate: tokio::sync::Mutex::new(()),
        }
    }

    fn snapshot(&self) -> ExecutionSnapshot {
        let st = self.state.lock().unwrap();
        ExecutionSnapshot {
            id: self.id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            tty: self.tty,
            started_at: self.started_at,
            exited_at: st.exited_at,
            exit_status: st.exit_status,
            error: st.error.clone(),
            stdout_len: st.stdout.end(),
            stderr_len: st.stderr.end(),
            stdin: StdinState {
                bytes_written: st.stdin_written,
                closed: st.stdin_closed,
            },
        }
    }

    fn bump(&self) {
        self.version.send_modify(|v| *v += 1);
    }

    /// Record the session's end and wake all subscribers. Idempotent: the
    /// first outcome wins (a teardown purge and the session's own exit path
    /// can race).
    fn mark_exited(&self, outcome: &std::result::Result<ExitStatus, String>) {
        let mut st = self.state.lock().unwrap();
        if st.exited_at.is_some() {
            return;
        }
        st.exited_at = Some(Utc::now());
        match outcome {
            Ok(status) => st.exit_status = Some(*status),
            Err(e) => st.error = Some(e.clone()),
        }
        drop(st);
        self.bump();
    }

    fn has_exited(&self) -> bool {
        self.state.lock().unwrap().exited_at.is_some()
    }

    /// Error for operations that need the workload alive.
    fn exited_error(&self) -> VmmError {
        VmmError::WrongState {
            id: format!("execution '{}'", self.id),
            expected: "running".into(),
            actual: "exited".into(),
        }
    }

    /// Spawn a forwarder that replays buffered output from the given offsets
    /// and follows live output until exit.
    fn attach(
        self: &Arc<Self>,
        stdout_offset: u64,
        stderr_offset: u64,
    ) -> (ExecutionSnapshot, mpsc::Receiver<ExecutionOutput>) {
        let snapshot = self.snapshot();
        let (tx, rx) = mpsc::channel(ATTACH_QUEUE);
        tokio::spawn(pump_attach(
            Arc::clone(self),
            stdout_offset,
            stderr_offset,
            tx,
        ));
        (snapshot, rx)
    }

    /// Offset-idempotent stdin write; see [`SandboxManager::write_stdin`].
    async fn write_stdin(&self, offset: u64, data: &[u8], eof: bool) -> Result<StdinState> {
        if eof && self.tty {
            return Err(VmmError::Config(
                "cannot close stdin of a TTY execution; send Ctrl-D (0x04) instead".into(),
            ));
        }
        // One writer at a time: the accept-forward-account sequence below
        // must not interleave between concurrent callers.
        let _gate = self.stdin_gate.lock().await;

        let fresh = {
            let st = self.state.lock().unwrap();
            if st.exited_at.is_some() {
                return Err(self.exited_error());
            }
            if offset > st.stdin_written {
                return Err(VmmError::StdinGap {
                    accepted: st.stdin_written,
                    offset,
                });
            }
            let overlap = st.stdin_written - offset;
            if overlap >= data.len() as u64 {
                // Pure retry of already-accepted bytes.
                Vec::new()
            } else {
                if st.stdin_closed {
                    return Err(VmmError::Config("stdin is already closed".into()));
                }
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "overlap < data.len() which is usize"
                )]
                let skip = overlap as usize;
                data[skip..].to_vec()
            }
        };

        if !fresh.is_empty() {
            let accepted = fresh.len() as u64;
            self.input_tx
                .send(ExecInputMsg::Stdin(fresh))
                .await
                .map_err(|_| self.exited_error())?;
            self.state.lock().unwrap().stdin_written += accepted;
            self.bump();
        }
        if eof && !self.state.lock().unwrap().stdin_closed {
            // Best-effort: the process may exit between the check and the
            // send; the closed flag still records what the client asked for.
            let _ = self.input_tx.send(ExecInputMsg::Eof).await;
            self.state.lock().unwrap().stdin_closed = true;
            self.bump();
        }

        Ok(self.snapshot().stdin)
    }

    /// Deliver a POSIX signal to the running workload's process group.
    async fn signal(&self, signal: i32) -> Result<()> {
        if !(1..=64).contains(&signal) {
            return Err(VmmError::Config(format!("invalid signal {signal}")));
        }
        if self.has_exited() {
            return Err(self.exited_error());
        }
        self.input_tx
            .send(ExecInputMsg::Signal(signal))
            .await
            .map_err(|_| self.exited_error())
    }

    /// Resize the workload's pseudo-TTY.
    async fn resize(&self, width: u16, height: u16) -> Result<()> {
        if !self.tty {
            return Err(VmmError::Config("execution has no TTY to resize".into()));
        }
        if self.has_exited() {
            return Err(self.exited_error());
        }
        self.input_tx
            .send(ExecInputMsg::Resize { width, height })
            .await
            .map_err(|_| self.exited_error())
    }

    /// Wait until the workload exits or `timeout` elapses; zero polls.
    async fn wait(&self, timeout: Duration) -> ExecutionSnapshot {
        let mut version = self.version.subscribe();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Mark the version seen before inspecting state, so a mutation in
            // between leaves a pending change notification.
            version.borrow_and_update();
            if self.has_exited() || timeout.is_zero() {
                return self.snapshot();
            }
            if tokio::time::timeout_at(deadline, version.changed())
                .await
                .is_err()
            {
                return self.snapshot();
            }
        }
    }
}

type ExecKey = (SandboxId, String);

/// Registry of executions, keyed by `(sandbox_id, execution_id)`.
#[derive(Default)]
pub(super) struct ExecutionRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    live: HashMap<ExecKey, Arc<Execution>>,
    /// Keys reserved by an in-flight start, so a duplicate id can never
    /// dispatch a second process (mirrors `reserve_id` for sandboxes).
    pending: HashMap<ExecKey, PendingStart>,
}

/// A start that has reserved its key but not finished dispatching.
struct PendingStart {
    /// The command being started, so a retry can tell an idempotent replay
    /// from an id collision before the execution exists.
    cmd: Vec<String>,
    /// Fires once the start commits or unwinds, waking matching retries.
    done: watch::Sender<bool>,
}

/// Outcome of reserving an execution slot.
enum Reserve {
    /// The id already ran this exact command — an idempotent start retry.
    Existing(ExecutionSnapshot),
    /// The slot is reserved; commit or drop to release.
    Slot(SlotGuard),
    /// An identical start is still in flight; await it, then re-reserve.
    AwaitPending(watch::Receiver<bool>),
}

/// RAII reservation for an execution key; removed on drop unless committed.
struct SlotGuard {
    registry: Arc<ExecutionRegistry>,
    key: ExecKey,
    committed: bool,
}

impl SlotGuard {
    fn commit(mut self, exec: &Arc<Execution>) {
        let mut inner = self.registry.inner.lock().unwrap();
        let pending = inner.pending.remove(&self.key);
        inner.live.insert(self.key.clone(), Arc::clone(exec));
        drop(inner);
        // Wake matching retries only after the execution is visible, so the
        // one that wakes finds it live rather than racing back to pending.
        if let Some(pending) = pending {
            let _ = pending.done.send(true);
        }
        self.committed = true;
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        if !self.committed {
            let pending = self
                .registry
                .inner
                .lock()
                .unwrap()
                .pending
                .remove(&self.key);
            if let Some(pending) = pending {
                let _ = pending.done.send(true);
            }
        }
    }
}

impl ExecutionRegistry {
    fn reserve(self: &Arc<Self>, key: ExecKey, cmd: &[String]) -> Result<Reserve> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(existing) = inner.live.get(&key) {
            if existing.cmd == cmd {
                return Ok(Reserve::Existing(existing.snapshot()));
            }
            return Err(VmmError::AlreadyExists(format!(
                "execution '{}' (id reused for a different command)",
                key.1
            )));
        }
        if let Some(pending) = inner.pending.get(&key) {
            if pending.cmd == cmd {
                // A retry inside the start window is still an idempotent
                // retry: wait for the original rather than failing, or the
                // contract only holds once the process is already running.
                return Ok(Reserve::AwaitPending(pending.done.subscribe()));
            }
            return Err(VmmError::AlreadyExists(format!(
                "execution '{}' (id reused for a different command)",
                key.1
            )));
        }
        inner.pending.insert(
            key.clone(),
            PendingStart {
                cmd: cmd.to_vec(),
                done: watch::channel(false).0,
            },
        );
        Ok(Reserve::Slot(SlotGuard {
            registry: Arc::clone(self),
            key,
            committed: false,
        }))
    }

    fn get(&self, sandbox_id: &str, execution_id: &str) -> Result<Arc<Execution>> {
        self.inner
            .lock()
            .unwrap()
            .live
            .get(&(sandbox_id.to_owned(), execution_id.to_owned()))
            .cloned()
            .ok_or_else(|| {
                VmmError::NotFound(format!(
                    "execution '{execution_id}' in sandbox '{sandbox_id}'"
                ))
            })
    }

    /// Snapshots of every retained execution of one sandbox — running and
    /// exited, until the retention GC drops them.
    fn list(&self, sandbox_id: &str) -> Vec<ExecutionSnapshot> {
        self.inner
            .lock()
            .unwrap()
            .live
            .iter()
            .filter(|((sid, _), _)| sid == sandbox_id)
            .map(|(_, exec)| exec.snapshot())
            .collect()
    }

    /// Remove `exec`'s entry if it is still the registered generation.
    fn remove_generation(&self, exec: &Arc<Execution>) {
        let key = (exec.sandbox_id.clone(), exec.id.clone());
        let mut inner = self.inner.lock().unwrap();
        if inner.live.get(&key).is_some_and(|e| Arc::ptr_eq(e, exec)) {
            inner.live.remove(&key);
        }
    }

    /// Mark every still-running execution of a sandbox as torn down so
    /// parked attach/wait subscribers resolve. Entries stay registered —
    /// their buffered output remains readable until the per-execution
    /// retention GC drops them.
    fn interrupt_sandbox(&self, sandbox_id: &str) {
        let executions: Vec<Arc<Execution>> = {
            let inner = self.inner.lock().unwrap();
            inner
                .live
                .iter()
                .filter(|((sid, _), _)| sid == sandbox_id)
                .map(|(_, exec)| Arc::clone(exec))
                .collect()
        };
        for exec in executions {
            exec.mark_exited(&Err("sandbox stopped".to_owned()));
        }
    }
}

/// Interrupt executions when their sandbox reaches a terminal state. Covers
/// every teardown path (stop, remove, TTL expiry, boot failure) without
/// threading the registry through each of them.
pub(super) fn spawn_teardown_purge(
    registry: Arc<ExecutionRegistry>,
    mut events: broadcast::Receiver<SandboxEvent>,
) {
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ev) if ev.is_terminal() => {
                    registry.interrupt_sandbox(&ev.sandbox_id);
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

/// Flip a sandbox whose execution session broke (no exit observed) back to
/// `Ready` and announce the interruption. The guest vm-agent kills the
/// workload when its host connection drops, so `Ready` is accurate.
fn abort_workload(
    id: &SandboxId,
    error: &str,
    instances: &InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
) {
    let arc = instances.read().unwrap().get(id).cloned();
    if let Some(arc) = arc {
        let mut inst = arc.lock().unwrap();
        inst.last_exited_at = Some(Utc::now());
        if inst.state == SandboxState::Running {
            inst.state = SandboxState::Ready;
        }
    }
    let _ = events_tx.send(SandboxEvent::new(id, action::IDLE).with_attr("error", error));
}

/// Drain a session's output into the execution's buffers until it exits,
/// then keep the exited record around for late attach/wait before GC.
async fn run_session(
    exec: Arc<Execution>,
    mut output_rx: mpsc::Receiver<Result<OutputChunk>>,
    instances: InstanceMap,
    events_tx: broadcast::Sender<SandboxEvent>,
    registry: Arc<ExecutionRegistry>,
) {
    let outcome: std::result::Result<ExitStatus, String> = loop {
        match output_rx.recv().await {
            Some(Ok(OutputChunk::Stdout(data))) => {
                exec.state.lock().unwrap().stdout.append(&data);
                exec.bump();
            }
            Some(Ok(OutputChunk::Stderr(data))) => {
                exec.state.lock().unwrap().stderr.append(&data);
                exec.bump();
            }
            Some(Ok(OutputChunk::Exit(status))) => break Ok(status),
            Some(Err(e)) => break Err(e.to_string()),
            None => break Err("execution session closed before exit".to_owned()),
        }
    };

    match &outcome {
        Ok(status) => {
            super::workload::finish_workload(&exec.sandbox_id, *status, &instances, &events_tx);
        }
        Err(e) => {
            warn!(sandbox_id = %exec.sandbox_id, execution_id = %exec.id, error = %e,
                  "execution session broke before exit");
            abort_workload(&exec.sandbox_id, e, &instances, &events_tx);
        }
    }
    exec.mark_exited(&outcome);

    tokio::time::sleep(EXITED_RETENTION).await;
    registry.remove_generation(&exec);
}

impl SandboxManager {
    /// Start an execution inside a `Ready` sandbox.
    ///
    /// The execution id (caller-supplied or generated) addresses the process
    /// afterwards: attach, stdin writes, signals, resize, and wait all go
    /// through it. Retrying a start with the same id and command returns the
    /// existing execution instead of dispatching a second process.
    pub async fn start_execution(
        &self,
        sandbox_id: &SandboxId,
        spec: ExecutionSpec,
    ) -> Result<ExecutionSnapshot> {
        let id = match &spec.id {
            Some(id) if !id.is_empty() => {
                super::validate_id("execution id", id)?;
                id.clone()
            }
            _ => Uuid::new_v4().to_string(),
        };
        if spec.cmd.is_empty() {
            return Err(VmmError::Config(
                "execution command must not be empty".into(),
            ));
        }

        // Resolve the reservation, awaiting an identical in-flight start
        // rather than failing it. One await is the normal case (the original
        // commits or unwinds); the bound only stops a pathological interleave
        // of repeated failing starts from spinning here forever.
        let mut slot = None;
        for _ in 0..MAX_START_RESERVE_ROUNDS {
            match self
                .executions
                .reserve((sandbox_id.clone(), id.clone()), &spec.cmd)?
            {
                Reserve::Existing(snapshot) => return Ok(snapshot),
                Reserve::Slot(guard) => {
                    slot = Some(guard);
                    break;
                }
                Reserve::AwaitPending(mut done) => {
                    let _ = done.changed().await;
                }
            }
        }
        let Some(slot) = slot else {
            return Err(VmmError::AlreadyExists(format!(
                "execution '{id}' (concurrent starts did not settle)"
            )));
        };

        let vsock = self.require_ready_vsock(sandbox_id)?;
        let start = StartCommand {
            cmd: spec.cmd.clone(),
            env: spec.env.clone(),
            working_dir: spec.working_dir.clone(),
            user: spec.user.clone(),
            tty: spec.tty,
            tty_width: spec.tty_size.map_or(80, |(w, _)| w),
            tty_height: spec.tty_size.map_or(24, |(_, h)| h),
            timeout_seconds: spec.timeout_seconds,
        };

        // Claim the sandbox (Ready → Running) before dispatching, so a losing
        // racer never launches a process (same discipline as workload.rs).
        super::workload::claim_running(sandbox_id, &self.instances)?;

        let (input_tx, output_rx) = match vsock::exec(vsock.as_ref(), start).await {
            Ok(pair) => pair,
            Err(e) => {
                super::workload::release_running(sandbox_id, &self.instances);
                return Err(e);
            }
        };
        if !spec.stdin && !spec.tty {
            // Run semantics: the process starts with stdin at EOF. TTY
            // executions are exempt — a PTY has no out-of-band EOF, and the
            // vm-agent's TTY session stops reading input frames (signals,
            // resizes) once it sees one.
            let _ = input_tx.send(ExecInputMsg::Eof).await;
        }

        let exec = Arc::new(Execution::new(id, sandbox_id.clone(), &spec, input_tx));
        slot.commit(&exec);
        let _ = self
            .events_tx
            .send(SandboxEvent::new(sandbox_id, action::RUNNING));

        tokio::spawn(run_session(
            Arc::clone(&exec),
            output_rx,
            Arc::clone(&self.instances),
            self.events_tx.clone(),
            Arc::clone(&self.executions),
        ));

        Ok(exec.snapshot())
    }

    /// Attach to an execution's output from the given per-channel offsets.
    ///
    /// The receiver yields buffered output first (starting at the earliest
    /// retained byte if retention already dropped the requested offset), then
    /// live output, and closes once the execution has exited and both
    /// channels are drained. Read the final state with
    /// [`SandboxManager::wait_execution`] afterwards.
    pub fn attach_execution(
        &self,
        sandbox_id: &str,
        execution_id: &str,
        stdout_offset: u64,
        stderr_offset: u64,
    ) -> Result<(ExecutionSnapshot, mpsc::Receiver<ExecutionOutput>)> {
        let exec = self.executions.get(sandbox_id, execution_id)?;
        Ok(exec.attach(stdout_offset, stderr_offset))
    }

    /// Write stdin bytes at an absolute offset (offset-idempotent).
    ///
    /// Bytes below the accepted count are deduplicated so a retried write
    /// never double-feeds the process; an offset beyond the accepted count is
    /// a gap and is rejected with the resume point. `eof` closes stdin after
    /// the write — rejected for TTY executions, where EOF is a byte (Ctrl-D)
    /// the client sends through the stream itself.
    pub async fn write_stdin(
        &self,
        sandbox_id: &str,
        execution_id: &str,
        offset: u64,
        data: &[u8],
        eof: bool,
    ) -> Result<StdinState> {
        self.executions
            .get(sandbox_id, execution_id)?
            .write_stdin(offset, data, eof)
            .await
    }

    /// Current stdin acceptance state — the resume point after a lost write.
    pub fn stdin_status(&self, sandbox_id: &str, execution_id: &str) -> Result<StdinState> {
        Ok(self
            .executions
            .get(sandbox_id, execution_id)?
            .snapshot()
            .stdin)
    }

    /// Deliver a POSIX signal to a running execution's process group.
    pub async fn signal_execution(
        &self,
        sandbox_id: &str,
        execution_id: &str,
        signal: i32,
    ) -> Result<()> {
        self.executions
            .get(sandbox_id, execution_id)?
            .signal(signal)
            .await
    }

    /// Resize a running TTY execution's terminal.
    pub async fn resize_execution(
        &self,
        sandbox_id: &str,
        execution_id: &str,
        width: u16,
        height: u16,
    ) -> Result<()> {
        self.executions
            .get(sandbox_id, execution_id)?
            .resize(width, height)
            .await
    }

    /// Wait until an execution exits or `timeout` elapses, then return its
    /// state. A zero timeout polls the current state.
    pub async fn wait_execution(
        &self,
        sandbox_id: &str,
        execution_id: &str,
        timeout: Duration,
    ) -> Result<ExecutionSnapshot> {
        Ok(self
            .executions
            .get(sandbox_id, execution_id)?
            .wait(timeout)
            .await)
    }

    /// List a sandbox's retained executions, running and exited, ordered by
    /// start time (then id, for a stable order under equal timestamps).
    ///
    /// The sandbox must exist; an unknown id is `NotFound` rather than an
    /// empty list, so a caller can tell "no executions" from a typo.
    pub fn list_executions(&self, sandbox_id: &SandboxId) -> Result<Vec<ExecutionSnapshot>> {
        self.get_instance(sandbox_id)?;
        let mut snapshots = self.executions.list(sandbox_id);
        snapshots.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(snapshots)
    }

    /// Wait until something inside an alive sandbox listens on TCP `port`,
    /// or fail with [`VmmError::DeadlineExceeded`] once `timeout` elapses.
    ///
    /// The vm-agent watches the guest's own listen table in-process — no
    /// connect probes that would perturb the workload with spurious
    /// accepted connections.
    pub async fn wait_sandbox_port(
        &self,
        id: &SandboxId,
        port: u16,
        timeout: Duration,
    ) -> Result<()> {
        let vsock = self.require_alive_vsock(id)?;
        match vsock::wait_for_port(vsock.as_ref(), port, timeout).await? {
            crate::vsock::PortWait::Listening => Ok(()),
            crate::vsock::PortWait::Deadline => Err(VmmError::DeadlineExceeded(format!(
                "no listener on port {port} in sandbox '{id}' within {}s",
                timeout.as_secs()
            ))),
        }
    }
}

/// Forward buffered + live output to one attach consumer.
async fn pump_attach(
    exec: Arc<Execution>,
    mut stdout_cursor: u64,
    mut stderr_cursor: u64,
    tx: mpsc::Sender<ExecutionOutput>,
) {
    let mut version = exec.version.subscribe();
    loop {
        // Mark the version seen before reading, so an append between the read
        // and the wait below leaves a pending change notification.
        version.borrow_and_update();
        loop {
            let (chunk, exited) = {
                let st = exec.state.lock().unwrap();
                let (start, data) = st.stdout.read_from(stdout_cursor, ATTACH_CHUNK);
                if data.is_empty() {
                    let (start, data) = st.stderr.read_from(stderr_cursor, ATTACH_CHUNK);
                    if data.is_empty() {
                        (None, st.exited_at.is_some())
                    } else {
                        stderr_cursor = start + data.len() as u64;
                        (
                            Some(ExecutionOutput {
                                channel: ExecutionChannel::Stderr,
                                offset: start,
                                data,
                            }),
                            false,
                        )
                    }
                } else {
                    stdout_cursor = start + data.len() as u64;
                    (
                        Some(ExecutionOutput {
                            channel: ExecutionChannel::Stdout,
                            offset: start,
                            data,
                        }),
                        false,
                    )
                }
            };
            match chunk {
                Some(chunk) => {
                    if tx.send(chunk).await.is_err() {
                        return; // consumer gone
                    }
                }
                None if exited => return, // drained past the exit
                None => break,            // caught up; wait for more
            }
        }
        // The sender lives inside `exec`, which we hold — never closed.
        let _ = version.changed().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stdin_spec() -> ExecutionSpec {
        ExecutionSpec {
            cmd: vec!["cat".into()],
            stdin: true,
            ..ExecutionSpec::default()
        }
    }

    fn test_execution(spec: &ExecutionSpec) -> (Arc<Execution>, mpsc::Receiver<ExecInputMsg>) {
        let (tx, rx) = mpsc::channel(8);
        let exec = Arc::new(Execution::new(
            "exec-1".into(),
            "sandbox-1".into(),
            spec,
            tx,
        ));
        (exec, rx)
    }

    #[test]
    fn channel_buffer_addresses_bytes_absolutely() {
        let mut buf = ChannelBuffer::default();
        buf.append(b"hello ");
        buf.append(b"world");
        assert_eq!(buf.end(), 11);

        let (start, data) = buf.read_from(0, 1024);
        assert_eq!((start, data.as_slice()), (0, b"hello world".as_slice()));

        let (start, data) = buf.read_from(6, 3);
        assert_eq!((start, data.as_slice()), (6, b"wor".as_slice()));

        // Reads at or past the end are empty at the requested offset.
        let (start, data) = buf.read_from(11, 1024);
        assert_eq!((start, data.len()), (11, 0));
    }

    #[test]
    fn channel_buffer_trims_to_retention_and_advances_base() {
        let mut buf = ChannelBuffer::default();
        let chunk = vec![7u8; CHANNEL_RETENTION];
        buf.append(&chunk);
        buf.append(b"tail");

        assert_eq!(buf.base, 4);
        assert_eq!(buf.end(), CHANNEL_RETENTION as u64 + 4);

        // A read below the base is clamped to the earliest retained byte —
        // the returned offset exposes the gap.
        let (start, data) = buf.read_from(0, 8);
        assert_eq!(start, 4);
        assert_eq!(data.len(), 8);
    }

    #[tokio::test]
    async fn write_stdin_dedupes_retries_and_rejects_gaps() {
        let (exec, mut rx) = test_execution(&stdin_spec());

        let st = exec.write_stdin(0, b"hello", false).await.unwrap();
        assert_eq!(st.bytes_written, 5);

        // Full retry of the same write: accepted, nothing re-forwarded.
        let st = exec.write_stdin(0, b"hello", false).await.unwrap();
        assert_eq!(st.bytes_written, 5);

        // Overlapping retry: only the unseen suffix is forwarded.
        let st = exec.write_stdin(3, b"lo world", false).await.unwrap();
        assert_eq!(st.bytes_written, 11);

        // A gap is rejected with the resume point.
        let err = exec.write_stdin(99, b"x", false).await.unwrap_err();
        assert!(matches!(err, VmmError::StdinGap { accepted: 11, .. }));

        // Exactly the deduplicated byte stream reached the process.
        let mut forwarded = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            match msg {
                ExecInputMsg::Stdin(data) => forwarded.extend_from_slice(&data),
                other => panic!("unexpected input message: {other:?}"),
            }
        }
        assert_eq!(forwarded, b"hello world");
    }

    #[tokio::test]
    async fn write_stdin_eof_closes_and_tty_rejects_eof() {
        let (exec, mut rx) = test_execution(&stdin_spec());

        let st = exec.write_stdin(0, b"in", true).await.unwrap();
        assert!(st.closed);
        assert!(matches!(rx.recv().await, Some(ExecInputMsg::Stdin(_))));
        assert!(matches!(rx.recv().await, Some(ExecInputMsg::Eof)));

        // Further data after EOF is rejected; a pure duplicate is not.
        let err = exec.write_stdin(2, b"more", false).await.unwrap_err();
        assert!(matches!(err, VmmError::Config(_)));
        let st = exec.write_stdin(0, b"in", false).await.unwrap();
        assert_eq!(st.bytes_written, 2);

        // TTY executions cannot close stdin via eof.
        let tty_spec = ExecutionSpec {
            tty: true,
            ..stdin_spec()
        };
        let (tty_exec, _tty_rx) = test_execution(&tty_spec);
        let err = tty_exec.write_stdin(0, b"", true).await.unwrap_err();
        assert!(matches!(err, VmmError::Config(_)));
    }

    #[tokio::test]
    async fn attach_replays_from_offsets_and_closes_after_exit() {
        let (exec, _rx) = test_execution(&stdin_spec());

        {
            let mut st = exec.state.lock().unwrap();
            st.stdout.append(b"out-data");
            st.stderr.append(b"err");
        }
        exec.bump();

        let (snapshot, mut out) = exec.attach(2, 0);
        assert!(snapshot.is_running());

        let first = out.recv().await.unwrap();
        assert_eq!(first.channel, ExecutionChannel::Stdout);
        assert_eq!(first.offset, 2);
        assert_eq!(first.data, b"t-data");
        let second = out.recv().await.unwrap();
        assert_eq!(second.channel, ExecutionChannel::Stderr);
        assert_eq!(second.offset, 0);
        assert_eq!(second.data, b"err");

        // Live append after the replay is delivered too.
        exec.state.lock().unwrap().stdout.append(b"+live");
        exec.bump();
        let live = out.recv().await.unwrap();
        assert_eq!(live.offset, 8);
        assert_eq!(live.data, b"+live");

        // Exit closes the stream once drained.
        exec.mark_exited(&Ok(ExitStatus::Code(0)));
        assert!(out.recv().await.is_none());

        let done = exec.wait(Duration::ZERO).await;
        assert_eq!(done.exit_status, Some(ExitStatus::Code(0)));
    }

    #[tokio::test]
    async fn wait_times_out_then_resolves_on_exit() {
        let (exec, _rx) = test_execution(&stdin_spec());

        // Zero timeout polls the running state.
        assert!(exec.wait(Duration::ZERO).await.is_running());
        // A short timeout returns the still-running state.
        assert!(exec.wait(Duration::from_millis(20)).await.is_running());

        // A concurrent exit resolves a parked wait.
        let exiter = {
            let exec = Arc::clone(&exec);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                exec.mark_exited(&Ok(ExitStatus::Signaled(9)));
            })
        };
        let snap = exec.wait(Duration::from_secs(5)).await;
        assert_eq!(snap.exit_status, Some(ExitStatus::Signaled(9)));
        exiter.await.unwrap();
    }

    #[tokio::test]
    async fn signal_and_resize_validate_state() {
        let (exec, mut rx) = test_execution(&stdin_spec());

        exec.signal(15).await.unwrap();
        assert!(matches!(rx.recv().await, Some(ExecInputMsg::Signal(15))));
        assert!(matches!(
            exec.signal(0).await.unwrap_err(),
            VmmError::Config(_)
        ));
        // Non-TTY executions have nothing to resize.
        assert!(matches!(
            exec.resize(80, 24).await.unwrap_err(),
            VmmError::Config(_)
        ));

        exec.mark_exited(&Ok(ExitStatus::Code(0)));
        assert!(matches!(
            exec.signal(9).await.unwrap_err(),
            VmmError::WrongState { .. }
        ));
    }

    #[tokio::test]
    async fn interrupt_sandbox_marks_running_executions_but_keeps_them_readable() {
        let registry = Arc::new(ExecutionRegistry::default());
        let (exec, _rx) = test_execution(&stdin_spec());
        registry
            .inner
            .lock()
            .unwrap()
            .live
            .insert(("sandbox-1".into(), "exec-1".into()), Arc::clone(&exec));

        registry.interrupt_sandbox("sandbox-1");
        // Still registered: buffered output stays readable until the
        // retention GC, but the execution is resolved as torn down.
        assert!(registry.get("sandbox-1", "exec-1").is_ok());
        let snap = exec.snapshot();
        assert!(!snap.is_running());
        assert_eq!(snap.error.as_deref(), Some("sandbox stopped"));

        // An already-exited execution keeps its original outcome.
        let (done, _rx2) = test_execution(&stdin_spec());
        done.mark_exited(&Ok(ExitStatus::Code(3)));
        registry
            .inner
            .lock()
            .unwrap()
            .live
            .insert(("sandbox-1".into(), "exec-2".into()), Arc::clone(&done));
        registry.interrupt_sandbox("sandbox-1");
        assert_eq!(done.snapshot().exit_status, Some(ExitStatus::Code(3)));
    }

    #[tokio::test]
    async fn start_reservation_is_idempotent_per_command() {
        let registry = Arc::new(ExecutionRegistry::default());
        let key = ("s".to_owned(), "e".to_owned());
        let cmd = vec!["echo".to_owned()];

        // Reserve → commit.
        let Reserve::Slot(slot) = registry.reserve(key.clone(), &cmd).unwrap() else {
            panic!("expected a fresh slot");
        };
        let (tx, _rx) = mpsc::channel(1);
        let exec = Arc::new(Execution::new(
            "e".into(),
            "s".into(),
            &ExecutionSpec {
                cmd: cmd.clone(),
                ..ExecutionSpec::default()
            },
            tx,
        ));
        slot.commit(&exec);

        // Same command → idempotent retry hands back the existing execution.
        assert!(matches!(
            registry.reserve(key.clone(), &cmd).unwrap(),
            Reserve::Existing(_)
        ));
        // Different command under the same id → collision.
        assert!(matches!(
            registry.reserve(key, &["other".to_owned()]),
            Err(VmmError::AlreadyExists(_))
        ));

        // While a start is in flight, a matching retry waits for it instead
        // of failing — the idempotency contract holds inside the start
        // window, not only once the process is already running. A differing
        // command is still a collision.
        let key2 = ("s".to_owned(), "e2".to_owned());
        {
            let Reserve::Slot(_slot) = registry.reserve(key2.clone(), &cmd).unwrap() else {
                panic!("expected a fresh slot");
            };
            assert!(matches!(
                registry.reserve(key2.clone(), &cmd).unwrap(),
                Reserve::AwaitPending(_)
            ));
            assert!(matches!(
                registry.reserve(key2.clone(), &["other".to_owned()]),
                Err(VmmError::AlreadyExists(_))
            ));
        }
        // A dropped (uncommitted) reservation frees the slot.
        assert!(matches!(
            registry.reserve(key2, &cmd).unwrap(),
            Reserve::Slot(_)
        ));
    }

    #[tokio::test]
    async fn a_pending_start_wakes_matching_retries_with_the_committed_execution() {
        let registry = Arc::new(ExecutionRegistry::default());
        let key = ("s".to_owned(), "e".to_owned());
        let cmd = vec!["sleep".to_owned()];

        let Reserve::Slot(slot) = registry.reserve(key.clone(), &cmd).unwrap() else {
            panic!("expected a fresh slot");
        };
        let Reserve::AwaitPending(mut waiter) = registry.reserve(key.clone(), &cmd).unwrap() else {
            panic!("a matching retry must await the in-flight start");
        };

        // Commit the original; the waiter must then see the live execution.
        let (tx, _rx) = mpsc::channel(1);
        let exec = Arc::new(Execution::new(
            "e".into(),
            "s".into(),
            &ExecutionSpec {
                cmd: cmd.clone(),
                ..ExecutionSpec::default()
            },
            tx,
        ));
        slot.commit(&exec);

        waiter.changed().await.expect("pending start signals");
        assert!(matches!(
            registry.reserve(key.clone(), &cmd).unwrap(),
            Reserve::Existing(_)
        ));

        // A start that unwinds instead wakes waiters too, and the key is
        // free for the retry to claim.
        let key2 = ("s".to_owned(), "e2".to_owned());
        let Reserve::Slot(failed) = registry.reserve(key2.clone(), &cmd).unwrap() else {
            panic!("expected a fresh slot");
        };
        let Reserve::AwaitPending(mut waiter) = registry.reserve(key2.clone(), &cmd).unwrap()
        else {
            panic!("a matching retry must await the in-flight start");
        };
        drop(failed);
        waiter.changed().await.expect("unwound start signals");
        assert!(matches!(
            registry.reserve(key2, &cmd).unwrap(),
            Reserve::Slot(_)
        ));
    }
}
