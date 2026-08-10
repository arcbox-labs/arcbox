//! Running commands inside one sandbox.
//!
//! [`Commands::run`] is the foreground form (start, collect output,
//! wait for the exit); [`Commands::spawn`] is the background form,
//! returning a [`CommandHandle`] whose output stream survives transport
//! drops by re-attaching at the retained byte offsets — the daemon
//! addresses output by offset, so nothing is lost or replayed.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{SandboxProcessServiceClient, execution_event, exit_status};
use connectrpc::client::{ClientTransport, ServerStream, SharedHttp2Connection};

use crate::client::ClientContext;
use crate::error::{Error, ErrorKind, Result};
use crate::types::seconds_to_wire;

/// The generated process client over the shared transport.
type ProcessClient = SandboxProcessServiceClient<SharedHttp2Connection>;

/// The server stream [`ProcessClient::attach_execution`] returns.
type AttachStream = ServerStream<
    <SharedHttp2Connection as ClientTransport>::ResponseBody,
    pb::__buffa::view::ExecutionEventView<'static>,
>;

/// Re-attach attempts before an output stream gives up — any received
/// event resets the budget, so this bounds *consecutive* dead dials.
const ATTACH_RESUME_ATTEMPTS: u32 = 3;

/// Backoff base between re-attach attempts (multiplied by the attempt).
const ATTACH_RESUME_BACKOFF: Duration = Duration::from_millis(200);

/// Wait slice for [`CommandHandle::wait`]: the daemon parks each
/// WaitExecution unary for at most this long, so an unbounded wait is a
/// sequence of bounded ones.
const WAIT_SLICE: Duration = Duration::from_secs(30);

/// What to run: an argv, or a shell line (`/bin/sh -lc`).
#[derive(Debug, Clone)]
pub enum Cmd {
    /// An argv, executed as-is.
    Argv(Vec<String>),
    /// A shell line, wrapped as `/bin/sh -lc <line>`.
    Shell(String),
}

impl From<&str> for Cmd {
    fn from(line: &str) -> Self {
        Self::Shell(line.to_owned())
    }
}

impl From<String> for Cmd {
    fn from(line: String) -> Self {
        Self::Shell(line)
    }
}

impl From<Vec<String>> for Cmd {
    fn from(argv: Vec<String>) -> Self {
        Self::Argv(argv)
    }
}

impl From<&[&str]> for Cmd {
    fn from(argv: &[&str]) -> Self {
        Self::Argv(argv.iter().map(|&arg| arg.to_owned()).collect())
    }
}

impl Cmd {
    fn into_argv(self) -> Vec<String> {
        match self {
            Self::Argv(argv) => argv,
            Self::Shell(line) => vec!["/bin/sh".to_owned(), "-lc".to_owned(), line],
        }
    }
}

/// Terminal geometry for a PTY command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    /// Terminal width in columns.
    pub cols: u32,
    /// Terminal height in rows.
    pub rows: u32,
}

/// What the command's stdin starts as.
#[derive(Debug, Clone, Default)]
pub enum Stdin {
    /// Closed from the start (the default).
    #[default]
    Closed,
    /// Write these bytes, then close.
    Data(Vec<u8>),
    /// Keep stdin open for [`CommandHandle::write_stdin`] — only
    /// meaningful with [`Commands::spawn`], which returns the handle.
    Open,
}

/// Options for [`Commands::run`] and [`Commands::spawn`].
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Working directory (unset = the daemon default).
    pub cwd: Option<String>,
    /// Extra environment for this command.
    pub env: BTreeMap<String, String>,
    /// User to run as (unset = the daemon default).
    pub user: Option<String>,
    /// Kill the process group after this long.
    pub timeout: Option<Duration>,
    /// Allocate a pseudo-terminal of this size. A terminal merges
    /// stdout and stderr into one [`Channel::Pty`] stream.
    pub pty: Option<PtySize>,
    /// The command's stdin (see [`Stdin`]).
    pub stdin: Stdin,
}

/// Signals deliverable to a command's process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signal {
    Hup,
    Int,
    Quit,
    Kill,
    Term,
}

impl Signal {
    fn to_wire(self) -> pb::Signal {
        match self {
            Self::Hup => pb::Signal::SIGNAL_SIGHUP,
            Self::Int => pb::Signal::SIGNAL_SIGINT,
            Self::Quit => pb::Signal::SIGNAL_SIGQUIT,
            Self::Kill => pb::Signal::SIGNAL_SIGKILL,
            Self::Term => pb::Signal::SIGNAL_SIGTERM,
        }
    }
}

/// Which stream a chunk of output belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stdout,
    Stderr,
    /// A terminal's merged stream, escape sequences included.
    Pty,
}

/// One chunk of command output.
#[derive(Debug, Clone)]
pub struct OutputChunk {
    pub channel: Channel,
    pub data: Vec<u8>,
}

/// A finished command. A non-zero exit is data, not an error.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CommandResult {
    /// Process exit code. When the process was killed by a signal this
    /// is `128 + signal` (shell convention) and [`signal`](Self::signal)
    /// is set.
    pub exit_code: i32,
    /// Signal name (`"SIGKILL"`) when the process died by one.
    pub signal: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandResult {
    /// Whether the command exited zero.
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// Stdout as text, invalid UTF-8 replaced.
    #[must_use]
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Stderr as text, invalid UTF-8 replaced.
    #[must_use]
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Lifecycle state of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandState {
    Running,
    Exited,
    Unknown,
}

/// One row of a command listing.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CommandInfo {
    pub command_id: String,
    /// Whether the command runs on a PTY.
    pub tty: bool,
    pub state: CommandState,
    /// Exit code, once exited (shell convention for signal deaths).
    pub exit_code: Option<i32>,
    /// Signal name, when the process died by one.
    pub signal: Option<String>,
    /// Daemon-reported failure, when the command could not run.
    pub error: Option<String>,
}

/// Stdin acceptance state of a command, as reported by the daemon.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct StdinStatus {
    /// Bytes accepted and forwarded so far — the offset the next stdin
    /// write starts at.
    pub bytes_written: u64,
    /// Whether stdin has been closed.
    pub closed: bool,
}

/// The `sandbox.commands()` namespace: run processes inside one sandbox.
#[derive(Clone)]
pub struct Commands {
    ctx: ClientContext,
    sandbox_id: String,
}

impl Commands {
    pub(crate) fn attached(ctx: ClientContext, sandbox_id: String) -> Self {
        Self { ctx, sandbox_id }
    }

    fn client(&self) -> ProcessClient {
        SandboxProcessServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
    }

    /// Run a command in the foreground: start it, collect its output,
    /// and return the result once it exits. A non-zero exit is data on
    /// the result, never an error.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidArgument`] for [`Stdin::Open`] (only a
    /// spawned handle can keep writing); otherwise any RPC failure.
    pub async fn run(&self, cmd: impl Into<Cmd>, options: RunOptions) -> Result<CommandResult> {
        if matches!(options.stdin, Stdin::Open) {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "Stdin::Open needs a handle to write through — use spawn()",
                "commands.run",
            ));
        }
        let handle = self.start(cmd.into(), options, "commands.run").await?;
        handle.wait(None).await
    }

    /// Start a command in the background and return its handle.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidArgument`] for [`Stdin::Data`] combined with
    /// a PTY (a terminal's input is interactive by nature); otherwise
    /// any RPC failure.
    pub async fn spawn(&self, cmd: impl Into<Cmd>, options: RunOptions) -> Result<CommandHandle> {
        self.start(cmd.into(), options, "commands.spawn").await
    }

    async fn start(
        &self,
        cmd: Cmd,
        options: RunOptions,
        operation: &'static str,
    ) -> Result<CommandHandle> {
        if options.pty.is_some() && matches!(options.stdin, Stdin::Data(_)) {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "one-shot stdin bytes and a PTY are mutually exclusive — a \
                 terminal's input is interactive; write through the handle",
                operation,
            ));
        }
        let execution_id = uuid::Uuid::new_v4().to_string();
        let stdin_open = !matches!(options.stdin, Stdin::Closed);
        let mut request = pb::StartExecutionRequest {
            sandbox_id: self.sandbox_id.clone(),
            execution_id: execution_id.clone(),
            cmd: cmd.into_argv(),
            env: options.env.into_iter().collect(),
            working_dir: options.cwd.unwrap_or_default(),
            user: options.user.unwrap_or_default(),
            timeout_seconds: seconds_to_wire(options.timeout),
            stdin: stdin_open,
            ..Default::default()
        };
        if let Some(size) = options.pty {
            request.tty = true;
            request.tty_size = pb::TerminalSize {
                width: size.cols,
                height: size.rows,
                ..Default::default()
            }
            .into();
        }
        self.client()
            .start_execution(request)
            .await
            .map_err(|error| Error::from_connect(error, operation))?;

        let handle = CommandHandle {
            ctx: self.ctx.clone(),
            sandbox_id: self.sandbox_id.clone(),
            command_id: execution_id,
            stdin_cursor: Arc::new(tokio::sync::Mutex::new(Some(0))),
        };
        if let Stdin::Data(data) = options.stdin {
            handle.write_stdin(&data).await?;
            handle.close_stdin().await?;
        }
        Ok(handle)
    }

    /// Take a handle on a command started elsewhere. The stdin cursor
    /// is seeded from the daemon, so writes resume at the accepted
    /// offset.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::ExecutionNotFound`] when no such command exists;
    /// otherwise any RPC failure.
    pub async fn get(&self, command_id: &str) -> Result<CommandHandle> {
        let execution = self
            .client()
            .wait_execution(pb::WaitExecutionRequest {
                sandbox_id: self.sandbox_id.clone(),
                execution_id: command_id.to_owned(),
                // 0 = answer with the current state immediately.
                timeout_seconds: 0,
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "commands.get"))?
            .into_owned();
        let accepted = execution
            .stdin
            .as_option()
            .map_or(0, |stdin| stdin.bytes_written);
        Ok(CommandHandle {
            ctx: self.ctx.clone(),
            sandbox_id: self.sandbox_id.clone(),
            command_id: command_id.to_owned(),
            stdin_cursor: Arc::new(tokio::sync::Mutex::new(Some(accepted))),
        })
    }

    /// List the sandbox's commands, running and exited.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn list(&self) -> Result<Vec<CommandInfo>> {
        let response = self
            .client()
            .list_executions(pb::ListExecutionsRequest {
                sandbox_id: self.sandbox_id.clone(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "commands.list"))?
            .into_owned();
        Ok(response
            .executions
            .into_iter()
            .map(info_from_wire)
            .collect())
    }
}

/// A running (or finished) command.
///
/// Cheap to clone; every clone addresses the same execution.
#[derive(Clone)]
pub struct CommandHandle {
    ctx: ClientContext,
    sandbox_id: String,
    command_id: String,
    /// The next stdin offset, serialized so concurrent writes cannot
    /// interleave their idempotency windows. `None` = unknown (a write
    /// failed mid-flight); the next write re-reads it from the daemon.
    stdin_cursor: Arc<tokio::sync::Mutex<Option<u64>>>,
}

impl CommandHandle {
    fn client(&self) -> ProcessClient {
        SandboxProcessServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
    }

    /// The execution id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.command_id
    }

    /// The command's output, one chunk at a time.
    ///
    /// The stream re-attaches at the retained byte offsets when the
    /// transport drops — output is offset-addressed daemon-side, so
    /// nothing is lost or replayed. It ends when the command exits.
    #[must_use]
    pub fn output(&self) -> OutputStream {
        OutputStream {
            handle: self.clone(),
            stream: None,
            stdout_offset: 0,
            stderr_offset: 0,
            attempts: 0,
            done: false,
            exited: None,
        }
    }

    /// Wait for the command to finish and return its result, output
    /// included. `timeout` bounds the wait ([`ErrorKind::Timeout`] on
    /// expiry; the command keeps running).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Timeout`] when `timeout` elapses first; otherwise
    /// any RPC failure.
    pub async fn wait(&self, timeout: Option<Duration>) -> Result<CommandResult> {
        match timeout {
            None => self.wait_inner().await,
            Some(deadline) => tokio::time::timeout(deadline, self.wait_inner())
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::Timeout,
                        format!(
                            "wait(timeout) elapsed before command {} exited",
                            self.command_id
                        ),
                        "commands.wait",
                    )
                    .with_suggestion("increase the wait timeout, or kill() the command")
                    .with_context("command_id", &*self.command_id)
                })?,
        }
    }

    async fn wait_inner(&self) -> Result<CommandResult> {
        // Collect the output; the stream ends when the command exits
        // and carries the exit through its final event.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut output = self.output();
        while let Some(chunk) = output.next().await? {
            match chunk.channel {
                Channel::Stderr => stderr.extend_from_slice(&chunk.data),
                // A terminal merges the streams; deliver as stdout.
                Channel::Stdout | Channel::Pty => stdout.extend_from_slice(&chunk.data),
            }
        }
        if let Some(execution) = output.exited.take() {
            return Ok(result_from_wire(&execution, stdout, stderr));
        }
        // The stream ended without an exit event (attach gave up, or
        // the daemon closed early): the authoritative wait decides.
        loop {
            let execution = self
                .client()
                .wait_execution(pb::WaitExecutionRequest {
                    sandbox_id: self.sandbox_id.clone(),
                    execution_id: self.command_id.clone(),
                    timeout_seconds: seconds_to_wire(Some(WAIT_SLICE)),
                    ..Default::default()
                })
                .await
                .map_err(|error| Error::from_connect(error, "commands.wait"))?
                .into_owned();
            if execution.state.as_known() == Some(pb::ExecutionState::EXECUTION_STATE_EXITED) {
                return Ok(result_from_wire(&execution, stdout, stderr));
            }
        }
    }

    /// Feed bytes to the command's stdin.
    ///
    /// Writes are offset-idempotent: each carries the byte offset it
    /// starts at, the daemon dedups anything below its accepted count,
    /// and concurrent writes are serialized here — so a retried write
    /// can never double-deliver.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::StdinClosed`] once stdin is closed; otherwise any
    /// RPC failure.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<()> {
        let mut cursor = self.stdin_cursor.lock().await;
        let offset = match *cursor {
            Some(offset) => offset,
            // A previous write failed mid-flight; the daemon's accepted
            // count is the truth.
            None => self.stdin_status_inner().await?.bytes_written,
        };
        match self
            .client()
            .write_stdin(pb::WriteStdinRequest {
                sandbox_id: self.sandbox_id.clone(),
                execution_id: self.command_id.clone(),
                offset,
                data: data.to_vec(),
                ..Default::default()
            })
            .await
        {
            Ok(status) => {
                *cursor = Some(status.into_owned().bytes_written);
                Ok(())
            }
            Err(error) => {
                *cursor = None;
                Err(Error::from_connect(error, "commands.write_stdin"))
            }
        }
    }

    /// Close the command's stdin.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn close_stdin(&self) -> Result<()> {
        let mut cursor = self.stdin_cursor.lock().await;
        let offset = match *cursor {
            Some(offset) => offset,
            None => self.stdin_status_inner().await?.bytes_written,
        };
        self.client()
            .write_stdin(pb::WriteStdinRequest {
                sandbox_id: self.sandbox_id.clone(),
                execution_id: self.command_id.clone(),
                offset,
                eof: true,
                ..Default::default()
            })
            .await
            .map_err(|error| {
                *cursor = None;
                Error::from_connect(error, "commands.close_stdin")
            })?;
        Ok(())
    }

    /// Stdin acceptance state, as the daemon reports it.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn stdin_status(&self) -> Result<StdinStatus> {
        self.stdin_status_inner().await
    }

    async fn stdin_status_inner(&self) -> Result<StdinStatus> {
        let status = self
            .client()
            .get_stdin_status(pb::GetStdinStatusRequest {
                sandbox_id: self.sandbox_id.clone(),
                execution_id: self.command_id.clone(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "commands.stdin_status"))?
            .into_owned();
        Ok(StdinStatus {
            bytes_written: status.bytes_written,
            closed: status.closed,
        })
    }

    /// Resize the command's terminal.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::TtyRequired`] for a command without a PTY;
    /// otherwise any RPC failure.
    pub async fn resize(&self, size: PtySize) -> Result<()> {
        self.client()
            .resize_execution_tty(pb::ResizeExecutionTtyRequest {
                sandbox_id: self.sandbox_id.clone(),
                execution_id: self.command_id.clone(),
                size: pb::TerminalSize {
                    width: size.cols,
                    height: size.rows,
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "commands.resize"))?;
        Ok(())
    }

    /// Deliver a signal to the command's process group.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn kill(&self, signal: Signal) -> Result<()> {
        self.client()
            .signal_execution(pb::SignalExecutionRequest {
                sandbox_id: self.sandbox_id.clone(),
                execution_id: self.command_id.clone(),
                signal: signal.to_wire().into(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "commands.kill"))?;
        Ok(())
    }
}

impl std::fmt::Debug for CommandHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandHandle")
            .field("sandbox_id", &self.sandbox_id)
            .field("command_id", &self.command_id)
            .finish_non_exhaustive()
    }
}

/// A command's output, read one chunk at a time with [`next`](Self::next).
///
/// Re-attaches at the retained byte offsets on transport drops, with a
/// bounded budget for *consecutive* failed dials — any received event
/// resets it.
pub struct OutputStream {
    handle: CommandHandle,
    stream: Option<AttachStream>,
    stdout_offset: u64,
    stderr_offset: u64,
    attempts: u32,
    done: bool,
    /// The exit the stream delivered, when it ended with one.
    exited: Option<pb::Execution>,
}

impl OutputStream {
    /// The next chunk, or `None` when the command exited (or the
    /// re-attach budget ran out with the stream dead).
    ///
    /// # Errors
    ///
    /// Any RPC failure that survives the re-attach budget.
    pub async fn next(&mut self) -> Result<Option<OutputChunk>> {
        loop {
            if self.done {
                return Ok(None);
            }
            if self.stream.is_none() {
                match self.attach().await {
                    Ok(stream) => self.stream = Some(stream),
                    Err(error) => {
                        if self.bump_attempts().await {
                            continue;
                        }
                        self.done = true;
                        return Err(error);
                    }
                }
            }
            let stream = self.stream.as_mut().expect("stream attached above");
            match stream.message::<pb::ExecutionEvent>().await {
                Ok(Some(frame)) => {
                    // Anything received proves the stream re-established.
                    self.attempts = 0;
                    match frame.to_owned_message().event {
                        Some(execution_event::Event::Output(output)) => {
                            let channel = match output.channel.as_known() {
                                Some(pb::StdioChannel::STDIO_CHANNEL_STDERR) => Channel::Stderr,
                                Some(pb::StdioChannel::STDIO_CHANNEL_PTY) => Channel::Pty,
                                _ => Channel::Stdout,
                            };
                            // Advance past this chunk even when empty, so
                            // a resume never re-reads it. The server may
                            // report a higher offset than we tracked
                            // (retention trimming); trust it.
                            let end = output.offset.saturating_add(output.data.len() as u64);
                            match channel {
                                Channel::Stderr => {
                                    self.stderr_offset = self.stderr_offset.max(end);
                                }
                                Channel::Stdout | Channel::Pty => {
                                    self.stdout_offset = self.stdout_offset.max(end);
                                }
                            }
                            if output.data.is_empty() {
                                continue;
                            }
                            return Ok(Some(OutputChunk {
                                channel,
                                data: output.data,
                            }));
                        }
                        Some(execution_event::Event::Exited(exited)) => {
                            self.exited = exited.execution.as_option().cloned();
                            self.done = true;
                            return Ok(None);
                        }
                        // Started and keepalive frames prove liveness but
                        // carry no output.
                        _ => {}
                    }
                }
                // Clean end without an exit event: the caller's wait
                // decides authoritatively.
                Ok(None) => {
                    self.done = true;
                    return Ok(None);
                }
                Err(error) => {
                    self.stream = None;
                    if self.bump_attempts().await {
                        continue;
                    }
                    self.done = true;
                    return Err(Error::from_connect(error, "commands.output"));
                }
            }
        }
    }

    async fn attach(&self) -> std::result::Result<AttachStream, Error> {
        self.handle
            .client()
            .attach_execution(pb::AttachExecutionRequest {
                sandbox_id: self.handle.sandbox_id.clone(),
                execution_id: self.handle.command_id.clone(),
                stdout_offset: self.stdout_offset,
                stderr_offset: self.stderr_offset,
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "commands.output"))
    }

    /// One more attempt, with backoff. `true` = keep trying.
    async fn bump_attempts(&mut self) -> bool {
        self.attempts += 1;
        if self.attempts > ATTACH_RESUME_ATTEMPTS {
            return false;
        }
        tokio::time::sleep(ATTACH_RESUME_BACKOFF * self.attempts).await;
        true
    }
}

/// Exit code + signal name from the wire exit status, shell convention
/// for signal deaths.
fn exit_parts(execution: &pb::Execution) -> (Option<i32>, Option<String>) {
    match execution
        .exit_status
        .as_option()
        .and_then(|status| status.status.clone())
    {
        Some(exit_status::Status::Code(code)) => (Some(code), None),
        Some(exit_status::Status::Signal(signal)) => {
            (Some(128 + signal), Some(signal_name(signal)))
        }
        None => (None, None),
    }
}

fn signal_name(value: i32) -> String {
    match buffa::EnumValue::<pb::Signal>::from(value).as_known() {
        Some(signal) => {
            let name = format!("{signal:?}");
            name.strip_prefix("SIGNAL_").unwrap_or(&name).to_owned()
        }
        None => format!("SIG{value}"),
    }
}

fn result_from_wire(execution: &pb::Execution, stdout: Vec<u8>, stderr: Vec<u8>) -> CommandResult {
    let (exit_code, signal) = exit_parts(execution);
    CommandResult {
        exit_code: exit_code.unwrap_or(0),
        signal,
        stdout,
        stderr,
    }
}

fn info_from_wire(execution: pb::Execution) -> CommandInfo {
    let (exit_code, signal) = exit_parts(&execution);
    let state = match execution.state.as_known() {
        Some(pb::ExecutionState::EXECUTION_STATE_RUNNING) => CommandState::Running,
        Some(pb::ExecutionState::EXECUTION_STATE_EXITED) => CommandState::Exited,
        _ => CommandState::Unknown,
    };
    CommandInfo {
        command_id: execution.id,
        tty: execution.tty,
        state,
        exit_code: if state == CommandState::Exited {
            exit_code
        } else {
            None
        },
        signal,
        error: (!execution.error.is_empty()).then_some(execution.error),
    }
}
