//! Host-side vsock client for communicating with the in-VM guest agent.
//!
//! ## Reaching the guest
//!
//! Every protocol function here dials the guest through the driver port's
//! [`Vsock`] capability: [`connect_to_port`] asks it for a connection to a
//! guest port and retries — only — while the guest has no listener there
//! yet, then turns the [`VsockConn`] it hands back into the tokio stream the
//! frame codec speaks over. Where that connection comes from is the
//! driver's business.
//!
//! ## How Firecracker proxies vsock
//!
//! Until the Firecracker adapter owns it, [`UdsVsock`] performs the
//! dial: Firecracker exposes a Unix domain socket (`uds_path`) that acts as
//! a proxy for host-initiated connections to guest vsock ports.  The
//! handshake:
//!
//! 1. Connect to `uds_path`.
//! 2. Write `"CONNECT {AGENT_PORT}\n"`.
//! 3. Read until `'\n'` — the response is `"OK {host_ephemeral_port}\n"`.
//! 4. The socket is now a bidirectional pipe to the guest's vsock port.
//!
//! In the other direction, a guest-initiated connect to host port `P` is
//! forwarded by Firecracker to a host Unix socket at `{uds_path}_{P}`; the
//! boot readiness gate pre-listens there ([`arcbox_fc_driver::vsock::UdsListener`]
//! + [`wait_ready`]).
//!
//! ## Frame format
//!
//! The opcodes, payload layouts, and the JSON DTOs ([`StartCommand`],
//! [`WaitPortReq`]) are the exec-channel vocabulary in
//! [`arcbox_vm_proto::exec`], re-exported here; the net-reconfig timing
//! suffix on `MSG_EXIT` is decoded by [`ReconfigTimings`].

use std::time::Duration;

use arcbox_fc_driver::vsock::UdsListener;
use arcbox_vm_driver::{IoMode, Vsock, VsockConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::error::{Result, VmmError};

// Exec-channel vocabulary, shared with vm-agent through `arcbox-vm-proto`.
pub use arcbox_vm_proto::exec::{AGENT_PORT, MSG_WAIT_PORT, READY_PORT, StartCommand, WaitPortReq};
pub(crate) use arcbox_vm_proto::exec::{MAX_FRAME_SIZE, MSG_CLOCK_SYNC, MSG_NET_RECONFIG};
use arcbox_vm_proto::exec::{
    MSG_EOF, MSG_EXIT, MSG_RESIZE, MSG_SIGNAL, MSG_START, MSG_STDERR, MSG_STDIN, MSG_STDOUT,
};

mod uds;
pub use uds::UdsVsock;

// =============================================================================
// Public types
// =============================================================================

/// How a guest workload terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// The process exited normally with this code.
    Code(i32),
    /// The process was killed by this POSIX signal.
    Signaled(i32),
}

impl ExitStatus {
    /// Shell-convention scalar: the exit code itself, or `128 + signal` for a
    /// signal death. For consumers that can only carry one integer.
    #[must_use]
    pub const fn conventional_code(self) -> i32 {
        match self {
            Self::Code(code) => code,
            Self::Signaled(signal) => 128 + signal,
        }
    }

    /// Decode a `MSG_EXIT` payload.
    ///
    /// New agents send `[i32 LE code][i32 LE signal]`; agents from before the
    /// signal extension (e.g. inside restored snapshots) send only the 4-byte
    /// code, in which case a signal death arrives collapsed as `128 + signal`.
    fn from_exit_payload(payload: &[u8]) -> Self {
        if payload.len() >= 8 {
            let signal = i32::from_le_bytes(payload[4..8].try_into().unwrap());
            if signal != 0 {
                return Self::Signaled(signal);
            }
        }
        let code = if payload.len() >= 4 {
            i32::from_le_bytes(payload[..4].try_into().unwrap())
        } else {
            0
        };
        Self::Code(code)
    }
}

/// A chunk of output emitted by a guest process.
#[derive(Debug, Clone)]
pub enum OutputChunk {
    /// Bytes from the process's stdout (the merged PTY stream for `tty` sessions).
    Stdout(Vec<u8>),
    /// Bytes from the process's stderr (never emitted for `tty` sessions).
    Stderr(Vec<u8>),
    /// The process terminated. Always the final chunk of a session.
    Exit(ExitStatus),
}

/// A message the host sends to the guest during an exec/run session.
#[derive(Debug)]
pub enum ExecInputMsg {
    /// Raw bytes to forward to the process's stdin.
    Stdin(Vec<u8>),
    /// Resize the pseudo-TTY.
    Resize { width: u16, height: u16 },
    /// Deliver a POSIX signal to the workload's process group.
    Signal(i32),
    /// Signal EOF on the process's stdin.
    Eof,
}

/// Outcome of a guest listen-table wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortWait {
    /// A listener on the port exists.
    Listening,
    /// The deadline elapsed with no listener.
    Deadline,
}

// =============================================================================
// Internal helpers
// =============================================================================

/// How long to wait for the guest agent to start accepting vsock connections.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(30);
/// First retry delay of the vsock connect backoff; doubles per attempt.
const AGENT_READY_INITIAL_BACKOFF: Duration = Duration::from_millis(2);
/// Ceiling for the vsock connect retry backoff.
const AGENT_READY_MAX_BACKOFF: Duration = Duration::from_millis(200);

/// Next delay of the exponential connect backoff: double, capped at
/// [`AGENT_READY_MAX_BACKOFF`].
fn next_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(AGENT_READY_MAX_BACKOFF)
}

/// Open a host-initiated vsock connection to the guest agent (port 52).
///
/// Retries the dial until the guest agent accepts or [`AGENT_READY_TIMEOUT`]
/// elapses: a guest still booting (kernel up, vm-agent not yet listening)
/// answers every dial with `ConnectionRefused`, the one transient outcome.
async fn connect_to_agent(vsock: &dyn Vsock) -> Result<UnixStream> {
    connect_to_port(vsock, AGENT_PORT).await
}

/// Open a host-initiated vsock connection to an arbitrary guest port.
///
/// Same retry semantics as [`connect_to_agent`].  Used by the file I/O and
/// port-forward modules which operate on different vsock ports. Retries
/// only on [`arcbox_vm_driver::Error::Io`] of kind
/// [`ConnectionRefused`](std::io::ErrorKind::ConnectionRefused) — the
/// port's "no guest listener yet" answer; every other error is final.
pub(crate) async fn connect_to_port(vsock: &dyn Vsock, port: u32) -> Result<UnixStream> {
    let deadline = tokio::time::Instant::now() + AGENT_READY_TIMEOUT;
    let mut backoff = AGENT_READY_INITIAL_BACKOFF;
    loop {
        match vsock.dial(port).await {
            Ok(conn) => return into_unix_stream(conn),
            Err(error) if is_not_listening(&error) => {}
            Err(error) => return Err(error.into()),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(VmmError::Vsock(format!(
                "vsock port {port} did not become ready within {}s",
                AGENT_READY_TIMEOUT.as_secs(),
            )));
        }
        tokio::time::sleep(backoff).await;
        backoff = next_backoff(backoff);
    }
}

/// The dial outcome [`connect_to_port`] retries: the guest has no listener
/// on the port yet.
fn is_not_listening(error: &arcbox_vm_driver::Error) -> bool {
    matches!(
        error,
        arcbox_vm_driver::Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused
    )
}

/// Register a dialed connection with the tokio reactor.
///
/// This client is tokio tasks all the way down and has no blocking-thread
/// transport, so a connection whose driver requires [`IoMode::Blocking`] is
/// refused rather than misregistered with the reactor.
fn into_unix_stream(conn: VsockConn) -> Result<UnixStream> {
    match conn.mode {
        IoMode::Async => {
            let stream = std::os::unix::net::UnixStream::from(conn.fd);
            stream.set_nonblocking(true)?;
            Ok(UnixStream::from_std(stream)?)
        }
        IoMode::Blocking => Err(VmmError::Vsock(
            "vsock connection requires blocking I/O, which the guest-agent client cannot drive"
                .into(),
        )),
    }
}

/// Wait for the guest agent's readiness dial-out on a pre-bound listener:
/// `accept()` one connection and read (and discard) its single byte.
/// Completion is the readiness event.
pub(crate) async fn wait_ready(listener: &UdsListener) -> Result<()> {
    let mut stream = listener
        .accept()
        .await
        .map_err(|e| VmmError::Vsock(format!("accept on ready socket: {e}")))?;
    let mut byte = [0u8; 1];
    stream
        .read(&mut byte)
        .await
        .map_err(|e| VmmError::Vsock(format!("read ready byte: {e}")))?;
    Ok(())
}

/// Write a single frame to any `AsyncWrite`.
pub(crate) async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "frame payload too large: {} bytes (max {MAX_FRAME_SIZE})",
                payload.len()
            ),
        ));
    }
    w.write_u8(msg_type).await?;
    w.write_u32_le(payload.len() as u32).await?;
    if !payload.is_empty() {
        w.write_all(payload).await?;
    }
    Ok(())
}

/// Read a single frame from any `AsyncRead`.
pub(crate) async fn read_frame<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> std::io::Result<(u8, Vec<u8>)> {
    let msg_type = r.read_u8().await?;
    let len = r.read_u32_le().await? as usize;
    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes (max {MAX_FRAME_SIZE})"),
        ));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok((msg_type, payload))
}

/// Drain an output half, forwarding frames to `tx` until `MSG_EXIT` or error.
async fn drain_output<R: AsyncReadExt + Unpin>(
    mut read_half: R,
    tx: mpsc::Sender<Result<OutputChunk>>,
) {
    loop {
        match read_frame(&mut read_half).await {
            Ok((msg_type, payload)) => {
                let chunk = match msg_type {
                    MSG_STDOUT => OutputChunk::Stdout(payload),
                    MSG_STDERR => OutputChunk::Stderr(payload),
                    MSG_EXIT => {
                        let status = ExitStatus::from_exit_payload(&payload);
                        let _ = tx.send(Ok(OutputChunk::Exit(status))).await;
                        break;
                    }
                    other => {
                        warn!(msg_type = other, "unknown agent→host frame type; ignoring");
                        continue;
                    }
                };
                if tx.send(Ok(chunk)).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(Err(VmmError::Vsock(format!("agent read error: {e}"))))
                    .await;
                break;
            }
        }
    }
}

// =============================================================================
// run() — non-interactive command execution
// =============================================================================

/// Run a command in the sandbox and stream its output.
///
/// The host sends `MSG_START` followed immediately by `MSG_EOF` (no stdin),
/// then receives a stream of `MSG_STDOUT` / `MSG_STDERR` / `MSG_EXIT` frames.
///
/// Returns a channel receiver.  The final [`OutputChunk`] has
/// `stream == "exit"` and carries the process exit code.
pub async fn run(
    vsock: &dyn Vsock,
    start: StartCommand,
) -> Result<mpsc::Receiver<Result<OutputChunk>>> {
    let mut stream = connect_to_agent(vsock).await?;

    // Send the start command.
    let payload = serde_json::to_vec(&start)
        .map_err(|e| VmmError::Vsock(format!("serialize StartCommand: {e}")))?;
    write_frame(&mut stream, MSG_START, &payload)
        .await
        .map_err(|e| VmmError::Vsock(format!("write MSG_START: {e}")))?;

    // No stdin for run(): close immediately.
    write_frame(&mut stream, MSG_EOF, &[])
        .await
        .map_err(|e| VmmError::Vsock(format!("write MSG_EOF: {e}")))?;

    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        drain_output(stream, tx).await;
    });

    Ok(rx)
}

// =============================================================================
// exec() — interactive bidirectional session
// =============================================================================

/// Start an interactive session in the sandbox.
///
/// Returns `(input_sender, output_receiver)`:
/// - Push [`ExecInputMsg`]s into `input_sender` for stdin data, TTY resize, or EOF.
/// - Read [`OutputChunk`]s from `output_receiver` for stdout, stderr, and the
///   final exit frame.
pub async fn exec(
    vsock: &dyn Vsock,
    start: StartCommand,
) -> Result<(
    mpsc::Sender<ExecInputMsg>,
    mpsc::Receiver<Result<OutputChunk>>,
)> {
    let stream = connect_to_agent(vsock).await?;

    // Send the start command.
    let payload = serde_json::to_vec(&start)
        .map_err(|e| VmmError::Vsock(format!("serialize StartCommand: {e}")))?;
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    write_frame(&mut write_half, MSG_START, &payload)
        .await
        .map_err(|e| VmmError::Vsock(format!("write MSG_START: {e}")))?;

    let (in_tx, mut in_rx) = mpsc::channel::<ExecInputMsg>(32);
    let (out_tx, out_rx) = mpsc::channel::<Result<OutputChunk>>(64);

    // Writer task: ExecInputMsg → agent frames.
    tokio::spawn(async move {
        while let Some(msg) = in_rx.recv().await {
            let result = match msg {
                ExecInputMsg::Stdin(data) => write_frame(&mut write_half, MSG_STDIN, &data).await,
                ExecInputMsg::Resize { width, height } => {
                    let mut buf = [0u8; 4];
                    buf[..2].copy_from_slice(&width.to_le_bytes());
                    buf[2..].copy_from_slice(&height.to_le_bytes());
                    write_frame(&mut write_half, MSG_RESIZE, &buf).await
                }
                ExecInputMsg::Signal(signal) => {
                    write_frame(&mut write_half, MSG_SIGNAL, &signal.to_le_bytes()).await
                }
                ExecInputMsg::Eof => write_frame(&mut write_half, MSG_EOF, &[]).await,
            };
            if result.is_err() {
                break;
            }
        }
    });

    // Reader task: agent frames → output channel.
    tokio::spawn(async move {
        drain_output(&mut read_half, out_tx).await;
    });

    Ok((in_tx, out_rx))
}

// =============================================================================
// sync_clock() — synchronise guest clock after snapshot restore
// =============================================================================

/// Outcome of a completed clock-sync round trip.
///
/// Both variants prove liveness — the agent accepted the connection, parsed
/// the frame, and replied — which is what the boot readiness gate needs.
/// Only [`ClockSync::Synced`] means the guest wall clock was actually set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockSync {
    /// The agent set the clock.
    Synced,
    /// The agent answered but could not set the clock (e.g. `clock_settime`
    /// failed); it carries the agent-reported exit code.
    AgentError(i32),
}

/// Synchronise the guest clock to the current host time.
///
/// Sends [`MSG_CLOCK_SYNC`] to the exec channel (vsock port 52) and waits for
/// `MSG_EXIT`.  Called immediately after `restore_sandbox()` completes so
/// the guest does not run with a stale timestamp from snapshot creation time,
/// and by the cold-boot path as the agent-readiness gate. `Err` means the
/// round trip itself failed (connect, transport, malformed reply); an agent
/// that answered-but-failed is `Ok(ClockSync::AgentError)` so callers can
/// separate liveness from the clock side effect.
pub async fn sync_clock(vsock: &dyn Vsock) -> Result<ClockSync> {
    // Split connect vs frame RTT: on a just-resumed guest these have very
    // different causes (vsock handshake vs guest-side processing), and the
    // CORE-75 settle-window investigation needs them attributable.
    let started = std::time::Instant::now();
    let mut stream = connect_to_agent(vsock).await?;
    let connected = std::time::Instant::now();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| VmmError::Vsock(format!("system time error: {e}")))?;

    let secs = i64::try_from(now.as_secs())
        .map_err(|e| VmmError::Vsock(format!("unix timestamp overflow: {e}")))?;
    let nanos = now.subsec_nanos();

    let result = sync_clock_on_stream(&mut stream, secs, nanos).await;
    info!(
        connect_ms = connected.duration_since(started).as_millis() as u64,
        rpc_ms = connected.elapsed().as_millis() as u64,
        "clock sync"
    );
    result
}

/// Send a clock-sync frame and validate the agent response.
///
/// Extracted from [`sync_clock`] so the wire protocol can be tested with
/// `tokio::io::duplex` without needing a real vsock connection.
async fn sync_clock_on_stream<S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut S,
    secs: i64,
    nanos: u32,
) -> Result<ClockSync> {
    let mut payload = [0u8; 12];
    payload[..8].copy_from_slice(&secs.to_le_bytes());
    payload[8..].copy_from_slice(&nanos.to_le_bytes());

    write_frame(stream, MSG_CLOCK_SYNC, &payload)
        .await
        .map_err(|e| VmmError::Vsock(format!("write MSG_CLOCK_SYNC: {e}")))?;

    let (msg_type, payload) = tokio::time::timeout(Duration::from_secs(5), read_frame(stream))
        .await
        .map_err(|_| VmmError::Vsock("clock sync: timed out waiting for response".into()))?
        .map_err(|e| VmmError::Vsock(format!("read clock sync response: {e}")))?;

    if msg_type != MSG_EXIT {
        return Err(VmmError::Vsock(format!(
            "clock sync: unexpected response type 0x{msg_type:02x}"
        )));
    }
    if payload.len() < 4 {
        return Err(VmmError::Vsock(format!(
            "clock sync: payload too short ({} bytes, expected 4)",
            payload.len()
        )));
    }
    let code = i32::from_le_bytes(payload[..4].try_into().unwrap());
    if code != 0 {
        return Ok(ClockSync::AgentError(code));
    }
    Ok(ClockSync::Synced)
}

/// Re-address the guest network after a fresh-network snapshot restore.
///
/// Sends [`MSG_NET_RECONFIG`] to the exec channel (vsock port 52) and waits
/// for `MSG_EXIT(0)`. A restored kernel still carries the origin's `ip=`
/// boot configuration, so a restore that allocated a new TAP/IP must
/// re-address the guest or the clone collides with the running origin.
pub async fn reconfigure_network(
    vsock: &dyn Vsock,
    cmd: &crate::boot_proto::NetReconfigCommand,
) -> Result<()> {
    let started = std::time::Instant::now();
    let mut stream = connect_to_agent(vsock).await?;
    let connected = std::time::Instant::now();
    let result = net_reconfig_on_stream(&mut stream, cmd).await;
    info!(
        connect_ms = connected.duration_since(started).as_millis() as u64,
        rpc_ms = connected.elapsed().as_millis() as u64,
        "net reconfig"
    );
    result
}

/// Send a net-reconfig frame and validate the agent response.
///
/// Extracted from [`reconfigure_network`] so the wire protocol can be tested
/// with `tokio::io::duplex` without needing a real vsock connection.
async fn net_reconfig_on_stream<S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut S,
    cmd: &crate::boot_proto::NetReconfigCommand,
) -> Result<()> {
    let payload = serde_json::to_vec(cmd)
        .map_err(|e| VmmError::Vsock(format!("encode NetReconfigCommand: {e}")))?;

    write_frame(stream, MSG_NET_RECONFIG, &payload)
        .await
        .map_err(|e| VmmError::Vsock(format!("write MSG_NET_RECONFIG: {e}")))?;

    let (msg_type, payload) = tokio::time::timeout(Duration::from_secs(5), read_frame(stream))
        .await
        .map_err(|_| VmmError::Vsock("net reconfig: timed out waiting for response".into()))?
        .map_err(|e| VmmError::Vsock(format!("read net reconfig response: {e}")))?;

    if msg_type != MSG_EXIT {
        return Err(VmmError::Vsock(format!(
            "net reconfig: unexpected response type 0x{msg_type:02x}"
        )));
    }
    if payload.len() < 4 {
        return Err(VmmError::Vsock(format!(
            "net reconfig: payload too short ({} bytes, expected 4)",
            payload.len()
        )));
    }
    let code = i32::from_le_bytes(payload[..4].try_into().unwrap());
    if code != 0 {
        return Err(VmmError::Vsock(format!(
            "net reconfig: agent returned exit code {code}"
        )));
    }
    if let Some(t) = ReconfigTimings::parse(&payload) {
        info!(
            addr_us = t.steps[0],
            netmask_us = t.steps[1],
            delrt_us = t.steps[2],
            addrt_us = t.steps[3],
            resolv_us = t.resolv,
            handler_us = t.handler,
            "net reconfig guest split"
        );
    }
    Ok(())
}

/// Wait until the guest's TCP listen table has a listener on `port`.
///
/// Sends [`MSG_WAIT_PORT`] to the exec channel; the vm-agent watches
/// `/proc/net/tcp{,6}` in-process (never a connect probe) and answers when
/// the listener appears or `timeout` elapses. The host-side read deadline
/// adds slack on top of the guest's own budget so a live guest always
/// answers first.
pub async fn wait_for_port(vsock: &dyn Vsock, port: u16, timeout: Duration) -> Result<PortWait> {
    let mut stream = connect_to_agent(vsock).await?;
    wait_for_port_on_stream(&mut stream, port, timeout).await
}

/// Send a wait-port frame and decode the agent's verdict.
///
/// Extracted from [`wait_for_port`] so the wire protocol can be tested with
/// `tokio::io::duplex` without needing a real vsock connection.
async fn wait_for_port_on_stream<S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut S,
    port: u16,
    timeout: Duration,
) -> Result<PortWait> {
    let req = WaitPortReq {
        port,
        timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
    };
    let payload = serde_json::to_vec(&req)
        .map_err(|e| VmmError::Vsock(format!("encode WaitPortReq: {e}")))?;
    write_frame(stream, MSG_WAIT_PORT, &payload)
        .await
        .map_err(|e| VmmError::Vsock(format!("write MSG_WAIT_PORT: {e}")))?;

    let read_deadline = timeout + Duration::from_secs(5);
    let (msg_type, payload) = tokio::time::timeout(read_deadline, read_frame(stream))
        .await
        .map_err(|_| VmmError::Vsock("wait for port: timed out waiting for response".into()))?
        .map_err(|e| VmmError::Vsock(format!("read wait-port response: {e}")))?;

    if msg_type != MSG_EXIT {
        return Err(VmmError::Vsock(format!(
            "wait for port: unexpected response type 0x{msg_type:02x}"
        )));
    }
    if payload.len() < 4 {
        return Err(VmmError::Vsock(format!(
            "wait for port: payload too short ({} bytes, expected 4)",
            payload.len()
        )));
    }
    match i32::from_le_bytes(payload[..4].try_into().unwrap()) {
        0 => Ok(PortWait::Listening),
        1 => Ok(PortWait::Deadline),
        code => Err(VmmError::Vsock(format!(
            "wait for port: agent returned exit code {code}"
        ))),
    }
}

/// Guest-side timing breakdown a net-reconfig `MSG_EXIT` reply may carry:
/// six `u32 LE` microsecond values (four per-ioctl, resolv.conf write, whole
/// handler) appended after the `[code][signal]` header — CORE-75 latency
/// attribution. Absent from legacy agents; readers key on payload length.
#[derive(Debug, PartialEq, Eq)]
struct ReconfigTimings {
    steps: [u32; 4],
    resolv: u32,
    handler: u32,
}

impl ReconfigTimings {
    fn parse(payload: &[u8]) -> Option<Self> {
        let extra = payload.get(8..32)?;
        let at = |i: usize| u32::from_le_bytes(extra[i * 4..i * 4 + 4].try_into().unwrap());
        Some(Self {
            steps: [at(0), at(1), at(2), at(3)],
            resolv: at(4),
            handler: at(5),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use async_trait::async_trait;
    use tokio::net::UnixListener;

    use super::*;

    /// Build a raw frame byte-by-byte for use in read tests.
    fn make_raw_frame(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(msg_type);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn connect_backoff_doubles_up_to_the_cap() {
        let mut delays = Vec::new();
        let mut backoff = AGENT_READY_INITIAL_BACKOFF;
        for _ in 0..10 {
            delays.push(backoff.as_millis());
            backoff = next_backoff(backoff);
        }
        assert_eq!(delays, [2, 4, 8, 16, 32, 64, 128, 200, 200, 200]);
    }

    /// A [`Vsock`] whose dials answer from a script. Once the script runs
    /// out it answers `ConnectionRefused` forever — a guest that never
    /// listens.
    struct ScriptedVsock {
        script: std::sync::Mutex<std::collections::VecDeque<arcbox_vm_driver::Result<IoMode>>>,
        dials: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedVsock {
        fn new(script: impl IntoIterator<Item = arcbox_vm_driver::Result<IoMode>>) -> Self {
            Self {
                script: std::sync::Mutex::new(script.into_iter().collect()),
                dials: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn dials(&self) -> usize {
            self.dials.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Vsock for ScriptedVsock {
        async fn dial(&self, _port: u32) -> arcbox_vm_driver::Result<VsockConn> {
            self.dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let next = self.script.lock().unwrap().pop_front();
            let mode = next.unwrap_or_else(|| Err(refused()))?;
            let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
            Ok(VsockConn {
                fd: OwnedFd::from(ours),
                mode,
            })
        }
    }

    fn refused() -> arcbox_vm_driver::Error {
        std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into()
    }

    #[tokio::test]
    async fn connect_retries_only_while_the_guest_is_not_listening() {
        let vsock = ScriptedVsock::new([Err(refused()), Err(refused()), Ok(IoMode::Async)]);
        connect_to_port(&vsock, AGENT_PORT).await.unwrap();
        assert_eq!(vsock.dials(), 3);
    }

    #[tokio::test]
    async fn connect_fails_fast_on_any_other_error() {
        // Each final error keeps its native shape through the conversion:
        // an I/O failure stays `Io`, a driver `WrongState` stays
        // `WrongState` (the guest agent maps that to 412, not 500).
        type Native = fn(&VmmError) -> bool;
        let finals: [(arcbox_vm_driver::Error, Native); 2] = [
            (
                arcbox_vm_driver::Error::Io(std::io::ErrorKind::BrokenPipe.into()),
                |err| matches!(err, VmmError::Io(_)),
            ),
            (
                arcbox_vm_driver::Error::WrongState {
                    id: arcbox_vm_driver::VmId::new("vm").unwrap(),
                    state: arcbox_vm_driver::VmState::Exited(
                        arcbox_vm_driver::ExitStatus::signaled(9),
                    ),
                    expected: "running",
                },
                |err| matches!(err, VmmError::WrongState { expected, actual, .. } if expected == "running" && actual.starts_with("exited")),
            ),
        ];
        for (error, native) in finals {
            let vsock = ScriptedVsock::new([Err(error), Ok(IoMode::Async)]);
            let err = connect_to_port(&vsock, AGENT_PORT).await.unwrap_err();
            assert!(native(&err), "unexpected error: {err}");
            assert_eq!(vsock.dials(), 1, "a final error must not be retried");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connect_gives_up_after_the_ready_budget() {
        let vsock = ScriptedVsock::new([]);
        let err = connect_to_port(&vsock, AGENT_PORT).await.unwrap_err();
        assert!(
            matches!(err, VmmError::Vsock(ref m) if m.contains("did not become ready within 30s")),
            "unexpected error: {err}"
        );
        assert!(vsock.dials() > 1);
    }

    #[tokio::test]
    async fn blocking_connections_are_refused_not_misregistered() {
        let vsock = ScriptedVsock::new([Ok(IoMode::Blocking)]);
        let err = connect_to_port(&vsock, AGENT_PORT).await.unwrap_err();
        assert!(
            matches!(err, VmmError::Vsock(ref m) if m.contains("blocking I/O")),
            "unexpected error: {err}"
        );
    }

    /// The transitional adapter's classification of Firecracker's proxy
    /// answers: closed without `OK` is the retryable "no listener yet",
    /// anything else final, `OK` a usable async connection.
    #[tokio::test]
    async fn uds_vsock_classifies_the_proxy_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fc.vsock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            for answer in [None, Some(&b"NOPE\n"[..]), Some(&b"OK 52\n"[..])] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut byte = [0u8; 1];
                loop {
                    stream.read_exact(&mut byte).await.unwrap();
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                if let Some(answer) = answer {
                    stream.write_all(answer).await.unwrap();
                    // Keep the accepted end alive until the dial returns.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        });
        let vsock = UdsVsock(path);

        let err = vsock.dial(AGENT_PORT).await.unwrap_err();
        assert!(
            is_not_listening(&err),
            "closed proxy must be ConnectionRefused: {err}"
        );
        let err = vsock.dial(AGENT_PORT).await.unwrap_err();
        assert!(
            matches!(err, arcbox_vm_driver::Error::Driver { .. }),
            "unexpected response must be final: {err}"
        );
        let conn = vsock.dial(AGENT_PORT).await.unwrap();
        assert_eq!(conn.mode, IoMode::Async);
    }

    #[tokio::test]
    async fn test_write_read_frame_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_frame(&mut a, MSG_START, b"hello world")
            .await
            .unwrap();
        let (msg_type, payload) = read_frame(&mut b).await.unwrap();
        assert_eq!(msg_type, MSG_START);
        assert_eq!(payload, b"hello world");
    }

    #[tokio::test]
    async fn test_empty_payload_frame() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, MSG_EOF, &[]).await.unwrap();
        let (msg_type, payload) = read_frame(&mut b).await.unwrap();
        assert_eq!(msg_type, MSG_EOF);
        assert!(payload.is_empty());
    }

    #[tokio::test]
    async fn test_exit_code_encoding() {
        let exit_code: i32 = 42;
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, MSG_EXIT, &exit_code.to_le_bytes())
            .await
            .unwrap();
        let (msg_type, payload) = read_frame(&mut b).await.unwrap();
        assert_eq!(msg_type, MSG_EXIT);
        let decoded = i32::from_le_bytes(payload[..4].try_into().unwrap());
        assert_eq!(decoded, 42);
    }

    #[test]
    fn exit_payload_decodes_legacy_and_signal_forms() {
        // Legacy 4-byte form (old vm-agent): always a plain code.
        assert_eq!(
            ExitStatus::from_exit_payload(&7i32.to_le_bytes()),
            ExitStatus::Code(7)
        );
        // 8-byte form, signal 0: a normal exit — even for code 137, which the
        // legacy form could not distinguish from a SIGKILL death.
        let mut normal_137 = Vec::new();
        normal_137.extend_from_slice(&137i32.to_le_bytes());
        normal_137.extend_from_slice(&0i32.to_le_bytes());
        assert_eq!(
            ExitStatus::from_exit_payload(&normal_137),
            ExitStatus::Code(137)
        );
        // 8-byte form, signal set: a signal death.
        let mut sigkill = Vec::new();
        sigkill.extend_from_slice(&137i32.to_le_bytes());
        sigkill.extend_from_slice(&9i32.to_le_bytes());
        assert_eq!(
            ExitStatus::from_exit_payload(&sigkill),
            ExitStatus::Signaled(9)
        );
        assert_eq!(ExitStatus::Signaled(9).conventional_code(), 137);
        // Truncated payload degrades to code 0 (matches the old lenient parse).
        assert_eq!(ExitStatus::from_exit_payload(&[1, 2]), ExitStatus::Code(0));
    }

    #[tokio::test]
    async fn signal_frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, MSG_SIGNAL, &15i32.to_le_bytes())
            .await
            .unwrap();
        let (msg_type, payload) = read_frame(&mut b).await.unwrap();
        assert_eq!(msg_type, MSG_SIGNAL);
        assert_eq!(i32::from_le_bytes(payload[..4].try_into().unwrap()), 15);
    }

    #[tokio::test]
    async fn test_resize_frame_encoding() {
        let width: u16 = 80;
        let height: u16 = 24;
        let mut resize_payload = [0u8; 4];
        resize_payload[..2].copy_from_slice(&width.to_le_bytes());
        resize_payload[2..].copy_from_slice(&height.to_le_bytes());

        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, MSG_RESIZE, &resize_payload)
            .await
            .unwrap();
        let (msg_type, payload) = read_frame(&mut b).await.unwrap();
        assert_eq!(msg_type, MSG_RESIZE);
        let w = u16::from_le_bytes(payload[..2].try_into().unwrap());
        let h = u16::from_le_bytes(payload[2..].try_into().unwrap());
        assert_eq!(w, 80);
        assert_eq!(h, 24);
    }

    #[tokio::test]
    async fn test_read_frame_from_raw_bytes() {
        // Verify the parser accepts hand-crafted bytes (regression guard).
        let raw = make_raw_frame(MSG_STDOUT, b"output line\n");
        let mut cursor = std::io::Cursor::new(raw);
        let (msg_type, payload) = read_frame(&mut cursor).await.unwrap();
        assert_eq!(msg_type, MSG_STDOUT);
        assert_eq!(payload, b"output line\n");
    }

    #[test]
    fn test_start_command_json_serde() {
        let cmd = StartCommand {
            cmd: vec!["echo".into(), "hello".into()],
            env: std::collections::HashMap::new(),
            working_dir: "/tmp".into(),
            user: "root".into(),
            tty: false,
            tty_width: 0,
            tty_height: 0,
            timeout_seconds: 30,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let decoded: StartCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.cmd, vec!["echo", "hello"]);
        assert_eq!(decoded.working_dir, "/tmp");
        assert_eq!(decoded.timeout_seconds, 30);
        assert!(!decoded.tty);
    }

    // -----------------------------------------------------------------
    // sync_clock protocol tests
    // -----------------------------------------------------------------

    /// Simulate a successful clock sync exchange.
    #[tokio::test]
    async fn test_sync_clock_success() {
        let (mut agent, mut host) = tokio::io::duplex(256);

        let agent_handle = tokio::spawn(async move {
            // Read MSG_CLOCK_SYNC frame.
            let (ty, payload) = read_frame(&mut agent).await.unwrap();
            assert_eq!(ty, MSG_CLOCK_SYNC);
            assert_eq!(payload.len(), 12);

            // Verify payload encodes the expected timestamp.
            let secs = i64::from_le_bytes(payload[..8].try_into().unwrap());
            let nanos = u32::from_le_bytes(payload[8..12].try_into().unwrap());
            assert_eq!(secs, 1_700_000_000);
            assert_eq!(nanos, 123_456_789);

            // Respond with MSG_EXIT(0).
            write_frame(&mut agent, MSG_EXIT, &0i32.to_le_bytes())
                .await
                .unwrap();
        });

        let result = sync_clock_on_stream(&mut host, 1_700_000_000, 123_456_789).await;
        assert_eq!(result.unwrap(), ClockSync::Synced);
        agent_handle.await.unwrap();
    }

    /// Agent answers with a non-zero exit code: liveness proven, clock not
    /// set — `Ok(AgentError)`, not `Err`, so the boot gate can pass on it.
    #[tokio::test]
    async fn test_sync_clock_agent_error() {
        let (mut agent, mut host) = tokio::io::duplex(256);

        let agent_handle = tokio::spawn(async move {
            let _ = read_frame(&mut agent).await.unwrap();
            write_frame(&mut agent, MSG_EXIT, &(-1i32).to_le_bytes())
                .await
                .unwrap();
        });

        let result = sync_clock_on_stream(&mut host, 1_700_000_000, 0).await;
        assert_eq!(result.unwrap(), ClockSync::AgentError(-1));
        agent_handle.await.unwrap();
    }

    /// Agent returns a short payload (< 4 bytes).
    #[tokio::test]
    async fn test_sync_clock_short_payload() {
        let (mut agent, mut host) = tokio::io::duplex(256);

        let agent_handle = tokio::spawn(async move {
            let _ = read_frame(&mut agent).await.unwrap();
            write_frame(&mut agent, MSG_EXIT, &[0u8; 2]).await.unwrap();
        });

        let result = sync_clock_on_stream(&mut host, 1_700_000_000, 0).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too short"), "unexpected error: {msg}");
        agent_handle.await.unwrap();
    }

    /// Agent responds with an unexpected frame type.
    #[tokio::test]
    async fn test_sync_clock_unexpected_frame() {
        let (mut agent, mut host) = tokio::io::duplex(256);

        let agent_handle = tokio::spawn(async move {
            let _ = read_frame(&mut agent).await.unwrap();
            write_frame(&mut agent, MSG_STDOUT, b"oops").await.unwrap();
        });

        let result = sync_clock_on_stream(&mut host, 1_700_000_000, 0).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("unexpected response type"),
            "unexpected error: {msg}"
        );
        agent_handle.await.unwrap();
    }

    // -----------------------------------------------------------------
    // reconfigure_network protocol tests
    // -----------------------------------------------------------------

    fn reconfig_cmd() -> crate::boot_proto::NetReconfigCommand {
        crate::boot_proto::NetReconfigCommand {
            ip: std::net::Ipv4Addr::new(172, 20, 0, 3),
            netmask: std::net::Ipv4Addr::new(255, 255, 0, 0),
            gateway: std::net::Ipv4Addr::new(172, 20, 0, 1),
        }
    }

    /// Simulate a successful net-reconfig exchange, round-tripping the JSON.
    #[tokio::test]
    async fn test_net_reconfig_success() {
        let (mut agent, mut host) = tokio::io::duplex(1024);

        let agent_handle = tokio::spawn(async move {
            let (ty, payload) = read_frame(&mut agent).await.unwrap();
            assert_eq!(ty, MSG_NET_RECONFIG);
            let cmd: crate::boot_proto::NetReconfigCommand =
                serde_json::from_slice(&payload).unwrap();
            assert_eq!(cmd, reconfig_cmd());

            write_frame(&mut agent, MSG_EXIT, &0i32.to_le_bytes())
                .await
                .unwrap();
        });

        let result = net_reconfig_on_stream(&mut host, &reconfig_cmd()).await;
        assert!(result.is_ok());
        agent_handle.await.unwrap();
    }

    /// Agent reports failure to apply the new configuration.
    #[tokio::test]
    async fn test_net_reconfig_agent_error() {
        let (mut agent, mut host) = tokio::io::duplex(1024);

        let agent_handle = tokio::spawn(async move {
            let _ = read_frame(&mut agent).await.unwrap();
            write_frame(&mut agent, MSG_EXIT, &(-1i32).to_le_bytes())
                .await
                .unwrap();
        });

        let result = net_reconfig_on_stream(&mut host, &reconfig_cmd()).await;
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("agent returned exit code -1"),
            "unexpected error: {msg}"
        );
        agent_handle.await.unwrap();
    }

    /// The extended 32-byte reply parses in the exact layout the agent
    /// writes: `[code][signal]` then six u32 LE micros. A reply with an
    /// extended payload must also still pass the success path end to end.
    #[tokio::test]
    async fn test_net_reconfig_timing_payload() {
        // Layout mirror of vm-agent's handle_net_reconfig response builder.
        let mut payload = [0u8; 32];
        for (slot, us) in payload[8..]
            .chunks_exact_mut(4)
            .zip([1_u32, 2, 3, 4, 30_000, 40_000])
        {
            slot.copy_from_slice(&us.to_le_bytes());
        }

        assert_eq!(
            ReconfigTimings::parse(&payload),
            Some(ReconfigTimings {
                steps: [1, 2, 3, 4],
                resolv: 30_000,
                handler: 40_000,
            })
        );
        // Legacy shapes carry no timings.
        assert_eq!(ReconfigTimings::parse(&0i32.to_le_bytes()), None);
        assert_eq!(ReconfigTimings::parse(&[0u8; 8]), None);

        let (mut agent, mut host) = tokio::io::duplex(1024);
        let agent_handle = tokio::spawn(async move {
            let _ = read_frame(&mut agent).await.unwrap();
            write_frame(&mut agent, MSG_EXIT, &payload).await.unwrap();
        });
        net_reconfig_on_stream(&mut host, &reconfig_cmd())
            .await
            .expect("extended payload must still count as success");
        agent_handle.await.unwrap();
    }
}
