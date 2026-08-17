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
//! The capability comes off the running VM's handle (`HandleVsock` keeps
//! that handle alive for the callers that hold the vsock across awaits).
//! In the other direction — the guest agent's readiness dial-out — the
//! boot pre-listens through the driver's `VsockListen` capability and
//! [`wait_ready`] takes the one connection.
//!
//! ## Frame format
//!
//! The opcodes, payload layouts, and the JSON DTOs ([`StartCommand`],
//! [`WaitPortReq`]) are the exec-channel vocabulary in
//! [`arcbox_vm_proto::exec`], re-exported here. This module holds the
//! connection and framing layer plus the shared types; the protocols each
//! have a file of their own: `exec` (`run`, `exec`), `clock`
//! (`sync_clock`), `net` (`reconfigure_network`), `wait_port`
//! (`wait_for_port`).

use std::time::Duration;

use arcbox_vm_driver::{IoMode, Vsock, VsockConn, VsockListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::warn;

use crate::error::{Result, VmmError};

// Exec-channel vocabulary, shared with vm-agent through `arcbox-vm-proto`.
pub use arcbox_vm_proto::exec::{AGENT_PORT, MSG_WAIT_PORT, READY_PORT, StartCommand, WaitPortReq};
pub(crate) use arcbox_vm_proto::exec::{MAX_FRAME_SIZE, MSG_CLOCK_SYNC, MSG_NET_RECONFIG};
use arcbox_vm_proto::exec::{MSG_EXIT, MSG_STDERR, MSG_STDOUT};

mod clock;
mod exec;
pub mod files;
mod handle;
mod net;
mod wait_port;

pub use clock::{ClockSync, sync_clock};
pub use exec::{exec, run};
pub(crate) use handle::HandleVsock;
pub use net::reconfigure_network;
pub use wait_port::wait_for_port;

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
/// only on the two transient answers [`is_transient`] names — no guest
/// listener yet, or a VM frozen for a checkpoint; every other error is
/// final.
pub(crate) async fn connect_to_port(vsock: &dyn Vsock, port: u32) -> Result<UnixStream> {
    let deadline = tokio::time::Instant::now() + AGENT_READY_TIMEOUT;
    let mut backoff = AGENT_READY_INITIAL_BACKOFF;
    loop {
        match vsock.dial(port).await {
            Ok(conn) => return into_unix_stream(conn),
            Err(error) if is_transient(&error) => {}
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

/// The dial outcomes [`connect_to_port`] retries: the guest has no listener
/// on the port yet ([`arcbox_vm_driver::Error::Io`] of kind
/// [`ConnectionRefused`](std::io::ErrorKind::ConnectionRefused), the port's
/// answer for that), or the VM is frozen for a checkpoint
/// ([`arcbox_vm_driver::VmState::Quiesced`]). The second is a moment, not
/// a state to fail on: a file read or an exec that races a checkpoint used
/// to sit on the VMM's connect until the guest resumed, and the driver's
/// refusal to dial a quiesced VM must not turn that wait into an error. A
/// VM that stays frozen — pause holds it, then kills it — turns the retry
/// into the exited-VM error or the ready budget's.
fn is_transient(error: &arcbox_vm_driver::Error) -> bool {
    match error {
        arcbox_vm_driver::Error::Io(io) => io.kind() == std::io::ErrorKind::ConnectionRefused,
        arcbox_vm_driver::Error::WrongState { state, .. } => {
            *state == arcbox_vm_driver::VmState::Quiesced
        }
        _ => false,
    }
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
pub(crate) async fn wait_ready(listener: &mut dyn VsockListener) -> Result<()> {
    let conn = listener
        .accept()
        .await
        .map_err(|e| VmmError::Vsock(format!("accept on ready socket: {e}")))?;
    let mut stream = into_unix_stream(conn)?;
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

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use arcbox_vm_proto::exec::{MSG_EOF, MSG_RESIZE, MSG_SIGNAL, MSG_START};
    use async_trait::async_trait;

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

    fn quiesced() -> arcbox_vm_driver::Error {
        arcbox_vm_driver::Error::WrongState {
            id: arcbox_vm_driver::VmId::new("vm").unwrap(),
            state: arcbox_vm_driver::VmState::Quiesced,
            expected: "running",
        }
    }

    #[tokio::test]
    async fn connect_retries_only_while_the_guest_is_not_listening() {
        let vsock = ScriptedVsock::new([Err(refused()), Err(refused()), Ok(IoMode::Async)]);
        connect_to_port(&vsock, AGENT_PORT).await.unwrap();
        assert_eq!(vsock.dials(), 3);
    }

    /// A VM frozen for a checkpoint is dialed again once it thaws — the
    /// wait a caller racing a checkpoint always had — while an exited VM
    /// is final.
    #[tokio::test]
    async fn connect_waits_out_a_quiesced_vm() {
        let vsock = ScriptedVsock::new([Err(quiesced()), Err(quiesced()), Ok(IoMode::Async)]);
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
}
