//! Host-side vsock client for communicating with the in-VM guest agent.
//!
//! ## How Firecracker proxies vsock
//!
//! Firecracker exposes a Unix domain socket (`uds_path`) that acts as a proxy
//! for host-initiated connections to guest vsock ports.  The handshake:
//!
//! 1. Connect to `uds_path`.
//! 2. Write `"CONNECT {AGENT_PORT}\n"`.
//! 3. Read until `'\n'` — the response is `"OK {host_ephemeral_port}\n"`.
//! 4. The socket is now a bidirectional pipe to the guest's vsock port.
//!
//! ## Frame format
//!
//! Every message (in both directions) is:
//!
//! ```text
//! [u8: msg_type][u32 LE: payload_len][payload_len bytes: payload]
//! ```
//!
//! | Type | Direction   | Payload                          |
//! |------|-------------|----------------------------------|
//! | 0x01 | Host→Agent  | JSON-encoded `StartCommand`      |
//! | 0x02 | Host→Agent  | raw stdin bytes                  |
//! | 0x03 | Host→Agent  | `[u16 LE width][u16 LE height]`  |
//! | 0x04 | Host→Agent  | empty — signals stdin EOF        |
//! | 0x10 | Agent→Host  | raw stdout bytes                 |
//! | 0x11 | Agent→Host  | raw stderr bytes                 |
//! | 0x12 | Agent→Host  | `[i32 LE exit_code]`             |

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::warn;

use crate::error::{Result, VmmError};

/// Guest-side vsock port the agent listens on (exec channel).
pub const AGENT_PORT: u32 = 52;

// Frame type constants — Host → Agent (exec channel).
const MSG_START: u8 = 0x01;
const MSG_STDIN: u8 = 0x02;
const MSG_RESIZE: u8 = 0x03;
const MSG_EOF: u8 = 0x04;
/// Synchronise the guest clock to the host after snapshot restore.
/// Payload: `[i64 LE unix_seconds][u32 LE nanos]` (12 bytes).
pub(crate) const MSG_CLOCK_SYNC: u8 = 0x05;

// Frame type constants — Agent → Host (exec channel).
const MSG_STDOUT: u8 = 0x10;
const MSG_STDERR: u8 = 0x11;
const MSG_EXIT: u8 = 0x12;

/// Maximum allowed frame payload size (16 MiB).
pub(crate) const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

// =============================================================================
// Public types
// =============================================================================

/// A chunk of output emitted by a guest process.
#[derive(Debug, Clone)]
pub struct OutputChunk {
    /// `"stdout"`, `"stderr"`, or `"exit"`.
    pub stream: String,
    /// Raw bytes (empty when `stream == "exit"`).
    pub data: Vec<u8>,
    /// Exit code — only meaningful when `stream == "exit"`.
    pub exit_code: i32,
}

/// A message the host sends to the guest during an exec/run session.
#[derive(Debug)]
pub enum ExecInputMsg {
    /// Raw bytes to forward to the process's stdin.
    Stdin(Vec<u8>),
    /// Resize the pseudo-TTY.
    Resize { width: u16, height: u16 },
    /// Signal EOF on the process's stdin.
    Eof,
}

/// Parameters forwarded to the guest agent as the session-start frame.
#[derive(Debug, Serialize, Deserialize)]
pub struct StartCommand {
    pub cmd: Vec<String>,
    pub env: HashMap<String, String>,
    pub working_dir: String,
    pub user: String,
    pub tty: bool,
    pub tty_width: u16,
    pub tty_height: u16,
    pub timeout_seconds: u32,
}

// =============================================================================
// Internal helpers
// =============================================================================

/// How long to wait for the guest agent to start accepting vsock connections.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Interval between vsock connection attempts while the guest is still booting.
const AGENT_READY_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Open a host-initiated vsock connection to the guest agent (port 52).
///
/// Retries the `CONNECT` handshake until the guest agent accepts or
/// [`AGENT_READY_TIMEOUT`] elapses.  Firecracker responds with "connection
/// closed" when no listener is active on the guest vsock port yet (kernel
/// still booting / vm-agent not started), so that response is treated as a
/// transient error and retried.
async fn connect_to_agent(uds_path: &Path) -> Result<UnixStream> {
    connect_to_port(uds_path, AGENT_PORT).await
}

/// Open a host-initiated vsock connection to an arbitrary guest port.
///
/// Same retry semantics as [`connect_to_agent`].  Used by the file I/O and
/// port-forward modules which operate on different vsock ports.
pub(crate) async fn connect_to_port(uds_path: &Path, port: u32) -> Result<UnixStream> {
    let deadline = tokio::time::Instant::now() + AGENT_READY_TIMEOUT;
    loop {
        match try_vsock_handshake(uds_path, port).await {
            Ok(stream) => return Ok(stream),
            Err(VmmError::Vsock(ref msg)) if msg.contains("connection closed") => {}
            Err(e) => return Err(e),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(VmmError::Vsock(format!(
                "vsock port {port} on {} did not become ready within {}s",
                uds_path.display(),
                AGENT_READY_TIMEOUT.as_secs(),
            )));
        }
        tokio::time::sleep(AGENT_READY_POLL_INTERVAL).await;
    }
}

/// Single attempt: connect to the Firecracker vsock UDS and complete the
/// `CONNECT {port}` / `OK` handshake.
async fn try_vsock_handshake(uds_path: &Path, port: u32) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(uds_path)
        .await
        .map_err(|e| VmmError::Vsock(format!("connect to {}: {e}", uds_path.display())))?;

    // Firecracker vsock host-initiated handshake.
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await
        .map_err(|e| VmmError::Vsock(format!("vsock CONNECT write: {e}")))?;

    // Read "OK {port}\n".
    let mut buf = [0u8; 64];
    let mut i = 0usize;
    loop {
        let n = stream
            .read(&mut buf[i..=i])
            .await
            .map_err(|e| VmmError::Vsock(format!("vsock handshake read: {e}")))?;
        if n == 0 {
            return Err(VmmError::Vsock("vsock handshake: connection closed".into()));
        }
        if buf[i] == b'\n' {
            break;
        }
        i += 1;
        if i >= buf.len() - 1 {
            return Err(VmmError::Vsock("vsock handshake: response too long".into()));
        }
    }
    let resp = std::str::from_utf8(&buf[..=i])
        .map_err(|_| VmmError::Vsock("vsock handshake: non-UTF-8 response".into()))?;
    if !resp.starts_with("OK") {
        return Err(VmmError::Vsock(format!(
            "vsock handshake: unexpected response: {resp:?}"
        )));
    }
    Ok(stream)
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
                    MSG_STDOUT => OutputChunk {
                        stream: "stdout".into(),
                        data: payload,
                        exit_code: 0,
                    },
                    MSG_STDERR => OutputChunk {
                        stream: "stderr".into(),
                        data: payload,
                        exit_code: 0,
                    },
                    MSG_EXIT => {
                        let code = if payload.len() >= 4 {
                            i32::from_le_bytes(payload[..4].try_into().unwrap())
                        } else {
                            0
                        };
                        let _ = tx
                            .send(Ok(OutputChunk {
                                stream: "exit".into(),
                                data: vec![],
                                exit_code: code,
                            }))
                            .await;
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
    uds_path: &Path,
    start: StartCommand,
) -> Result<mpsc::Receiver<Result<OutputChunk>>> {
    let mut stream = connect_to_agent(uds_path).await?;

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
    uds_path: &Path,
    start: StartCommand,
) -> Result<(
    mpsc::Sender<ExecInputMsg>,
    mpsc::Receiver<Result<OutputChunk>>,
)> {
    let stream = connect_to_agent(uds_path).await?;

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

/// Synchronise the guest clock to the current host time.
///
/// Sends [`MSG_CLOCK_SYNC`] to the exec channel (vsock port 52) and waits for
/// `MSG_EXIT(0)`.  Should be called immediately after `restore_sandbox()`
/// completes so the guest does not run with a stale timestamp from snapshot
/// creation time.
pub async fn sync_clock(uds_path: &Path) -> Result<()> {
    let mut stream = connect_to_agent(uds_path).await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| VmmError::Vsock(format!("system time error: {e}")))?;

    let secs = i64::try_from(now.as_secs())
        .map_err(|e| VmmError::Vsock(format!("unix timestamp overflow: {e}")))?;
    let nanos = now.subsec_nanos();
    let mut payload = [0u8; 12];
    payload[..8].copy_from_slice(&secs.to_le_bytes());
    payload[8..].copy_from_slice(&nanos.to_le_bytes());

    write_frame(&mut stream, MSG_CLOCK_SYNC, &payload)
        .await
        .map_err(|e| VmmError::Vsock(format!("write MSG_CLOCK_SYNC: {e}")))?;

    let (msg_type, payload) = read_frame(&mut stream)
        .await
        .map_err(|e| VmmError::Vsock(format!("read clock sync response: {e}")))?;

    if msg_type != MSG_EXIT {
        return Err(VmmError::Vsock(format!(
            "clock sync: unexpected response type 0x{msg_type:02x}"
        )));
    }
    let code = if payload.len() >= 4 {
        i32::from_le_bytes(payload[..4].try_into().unwrap())
    } else {
        0
    };
    if code != 0 {
        return Err(VmmError::Vsock(format!(
            "clock sync: agent returned exit code {code}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw frame byte-by-byte for use in read tests.
    fn make_raw_frame(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(msg_type);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        buf
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
            env: HashMap::new(),
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
