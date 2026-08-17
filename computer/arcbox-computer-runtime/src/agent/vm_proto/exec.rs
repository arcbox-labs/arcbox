//! `run` and `exec`: command execution over the exec channel.

use tokio::sync::mpsc;

use arcbox_vm_driver::Vsock;
use arcbox_vm_proto::exec::{MSG_EOF, MSG_RESIZE, MSG_SIGNAL, MSG_START, MSG_STDIN};

use super::{StartCommand, connect_to_agent, drain_output, write_frame};
use crate::agent::{ExecInputMsg, OutputChunk};
use crate::error::{Result, VmmError};

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
