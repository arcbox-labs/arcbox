//! `wait_for_port`: wait for a guest listener through the agent's
//! listen-table watcher.

use std::time::Duration;

use arcbox_vm_driver::Vsock;

use super::{MSG_EXIT, MSG_WAIT_PORT, WaitPortReq, connect_to_agent, read_frame, write_frame};
use crate::agent::PortWait;
use crate::error::{ComputerError, Result};
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
        .map_err(|e| ComputerError::Vsock(format!("encode WaitPortReq: {e}")))?;
    write_frame(stream, MSG_WAIT_PORT, &payload)
        .await
        .map_err(|e| ComputerError::Vsock(format!("write MSG_WAIT_PORT: {e}")))?;

    let read_deadline = timeout + Duration::from_secs(5);
    let (msg_type, payload) = tokio::time::timeout(read_deadline, read_frame(stream))
        .await
        .map_err(|_| ComputerError::Vsock("wait for port: timed out waiting for response".into()))?
        .map_err(|e| ComputerError::Vsock(format!("read wait-port response: {e}")))?;

    if msg_type != MSG_EXIT {
        return Err(ComputerError::Vsock(format!(
            "wait for port: unexpected response type 0x{msg_type:02x}"
        )));
    }
    if payload.len() < 4 {
        return Err(ComputerError::Vsock(format!(
            "wait for port: payload too short ({} bytes, expected 4)",
            payload.len()
        )));
    }
    match i32::from_le_bytes(payload[..4].try_into().unwrap()) {
        0 => Ok(PortWait::Listening),
        1 => Ok(PortWait::Deadline),
        code => Err(ComputerError::Vsock(format!(
            "wait for port: agent returned exit code {code}"
        ))),
    }
}
