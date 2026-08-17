//! `sync_clock`: synchronise the guest clock after a boot or restore.

use std::time::Duration;

use arcbox_vm_driver::Vsock;
use tracing::info;

use super::{MSG_CLOCK_SYNC, MSG_EXIT, connect_to_agent, read_frame, write_frame};
use crate::error::{Result, VmmError};

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

#[cfg(test)]
mod tests {
    use super::super::MSG_STDOUT;
    use super::*;

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
}
