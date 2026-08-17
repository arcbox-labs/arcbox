//! `reconfigure_network`: re-address the guest after a fresh-network
//! restore.

use std::time::Duration;

use arcbox_vm_driver::Vsock;
use tracing::info;

use super::{MSG_EXIT, MSG_NET_RECONFIG, connect_to_agent, read_frame, write_frame};
use crate::error::{Result, VmmError};
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
    use super::*;

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
