#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sandbox_smoke example is Linux-only");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use arcbox_connect::sandbox_v1::{
        AttachExecutionRequest, CreateSandboxRequest, CreateSandboxResponse, Execution,
        ExecutionEvent, InspectSandboxRequest, ListSandboxesRequest, ListSandboxesResponse,
        RemoveSandboxRequest, SandboxState, StartExecutionRequest, StopSandboxRequest,
        execution_event, exit_status,
    };
    use arcbox_constants::ports::AGENT_PORT;
    use arcbox_constants::wire::MessageType;
    use buffa::Message;
    use bytes::{Buf, BufMut, BytesMut};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Instant, sleep};
    use tokio_vsock::{VMADDR_CID_LOCAL, VsockAddr, VsockStream};

    const ERROR_HEADER_SIZE: usize = 8;

    pub async fn run() -> Result<()> {
        let mut stream = connect_with_retry().await?;

        // Empty template = the built-in busybox image.
        let create = CreateSandboxRequest {
            labels: std::iter::once(("suite".to_string(), "agent-smoke".to_string())).collect(),
            ..Default::default()
        };

        let created: CreateSandboxResponse = rpc_unary(
            &mut stream,
            MessageType::SandboxCreateRequest,
            MessageType::SandboxCreateResponse,
            &create,
        )
        .await
        .context("sandbox create failed")?;
        if created.id.is_empty() {
            bail!("create returned empty sandbox id");
        }
        println!(
            "created sandbox id={} ip={}",
            created.id, created.ip_address
        );

        let sandbox_id = created.id;

        let list: ListSandboxesResponse = rpc_unary(
            &mut stream,
            MessageType::SandboxListRequest,
            MessageType::SandboxListResponse,
            &ListSandboxesRequest::default(),
        )
        .await
        .context("sandbox list failed")?;
        if !list.sandboxes.iter().any(|s| s.id == sandbox_id) {
            bail!("created sandbox {sandbox_id} not found in list");
        }

        wait_until_ready(&mut stream, &sandbox_id, Duration::from_secs(45)).await?;

        let start_req = StartExecutionRequest {
            sandbox_id: sandbox_id.clone(),
            execution_id: "agent-smoke-echo".to_string(),
            cmd: vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                "echo arcbox-agent-smoke".to_string(),
            ],
            timeout_seconds: 30,
            ..Default::default()
        };
        execute_and_assert_success(&mut stream, start_req).await?;

        rpc_unary_empty(
            &mut stream,
            MessageType::SandboxStopRequest,
            MessageType::SandboxStopResponse,
            &StopSandboxRequest {
                id: sandbox_id.clone(),
                timeout_seconds: 20,
                ..Default::default()
            },
        )
        .await
        .context("sandbox stop failed")?;

        rpc_unary_empty(
            &mut stream,
            MessageType::SandboxRemoveRequest,
            MessageType::SandboxRemoveResponse,
            &RemoveSandboxRequest {
                id: sandbox_id.clone(),
                force: true,
                ..Default::default()
            },
        )
        .await
        .context("sandbox remove failed")?;

        println!("sandbox smoke passed for id={sandbox_id}");
        Ok(())
    }

    async fn connect_with_retry() -> Result<VsockStream> {
        let cid = resolve_target_cid();
        let addr = VsockAddr::new(cid, AGENT_PORT);

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match VsockStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) if Instant::now() < deadline => {
                    eprintln!("waiting for agent vsock listener: {e}");
                    sleep(Duration::from_millis(400)).await;
                }
                Err(e) => return Err(e).context("connect to arcbox-agent over vsock failed"),
            }
        }
    }

    fn resolve_target_cid() -> u32 {
        if let Some(cid) = std::env::var("ARCBOX_AGENT_CID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
        {
            return cid;
        }

        if let Some(cid) = std::fs::read_to_string("/proc/sys/net/vsock/local_cid")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        {
            return cid;
        }

        VMADDR_CID_LOCAL
    }

    async fn wait_until_ready(stream: &mut VsockStream, id: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let info: arcbox_connect::sandbox_v1::SandboxInfo = rpc_unary(
                stream,
                MessageType::SandboxInspectRequest,
                MessageType::SandboxInspectResponse,
                &InspectSandboxRequest {
                    id: id.to_string(),
                    ..Default::default()
                },
            )
            .await?;

            if info.state == SandboxState::Ready {
                return Ok(());
            }
            if info.state == SandboxState::Failed {
                bail!("sandbox transitioned to failed state: {}", info.error);
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for sandbox {id} to become ready");
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Start an execution, attach to its output, and assert a zero exit.
    async fn execute_and_assert_success(
        stream: &mut VsockStream,
        req: StartExecutionRequest,
    ) -> Result<()> {
        let started: Execution = rpc_unary(
            stream,
            MessageType::SandboxExecStartRequest,
            MessageType::SandboxExecStartResponse,
            &req,
        )
        .await
        .context("start execution failed")?;

        let attach = AttachExecutionRequest {
            sandbox_id: req.sandbox_id.clone(),
            execution_id: started.id.clone(),
            ..Default::default()
        };
        write_message(
            stream,
            MessageType::SandboxExecAttachRequest,
            "",
            &attach.encode_to_vec(),
        )
        .await?;

        loop {
            let (resp_type_raw, _trace, resp_payload) = read_message(stream).await?;

            if resp_type_raw == MessageType::Error as u32 {
                let msg = parse_error_response(&resp_payload);
                bail!("execution attach returned error: {msg}");
            }
            if resp_type_raw != MessageType::SandboxExecEvent as u32 {
                bail!("unexpected response while attached: 0x{resp_type_raw:04x}");
            }

            let event = ExecutionEvent::decode_from_slice(&resp_payload)
                .context("decode ExecutionEvent payload failed")?;
            match event.event {
                Some(execution_event::Event::Output(output)) => {
                    print!("{}", String::from_utf8_lossy(&output.data));
                }
                Some(execution_event::Event::Exited(exited)) => {
                    let status = exited
                        .execution
                        .into_option()
                        .and_then(|e| e.exit_status.into_option())
                        .and_then(|s| s.status);
                    match status {
                        Some(exit_status::Status::Code(0)) => return Ok(()),
                        other => bail!("execution did not exit cleanly: {other:?}"),
                    }
                }
                Some(execution_event::Event::Started(_) | execution_event::Event::KeepAlive(_))
                | None => {}
            }
        }
    }

    async fn rpc_unary<TReq, TResp>(
        stream: &mut VsockStream,
        req_type: MessageType,
        expected_resp_type: MessageType,
        req: &TReq,
    ) -> Result<TResp>
    where
        TReq: Message,
        TResp: Message + Default,
    {
        let payload = req.encode_to_vec();
        write_message(stream, req_type, "", &payload).await?;
        let (resp_type_raw, _trace, resp_payload) = read_message(stream).await?;

        if resp_type_raw == MessageType::Error as u32 {
            let msg = parse_error_response(&resp_payload);
            bail!("{msg}");
        }
        if resp_type_raw != expected_resp_type as u32 {
            bail!(
                "unexpected response type: got=0x{resp_type_raw:04x} expected=0x{:04x}",
                expected_resp_type as u32
            );
        }

        TResp::decode_from_slice(&resp_payload).context("decode unary response failed")
    }

    async fn rpc_unary_empty<TReq>(
        stream: &mut VsockStream,
        req_type: MessageType,
        expected_resp_type: MessageType,
        req: &TReq,
    ) -> Result<()>
    where
        TReq: Message,
    {
        let payload = req.encode_to_vec();
        write_message(stream, req_type, "", &payload).await?;
        let (resp_type_raw, _trace, resp_payload) = read_message(stream).await?;

        if resp_type_raw == MessageType::Error as u32 {
            let msg = parse_error_response(&resp_payload);
            bail!("{msg}");
        }
        if resp_type_raw != expected_resp_type as u32 && resp_type_raw != MessageType::Empty as u32
        {
            bail!(
                "unexpected empty response type: got=0x{resp_type_raw:04x} expected=0x{:04x}/empty",
                expected_resp_type as u32
            );
        }

        Ok(())
    }

    async fn write_message(
        stream: &mut VsockStream,
        msg_type: MessageType,
        trace_id: &str,
        payload: &[u8],
    ) -> Result<()> {
        let trace_bytes = trace_id.as_bytes();
        let trace_len = trace_bytes.len().min(u16::MAX as usize);
        let length = 4 + 2 + trace_len + payload.len();

        let mut buf = BytesMut::with_capacity(8 + 2 + trace_len + payload.len());
        buf.put_u32(length as u32);
        buf.put_u32(msg_type as u32);
        buf.put_u16(trace_len as u16);
        if trace_len > 0 {
            buf.extend_from_slice(&trace_bytes[..trace_len]);
        }
        buf.extend_from_slice(payload);

        stream.write_all(&buf).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn read_message(stream: &mut VsockStream) -> Result<(u32, String, Vec<u8>)> {
        let mut header = [0_u8; 8];
        stream.read_exact(&mut header).await?;
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let msg_type = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

        let remaining = length.saturating_sub(4);
        let mut body = vec![0_u8; remaining];
        if remaining > 0 {
            stream.read_exact(&mut body).await?;
        }

        if body.len() < 2 {
            return Ok((msg_type, String::new(), body));
        }
        let mut cursor = std::io::Cursor::new(body.as_slice());
        let trace_len = cursor.get_u16() as usize;
        if body.len() < 2 + trace_len {
            return Ok((msg_type, String::new(), Vec::new()));
        }

        let trace_start = 2;
        let trace_end = 2 + trace_len;
        let trace_id = String::from_utf8(body[trace_start..trace_end].to_vec()).unwrap_or_default();
        let payload = body[trace_end..].to_vec();
        Ok((msg_type, trace_id, payload))
    }

    fn parse_error_response(payload: &[u8]) -> String {
        if payload.len() < ERROR_HEADER_SIZE {
            return "unknown error".to_string();
        }
        let mut cursor = std::io::Cursor::new(payload);
        let _code = cursor.get_i32();
        let msg_len = cursor.get_u32() as usize;
        if payload.len() < ERROR_HEADER_SIZE + msg_len {
            return "truncated error message".to_string();
        }
        String::from_utf8(payload[ERROR_HEADER_SIZE..ERROR_HEADER_SIZE + msg_len].to_vec())
            .unwrap_or_else(|_| "invalid error payload".to_string())
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    linux::run().await
}
