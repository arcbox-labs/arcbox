//! Execution RPC handlers (the execution redesign, CORE-55/56).
//!
//! Executions are addressable: start returns an identity, attach streams
//! offset-addressed output, stdin writes are offset-idempotent, and signal /
//! resize / wait go through the id rather than any stream.

use std::time::Duration;

use arcbox_connect::sandbox_v1;
use arcbox_vm::ExecutionSpec;
use buffa::Message;
use tokio::io::AsyncWrite;

use super::{SandboxService, convert};
use crate::error::SandboxError;
use crate::rpc::{ErrorResponse, MessageType, write_message};

impl SandboxService {
    /// Start an execution and return its identity.
    pub async fn start_execution(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::Execution, SandboxError> {
        let req = sandbox_v1::StartExecutionRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let tty_size = req
            .tty_size
            .map(|s| {
                let width = u16::try_from(s.width).map_err(|_| {
                    SandboxError::InvalidArgument(format!("invalid tty width {}", s.width))
                })?;
                let height = u16::try_from(s.height).map_err(|_| {
                    SandboxError::InvalidArgument(format!("invalid tty height {}", s.height))
                })?;
                Ok::<_, SandboxError>((width, height))
            })
            .transpose()?;

        let spec = ExecutionSpec {
            id: (!req.execution_id.is_empty()).then(|| req.execution_id.clone()),
            cmd: req.cmd,
            env: req.env.into_iter().collect(),
            working_dir: req.working_dir,
            user: req.user,
            tty: req.tty,
            tty_size,
            timeout_seconds: req.timeout_seconds,
            stdin: req.stdin,
        };
        let snapshot = self
            .manager
            .start_execution(&req.sandbox_id, spec)
            .await
            .map_err(SandboxError::from)?;
        Ok(convert::execution_to_proto(&snapshot))
    }

    /// Stream `SandboxExecEvent` frames for an attach request: a `started`
    /// preamble, output chunks from the requested offsets, then a terminal
    /// `exited` frame carrying the final state.
    pub async fn handle_attach<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let req = match sandbox_v1::AttachExecutionRequest::decode_from_slice(payload) {
            Ok(r) => r,
            Err(e) => {
                let err = ErrorResponse::new(400, format!("decode error: {e}"));
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        let (snapshot, mut rx) = match self.manager.attach_execution(
            &req.sandbox_id,
            &req.execution_id,
            req.stdout_offset,
            req.stderr_offset,
        ) {
            Ok(pair) => pair,
            Err(e) => {
                let e = SandboxError::from(e);
                let err = ErrorResponse::new(e.status_code(), e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };
        let tty = snapshot.tty;

        let started = sandbox_v1::ExecutionEvent {
            event: sandbox_v1::ExecutionStarted {
                execution: convert::execution_to_proto(&snapshot).into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        write_message(
            stream,
            MessageType::SandboxExecEvent,
            trace_id,
            &started.encode_to_vec(),
        )
        .await?;

        while let Some(chunk) = rx.recv().await {
            let event = sandbox_v1::ExecutionEvent {
                event: sandbox_v1::ExecutionOutput {
                    channel: convert::channel_to_proto(chunk.channel, tty).into(),
                    offset: chunk.offset,
                    data: chunk.data,
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            };
            write_message(
                stream,
                MessageType::SandboxExecEvent,
                trace_id,
                &event.encode_to_vec(),
            )
            .await?;
        }

        // The receiver closes once the execution exited and both channels are
        // drained; fetch the terminal state for the final frame. A NotFound
        // here means the retention GC raced us — fall back to the attach-time
        // snapshot marked as expired.
        let execution = match self
            .manager
            .wait_execution(&req.sandbox_id, &req.execution_id, Duration::ZERO)
            .await
        {
            Ok(fin) => convert::execution_to_proto(&fin),
            Err(_) => {
                let mut expired = convert::execution_to_proto(&snapshot);
                expired.state = sandbox_v1::ExecutionState::Exited.into();
                expired.error = "execution record expired".into();
                expired
            }
        };
        let exited = sandbox_v1::ExecutionEvent {
            event: sandbox_v1::ExecutionExited {
                execution: execution.into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        write_message(
            stream,
            MessageType::SandboxExecEvent,
            trace_id,
            &exited.encode_to_vec(),
        )
        .await?;
        Ok(())
    }

    /// Offset-idempotent stdin write.
    pub async fn write_stdin(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::StdinStatus, SandboxError> {
        let req = sandbox_v1::WriteStdinRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let state = self
            .manager
            .write_stdin(
                &req.sandbox_id,
                &req.execution_id,
                req.offset,
                &req.data,
                req.eof,
            )
            .await
            .map_err(SandboxError::from)?;
        Ok(convert::stdin_to_proto(state))
    }

    /// Current stdin acceptance state.
    pub fn stdin_status(&self, payload: &[u8]) -> Result<sandbox_v1::StdinStatus, SandboxError> {
        let req = sandbox_v1::GetStdinStatusRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let state = self
            .manager
            .stdin_status(&req.sandbox_id, &req.execution_id)
            .map_err(SandboxError::from)?;
        Ok(convert::stdin_to_proto(state))
    }

    /// Deliver a POSIX signal to a running execution.
    pub async fn signal_execution(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::SignalExecutionRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        // Signal enum values ARE the POSIX numbers; the manager validates
        // the range, so an UNSPECIFIED (0) request is rejected there.
        self.manager
            .signal_execution(&req.sandbox_id, &req.execution_id, req.signal.to_i32())
            .await
            .map_err(SandboxError::from)
    }

    /// Resize a TTY execution's terminal.
    pub async fn resize_execution(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::ResizeExecutionTtyRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let size = req
            .size
            .ok_or_else(|| SandboxError::InvalidArgument("missing terminal size".into()))?;
        let width = u16::try_from(size.width)
            .map_err(|_| SandboxError::InvalidArgument(format!("invalid width {}", size.width)))?;
        let height = u16::try_from(size.height).map_err(|_| {
            SandboxError::InvalidArgument(format!("invalid height {}", size.height))
        })?;
        self.manager
            .resize_execution(&req.sandbox_id, &req.execution_id, width, height)
            .await
            .map_err(SandboxError::from)
    }

    /// Wait for an execution to exit (zero timeout polls).
    pub async fn wait_execution(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::Execution, SandboxError> {
        let req = sandbox_v1::WaitExecutionRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let snapshot = self
            .manager
            .wait_execution(
                &req.sandbox_id,
                &req.execution_id,
                Duration::from_secs(u64::from(req.timeout_seconds)),
            )
            .await
            .map_err(SandboxError::from)?;
        Ok(convert::execution_to_proto(&snapshot))
    }

    /// List a sandbox's retained executions, running and exited.
    pub fn list_executions(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::ListExecutionsResponse, SandboxError> {
        let req = sandbox_v1::ListExecutionsRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let snapshots = self
            .manager
            .list_executions(&req.sandbox_id)
            .map_err(SandboxError::from)?;
        Ok(sandbox_v1::ListExecutionsResponse {
            executions: snapshots.iter().map(convert::execution_to_proto).collect(),
            ..Default::default()
        })
    }

    /// Wait for a TCP listener inside the sandbox (the caller resolves the
    /// timeout default; 0 checks once).
    pub async fn wait_for_port(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::WaitForPortRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let port = u16::try_from(req.port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| SandboxError::InvalidArgument(format!("invalid port {}", req.port)))?;
        self.manager
            .wait_sandbox_port(
                &req.sandbox_id,
                port,
                Duration::from_secs(u64::from(req.timeout_seconds)),
            )
            .await
            .map_err(SandboxError::from)
    }
}
