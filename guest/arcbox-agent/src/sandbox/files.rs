//! Sandbox file I/O streaming handlers.

use arcbox_protocol::sandbox_v1;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use super::SandboxService;
use crate::error::SandboxError;
use crate::rpc::{ErrorResponse, MessageType, read_message, write_message};

impl SandboxService {
    /// Stream a file out of a sandbox as `SandboxFileData` frames.
    ///
    /// The final frame carries `done == true`. Errors (missing sandbox,
    /// missing file, wrong state) are reported as a single `Error` frame.
    pub async fn handle_read_file<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let req = match sandbox_v1::ReadFileRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => {
                let err = ErrorResponse::new(400, format!("decode error: {e}"));
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        let data = match self.manager.read_sandbox_file(&req.id, &req.path).await {
            Ok(d) => d,
            Err(e) => {
                let e = SandboxError::from(e);
                let err = ErrorResponse::new(e.status_code(), e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        const CHUNK_SIZE: usize = 1024 * 1024;
        for chunk in data.chunks(CHUNK_SIZE) {
            let msg = sandbox_v1::FileChunk {
                data: chunk.to_vec(),
                done: false,
            };
            write_message(
                stream,
                MessageType::SandboxFileData,
                trace_id,
                &msg.encode_to_vec(),
            )
            .await?;
        }
        let done = sandbox_v1::FileChunk {
            data: Vec::new(),
            done: true,
        };
        write_message(
            stream,
            MessageType::SandboxFileData,
            trace_id,
            &done.encode_to_vec(),
        )
        .await?;
        Ok(())
    }

    /// Receive a `SandboxFileChunk` stream and store it inside the sandbox.
    ///
    /// The open payload was already parsed by the dispatcher frame; chunk
    /// frames follow on the same connection until `done == true`, then a
    /// `SandboxFileWriteResponse` (or `Error`) frame answers.
    pub async fn handle_write_file<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let open = match sandbox_v1::WriteFileOpen::decode(payload) {
            Ok(o) => o,
            Err(e) => {
                let err = ErrorResponse::new(400, format!("decode error: {e}"));
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        let max = arcbox_vm::file_io::proto::MAX_FILE_SIZE;
        let mut data = Vec::new();
        loop {
            match read_message(stream).await {
                Ok((MessageType::SandboxFileChunk, _, frame)) => {
                    let chunk = match sandbox_v1::FileChunk::decode(frame.as_slice()) {
                        Ok(c) => c,
                        Err(e) => {
                            let err = ErrorResponse::new(400, format!("decode error: {e}"));
                            write_message(stream, MessageType::Error, trace_id, &err.encode())
                                .await?;
                            return Ok(());
                        }
                    };
                    if data.len() + chunk.data.len() > max {
                        let err = ErrorResponse::new(
                            400,
                            format!("file exceeds the {max}-byte write limit"),
                        );
                        write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                        return Ok(());
                    }
                    data.extend_from_slice(&chunk.data);
                    if chunk.done {
                        break;
                    }
                }
                Ok((other, _, _)) => {
                    let err = ErrorResponse::new(
                        400,
                        format!("unexpected frame during write: {other:?}"),
                    );
                    write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(error = %e, "write stream ended before done chunk");
                    return Ok(());
                }
            }
        }

        let mode = if open.mode == 0 { 0o644 } else { open.mode };
        match self
            .manager
            .write_sandbox_file(&open.id, &open.path, mode, &data)
            .await
        {
            Ok(()) => {
                write_message(stream, MessageType::SandboxFileWriteResponse, trace_id, &[]).await?;
            }
            Err(e) => {
                let e = SandboxError::from(e);
                let err = ErrorResponse::new(e.status_code(), e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
            }
        }
        Ok(())
    }
}
