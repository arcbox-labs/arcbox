//! Sandbox file I/O streaming handlers and path verbs (CORE-62).

use std::time::Duration;

use arcbox_connect::sandbox_v1;
use buffa::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{SandboxService, convert};
use crate::error::SandboxError;
use crate::rpc::{ErrorResponse, MessageType, read_message, write_message};

/// How often an idle watch stream emits a keepalive frame. Below the
/// daemon's own 15 s client-facing keepalive so the host↔guest hop never
/// looks dead first.
const WATCH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

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
        let req = match sandbox_v1::ReadFileRequest::decode_from_slice(payload) {
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
                ..Default::default()
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
            done: true,
            ..Default::default()
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
        let open = match sandbox_v1::WriteFileOpen::decode_from_slice(payload) {
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
                    let chunk = match sandbox_v1::FileChunk::decode_from_slice(&frame) {
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

    /// Stat one path inside a sandbox (symlinks reported, not followed).
    pub async fn stat_file(&self, payload: &[u8]) -> Result<sandbox_v1::FileStat, SandboxError> {
        let req = sandbox_v1::StatFileRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let dto = self
            .manager
            .stat_sandbox_path(&req.id, &req.path)
            .await
            .map_err(SandboxError::from)?;
        Ok(convert::file_stat_to_proto(&dto))
    }

    /// List a directory inside a sandbox, non-recursively.
    pub async fn list_dir(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::ListDirResponse, SandboxError> {
        let req = sandbox_v1::ListDirRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let entries = self
            .manager
            .list_sandbox_dir(&req.id, &req.path)
            .await
            .map_err(SandboxError::from)?;
        Ok(sandbox_v1::ListDirResponse {
            entries: entries.iter().map(convert::file_stat_to_proto).collect(),
            ..Default::default()
        })
    }

    /// Create a directory (with `mkdir -p` semantics) inside a sandbox.
    pub async fn make_dir(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::MakeDirRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let mode = if req.mode == 0 { 0o755 } else { req.mode };
        self.manager
            .make_sandbox_dir(&req.id, &req.path, mode)
            .await
            .map_err(SandboxError::from)
    }

    /// Remove a file, symlink, or directory inside a sandbox.
    pub async fn remove_entry(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::RemoveEntryRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        self.manager
            .remove_sandbox_path(&req.id, &req.path, req.recursive)
            .await
            .map_err(SandboxError::from)
    }

    /// Rename / move an entry within a sandbox.
    pub async fn move_entry(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::MoveEntryRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        self.manager
            .move_sandbox_path(&req.id, &req.from_path, &req.to_path)
            .await
            .map_err(SandboxError::from)
    }

    /// Stream `SandboxFileWatchEvent` frames for a directory watch.
    ///
    /// An immediate keepalive frame confirms the watch is established (it
    /// also lets the daemon's paused-sandbox first-frame peek return fast);
    /// further keepalives are interleaved while idle. The stream ends with
    /// `SandboxFileWatchEnd` when the sandbox stops (the vm-agent side of
    /// the vsock channel closes), or an `Error` frame on setup and stream
    /// failures. Host cancellation surfaces as a failed write here, which
    /// drops the watch and closes the vm-agent connection.
    pub async fn handle_watch_dir<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let req = match sandbox_v1::WatchDirRequest::decode_from_slice(payload) {
            Ok(r) => r,
            Err(e) => {
                let err = ErrorResponse::new(400, format!("decode error: {e}"));
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        let mut watch = match self
            .manager
            .watch_sandbox_dir(&req.id, &req.path, req.recursive)
            .await
        {
            Ok(watch) => watch,
            Err(e) => {
                let e = SandboxError::from(e);
                let err = ErrorResponse::new(e.status_code(), e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        // Relay events through a channel: `next_event` is not cancellation
        // safe (a frame read spans several awaits), so it must not race a
        // keepalive tick inside select!. Dropping the receiver stops the
        // relay, which drops the watch and closes the vm-agent connection.
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = watch.next_event() => match event {
                        Ok(Some(event)) => {
                            if event_tx.send(Ok(Some(event))).await.is_err() {
                                return;
                            }
                        }
                        terminal => {
                            let _ = event_tx.send(terminal).await;
                            return;
                        }
                    },
                    // The handler dropped the receiver (host cancelled): stop
                    // relaying even while no event ever arrives, so the watch
                    // and its vm-agent connection are released immediately
                    // rather than on the next filesystem event. Cutting
                    // `next_event` mid-frame is fine — the connection is being
                    // torn down either way.
                    () = event_tx.closed() => return,
                }
            }
        });

        write_watch_keepalive(stream, trace_id).await?;
        let mut keepalive = tokio::time::interval_at(
            tokio::time::Instant::now() + WATCH_KEEPALIVE_INTERVAL,
            WATCH_KEEPALIVE_INTERVAL,
        );
        loop {
            tokio::select! {
                event = event_rx.recv() => match event {
                    Some(Ok(Some(event))) => {
                        let frame = sandbox_v1::WatchDirResponse {
                            payload: convert::fs_event_to_proto(event).into(),
                            ..Default::default()
                        };
                        write_message(
                            stream,
                            MessageType::SandboxFileWatchEvent,
                            trace_id,
                            &frame.encode_to_vec(),
                        )
                        .await?;
                    }
                    // Clean EOF from the vm-agent: the sandbox stopped.
                    Some(Ok(None)) | None => {
                        write_message(stream, MessageType::SandboxFileWatchEnd, trace_id, &[])
                            .await?;
                        return Ok(());
                    }
                    Some(Err(e)) => {
                        let e = SandboxError::from(e);
                        let err = ErrorResponse::new(e.status_code(), e.to_string());
                        write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                        return Ok(());
                    }
                },
                _ = keepalive.tick() => write_watch_keepalive(stream, trace_id).await?,
            }
        }
    }
}

/// One `SandboxFileWatchEvent` frame carrying a keepalive payload.
async fn write_watch_keepalive<S>(stream: &mut S, trace_id: &str) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frame = sandbox_v1::WatchDirResponse {
        payload: sandbox_v1::KeepAlive::default().into(),
        ..Default::default()
    };
    write_message(
        stream,
        MessageType::SandboxFileWatchEvent,
        trace_id,
        &frame.encode_to_vec(),
    )
    .await
}
