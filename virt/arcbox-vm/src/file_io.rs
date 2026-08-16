//! Host-side file I/O client over the file channel (`FILE_PORT` = 53).
//!
//! The wire vocabulary — frame opcodes, request payloads, the stat/event
//! DTOs, and the per-verb flows — is [`arcbox_vm_proto::file`], re-exported
//! here as [`proto`] so `arcbox_vm::file_io::proto` keeps resolving for
//! every consumer. This module is the tokio client the manager drives:
//! one vsock connection per operation, timeouts, and the mapping of the
//! agent's errno-prefixed `FILE_ERR` payloads onto typed [`VmmError`]
//! variants (`decode_file_err`).

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;

use crate::error::{Result, VmmError};
use crate::vsock::{MAX_FRAME_SIZE, connect_to_port, read_frame, write_frame};

/// Per-operation timeout for file I/O over vsock.
const FILE_IO_TIMEOUT: Duration = Duration::from_mins(1);

/// The file-channel wire vocabulary, shared with `vm-agent`.
pub use arcbox_vm_proto::file as proto;

pub use proto::FILE_PORT;
use proto::{
    FILE_ACK, FILE_DATA, FILE_DONE, FILE_ERR, FILE_EVENT, FILE_LIST, FILE_LIST_REQ, FILE_MKDIR_REQ,
    FILE_MOVE_REQ, FILE_READ_REQ, FILE_REMOVE_REQ, FILE_STAT, FILE_STAT_REQ, FILE_WATCH_REQ,
    FILE_WRITE_REQ, FileStatDto, FsEventDto, ListDirReq, MAX_FILE_SIZE, MakeDirReq, MoveReq,
    RemoveReq, StatReq, WatchReq,
};

#[derive(Serialize)]
struct WriteReq<'a> {
    path: &'a str,
    mode: u32,
}

#[derive(Serialize)]
struct ReadReq<'a> {
    path: &'a str,
}

/// Write `data` to `path` inside the sandbox.
///
/// The guest agent creates any missing parent directories.  `mode` is the Unix
/// file permission bits (e.g. `0o644`); `0` defaults to `0o644` on the agent
/// side.
pub async fn write_file(uds_path: &Path, path: &str, mode: u32, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FILE_SIZE {
        return Err(VmmError::Vsock(format!(
            "file too large ({} bytes, max {MAX_FILE_SIZE})",
            data.len()
        )));
    }

    tokio::time::timeout(
        FILE_IO_TIMEOUT,
        write_file_inner(uds_path, path, mode, data),
    )
    .await
    .map_err(|_| VmmError::Vsock("file write: timed out".into()))?
}

async fn write_file_inner(uds_path: &Path, path: &str, mode: u32, data: &[u8]) -> Result<()> {
    let mut stream = connect_to_port(uds_path, FILE_PORT).await?;

    let req = serde_json::to_vec(&WriteReq { path, mode })
        .map_err(|e| VmmError::Vsock(format!("serialize WriteReq: {e}")))?;
    write_frame(&mut stream, FILE_WRITE_REQ, &req)
        .await
        .map_err(|e| VmmError::Vsock(format!("write FILE_WRITE_REQ: {e}")))?;

    // Stream data in MAX_FRAME_SIZE chunks.
    for chunk in data.chunks(MAX_FRAME_SIZE) {
        write_frame(&mut stream, FILE_DATA, chunk)
            .await
            .map_err(|e| VmmError::Vsock(format!("write FILE_DATA: {e}")))?;
    }
    write_frame(&mut stream, FILE_DONE, &[])
        .await
        .map_err(|e| VmmError::Vsock(format!("write FILE_DONE: {e}")))?;

    // Read the agent's response.
    let (resp_type, payload) = read_frame(&mut stream)
        .await
        .map_err(|e| VmmError::Vsock(format!("read write response: {e}")))?;

    match resp_type {
        FILE_ACK => Ok(()),
        FILE_ERR => Err(decode_file_err(&payload)),
        other => Err(VmmError::Vsock(format!(
            "file write: unexpected response type 0x{other:02x}"
        ))),
    }
}

/// Read the file at `path` inside the sandbox and return its contents.
pub async fn read_file(uds_path: &Path, path: &str) -> Result<Vec<u8>> {
    tokio::time::timeout(FILE_IO_TIMEOUT, read_file_inner(uds_path, path))
        .await
        .map_err(|_| VmmError::Vsock("file read: timed out".into()))?
}

async fn read_file_inner(uds_path: &Path, path: &str) -> Result<Vec<u8>> {
    let mut stream = connect_to_port(uds_path, FILE_PORT).await?;

    let req = serde_json::to_vec(&ReadReq { path })
        .map_err(|e| VmmError::Vsock(format!("serialize ReadReq: {e}")))?;
    write_frame(&mut stream, FILE_READ_REQ, &req)
        .await
        .map_err(|e| VmmError::Vsock(format!("write FILE_READ_REQ: {e}")))?;

    // Collect FILE_DATA chunks until FILE_DONE or FILE_ERR.
    let mut buf = Vec::new();
    loop {
        let (frame_type, payload) = read_frame(&mut stream)
            .await
            .map_err(|e| VmmError::Vsock(format!("read file data: {e}")))?;
        match frame_type {
            FILE_DATA => {
                buf.extend_from_slice(&payload);
                if buf.len() > MAX_FILE_SIZE {
                    return Err(VmmError::Vsock(format!(
                        "file too large (>{MAX_FILE_SIZE} bytes)"
                    )));
                }
            }
            FILE_DONE => return Ok(buf),
            FILE_ERR => return Err(decode_file_err(&payload)),
            other => {
                return Err(VmmError::Vsock(format!(
                    "file read: unexpected frame type 0x{other:02x}"
                )));
            }
        }
    }
}

/// Map a `FILE_ERR` payload onto a typed error.
///
/// Every verb — path verbs and read/write alike — carries the errno
/// prefixes from [`proto`]; anything else (including all errors from old
/// vm-agents) stays a vsock error.
fn decode_file_err(payload: &[u8]) -> VmmError {
    let text = String::from_utf8_lossy(payload).into_owned();
    if let Some(path) = text.strip_prefix(proto::ERR_NOT_FOUND) {
        VmmError::PathNotFound(path.to_owned())
    } else if let Some(path) = text.strip_prefix(proto::ERR_NOT_A_DIRECTORY) {
        VmmError::NotADirectory(path.to_owned())
    } else if let Some(path) = text.strip_prefix(proto::ERR_NOT_EMPTY) {
        VmmError::DirectoryNotEmpty(path.to_owned())
    } else {
        VmmError::Vsock(text)
    }
}

/// One request frame, one response frame. Returns the response payload when
/// the type matches `ok_type`; decodes `FILE_ERR` into a typed error.
async fn unary_file_op(
    uds_path: &Path,
    req_type: u8,
    req: &(impl Serialize + Sync),
    ok_type: u8,
) -> Result<Vec<u8>> {
    let payload =
        serde_json::to_vec(req).map_err(|e| VmmError::Vsock(format!("serialize request: {e}")))?;
    let op = async {
        let mut stream = connect_to_port(uds_path, FILE_PORT).await?;
        write_frame(&mut stream, req_type, &payload)
            .await
            .map_err(|e| VmmError::Vsock(format!("write request 0x{req_type:02x}: {e}")))?;
        let (resp_type, resp) = read_frame(&mut stream)
            .await
            .map_err(|e| VmmError::Vsock(format!("read response: {e}")))?;
        match resp_type {
            t if t == ok_type => Ok(resp),
            FILE_ERR => Err(decode_file_err(&resp)),
            other => Err(VmmError::Vsock(format!(
                "unexpected response type 0x{other:02x}"
            ))),
        }
    };
    tokio::time::timeout(FILE_IO_TIMEOUT, op)
        .await
        .map_err(|_| VmmError::Vsock("file operation timed out".into()))?
}

fn parse_json<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T> {
    serde_json::from_slice(payload)
        .map_err(|e| VmmError::Vsock(format!("malformed agent response: {e}")))
}

/// Stat one path inside the sandbox (symlinks reported, not followed).
pub async fn stat_file(uds_path: &Path, path: &str) -> Result<FileStatDto> {
    let req = StatReq {
        path: path.to_owned(),
    };
    let payload = unary_file_op(uds_path, FILE_STAT_REQ, &req, FILE_STAT).await?;
    parse_json(&payload)
}

/// List a directory inside the sandbox, non-recursively, entries sorted by
/// name with full metadata.
pub async fn list_dir(uds_path: &Path, path: &str) -> Result<Vec<FileStatDto>> {
    let req = ListDirReq {
        path: path.to_owned(),
    };
    let payload = unary_file_op(uds_path, FILE_LIST_REQ, &req, FILE_LIST).await?;
    parse_json(&payload)
}

/// Create a directory (and missing parents) inside the sandbox. Succeeds
/// when the directory already exists. `mode` is the Unix permission bits;
/// `0` defaults to `0o755` on the agent side.
pub async fn make_dir(uds_path: &Path, path: &str, mode: u32) -> Result<()> {
    let req = MakeDirReq {
        path: path.to_owned(),
        mode,
    };
    unary_file_op(uds_path, FILE_MKDIR_REQ, &req, FILE_ACK).await?;
    Ok(())
}

/// Remove a file, symlink, or directory inside the sandbox. A non-empty
/// directory requires `recursive` and fails with
/// [`VmmError::DirectoryNotEmpty`] otherwise.
pub async fn remove_entry(uds_path: &Path, path: &str, recursive: bool) -> Result<()> {
    let req = RemoveReq {
        path: path.to_owned(),
        recursive,
    };
    unary_file_op(uds_path, FILE_REMOVE_REQ, &req, FILE_ACK).await?;
    Ok(())
}

/// Rename / move an entry within the sandbox.
pub async fn move_entry(uds_path: &Path, from: &str, to: &str) -> Result<()> {
    let req = MoveReq {
        from: from.to_owned(),
        to: to.to_owned(),
    };
    unary_file_op(uds_path, FILE_MOVE_REQ, &req, FILE_ACK).await?;
    Ok(())
}

/// A live directory watch over the sandbox's vsock file channel.
///
/// The connection streams `FILE_EVENT` frames until either side closes it.
/// Dropping this closes the connection, which is the cancellation signal
/// the vm-agent tears its inotify watch down on.
#[derive(Debug)]
pub struct DirWatch {
    stream: UnixStream,
}

impl DirWatch {
    /// Next filesystem event. `Ok(None)` is the clean end of the stream —
    /// the vm-agent side closed the connection (sandbox stopped).
    pub async fn next_event(&mut self) -> Result<Option<FsEventDto>> {
        // Read the frame-type byte manually: a clean EOF is only clean at a
        // frame boundary, which `read_frame`'s `read_exact` cannot express.
        let mut ty = [0u8; 1];
        let n = self
            .stream
            .read(&mut ty)
            .await
            .map_err(|e| VmmError::Vsock(format!("watch read: {e}")))?;
        if n == 0 {
            return Ok(None);
        }
        let len = self
            .stream
            .read_u32_le()
            .await
            .map_err(|e| VmmError::Vsock(format!("watch read: {e}")))? as usize;
        if len > MAX_FRAME_SIZE {
            return Err(VmmError::Vsock(format!("watch frame too large: {len}")));
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.stream
                .read_exact(&mut payload)
                .await
                .map_err(|e| VmmError::Vsock(format!("watch read: {e}")))?;
        }
        match ty[0] {
            FILE_EVENT => Ok(Some(parse_json(&payload)?)),
            FILE_ERR => Err(decode_file_err(&payload)),
            other => Err(VmmError::Vsock(format!(
                "unexpected watch frame type 0x{other:02x}"
            ))),
        }
    }
}

/// Open a directory watch inside the sandbox. The setup handshake (connect,
/// request, `FILE_ACK`) is bounded by [`FILE_IO_TIMEOUT`]; the returned
/// stream itself is long-lived and unbounded.
pub async fn watch_dir(uds_path: &Path, path: &str, recursive: bool) -> Result<DirWatch> {
    let req = WatchReq {
        path: path.to_owned(),
        recursive,
    };
    let payload = serde_json::to_vec(&req)
        .map_err(|e| VmmError::Vsock(format!("serialize WatchReq: {e}")))?;
    let setup = async {
        let mut stream = connect_to_port(uds_path, FILE_PORT).await?;
        write_frame(&mut stream, FILE_WATCH_REQ, &payload)
            .await
            .map_err(|e| VmmError::Vsock(format!("write FILE_WATCH_REQ: {e}")))?;
        let (resp_type, resp) = read_frame(&mut stream)
            .await
            .map_err(|e| VmmError::Vsock(format!("read watch ack: {e}")))?;
        match resp_type {
            FILE_ACK => Ok(DirWatch { stream }),
            FILE_ERR => Err(decode_file_err(&resp)),
            other => Err(VmmError::Vsock(format!(
                "unexpected watch ack type 0x{other:02x}"
            ))),
        }
    };
    tokio::time::timeout(FILE_IO_TIMEOUT, setup)
        .await
        .map_err(|_| VmmError::Vsock("watch setup timed out".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vsock::{read_frame as async_read_frame, write_frame as async_write_frame};

    #[test]
    fn test_write_req_serializes() {
        let req = WriteReq {
            path: "/tmp/test.txt",
            mode: 0o644,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("/tmp/test.txt"));
        assert!(json.contains("420")); // 0o644 == 420 decimal
    }

    #[test]
    fn test_read_req_serializes() {
        let req = ReadReq { path: "/etc/hosts" };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("/etc/hosts"));
    }

    /// Simulate a successful write: host sends WRITE_REQ + DATA + DONE,
    /// agent replies FILE_ACK.
    #[tokio::test]
    async fn test_write_file_protocol_success() {
        let (mut agent, host) = tokio::io::duplex(8192);

        // Spawn a mock agent that reads the write protocol and responds.
        let agent_handle = tokio::spawn(async move {
            // Read FILE_WRITE_REQ header.
            let (ty, payload) = async_read_frame(&mut agent).await.unwrap();
            assert_eq!(ty, FILE_WRITE_REQ);
            let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(parsed["path"], "/tmp/hello.txt");

            // Read FILE_DATA chunks.
            let mut data = Vec::new();
            loop {
                let (ty, chunk) = async_read_frame(&mut agent).await.unwrap();
                match ty {
                    FILE_DATA => data.extend_from_slice(&chunk),
                    FILE_DONE => break,
                    _ => panic!("unexpected frame type 0x{ty:02x}"),
                }
            }
            assert_eq!(data, b"hello world");

            // Send FILE_ACK.
            async_write_frame(&mut agent, FILE_ACK, &[]).await.unwrap();
        });

        // Drive the host side directly on the duplex stream.
        let mut stream = host;
        let req = serde_json::to_vec(&WriteReq {
            path: "/tmp/hello.txt",
            mode: 0o644,
        })
        .unwrap();
        async_write_frame(&mut stream, FILE_WRITE_REQ, &req)
            .await
            .unwrap();
        for chunk in b"hello world".chunks(MAX_FRAME_SIZE) {
            async_write_frame(&mut stream, FILE_DATA, chunk)
                .await
                .unwrap();
        }
        async_write_frame(&mut stream, FILE_DONE, &[])
            .await
            .unwrap();
        let (resp_type, _) = async_read_frame(&mut stream).await.unwrap();
        assert_eq!(resp_type, FILE_ACK);

        agent_handle.await.unwrap();
    }

    /// Simulate a write error: agent replies FILE_ERR.
    #[tokio::test]
    async fn test_write_file_protocol_error() {
        let (mut agent, host) = tokio::io::duplex(8192);

        let agent_handle = tokio::spawn(async move {
            // Consume WRITE_REQ + DATA + DONE.
            let _ = async_read_frame(&mut agent).await.unwrap();
            loop {
                let (ty, _) = async_read_frame(&mut agent).await.unwrap();
                if ty == FILE_DONE {
                    break;
                }
            }
            async_write_frame(&mut agent, FILE_ERR, b"permission denied")
                .await
                .unwrap();
        });

        let mut stream = host;
        let req = serde_json::to_vec(&WriteReq {
            path: "/root/secret",
            mode: 0o600,
        })
        .unwrap();
        async_write_frame(&mut stream, FILE_WRITE_REQ, &req)
            .await
            .unwrap();
        async_write_frame(&mut stream, FILE_DONE, &[])
            .await
            .unwrap();
        let (resp_type, payload) = async_read_frame(&mut stream).await.unwrap();
        assert_eq!(resp_type, FILE_ERR);
        assert_eq!(std::str::from_utf8(&payload).unwrap(), "permission denied");

        agent_handle.await.unwrap();
    }

    /// Simulate a successful read: agent sends DATA chunks then DONE.
    #[tokio::test]
    async fn test_read_file_protocol_success() {
        let (mut agent, host) = tokio::io::duplex(8192);

        let agent_handle = tokio::spawn(async move {
            let (ty, _payload) = async_read_frame(&mut agent).await.unwrap();
            assert_eq!(ty, FILE_READ_REQ);

            // Send file content in two chunks.
            async_write_frame(&mut agent, FILE_DATA, b"part1")
                .await
                .unwrap();
            async_write_frame(&mut agent, FILE_DATA, b"part2")
                .await
                .unwrap();
            async_write_frame(&mut agent, FILE_DONE, &[]).await.unwrap();
        });

        let mut stream = host;
        let req = serde_json::to_vec(&ReadReq {
            path: "/tmp/test.txt",
        })
        .unwrap();
        async_write_frame(&mut stream, FILE_READ_REQ, &req)
            .await
            .unwrap();

        // Collect chunks.
        let mut buf = Vec::new();
        loop {
            let (ty, payload) = async_read_frame(&mut stream).await.unwrap();
            match ty {
                FILE_DATA => buf.extend_from_slice(&payload),
                FILE_DONE => break,
                _ => panic!("unexpected frame type 0x{ty:02x}"),
            }
        }
        assert_eq!(buf, b"part1part2");

        agent_handle.await.unwrap();
    }

    /// Simulate a read error: agent replies FILE_ERR.
    #[tokio::test]
    async fn test_read_file_protocol_error() {
        let (mut agent, host) = tokio::io::duplex(8192);

        let agent_handle = tokio::spawn(async move {
            let _ = async_read_frame(&mut agent).await.unwrap();
            async_write_frame(&mut agent, FILE_ERR, b"no such file")
                .await
                .unwrap();
        });

        let mut stream = host;
        let req = serde_json::to_vec(&ReadReq {
            path: "/nonexistent",
        })
        .unwrap();
        async_write_frame(&mut stream, FILE_READ_REQ, &req)
            .await
            .unwrap();
        let (ty, payload) = async_read_frame(&mut stream).await.unwrap();
        assert_eq!(ty, FILE_ERR);
        assert_eq!(std::str::from_utf8(&payload).unwrap(), "no such file");

        agent_handle.await.unwrap();
    }

    #[test]
    fn file_err_prefixes_decode_to_typed_errors() {
        assert!(matches!(
            decode_file_err(b"ENOENT: /a/b"),
            VmmError::PathNotFound(p) if p == "/a/b"
        ));
        assert!(matches!(
            decode_file_err(b"ENOTDIR: /a/file"),
            VmmError::NotADirectory(p) if p == "/a/file"
        ));
        assert!(matches!(
            decode_file_err(b"ENOTEMPTY: /a/dir"),
            VmmError::DirectoryNotEmpty(p) if p == "/a/dir"
        ));
        // Old-agent / free-form errors stay vsock errors.
        assert!(matches!(
            decode_file_err(b"read file: boom"),
            VmmError::Vsock(m) if m == "read file: boom"
        ));
    }

    /// Bind a mock Firecracker vsock UDS: accept one connection, answer the
    /// `CONNECT {port}` handshake, then hand the stream to `script`.
    async fn mock_vsock_server<F, Fut>(script: F) -> (tempfile::TempDir, std::path::PathBuf)
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Consume "CONNECT {port}\n".
            let mut byte = [0u8; 1];
            loop {
                stream.read_exact(&mut byte).await.unwrap();
                if byte[0] == b'\n' {
                    break;
                }
            }
            use tokio::io::AsyncWriteExt as _;
            stream.write_all(b"OK 53\n").await.unwrap();
            script(stream).await;
        });
        (dir, path)
    }

    #[tokio::test]
    async fn stat_file_round_trips_the_dto() {
        let dto = FileStatDto {
            name: "b".into(),
            kind: proto::KIND_FILE.into(),
            size: 42,
            mode: 0o644,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 5,
            uid: 0,
            gid: 0,
            symlink_target: String::new(),
        };
        let expected = dto.clone();
        let (_dir, path) = mock_vsock_server(move |mut stream| async move {
            let (ty, payload) = async_read_frame(&mut stream).await.unwrap();
            assert_eq!(ty, FILE_STAT_REQ);
            let req: StatReq = serde_json::from_slice(&payload).unwrap();
            assert_eq!(req.path, "/a/b");
            let body = serde_json::to_vec(&dto).unwrap();
            async_write_frame(&mut stream, FILE_STAT, &body)
                .await
                .unwrap();
        })
        .await;

        let got = stat_file(&path, "/a/b").await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn remove_entry_surfaces_directory_not_empty() {
        let (_dir, path) = mock_vsock_server(|mut stream| async move {
            let (ty, _) = async_read_frame(&mut stream).await.unwrap();
            assert_eq!(ty, FILE_REMOVE_REQ);
            async_write_frame(&mut stream, FILE_ERR, b"ENOTEMPTY: /full")
                .await
                .unwrap();
        })
        .await;

        let err = remove_entry(&path, "/full", false).await.unwrap_err();
        assert!(matches!(err, VmmError::DirectoryNotEmpty(p) if p == "/full"));
    }

    #[tokio::test]
    async fn read_file_error_is_classified() {
        let (_dir, path) = mock_vsock_server(|mut stream| async move {
            let _ = async_read_frame(&mut stream).await.unwrap();
            async_write_frame(&mut stream, FILE_ERR, b"ENOENT: /missing")
                .await
                .unwrap();
        })
        .await;

        let err = read_file(&path, "/missing").await.unwrap_err();
        assert!(matches!(err, VmmError::PathNotFound(p) if p == "/missing"));
    }

    #[tokio::test]
    async fn write_file_error_is_classified() {
        let (_dir, path) = mock_vsock_server(|mut stream| async move {
            // Consume WRITE_REQ, then the data frames until DONE.
            let _ = async_read_frame(&mut stream).await.unwrap();
            loop {
                let (ty, _) = async_read_frame(&mut stream).await.unwrap();
                if ty == FILE_DONE {
                    break;
                }
            }
            async_write_frame(&mut stream, FILE_ERR, b"ENOTDIR: /plain.txt/sub")
                .await
                .unwrap();
        })
        .await;

        let err = write_file(&path, "/plain.txt/sub", 0, b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, VmmError::NotADirectory(p) if p == "/plain.txt/sub"));
    }

    #[tokio::test]
    async fn watch_dir_streams_events_until_clean_eof() {
        let (_dir, path) = mock_vsock_server(|mut stream| async move {
            let (ty, payload) = async_read_frame(&mut stream).await.unwrap();
            assert_eq!(ty, FILE_WATCH_REQ);
            let req: WatchReq = serde_json::from_slice(&payload).unwrap();
            assert!(req.recursive);
            async_write_frame(&mut stream, FILE_ACK, &[]).await.unwrap();
            let event = FsEventDto {
                kind: proto::EVENT_CREATED.into(),
                path: "/w/new".into(),
                renamed_to: String::new(),
            };
            let body = serde_json::to_vec(&event).unwrap();
            async_write_frame(&mut stream, FILE_EVENT, &body)
                .await
                .unwrap();
            // Dropping the stream is the clean end (sandbox stopped).
        })
        .await;

        let mut watch = watch_dir(&path, "/w", true).await.unwrap();
        let event = watch.next_event().await.unwrap().unwrap();
        assert_eq!(event.kind, proto::EVENT_CREATED);
        assert_eq!(event.path, "/w/new");
        assert!(watch.next_event().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn watch_dir_setup_error_is_typed() {
        let (_dir, path) = mock_vsock_server(|mut stream| async move {
            let _ = async_read_frame(&mut stream).await.unwrap();
            async_write_frame(&mut stream, FILE_ERR, b"ENOENT: /missing")
                .await
                .unwrap();
        })
        .await;

        let err = watch_dir(&path, "/missing", false).await.unwrap_err();
        assert!(matches!(err, VmmError::PathNotFound(p) if p == "/missing"));
    }
}
