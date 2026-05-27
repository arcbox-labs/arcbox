//! Host-side file I/O over a dedicated vsock port (FILE_PORT = 53).
//!
//! ## Protocol
//!
//! Frame format is identical to the exec channel: `[u8 type][u32 LE len][payload]`.
//! One vsock connection per operation; vm-agent closes after sending the final frame.
//!
//! | Hex  | Name             | Direction      | Payload                          |
//! |------|------------------|----------------|----------------------------------|
//! | 0x20 | `FILE_WRITE_REQ` | Host → Agent   | JSON `{"path": str, "mode": u32}`|
//! | 0x21 | `FILE_DATA`      | bidirectional  | raw bytes (one chunk)            |
//! | 0x22 | `FILE_DONE`      | bidirectional  | empty — end of data stream       |
//! | 0x23 | `FILE_READ_REQ`  | Host → Agent   | JSON `{"path": str}`             |
//! | 0x30 | `FILE_ACK`       | Agent → Host   | empty — write succeeded          |
//! | 0x31 | `FILE_ERR`       | Agent → Host   | UTF-8 error message              |
//!
//! ## Write flow
//! ```text
//! Host  →  FILE_WRITE_REQ  {path, mode}
//! Host  →  FILE_DATA       [chunk 1..N]
//! Host  →  FILE_DONE
//!           ←  FILE_ACK  (success)
//!           ←  FILE_ERR  (failure)
//! ```
//!
//! ## Read flow
//! ```text
//! Host  →  FILE_READ_REQ  {path}
//!           ←  FILE_DATA  [chunk 1..N]
//!           ←  FILE_DONE  (success — all bytes sent)
//!           ←  FILE_ERR   (failure)
//! ```

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::error::{Result, VmmError};
use crate::vsock::{MAX_FRAME_SIZE, connect_to_port, read_frame, write_frame};

/// Per-operation timeout for file I/O over vsock.
const FILE_IO_TIMEOUT: Duration = Duration::from_mins(1);

/// File I/O protocol constants shared between the host-side client and the
/// guest vm-agent binary.  The vm-agent should import these from
/// `arcbox_vm::file_io::proto` instead of duplicating numeric values.
pub mod proto {
    /// Guest-side vsock port for file I/O.
    pub const FILE_PORT: u32 = 53;

    // Frame type constants.
    pub const FILE_WRITE_REQ: u8 = 0x20;
    pub const FILE_DATA: u8 = 0x21;
    pub const FILE_DONE: u8 = 0x22;
    pub const FILE_READ_REQ: u8 = 0x23;
    pub const FILE_ACK: u8 = 0x30;
    pub const FILE_ERR: u8 = 0x31;

    /// Maximum total file size for file I/O operations (256 MiB).
    pub const MAX_FILE_SIZE: usize = 256 * 1024 * 1024;
}

pub use proto::FILE_PORT;
use proto::{
    FILE_ACK, FILE_DATA, FILE_DONE, FILE_ERR, FILE_READ_REQ, FILE_WRITE_REQ, MAX_FILE_SIZE,
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
        FILE_ERR => Err(VmmError::Vsock(
            String::from_utf8_lossy(&payload).into_owned(),
        )),
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
            FILE_ERR => {
                return Err(VmmError::Vsock(
                    String::from_utf8_lossy(&payload).into_owned(),
                ));
            }
            other => {
                return Err(VmmError::Vsock(format!(
                    "file read: unexpected frame type 0x{other:02x}"
                )));
            }
        }
    }
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
}
