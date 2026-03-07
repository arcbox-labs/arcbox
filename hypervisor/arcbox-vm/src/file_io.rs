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

use serde::Serialize;

use crate::error::{Result, VmmError};
use crate::vsock::{MAX_FRAME_SIZE, connect_to_port, read_frame, write_frame};

/// Guest-side vsock port for file I/O.
pub const FILE_PORT: u32 = 53;

// Frame type constants.
const FILE_WRITE_REQ: u8 = 0x20;
const FILE_DATA: u8 = 0x21;
const FILE_DONE: u8 = 0x22;
const FILE_READ_REQ: u8 = 0x23;
const FILE_ACK: u8 = 0x30;
const FILE_ERR: u8 = 0x31;

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
    let mut stream = connect_to_port(uds_path, FILE_PORT).await?;

    let req = serde_json::to_vec(&WriteReq { path, mode })
        .map_err(|e| VmmError::Vsock(format!("serialize WriteReq: {e}")))?;
    write_frame(&mut stream, FILE_WRITE_REQ, &req)
        .await
        .map_err(|e| VmmError::Vsock(format!("write FILE_WRITE_REQ: {e}")))?;

    // Stream data in MAX_FRAME_SIZE chunks.
    if data.is_empty() {
        write_frame(&mut stream, FILE_DATA, &[])
            .await
            .map_err(|e| VmmError::Vsock(format!("write FILE_DATA: {e}")))?;
    } else {
        for chunk in data.chunks(MAX_FRAME_SIZE) {
            write_frame(&mut stream, FILE_DATA, chunk)
                .await
                .map_err(|e| VmmError::Vsock(format!("write FILE_DATA: {e}")))?;
        }
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
            FILE_DATA => buf.extend_from_slice(&payload),
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
}
