//! File channel: the guest vsock port the agent serves file I/O on.
//!
//! Frame format is identical to the exec channel: `[u8 type][u32 LE len][payload]`.
//! One vsock connection per operation; the agent closes after sending the
//! final frame.
//!
//! | Hex  | Name              | Direction      | Payload                          |
//! |------|-------------------|----------------|----------------------------------|
//! | 0x20 | [`FILE_WRITE_REQ`]  | Host → Agent   | JSON `{"path": str, "mode": u32}`|
//! | 0x21 | [`FILE_DATA`]       | bidirectional  | raw bytes (one chunk)            |
//! | 0x22 | [`FILE_DONE`]       | bidirectional  | empty — end of data stream       |
//! | 0x23 | [`FILE_READ_REQ`]   | Host → Agent   | JSON `{"path": str}`             |
//! | 0x24 | [`FILE_STAT_REQ`]   | Host → Agent   | JSON [`StatReq`]                 |
//! | 0x25 | [`FILE_LIST_REQ`]   | Host → Agent   | JSON [`ListDirReq`]              |
//! | 0x26 | [`FILE_MKDIR_REQ`]  | Host → Agent   | JSON [`MakeDirReq`]              |
//! | 0x27 | [`FILE_REMOVE_REQ`] | Host → Agent   | JSON [`RemoveReq`]               |
//! | 0x28 | [`FILE_MOVE_REQ`]   | Host → Agent   | JSON [`MoveReq`]                 |
//! | 0x29 | [`FILE_WATCH_REQ`]  | Host → Agent   | JSON [`WatchReq`]                |
//! | 0x30 | [`FILE_ACK`]        | Agent → Host   | empty — operation succeeded      |
//! | 0x31 | [`FILE_ERR`]        | Agent → Host   | UTF-8 error message              |
//! | 0x32 | [`FILE_STAT`]       | Agent → Host   | JSON [`FileStatDto`]             |
//! | 0x33 | [`FILE_LIST`]       | Agent → Host   | JSON `[FileStatDto, ...]`        |
//! | 0x34 | [`FILE_EVENT`]      | Agent → Host   | JSON [`FsEventDto`]              |
//!
//! Stat/List answer one data frame; MakeDir/Remove/Move answer [`FILE_ACK`].
//! Watch answers [`FILE_ACK`] once the inotify watch is established, then
//! streams [`FILE_EVENT`] frames until either side closes the connection —
//! the host closing it is the cancellation signal, the agent side closing
//! it (sandbox stop) is the clean end of the stream.
//!
//! [`FILE_ERR`] payloads carry a machine-readable errno prefix
//! ([`ERR_NOT_FOUND`] and friends) on every verb — the path verbs and the
//! read/write flows alike — so the host maps them onto typed errors instead
//! of a blanket transport error.
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

use serde::{Deserialize, Serialize};

/// Guest-side vsock port for file I/O.
pub const FILE_PORT: u32 = 53;

/// Open a file for writing. Payload: JSON `{"path": str, "mode": u32}`.
pub const FILE_WRITE_REQ: u8 = 0x20;
/// One chunk of file bytes, in either direction.
pub const FILE_DATA: u8 = 0x21;
/// End of a data stream, in either direction. Empty payload.
pub const FILE_DONE: u8 = 0x22;
/// Read a file. Payload: JSON `{"path": str}`.
pub const FILE_READ_REQ: u8 = 0x23;
/// Stat one entry. Payload: JSON [`StatReq`].
pub const FILE_STAT_REQ: u8 = 0x24;
/// List a directory. Payload: JSON [`ListDirReq`].
pub const FILE_LIST_REQ: u8 = 0x25;
/// Create a directory. Payload: JSON [`MakeDirReq`].
pub const FILE_MKDIR_REQ: u8 = 0x26;
/// Remove an entry. Payload: JSON [`RemoveReq`].
pub const FILE_REMOVE_REQ: u8 = 0x27;
/// Rename an entry. Payload: JSON [`MoveReq`].
pub const FILE_MOVE_REQ: u8 = 0x28;
/// Watch a directory. Payload: JSON [`WatchReq`].
pub const FILE_WATCH_REQ: u8 = 0x29;
/// The operation succeeded. Empty payload.
pub const FILE_ACK: u8 = 0x30;
/// The operation failed. Payload: UTF-8 message, errno-prefixed.
pub const FILE_ERR: u8 = 0x31;
/// One entry's metadata. Payload: JSON [`FileStatDto`].
pub const FILE_STAT: u8 = 0x32;
/// A directory listing. Payload: JSON array of [`FileStatDto`].
pub const FILE_LIST: u8 = 0x33;
/// One filesystem event on a watched tree. Payload: JSON [`FsEventDto`].
pub const FILE_EVENT: u8 = 0x34;

/// Maximum total file size for file I/O operations (256 MiB).
pub const MAX_FILE_SIZE: usize = 256 * 1024 * 1024;

// Machine-readable errno prefixes on `FILE_ERR` payloads for the path
// verbs. The remainder of the payload is the affected path; the host maps
// each prefix onto a typed error.

/// `FILE_ERR` prefix: the path does not exist.
pub const ERR_NOT_FOUND: &str = "ENOENT: ";
/// `FILE_ERR` prefix: a directory was expected.
pub const ERR_NOT_A_DIRECTORY: &str = "ENOTDIR: ";
/// `FILE_ERR` prefix: a non-recursive remove hit a non-empty directory.
pub const ERR_NOT_EMPTY: &str = "ENOTEMPTY: ";

// `FileStatDto.kind` vocabulary.

/// [`FileStatDto::kind`]: a regular file.
pub const KIND_FILE: &str = "file";
/// [`FileStatDto::kind`]: a directory.
pub const KIND_DIR: &str = "dir";
/// [`FileStatDto::kind`]: a symbolic link (reported, never followed).
pub const KIND_SYMLINK: &str = "symlink";
/// [`FileStatDto::kind`]: anything else (device, socket, fifo, ...).
pub const KIND_OTHER: &str = "other";

// `FsEventDto.kind` vocabulary.

/// [`FsEventDto::kind`]: an entry appeared.
pub const EVENT_CREATED: &str = "created";
/// [`FsEventDto::kind`]: an entry's contents or attributes changed.
pub const EVENT_MODIFIED: &str = "modified";
/// [`FsEventDto::kind`]: an entry disappeared.
pub const EVENT_REMOVED: &str = "removed";
/// [`FsEventDto::kind`]: an entry was renamed within the watched tree.
pub const EVENT_RENAMED: &str = "renamed";

/// [`FILE_STAT_REQ`] payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatReq {
    /// Guest path.
    pub path: String,
}

/// [`FILE_LIST_REQ`] payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListDirReq {
    /// Guest path of the directory.
    pub path: String,
}

/// [`FILE_MKDIR_REQ`] payload. `mode` carries the Unix permission bits
/// for created directories; `0` defaults to `0o755` on the agent side.
#[derive(Debug, Serialize, Deserialize)]
pub struct MakeDirReq {
    /// Guest path to create (parents included).
    pub path: String,
    /// Permission bits, or `0` for the default.
    pub mode: u32,
}

/// [`FILE_REMOVE_REQ`] payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveReq {
    /// Guest path.
    pub path: String,
    /// Remove directories and their contents.
    pub recursive: bool,
}

/// [`FILE_MOVE_REQ`] payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct MoveReq {
    /// Guest source path.
    pub from: String,
    /// Guest destination path.
    pub to: String,
}

/// [`FILE_WATCH_REQ`] payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct WatchReq {
    /// Guest path of the directory to watch.
    pub path: String,
    /// Also watch subdirectories, present and future.
    pub recursive: bool,
}

/// Metadata of one filesystem entry ([`FILE_STAT`] / [`FILE_LIST`] payload).
///
/// Mirrors `arcbox.sandbox.v1.FileStat`: symlinks are reported, never
/// followed; `mode` is the low 12 bits of `st_mode`; `size` is 0 for
/// non-regular files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStatDto {
    /// Entry name (a listing) or the requested path's final component.
    pub name: String,
    /// One of the `KIND_*` constants.
    pub kind: String,
    /// Byte size for regular files, `0` otherwise.
    pub size: u64,
    /// Low 12 permission bits of `st_mode`.
    pub mode: u32,
    /// Modification time, seconds since the Unix epoch.
    pub mtime_secs: i64,
    /// Modification time, nanosecond part.
    pub mtime_nanos: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Link target for symlinks, empty otherwise.
    #[serde(default)]
    pub symlink_target: String,
}

/// One filesystem event ([`FILE_EVENT`] payload). Mirrors
/// `arcbox.sandbox.v1.FsEvent`: `path` is the old path for renames,
/// with `renamed_to` set only then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsEventDto {
    /// One of the `EVENT_*` constants.
    pub kind: String,
    /// Affected path (the old path for a rename).
    pub path: String,
    /// New path for a rename, empty otherwise.
    #[serde(default)]
    pub renamed_to: String,
}
