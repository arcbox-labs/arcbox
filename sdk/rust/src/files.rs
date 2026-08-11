//! Moving bytes in and out of one sandbox, and operating on its paths.
//!
//! Content is bytes end to end — `write` takes `impl AsRef<[u8]>` so
//! `&str` works directly, and `read` returns the exact bytes; text
//! decoding is the caller's one-liner. Paths are sandbox-side POSIX
//! paths carried as strings.

use std::time::SystemTime;

use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{SandboxFilesystemServiceClient, write_file_request};
use connectrpc::client::{ClientTransport, ServerStream, SharedHttp2Connection};

use crate::client::ClientContext;
use crate::error::{Error, ErrorKind, Result};
use crate::types::time_from_wire;

/// The generated filesystem client over the shared transport.
type FilesystemClient = SandboxFilesystemServiceClient<SharedHttp2Connection>;

/// The server stream [`FilesystemClient::read_file`] returns.
type ReadStream = ServerStream<
    <SharedHttp2Connection as ClientTransport>::ResponseBody,
    pb::__buffa::view::FileChunkView<'static>,
>;

/// The server stream [`FilesystemClient::watch_dir`] returns.
type WatchWireStream = ServerStream<
    <SharedHttp2Connection as ClientTransport>::ResponseBody,
    pb::__buffa::view::WatchDirResponseView<'static>,
>;

/// Per-file transfer cap enforced by the daemon (`filesystem.proto`).
pub const MAX_FILE_BYTES: usize = 256 * 1024 * 1024;

/// Chunk size for streamed writes, matching the sibling SDKs.
const WRITE_CHUNK_BYTES: usize = 256 * 1024;

/// Default permission bits for created files (the daemon's default).
const DEFAULT_WRITE_MODE: u32 = 0o644;

/// Kind of a filesystem entry. `Unknown` covers wire values this SDK
/// predates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
    Unknown,
}

/// Metadata of one filesystem entry. Symlinks are reported, never
/// followed; `mode` is the low permission bits of `st_mode`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FileStat {
    pub name: String,
    pub kind: FileKind,
    /// Size in bytes (0 for non-regular files).
    pub size: u64,
    /// Unix permission bits.
    pub mode: u32,
    pub modified_at: Option<SystemTime>,
    pub uid: u32,
    pub gid: u32,
    /// Target of a symlink; `None` for every other kind.
    pub symlink_target: Option<String>,
}

/// Kind of a filesystem event. `Unknown` covers wire values this SDK
/// predates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsEventKind {
    Created,
    Modified,
    Removed,
    Renamed,
    Unknown,
}

/// One filesystem event, as delivered by [`Files::watch`]. `path` is
/// the old path for renames, with `renamed_to` set only then.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FsEvent {
    pub kind: FsEventKind,
    pub path: String,
    pub renamed_to: Option<String>,
}

/// Options for [`Files::write`].
#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    /// Unix permission bits for the created file (unset = `0o644`).
    pub mode: Option<u32>,
}

/// Options for [`Files::mkdir`].
#[derive(Debug, Clone, Default)]
pub struct MkdirOptions {
    /// Unix permission bits for created directories (unset = the
    /// daemon default).
    pub mode: Option<u32>,
}

/// Options for [`Files::remove`].
#[derive(Debug, Clone, Default)]
pub struct RemoveOptions {
    /// Remove a non-empty directory and its contents. Without it, a
    /// non-empty directory is refused.
    pub recursive: bool,
}

/// Options for [`Files::watch`].
#[derive(Debug, Clone, Default)]
pub struct WatchOptions {
    /// Watch subdirectories too.
    pub recursive: bool,
}

/// The `sandbox.files()` namespace: move bytes in and out of one
/// sandbox, and operate on its paths.
#[derive(Clone)]
pub struct Files {
    ctx: ClientContext,
    sandbox_id: String,
}

impl Files {
    pub(crate) fn attached(ctx: ClientContext, sandbox_id: String) -> Self {
        Self { ctx, sandbox_id }
    }

    fn client(&self) -> FilesystemClient {
        SandboxFilesystemServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
    }

    /// Read the file at `path` and return its bytes.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::FileNotFound`] for a missing path;
    /// [`ErrorKind::FileTooLarge`] past [`MAX_FILE_BYTES`], checked
    /// client-side while collecting (nothing bounds a read wire-side);
    /// [`ErrorKind::ConnectionLost`] when the stream ends before the
    /// final chunk's done marker — a truncated transfer is never
    /// returned as a success. Otherwise any RPC failure.
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let mut stream: ReadStream = self
            .client()
            .read_file(pb::ReadFileRequest {
                id: self.sandbox_id.clone(),
                path: path.to_owned(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "files.read"))?;
        let mut content = Vec::new();
        loop {
            match stream.message::<pb::FileChunk>().await {
                Ok(Some(chunk)) => {
                    let chunk = chunk.to_owned_message();
                    content.extend_from_slice(&chunk.data);
                    if content.len() > MAX_FILE_BYTES {
                        return Err(Error::new(
                            ErrorKind::FileTooLarge,
                            format!(
                                "the file exceeds the {MAX_FILE_BYTES}-byte cap this \
                                 client collects into memory"
                            ),
                            "files.read",
                        )
                        .with_context("limit_bytes", MAX_FILE_BYTES.to_string()));
                    }
                    if chunk.done {
                        return Ok(content);
                    }
                }
                // The done marker is the transfer's integrity signal: a
                // stream that ends without it delivered a prefix, not
                // the file.
                Ok(None) => {
                    return Err(Error::new(
                        ErrorKind::ConnectionLost,
                        "the read stream ended before the file was fully transferred",
                        "files.read",
                    ));
                }
                Err(error) => return Err(Error::from_connect(error, "files.read")),
            }
        }
    }

    /// Write `data` to `path`, creating missing parent directories.
    ///
    /// `data` is taken by value (`Vec<u8>` moves in for free; `&str` /
    /// `&[u8]` copy once) and streamed lazily, so the peak footprint is
    /// the payload plus one wire chunk — never a second full copy.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::FileTooLarge`] past the daemon's per-file cap
    /// (checked client-side before any byte is sent); otherwise any RPC
    /// failure.
    pub async fn write(
        &self,
        path: &str,
        data: impl Into<Vec<u8>>,
        options: WriteOptions,
    ) -> Result<()> {
        let data: Vec<u8> = data.into();
        if data.len() > MAX_FILE_BYTES {
            return Err(Error::new(
                ErrorKind::FileTooLarge,
                format!(
                    "{} bytes exceed the {MAX_FILE_BYTES}-byte per-file cap",
                    data.len()
                ),
                "files.write",
            )
            .with_context("limit_bytes", MAX_FILE_BYTES.to_string()));
        }
        let open = pb::WriteFileRequest {
            payload: Some(write_file_request::Payload::from(pb::WriteFileOpen {
                id: self.sandbox_id.clone(),
                path: path.to_owned(),
                mode: options.mode.unwrap_or(DEFAULT_WRITE_MODE),
                ..Default::default()
            })),
            ..Default::default()
        };
        let total = data.len();
        let chunks = (0..total).step_by(WRITE_CHUNK_BYTES).map(move |start| {
            let end = (start + WRITE_CHUNK_BYTES).min(total);
            pb::WriteFileRequest {
                payload: Some(write_file_request::Payload::from(pb::FileChunk {
                    data: data[start..end].to_vec(),
                    ..Default::default()
                })),
                ..Default::default()
            }
        });
        let done = pb::WriteFileRequest {
            payload: Some(write_file_request::Payload::from(pb::FileChunk {
                done: true,
                ..Default::default()
            })),
            ..Default::default()
        };
        let frames = std::iter::once(open)
            .chain(chunks)
            .chain(std::iter::once(done));
        self.client()
            .write_file(connectrpc::client::stream_iter(frames))
            .await
            .map_err(|error| Error::from_connect(error, "files.write"))?;
        Ok(())
    }

    /// Metadata of one path (symlinks reported, not followed).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::FileNotFound`] for a missing path; otherwise any
    /// RPC failure.
    pub async fn stat(&self, path: &str) -> Result<FileStat> {
        let stat = self
            .client()
            .stat(pb::StatFileRequest {
                id: self.sandbox_id.clone(),
                path: path.to_owned(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "files.stat"))?
            .into_owned();
        Ok(FileStat::from(stat))
    }

    /// List a directory's entries, non-recursively, sorted by name.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::FileNotFound`] for a missing path; otherwise any
    /// RPC failure.
    pub async fn list(&self, path: &str) -> Result<Vec<FileStat>> {
        let response = self
            .client()
            .list_dir(pb::ListDirRequest {
                id: self.sandbox_id.clone(),
                path: path.to_owned(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "files.list"))?
            .into_owned();
        Ok(response.entries.into_iter().map(FileStat::from).collect())
    }

    /// Create a directory and any missing parents (`mkdir -p`
    /// semantics: an existing directory succeeds).
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn mkdir(&self, path: &str, options: MkdirOptions) -> Result<()> {
        self.client()
            .make_dir(pb::MakeDirRequest {
                id: self.sandbox_id.clone(),
                path: path.to_owned(),
                mode: options.mode.unwrap_or(0),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "files.mkdir"))?;
        Ok(())
    }

    /// Remove a file, symlink, or directory.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::FileNotFound`] for a missing path; a non-empty
    /// directory without [`RemoveOptions::recursive`] is a state error;
    /// otherwise any RPC failure.
    pub async fn remove(&self, path: &str, options: RemoveOptions) -> Result<()> {
        self.client()
            .remove(pb::RemoveEntryRequest {
                id: self.sandbox_id.clone(),
                path: path.to_owned(),
                recursive: options.recursive,
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "files.remove"))?;
        Ok(())
    }

    /// Rename or move an entry.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::FileNotFound`] for a missing source; otherwise any
    /// RPC failure.
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.client()
            .r#move(pb::MoveEntryRequest {
                id: self.sandbox_id.clone(),
                from_path: from.to_owned(),
                to_path: to.to_owned(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "files.rename"))?;
        Ok(())
    }

    /// Watch a directory, one typed event at a time. The stream ends
    /// cleanly when the sandbox stops; keepalive frames are filtered.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::FileNotFound`] for a missing path; otherwise any
    /// RPC failure — at subscription (first
    /// [`next`](WatchStream::next)) or mid-stream.
    #[must_use]
    pub fn watch(&self, path: &str, options: WatchOptions) -> WatchStream {
        WatchStream {
            files: self.clone(),
            path: path.to_owned(),
            recursive: options.recursive,
            stream: None,
            done: false,
        }
    }
}

/// A directory watch, read one event at a time with
/// [`next`](Self::next). The subscription is dialled on the first call.
pub struct WatchStream {
    files: Files,
    path: String,
    recursive: bool,
    stream: Option<WatchWireStream>,
    done: bool,
}

impl WatchStream {
    /// The next event, or `None` when the watch ended cleanly (the
    /// sandbox stopped).
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`]. Events cannot be
    /// replayed, so re-subscribing after an error is the caller's
    /// decision.
    pub async fn next(&mut self) -> Result<Option<FsEvent>> {
        if self.done {
            return Ok(None);
        }
        if self.stream.is_none() {
            let stream = self
                .files
                .client()
                .watch_dir(pb::WatchDirRequest {
                    id: self.files.sandbox_id.clone(),
                    path: self.path.clone(),
                    recursive: self.recursive,
                    ..Default::default()
                })
                .await
                .map_err(|error| {
                    self.done = true;
                    Error::from_connect(error, "files.watch")
                })?;
            self.stream = Some(stream);
        }
        let stream = self.stream.as_mut().expect("stream attached above");
        loop {
            match stream.message::<pb::WatchDirResponse>().await {
                Ok(Some(frame)) => {
                    if let Some(pb::watch_dir_response::Payload::Event(event)) =
                        frame.to_owned_message().payload
                    {
                        return Ok(Some(FsEvent::from(*event)));
                    }
                    // Keepalives prove liveness but carry no event.
                }
                Ok(None) => {
                    self.done = true;
                    return Ok(None);
                }
                Err(error) => {
                    self.done = true;
                    return Err(Error::from_connect(error, "files.watch"));
                }
            }
        }
    }
}

impl From<pb::FileStat> for FileStat {
    fn from(stat: pb::FileStat) -> Self {
        let kind = match stat.kind.as_known() {
            Some(pb::FileKind::FILE_KIND_FILE) => FileKind::File,
            Some(pb::FileKind::FILE_KIND_DIRECTORY) => FileKind::Directory,
            Some(pb::FileKind::FILE_KIND_SYMLINK) => FileKind::Symlink,
            Some(pb::FileKind::FILE_KIND_OTHER) => FileKind::Other,
            _ => FileKind::Unknown,
        };
        Self {
            name: stat.name,
            kind,
            size: stat.size,
            mode: stat.mode,
            modified_at: time_from_wire(stat.modified_at.as_option()),
            uid: stat.uid,
            gid: stat.gid,
            symlink_target: (!stat.symlink_target.is_empty()).then_some(stat.symlink_target),
        }
    }
}

impl From<pb::FsEvent> for FsEvent {
    fn from(event: pb::FsEvent) -> Self {
        let kind = match event.kind.as_known() {
            Some(pb::FsEventKind::FS_EVENT_KIND_CREATED) => FsEventKind::Created,
            Some(pb::FsEventKind::FS_EVENT_KIND_MODIFIED) => FsEventKind::Modified,
            Some(pb::FsEventKind::FS_EVENT_KIND_REMOVED) => FsEventKind::Removed,
            Some(pb::FsEventKind::FS_EVENT_KIND_RENAMED) => FsEventKind::Renamed,
            _ => FsEventKind::Unknown,
        };
        Self {
            kind,
            path: event.path,
            renamed_to: (!event.renamed_to.is_empty()).then_some(event.renamed_to),
        }
    }
}
