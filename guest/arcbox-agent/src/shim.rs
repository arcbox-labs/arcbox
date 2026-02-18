//! Container Process Shim.
//!
//! Manages container I/O and logging, providing unified handling for both
//! TTY and non-TTY mode containers.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │ Container       │────►│ ProcessShim     │────►│ Log File        │
//! │ (PTY/Pipes)     │     │ (async copier)  │     │ (JSON format)   │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//!                                │
//!                                ▼
//!                         ┌─────────────────┐
//!                         │ Attach Clients  │
//!                         │ (broadcast)     │
//!                         └─────────────────┘
//! ```
//!
//! ## Log Rotation
//!
//! The [`RotatingJsonFileWriter`] implements Docker-compatible log rotation:
//!
//! - `max_size`: Maximum size of each log file before rotation (default: 20MB)
//! - `max_files`: Maximum number of rotated files to keep (default: 5)
//! - `compress`: Whether to compress rotated files (default: true)
//!
//! File naming convention:
//! - `container.log` - Current log file
//! - `container.log.1` - Most recently rotated file (uncompressed for tools)
//! - `container.log.2.gz` - Older rotated files (compressed)
//!
//! ## Key Components
//!
//! - [`OutputSource`]: Trait abstracting PTY and Pipe readers
//! - [`LogWriter`]: Trait for log output destinations
//! - [`RotatingJsonFileWriter`]: JSON log writer with rotation support
//! - [`ProcessShim`]: Main shim implementation managing I/O copying
//! - [`BroadcastWriter`]: Tee writer for attach clients

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read as StdRead, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::process::{ChildStderr, ChildStdout};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_util::sync::CancellationToken;

// =============================================================================
// Stream Type
// =============================================================================

/// Stream type for log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// TTY mode - stdout and stderr are merged.
    Tty,
}

impl StreamType {
    /// Returns the stream name for logging.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout | Self::Tty => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

// =============================================================================
// Log Entry
// =============================================================================

/// A single log entry.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Stream type.
    pub stream: StreamType,
    /// Log data.
    pub data: Bytes,
    /// Timestamp in nanoseconds since Unix epoch.
    pub timestamp: i64,
    /// Whether this is a partial log (no trailing newline).
    pub partial: bool,
}

// =============================================================================
// Output Source Trait
// =============================================================================

/// Abstraction over different output sources (PTY master or pipes).
///
/// This trait unifies reading from PTY master file descriptor and
/// standard pipe file descriptors, allowing [`ProcessShim`] to handle
/// both TTY and non-TTY containers uniformly.
pub trait OutputSource: Send + 'static {
    /// Returns the stream type for this source.
    fn stream_type(&self) -> StreamType;

    /// Polls for read readiness and reads data into the buffer.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;
}

// =============================================================================
// PTY Source
// =============================================================================

/// Output source wrapping a PTY master file descriptor.
///
/// In TTY mode, both stdout and stderr are multiplexed through the PTY,
/// so we treat all output as [`StreamType::Tty`].
pub struct PtySource {
    /// Async file wrapper for the PTY master.
    inner: tokio::io::unix::AsyncFd<RawFdWrapper>,
}

/// Wrapper to implement `AsRawFd` for a raw file descriptor.
struct RawFdWrapper(RawFd);

impl AsRawFd for RawFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl PtySource {
    /// Creates a new PTY source from a raw file descriptor.
    ///
    /// # Safety
    ///
    /// The caller must ensure the file descriptor is valid and remains
    /// open for the lifetime of this source.
    pub fn new(fd: RawFd) -> io::Result<Self> {
        // Set non-blocking mode
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        let wrapper = RawFdWrapper(fd);
        let async_fd = tokio::io::unix::AsyncFd::new(wrapper)?;
        Ok(Self { inner: async_fd })
    }
}

impl OutputSource for PtySource {
    fn stream_type(&self) -> StreamType {
        StreamType::Tty
    }

    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let slice = buf.initialize_unfilled();
                let n = unsafe { libc::read(fd, slice.as_mut_ptr().cast(), slice.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

// =============================================================================
// Pipe Source
// =============================================================================

/// Output source wrapping a pipe file descriptor.
pub struct PipeSource {
    /// Stream type (stdout or stderr).
    stream: StreamType,
    /// Async file wrapper.
    inner: tokio::io::unix::AsyncFd<RawFdWrapper>,
}

impl PipeSource {
    /// Creates a new pipe source.
    ///
    /// # Safety
    ///
    /// The caller must ensure the file descriptor is valid.
    pub fn new(fd: RawFd, stream: StreamType) -> io::Result<Self> {
        // Set non-blocking mode
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        let wrapper = RawFdWrapper(fd);
        let async_fd = tokio::io::unix::AsyncFd::new(wrapper)?;
        Ok(Self {
            stream,
            inner: async_fd,
        })
    }
}

impl OutputSource for PipeSource {
    fn stream_type(&self) -> StreamType {
        self.stream
    }

    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let slice = buf.initialize_unfilled();
                let n = unsafe { libc::read(fd, slice.as_mut_ptr().cast(), slice.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

// =============================================================================
// Tokio Pipe Source
// =============================================================================

/// Output source wrapping Tokio child stdio pipes.
pub struct TokioPipeSource<R>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    /// Stream type (stdout or stderr).
    stream: StreamType,
    /// Tokio-managed reader.
    inner: R,
}

impl<R> TokioPipeSource<R>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    /// Creates a new Tokio pipe source.
    pub fn new(inner: R, stream: StreamType) -> Self {
        Self { stream, inner }
    }
}

impl<R> OutputSource for TokioPipeSource<R>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    fn stream_type(&self) -> StreamType {
        self.stream
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// =============================================================================
// Log Writer Trait
// =============================================================================

/// Trait for log output destinations.
///
/// Implementations can write to files, remote endpoints, or broadcast
/// to multiple clients.
#[async_trait::async_trait]
pub trait LogWriter: Send + Sync {
    /// Writes a log entry.
    async fn write(&self, entry: &LogEntry) -> io::Result<()>;

    /// Flushes pending writes.
    async fn flush(&self) -> io::Result<()>;
}

/// No-op log writer used when log files cannot be created.
pub struct NullLogWriter;

#[async_trait::async_trait]
impl LogWriter for NullLogWriter {
    async fn write(&self, _entry: &LogEntry) -> io::Result<()> {
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

// =============================================================================
// JSON File Writer
// =============================================================================

/// Docker-compatible JSON log format writer.
///
/// Writes logs in the format:
/// ```json
/// {"log":"content\n","stream":"stdout","time":"2024-01-15T10:30:00.123456789Z"}
/// ```
pub struct JsonFileWriter {
    /// File handle with buffering.
    file: Mutex<BufWriter<File>>,
}

impl JsonFileWriter {
    /// Creates a new JSON file writer.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            file: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Escapes a string for JSON output.
    fn escape_json(data: &[u8]) -> String {
        let s = String::from_utf8_lossy(data);
        s.chars()
            .map(|c| match c {
                '"' => "\\\"".to_string(),
                '\\' => "\\\\".to_string(),
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                '\t' => "\\t".to_string(),
                c if c.is_control() => format!("\\u{:04x}", c as u32),
                c => c.to_string(),
            })
            .collect()
    }

    /// Formats a timestamp as RFC3339 with nanosecond precision.
    fn format_timestamp(nanos: i64) -> String {
        let secs = nanos / 1_000_000_000;
        let nsecs = (nanos % 1_000_000_000) as u32;
        let dt = chrono::DateTime::from_timestamp(secs, nsecs).unwrap_or_else(chrono::Utc::now);
        dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string()
    }
}

#[async_trait::async_trait]
impl LogWriter for JsonFileWriter {
    async fn write(&self, entry: &LogEntry) -> io::Result<()> {
        let log = Self::escape_json(&entry.data);
        let stream = entry.stream.as_str();
        let time = Self::format_timestamp(entry.timestamp);

        let line = format!(
            r#"{{"log":"{}","stream":"{}","time":"{}"}}"#,
            log, stream, time
        );

        let mut file = self.file.lock().await;
        writeln!(file, "{}", line)?;
        // Keep `docker logs` responsive for running containers.
        file.flush()?;
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        let mut file = self.file.lock().await;
        file.flush()
    }
}

// =============================================================================
// Rotating JSON File Writer
// =============================================================================

/// Default maximum log file size (20 MB).
const DEFAULT_MAX_SIZE: u64 = 20 * 1024 * 1024;

/// Default maximum number of log files to keep.
const DEFAULT_MAX_FILES: u32 = 5;

/// Log rotation configuration.
#[derive(Debug, Clone)]
pub struct LogRotationConfig {
    /// Maximum size of each log file in bytes.
    pub max_size: u64,
    /// Maximum number of rotated files to keep.
    pub max_files: u32,
    /// Whether to compress rotated files using gzip.
    pub compress: bool,
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
            max_files: DEFAULT_MAX_FILES,
            compress: true,
        }
    }
}

/// Docker-compatible JSON log writer with rotation support.
///
/// Implements the same rotation strategy as Docker's json-file and local drivers:
/// - Rotates when file size exceeds `max_size`
/// - Keeps at most `max_files` rotated files
/// - Optionally compresses old log files
///
/// # File Naming
///
/// - `container.log` - Current active log file
/// - `container.log.1` - Most recently rotated (kept uncompressed for tool compatibility)
/// - `container.log.2.gz` - Older files (compressed if enabled)
///
/// # Thread Safety
///
/// All operations are protected by an async mutex, ensuring safe concurrent writes.
pub struct RotatingJsonFileWriter {
    /// Log file path (without rotation suffix).
    path: PathBuf,
    /// Rotation configuration.
    config: LogRotationConfig,
    /// Current file handle with buffering.
    file: Mutex<BufWriter<File>>,
    /// Current file size (tracked to avoid syscalls).
    size: Mutex<u64>,
}

impl RotatingJsonFileWriter {
    /// Creates a new rotating JSON file writer.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the log file (without rotation suffix)
    /// * `config` - Rotation configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be created or opened.
    pub fn new(path: impl AsRef<Path>, config: LogRotationConfig) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        let size = file.metadata()?.len();

        Ok(Self {
            path,
            config,
            file: Mutex::new(BufWriter::new(file)),
            size: Mutex::new(size),
        })
    }

    /// Creates a writer with default rotation configuration.
    pub fn with_defaults(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::new(path, LogRotationConfig::default())
    }

    /// Returns the rotation configuration.
    #[must_use]
    pub fn config(&self) -> &LogRotationConfig {
        &self.config
    }

    /// Performs log rotation.
    ///
    /// This method:
    /// 1. Closes the current log file
    /// 2. Renames existing rotated files (.N -> .N+1)
    /// 3. Renames current file to .1
    /// 4. Deletes files exceeding max_files
    /// 5. Creates a new empty log file
    /// 6. Optionally compresses .1 to .1.gz in background
    async fn rotate(&self) -> io::Result<()> {
        tracing::debug!(path = ?self.path, "rotating log file");

        let mut file_guard = self.file.lock().await;

        // Flush and close current file.
        file_guard.flush()?;
        drop(file_guard);

        // Perform file rotation.
        self.rotate_files()?;

        // Reopen fresh log file.
        let new_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.path)?;

        // Update internal state.
        *self.file.lock().await = BufWriter::new(new_file);
        *self.size.lock().await = 0;

        // Compress .1 file in background if enabled.
        if self.config.compress && self.config.max_files > 1 {
            let path = self.path.clone();
            tokio::spawn(async move {
                if let Err(e) = compress_log_file(&path) {
                    tracing::warn!(path = ?path, error = %e, "failed to compress rotated log file");
                }
            });
        }

        Ok(())
    }

    /// Rotates existing log files by renaming them.
    fn rotate_files(&self) -> io::Result<()> {
        let max_files = self.config.max_files;
        let compress = self.config.compress;

        if max_files < 2 {
            // No rotation needed, just truncate.
            return Ok(());
        }

        let extension = if compress { ".gz" } else { "" };

        // Delete oldest file if it exists.
        let oldest = format!("{}.{}{}", self.path.display(), max_files - 1, extension);
        if Path::new(&oldest).exists() {
            fs::remove_file(&oldest)?;
        }

        // Rename files: .N-1 -> .N, .N-2 -> .N-1, ...
        for i in (2..max_files).rev() {
            let from = format!("{}.{}{}", self.path.display(), i - 1, extension);
            let to = format!("{}.{}{}", self.path.display(), i, extension);
            if Path::new(&from).exists() {
                fs::rename(&from, &to)?;
            }
        }

        // Rename current file to .1 (always uncompressed initially).
        let rotated_path = format!("{}.1", self.path.display());
        if self.path.exists() {
            fs::rename(&self.path, &rotated_path)?;
        }

        Ok(())
    }

    /// Escapes a string for JSON output.
    fn escape_json(data: &[u8]) -> String {
        let s = String::from_utf8_lossy(data);
        s.chars()
            .map(|c| match c {
                '"' => "\\\"".to_string(),
                '\\' => "\\\\".to_string(),
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                '\t' => "\\t".to_string(),
                c if c.is_control() => format!("\\u{:04x}", c as u32),
                c => c.to_string(),
            })
            .collect()
    }

    /// Formats a timestamp as RFC3339 with nanosecond precision.
    fn format_timestamp(nanos: i64) -> String {
        let secs = nanos / 1_000_000_000;
        let nsecs = (nanos % 1_000_000_000) as u32;
        let dt = chrono::DateTime::from_timestamp(secs, nsecs).unwrap_or_else(chrono::Utc::now);
        dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string()
    }
}

#[async_trait::async_trait]
impl LogWriter for RotatingJsonFileWriter {
    async fn write(&self, entry: &LogEntry) -> io::Result<()> {
        let log = Self::escape_json(&entry.data);
        let stream = entry.stream.as_str();
        let time = Self::format_timestamp(entry.timestamp);

        let line = format!(
            r#"{{"log":"{}","stream":"{}","time":"{}"}}"#,
            log, stream, time
        );
        let line_bytes = line.as_bytes();
        let line_len = line_bytes.len() as u64 + 1; // +1 for newline

        // Check if rotation is needed before writing.
        let current_size = *self.size.lock().await;
        if self.config.max_size > 0 && current_size + line_len > self.config.max_size {
            self.rotate().await?;
        }

        // Write the log entry.
        {
            let mut file = self.file.lock().await;
            writeln!(file, "{}", line)?;
            // Keep `docker logs` responsive for running containers.
            file.flush()?;
        }

        // Update size counter.
        *self.size.lock().await += line_len;

        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        let mut file = self.file.lock().await;
        file.flush()
    }
}

/// Compresses a rotated log file (.1) to gzip format (.1.gz).
///
/// This function:
/// 1. Reads the uncompressed .1 file
/// 2. Writes compressed data to .1.gz
/// 3. Deletes the original .1 file on success
fn compress_log_file(base_path: &Path) -> io::Result<()> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let source_path = format!("{}.1", base_path.display());
    let dest_path = format!("{}.1.gz", base_path.display());

    // Check if source exists.
    if !Path::new(&source_path).exists() {
        return Ok(());
    }

    // Read source file.
    let mut source = File::open(&source_path)?;
    let mut data = Vec::new();
    source.read_to_end(&mut data)?;
    drop(source);

    // Write compressed file.
    let dest_file = File::create(&dest_path)?;
    let mut encoder = GzEncoder::new(dest_file, Compression::default());
    encoder.write_all(&data)?;
    encoder.finish()?;

    // Remove source file.
    fs::remove_file(&source_path)?;

    tracing::debug!(source = %source_path, dest = %dest_path, "compressed log file");

    Ok(())
}

// =============================================================================
// Broadcast Writer
// =============================================================================

/// In-memory backlog to replay recent output to new subscribers.
struct BroadcastBacklog {
    entries: VecDeque<LogEntry>,
    total_bytes: usize,
}

impl BroadcastBacklog {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            total_bytes: 0,
        }
    }

    /// Push a new log entry and trim oldest data to respect limits.
    fn push_and_trim(&mut self, entry: LogEntry) {
        self.total_bytes += entry.data.len();
        self.entries.push_back(entry);

        while self.entries.len() > BROADCAST_BACKLOG_MAX_ENTRIES
            || self.total_bytes > BROADCAST_BACKLOG_MAX_BYTES
        {
            if let Some(removed) = self.entries.pop_front() {
                self.total_bytes = self.total_bytes.saturating_sub(removed.data.len());
            } else {
                self.total_bytes = 0;
                break;
            }
        }
    }
}

/// Broadcast writer for attach clients.
///
/// Allows multiple clients to subscribe to log output in real-time.
/// When data is written, it is sent to all subscribed clients.
pub struct BroadcastWriter {
    /// Active subscribers.
    subscribers: RwLock<Vec<mpsc::Sender<LogEntry>>>,
    /// Recent output backlog for late subscribers.
    backlog: RwLock<BroadcastBacklog>,
    /// Whether the stream is closed.
    closed: AtomicBool,
}

const BROADCAST_BACKLOG_MAX_ENTRIES: usize = 64;
const BROADCAST_BACKLOG_MAX_BYTES: usize = 64 * 1024;

impl BroadcastWriter {
    /// Creates a new broadcast writer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscribers: RwLock::new(Vec::new()),
            backlog: RwLock::new(BroadcastBacklog::new()),
            closed: AtomicBool::new(false),
        }
    }

    /// Subscribes to log output.
    ///
    /// Returns a receiver that will receive log entries as they are written.
    pub async fn subscribe(&self) -> mpsc::Receiver<LogEntry> {
        let (tx, rx) = mpsc::channel(64);

        let closed = self.closed.load(Ordering::SeqCst);
        tracing::info!(
            "BroadcastWriter::subscribe: closed={}, will register={}",
            closed,
            !closed
        );
        if !closed {
            // Register subscriber first to receive new data arriving during replay.
            self.subscribers.write().await.push(tx.clone());
        }

        // Replay buffered output so fast commands are not missed.
        {
            let backlog = self.backlog.read().await;
            tracing::info!(
                "BroadcastWriter::subscribe: replaying {} backlog entries, total_bytes={}",
                backlog.entries.len(),
                backlog.total_bytes
            );
            for entry in backlog.entries.iter() {
                if tx.send(entry.clone()).await.is_err() {
                    tracing::debug!("BroadcastWriter::subscribe: send failed during replay");
                    return rx;
                }
            }
        }

        if closed {
            tracing::debug!("BroadcastWriter::subscribe: dropping tx because closed");
            drop(tx);
        }

        rx
    }

    /// Closes all subscribers so attach sessions can end.
    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let mut subs = self.subscribers.write().await;
        subs.clear();
    }

    /// Removes closed subscribers.
    async fn cleanup(&self) {
        let mut subs = self.subscribers.write().await;
        subs.retain(|tx| !tx.is_closed());
    }
}

impl Default for BroadcastWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl LogWriter for BroadcastWriter {
    async fn write(&self, entry: &LogEntry) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }

        {
            let mut backlog = self.backlog.write().await;
            backlog.push_and_trim(entry.clone());
        }

        let subs = self.subscribers.read().await;
        for tx in subs.iter() {
            // Best-effort send, don't block if a subscriber is slow
            let _ = tx.try_send(entry.clone());
        }
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        self.cleanup().await;
        Ok(())
    }
}

// =============================================================================
// Tee Writer
// =============================================================================

/// Tee writer that writes to multiple destinations.
///
/// Typically used to write to both a log file and broadcast to attach clients.
pub struct TeeWriter<W1, W2> {
    /// Primary writer (usually log file).
    primary: W1,
    /// Secondary writer (usually broadcast).
    secondary: W2,
}

impl<W1, W2> TeeWriter<W1, W2> {
    /// Creates a new tee writer.
    pub fn new(primary: W1, secondary: W2) -> Self {
        Self { primary, secondary }
    }
}

#[async_trait::async_trait]
impl<W1, W2> LogWriter for TeeWriter<W1, W2>
where
    W1: LogWriter,
    W2: LogWriter,
{
    async fn write(&self, entry: &LogEntry) -> io::Result<()> {
        // Write to both, but don't fail if secondary fails
        self.primary.write(entry).await?;
        let _ = self.secondary.write(entry).await;
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        self.primary.flush().await?;
        let _ = self.secondary.flush().await;
        Ok(())
    }
}

// =============================================================================
// Pinned Source Wrapper
// =============================================================================

/// Wrapper to make OutputSource implement AsyncRead.
struct SourceReader<S> {
    source: S,
}

impl<S: OutputSource + Unpin> AsyncRead for SourceReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.source).poll_read(cx, buf)
    }
}

// =============================================================================
// Process Shim
// =============================================================================

/// Container log directory.
const CONTAINER_LOG_DIR: &str = "/var/log/containers";

/// Default read buffer size.
const READ_BUFFER_SIZE: usize = 8192;

/// Per-container process shim.
///
/// Manages container I/O and logging:
/// - Holds PTY master (TTY mode) or pipes (non-TTY mode)
/// - Copies output to log file asynchronously
/// - Supports attaching clients for real-time log streaming
///
/// ## Usage
///
/// ```ignore
/// // For TTY mode container
/// let shim = ProcessShim::with_pty(container_id, pty_master_fd)?;
///
/// // For non-TTY mode container
/// let shim = ProcessShim::with_pipes(container_id, stdout_fd, stderr_fd)?;
///
/// // Run the shim (typically in a spawned task)
/// shim.run().await?;
/// ```
pub struct ProcessShim {
    /// Container ID.
    container_id: String,

    /// Output sources.
    sources: Vec<Box<dyn OutputSource + Unpin>>,

    /// Log file writer.
    log_writer: Box<dyn LogWriter>,

    /// Broadcast writer for attach clients.
    broadcast: Arc<BroadcastWriter>,

    /// Shutdown signal.
    shutdown: CancellationToken,
}

impl ProcessShim {
    /// Creates a shim for a TTY mode container.
    ///
    /// The PTY master file descriptor is used to read container output.
    /// All output is treated as stdout since TTY merges stdout and stderr.
    pub fn with_pty(container_id: String, pty_master_fd: RawFd) -> io::Result<Self> {
        let source = PtySource::new(pty_master_fd)?;
        Self::new(container_id, vec![Box::new(source)])
    }

    /// Creates a shim for a non-TTY mode container.
    ///
    /// Separate file descriptors are used for stdout and stderr.
    pub fn with_pipes(
        container_id: String,
        stdout_fd: RawFd,
        stderr_fd: RawFd,
    ) -> io::Result<Self> {
        let stdout_source = PipeSource::new(stdout_fd, StreamType::Stdout)?;
        let stderr_source = PipeSource::new(stderr_fd, StreamType::Stderr)?;
        Self::new(
            container_id,
            vec![Box::new(stdout_source), Box::new(stderr_source)],
        )
    }

    /// Creates a shim for a non-TTY mode container using Tokio child pipes.
    ///
    /// This avoids re-registering file descriptors that Tokio already owns.
    pub fn with_child_pipes(
        container_id: String,
        stdout: ChildStdout,
        stderr: ChildStderr,
    ) -> io::Result<Self> {
        let stdout_source = TokioPipeSource::new(stdout, StreamType::Stdout);
        let stderr_source = TokioPipeSource::new(stderr, StreamType::Stderr);
        Self::new(
            container_id,
            vec![Box::new(stdout_source), Box::new(stderr_source)],
        )
    }

    /// Internal constructor.
    fn new(container_id: String, sources: Vec<Box<dyn OutputSource + Unpin>>) -> io::Result<Self> {
        // Ensure log directory exists, but keep shims running even if logs are unavailable.
        if let Err(e) = std::fs::create_dir_all(CONTAINER_LOG_DIR) {
            tracing::warn!("Failed to create log dir {}: {}", CONTAINER_LOG_DIR, e);
        }

        let log_path = format!("{}/{}.log", CONTAINER_LOG_DIR, container_id);
        let log_writer: Box<dyn LogWriter> = match JsonFileWriter::new(&log_path) {
            Ok(writer) => Box::new(writer),
            Err(e) => {
                tracing::warn!("Failed to open log file {}: {}", log_path, e);
                Box::new(NullLogWriter)
            }
        };

        Ok(Self {
            container_id,
            sources,
            log_writer,
            broadcast: Arc::new(BroadcastWriter::new()),
            shutdown: CancellationToken::new(),
        })
    }

    /// Returns a handle to subscribe to log output.
    ///
    /// Attach clients can use this to receive log entries in real-time.
    pub fn broadcaster(&self) -> Arc<BroadcastWriter> {
        Arc::clone(&self.broadcast)
    }

    /// Returns a cancellation token to stop the shim.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Runs the shim, copying output to log file and broadcast.
    ///
    /// This method runs until all sources are closed or shutdown is signaled.
    pub async fn run(mut self) -> io::Result<()> {
        tracing::info!("Shim started for container {}", self.container_id);

        // Take ownership of sources
        let sources = std::mem::take(&mut self.sources);
        let num_sources = sources.len();

        if num_sources == 0 {
            tracing::warn!("No output sources for container {}", self.container_id);
            return Ok(());
        }

        // Create channels for each source
        let (tx, mut rx) = mpsc::channel::<LogEntry>(64);

        // Spawn a reader task for each source
        for source in sources {
            let tx = tx.clone();
            let shutdown = self.shutdown.clone();
            let container_id = self.container_id.clone();

            tokio::spawn(async move {
                if let Err(e) = read_source(source, tx, shutdown).await {
                    if e.kind() != io::ErrorKind::UnexpectedEof {
                        tracing::error!("Error reading from source for {}: {}", container_id, e);
                    }
                }
            });
        }

        // Drop our sender so the channel closes when all sources are done
        drop(tx);

        // Process entries from all sources
        let mut entry_count = 0u32;
        while let Some(entry) = rx.recv().await {
            entry_count += 1;
            tracing::info!(
                "Shim: received entry #{} for {}, stream={:?}, len={}",
                entry_count,
                self.container_id,
                entry.stream,
                entry.data.len()
            );

            // Write to log file
            if let Err(e) = self.log_writer.write(&entry).await {
                tracing::error!("Error writing log for {}: {}", self.container_id, e);
            }

            // Broadcast to attach clients
            let _ = self.broadcast.write(&entry).await;
        }
        tracing::info!(
            "Shim: finished processing {} entries for {}",
            entry_count,
            self.container_id
        );

        // Flush log file
        self.log_writer.flush().await?;

        // Close broadcast stream so attach sessions can end.
        self.broadcast.close().await;

        tracing::info!("Shim stopped for container {}", self.container_id);
        Ok(())
    }
}

/// Starts a broadcast-only shim for non-TTY pipes.
pub fn spawn_broadcast_only_from_pipes(stdout_fd: RawFd, stderr_fd: RawFd) -> Arc<BroadcastWriter> {
    let broadcaster = Arc::new(BroadcastWriter::new());

    let stdout_source = match PipeSource::new(stdout_fd, StreamType::Stdout) {
        Ok(source) => source,
        Err(e) => {
            tracing::warn!("Broadcast-only shim: failed to wrap stdout fd: {}", e);
            return broadcaster;
        }
    };
    let stderr_source = match PipeSource::new(stderr_fd, StreamType::Stderr) {
        Ok(source) => source,
        Err(e) => {
            tracing::warn!("Broadcast-only shim: failed to wrap stderr fd: {}", e);
            return broadcaster;
        }
    };

    let (tx, mut rx) = mpsc::channel::<LogEntry>(64);
    let shutdown = CancellationToken::new();

    let tx_stdout = tx.clone();
    let shutdown_stdout = shutdown.clone();
    tokio::spawn(async move {
        let _ = read_source(Box::new(stdout_source), tx_stdout, shutdown_stdout).await;
    });

    let tx_stderr = tx.clone();
    let shutdown_stderr = shutdown.clone();
    tokio::spawn(async move {
        let _ = read_source(Box::new(stderr_source), tx_stderr, shutdown_stderr).await;
    });

    drop(tx);

    let broadcaster_clone = Arc::clone(&broadcaster);
    tokio::spawn(async move {
        while let Some(entry) = rx.recv().await {
            let _ = broadcaster_clone.write(&entry).await;
        }
        broadcaster_clone.close().await;
    });

    broadcaster
}

/// Starts a broadcast-only shim for TTY output.
pub fn spawn_broadcast_only_from_pty(pty_master_fd: RawFd) -> Arc<BroadcastWriter> {
    let broadcaster = Arc::new(BroadcastWriter::new());

    let pty_source = match PtySource::new(pty_master_fd) {
        Ok(source) => source,
        Err(e) => {
            tracing::warn!("Broadcast-only shim: failed to wrap pty fd: {}", e);
            return broadcaster;
        }
    };

    let (tx, mut rx) = mpsc::channel::<LogEntry>(64);
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = read_source(Box::new(pty_source), tx, shutdown_clone).await;
    });

    let broadcaster_clone = Arc::clone(&broadcaster);
    tokio::spawn(async move {
        while let Some(entry) = rx.recv().await {
            let _ = broadcaster_clone.write(&entry).await;
        }
        broadcaster_clone.close().await;
    });

    broadcaster
}

/// Reads from a source and sends entries to the channel.
async fn read_source(
    mut source: Box<dyn OutputSource + Unpin>,
    tx: mpsc::Sender<LogEntry>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let stream_type = source.stream_type();
    tracing::info!("read_source: starting for stream {:?}", stream_type);
    let mut buf = BytesMut::with_capacity(READ_BUFFER_SIZE);
    let mut read_buf = [0u8; READ_BUFFER_SIZE];
    let mut total_bytes_read = 0usize;

    loop {
        // Create a ReadBuf for this read
        let mut rb = ReadBuf::new(&mut read_buf);

        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                tracing::debug!("Source reader shutdown");
                break;
            }

            result = poll_fn(|cx| Pin::new(&mut *source).poll_read(cx, &mut rb)) => {
                result?;
                let n = rb.filled().len();
                total_bytes_read += n;

                if n == 0 {
                    // EOF - send any remaining data
                    tracing::info!(
                        "read_source: EOF for stream {:?}, total_bytes_read={}, remaining_buf={}",
                        stream_type,
                        total_bytes_read,
                        buf.len()
                    );
                    if !buf.is_empty() {
                        let entry = LogEntry {
                            stream: stream_type,
                            data: buf.freeze(),
                            timestamp: now_nanos(),
                            partial: true,
                        };
                        let _ = tx.send(entry).await;
                    }
                    break;
                }

                buf.extend_from_slice(&read_buf[..n]);

                // Process complete lines
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line = buf.split_to(pos + 1).freeze();
                    let entry = LogEntry {
                        stream: stream_type,
                        data: line,
                        timestamp: now_nanos(),
                        partial: false,
                    };
                    if tx.send(entry).await.is_err() {
                        // Receiver dropped
                        return Ok(());
                    }
                }

                // If buffer is getting too large, send as partial
                if buf.len() > READ_BUFFER_SIZE * 2 {
                    let data = buf.split().freeze();
                    let entry = LogEntry {
                        stream: stream_type,
                        data,
                        timestamp: now_nanos(),
                        partial: true,
                    };
                    if tx.send(entry).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}

/// Helper for polling a future.
fn poll_fn<F, T>(f: F) -> impl std::future::Future<Output = T>
where
    F: FnMut(&mut Context<'_>) -> Poll<T>,
{
    std::future::poll_fn(f)
}

/// Returns current time in nanoseconds since Unix epoch.
fn now_nanos() -> i64 {
    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_stream_type_as_str() {
        assert_eq!(StreamType::Stdout.as_str(), "stdout");
        assert_eq!(StreamType::Stderr.as_str(), "stderr");
        assert_eq!(StreamType::Tty.as_str(), "stdout");
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(JsonFileWriter::escape_json(b"hello"), "hello");
        assert_eq!(JsonFileWriter::escape_json(b"hello\n"), "hello\\n");
        assert_eq!(JsonFileWriter::escape_json(b"say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(JsonFileWriter::escape_json(b"back\\slash"), "back\\\\slash");
        assert_eq!(JsonFileWriter::escape_json(b"tab\there"), "tab\\there");
    }

    #[test]
    fn test_timestamp_format() {
        // 2024-01-15T10:30:00.123456789Z
        let nanos = 1705315800_123456789i64;
        let formatted = JsonFileWriter::format_timestamp(nanos);
        assert!(formatted.starts_with("2024-01-15T"));
        assert!(formatted.ends_with("Z"));
        assert!(formatted.contains(".123456789"));
    }

    #[tokio::test]
    async fn test_json_file_writer() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let writer = JsonFileWriter::new(&log_path).unwrap();

        let entry = LogEntry {
            stream: StreamType::Stdout,
            data: Bytes::from("hello world\n"),
            timestamp: 1705315800_000000000,
            partial: false,
        };

        writer.write(&entry).await.unwrap();
        writer.flush().await.unwrap();

        let mut content = String::new();
        File::open(&log_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        assert!(content.contains(r#""log":"hello world\n""#));
        assert!(content.contains(r#""stream":"stdout""#));
        assert!(content.contains(r#""time":"2024-01-15T"#));
    }

    #[tokio::test]
    async fn test_broadcast_writer() {
        let broadcast = BroadcastWriter::new();

        // Subscribe before writing
        let mut rx1 = broadcast.subscribe().await;
        let mut rx2 = broadcast.subscribe().await;

        let entry = LogEntry {
            stream: StreamType::Stdout,
            data: Bytes::from("test"),
            timestamp: 0,
            partial: false,
        };

        broadcast.write(&entry).await.unwrap();

        // Both subscribers should receive the entry
        let e1 = rx1.try_recv().unwrap();
        let e2 = rx2.try_recv().unwrap();

        assert_eq!(e1.data, Bytes::from("test"));
        assert_eq!(e2.data, Bytes::from("test"));
    }

    #[tokio::test]
    async fn test_tee_writer() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let file_writer = JsonFileWriter::new(&log_path).unwrap();
        let broadcast = BroadcastWriter::new();
        let mut rx = broadcast.subscribe().await;

        let tee = TeeWriter::new(file_writer, broadcast);

        let entry = LogEntry {
            stream: StreamType::Stderr,
            data: Bytes::from("error\n"),
            timestamp: 0,
            partial: false,
        };

        tee.write(&entry).await.unwrap();
        tee.flush().await.unwrap();

        // Check file was written
        let mut content = String::new();
        File::open(&log_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.contains("error"));

        // Check broadcast was sent
        let received = rx.try_recv().unwrap();
        assert_eq!(received.data, Bytes::from("error\n"));
    }

    // =========================================================================
    // JSON Escape Edge Cases
    // =========================================================================

    #[test]
    fn test_json_escape_empty() {
        assert_eq!(JsonFileWriter::escape_json(b""), "");
    }

    #[test]
    fn test_json_escape_control_chars() {
        // Test various control characters
        assert_eq!(JsonFileWriter::escape_json(b"\x00"), "\\u0000");
        assert_eq!(JsonFileWriter::escape_json(b"\x1f"), "\\u001f");
        assert_eq!(JsonFileWriter::escape_json(b"\x7f"), "\\u007f");
    }

    #[test]
    fn test_json_escape_unicode() {
        // UTF-8 should pass through unchanged
        let utf8 = "你好世界";
        assert_eq!(JsonFileWriter::escape_json(utf8.as_bytes()), utf8);
    }

    #[test]
    fn test_json_escape_mixed() {
        let input = b"line1\nline2\t\"quoted\"\r\n";
        let expected = "line1\\nline2\\t\\\"quoted\\\"\\r\\n";
        assert_eq!(JsonFileWriter::escape_json(input), expected);
    }

    // =========================================================================
    // Timestamp Edge Cases
    // =========================================================================

    #[test]
    fn test_timestamp_format_zero() {
        let formatted = JsonFileWriter::format_timestamp(0);
        assert!(formatted.starts_with("1970-01-01T"));
        assert!(formatted.ends_with("Z"));
    }

    #[test]
    fn test_timestamp_format_negative() {
        // Negative timestamp should still work (before Unix epoch)
        let formatted = JsonFileWriter::format_timestamp(-86400_000_000_000);
        assert!(formatted.starts_with("1969-12-31T"));
    }

    // =========================================================================
    // LogEntry Tests
    // =========================================================================

    #[test]
    fn test_log_entry_clone() {
        let entry = LogEntry {
            stream: StreamType::Stdout,
            data: Bytes::from("test data"),
            timestamp: 12345,
            partial: true,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.stream, entry.stream);
        assert_eq!(cloned.data, entry.data);
        assert_eq!(cloned.timestamp, entry.timestamp);
        assert_eq!(cloned.partial, entry.partial);
    }

    // =========================================================================
    // BroadcastWriter Advanced Tests
    // =========================================================================

    #[tokio::test]
    async fn test_broadcast_writer_no_subscribers() {
        let broadcast = BroadcastWriter::new();

        // Writing without subscribers should not fail
        let entry = LogEntry {
            stream: StreamType::Stdout,
            data: Bytes::from("test"),
            timestamp: 0,
            partial: false,
        };

        let result = broadcast.write(&entry).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_broadcast_writer_subscriber_dropped() {
        let broadcast = BroadcastWriter::new();

        // Subscribe and then drop the receiver
        let rx = broadcast.subscribe().await;
        drop(rx);

        // Writing should still succeed
        let entry = LogEntry {
            stream: StreamType::Stdout,
            data: Bytes::from("test"),
            timestamp: 0,
            partial: false,
        };

        let result = broadcast.write(&entry).await;
        assert!(result.is_ok());

        // Cleanup should remove the dropped subscriber
        broadcast.flush().await.unwrap();
    }

    #[tokio::test]
    async fn test_broadcast_writer_multiple_entries() {
        let broadcast = BroadcastWriter::new();
        let mut rx = broadcast.subscribe().await;

        for i in 0..10 {
            let entry = LogEntry {
                stream: StreamType::Stdout,
                data: Bytes::from(format!("line {}\n", i)),
                timestamp: i as i64,
                partial: false,
            };
            broadcast.write(&entry).await.unwrap();
        }

        // Verify all entries received
        for i in 0..10 {
            let received = rx.recv().await.unwrap();
            assert_eq!(received.data, Bytes::from(format!("line {}\n", i)));
        }
    }

    // =========================================================================
    // JsonFileWriter Advanced Tests
    // =========================================================================

    #[tokio::test]
    async fn test_json_file_writer_multiple_entries() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let writer = JsonFileWriter::new(&log_path).unwrap();

        // Write multiple entries
        for i in 0..5 {
            let entry = LogEntry {
                stream: if i % 2 == 0 {
                    StreamType::Stdout
                } else {
                    StreamType::Stderr
                },
                data: Bytes::from(format!("line {}\n", i)),
                timestamp: 1705315800_000000000 + i as i64 * 1_000_000_000,
                partial: false,
            };
            writer.write(&entry).await.unwrap();
        }
        writer.flush().await.unwrap();

        // Read and verify
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);

        // Verify each line is valid JSON
        for line in lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("log").is_some());
            assert!(parsed.get("stream").is_some());
            assert!(parsed.get("time").is_some());
        }
    }

    #[tokio::test]
    async fn test_json_file_writer_stderr_stream() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let writer = JsonFileWriter::new(&log_path).unwrap();

        let entry = LogEntry {
            stream: StreamType::Stderr,
            data: Bytes::from("error message\n"),
            timestamp: 0,
            partial: false,
        };

        writer.write(&entry).await.unwrap();
        writer.flush().await.unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains(r#""stream":"stderr""#));
    }

    #[tokio::test]
    async fn test_json_file_writer_tty_stream() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let writer = JsonFileWriter::new(&log_path).unwrap();

        let entry = LogEntry {
            stream: StreamType::Tty,
            data: Bytes::from("tty output\n"),
            timestamp: 0,
            partial: false,
        };

        writer.write(&entry).await.unwrap();
        writer.flush().await.unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        // TTY mode should be logged as stdout
        assert!(content.contains(r#""stream":"stdout""#));
    }

    #[tokio::test]
    async fn test_json_file_writer_append_mode() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Write first entry
        {
            let writer = JsonFileWriter::new(&log_path).unwrap();
            let entry = LogEntry {
                stream: StreamType::Stdout,
                data: Bytes::from("first\n"),
                timestamp: 0,
                partial: false,
            };
            writer.write(&entry).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Write second entry (new writer instance)
        {
            let writer = JsonFileWriter::new(&log_path).unwrap();
            let entry = LogEntry {
                stream: StreamType::Stdout,
                data: Bytes::from("second\n"),
                timestamp: 0,
                partial: false,
            };
            writer.write(&entry).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Both entries should be in the file
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(content.contains("first"));
        assert!(content.contains("second"));
    }

    // =========================================================================
    // Mock OutputSource for Testing
    // =========================================================================

    /// Mock output source for testing.
    struct MockOutputSource {
        stream: StreamType,
        data: std::sync::Mutex<Vec<u8>>,
        position: std::sync::Mutex<usize>,
    }

    impl MockOutputSource {
        fn new(stream: StreamType, data: Vec<u8>) -> Self {
            Self {
                stream,
                data: std::sync::Mutex::new(data),
                position: std::sync::Mutex::new(0),
            }
        }
    }

    impl OutputSource for MockOutputSource {
        fn stream_type(&self) -> StreamType {
            self.stream
        }

        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let data = self.data.lock().unwrap();
            let mut pos = self.position.lock().unwrap();

            if *pos >= data.len() {
                return Poll::Ready(Ok(())); // EOF
            }

            let to_read = std::cmp::min(buf.remaining(), data.len() - *pos);
            buf.put_slice(&data[*pos..*pos + to_read]);
            *pos += to_read;

            Poll::Ready(Ok(()))
        }
    }

    // =========================================================================
    // Integration Tests with Pipes
    // =========================================================================

    /// Helper function to write to a raw fd using libc.
    fn write_to_fd(fd: RawFd, data: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    #[tokio::test]
    async fn test_pipe_source_basic() {
        // Create a pipe
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let write_raw_fd = write_fd.as_raw_fd();
        let read_raw_fd = read_fd.as_raw_fd();

        // Write some data to the pipe
        let write_data = b"hello from pipe\n";
        write_to_fd(write_raw_fd, write_data).unwrap();
        drop(write_fd); // Close write end

        // Create pipe source
        let source = PipeSource::new(read_raw_fd, StreamType::Stdout).unwrap();
        std::mem::forget(read_fd); // Don't close the fd, PipeSource will use it

        // Read using poll_read
        let mut buf = [0u8; 256];
        let mut read_buf = ReadBuf::new(&mut buf);

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Should be ready immediately since data is in the pipe
        let pin_source = std::pin::pin!(source);
        match pin_source.poll_read(&mut cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let data = read_buf.filled();
                assert_eq!(data, write_data);
            }
            Poll::Ready(Err(e)) => panic!("Read error: {}", e),
            Poll::Pending => {
                // May need to poll again
            }
        }
    }

    #[tokio::test]
    async fn test_read_source_with_mock() {
        let source =
            MockOutputSource::new(StreamType::Stdout, b"line 1\nline 2\nline 3\n".to_vec());

        let (tx, mut rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();

        // Run read_source in a task
        let handle = tokio::spawn(async move { read_source(Box::new(source), tx, shutdown).await });

        // Collect entries
        let mut entries = Vec::new();
        while let Some(entry) = rx.recv().await {
            entries.push(entry);
        }

        handle.await.unwrap().unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].data, Bytes::from("line 1\n"));
        assert_eq!(entries[1].data, Bytes::from("line 2\n"));
        assert_eq!(entries[2].data, Bytes::from("line 3\n"));

        for entry in &entries {
            assert_eq!(entry.stream, StreamType::Stdout);
            assert!(!entry.partial);
        }
    }

    #[tokio::test]
    async fn test_read_source_partial_line() {
        // Test data without trailing newline
        let source =
            MockOutputSource::new(StreamType::Stderr, b"partial data without newline".to_vec());

        let (tx, mut rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();

        let handle = tokio::spawn(async move { read_source(Box::new(source), tx, shutdown).await });

        let mut entries = Vec::new();
        while let Some(entry) = rx.recv().await {
            entries.push(entry);
        }

        handle.await.unwrap().unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, Bytes::from("partial data without newline"));
        assert!(entries[0].partial); // Should be marked as partial
        assert_eq!(entries[0].stream, StreamType::Stderr);
    }

    #[tokio::test]
    async fn test_read_source_shutdown() {
        // Create a source that would block forever
        struct BlockingSource;

        impl OutputSource for BlockingSource {
            fn stream_type(&self) -> StreamType {
                StreamType::Stdout
            }

            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending // Always pending
            }
        }

        let (tx, _rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle =
            tokio::spawn(
                async move { read_source(Box::new(BlockingSource), tx, shutdown_clone).await },
            );

        // Give task time to start
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Cancel the shutdown token
        shutdown.cancel();

        // Task should complete quickly
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), handle).await;

        assert!(result.is_ok(), "Task should complete after shutdown");
    }

    // =========================================================================
    // End-to-End Pipe Test
    // =========================================================================

    #[tokio::test]
    async fn test_shim_with_real_pipe() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("containers");
        std::fs::create_dir_all(&log_dir).unwrap();

        // Create pipes for stdout and stderr
        let (stdout_read, stdout_write) = nix::unistd::pipe().unwrap();
        let (stderr_read, stderr_write) = nix::unistd::pipe().unwrap();

        let stdout_read_fd = stdout_read.as_raw_fd();
        let stderr_read_fd = stderr_read.as_raw_fd();
        let stdout_write_fd = stdout_write.as_raw_fd();
        let stderr_write_fd = stderr_write.as_raw_fd();

        let container_id = "test-container";
        let log_path = log_dir.join(format!("{}.log", container_id));

        // Create the log writer manually
        let log_writer = JsonFileWriter::new(&log_path).unwrap();

        // Create sources
        let stdout_source = PipeSource::new(stdout_read_fd, StreamType::Stdout).unwrap();
        let stderr_source = PipeSource::new(stderr_read_fd, StreamType::Stderr).unwrap();
        std::mem::forget(stdout_read);
        std::mem::forget(stderr_read);

        let broadcast = Arc::new(BroadcastWriter::new());
        let mut subscriber = broadcast.subscribe().await;

        let (tx, mut rx) = mpsc::channel::<LogEntry>(64);
        let shutdown = CancellationToken::new();

        // Spawn readers
        let tx1 = tx.clone();
        let shutdown1 = shutdown.clone();
        tokio::spawn(async move {
            let _ = read_source(Box::new(stdout_source), tx1, shutdown1).await;
        });

        let tx2 = tx.clone();
        let shutdown2 = shutdown.clone();
        tokio::spawn(async move {
            let _ = read_source(Box::new(stderr_source), tx2, shutdown2).await;
        });

        drop(tx);

        // Write to pipes from "container"
        write_to_fd(stdout_write_fd, b"stdout line 1\n").unwrap();
        write_to_fd(stderr_write_fd, b"stderr line 1\n").unwrap();
        write_to_fd(stdout_write_fd, b"stdout line 2\n").unwrap();

        // Close write ends to signal EOF
        drop(stdout_write);
        drop(stderr_write);

        // Collect and write entries
        let mut entries = Vec::new();
        while let Some(entry) = rx.recv().await {
            log_writer.write(&entry).await.unwrap();
            broadcast.write(&entry).await.unwrap();
            entries.push(entry);
        }
        log_writer.flush().await.unwrap();

        // Verify entries
        assert_eq!(entries.len(), 3);

        // Verify log file
        let log_content = std::fs::read_to_string(&log_path).unwrap();
        let log_lines: Vec<&str> = log_content.lines().collect();
        assert_eq!(log_lines.len(), 3);

        // Verify JSON format
        for line in log_lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("log").is_some());
            assert!(parsed.get("stream").is_some());
            assert!(parsed.get("time").is_some());
        }

        // Verify broadcast received entries
        for _ in 0..3 {
            let received = subscriber.try_recv();
            assert!(received.is_ok());
        }
    }

    // =========================================================================
    // StreamType Tests
    // =========================================================================

    #[test]
    fn test_stream_type_equality() {
        assert_eq!(StreamType::Stdout, StreamType::Stdout);
        assert_eq!(StreamType::Stderr, StreamType::Stderr);
        assert_eq!(StreamType::Tty, StreamType::Tty);
        assert_ne!(StreamType::Stdout, StreamType::Stderr);
        assert_ne!(StreamType::Stdout, StreamType::Tty);
    }

    #[test]
    fn test_stream_type_copy() {
        let s1 = StreamType::Stdout;
        let s2 = s1; // Copy
        assert_eq!(s1, s2);
    }

    // =========================================================================
    // now_nanos Tests
    // =========================================================================

    #[test]
    fn test_now_nanos_reasonable_value() {
        let nanos = now_nanos();
        // Should be after 2020-01-01
        assert!(nanos > 1577836800_000_000_000);
        // Should be before 2100-01-01
        assert!(nanos < 4102444800_000_000_000);
    }

    #[test]
    fn test_now_nanos_monotonic() {
        let t1 = now_nanos();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let t2 = now_nanos();
        assert!(t2 >= t1);
    }

    // =========================================================================
    // Log Rotation Tests
    // =========================================================================

    #[test]
    fn test_log_rotation_config_default() {
        let config = LogRotationConfig::default();
        assert_eq!(config.max_size, 20 * 1024 * 1024); // 20 MB
        assert_eq!(config.max_files, 5);
        assert!(config.compress);
    }

    #[tokio::test]
    async fn test_rotating_json_file_writer_basic() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let config = LogRotationConfig {
            max_size: 1024 * 1024, // 1 MB
            max_files: 3,
            compress: false,
        };

        let writer = RotatingJsonFileWriter::new(&log_path, config).unwrap();

        let entry = LogEntry {
            stream: StreamType::Stdout,
            data: Bytes::from("test message\n"),
            timestamp: 1705315800_000000000,
            partial: false,
        };

        writer.write(&entry).await.unwrap();
        writer.flush().await.unwrap();

        let mut content = String::new();
        File::open(&log_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        assert!(content.contains(r#""log":"test message\n""#));
        assert!(content.contains(r#""stream":"stdout""#));
    }

    #[tokio::test]
    async fn test_rotating_json_file_writer_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Use small max_size to trigger rotation quickly.
        let config = LogRotationConfig {
            max_size: 200, // 200 bytes
            max_files: 3,
            compress: false,
        };

        let writer = RotatingJsonFileWriter::new(&log_path, config).unwrap();

        // Write enough entries to trigger rotation.
        for i in 0..10 {
            let entry = LogEntry {
                stream: StreamType::Stdout,
                data: Bytes::from(format!("message number {} with some padding\n", i)),
                timestamp: 1705315800_000000000 + i as i64,
                partial: false,
            };
            writer.write(&entry).await.unwrap();
        }
        writer.flush().await.unwrap();

        // Check that rotation happened.
        let rotated_1 = temp_dir.path().join("test.log.1");
        let rotated_2 = temp_dir.path().join("test.log.2");

        // At least one rotation should have happened.
        assert!(
            rotated_1.exists() || rotated_2.exists(),
            "rotation should have created .1 or .2 files"
        );

        // Original file should still exist.
        assert!(log_path.exists(), "current log file should exist");
    }

    #[test]
    fn test_rotating_json_escape() {
        // Test that RotatingJsonFileWriter uses the same escaping as JsonFileWriter.
        assert_eq!(RotatingJsonFileWriter::escape_json(b"hello"), "hello");
        assert_eq!(RotatingJsonFileWriter::escape_json(b"hello\n"), "hello\\n");
        assert_eq!(
            RotatingJsonFileWriter::escape_json(b"say \"hi\""),
            "say \\\"hi\\\""
        );
    }

    #[test]
    fn test_rotating_timestamp_format() {
        let nanos = 1705315800_123456789i64;
        let formatted = RotatingJsonFileWriter::format_timestamp(nanos);
        assert!(formatted.starts_with("2024-01-15T"));
        assert!(formatted.ends_with("Z"));
        assert!(formatted.contains(".123456789"));
    }
}
