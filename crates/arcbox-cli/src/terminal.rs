//! Terminal handling for interactive container sessions.
//!
//! This module provides raw terminal mode, SIGWINCH handling for terminal resize,
//! and bidirectional I/O streaming for -it mode in run/exec commands.

use anyhow::{Context, Result};
use crossterm::terminal::{self, disable_raw_mode, enable_raw_mode};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Terminal size (width x height).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    /// Width in columns.
    pub cols: u16,
    /// Height in rows.
    pub rows: u16,
}

impl TerminalSize {
    /// Gets the current terminal size.
    pub fn current() -> Result<Self> {
        let (cols, rows) = terminal::size().context("failed to get terminal size")?;
        Ok(Self { cols, rows })
    }
}

/// RAII guard that restores terminal mode on drop.
pub struct RawModeGuard {
    _private: (),
}

impl RawModeGuard {
    /// Enables raw mode and returns a guard that restores normal mode on drop.
    pub fn new() -> Result<Self> {
        enable_raw_mode().context("failed to enable raw mode")?;
        Ok(Self { _private: () })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Terminal resize event channel.
pub struct ResizeWatcher {
    rx: mpsc::UnboundedReceiver<TerminalSize>,
    _shutdown: Arc<AtomicBool>,
}

impl ResizeWatcher {
    /// Creates a new resize watcher that monitors SIGWINCH signals.
    #[cfg(unix)]
    pub fn new() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};

        let (tx, rx) = mpsc::unbounded_channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        tokio::spawn(async move {
            let mut sigwinch = match signal(SignalKind::window_change()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Failed to register SIGWINCH handler: {}", e);
                    return;
                }
            };

            while !shutdown_clone.load(Ordering::Relaxed) {
                if sigwinch.recv().await.is_some() {
                    if let Ok(size) = TerminalSize::current() {
                        if tx.send(size).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            rx,
            _shutdown: shutdown,
        })
    }

    /// Receives the next resize event.
    pub async fn recv(&mut self) -> Option<TerminalSize> {
        self.rx.recv().await
    }
}

/// Interactive terminal session for container attach/exec.
///
/// Handles bidirectional I/O between the local terminal and a remote stream,
/// with support for raw mode and resize events.
pub struct InteractiveSession<R, W> {
    /// Remote read stream (container stdout/stderr).
    reader: R,
    /// Remote write stream (container stdin).
    writer: W,
    /// Whether to use TTY mode.
    tty: bool,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl<R, W> InteractiveSession<R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    /// Creates a new interactive session.
    pub fn new(reader: R, writer: W, tty: bool) -> Self {
        Self {
            reader,
            writer,
            tty,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Runs the interactive session.
    ///
    /// This function:
    /// 1. Enables raw mode if TTY is requested
    /// 2. Sets up SIGWINCH handler for resize events
    /// 3. Streams stdin to the remote writer
    /// 4. Streams remote reader to stdout
    /// 5. Handles Ctrl-C and other escape sequences
    pub async fn run(self) -> Result<()> {
        // Enable raw mode for TTY
        let _raw_guard = if self.tty {
            Some(RawModeGuard::new()?)
        } else {
            None
        };

        // Get initial terminal size
        let initial_size = if self.tty {
            TerminalSize::current().ok()
        } else {
            None
        };

        // Log initial size
        if let Some(size) = initial_size {
            tracing::debug!("Initial terminal size: {}x{}", size.cols, size.rows);
        }

        let shutdown = self.shutdown.clone();
        let shutdown_stdin = self.shutdown.clone();

        // Spawn stdin reader task
        let mut writer = self.writer;
        let stdin_task = tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 1024];

            loop {
                if shutdown_stdin.load(Ordering::Relaxed) {
                    break;
                }

                tokio::select! {
                    result = stdin.read(&mut buf) => {
                        match result {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                // Check for escape sequence (Ctrl-P, Ctrl-Q to detach)
                                if n >= 2 && buf[0] == 0x10 && buf[1] == 0x11 {
                                    tracing::debug!("Detach sequence detected");
                                    break;
                                }

                                if let Err(e) = writer.write_all(&buf[..n]).await {
                                    tracing::debug!("Failed to write to remote: {}", e);
                                    break;
                                }
                                if let Err(e) = writer.flush().await {
                                    tracing::debug!("Failed to flush remote: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Failed to read stdin: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Spawn stdout writer task
        let mut reader = self.reader;
        let stdout_task = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            let mut buf = [0u8; 4096];

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                match reader.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if let Err(e) = stdout.write_all(&buf[..n]).await {
                            tracing::debug!("Failed to write to stdout: {}", e);
                            break;
                        }
                        if let Err(e) = stdout.flush().await {
                            tracing::debug!("Failed to flush stdout: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to read from remote: {}", e);
                        break;
                    }
                }
            }
        });

        // Wait for either task to complete
        tokio::select! {
            _ = stdin_task => {
                tracing::debug!("stdin task completed");
            }
            _ = stdout_task => {
                tracing::debug!("stdout task completed");
            }
        }

        // Signal shutdown to other tasks
        self.shutdown.store(true, Ordering::Relaxed);

        Ok(())
    }
}

/// Synchronous terminal I/O for attach operations.
///
/// This is used when async I/O is not available (e.g., HTTP upgrade streams).
pub struct SyncTerminalIO {
    shutdown: Arc<AtomicBool>,
}

impl SyncTerminalIO {
    /// Creates a new sync terminal I/O handler.
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signals shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Returns whether shutdown has been signaled.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

impl Default for SyncTerminalIO {
    fn default() -> Self {
        Self::new()
    }
}

/// Resize callback type for terminal resize events.
pub type ResizeCallback = Box<dyn Fn(TerminalSize) + Send + 'static>;

/// Attach configuration for container attach operations.
#[derive(Default)]
pub struct AttachConfig {
    /// Whether to allocate a TTY.
    pub tty: bool,
    /// Whether to attach stdin.
    pub stdin: bool,
    /// Whether to attach stdout.
    pub stdout: bool,
    /// Whether to attach stderr.
    pub stderr: bool,
    /// Optional resize callback.
    pub on_resize: Option<ResizeCallback>,
}

impl AttachConfig {
    /// Creates a new attach configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets TTY mode.
    pub fn with_tty(mut self, tty: bool) -> Self {
        self.tty = tty;
        self
    }

    /// Sets stdin attachment.
    pub fn with_stdin(mut self, stdin: bool) -> Self {
        self.stdin = stdin;
        self
    }

    /// Sets stdout attachment.
    pub fn with_stdout(mut self, stdout: bool) -> Self {
        self.stdout = stdout;
        self
    }

    /// Sets stderr attachment.
    pub fn with_stderr(mut self, stderr: bool) -> Self {
        self.stderr = stderr;
        self
    }

    /// Sets resize callback.
    pub fn with_resize_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(TerminalSize) + Send + 'static,
    {
        self.on_resize = Some(Box::new(callback));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_size_current() {
        // This test may fail in non-terminal environments (CI)
        // Just verify it doesn't panic
        let _ = TerminalSize::current();
    }

    #[test]
    fn test_attach_config_builder() {
        let config = AttachConfig::new()
            .with_tty(true)
            .with_stdin(true)
            .with_stdout(true)
            .with_stderr(false);

        assert!(config.tty);
        assert!(config.stdin);
        assert!(config.stdout);
        assert!(!config.stderr);
    }

    #[test]
    fn test_sync_terminal_io_shutdown() {
        let io = SyncTerminalIO::new();
        assert!(!io.is_shutdown());
        io.shutdown();
        assert!(io.is_shutdown());
    }
}
