//! Shared logging infrastructure for ArcBox components.
//!
//! Provides a unified tracing initialization with:
//! - Size-based log file rotation (default: 10 MB per file, 5 files max)
//! - JSON format for files (machine-parseable)
//! - Human-readable format for stderr (when running in foreground)
//! - Non-blocking file writes via `tracing-appender`

mod rotating;

use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub use rotating::SizeRotatingWriter;

/// Configuration for log initialization.
pub struct LogConfig {
    /// Directory to write log files into (e.g. `~/.arcbox/log`).
    pub log_dir: PathBuf,
    /// Log file name (e.g. `"daemon.log"`).
    pub file_name: String,
    /// Default `EnvFilter` directive when `RUST_LOG` is unset.
    pub default_filter: String,
    /// Maximum size in bytes before rotating (default: 10 MB).
    pub max_file_size: u64,
    /// Maximum number of rotated files to keep (default: 5).
    pub max_files: usize,
    /// When true, also emit human-readable logs to stderr.
    pub foreground: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("."),
            file_name: "app.log".to_string(),
            default_filter: "info".to_string(),
            max_file_size: 10 * 1024 * 1024,
            max_files: 5,
            foreground: false,
        }
    }
}

/// Guard that keeps the non-blocking writer alive. Must be held for the
/// lifetime of the program — dropping it flushes pending writes.
pub struct LogGuard {
    _file_guard: WorkerGuard,
}

impl LogGuard {
    /// Explicitly drop the guard to flush pending log writes.
    /// Call this during graceful shutdown before process exit.
    pub fn flush(self) {
        // Drop triggers flush in WorkerGuard.
        drop(self);
    }
}

/// Initialize the tracing subscriber with file + optional stderr output.
///
/// Returns a [`LogGuard`] that **must** be held until shutdown. Dropping
/// the guard flushes all pending writes to the log file.
///
/// # Panics
///
/// Panics if the log directory cannot be created.
pub fn init(config: LogConfig) -> LogGuard {
    // Bridge `log` crate → tracing so third-party dependencies emitting via
    // `log` have their output captured by the tracing subscriber.
    std::fs::create_dir_all(&config.log_dir).expect("failed to create log directory");

    let rotating_writer = SizeRotatingWriter::new(
        config.log_dir.join(&config.file_name),
        config.max_file_size,
        config.max_files,
    );

    let (non_blocking, file_guard) = tracing_appender::non_blocking(rotating_writer);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| config.default_filter.into());

    // File layer: JSON format for machine parsing.
    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_writer(non_blocking);

    // Stderr layer: human-readable, only when running in foreground.
    let stderr_layer = config.foreground.then(|| {
        tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_writer(std::io::stderr)
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(stderr_layer)
        .init();

    LogGuard {
        _file_guard: file_guard,
    }
}

/// Initialize tracing with file output + sentry layer.
///
/// Same as [`init`] but adds a `sentry::integrations::tracing::layer()`.
/// Requires sentry to be initialized before calling this.
#[cfg(feature = "sentry")]
pub fn init_with_sentry(config: LogConfig) -> LogGuard {
    std::fs::create_dir_all(&config.log_dir).expect("failed to create log directory");

    let rotating_writer = SizeRotatingWriter::new(
        config.log_dir.join(&config.file_name),
        config.max_file_size,
        config.max_files,
    );

    let (non_blocking, file_guard) = tracing_appender::non_blocking(rotating_writer);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| config.default_filter.into());

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_writer(non_blocking);

    let stderr_layer = config.foreground.then(|| {
        tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_writer(std::io::stderr)
    });

    let sentry_layer = sentry::integrations::tracing::layer();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(stderr_layer)
        .with(sentry_layer)
        .init();

    LogGuard {
        _file_guard: file_guard,
    }
}
