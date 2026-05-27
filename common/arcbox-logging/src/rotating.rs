//! Size-based log file rotation.
//!
//! Rotates `daemon.log` → `daemon.log.1` → `daemon.log.2` → … when the
//! current file exceeds `max_file_size`. Oldest files beyond `max_files`
//! are deleted.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

/// A `Write` implementation that rotates the underlying file when it
/// exceeds `max_size` bytes. Thread-safe via internal mutex.
pub struct SizeRotatingWriter {
    inner: Mutex<RotatingState>,
}

struct RotatingState {
    path: PathBuf,
    max_size: u64,
    max_files: usize,
    file: File,
    current_size: u64,
}

impl SizeRotatingWriter {
    /// Create a new rotating writer.
    ///
    /// Opens (or creates) the file at `path` in append mode. The file is
    /// rotated when it exceeds `max_size` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `max_size` is 0 or `max_files` is 0.
    pub fn new(path: PathBuf, max_size: u64, max_files: usize) -> Self {
        assert!(max_size > 0, "max_size must be > 0");
        assert!(max_files > 0, "max_files must be > 0");

        let (file, current_size) = open_log_file(&path);
        Self {
            inner: Mutex::new(RotatingState {
                path,
                max_size,
                max_files,
                file,
                current_size,
            }),
        }
    }
}

impl Write for SizeRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.inner.lock();
        write_and_maybe_rotate(&mut state, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.inner.lock();
        state.file.flush()
    }
}

/// `tracing_appender::non_blocking` calls `Write` through a `&` reference,
/// so we need this impl for the non-blocking wrapper to work.
impl Write for &SizeRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.inner.lock();
        write_and_maybe_rotate(&mut state, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.inner.lock();
        state.file.flush()
    }
}

fn write_and_maybe_rotate(state: &mut RotatingState, buf: &[u8]) -> io::Result<usize> {
    // Check if rotation is needed before writing.
    if state.current_size > 0 && state.current_size + buf.len() as u64 > state.max_size {
        rotate(state);
    }

    let written = state.file.write(buf)?;
    state.current_size += written as u64;
    Ok(written)
}

/// Rotate files: app.log → app.log.1 → app.log.2 → …
/// Delete app.log.{max_files} if it exists.
fn rotate(state: &mut RotatingState) {
    // Flush current file before rotation.
    let _ = state.file.flush();

    // Delete the oldest rotated file first, then shift the rest up.
    let oldest = rotated_path(&state.path, state.max_files);
    if let Err(e) = fs::remove_file(&oldest) {
        if e.kind() != io::ErrorKind::NotFound {
            eprintln!("log rotate: failed to remove {}: {e}", oldest.display());
        }
    }

    // Shift existing rotated files: .{n-1} → .{n}, ..., .1 → .2
    for i in (1..state.max_files).rev() {
        let from = rotated_path(&state.path, i);
        let to = rotated_path(&state.path, i + 1);
        if let Err(e) = fs::rename(&from, &to) {
            if e.kind() != io::ErrorKind::NotFound {
                eprintln!(
                    "log rotate: failed to rename {} → {}: {e}",
                    from.display(),
                    to.display()
                );
            }
        }
    }

    // Move current log to .1
    let rotated = rotated_path(&state.path, 1);
    if let Err(e) = fs::rename(&state.path, &rotated) {
        eprintln!(
            "log rotate: failed to rename {} → {}: {e}",
            state.path.display(),
            rotated.display()
        );
        // Rotation failed — continue writing to the same file.
        return;
    }

    // Open a fresh file.
    let (file, size) = open_log_file(&state.path);
    state.file = file;
    state.current_size = size;
}

fn rotated_path(base: &Path, index: usize) -> PathBuf {
    let mut p = base.as_os_str().to_os_string();
    p.push(format!(".{index}"));
    PathBuf::from(p)
}

fn open_log_file(path: &Path) -> (File, u64) {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|e| panic!("failed to open log file {}: {e}", path.display()));

    let size = file.metadata().map_or(0, |m| m.len());
    (file, size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rotation_creates_numbered_files() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        // 100 bytes max, 3 files max.
        let mut writer = SizeRotatingWriter::new(log_path.clone(), 100, 3);

        // Write 120 bytes → should stay in test.log (rotation happens before next write).
        let data = vec![b'A'; 60];
        writer.write_all(&data).unwrap();
        writer.write_all(&data).unwrap();
        assert!(log_path.exists());

        // Write more → triggers rotation.
        writer.write_all(&data).unwrap();
        assert!(log_path.exists());
        assert!(dir.path().join("test.log.1").exists());
    }

    #[test]
    fn oldest_file_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        // max_files=3: keep .1, .2, .3 — never .4
        let mut writer = SizeRotatingWriter::new(log_path.clone(), 50, 3);

        let data = vec![b'X'; 60];

        // Trigger enough rotations to overflow max_files.
        for _ in 0..6 {
            writer.write_all(&data).unwrap();
        }

        assert!(log_path.exists());
        assert!(dir.path().join("test.log.1").exists());
        assert!(dir.path().join("test.log.2").exists());
        assert!(dir.path().join("test.log.3").exists());
        // .4 should not exist (max_files=3).
        assert!(!dir.path().join("test.log.4").exists());
    }
}
