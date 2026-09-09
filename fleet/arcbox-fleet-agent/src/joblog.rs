//! Per-job runner logs: one file per job holding that job's stdout and
//! stderr, combined, byte-for-byte.
//!
//! Every backend routes its runner's output here — the host process group,
//! the Docker container, the macOS guest's SSH session, the WSL interop
//! relay — so the local record of a job survives the thing that produced
//! it. That matters exactly when GitHub's own job log is empty: a runner
//! that died before it could ship anything, which is the case the
//! `RunnerExited` liveness hint exists to signal.
//!
//! The files are owner-only under `<data_dir>/log/jobs/`, kept for
//! [`RETENTION`], and each capped at [`MAX_BYTES`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::fsutil;

/// How long a job's log is kept. Age-based rather than counted: a burst of
/// short jobs must not evict the log of the long one that ran alongside them.
const RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);

/// Ceiling on one job's log. Past it the output is dropped (see
/// [`Sink::write`]) — a runaway runner must not fill the disk and take the
/// agent down with it.
const MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Read buffer of [`JobLog::pump`]. Runner output is line-ish and bursty;
/// this is large enough that a chatty build does not syscall per line.
const PUMP_BUF: usize = 16 * 1024;

/// The job-log directory.
///
/// Path math only — [`new`](Self::new) does no I/O, so the `jobs` CLI
/// command can construct one purely to read what is already there.
#[derive(Clone)]
pub struct JobLogs {
    dir: PathBuf,
}

impl JobLogs {
    /// The `jobs/` subdirectory of `log_dir` — a subdirectory so the age
    /// sweep below can never reach the agent's own `fleet-agent.log`.
    pub fn new(log_dir: &Path) -> Self {
        Self {
            dir: log_dir.join("jobs"),
        }
    }

    /// A directory nothing is ever written to, for tests that build a
    /// supervisor but never start a runner. `sweep` treats the missing
    /// directory as the normal pre-first-job case, so nothing here touches
    /// the filesystem.
    #[cfg(test)]
    pub fn nowhere() -> Self {
        Self {
            dir: PathBuf::from("/nonexistent/arcbox-fleet-agent"),
        }
    }

    /// The log file for `job_id`, opened for appending.
    ///
    /// Appending, not truncating: a second open for the same job (a
    /// redelivery after a restart) must not destroy what the first attempt
    /// recorded.
    pub fn open(&self, job_id: &str) -> Result<JobLog> {
        let path = self.path_for(job_id)?;
        fsutil::ensure_owner_only_dir(&self.dir)?;
        let file = fsutil::open_append_owner_only(&path)?;
        let written = file
            .metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .len();
        Ok(JobLog {
            sink: Arc::new(Mutex::new(Sink {
                file: tokio::fs::File::from_std(file),
                written,
                stopped: false,
            })),
            path: path.into(),
        })
    }

    /// Delete every log older than [`RETENTION`]. A missing directory is
    /// the normal case before the first job, not an error.
    pub fn sweep(&self) {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!(dir = %self.dir.display(), error = %e, "cannot read the job log directory");
                return;
            }
        };
        let cutoff = SystemTime::now() - RETENTION;
        for entry in entries.flatten() {
            let path = entry.path();
            let aged_out = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|modified| modified < cutoff);
            if aged_out {
                match std::fs::remove_file(&path) {
                    Ok(()) => debug!(path = %path.display(), "removed an expired job log"),
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "cannot remove an expired job log");
                    }
                }
            }
        }
    }

    /// The path `job_id` maps to, rejecting anything that is not a plain
    /// file name.
    ///
    /// `job_id` is issued by the gateway and validated nowhere else in the
    /// agent — `docker::container_name` and `vm::machine_name` interpolate
    /// it raw — and this is the first place it reaches the filesystem. The
    /// character set admits GitHub's `rjob_…` ids and nothing that could
    /// carry a path separator, a `..`, or an unbounded name.
    fn path_for(&self, job_id: &str) -> Result<PathBuf> {
        let safe = !job_id.is_empty()
            && job_id.len() <= 128
            && job_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
        if !safe {
            bail!("job id {job_id:?} is not a usable log file name");
        }
        Ok(self.dir.join(format!("{job_id}.log")))
    }
}

/// One job's log. Clone-cheap: every clone writes to the same file, so a
/// backend can hand one to its stdout pump and one to its stderr pump and
/// get them interleaved in arrival order.
#[derive(Clone)]
pub struct JobLog {
    sink: Arc<Mutex<Sink>>,
    path: Arc<Path>,
}

impl JobLog {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append `bytes` verbatim. Never fails the caller: a job's output is
    /// not worth failing the job over.
    pub async fn write(&self, bytes: &[u8]) {
        self.sink.lock().await.write(bytes, &self.path).await;
    }

    /// Copy `reader` into the log until EOF.
    ///
    /// Read errors end the pump; write errors do not (see [`Sink::write`]).
    /// The loop always runs to EOF, which is what keeps a runner whose
    /// output is being discarded from wedging on a full pipe.
    pub async fn pump<R: AsyncRead + Unpin>(&self, mut reader: R) {
        let mut buf = vec![0_u8; PUMP_BUF];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => self.write(&buf[..n]).await,
                Err(e) => {
                    debug!(path = %self.path.display(), error = %e, "job log source ended");
                    return;
                }
            }
        }
    }
}

/// The open file plus its byte count. Writes are small and infrequent
/// relative to anything else a job does, so one mutex is the whole
/// concurrency story here.
struct Sink {
    file: tokio::fs::File,
    written: u64,
    /// Set once the cap is hit or a write fails, so neither is reported
    /// more than once and later chunks are dropped without syscalls.
    stopped: bool,
}

impl Sink {
    /// Append `bytes`, or drop them once this sink has stopped.
    ///
    /// Both stop conditions — the cap and a write error — leave the pumps
    /// running and silently discarding. That is deliberate: `interop`'s
    /// relay and every piped child block once their pipe fills, so a pump
    /// that stopped reading would stall the runner itself. Losing tail
    /// output beats hanging a customer's job.
    async fn write(&mut self, bytes: &[u8], path: &Path) {
        if self.stopped {
            return;
        }
        if self.written + bytes.len() as u64 > MAX_BYTES {
            self.stopped = true;
            warn!(path = %path.display(), "job log hit its size cap; discarding further output");
            let notice = format!(
                "\n[arcbox-fleet-agent] log truncated at {} MiB; further output discarded\n",
                MAX_BYTES / (1024 * 1024)
            );
            let _ = self.file.write_all(notice.as_bytes()).await;
            let _ = self.file.flush().await;
            return;
        }
        // Flushed per chunk, not left in `tokio::fs::File`'s buffer: this log
        // exists for the runner that died without reporting anything, so what
        // it wrote has to be on disk before the process that wrote it is gone.
        // A flush here is a `write(2)`, not an fsync.
        let written = async {
            self.file.write_all(bytes).await?;
            self.file.flush().await
        }
        .await;
        if let Err(e) = written {
            self.stopped = true;
            warn!(path = %path.display(), error = %e, "cannot write the job log; discarding further output");
            return;
        }
        self.written += bytes.len() as u64;
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn logs(dir: &Path) -> JobLogs {
        JobLogs::new(dir)
    }

    /// A gateway-issued job id reaches the filesystem here, so anything
    /// that is not a plain file name has to be refused rather than
    /// escaping the directory.
    #[test]
    fn hostile_job_ids_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let logs = logs(dir.path());

        for bad in [
            "",
            "..",
            "../..",
            "../../etc/passwd",
            "/etc/passwd",
            "rjob/../x",
            "rjob abc",
            "rjob.abc",
            &"a".repeat(129),
        ] {
            assert!(logs.open(bad).is_err(), "{bad:?} was accepted");
        }

        assert!(logs.open("rjob_abc-123").is_ok());
    }

    /// Both pumps write into the same file, and the directory and file
    /// carry the owner-only modes job output needs.
    #[tokio::test]
    async fn both_streams_land_in_one_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let logs = logs(dir.path());
        let log = logs.open("rjob_combined").unwrap();

        log.pump(&b"from stdout\n"[..]).await;
        log.clone().pump(&b"from stderr\n"[..]).await;

        let contents = std::fs::read_to_string(log.path()).unwrap();
        assert_eq!(contents, "from stdout\nfrom stderr\n");

        let file_mode = std::fs::metadata(log.path()).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(logs.dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    /// Reopening a job's log appends: a redelivery must not erase what the
    /// first attempt recorded.
    #[tokio::test]
    async fn reopening_appends() {
        let dir = tempfile::tempdir().unwrap();
        let logs = logs(dir.path());

        logs.open("rjob_twice").unwrap().write(b"first\n").await;
        logs.open("rjob_twice").unwrap().write(b"second\n").await;

        let contents = std::fs::read_to_string(logs.dir.join("rjob_twice.log")).unwrap();
        assert_eq!(contents, "first\nsecond\n");
    }

    /// Past the cap the output is dropped with a notice — but the pump
    /// still drains its reader to EOF, because a pump that stopped reading
    /// would block the runner on a full pipe.
    #[tokio::test]
    async fn the_cap_truncates_but_the_pump_still_drains() {
        let dir = tempfile::tempdir().unwrap();
        let logs = logs(dir.path());
        let log = logs.open("rjob_chatty").unwrap();

        // Pre-charge the counter so the test needn't write 256 MiB.
        log.sink.lock().await.written = MAX_BYTES;

        let source = vec![b'@'; PUMP_BUF * 3];
        let mut reader = &source[..];
        log.pump(&mut reader).await;

        assert!(reader.is_empty(), "the pump stopped short of EOF");
        let contents = std::fs::read_to_string(log.path()).unwrap();
        assert!(contents.contains("log truncated at 256 MiB"), "{contents}");
        assert!(!contents.contains('@'), "output past the cap was written");
    }

    #[test]
    fn sweep_drops_aged_logs_and_keeps_fresh_ones() {
        let dir = tempfile::tempdir().unwrap();
        let logs = logs(dir.path());

        // A missing directory is the pre-first-job case, not an error.
        logs.sweep();

        logs.open("rjob_fresh").unwrap();
        logs.open("rjob_aged").unwrap();
        let aged = logs.dir.join("rjob_aged.log");
        let long_ago = SystemTime::now() - RETENTION - Duration::from_secs(3600);
        std::fs::File::open(&aged)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();

        logs.sweep();

        assert!(!aged.exists(), "an expired log survived the sweep");
        assert!(logs.dir.join("rjob_fresh.log").exists());
    }
}
