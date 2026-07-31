//! Replace the current process image, preserving argv.
//!
//! The agent restarts itself in place rather than asking a service manager
//! to do it: `execv` keeps the PID, so a launchd job's bookkeeping (and its
//! `KeepAlive` policy) is undisturbed, and the same mechanism works for a
//! foreground run with no service manager at all. Both self-update
//! ([`crate::update`], exec'ing the swapped managed binary) and the
//! operator `Restart` (exec'ing the running executable) go through here.
//!
//! `exec` runs no destructors, so anything that must be flushed has to be
//! dropped first — which is why [`crate::main`] is the only caller. Both
//! triggers name their image on the [`crate::handover::Handover`]
//! ([`Outcome::Exec`](crate::handover::Outcome::Exec)) and let the normal
//! teardown run; `main` then drops the tokio runtime, drops the logging guard
//! that flushes the non-blocking writer, and only then replaces the image.
//! Exec'ing from inside a task instead — as self-update used to — skips the
//! runner teardown, leaves the control socket bound, and loses whatever the
//! log writer had buffered.

use std::path::Path;

/// Replace this process image with `binary`, passing this process's own
/// arguments and environment. Returns only the exec error; on success there
/// is no caller left to return to.
pub fn exec(binary: &Path) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let error = std::process::Command::new(binary)
        .args(std::env::args_os().skip(1))
        .exec();
    anyhow::Error::new(error).context(format!("exec {}", binary.display()))
}
