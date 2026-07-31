//! Replace the current process image, preserving argv.
//!
//! The agent restarts itself in place rather than asking a service manager
//! to do it: `execv` keeps the PID, so a launchd job's bookkeeping (and its
//! `KeepAlive` policy) is undisturbed, and the same mechanism works for a
//! foreground run with no service manager at all. Both self-update
//! ([`crate::update`], exec'ing the swapped managed binary) and the
//! operator `Restart` (exec'ing the running executable) go through here.
//!
//! Note that `exec` runs no destructors: anything that must be flushed —
//! notably the logging guard — has to be dropped before calling this. The
//! operator restart honors that (`main` drops the runtime, then the guard);
//! self-update cannot, because it execs from inside the attach task, and so
//! loses whatever the non-blocking log writer had buffered. Pre-existing, and
//! fixable only by plumbing the update payload out to `main`.

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
