//! Guest shutdown sequence.
//!
//! When the host requests a graceful shutdown over vsock, the agent calls
//! [`poweroff`]. How the VM is powered off depends on whether the agent is PID 1:
//!
//! - Under **busybox init** (the normal boot path) the agent is a supervised
//!   child, so it asks PID 1 to power off (`SIGUSR2`); busybox init then stops all
//!   children, syncs, and halts the VM. A direct `reboot(POWER_OFF)` is the
//!   fallback if PID 1 does not power off in time.
//! - In **legacy standalone** boot (the agent is run directly as PID 1, e.g. the
//!   e2e harness) the agent drives shutdown itself: terminate every process, sync,
//!   and `reboot(LINUX_REBOOT_CMD_POWER_OFF)` (PSCI SYSTEM_OFF on ARM64).

use std::time::Duration;

/// How to power the VM off, selected by whether the agent is PID 1.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownStrategy {
    /// The agent is PID 1 (legacy standalone boot): drive the whole shutdown
    /// here — terminate all processes, sync, and `reboot(POWER_OFF)`.
    DirectReboot,
    /// busybox init is PID 1: ask it to power off (`SIGUSR2`) so it stops children
    /// gracefully and syncs, falling back to a direct reboot if it does not.
    SignalInit,
}

/// Chooses the [`ShutdownStrategy`] from the agent's PID.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const fn shutdown_strategy(pid: u32) -> ShutdownStrategy {
    if pid == 1 {
        ShutdownStrategy::DirectReboot
    } else {
        ShutdownStrategy::SignalInit
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{ShutdownStrategy, shutdown_strategy};
    use std::time::{Duration, Instant};

    /// Powers off the VM, dispatching on [`ShutdownStrategy`].
    ///
    /// This function does not return on success.
    pub fn poweroff(grace: Duration) {
        match shutdown_strategy(std::process::id()) {
            ShutdownStrategy::DirectReboot => direct_reboot(grace),
            ShutdownStrategy::SignalInit => signal_init_then_reboot(grace),
        }
    }

    /// Asks busybox init (PID 1) to power off, then forces it if it doesn't.
    fn signal_init_then_reboot(grace: Duration) {
        tracing::info!("Shutdown: requesting orderly poweroff from busybox init (PID 1)");

        // SAFETY: kill(1, SIGUSR2) asks busybox init to run its poweroff sequence
        // (stop all children, sync, power off). No memory-safety preconditions.
        unsafe { libc::kill(1, libc::SIGUSR2) };

        // busybox init SIGTERMs this process as part of that sequence, so we
        // normally never wake from this sleep.
        std::thread::sleep(grace);

        // PID 1 did not power the VM off in time — force it. The agent holds
        // CAP_SYS_BOOT regardless of PID, so reboot() still works.
        tracing::warn!("Shutdown: busybox init did not power off in time; forcing poweroff");

        // SAFETY: sync() flushes all filesystem buffers. No preconditions.
        unsafe { libc::sync() };

        // SAFETY: CAP_SYS_BOOT is held; LINUX_REBOOT_CMD_POWER_OFF triggers PSCI
        // SYSTEM_OFF on ARM64, halting the VM.
        unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };

        tracing::error!("Shutdown: reboot(POWER_OFF) returned unexpectedly, forcing exit");
        // SAFETY: _exit terminates the process immediately.
        unsafe { libc::_exit(1) };
    }

    /// Drives the full shutdown from PID 1: SIGTERM, SIGKILL, sync, reboot.
    fn direct_reboot(grace: Duration) {
        tracing::info!("Shutdown: sending SIGTERM to all processes");

        // SAFETY: kill(-1, SIGTERM) sends SIGTERM to every process except PID 1.
        // The agent is PID 1 so it is not affected.
        unsafe { libc::kill(-1, libc::SIGTERM) };

        wait_for_children(grace);

        tracing::info!("Shutdown: sending SIGKILL to remaining processes");

        // SAFETY: kill(-1, SIGKILL) sends SIGKILL to every process except PID 1.
        unsafe { libc::kill(-1, libc::SIGKILL) };

        // Brief reap pass for SIGKILL'd processes.
        wait_for_children(Duration::from_millis(500));

        tracing::info!("Shutdown: syncing filesystems");

        // SAFETY: sync() flushes all filesystem buffers. No preconditions.
        unsafe { libc::sync() };

        tracing::info!("Shutdown: powering off");

        // SAFETY: Called as PID 1 with CAP_SYS_BOOT. LINUX_REBOOT_CMD_POWER_OFF
        // triggers PSCI SYSTEM_OFF on ARM64, halting the VM.
        unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };

        // Should not reach here — reboot does not return on success.
        // Terminate PID 1 so the kernel doesn't continue running a
        // half-shutdown guest with all processes already killed.
        tracing::error!("Shutdown: reboot(POWER_OFF) returned unexpectedly, forcing exit");
        // SAFETY: _exit terminates the process immediately. All other
        // processes are already dead (SIGKILL'd above).
        unsafe { libc::_exit(1) };
    }

    /// Reaps children via `waitpid(-1, WNOHANG)` until none remain or
    /// `timeout` elapses.
    fn wait_for_children(timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return;
            }
            let mut status: i32 = 0;
            // SAFETY: waitpid(-1, ..., WNOHANG) is safe to call from PID 1.
            // It returns 0 when no children have exited, -1/ECHILD when none remain.
            let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
            if pid <= 0 {
                if pid == -1 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ECHILD) {
                        tracing::debug!("Shutdown: no more children");
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use platform::poweroff;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code, reason = "stub for non-Linux development builds")]
pub fn poweroff(_grace: Duration) {
    tracing::warn!("poweroff not supported on this platform");
}

#[cfg(test)]
mod tests {
    use super::{ShutdownStrategy, shutdown_strategy};

    #[test]
    fn pid1_drives_shutdown_directly() {
        assert_eq!(shutdown_strategy(1), ShutdownStrategy::DirectReboot);
    }

    #[test]
    fn non_pid1_delegates_to_busybox_init() {
        // Any non-1 PID means the agent is a supervised child of busybox init.
        assert_eq!(shutdown_strategy(2), ShutdownStrategy::SignalInit);
        assert_eq!(shutdown_strategy(1234), ShutdownStrategy::SignalInit);
    }
}
