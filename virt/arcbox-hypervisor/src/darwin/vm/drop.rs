use crate::traits::VirtualMachine;

use super::DarwinVm;

impl Drop for DarwinVm {
    fn drop(&mut self) {
        // Stop VM if running, unless the caller has already handled shutdown
        // and set skip_stop_on_drop to avoid crashing the VF stop path.
        if self.is_running() && !self.skip_stop_on_drop {
            let _ = self.stop();
        }

        // Close serial FDs for both console ports.
        for fds in [self.console_fds.take(), self.agent_log_fds.take()]
            .into_iter()
            .flatten()
        {
            // SAFETY: These are valid pipe fds from setup_serial_console().
            unsafe {
                libc::close(fds.0);
                if fds.1 != fds.0 {
                    libc::close(fds.1);
                }
            }
        }

        // VZ handles and dispatch queue are automatically released by arcbox-vz's drop

        tracing::debug!("Dropped VM {}", self.id);
    }
}
