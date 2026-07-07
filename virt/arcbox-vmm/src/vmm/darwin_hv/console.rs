use std::sync::Arc;

use crate::device::DeviceManager;
use crate::error::{Result, VmmError};

use super::*;

impl Vmm {
    /// Spawns the interactive debug-console RX worker when a debug-console
    /// socket was configured (`VmmConfig::debug_console_socket`). The worker
    /// reads operator keystrokes from the socket and injects them into the
    /// guest console RX queue. No-op when the debug console is disabled.
    ///
    /// Joined in `stop_darwin_hv` before guest memory is released; the worker
    /// polls on a 10 ms tick and observes `running=false` promptly.
    pub(super) fn spawn_console_rx_worker(
        &mut self,
        device_manager: &Arc<DeviceManager>,
    ) -> Result<()> {
        if self.hv_console_worker.is_some() {
            return Ok(());
        }
        let Some(socket) = device_manager.debug_console_socket().cloned() else {
            return Ok(());
        };

        let ctx = crate::console_rx_worker::ConsoleRxWorkerContext {
            device_manager: Arc::clone(device_manager),
            socket,
            running: self.running.clone(),
            exit_vcpus: make_exit_vcpus_fn(
                self.hv_vcpu_ids
                    .clone()
                    .expect("hv_vcpu_ids asserted Some above"),
            ),
        };
        let handle = std::thread::Builder::new()
            .name("console-io".to_string())
            .spawn(move || crate::console_rx_worker::console_rx_worker_loop(ctx))
            .map_err(|e| VmmError::Device(format!("spawn console-io worker: {e}")))?;
        self.hv_console_worker = Some(handle);
        Ok(())
    }
}
