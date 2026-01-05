//! vCPU management.
//!
//! This module manages the lifecycle of virtual CPUs, including thread
//! management and execution coordination.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};

use tokio::sync::mpsc;

use crate::device::DeviceManager;
use crate::error::{Result, VmmError};

use arcbox_hypervisor::{Vcpu, VcpuExit};

/// Handler for vCPU exits that require VMM interaction.
pub trait ExitHandler: Send + Sync {
    /// Handles MMIO read from guest.
    fn handle_mmio_read(&self, addr: u64, size: usize) -> u64;

    /// Handles MMIO write from guest.
    fn handle_mmio_write(&self, addr: u64, size: usize, data: u64);

    /// Handles I/O port read from guest (x86 only).
    fn handle_io_read(&self, port: u16, size: usize) -> u64;

    /// Handles I/O port write from guest (x86 only).
    fn handle_io_write(&self, port: u16, size: usize, data: u64);
}

/// Default exit handler that forwards to DeviceManager.
pub struct DeviceManagerExitHandler {
    device_manager: Arc<RwLock<DeviceManager>>,
}

impl DeviceManagerExitHandler {
    /// Creates a new exit handler wrapping a DeviceManager.
    #[must_use]
    pub fn new(device_manager: Arc<RwLock<DeviceManager>>) -> Self {
        Self { device_manager }
    }
}

impl ExitHandler for DeviceManagerExitHandler {
    fn handle_mmio_read(&self, addr: u64, size: usize) -> u64 {
        match self.device_manager.read() {
            Ok(dm) => match dm.handle_mmio_read(addr, size) {
                Ok(value) => value,
                Err(e) => {
                    tracing::warn!("MMIO read error at {:#x}: {}", addr, e);
                    0
                }
            },
            Err(e) => {
                tracing::error!("Failed to lock device manager: {}", e);
                0
            }
        }
    }

    fn handle_mmio_write(&self, addr: u64, size: usize, data: u64) {
        match self.device_manager.read() {
            Ok(dm) => {
                if let Err(e) = dm.handle_mmio_write(addr, size, data) {
                    tracing::warn!("MMIO write error at {:#x}: {}", addr, e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to lock device manager: {}", e);
            }
        }
    }

    fn handle_io_read(&self, port: u16, size: usize) -> u64 {
        // I/O ports are typically x86-specific
        // Common ports: 0x3F8 (COM1), 0x60/0x64 (keyboard), etc.
        tracing::trace!("I/O read: port={:#x}, size={}", port, size);
        0xFF // Return all 1s for unhandled ports
    }

    fn handle_io_write(&self, port: u16, size: usize, data: u64) {
        // Handle common I/O ports
        tracing::trace!("I/O write: port={:#x}, size={}, data={:#x}", port, size, data);
    }
}

/// vCPU command sent to vCPU threads.
#[derive(Debug)]
pub enum VcpuCommand {
    /// Run the vCPU.
    Run,
    /// Pause the vCPU.
    Pause,
    /// Resume the vCPU.
    Resume,
    /// Stop the vCPU and exit thread.
    Stop,
}

/// vCPU response sent from vCPU threads.
#[derive(Debug)]
pub enum VcpuResponse {
    /// vCPU started running.
    Started,
    /// vCPU paused.
    Paused,
    /// vCPU resumed.
    Resumed,
    /// vCPU stopped.
    Stopped,
    /// vCPU exited with reason.
    Exited(VcpuExit),
    /// Error occurred.
    Error(String),
}

/// Manages vCPU threads.
///
/// The vCPU manager creates and coordinates multiple vCPU threads,
/// handling their lifecycle and event communication.
pub struct VcpuManager {
    /// Number of vCPUs.
    vcpu_count: u32,
    /// vCPU handles.
    handles: Vec<VcpuHandle>,
    /// Whether vCPUs are running.
    running: Arc<AtomicBool>,
    /// Exit handler for device I/O.
    exit_handler: Option<Arc<dyn ExitHandler>>,
}

/// Handle to a single vCPU thread.
struct VcpuHandle {
    /// vCPU ID.
    id: u32,
    /// Command sender.
    cmd_tx: mpsc::UnboundedSender<VcpuCommand>,
    /// Thread handle.
    thread: Option<JoinHandle<()>>,
}

impl VcpuManager {
    /// Creates a new vCPU manager.
    #[must_use]
    pub fn new(vcpu_count: u32) -> Self {
        Self {
            vcpu_count,
            handles: Vec::with_capacity(vcpu_count as usize),
            running: Arc::new(AtomicBool::new(false)),
            exit_handler: None,
        }
    }

    /// Sets the exit handler for device I/O.
    pub fn set_exit_handler<H: ExitHandler + 'static>(&mut self, handler: H) {
        self.exit_handler = Some(Arc::new(handler));
    }

    /// Sets the exit handler from an Arc.
    pub fn set_exit_handler_arc(&mut self, handler: Arc<dyn ExitHandler>) {
        self.exit_handler = Some(handler);
    }

    /// Returns the number of vCPUs.
    #[must_use]
    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    /// Returns whether vCPUs are running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Adds a vCPU to the manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the vCPU cannot be added.
    pub fn add_vcpu<V: Vcpu + 'static>(&mut self, vcpu: V) -> Result<()> {
        let id = vcpu.id();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let running = Arc::clone(&self.running);
        let exit_handler = self.exit_handler.clone();

        // Create vCPU thread (but don't start yet)
        let thread = thread::Builder::new()
            .name(format!("vcpu-{}", id))
            .spawn(move || {
                Self::vcpu_thread(id, vcpu, cmd_rx, running, exit_handler);
            })
            .map_err(|e| VmmError::Vcpu(format!("failed to spawn vCPU thread: {}", e)))?;

        self.handles.push(VcpuHandle {
            id,
            cmd_tx,
            thread: Some(thread),
        });

        tracing::debug!("Added vCPU {}", id);
        Ok(())
    }

    /// The main vCPU thread function.
    fn vcpu_thread<V: Vcpu>(
        id: u32,
        mut vcpu: V,
        mut cmd_rx: mpsc::UnboundedReceiver<VcpuCommand>,
        running: Arc<AtomicBool>,
        exit_handler: Option<Arc<dyn ExitHandler>>,
    ) {
        tracing::debug!("vCPU {} thread started", id);

        let mut paused = true;

        loop {
            // Check for commands (non-blocking if running)
            let cmd = if paused {
                // Block until we get a command
                cmd_rx.blocking_recv()
            } else {
                // Non-blocking check
                cmd_rx.try_recv().ok()
            };

            if let Some(cmd) = cmd {
                match cmd {
                    VcpuCommand::Run => {
                        tracing::debug!("vCPU {} starting", id);
                        paused = false;
                    }
                    VcpuCommand::Pause => {
                        tracing::debug!("vCPU {} pausing", id);
                        paused = true;
                    }
                    VcpuCommand::Resume => {
                        tracing::debug!("vCPU {} resuming", id);
                        paused = false;
                    }
                    VcpuCommand::Stop => {
                        tracing::debug!("vCPU {} stopping", id);
                        break;
                    }
                }
            }

            // Execute vCPU if not paused
            if !paused && running.load(Ordering::SeqCst) {
                match vcpu.run() {
                    Ok(exit) => {
                        // Handle exit
                        match exit {
                            VcpuExit::Halt | VcpuExit::Shutdown => {
                                tracing::info!("vCPU {} halted", id);
                                break;
                            }
                            VcpuExit::IoOut { port, size, data } => {
                                if let Some(ref handler) = exit_handler {
                                    handler.handle_io_write(port, size.into(), data);
                                } else {
                                    tracing::trace!(
                                        "vCPU {} I/O out: port={:#x}, size={}, data={:#x}",
                                        id, port, size, data
                                    );
                                }
                            }
                            VcpuExit::IoIn { port, size } => {
                                let value = if let Some(ref handler) = exit_handler {
                                    handler.handle_io_read(port, size.into())
                                } else {
                                    tracing::trace!(
                                        "vCPU {} I/O in: port={:#x}, size={}",
                                        id, port, size
                                    );
                                    0xFF
                                };
                                // Inject the read result back to the vCPU
                                if let Err(e) = vcpu.set_io_result(value) {
                                    tracing::warn!("Failed to set I/O result: {}", e);
                                }
                            }
                            VcpuExit::MmioRead { addr, size } => {
                                let value = if let Some(ref handler) = exit_handler {
                                    handler.handle_mmio_read(addr, size.into())
                                } else {
                                    tracing::trace!(
                                        "vCPU {} MMIO read: addr={:#x}, size={}",
                                        id, addr, size
                                    );
                                    0
                                };
                                // Inject the read result back to the vCPU
                                if let Err(e) = vcpu.set_mmio_result(value) {
                                    tracing::warn!("Failed to set MMIO result: {}", e);
                                }
                            }
                            VcpuExit::MmioWrite { addr, size, data } => {
                                if let Some(ref handler) = exit_handler {
                                    handler.handle_mmio_write(addr, size.into(), data);
                                } else {
                                    tracing::trace!(
                                        "vCPU {} MMIO write: addr={:#x}, size={}, data={:#x}",
                                        id, addr, size, data
                                    );
                                }
                            }
                            _ => {
                                tracing::debug!("vCPU {} exit: {:?}", id, exit);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("vCPU {} error: {}", id, e);
                        break;
                    }
                }
            }
        }

        tracing::debug!("vCPU {} thread exited", id);
    }

    /// Starts all vCPUs.
    ///
    /// # Errors
    ///
    /// Returns an error if vCPUs cannot be started.
    pub fn start(&mut self) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        for handle in &self.handles {
            handle.cmd_tx.send(VcpuCommand::Run).map_err(|e| {
                VmmError::Vcpu(format!("failed to send Run command: {}", e))
            })?;
        }

        tracing::info!("Started {} vCPUs", self.vcpu_count);
        Ok(())
    }

    /// Pauses all vCPUs.
    ///
    /// # Errors
    ///
    /// Returns an error if vCPUs cannot be paused.
    pub fn pause(&mut self) -> Result<()> {
        for handle in &self.handles {
            handle.cmd_tx.send(VcpuCommand::Pause).map_err(|e| {
                VmmError::Vcpu(format!("failed to send Pause command: {}", e))
            })?;
        }

        tracing::info!("Paused {} vCPUs", self.vcpu_count);
        Ok(())
    }

    /// Resumes all vCPUs.
    ///
    /// # Errors
    ///
    /// Returns an error if vCPUs cannot be resumed.
    pub fn resume(&mut self) -> Result<()> {
        for handle in &self.handles {
            handle.cmd_tx.send(VcpuCommand::Resume).map_err(|e| {
                VmmError::Vcpu(format!("failed to send Resume command: {}", e))
            })?;
        }

        tracing::info!("Resumed {} vCPUs", self.vcpu_count);
        Ok(())
    }

    /// Stops all vCPUs.
    ///
    /// # Errors
    ///
    /// Returns an error if vCPUs cannot be stopped.
    pub fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);

        // Send stop commands
        for handle in &self.handles {
            let _ = handle.cmd_tx.send(VcpuCommand::Stop);
        }

        // Wait for threads to exit
        for handle in &mut self.handles {
            if let Some(thread) = handle.thread.take() {
                let _ = thread.join();
            }
        }

        tracing::info!("Stopped {} vCPUs", self.vcpu_count);
        Ok(())
    }
}

impl Drop for VcpuManager {
    fn drop(&mut self) {
        if self.is_running() {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vcpu_manager_creation() {
        let manager = VcpuManager::new(4);
        assert_eq!(manager.vcpu_count(), 4);
        assert!(!manager.is_running());
    }
}
