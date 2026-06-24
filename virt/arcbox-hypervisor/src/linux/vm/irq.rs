use std::os::unix::io::RawFd;

use crate::error::HypervisorError;

use super::KvmVm;

impl KvmVm {
    /// Sets the IRQ line level on the in-kernel irqchip.
    ///
    /// For edge-triggered interrupts, call with level=true then level=false.
    /// For level-triggered interrupts, keep level=true until acknowledged.
    ///
    /// # Arguments
    /// * `gsi` - Global System Interrupt number
    /// * `level` - true to assert, false to deassert
    pub fn set_irq_line(&self, gsi: u32, level: bool) -> Result<(), HypervisorError> {
        self.vm_fd
            .set_irq_line(gsi, level)
            .map_err(|e| HypervisorError::DeviceError(format!("Failed to set IRQ line: {}", e)))
    }

    /// Triggers an edge-triggered interrupt.
    ///
    /// Convenience method that asserts then immediately deasserts the IRQ line.
    pub fn trigger_edge_irq(&self, gsi: u32) -> Result<(), HypervisorError> {
        self.set_irq_line(gsi, true)?;
        self.set_irq_line(gsi, false)
    }

    /// Registers an eventfd for IRQ injection (IRQFD).
    ///
    /// When the eventfd is signaled (write 1 to it), KVM will automatically
    /// inject the specified GSI into the guest. This is the most efficient
    /// method for interrupt delivery.
    ///
    /// # Arguments
    /// * `eventfd` - The eventfd file descriptor
    /// * `gsi` - The GSI to inject when eventfd is signaled
    /// * `resample_fd` - For level-triggered IRQs, optional resample eventfd
    pub fn register_irqfd(
        &self,
        eventfd: RawFd,
        gsi: u32,
        resample_fd: Option<RawFd>,
    ) -> Result<(), HypervisorError> {
        self.vm_fd
            .register_irqfd(eventfd, gsi, resample_fd)
            .map_err(|e| HypervisorError::DeviceError(format!("Failed to register IRQFD: {}", e)))
    }

    /// Unregisters an eventfd for IRQ injection.
    pub fn unregister_irqfd(&self, eventfd: RawFd, gsi: u32) -> Result<(), HypervisorError> {
        self.vm_fd
            .unregister_irqfd(eventfd, gsi)
            .map_err(|e| HypervisorError::DeviceError(format!("Failed to unregister IRQFD: {}", e)))
    }
}
