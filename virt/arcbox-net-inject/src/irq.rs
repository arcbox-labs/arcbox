//! IRQ handle for interrupt injection.

use std::sync::Arc;

/// Error type returned by the GIC SPI callback.
pub type IrqError = Box<dyn std::error::Error + Send + Sync>;

/// Thread-safe GIC SPI callback: `(irq_number, level) -> Result<()>`.
pub type IrqCallback = dyn Fn(u32, bool) -> Result<(), IrqError> + Send + Sync;

/// Encapsulates the interrupt delivery mechanism.
///
/// Holds the GIC SPI callback and the vCPU force-exit function,
/// both thread-safe.
pub struct IrqHandle {
    /// Fires the GIC SPI for the virtio-net device.
    pub callback: Arc<IrqCallback>,
    /// Force-exits all vCPUs from hv_vcpu_run.
    pub exit_vcpus: Arc<dyn Fn() + Send + Sync>,
    /// IRQ number (GIC SPI) for the primary VirtioNet device.
    pub irq: u32,
}

impl IrqHandle {
    /// Fires the interrupt: set MMIO interrupt_status + GIC SPI + exit vCPUs.
    pub fn trigger(&self) {
        let _ = (self.callback)(self.irq, true);
        (self.exit_vcpus)();
    }
}
