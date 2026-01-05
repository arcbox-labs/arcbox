//! Interrupt controller management.
//!
//! This module provides the IRQ chip abstraction for managing interrupts.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::Result;

/// IRQ number type.
pub type Irq = u32;

/// Maximum number of IRQs.
pub const MAX_IRQS: u32 = 256;

/// IRQ chip abstraction.
///
/// Manages interrupt routing and delivery.
pub struct IrqChip {
    /// Next available IRQ number.
    next_irq: AtomicU32,
    /// IRQ mask (bit set = masked).
    mask: AtomicU32,
}

impl IrqChip {
    /// Creates a new IRQ chip.
    ///
    /// # Errors
    ///
    /// Returns an error if the IRQ chip cannot be created.
    pub fn new() -> Result<Self> {
        tracing::debug!("Creating IRQ chip");
        Ok(Self {
            next_irq: AtomicU32::new(32), // Start after legacy IRQs
            mask: AtomicU32::new(0),
        })
    }

    /// Allocates an IRQ number.
    ///
    /// # Errors
    ///
    /// Returns an error if no IRQ is available.
    pub fn allocate_irq(&self) -> Result<Irq> {
        let irq = self.next_irq.fetch_add(1, Ordering::SeqCst);
        if irq >= MAX_IRQS {
            return Err(crate::error::VmmError::Irq("IRQ exhausted".to_string()));
        }
        tracing::debug!("Allocated IRQ {}", irq);
        Ok(irq)
    }

    /// Triggers an interrupt.
    ///
    /// # Errors
    ///
    /// Returns an error if the interrupt cannot be delivered.
    pub fn trigger_irq(&self, irq: Irq) -> Result<()> {
        // Check if masked
        if self.is_masked(irq) {
            tracing::trace!("IRQ {} is masked, not triggering", irq);
            return Ok(());
        }

        tracing::trace!("Triggering IRQ {}", irq);
        // TODO: Actually deliver interrupt to vCPU
        Ok(())
    }

    /// Masks an interrupt.
    pub fn mask_irq(&self, irq: Irq) {
        if irq < 32 {
            let old = self.mask.fetch_or(1 << irq, Ordering::SeqCst);
            tracing::trace!("Masked IRQ {}, old mask: {:#x}", irq, old);
        }
    }

    /// Unmasks an interrupt.
    pub fn unmask_irq(&self, irq: Irq) {
        if irq < 32 {
            let old = self.mask.fetch_and(!(1 << irq), Ordering::SeqCst);
            tracing::trace!("Unmasked IRQ {}, old mask: {:#x}", irq, old);
        }
    }

    /// Checks if an IRQ is masked.
    #[must_use]
    pub fn is_masked(&self, irq: Irq) -> bool {
        if irq < 32 {
            (self.mask.load(Ordering::SeqCst) & (1 << irq)) != 0
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irq_allocation() {
        let chip = IrqChip::new().unwrap();

        let irq1 = chip.allocate_irq().unwrap();
        let irq2 = chip.allocate_irq().unwrap();

        assert!(irq2 > irq1);
    }

    #[test]
    fn test_irq_masking() {
        let chip = IrqChip::new().unwrap();

        assert!(!chip.is_masked(0));

        chip.mask_irq(0);
        assert!(chip.is_masked(0));

        chip.unmask_irq(0);
        assert!(!chip.is_masked(0));
    }
}
