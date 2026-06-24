//! Interrupt controller management.
//!
//! This module provides the IRQ chip abstraction for managing interrupts,
//! including GSI mapping, trigger modes, and interrupt coalescing.

mod chip;
mod coalescing;
mod stats;
mod types;

pub use chip::IrqChip;
pub use coalescing::{CoalescingConfig, CoalescingState};
pub use stats::IrqStats;
pub use types::{Gsi, Irq, IrqConfig, IrqTriggerCallback, MAX_GSIS, MAX_IRQS, TriggerMode};
