use crate::error::Result;

/// IRQ number type.
pub type Irq = u32;

/// Global System Interrupt number type.
pub type Gsi = u32;

/// Maximum number of IRQs.
pub const MAX_IRQS: u32 = 256;

/// Maximum number of GSIs (typically matches IOAPIC entries + legacy PICs).
pub const MAX_GSIS: u32 = 24;

/// Interrupt trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriggerMode {
    /// Edge-triggered: interrupt is signaled on level transition.
    /// Device asserts then deasserts the IRQ line.
    #[default]
    Edge,
    /// Level-triggered: interrupt remains asserted until acknowledged.
    /// Device keeps line asserted until serviced.
    Level,
}

/// IRQ configuration for a single interrupt line.
#[derive(Debug, Clone)]
pub struct IrqConfig {
    /// The GSI this IRQ is mapped to.
    pub gsi: Gsi,
    /// Trigger mode for this IRQ.
    pub trigger_mode: TriggerMode,
    /// Whether this IRQ is currently asserted (for level-triggered).
    pub asserted: bool,
}

/// Callback type for triggering interrupts on the hypervisor.
///
/// The callback receives (gsi, level) where level is true for assert.
pub type IrqTriggerCallback = Box<dyn Fn(Gsi, bool) -> Result<()> + Send + Sync>;
