use std::sync::atomic::AtomicU64;

/// Statistics for interrupt coalescing.
#[derive(Debug, Default)]
pub struct IrqStats {
    /// Total interrupts triggered.
    pub triggered: AtomicU64,
    /// Interrupts coalesced (not delivered because pending).
    pub coalesced: AtomicU64,
}
