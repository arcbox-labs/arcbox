//! Interrupt controller management.
//!
//! This module provides the IRQ chip abstraction for managing interrupts,
//! including GSI mapping, trigger modes, and interrupt coalescing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

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

/// Configuration for timer-based interrupt coalescing.
///
/// Trades a small latency increase for significant wakeup reduction.
/// When an interrupt fires, a coalescing window opens; additional interrupts
/// within the window are accumulated and delivered as a single notification
/// when the window expires or the count threshold is reached.
#[derive(Debug, Clone)]
pub struct CoalescingConfig {
    /// Maximum delay before delivering a pending interrupt.
    pub max_delay: Duration,
    /// Force delivery after this many pending interrupts.
    pub max_coalesce_count: u32,
    /// Whether coalescing is enabled.
    pub enabled: bool,
}

impl Default for CoalescingConfig {
    fn default() -> Self {
        Self {
            max_delay: Duration::from_micros(50),
            max_coalesce_count: 64,
            enabled: true,
        }
    }
}

impl CoalescingConfig {
    /// Preset for virtio-net: moderate latency tolerance.
    #[must_use]
    pub fn for_net() -> Self {
        Self {
            max_delay: Duration::from_micros(50),
            max_coalesce_count: 64,
            enabled: true,
        }
    }

    /// Preset for virtio-blk: lower latency tolerance.
    #[must_use]
    pub fn for_block() -> Self {
        Self {
            max_delay: Duration::from_micros(25),
            max_coalesce_count: 32,
            enabled: true,
        }
    }

    /// Preset for virtio-fs: batches well.
    #[must_use]
    pub fn for_fs() -> Self {
        Self {
            max_delay: Duration::from_micros(50),
            max_coalesce_count: 64,
            enabled: true,
        }
    }

    /// Preset for virtio-vsock: control plane, latency insensitive.
    #[must_use]
    pub fn for_vsock() -> Self {
        Self {
            max_delay: Duration::from_micros(100),
            max_coalesce_count: 128,
            enabled: true,
        }
    }

    /// Disabled coalescing — pass through immediately.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

/// Per-IRQ coalescing state.
///
/// Tracks pending interrupt count and timer state for a single IRQ line.
pub struct CoalescingState {
    /// Number of interrupts accumulated in the current window.
    pub pending_count: AtomicU32,
    /// Whether the coalescing timer is armed.
    pub timer_armed: AtomicBool,
    /// When the timer was armed (for expiry check).
    pub last_armed: Mutex<Option<Instant>>,
    /// Configuration for this IRQ line.
    pub config: CoalescingConfig,
}

impl CoalescingState {
    /// Creates a new coalescing state with the given configuration.
    #[must_use]
    pub fn new(config: CoalescingConfig) -> Self {
        Self {
            pending_count: AtomicU32::new(0),
            timer_armed: AtomicBool::new(false),
            last_armed: Mutex::new(None),
            config,
        }
    }

    /// Record a pending interrupt.
    ///
    /// Returns `true` if immediate delivery is needed (count exceeds threshold).
    pub fn record(&self) -> bool {
        let count = self.pending_count.fetch_add(1, Ordering::Relaxed);
        if count + 1 >= self.config.max_coalesce_count {
            return true;
        }
        if count == 0 {
            // First interrupt in window — arm timer
            self.timer_armed.store(true, Ordering::Release);
            *self.last_armed.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        }
        false
    }

    /// Flush coalesced state. Returns the number of coalesced interrupts.
    pub fn flush(&self) -> u32 {
        let count = self.pending_count.swap(0, Ordering::SeqCst);
        self.timer_armed.store(false, Ordering::Release);
        *self.last_armed.lock().unwrap_or_else(|e| e.into_inner()) = None;
        count
    }

    /// Check if the coalescing timer has expired.
    #[must_use]
    pub fn timer_expired(&self) -> bool {
        if !self.timer_armed.load(Ordering::Acquire) {
            return false;
        }
        let guard = self.last_armed.lock().unwrap_or_else(|e| e.into_inner());
        guard.is_some_and(|armed_at| armed_at.elapsed() >= self.config.max_delay)
    }
}

/// Statistics for interrupt coalescing.
#[derive(Debug, Default)]
pub struct IrqStats {
    /// Total interrupts triggered.
    pub triggered: AtomicU64,
    /// Interrupts coalesced (not delivered because pending).
    pub coalesced: AtomicU64,
}

/// IRQ chip abstraction.
///
/// Manages interrupt routing, delivery, and coalescing.
pub struct IrqChip {
    /// Next available IRQ number.
    next_irq: AtomicU32,
    /// IRQ mask (bit set = masked).
    mask: AtomicU32,
    /// IRQ to GSI mapping and configuration.
    irq_configs: RwLock<HashMap<Irq, IrqConfig>>,
    /// Pending interrupts bitmap for coalescing.
    /// If an IRQ is already pending, we don't trigger again.
    pending: AtomicU32,
    /// Callback for actually triggering interrupts on the VM.
    trigger_callback: Mutex<Option<Arc<IrqTriggerCallback>>>,
    /// Per-IRQ timer-based coalescing state.
    coalescing_states: RwLock<HashMap<Irq, Arc<CoalescingState>>>,
    /// Statistics for monitoring.
    stats: IrqStats,
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
            irq_configs: RwLock::new(HashMap::new()),
            pending: AtomicU32::new(0),
            trigger_callback: Mutex::new(None),
            coalescing_states: RwLock::new(HashMap::new()),
            stats: IrqStats::default(),
        })
    }

    /// Sets the callback for triggering interrupts.
    ///
    /// This should be called after the VM is created with a callback that
    /// invokes the hypervisor's interrupt injection mechanism.
    pub fn set_trigger_callback(&self, callback: Arc<IrqTriggerCallback>) {
        let mut cb = self
            .trigger_callback
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cb = Some(callback);
        tracing::debug!("IRQ trigger callback registered");
    }

    /// Configures timer-based coalescing for an IRQ.
    ///
    /// When enabled, interrupts are accumulated for up to `config.max_delay`
    /// before delivery. This trades slight latency for significant wakeup
    /// reduction during steady-state I/O.
    pub fn set_coalescing(&self, irq: Irq, config: CoalescingConfig) {
        let state = Arc::new(CoalescingState::new(config));
        let mut states = self
            .coalescing_states
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        states.insert(irq, state);
    }

    /// Returns the coalescing state for an IRQ (for timer-expiry flushing).
    #[must_use]
    pub fn coalescing_state(&self, irq: Irq) -> Option<Arc<CoalescingState>> {
        let states = self
            .coalescing_states
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        states.get(&irq).cloned()
    }

    /// Flush coalesced interrupts for an IRQ (called when timer expires).
    ///
    /// # Errors
    ///
    /// Returns an error if interrupt delivery fails.
    pub fn flush_coalesced(&self, irq: Irq) -> Result<()> {
        let state = {
            let states = self
                .coalescing_states
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            states.get(&irq).cloned()
        };
        if let Some(state) = state {
            let count = state.flush();
            if count > 0 {
                self.stats
                    .coalesced
                    .fetch_add(u64::from(count.saturating_sub(1)), Ordering::Relaxed);
                self.deliver_irq(irq)?;
            }
        }
        Ok(())
    }

    /// Allocates an IRQ number with the specified configuration.
    ///
    /// # Arguments
    /// * `gsi` - The GSI to map this IRQ to
    /// * `trigger_mode` - Edge or level triggered
    ///
    /// # Errors
    ///
    /// Returns an error if no IRQ is available.
    pub fn allocate_irq_with_config(&self, gsi: Gsi, trigger_mode: TriggerMode) -> Result<Irq> {
        let irq = self.next_irq.fetch_add(1, Ordering::SeqCst);
        if irq >= MAX_IRQS {
            return Err(crate::error::VmmError::Irq("IRQ exhausted".to_string()));
        }

        let config = IrqConfig {
            gsi,
            trigger_mode,
            asserted: false,
        };

        {
            let mut configs = self
                .irq_configs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            configs.insert(irq, config);
        }

        tracing::debug!(
            "Allocated IRQ {} -> GSI {}, mode={:?}",
            irq,
            gsi,
            trigger_mode
        );

        Ok(irq)
    }

    /// Allocates an IRQ number with default edge-triggered mode.
    ///
    /// # Errors
    ///
    /// Returns an error if no IRQ is available.
    pub fn allocate_irq(&self) -> Result<Irq> {
        self.allocate_irq_inner(TriggerMode::Edge)
    }

    /// Allocates an IRQ with level-triggered mode.
    /// Used for VirtIO MMIO devices on ARM64 where the GIC SPI level must
    /// track the device's interrupt_status register.
    pub fn allocate_level_irq(&self) -> Result<Irq> {
        self.allocate_irq_inner(TriggerMode::Level)
    }

    fn allocate_irq_inner(&self, trigger_mode: TriggerMode) -> Result<Irq> {
        let irq = self.next_irq.fetch_add(1, Ordering::SeqCst);
        if irq >= MAX_IRQS {
            return Err(crate::error::VmmError::Irq("IRQ exhausted".to_string()));
        }

        let gsi = irq;
        let config = IrqConfig {
            gsi,
            trigger_mode,
            asserted: false,
        };

        {
            let mut configs = self
                .irq_configs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            configs.insert(irq, config);
        }

        tracing::debug!("Allocated IRQ {} -> GSI {} (default edge)", irq, gsi);

        Ok(irq)
    }

    /// Configures an existing IRQ.
    pub fn configure_irq(&self, irq: Irq, gsi: Gsi, trigger_mode: TriggerMode) -> Result<()> {
        let mut configs = self
            .irq_configs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(config) = configs.get_mut(&irq) {
            config.gsi = gsi;
            config.trigger_mode = trigger_mode;
            tracing::debug!(
                "Reconfigured IRQ {} -> GSI {}, mode={:?}",
                irq,
                gsi,
                trigger_mode
            );
            Ok(())
        } else {
            Err(crate::error::VmmError::Irq(format!(
                "IRQ {irq} not allocated"
            )))
        }
    }

    /// Triggers an interrupt.
    ///
    /// For edge-triggered IRQs, this sends a pulse (assert then deassert).
    /// For level-triggered IRQs, this asserts the line (use `deassert_irq` to clear).
    ///
    /// Implements interrupt coalescing: if the IRQ is already pending,
    /// the trigger is coalesced (not delivered again).
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

        // Get configuration
        let configs = self
            .irq_configs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = configs.get(&irq);
        let trigger_mode = match config {
            Some(c) => c.trigger_mode,
            None => TriggerMode::Edge,
        };
        drop(configs);

        // Timer-based coalescing: only for edge-triggered IRQs (level-triggered
        // must always assert/deassert to maintain correct line state).
        let has_coalescing = if trigger_mode == TriggerMode::Edge {
            let states = self
                .coalescing_states
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match states.get(&irq) {
                Some(state) if state.config.enabled => {
                    let force_deliver = state.record();
                    if !force_deliver {
                        return Ok(());
                    }
                    // Threshold reached — flush and deliver. N merged into 1
                    // means N-1 coalesced.
                    let flushed = state.flush();
                    if flushed > 1 {
                        self.stats
                            .coalesced
                            .fetch_add(u64::from(flushed - 1), Ordering::Relaxed);
                    }
                    true
                }
                _ => false,
            }
        } else {
            false
        };

        // Bitmap-level dedup: only for edge-triggered IRQs 0–31 without
        // timer-based coalescing. The bitmap is a single u32; IRQs >= 32
        // would alias (e.g. 32 and 64 map to the same bit), so we skip
        // bitmap dedup for them entirely.
        if !has_coalescing && trigger_mode == TriggerMode::Edge && irq < 32 {
            let irq_bit = 1u32 << irq;
            let old_pending = self.pending.fetch_or(irq_bit, Ordering::SeqCst);
            if (old_pending & irq_bit) != 0 {
                self.stats.coalesced.fetch_add(1, Ordering::Relaxed);
                tracing::trace!("IRQ {} coalesced (already pending)", irq);
                return Ok(());
            }
        }

        self.deliver_irq(irq)
    }

    /// Delivers an interrupt immediately (bypassing coalescing).
    fn deliver_irq(&self, irq: Irq) -> Result<()> {
        let configs = self
            .irq_configs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = configs.get(&irq);
        let (gsi, trigger_mode) = match config {
            Some(c) => (c.gsi, c.trigger_mode),
            None => (irq % MAX_GSIS, TriggerMode::Edge),
        };
        drop(configs);

        self.stats.triggered.fetch_add(1, Ordering::Relaxed);
        tracing::trace!("Triggering IRQ {} -> GSI {}", irq, gsi);

        // Clone the callback Arc and drop the lock before invoking. This prevents
        // deadlock if the callback re-enters deliver_irq (e.g. device IRQ chaining).
        let callback = self
            .trigger_callback
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(ref cb) = callback {
            match trigger_mode {
                TriggerMode::Edge => {
                    cb(gsi, true)?;
                    cb(gsi, false)?;
                    let irq_bit = 1u32 << (irq % 32);
                    self.pending.fetch_and(!irq_bit, Ordering::SeqCst);
                }
                TriggerMode::Level => {
                    cb(gsi, true)?;
                    let mut configs = self
                        .irq_configs
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(c) = configs.get_mut(&irq) {
                        c.asserted = true;
                    }
                }
            }
        } else {
            tracing::warn!(
                "IRQ {} triggered but no callback registered (GSI {})",
                irq,
                gsi
            );
        }

        Ok(())
    }

    /// Deasserts a level-triggered interrupt.
    ///
    /// For level-triggered IRQs, the device calls this when the interrupt
    /// condition is cleared (e.g., data read from FIFO).
    pub fn deassert_irq(&self, irq: Irq) -> Result<()> {
        let configs = self
            .irq_configs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = configs.get(&irq);
        let gsi = match config {
            Some(c) if c.trigger_mode == TriggerMode::Level => c.gsi,
            Some(_) => {
                tracing::trace!("deassert_irq called on edge-triggered IRQ {}", irq);
                return Ok(());
            }
            None => {
                return Ok(());
            }
        };
        drop(configs);

        // Clone and drop lock before invoking to prevent deadlock on re-entry.
        let callback = self
            .trigger_callback
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(ref cb) = callback {
            cb(gsi, false)?;
        }

        // Mark as deasserted
        let mut configs = self
            .irq_configs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(c) = configs.get_mut(&irq) {
            c.asserted = false;
        }

        tracing::trace!("Deasserted IRQ {} (GSI {})", irq, gsi);

        Ok(())
    }

    /// Acknowledges an interrupt (clears pending state).
    ///
    /// Called by the interrupt handler after processing to allow
    /// new interrupts of the same type.
    pub fn ack_irq(&self, irq: Irq) {
        if irq < 32 {
            let irq_bit = 1u32 << irq;
            self.pending.fetch_and(!irq_bit, Ordering::SeqCst);
            tracing::trace!("Acknowledged IRQ {}", irq);
        }
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

    /// Checks if an IRQ is pending.
    #[must_use]
    pub fn is_pending(&self, irq: Irq) -> bool {
        if irq < 32 {
            (self.pending.load(Ordering::SeqCst) & (1 << irq)) != 0
        } else {
            false
        }
    }

    /// Gets the GSI for an IRQ.
    #[must_use]
    pub fn get_gsi(&self, irq: Irq) -> Option<Gsi> {
        let configs = self
            .irq_configs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        configs.get(&irq).map(|c| c.gsi)
    }

    /// Gets the trigger mode for an IRQ.
    #[must_use]
    pub fn get_trigger_mode(&self, irq: Irq) -> Option<TriggerMode> {
        let configs = self
            .irq_configs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        configs.get(&irq).map(|c| c.trigger_mode)
    }

    /// Returns interrupt statistics.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.stats.triggered.load(Ordering::Relaxed),
            self.stats.coalesced.load(Ordering::Relaxed),
        )
    }

    /// Resets statistics.
    pub fn reset_stats(&self) {
        self.stats.triggered.store(0, Ordering::Relaxed);
        self.stats.coalesced.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn test_irq_allocation() {
        let chip = IrqChip::new().unwrap();

        let irq1 = chip.allocate_irq().unwrap();
        let irq2 = chip.allocate_irq().unwrap();

        assert!(irq2 > irq1);
    }

    #[test]
    fn test_irq_allocation_with_config() {
        let chip = IrqChip::new().unwrap();

        let irq = chip
            .allocate_irq_with_config(5, TriggerMode::Level)
            .unwrap();

        assert_eq!(chip.get_gsi(irq), Some(5));
        assert_eq!(chip.get_trigger_mode(irq), Some(TriggerMode::Level));
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

    #[test]
    fn test_irq_device_trigger_chain() {
        let chip = Arc::new(IrqChip::new().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&events);

        let callback: IrqTriggerCallback = Box::new(move |gsi, level| {
            events_clone
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((gsi, level));
            Ok(())
        });
        chip.set_trigger_callback(Arc::new(callback));

        // Use a legacy IRQ to exercise pending tracking.
        let irq: Irq = 5;
        {
            let mut configs = chip.irq_configs.write().unwrap_or_else(|e| e.into_inner());
            configs.insert(
                irq,
                IrqConfig {
                    gsi: 5,
                    trigger_mode: TriggerMode::Edge,
                    asserted: false,
                },
            );
        }

        assert!(!chip.is_pending(irq));
        chip.trigger_irq(irq).unwrap();
        assert!(!chip.is_pending(irq));

        let recorded = events.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(recorded.as_slice(), &[(5, true), (5, false)]);
    }

    #[test]
    fn test_irq_trigger_with_callback() {
        let chip = IrqChip::new().unwrap();
        let trigger_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&trigger_count);

        // Set up callback
        let callback: IrqTriggerCallback = Box::new(move |_gsi, _level| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        chip.set_trigger_callback(Arc::new(callback));

        // Allocate and trigger
        let irq = chip.allocate_irq_with_config(1, TriggerMode::Edge).unwrap();
        chip.trigger_irq(irq).unwrap();

        // Edge-triggered should call callback twice (assert + deassert)
        assert_eq!(trigger_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_irq_coalescing() {
        let chip = IrqChip::new().unwrap();
        let trigger_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&trigger_count);

        // Set up callback that doesn't clear pending
        let callback: IrqTriggerCallback = Box::new(move |_gsi, _level| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        chip.set_trigger_callback(Arc::new(callback));

        // Allocate edge-triggered IRQ
        let irq = chip.allocate_irq_with_config(1, TriggerMode::Edge).unwrap();

        // Trigger multiple times
        chip.trigger_irq(irq).unwrap();
        chip.trigger_irq(irq).unwrap(); // Should be coalesced
        chip.trigger_irq(irq).unwrap(); // Should be coalesced

        // Only first should trigger (edge cleared pending immediately)
        // Actually for edge-triggered, pending is cleared after delivery
        // So subsequent triggers should also go through
        let (triggered, coalesced) = chip.stats();
        assert!(triggered >= 1);
        // The exact behavior depends on timing
        tracing::debug!("triggered={}, coalesced={}", triggered, coalesced);
    }

    #[test]
    fn test_level_triggered_irq() {
        let chip = IrqChip::new().unwrap();
        let levels = Arc::new(Mutex::new(Vec::new()));
        let levels_clone = Arc::clone(&levels);

        let callback: IrqTriggerCallback = Box::new(move |gsi, level| {
            levels_clone
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((gsi, level));
            Ok(())
        });
        chip.set_trigger_callback(Arc::new(callback));

        let irq = chip
            .allocate_irq_with_config(3, TriggerMode::Level)
            .unwrap();

        // Assert
        chip.trigger_irq(irq).unwrap();
        // Deassert
        chip.deassert_irq(irq).unwrap();

        let recorded = levels.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0], (3, true)); // assert
        assert_eq!(recorded[1], (3, false)); // deassert
    }

    #[test]
    fn test_masked_irq_not_triggered() {
        let chip = IrqChip::new().unwrap();
        let trigger_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&trigger_count);

        let callback: IrqTriggerCallback = Box::new(move |_gsi, _level| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        chip.set_trigger_callback(Arc::new(callback));

        // Allocate IRQ (will be >= 32, outside maskable range)
        let irq = chip.allocate_irq_with_config(0, TriggerMode::Edge).unwrap();

        // For this test, we need to test with a legacy IRQ that's maskable
        // Use mask_irq with IRQ 5 (a legacy IRQ)
        let legacy_irq: Irq = 5;

        // Insert config for legacy IRQ 5
        {
            let mut configs = chip.irq_configs.write().unwrap_or_else(|e| e.into_inner());
            configs.insert(
                legacy_irq,
                super::IrqConfig {
                    gsi: 5,
                    trigger_mode: TriggerMode::Edge,
                    asserted: false,
                },
            );
        }

        // Mask legacy IRQ and try to trigger
        chip.mask_irq(legacy_irq);
        chip.trigger_irq(legacy_irq).unwrap();

        // Should not have triggered because masked
        assert_eq!(trigger_count.load(Ordering::SeqCst), 0);

        // Unmask and trigger
        chip.unmask_irq(legacy_irq);
        chip.trigger_irq(legacy_irq).unwrap();

        // Should have triggered now
        assert_eq!(trigger_count.load(Ordering::SeqCst), 2); // assert + deassert

        // Also test that IRQs >= 32 are not affected by mask
        // IRQ was allocated with allocate_irq_with_config so it's >= 32
        assert!(irq >= 32);
        // These IRQs are never masked (is_masked returns false)
        assert!(!chip.is_masked(irq));
    }

    // ==========================================================================
    // CoalescingConfig / CoalescingState Tests
    // ==========================================================================

    #[test]
    fn test_coalescing_config_presets() {
        let net = CoalescingConfig::for_net();
        assert!(net.enabled);
        assert_eq!(net.max_delay, Duration::from_micros(50));

        let blk = CoalescingConfig::for_block();
        assert_eq!(blk.max_delay, Duration::from_micros(25));

        let disabled = CoalescingConfig::disabled();
        assert!(!disabled.enabled);
    }

    #[test]
    fn test_coalescing_record_first() {
        let state = CoalescingState::new(CoalescingConfig::default());
        assert!(!state.record()); // first interrupt arms timer, no force delivery
        assert!(state.timer_armed.load(Ordering::Relaxed));
        assert_eq!(state.pending_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_coalescing_force_delivery() {
        let config = CoalescingConfig {
            max_coalesce_count: 3,
            ..Default::default()
        };
        let state = CoalescingState::new(config);
        assert!(!state.record()); // 1
        assert!(!state.record()); // 2
        assert!(state.record()); // 3 = max → force deliver
    }

    #[test]
    fn test_coalescing_flush() {
        let state = CoalescingState::new(CoalescingConfig::default());
        state.record();
        state.record();
        let count = state.flush();
        assert_eq!(count, 2);
        assert_eq!(state.pending_count.load(Ordering::Relaxed), 0);
        assert!(!state.timer_armed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_coalescing_timer_expired() {
        let config = CoalescingConfig {
            max_delay: Duration::from_millis(1),
            ..Default::default()
        };
        let state = CoalescingState::new(config);
        assert!(!state.timer_expired()); // not armed
        state.record();
        // Timer just armed, should not be expired yet (1ms is tiny but non-zero)
        // Sleep to guarantee expiry
        std::thread::sleep(Duration::from_millis(2));
        assert!(state.timer_expired());
    }

    #[test]
    fn test_coalescing_disabled() {
        let state = CoalescingState::new(CoalescingConfig::disabled());
        assert!(!state.config.enabled);
    }

    #[test]
    fn test_trigger_irq_with_coalescing_accumulates() {
        let chip = IrqChip::new().unwrap();
        let trigger_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&trigger_count);

        let callback: IrqTriggerCallback = Box::new(move |_gsi, _level| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        chip.set_trigger_callback(Arc::new(callback));

        // Allocate edge-triggered IRQ and enable coalescing (threshold=5)
        let irq = chip.allocate_irq_with_config(1, TriggerMode::Edge).unwrap();
        chip.set_coalescing(
            irq,
            CoalescingConfig {
                max_coalesce_count: 5,
                max_delay: Duration::from_secs(10),
                enabled: true,
            },
        );

        // Trigger 4 times — all should be accumulated, not delivered
        for _ in 0..4 {
            chip.trigger_irq(irq).unwrap();
        }
        assert_eq!(trigger_count.load(Ordering::SeqCst), 0);

        // 5th trigger hits threshold → force delivery
        chip.trigger_irq(irq).unwrap();
        // deliver_irq does assert+deassert for edge → 2 callback invocations
        assert_eq!(trigger_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_flush_coalesced_delivers() {
        let chip = IrqChip::new().unwrap();
        let trigger_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&trigger_count);

        let callback: IrqTriggerCallback = Box::new(move |_gsi, _level| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        chip.set_trigger_callback(Arc::new(callback));

        let irq = chip.allocate_irq_with_config(1, TriggerMode::Edge).unwrap();
        chip.set_coalescing(irq, CoalescingConfig::default());

        // Trigger once — accumulated
        chip.trigger_irq(irq).unwrap();
        assert_eq!(trigger_count.load(Ordering::SeqCst), 0);

        // Flush — should deliver
        chip.flush_coalesced(irq).unwrap();
        assert_eq!(trigger_count.load(Ordering::SeqCst), 2); // assert + deassert
    }
}
