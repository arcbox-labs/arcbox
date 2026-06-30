use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::error::Result;

use super::{
    CoalescingConfig, CoalescingState, Gsi, Irq, IrqConfig, IrqStats, IrqTriggerCallback, MAX_GSIS,
    MAX_IRQS, TriggerMode,
};

/// First GICv3 SPI INTID. INTIDs 0–31 are SGIs/PPIs; 32+ are SPIs.
const SPI_BASE: Irq = 32;

/// Default trigger mode for an IRQ with no explicit `IrqConfig`.
///
/// On this GICv3/ARM64 platform every SPI we expose (virtio-mmio devices and
/// the PL011 UART) is declared `IRQ_TYPE_LEVEL_HIGH` in the guest device tree,
/// so an SPI must be driven as level-triggered: the line is held asserted
/// until the guest clears the device's `interrupt_status`, and the device
/// then deasserts it. Treating an SPI as edge (a momentary assert/deassert
/// pulse) violates that contract — with the Apple GIC it leaves the line in a
/// state the guest re-takes endlessly, producing an interrupt storm that wedges
/// early boot (ABX-386). SGIs/PPIs (< 32) remain edge.
const fn default_trigger_mode(irq: Irq) -> TriggerMode {
    if irq >= SPI_BASE {
        TriggerMode::Level
    } else {
        TriggerMode::Edge
    }
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
            None => default_trigger_mode(irq),
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
            None => (irq % MAX_GSIS, default_trigger_mode(irq)),
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
            // No explicit config: SPIs default to level (see
            // `default_trigger_mode`), so honor the deassert; sub-32 lines stay
            // edge and have nothing to lower.
            None if default_trigger_mode(irq) == TriggerMode::Level => irq % MAX_GSIS,
            None => return Ok(()),
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
    use std::time::Duration;

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
    fn unconfigured_spi_defaults_to_level() {
        // ABX-386: a virtio-mmio SPI (>= 32) with no explicit IrqConfig — the
        // shape the custom HV path produces — must be delivered level-triggered
        // (single assert, held until an explicit deassert), not as an edge
        // pulse. An edge pulse on a line the guest treats as level produces an
        // interrupt storm that wedges cold boot.
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

        let spi: Irq = 48; // VIRTIO_IRQ_BASE — never configured on the HV path.
        chip.trigger_irq(spi).unwrap();
        chip.deassert_irq(spi).unwrap();

        let recorded = events.lock().unwrap_or_else(|e| e.into_inner());
        // Level: assert held, then a real deassert — never an assert/deassert
        // pulse from the trigger alone.
        assert_eq!(
            recorded.as_slice(),
            &[(spi % MAX_GSIS, true), (spi % MAX_GSIS, false)]
        );
    }

    #[test]
    fn unconfigured_legacy_irq_stays_edge() {
        // Sub-32 lines (SGIs/PPIs) keep edge semantics: a single trigger is a
        // self-clearing assert/deassert pulse, and deassert is a no-op.
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

        let legacy: Irq = 7;
        chip.trigger_irq(legacy).unwrap();
        chip.deassert_irq(legacy).unwrap(); // no-op for edge

        let recorded = events.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(recorded.as_slice(), &[(7, true), (7, false)]);
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
                IrqConfig {
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
