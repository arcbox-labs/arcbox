use std::sync::atomic::Ordering;

use crate::{
    error::HypervisorError,
    memory::{GuestAddress, PAGE_SIZE},
    types::DirtyPageInfo,
};

use super::{KvmUserspaceMemoryRegion, KvmVm, MemorySlotInfo, ffi};

impl KvmVm {
    /// Adds an additional memory region to the VM.
    pub fn add_memory_region(
        &self,
        guest_addr: GuestAddress,
        host_addr: *mut u8,
        size: u64,
        read_only: bool,
    ) -> Result<u32, HypervisorError> {
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst);

        let mut base_flags = 0u32;
        if read_only {
            base_flags |= ffi::KVM_MEM_READONLY;
        }

        let mut region_flags = base_flags;
        if self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            region_flags |= ffi::KVM_MEM_LOG_DIRTY_PAGES;
        }

        let region = KvmUserspaceMemoryRegion {
            slot,
            flags: region_flags,
            guest_phys_addr: guest_addr.raw(),
            memory_size: size,
            userspace_addr: host_addr as u64,
        };

        self.vm_fd.set_user_memory_region(&region).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to add memory region: {}", e))
        })?;

        {
            let mut slots = self
                .memory_slots
                .write()
                .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;
            slots.push(MemorySlotInfo {
                slot,
                guest_phys_addr: guest_addr.raw(),
                size,
                userspace_addr: host_addr as u64,
            });
        }

        self.memory
            .register_slot(slot, guest_addr.raw(), size, host_addr as u64, base_flags)?;

        tracing::debug!(
            "Added memory region {} at {}: {}MB, read_only={}",
            slot,
            guest_addr,
            size / (1024 * 1024),
            read_only
        );

        Ok(slot)
    }

    /// Removes a memory region from the VM.
    pub fn remove_memory_region(&self, slot: u32) -> Result<(), HypervisorError> {
        let region = KvmUserspaceMemoryRegion {
            slot,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
        };

        self.vm_fd.set_user_memory_region(&region).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to remove memory region: {}", e))
        })?;

        {
            let mut slots = self
                .memory_slots
                .write()
                .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;
            slots.retain(|entry| entry.slot != slot);
        }

        self.memory.unregister_slot(slot)?;

        tracing::debug!("Removed memory region {}", slot);

        Ok(())
    }
    /// Enables dirty page tracking for all memory regions.
    ///
    /// When enabled, KVM tracks which pages have been written to by the guest.
    /// Use `get_dirty_pages` to retrieve and clear the dirty page bitmap.
    ///
    /// This is useful for:
    /// - Live migration: Only transfer modified pages
    /// - Snapshotting: Track incremental changes
    ///
    /// # Errors
    ///
    /// Returns an error if dirty logging cannot be enabled.
    pub fn enable_dirty_tracking(&self) -> Result<(), HypervisorError> {
        if self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            // Already enabled.
            return Ok(());
        }

        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        // Enable dirty logging for all memory slots.
        for slot in slots.iter() {
            self.vm_fd
                .enable_dirty_logging(
                    slot.slot,
                    slot.guest_phys_addr,
                    slot.size,
                    slot.userspace_addr,
                )
                .map_err(|e| {
                    HypervisorError::SnapshotError(format!(
                        "Failed to enable dirty logging for slot {}: {}",
                        slot.slot, e
                    ))
                })?;

            tracing::debug!(
                "Enabled dirty logging for slot {}: guest={:#x}, size={}MB",
                slot.slot,
                slot.guest_phys_addr,
                slot.size / (1024 * 1024)
            );
        }

        self.dirty_tracking_enabled.store(true, Ordering::SeqCst);
        self.memory.set_dirty_tracking_enabled(true);
        tracing::info!("Dirty page tracking enabled for VM {}", self.id);

        Ok(())
    }

    /// Disables dirty page tracking for all memory regions.
    ///
    /// # Errors
    ///
    /// Returns an error if dirty logging cannot be disabled.
    pub fn disable_dirty_tracking(&self) -> Result<(), HypervisorError> {
        if !self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            // Already disabled.
            return Ok(());
        }

        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        // Disable dirty logging for all memory slots.
        for slot in slots.iter() {
            self.vm_fd
                .disable_dirty_logging(
                    slot.slot,
                    slot.guest_phys_addr,
                    slot.size,
                    slot.userspace_addr,
                )
                .map_err(|e| {
                    HypervisorError::SnapshotError(format!(
                        "Failed to disable dirty logging for slot {}: {}",
                        slot.slot, e
                    ))
                })?;
        }

        self.dirty_tracking_enabled.store(false, Ordering::SeqCst);
        self.memory.set_dirty_tracking_enabled(false);
        tracing::info!("Dirty page tracking disabled for VM {}", self.id);

        Ok(())
    }

    /// Returns whether dirty page tracking is enabled.
    #[must_use]
    pub fn is_dirty_tracking_enabled(&self) -> bool {
        self.dirty_tracking_enabled.load(Ordering::SeqCst)
    }

    /// Gets the list of dirty pages across all memory regions.
    ///
    /// This retrieves and clears the dirty page bitmap from KVM.
    /// Each call returns pages that were written since the last call.
    ///
    /// # Errors
    ///
    /// Returns an error if dirty tracking is not enabled or if the
    /// dirty log cannot be retrieved.
    pub fn get_dirty_pages(&self) -> Result<Vec<DirtyPageInfo>, HypervisorError> {
        if !self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            return Err(HypervisorError::SnapshotError(
                "Dirty tracking not enabled".to_string(),
            ));
        }

        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        let mut dirty_pages = Vec::new();

        for slot in slots.iter() {
            // Get the dirty bitmap for this slot.
            let bitmap = self
                .vm_fd
                .get_dirty_log(slot.slot, slot.size, PAGE_SIZE)
                .map_err(|e| {
                    HypervisorError::SnapshotError(format!(
                        "Failed to get dirty log for slot {}: {}",
                        slot.slot, e
                    ))
                })?;

            // Parse the bitmap to extract dirty page addresses.
            let pages = Self::parse_dirty_bitmap(&bitmap, slot.guest_phys_addr, slot.size);

            tracing::debug!(
                "Slot {}: {} dirty pages out of {} total",
                slot.slot,
                pages.len(),
                slot.size / PAGE_SIZE
            );

            dirty_pages.extend(pages);
        }

        tracing::debug!(
            "get_dirty_pages: found {} dirty pages total",
            dirty_pages.len()
        );

        Ok(dirty_pages)
    }

    /// Parses a dirty bitmap to extract individual dirty page addresses.
    ///
    /// # Arguments
    /// * `bitmap` - The bitmap from KVM_GET_DIRTY_LOG
    /// * `base_addr` - The guest physical address of the region start
    /// * `size` - Total size of the region
    ///
    /// # Returns
    /// A vector of DirtyPageInfo for each dirty page.
    pub(super) fn parse_dirty_bitmap(
        bitmap: &[u64],
        base_addr: u64,
        size: u64,
    ) -> Vec<DirtyPageInfo> {
        let mut pages = Vec::new();
        let num_pages = size / PAGE_SIZE;

        for (word_idx, &word) in bitmap.iter().enumerate() {
            if word == 0 {
                // Skip words with no dirty pages.
                continue;
            }

            // Check each bit in the word.
            for bit_idx in 0..64 {
                if (word >> bit_idx) & 1 != 0 {
                    let page_num = (word_idx as u64 * 64) + bit_idx as u64;
                    if page_num < num_pages {
                        pages.push(DirtyPageInfo {
                            guest_addr: base_addr + page_num * PAGE_SIZE,
                            size: PAGE_SIZE,
                        });
                    }
                }
            }
        }

        pages
    }
}
