use super::*;

impl DeviceManager {
    /// Returns device tree entries for all `VirtIO` devices.
    #[must_use]
    pub fn device_tree_entries(&self) -> Vec<DeviceTreeEntry> {
        // Sort by MMIO base address so the FDT node order is deterministic.
        // Linux discovers virtio-mmio devices in FDT order, so the first
        // virtio-blk node becomes vda, the second vdb, etc. Without sorting,
        // HashMap iteration order is arbitrary and block device naming becomes
        // non-deterministic (root=/dev/vda may point at the wrong disk).
        let mut entries: Vec<DeviceTreeEntry> = self
            .devices
            .values()
            .filter_map(|d| {
                if let (Some(base), Some(irq)) = (d.info.mmio_base, d.info.irq) {
                    Some(DeviceTreeEntry {
                        compatible: "virtio,mmio".to_string(),
                        reg_base: base,
                        reg_size: d.info.mmio_size,
                        irq,
                    })
                } else {
                    None
                }
            })
            .collect();
        entries.sort_by_key(|e| e.reg_base);
        entries
    }
}
/// Device tree entry for FDT generation.
#[derive(Debug, Clone)]
pub struct DeviceTreeEntry {
    /// Compatible string.
    pub compatible: String,
    /// Register base address.
    pub reg_base: u64,
    /// Register region size.
    pub reg_size: u64,
    /// IRQ number.
    pub irq: Irq,
}
