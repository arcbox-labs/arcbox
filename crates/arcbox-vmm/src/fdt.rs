//! Flattened Device Tree (FDT) generation for ARM.
//!
//! This module generates device tree blobs for ARM64 VMs, describing
//! the virtual hardware configuration to the guest kernel.

use crate::boot::arm64;
use crate::device::DeviceTreeEntry;
use crate::error::{Result, VmmError};
use arcbox_hypervisor::GuestAddress;

/// FDT header magic number.
pub const FDT_MAGIC: u32 = 0xD00DFEED;

/// FDT version.
pub const FDT_VERSION: u32 = 17;

/// FDT last compatible version.
pub const FDT_LAST_COMP_VERSION: u32 = 16;

/// FDT token types.
pub mod token {
    pub const BEGIN_NODE: u32 = 0x00000001;
    pub const END_NODE: u32 = 0x00000002;
    pub const PROP: u32 = 0x00000003;
    pub const NOP: u32 = 0x00000004;
    pub const END: u32 = 0x00000009;
}

/// FDT builder for creating device tree blobs.
pub struct FdtBuilder {
    /// The FDT data buffer.
    data: Vec<u8>,
    /// Strings block.
    strings: Vec<u8>,
    /// String offsets cache.
    string_offsets: std::collections::HashMap<String, u32>,
    /// Current indentation level.
    depth: u32,
}

impl FdtBuilder {
    /// Creates a new FDT builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            strings: Vec::new(),
            string_offsets: std::collections::HashMap::new(),
            depth: 0,
        }
    }

    /// Adds a string to the strings block and returns its offset.
    fn add_string(&mut self, s: &str) -> u32 {
        if let Some(&offset) = self.string_offsets.get(s) {
            return offset;
        }

        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0); // Null terminator
        self.string_offsets.insert(s.to_string(), offset);
        offset
    }

    /// Writes a 32-bit big-endian value.
    fn write_u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a 64-bit big-endian value.
    fn write_u64(&mut self, value: u64) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    /// Aligns the data to 4 bytes.
    fn align4(&mut self) {
        while self.data.len() % 4 != 0 {
            self.data.push(0);
        }
    }

    /// Begins a new node.
    pub fn begin_node(&mut self, name: &str) {
        self.write_u32(token::BEGIN_NODE);
        self.data.extend_from_slice(name.as_bytes());
        self.data.push(0);
        self.align4();
        self.depth += 1;
    }

    /// Ends the current node.
    pub fn end_node(&mut self) {
        self.write_u32(token::END_NODE);
        self.depth -= 1;
    }

    /// Adds a property with raw data.
    pub fn property(&mut self, name: &str, data: &[u8]) {
        let name_off = self.add_string(name);
        self.write_u32(token::PROP);
        self.write_u32(data.len() as u32);
        self.write_u32(name_off);
        self.data.extend_from_slice(data);
        self.align4();
    }

    /// Adds an empty property.
    pub fn property_empty(&mut self, name: &str) {
        self.property(name, &[]);
    }

    /// Adds a string property.
    pub fn property_string(&mut self, name: &str, value: &str) {
        let mut data = value.as_bytes().to_vec();
        data.push(0);
        self.property(name, &data);
    }

    /// Adds a string list property.
    pub fn property_string_list(&mut self, name: &str, values: &[&str]) {
        let mut data = Vec::new();
        for value in values {
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }
        self.property(name, &data);
    }

    /// Adds a u32 property.
    pub fn property_u32(&mut self, name: &str, value: u32) {
        self.property(name, &value.to_be_bytes());
    }

    /// Adds a u64 property.
    pub fn property_u64(&mut self, name: &str, value: u64) {
        self.property(name, &value.to_be_bytes());
    }

    /// Adds a cell array property.
    pub fn property_cells(&mut self, name: &str, cells: &[u32]) {
        let mut data = Vec::with_capacity(cells.len() * 4);
        for cell in cells {
            data.extend_from_slice(&cell.to_be_bytes());
        }
        self.property(name, &data);
    }

    /// Adds a reg property with address and size.
    pub fn property_reg(&mut self, addr: u64, size: u64) {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&addr.to_be_bytes());
        data.extend_from_slice(&size.to_be_bytes());
        self.property("reg", &data);
    }

    /// Finalizes the FDT and returns the blob.
    ///
    /// # Errors
    ///
    /// Returns an error if the FDT is invalid.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        // Add end token
        self.write_u32(token::END);

        // Calculate offsets and sizes
        let header_size = 40; // Standard FDT header
        let dt_struct_offset = header_size;
        let dt_struct_size = self.data.len();
        let dt_strings_offset = dt_struct_offset + dt_struct_size;
        let dt_strings_size = self.strings.len();
        let total_size = dt_strings_offset + dt_strings_size;

        // Build final blob
        let mut blob = Vec::with_capacity(total_size);

        // Write header
        blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        blob.extend_from_slice(&(total_size as u32).to_be_bytes());
        blob.extend_from_slice(&(dt_struct_offset as u32).to_be_bytes());
        blob.extend_from_slice(&(dt_strings_offset as u32).to_be_bytes());
        blob.extend_from_slice(&0u32.to_be_bytes()); // mem_rsvmap_off (not used)
        blob.extend_from_slice(&FDT_VERSION.to_be_bytes());
        blob.extend_from_slice(&FDT_LAST_COMP_VERSION.to_be_bytes());
        blob.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys
        blob.extend_from_slice(&(dt_strings_size as u32).to_be_bytes());
        blob.extend_from_slice(&(dt_struct_size as u32).to_be_bytes());

        // Write structure block
        blob.extend_from_slice(&self.data);

        // Write strings block
        blob.extend_from_slice(&self.strings);

        Ok(blob)
    }
}

impl Default for FdtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// FDT configuration for a VM.
#[derive(Debug, Clone)]
pub struct FdtConfig {
    /// Number of CPUs.
    pub num_cpus: u32,
    /// Memory size in bytes.
    pub memory_size: u64,
    /// Memory base address.
    pub memory_base: u64,
    /// Kernel command line.
    pub cmdline: String,
    /// Initrd address (if any).
    pub initrd_addr: Option<u64>,
    /// Initrd size (if any).
    pub initrd_size: Option<u64>,
    /// VirtIO devices.
    pub virtio_devices: Vec<DeviceTreeEntry>,
    /// GIC (interrupt controller) version.
    pub gic_version: u32,
    /// GIC distributor address.
    pub gic_dist_addr: u64,
    /// GIC distributor size.
    pub gic_dist_size: u64,
    /// GIC redistributor address (GICv3).
    pub gic_redist_addr: u64,
    /// GIC redistributor size.
    pub gic_redist_size: u64,
    /// Timer IRQ numbers.
    pub timer_irqs: [u32; 4],
}

impl Default for FdtConfig {
    fn default() -> Self {
        Self {
            num_cpus: 1,
            memory_size: 512 * 1024 * 1024,
            memory_base: 0x4000_0000, // 1GB
            cmdline: String::new(),
            initrd_addr: None,
            initrd_size: None,
            virtio_devices: Vec::new(),
            gic_version: 3,
            gic_dist_addr: 0x0800_0000,
            gic_dist_size: 0x1_0000,
            gic_redist_addr: 0x080A_0000,
            gic_redist_size: 0xF6_0000,
            timer_irqs: [13, 14, 11, 10], // PPI interrupts
        }
    }
}

/// Generates an FDT for an ARM64 VM.
///
/// # Errors
///
/// Returns an error if FDT generation fails.
pub fn generate_fdt(config: &FdtConfig) -> Result<Vec<u8>> {
    let mut fdt = FdtBuilder::new();

    // Root node
    fdt.begin_node("");
    fdt.property_string("compatible", "linux,dummy-virt");
    fdt.property_u32("#address-cells", 2);
    fdt.property_u32("#size-cells", 2);
    fdt.property_u32("interrupt-parent", 1); // GIC phandle

    // Chosen node (kernel command line, initrd)
    fdt.begin_node("chosen");
    if !config.cmdline.is_empty() {
        fdt.property_string("bootargs", &config.cmdline);
    }
    fdt.property_string("stdout-path", "/pl011@9000000");
    if let (Some(addr), Some(size)) = (config.initrd_addr, config.initrd_size) {
        fdt.property_u64("linux,initrd-start", addr);
        fdt.property_u64("linux,initrd-end", addr + size);
    }
    fdt.end_node();

    // Memory node
    fdt.begin_node(&format!("memory@{:x}", config.memory_base));
    fdt.property_string("device_type", "memory");
    fdt.property_reg(config.memory_base, config.memory_size);
    fdt.end_node();

    // CPUs node
    fdt.begin_node("cpus");
    fdt.property_u32("#address-cells", 1);
    fdt.property_u32("#size-cells", 0);

    for i in 0..config.num_cpus {
        fdt.begin_node(&format!("cpu@{}", i));
        fdt.property_string("device_type", "cpu");
        fdt.property_string("compatible", "arm,arm-v8");
        fdt.property_string("enable-method", "psci");
        fdt.property_u32("reg", i);
        fdt.end_node();
    }
    fdt.end_node();

    // Timer node
    fdt.begin_node("timer");
    fdt.property_string("compatible", "arm,armv8-timer");
    fdt.property_empty("always-on");
    // interrupts: secure phys, non-secure phys, virt, hyp
    let mut interrupts = Vec::new();
    for &irq in &config.timer_irqs {
        interrupts.push(1); // GIC_PPI
        interrupts.push(irq);
        interrupts.push(0x304); // IRQ_TYPE_LEVEL_LOW | active low
    }
    fdt.property_cells("interrupts", &interrupts);
    fdt.end_node();

    // PSCI node
    fdt.begin_node("psci");
    fdt.property_string("compatible", "arm,psci-1.0");
    fdt.property_string("method", "hvc");
    fdt.end_node();

    // GIC (interrupt controller)
    if config.gic_version == 3 {
        fdt.begin_node(&format!("intc@{:x}", config.gic_dist_addr));
        fdt.property_string("compatible", "arm,gic-v3");
        fdt.property_u32("#interrupt-cells", 3);
        fdt.property_empty("interrupt-controller");
        fdt.property_u32("phandle", 1);

        // reg: distributor, redistributor
        let mut reg = Vec::new();
        reg.extend_from_slice(&config.gic_dist_addr.to_be_bytes());
        reg.extend_from_slice(&config.gic_dist_size.to_be_bytes());
        reg.extend_from_slice(&config.gic_redist_addr.to_be_bytes());
        reg.extend_from_slice(&config.gic_redist_size.to_be_bytes());
        fdt.property("reg", &reg);

        fdt.end_node();
    }

    // PL011 UART
    fdt.begin_node("pl011@9000000");
    fdt.property_string("compatible", "arm,pl011");
    fdt.property_reg(0x0900_0000, 0x1000);
    fdt.property_cells("interrupts", &[0, 1, 4]); // SPI 1
    fdt.property_u32("clock-frequency", 24000000);
    fdt.end_node();

    // VirtIO MMIO devices
    for (i, device) in config.virtio_devices.iter().enumerate() {
        fdt.begin_node(&format!("virtio_mmio@{:x}", device.reg_base));
        fdt.property_string("compatible", &device.compatible);
        fdt.property_reg(device.reg_base, device.reg_size);
        fdt.property_cells("interrupts", &[0, device.irq, 1]); // SPI, edge
        fdt.property_empty("dma-coherent");
        fdt.end_node();
    }

    // End root node
    fdt.end_node();

    fdt.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fdt_builder_basic() {
        let mut fdt = FdtBuilder::new();

        fdt.begin_node("");
        fdt.property_string("compatible", "test");
        fdt.property_u32("#address-cells", 2);
        fdt.end_node();

        let blob = fdt.finish().unwrap();

        // Check magic
        let magic = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
        assert_eq!(magic, FDT_MAGIC);
    }

    #[test]
    fn test_fdt_builder_nested() {
        let mut fdt = FdtBuilder::new();

        fdt.begin_node("");
        fdt.begin_node("child");
        fdt.property_string("name", "child");
        fdt.end_node();
        fdt.end_node();

        let blob = fdt.finish().unwrap();
        assert!(!blob.is_empty());
    }

    #[test]
    fn test_generate_fdt() {
        let config = FdtConfig {
            num_cpus: 2,
            memory_size: 1024 * 1024 * 1024,
            cmdline: "console=ttyAMA0".to_string(),
            ..Default::default()
        };

        let blob = generate_fdt(&config).unwrap();

        // Check magic
        let magic = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
        assert_eq!(magic, FDT_MAGIC);

        // Check version
        let version = u32::from_be_bytes([blob[20], blob[21], blob[22], blob[23]]);
        assert_eq!(version, FDT_VERSION);
    }

    #[test]
    fn test_fdt_with_virtio_devices() {
        let config = FdtConfig {
            num_cpus: 1,
            memory_size: 512 * 1024 * 1024,
            virtio_devices: vec![
                DeviceTreeEntry {
                    compatible: "virtio,mmio".to_string(),
                    reg_base: 0x0A00_0000,
                    reg_size: 0x200,
                    irq: 32,
                },
                DeviceTreeEntry {
                    compatible: "virtio,mmio".to_string(),
                    reg_base: 0x0A00_0200,
                    reg_size: 0x200,
                    irq: 33,
                },
            ],
            ..Default::default()
        };

        let blob = generate_fdt(&config).unwrap();
        assert!(!blob.is_empty());
    }

    #[test]
    fn test_fdt_with_initrd() {
        let config = FdtConfig {
            initrd_addr: Some(0x4800_0000),
            initrd_size: Some(0x100_0000),
            ..Default::default()
        };

        let blob = generate_fdt(&config).unwrap();
        assert!(!blob.is_empty());
    }
}
