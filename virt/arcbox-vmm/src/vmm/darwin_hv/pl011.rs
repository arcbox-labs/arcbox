//! Minimal PL011 UART emulator for early boot console output.
//!
//! Only implements enough to capture kernel boot messages. The FDT has a
//! PL011 node at the address below — this emulator handles the data path
//! so early `earlycon` output reaches the host log.

/// PL011 MMIO base address. Placed at 0x0B00_0000 to avoid the GIC
/// redistributor region (0x080A_0000 + 32 MB = 0x0A0A_0000).
pub const PL011_BASE: u64 = 0x0B00_0000;
/// PL011 MMIO region size.
pub const PL011_SIZE: u64 = 0x1000;

// PL011 register offsets (only those we emulate).
/// Data Register offset.
pub const PL011_DR: u64 = 0x000;
/// Flag Register offset.
pub const PL011_FR: u64 = 0x018;

/// Minimal PL011 UART emulator for early boot console output.
pub struct Pl011 {
    /// Accumulated output buffer (line buffered).
    output: Vec<u8>,
}

impl Pl011 {
    /// Creates a new PL011 UART emulator.
    pub fn new() -> Self {
        Self { output: Vec::new() }
    }

    /// Returns `true` if `addr` falls within the PL011 MMIO range.
    pub fn contains(&self, addr: u64) -> bool {
        (PL011_BASE..PL011_BASE + PL011_SIZE).contains(&addr)
    }

    /// Handles an MMIO read from the PL011 region.
    pub fn read(&self, addr: u64, _size: usize) -> u64 {
        let offset = addr - PL011_BASE;
        match offset {
            // Flag Register: TX FIFO never full, RX FIFO always empty.
            PL011_FR => 0,
            _ => 0,
        }
    }

    /// Handles an MMIO write to the PL011 region.
    pub fn write(&mut self, addr: u64, _size: usize, value: u64) {
        let offset = addr - PL011_BASE;
        if offset == PL011_DR {
            let byte = (value & 0xFF) as u8;
            self.output.push(byte);
            // Emit to host log when we get a newline.
            if byte == b'\n' {
                if let Ok(line) = std::str::from_utf8(&self.output) {
                    tracing::info!(target: "guest_serial", "{}", line.trim_end());
                }
                self.output.clear();
            }
        }
        // Ignore writes to control registers — we only care about data.
    }

    /// Returns a reference to the internal output buffer (for tests).
    #[cfg(test)]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// Flush any remaining partial-line output.
    pub fn flush(&mut self) {
        if !self.output.is_empty() {
            if let Ok(line) = std::str::from_utf8(&self.output) {
                tracing::info!(target: "guest_serial", "{}", line.trim_end());
            }
            self.output.clear();
        }
    }
}
