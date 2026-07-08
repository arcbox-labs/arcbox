//! Minimal PL031 RTC emulator backed by the host wall clock.
//!
//! Gives the guest kernel a real-time clock so it can set CLOCK_REALTIME
//! itself at boot (`CONFIG_RTC_HCTOSYS`) and after resume, instead of
//! sitting at the kernel default epoch until the post-readiness agent ping
//! pushes the time (ABX-416).
//!
//! Emulated surface: the time-of-day registers plus the AMBA PrimeCell
//! identification registers — Linux binds `rtc-pl031` through the AMBA bus,
//! which probes the PeriphID/PCellID words before any driver code runs.
//! The match/alarm interrupt is accepted but never raised (RTC_RIS stays 0),
//! so RTC alarms are inert; nothing in the guest stack uses them.

/// PL031 MMIO base address. One page above the PL011 UART (0x0B00_0000),
/// below the VirtIO MMIO region (0x0C00_0000).
pub const PL031_BASE: u64 = 0x0B00_1000;
/// PL031 MMIO region size.
pub const PL031_SIZE: u64 = 0x1000;
/// FDT SPI number for the (never asserted) alarm interrupt. Kept far above
/// the VirtIO allocator's range (INTIDs from 32 == FDT SPI 0 upward) so the
/// node's `interrupts` property never aliases a live device line.
pub const PL031_FDT_SPI: u32 = 31;

// PL031 register offsets (ARM DDI 0224C).
/// Data register: current time in seconds (read-only).
const RTC_DR: u64 = 0x000;
/// Match register: alarm compare value.
const RTC_MR: u64 = 0x004;
/// Load register: writing sets the current time.
const RTC_LR: u64 = 0x008;
/// Control register: bit 0 = RTC enable.
const RTC_CR: u64 = 0x00C;
/// Interrupt mask set/clear.
const RTC_IMSC: u64 = 0x010;
/// Raw interrupt status (read-only).
const RTC_RIS: u64 = 0x014;
/// Masked interrupt status (read-only).
const RTC_MIS: u64 = 0x018;
/// Interrupt clear (write-only).
const RTC_ICR: u64 = 0x01C;

/// AMBA PrimeCell identification words, one byte per word, read at
/// 0xFE0..=0xFFC. PeriphID identifies the part as a PL031 r1; PCellID is
/// the fixed PrimeCell signature. The AMBA bus core validates these before
/// binding a driver.
const AMBA_ID_BASE: u64 = 0xFE0;
const AMBA_IDS: [u8; 8] = [0x31, 0x10, 0x14, 0x00, 0x0D, 0xF0, 0x05, 0xB1];

/// Minimal PL031 RTC emulator.
pub struct Pl031 {
    /// Guest-visible time = host wall clock + this offset (wrapping u32
    /// seconds). Zero until the guest writes RTC_LR, so reads report the
    /// host's own epoch seconds.
    tick_offset: u32,
    /// Last value written to RTC_LR (readable per the TRM).
    lr: u32,
    /// Match register value; stored but never compared (no alarm delivery).
    mr: u32,
    /// Interrupt mask bit 0; stored so the guest reads back what it wrote.
    imsc: u32,
}

impl Pl031 {
    /// Creates a PL031 reporting the host wall clock.
    pub fn new() -> Self {
        Self {
            tick_offset: 0,
            lr: 0,
            mr: 0,
            imsc: 0,
        }
    }

    /// Returns `true` if `addr` falls within the PL031 MMIO range.
    pub fn contains(&self, addr: u64) -> bool {
        (PL031_BASE..PL031_BASE + PL031_SIZE).contains(&addr)
    }

    /// Host wall clock as wrapping u32 seconds since the Unix epoch (the
    /// PL031 counter width; wraps in 2106).
    fn host_secs() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as u32)
    }

    /// Handles an MMIO read from the PL031 region.
    pub fn read(&self, addr: u64, _size: usize) -> u64 {
        let offset = addr - PL031_BASE;
        let value = match offset {
            RTC_DR => Self::host_secs().wrapping_add(self.tick_offset),
            RTC_MR => self.mr,
            RTC_LR => self.lr,
            // The RTC is always running; the enable bit reads as set.
            RTC_CR => 1,
            RTC_IMSC => self.imsc,
            // No alarm is ever raised.
            RTC_RIS | RTC_MIS => 0,
            _ if (AMBA_ID_BASE..AMBA_ID_BASE + 0x20).contains(&offset) => {
                u32::from(AMBA_IDS[((offset - AMBA_ID_BASE) >> 2) as usize])
            }
            _ => 0,
        };
        u64::from(value)
    }

    /// Handles an MMIO write to the PL031 region.
    pub fn write(&mut self, addr: u64, _size: usize, value: u64) {
        let offset = addr - PL031_BASE;
        let value = value as u32;
        match offset {
            RTC_LR => {
                // Guest sets the time: remember it as an offset from the
                // host clock so the RTC keeps ticking from the new value.
                self.tick_offset = value.wrapping_sub(Self::host_secs());
                self.lr = value;
            }
            RTC_MR => self.mr = value,
            RTC_IMSC => self.imsc = value & 1,
            // CR (enable bit) and ICR (interrupt clear) are ignored: the
            // RTC always runs and no interrupt is ever pending.
            RTC_CR | RTC_ICR => {}
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read32(rtc: &Pl031, offset: u64) -> u32 {
        rtc.read(PL031_BASE + offset, 4) as u32
    }

    #[test]
    fn dr_reports_host_wall_clock() {
        let rtc = Pl031::new();
        let before = Pl031::host_secs();
        let dr = read32(&rtc, RTC_DR);
        let after = Pl031::host_secs();
        assert!(
            (before..=after).contains(&dr),
            "DR {dr} not in [{before}, {after}]"
        );
    }

    #[test]
    fn lr_write_offsets_dr_and_reads_back() {
        let mut rtc = Pl031::new();
        let target = 0x1000_0000u32;
        rtc.write(PL031_BASE + RTC_LR, 4, u64::from(target));
        assert_eq!(read32(&rtc, RTC_LR), target);
        let dr = read32(&rtc, RTC_DR);
        // DR should now tick from the loaded value (allow a 2s test margin).
        assert!(
            dr.wrapping_sub(target) <= 2,
            "DR {dr} not near loaded {target}"
        );
    }

    #[test]
    fn control_and_interrupt_registers() {
        let mut rtc = Pl031::new();
        assert_eq!(read32(&rtc, RTC_CR), 1, "RTC reads as enabled");
        rtc.write(PL031_BASE + RTC_CR, 4, 0); // ignored
        assert_eq!(read32(&rtc, RTC_CR), 1);
        rtc.write(PL031_BASE + RTC_IMSC, 4, 1);
        assert_eq!(read32(&rtc, RTC_IMSC), 1);
        assert_eq!(read32(&rtc, RTC_RIS), 0);
        assert_eq!(read32(&rtc, RTC_MIS), 0);
        rtc.write(PL031_BASE + RTC_MR, 4, 42);
        assert_eq!(read32(&rtc, RTC_MR), 42);
    }

    #[test]
    fn amba_primecell_ids_match_pl031() {
        let rtc = Pl031::new();
        let ids: Vec<u32> = (0..8).map(|i| read32(&rtc, AMBA_ID_BASE + i * 4)).collect();
        assert_eq!(ids, vec![0x31, 0x10, 0x14, 0x00, 0x0D, 0xF0, 0x05, 0xB1]);
    }
}
