use super::*;

impl Vmm {
    /// Handles an event from the event loop.
    pub(super) fn handle_event(&self, event: crate::event::VmmEvent) {
        use crate::event::VmmEvent;

        match event {
            VmmEvent::VcpuExit { vcpu_id, exit } => {
                self.handle_vcpu_exit(vcpu_id, exit);
            }
            VmmEvent::DeviceIo {
                device_id,
                is_read,
                addr,
                data,
            } => {
                self.handle_device_io(device_id, is_read, addr, data);
            }
            VmmEvent::Timer { id } => {
                tracing::trace!("Timer {} fired", id);
                // Timer handling would go here (e.g., for RTC, PIT, etc.)
            }
            VmmEvent::Shutdown => {
                tracing::info!("Shutdown requested");
                self.running.store(false, Ordering::SeqCst);
            }
        }
    }

    /// Handles a vCPU exit event.
    ///
    /// This processes exits from the hypervisor such as I/O, MMIO, and special
    /// instructions that require VMM intervention.
    fn handle_vcpu_exit(&self, vcpu_id: u32, exit: arcbox_hypervisor::VcpuExit) {
        use arcbox_hypervisor::VcpuExit;

        match &exit {
            VcpuExit::Halt => {
                tracing::debug!("vCPU {} halted", vcpu_id);
                // HLT instruction - guest is idle, can reduce CPU usage
                // In a real implementation, we might pause the vCPU until an interrupt
            }

            VcpuExit::IoOut { port, size, data } => {
                tracing::trace!(
                    "vCPU {} I/O out: port={:#x}, size={}, data={:#x}",
                    vcpu_id,
                    port,
                    size,
                    data
                );
                self.handle_io_out(*port, *size, *data);
            }

            VcpuExit::IoIn { port, size } => {
                tracing::trace!("vCPU {} I/O in: port={:#x}, size={}", vcpu_id, port, size);
                let _value = self.handle_io_in(*port, *size);
                // Note: The value would need to be written back to the vCPU,
                // which requires access to the vCPU registers.
            }

            VcpuExit::MmioRead { addr, size } => {
                tracing::trace!(
                    "vCPU {} MMIO read: addr={:#x}, size={}",
                    vcpu_id,
                    addr,
                    size
                );
                if let Some(ref device_manager) = self.device_manager {
                    match device_manager.handle_mmio_read(*addr, *size as usize) {
                        Ok(value) => {
                            tracing::trace!("MMIO read returned: {:#x}", value);
                            // Note: Value would need to be written back to vCPU
                        }
                        Err(e) => {
                            tracing::warn!("MMIO read failed at {:#x}: {}", addr, e);
                        }
                    }
                }
            }

            VcpuExit::MmioWrite { addr, size, data } => {
                tracing::trace!(
                    "vCPU {} MMIO write: addr={:#x}, size={}, data={:#x}",
                    vcpu_id,
                    addr,
                    size,
                    data
                );
                if let Some(ref device_manager) = self.device_manager {
                    if let Err(e) = device_manager.handle_mmio_write(*addr, *size as usize, *data) {
                        tracing::warn!("MMIO write failed at {:#x}: {}", addr, e);
                    }
                }
            }

            VcpuExit::Hypercall { nr, args } => {
                tracing::debug!("vCPU {} hypercall: nr={}, args={:?}", vcpu_id, nr, args);
                // Hypercall handling - used for paravirtualization
                self.handle_hypercall(vcpu_id, *nr, *args);
            }

            VcpuExit::SystemReset => {
                tracing::info!("vCPU {} requested system reset", vcpu_id);
                // Guest requested a reset - could restart VM or signal caller
                self.running.store(false, Ordering::SeqCst);
            }

            VcpuExit::Shutdown => {
                tracing::info!("vCPU {} requested shutdown", vcpu_id);
                self.running.store(false, Ordering::SeqCst);
            }

            VcpuExit::Unknown(code) => {
                tracing::warn!("vCPU {} unknown exit: {}", vcpu_id, code);
            }

            VcpuExit::Debug => {
                tracing::debug!("vCPU {} unhandled exit: {:?}", vcpu_id, exit);
            }
        }
    }

    /// Handles device I/O events.
    fn handle_device_io(&self, device_id: u32, is_read: bool, addr: u64, data: Option<u64>) {
        if let Some(ref device_manager) = self.device_manager {
            if is_read {
                match device_manager.handle_mmio_read(addr, 4) {
                    Ok(value) => {
                        tracing::trace!("Device {} read at {:#x}: {:#x}", device_id, addr, value);
                    }
                    Err(e) => {
                        tracing::warn!("Device {} read failed: {}", device_id, e);
                    }
                }
            } else if let Some(value) = data {
                if let Err(e) = device_manager.handle_mmio_write(addr, 4, value) {
                    tracing::warn!("Device {} write failed: {}", device_id, e);
                }
            }
        }
    }

    /// Handles I/O port output.
    fn handle_io_out(&self, port: u16, size: u8, data: u64) {
        match port {
            // Serial ports (COM1-COM4)
            0x3F8..=0x3FF => {
                // COM1 - primary serial port
                if port == 0x3F8 {
                    // Data register - output character
                    let ch = (data & 0xFF) as u8;
                    if ch.is_ascii() && (ch.is_ascii_graphic() || ch.is_ascii_whitespace()) {
                        tracing::trace!("Serial output: '{}'", ch as char);
                    }
                }
            }
            0x2F8..=0x2FF => {
                // COM2
            }

            // Debug port (Bochs/QEMU convention)
            0x402 => {
                let ch = (data & 0xFF) as u8;
                if ch.is_ascii() {
                    tracing::debug!("Debug port: '{}'", ch as char);
                }
            }

            // ACPI power management
            0x604 => {
                // ACPI PM1a control - check for S5 (shutdown)
                if data & 0x2000 != 0 {
                    tracing::info!("ACPI shutdown requested");
                    // Would signal shutdown here
                }
            }

            // PIC (Programmable Interrupt Controller)
            0x20 | 0x21 | 0xA0 | 0xA1 => {
                tracing::trace!("PIC write: port={:#x}, data={:#x}", port, data);
            }

            // PIT (Programmable Interval Timer)
            0x40..=0x43 => {
                tracing::trace!("PIT write: port={:#x}, data={:#x}", port, data);
            }

            _ => {
                tracing::trace!(
                    "Unhandled I/O out: port={:#x}, size={}, data={:#x}",
                    port,
                    size,
                    data
                );
            }
        }
    }

    /// Handles I/O port input.
    fn handle_io_in(&self, port: u16, size: u8) -> u64 {
        match port {
            // Serial ports - Line Status Register
            0x3FD => {
                // LSR: Always report transmitter empty (0x60)
                0x60
            }

            // RTC (Real-Time Clock)
            0x70 | 0x71 => 0,

            // Keyboard controller status
            0x64 => {
                // Report output buffer empty, input buffer not full
                0x00
            }

            // PIC
            0x20 | 0x21 | 0xA0 | 0xA1 => 0xFF,

            _ => {
                tracing::trace!("Unhandled I/O in: port={:#x}, size={}", port, size);
                0xFF // Return all 1s for unhandled ports
            }
        }
    }

    /// Handles a hypercall from the guest.
    fn handle_hypercall(&self, vcpu_id: u32, nr: u64, args: [u64; 6]) {
        // Common hypercall numbers (KVM convention):
        // 0: KVM_HC_VAPIC_POLL_IRQ
        // 1: KVM_HC_MMU_OP (deprecated)
        // 2: KVM_HC_FEATURES
        // 3: KVM_HC_PPC_MAP_MAGIC_PAGE
        // 4: KVM_HC_KICK_CPU
        // 5: KVM_HC_SEND_IPI
        // 9: KVM_HC_MAP_GPA_RANGE

        match nr {
            0 => {
                // Poll for pending interrupts
                tracing::trace!("vCPU {} hypercall: VAPIC_POLL_IRQ", vcpu_id);
            }
            2 => {
                // Get features
                tracing::trace!("vCPU {} hypercall: GET_FEATURES", vcpu_id);
            }
            4 => {
                // Kick another vCPU
                let target_vcpu = args[0] as u32;
                tracing::trace!(
                    "vCPU {} hypercall: KICK_CPU target={}",
                    vcpu_id,
                    target_vcpu
                );
            }
            _ => {
                tracing::debug!(
                    "vCPU {} unhandled hypercall: nr={}, args={:?}",
                    vcpu_id,
                    nr,
                    args
                );
            }
        }
    }
}
