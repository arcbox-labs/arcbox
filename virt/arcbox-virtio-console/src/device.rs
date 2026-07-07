//! `VirtioConsole` device — config, ports, queue handling, `VirtioDevice` impl.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::VirtQueue;
use arcbox_virtio_core::{QueueConfig, VirtioDevice, VirtioDeviceId, virtio_bindings};

use crate::{ConsoleIo, StdioConsole};

/// Console device configuration.
#[derive(Debug, Clone)]
pub struct ConsoleConfig {
    /// Number of columns.
    pub cols: u16,
    /// Number of rows.
    pub rows: u16,
    /// Maximum number of ports.
    pub max_ports: u32,
    /// Enable multiport.
    pub multiport: bool,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 25,
            max_ports: 1,
            multiport: false,
        }
    }
}

/// Console port state.
#[derive(Debug)]
#[allow(dead_code)]
struct ConsolePort {
    /// Port number.
    id: u32,
    /// Whether the port is open.
    open: bool,
    /// Input buffer.
    input_buffer: VecDeque<u8>,
    /// Output buffer.
    output_buffer: VecDeque<u8>,
}

impl ConsolePort {
    fn new(id: u32) -> Self {
        Self {
            id,
            open: false,
            input_buffer: VecDeque::with_capacity(4096),
            output_buffer: VecDeque::with_capacity(4096),
        }
    }
}

/// `VirtIO` console device.
#[allow(dead_code)]
pub struct VirtioConsole {
    config: ConsoleConfig,
    features: u64,
    acked_features: u64,
    /// Console ports.
    ports: Vec<ConsolePort>,
    /// Receive queue (host -> guest).
    rx_queue: Option<VirtQueue>,
    /// Transmit queue (guest -> host).
    tx_queue: Option<VirtQueue>,
    /// Console I/O handler.
    io: Option<Arc<Mutex<dyn ConsoleIo>>>,
    /// Event sender for console input.
    input_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    /// Last consumed available index for the RX queue (host -> guest).
    /// Tracked directly because the HV path reads the ring from guest memory
    /// rather than via the internal `VirtQueue`.
    rx_last_avail: u16,
}

impl VirtioConsole {
    /// Feature: Console size.
    pub const FEATURE_SIZE: u64 = 1 << 0;
    /// Feature: Multiport.
    pub const FEATURE_MULTIPORT: u64 = 1 << 1;
    /// Feature: Emergency write.
    pub const FEATURE_EMERG_WRITE: u64 = 1 << 2;
    /// `VirtIO` 1.0 feature.
    pub const FEATURE_VERSION_1: u64 = 1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;

    /// Creates a new console device.
    #[must_use]
    pub fn new(config: ConsoleConfig) -> Self {
        // EVENT_IDX is not advertised for console because activate() does not
        // propagate it to queues. Add it when console queue setup is updated to
        // call set_event_idx().
        let mut features = Self::FEATURE_SIZE | Self::FEATURE_EMERG_WRITE | Self::FEATURE_VERSION_1;

        if config.multiport {
            features |= Self::FEATURE_MULTIPORT;
        }

        let mut ports = Vec::with_capacity(config.max_ports as usize);
        ports.push(ConsolePort::new(0)); // Port 0 is always present

        Self {
            config,
            features,
            acked_features: 0,
            ports,
            rx_queue: None,
            tx_queue: None,
            io: None,
            input_tx: None,
            rx_last_avail: 0,
        }
    }

    /// Creates a console with standard I/O.
    #[must_use]
    pub fn with_stdio() -> Self {
        let mut console = Self::new(ConsoleConfig::default());
        console.io = Some(Arc::new(Mutex::new(StdioConsole)));
        console
    }

    /// Sets the console I/O handler.
    pub fn set_io(&mut self, io: Arc<Mutex<dyn ConsoleIo>>) {
        self.io = Some(io);
    }

    /// Queues input data to be read by the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the console is not active.
    pub fn queue_input(&mut self, data: &[u8]) -> Result<()> {
        if let Some(port) = self.ports.first_mut() {
            port.input_buffer.extend(data);
            Ok(())
        } else {
            Err(VirtioError::NotReady("No console port".into()))
        }
    }

    /// Reads output data written by the guest.
    #[must_use]
    pub fn read_output(&mut self) -> Vec<u8> {
        if let Some(port) = self.ports.first_mut() {
            port.output_buffer.drain(..).collect()
        } else {
            Vec::new()
        }
    }

    /// Handles data from the guest (TX).
    fn handle_tx(&mut self, data: &[u8]) -> Result<()> {
        if let Some(port) = self.ports.first_mut() {
            port.output_buffer.extend(data);
        }

        if let Some(io) = &self.io {
            let mut io = io
                .lock()
                .map_err(|e| VirtioError::Io(format!("Failed to lock I/O: {e}")))?;
            io.write(data)
                .map_err(|e| VirtioError::Io(format!("Write failed: {e}")))?;
            io.flush()
                .map_err(|e| VirtioError::Io(format!("Flush failed: {e}")))?;
        }

        tracing::trace!("Console TX: {} bytes", data.len());
        Ok(())
    }

    /// Handles data to the guest (RX).
    #[allow(dead_code)]
    fn handle_rx(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(port) = self.ports.first_mut() {
            if !port.input_buffer.is_empty() {
                let len = buf.len().min(port.input_buffer.len());
                for (i, byte) in port.input_buffer.drain(..len).enumerate() {
                    buf[i] = byte;
                }
                return Ok(len);
            }
        }

        if let Some(io) = &self.io {
            let mut io = io
                .lock()
                .map_err(|e| VirtioError::Io(format!("Failed to lock I/O: {e}")))?;
            let n = io
                .read(buf)
                .map_err(|e| VirtioError::Io(format!("Read failed: {e}")))?;
            tracing::trace!("Console RX: {} bytes", n);
            return Ok(n);
        }

        Ok(0)
    }

    /// Processes the transmit queue.
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn process_tx_queue(&mut self, memory: &[u8]) -> Result<Vec<(u16, u32)>> {
        let mut tx_data: Vec<(u16, Vec<u8>)> = Vec::new();

        {
            let queue = self
                .tx_queue
                .as_mut()
                .ok_or_else(|| VirtioError::NotReady("TX queue not ready".into()))?;

            while let Some((head_idx, chain)) = queue.pop_avail() {
                let mut data = Vec::new();

                for desc in chain {
                    if !desc.is_write_only() {
                        let start = desc.addr as usize;
                        let end = start + desc.len as usize;
                        if end <= memory.len() {
                            data.extend_from_slice(&memory[start..end]);
                        }
                    }
                }

                tx_data.push((head_idx, data));
            }
        }

        let mut completed = Vec::new();
        for (head_idx, data) in tx_data {
            let len = data.len() as u32;
            self.handle_tx(&data)?;
            completed.push((head_idx, len));
        }

        Ok(completed)
    }

    /// Gets the number of bytes available for RX.
    #[must_use]
    pub fn rx_available(&self) -> usize {
        self.ports
            .first()
            .map(|p| p.input_buffer.len())
            .unwrap_or(0)
    }

    /// Injects pending host input (queued via [`queue_input`](Self::queue_input))
    /// into the guest RX queue (queue 0), advancing the used ring.
    ///
    /// Descriptors are read directly from guest memory — the HV path drives the
    /// queue from `QueueConfig` rather than the internal [`VirtQueue`]. Returns
    /// `true` if at least one descriptor was filled, in which case the caller
    /// must raise an `INT_VRING` interrupt so the guest services the input.
    ///
    /// # Errors
    ///
    /// Returns an error if a queue address lies below the guest RAM base.
    pub fn process_rx_queue(
        &mut self,
        memory: &mut [u8],
        queue_config: &QueueConfig,
    ) -> Result<bool> {
        if !queue_config.ready || queue_config.size == 0 {
            return Ok(false);
        }
        // Nothing buffered to deliver.
        if self.rx_available() == 0 {
            return Ok(false);
        }

        // SAFETY: `memory` is the guest RAM slice; the queue accesses it only
        // through the GuestMemWriter built here, and `memory` is not touched
        // directly while the queue is alive.
        let mem = std::sync::Arc::new(unsafe {
            arcbox_virtio_core::GuestMemWriter::new(
                memory.as_mut_ptr(),
                memory.len(),
                queue_config.gpa_base as usize,
            )
        });
        let mut queue = arcbox_virtio_core::SplitQueue::new(mem, 0, queue_config, false);
        queue.set_last_avail_idx(self.rx_last_avail);

        let mut completions: Vec<(u16, u32)> = Vec::new();
        // Fill RX descriptor chains with buffered input. Stop as soon as the
        // input buffer drains, leaving the remaining descriptors for the next
        // batch of keystrokes.
        while self.rx_available() > 0 {
            let Some(chain) = queue.pop_avail() else {
                break;
            };
            let mut written = 0u32;
            let mut input_done = false;
            for desc in &chain.descriptors {
                // RX descriptors are write-only (the device writes guest input).
                if desc.is_write() && desc.len > 0 {
                    if let Some(port) = self.ports.first_mut() {
                        let n = (desc.len as usize).min(port.input_buffer.len());
                        // SAFETY: write-only descriptor buffers are device-owned.
                        if let Some(buf) = unsafe { queue.mem().slice_mut(desc.addr as usize, n) } {
                            for slot in buf.iter_mut() {
                                if let Some(b) = port.input_buffer.pop_front() {
                                    *slot = b;
                                }
                            }
                            written += n as u32;
                            input_done = port.input_buffer.is_empty();
                        }
                    }
                }
                if input_done {
                    break; // input exhausted
                }
            }
            completions.push((chain.head_idx, written));
        }

        let injected = !completions.is_empty();
        queue.push_used_batch(&completions);
        self.rx_last_avail = queue.last_avail_idx();
        Ok(injected)
    }
}

impl VirtioDevice for VirtioConsole {
    fn device_id(&self) -> VirtioDeviceId {
        VirtioDeviceId::Console
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = self.features & features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Configuration space layout (VirtIO 1.1):
        // offset 0: cols (u16)
        // offset 2: rows (u16)
        // offset 4: max_nr_ports (u32)
        // offset 8: emerg_wr (u32)
        let config_data = [
            self.config.cols.to_le_bytes().as_slice(),
            &self.config.rows.to_le_bytes(),
            &self.config.max_ports.to_le_bytes(),
            &0u32.to_le_bytes(), // emerg_wr
        ]
        .concat();

        let offset = offset as usize;
        let len = data.len().min(config_data.len().saturating_sub(offset));
        if len > 0 {
            data[..len].copy_from_slice(&config_data[offset..offset + len]);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // Handle emergency write at offset 8
        if offset == 8 && data.len() >= 4 {
            let ch = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if ch != 0 {
                if let Some(c) = char::from_u32(ch) {
                    eprint!("{c}");
                }
            }
        }
    }

    fn activate(&mut self) -> Result<()> {
        self.rx_queue = Some(VirtQueue::new(256)?);
        self.tx_queue = Some(VirtQueue::new(256)?);

        if let Some(port) = self.ports.first_mut() {
            port.open = true;
        }

        tracing::info!(
            "VirtIO console activated: {}x{}, {} ports",
            self.config.cols,
            self.config.rows,
            self.config.max_ports
        );

        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.rx_queue = None;
        self.tx_queue = None;
        self.rx_last_avail = 0;

        for port in &mut self.ports {
            port.open = false;
            port.input_buffer.clear();
            port.output_buffer.clear();
        }
    }

    fn process_queue(
        &mut self,
        queue_idx: u16,
        memory: &mut [u8],
        queue_config: &QueueConfig,
    ) -> Result<Vec<(u16, u32)>> {
        // Queue 0 = RX (host→guest), Queue 1 = TX (guest→host).
        // We only handle TX here — extract guest output from descriptors.
        if queue_idx != 1 {
            return Ok(Vec::new());
        }

        if !queue_config.ready || queue_config.size == 0 {
            return Ok(Vec::new());
        }

        // SAFETY: `memory` is the guest RAM slice; the queue accesses it only
        // through the GuestMemWriter built here, and `memory` is not touched
        // directly while the queue is alive.
        let mem = std::sync::Arc::new(unsafe {
            arcbox_virtio_core::GuestMemWriter::new(
                memory.as_mut_ptr(),
                memory.len(),
                queue_config.gpa_base as usize,
            )
        });
        let mut queue = arcbox_virtio_core::SplitQueue::new(mem, queue_idx, queue_config, false);
        // TX posts exactly one used entry per consumed avail entry, so the avail
        // cursor tracks the guest's current used.idx (which SplitQueue seeded).
        let start = queue.mem().read_u16(queue_config.used_addr as usize + 2);
        queue.set_last_avail_idx(start);

        // Mirror guest output to the attached backend (e.g. the debug-console
        // Unix socket) in addition to the `guest_console` tracing target, so an
        // interactive operator sees raw output immediately — including partial
        // lines and prompts that never carry a trailing newline.
        let io = self.io.clone();

        let mut completions = Vec::new();
        while let Some(chain) = queue.pop_avail() {
            let mut total_len = 0u32;
            for desc in &chain.descriptors {
                // Read-only descriptor = data FROM guest (TX output).
                if desc.is_write() {
                    continue;
                }
                let Some(data) = queue.mem().slice(desc.addr as usize, desc.len as usize) else {
                    continue;
                };
                if let Some(io) = &io {
                    if let Ok(mut g) = io.lock() {
                        let _ = g.write(data);
                        let _ = g.flush();
                    }
                }
                if let Some(port) = self.ports.first_mut() {
                    port.output_buffer.extend(data.iter().copied());
                    // Flush on newline.
                    while let Some(pos) = port.output_buffer.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = port.output_buffer.drain(..=pos).collect();
                        if let Ok(s) = std::str::from_utf8(&line) {
                            tracing::info!(target: "guest_console", "{}", s.trim_end());
                        }
                    }
                }
                total_len += desc.len;
            }
            completions.push((chain.head_idx, total_len));
        }

        queue.push_used_batch(&completions);
        Ok(completions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BufferConsole;

    #[test]
    fn test_console_creation() {
        let console = VirtioConsole::new(ConsoleConfig::default());
        assert_eq!(console.device_id(), VirtioDeviceId::Console);
        assert!(console.features() & VirtioConsole::FEATURE_SIZE != 0);
    }

    #[test]
    fn test_console_config_read() {
        let config = ConsoleConfig {
            cols: 120,
            rows: 40,
            max_ports: 4,
            multiport: false,
        };
        let console = VirtioConsole::new(config);

        let mut data = [0u8; 8];
        console.read_config(0, &mut data);

        assert_eq!(u16::from_le_bytes([data[0], data[1]]), 120); // cols
        assert_eq!(u16::from_le_bytes([data[2], data[3]]), 40); // rows
        assert_eq!(u32::from_le_bytes([data[4], data[5], data[6], data[7]]), 4);
        // max_ports
    }

    #[test]
    fn test_console_input_queue() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());
        console.activate().unwrap();

        console.queue_input(b"test input").unwrap();
        assert_eq!(console.rx_available(), 10);
    }

    #[test]
    fn test_console_output() {
        let buffer = Arc::new(Mutex::new(BufferConsole::new()));
        let mut console = VirtioConsole::new(ConsoleConfig::default());
        console.set_io(buffer.clone());
        console.activate().unwrap();

        console.handle_tx(b"Hello, World!").unwrap();

        let output = buffer.lock().unwrap().take_output();
        assert_eq!(&output, b"Hello, World!");
    }

    #[test]
    fn test_console_multiport_feature() {
        let config = ConsoleConfig {
            multiport: true,
            ..Default::default()
        };
        let console = VirtioConsole::new(config);
        assert!(console.features() & VirtioConsole::FEATURE_MULTIPORT != 0);
    }

    #[test]
    fn test_console_activate_and_reset() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());

        console.activate().unwrap();
        assert!(console.rx_queue.is_some());
        assert!(console.tx_queue.is_some());

        console.reset();
        assert!(console.rx_queue.is_none());
        assert!(console.tx_queue.is_none());
        assert_eq!(console.acked_features, 0);
    }

    #[test]
    fn test_console_read_output() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());
        console.activate().unwrap();

        let output = console.read_output();
        assert!(output.is_empty());

        console.handle_tx(b"test output").unwrap();
        let output = console.read_output();
        assert_eq!(&output, b"test output");

        let output2 = console.read_output();
        assert!(output2.is_empty());
    }

    #[test]
    fn test_console_queue_input_not_ready() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());

        console.ports.clear();

        let result = console.queue_input(b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_console_config_write() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());

        let emergency_char = 'X' as u32;
        console.write_config(8, &emergency_char.to_le_bytes());

        // Should not crash — emergency write goes to stderr.
    }

    #[test]
    fn test_console_feature_negotiation() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());

        let offered = console.features();
        assert!(offered & VirtioConsole::FEATURE_VERSION_1 != 0);

        console.ack_features(VirtioConsole::FEATURE_SIZE | VirtioConsole::FEATURE_VERSION_1);
        assert!(console.acked_features & VirtioConsole::FEATURE_SIZE != 0);
    }

    #[test]
    fn test_console_with_stdio() {
        let console = VirtioConsole::with_stdio();
        assert!(console.io.is_some());
    }

    #[test]
    fn test_console_config_partial_read() {
        let console = VirtioConsole::new(ConsoleConfig {
            cols: 80,
            rows: 25,
            max_ports: 1,
            multiport: false,
        });

        let mut data = [0u8; 2];
        console.read_config(0, &mut data);
        assert_eq!(u16::from_le_bytes(data), 80);

        let mut data2 = [0u8; 2];
        console.read_config(2, &mut data2);
        assert_eq!(u16::from_le_bytes(data2), 25);
    }

    #[test]
    fn test_console_rx_available_empty() {
        let console = VirtioConsole::new(ConsoleConfig::default());
        assert_eq!(console.rx_available(), 0);
    }

    #[test]
    fn test_console_process_rx_queue_injects_input() {
        // Lay out a 4-entry RX virtqueue inside a flat guest-memory buffer.
        const SIZE: u16 = 4;
        const DESC: usize = 0x100;
        const AVAIL: usize = 0x200;
        const USED: usize = 0x300;
        const BUF: usize = 0x400;
        let mut mem = vec![0u8; 0x600];

        // Descriptor 0: write-only buffer at BUF, len 16.
        mem[DESC..DESC + 8].copy_from_slice(&(BUF as u64).to_le_bytes());
        mem[DESC + 8..DESC + 12].copy_from_slice(&16u32.to_le_bytes());
        mem[DESC + 12..DESC + 14].copy_from_slice(&2u16.to_le_bytes()); // VIRTQ_DESC_F_WRITE
        mem[DESC + 14..DESC + 16].copy_from_slice(&0u16.to_le_bytes());

        // Avail ring: ring[0] = descriptor 0, idx = 1.
        mem[AVAIL + 4..AVAIL + 6].copy_from_slice(&0u16.to_le_bytes());
        mem[AVAIL + 2..AVAIL + 4].copy_from_slice(&1u16.to_le_bytes());

        let qc = QueueConfig {
            desc_addr: DESC as u64,
            avail_addr: AVAIL as u64,
            used_addr: USED as u64,
            size: SIZE,
            ready: true,
            gpa_base: 0,
        };

        let mut console = VirtioConsole::new(ConsoleConfig::default());
        // No input yet → nothing to inject.
        assert!(!console.process_rx_queue(&mut mem, &qc).unwrap());

        console.queue_input(b"hello").unwrap();
        let injected = console.process_rx_queue(&mut mem, &qc).unwrap();
        assert!(injected);
        assert_eq!(&mem[BUF..BUF + 5], b"hello");

        // Used ring advanced to 1, entry id = descriptor 0, len = 5.
        assert_eq!(u16::from_le_bytes([mem[USED + 2], mem[USED + 3]]), 1);
        assert_eq!(
            u32::from_le_bytes([mem[USED + 4], mem[USED + 5], mem[USED + 6], mem[USED + 7]]),
            0
        );
        assert_eq!(
            u32::from_le_bytes([mem[USED + 8], mem[USED + 9], mem[USED + 10], mem[USED + 11]]),
            5
        );

        // Input fully consumed; a second call is a no-op (no fresh avail entries).
        assert_eq!(console.rx_available(), 0);
        assert!(!console.process_rx_queue(&mut mem, &qc).unwrap());
    }
}
