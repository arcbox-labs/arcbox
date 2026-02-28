//! VirtIO console device (virtio-console).
//!
//! Implements the VirtIO console device for serial I/O.
//!
//! Supports multiple console backends:
//! - Standard I/O (stdin/stdout)
//! - Buffer-based (for testing)
//! - PTY (pseudo-terminal) for real terminal emulation
//! - Socket-based for network console

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::error::{Result, VirtioError};
use crate::queue::VirtQueue;
use crate::{VirtioDevice, VirtioDeviceId};

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

/// Console I/O handler trait.
pub trait ConsoleIo: Send + Sync {
    /// Reads data from the console (host -> guest).
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Writes data to the console (guest -> host).
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;

    /// Flushes pending output.
    fn flush(&mut self) -> std::io::Result<()>;
}

/// Standard I/O console handler.
pub struct StdioConsole;

impl ConsoleIo for StdioConsole {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::stdin().read(buf)
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

/// Buffer-based console for testing.
pub struct BufferConsole {
    /// Input data (to be read by guest).
    pub input: VecDeque<u8>,
    /// Output data (written by guest).
    pub output: Vec<u8>,
}

impl BufferConsole {
    /// Creates a new buffer console.
    #[must_use]
    pub fn new() -> Self {
        Self {
            input: VecDeque::new(),
            output: Vec::new(),
        }
    }

    /// Pushes data to the input buffer.
    pub fn push_input(&mut self, data: &[u8]) {
        self.input.extend(data);
    }

    /// Takes all output data.
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }
}

impl Default for BufferConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleIo for BufferConsole {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len().min(self.input.len());
        for (i, byte) in self.input.drain(..len).enumerate() {
            buf[i] = byte;
        }
        Ok(len)
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ============================================================================
// PTY Console Backend
// ============================================================================

/// PTY (pseudo-terminal) console backend.
///
/// Provides a real terminal interface that can be connected to
/// by terminal emulators or the host shell.
#[cfg(unix)]
pub struct PtyConsole {
    /// Master file descriptor.
    master_fd: std::os::unix::io::RawFd,
    /// Slave file descriptor (opened for the guest).
    slave_fd: std::os::unix::io::RawFd,
    /// Path to the slave PTY device.
    slave_path: String,
    /// Non-blocking mode.
    nonblocking: bool,
}

#[cfg(unix)]
impl PtyConsole {
    /// Creates a new PTY console.
    ///
    /// # Errors
    ///
    /// Returns an error if PTY allocation fails.
    pub fn new() -> std::io::Result<Self> {
        // Open a new PTY pair
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;

        // Use openpty if available
        let ret = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Get the slave path
        let slave_path = unsafe {
            let path_ptr = libc::ttyname(slave_fd);
            if path_ptr.is_null() {
                libc::close(master_fd);
                libc::close(slave_fd);
                return Err(std::io::Error::last_os_error());
            }
            std::ffi::CStr::from_ptr(path_ptr)
                .to_string_lossy()
                .into_owned()
        };

        tracing::info!(
            "Created PTY console: master_fd={}, slave={}",
            master_fd,
            slave_path
        );

        Ok(Self {
            master_fd,
            slave_fd,
            slave_path,
            nonblocking: false,
        })
    }

    /// Returns the path to the slave PTY device.
    ///
    /// Users can connect to this path with a terminal emulator:
    /// - `screen /dev/pts/X`
    /// - `minicom -D /dev/pts/X`
    #[must_use]
    pub fn slave_path(&self) -> &str {
        &self.slave_path
    }

    /// Returns the master file descriptor.
    #[must_use]
    pub fn master_fd(&self) -> std::os::unix::io::RawFd {
        self.master_fd
    }

    /// Sets non-blocking mode on the master.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        let flags = unsafe { libc::fcntl(self.master_fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        let ret = unsafe { libc::fcntl(self.master_fd, libc::F_SETFL, new_flags) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.nonblocking = nonblocking;
        Ok(())
    }

    /// Sets terminal size.
    pub fn set_window_size(&self, rows: u16, cols: u16) -> std::io::Result<()> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let ret = unsafe { libc::ioctl(self.master_fd, libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Checks if data is available to read.
    pub fn has_data(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.master_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ret > 0 && (pollfd.revents & libc::POLLIN) != 0
    }
}

#[cfg(unix)]
impl Drop for PtyConsole {
    fn drop(&mut self) {
        if self.master_fd >= 0 {
            unsafe { libc::close(self.master_fd) };
        }
        if self.slave_fd >= 0 {
            unsafe { libc::close(self.slave_fd) };
        }
    }
}

#[cfg(unix)]
impl ConsoleIo for PtyConsole {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = unsafe {
            libc::read(
                self.master_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(err)
            }
        } else {
            Ok(ret as usize)
        }
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let ret = unsafe {
            libc::write(
                self.master_fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // PTY doesn't need explicit flush
        Ok(())
    }
}

// ============================================================================
// Socket Console Backend
// ============================================================================

/// Unix socket-based console backend.
///
/// Allows connecting to the console via a Unix socket,
/// useful for automated testing and scripting.
#[cfg(unix)]
pub struct SocketConsole {
    /// Listening socket.
    listener: Option<std::os::unix::net::UnixListener>,
    /// Connected client.
    client: Option<std::os::unix::net::UnixStream>,
    /// Socket path.
    path: std::path::PathBuf,
}

#[cfg(unix)]
impl SocketConsole {
    /// Creates a new socket console.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created.
    pub fn new(path: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let path = path.into();

        // Remove existing socket
        let _ = std::fs::remove_file(&path);

        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;

        tracing::info!("Created socket console: {}", path.display());

        Ok(Self {
            listener: Some(listener),
            client: None,
            path,
        })
    }

    /// Returns the socket path.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Accepts a new connection if available.
    pub fn accept(&mut self) -> std::io::Result<bool> {
        if let Some(listener) = &self.listener {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    self.client = Some(stream);
                    tracing::info!("Console client connected");
                    Ok(true)
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
                Err(e) => Err(e),
            }
        } else {
            Ok(false)
        }
    }

    /// Checks if a client is connected.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }
}

#[cfg(unix)]
impl Drop for SocketConsole {
    fn drop(&mut self) {
        self.client = None;
        self.listener = None;
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
impl ConsoleIo for SocketConsole {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Try to accept new connections
        let _ = self.accept();

        if let Some(client) = &mut self.client {
            match client.read(buf) {
                Ok(0) => {
                    // Client disconnected
                    self.client = None;
                    Ok(0)
                }
                Ok(n) => Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(e),
            }
        } else {
            Ok(0)
        }
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(client) = &mut self.client {
            match client.write(buf) {
                Ok(n) => Ok(n),
                Err(e) => {
                    // Client disconnected
                    self.client = None;
                    Err(e)
                }
            }
        } else {
            // No client connected, but don't error - just discard
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(client) = &mut self.client {
            client.flush()
        } else {
            Ok(())
        }
    }
}

/// VirtIO console device.
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
}

impl VirtioConsole {
    /// Feature: Console size.
    pub const FEATURE_SIZE: u64 = 1 << 0;
    /// Feature: Multiport.
    pub const FEATURE_MULTIPORT: u64 = 1 << 1;
    /// Feature: Emergency write.
    pub const FEATURE_EMERG_WRITE: u64 = 1 << 2;
    /// VirtIO 1.0 feature.
    pub const FEATURE_VERSION_1: u64 = 1 << 32;

    /// Creates a new console device.
    #[must_use]
    pub fn new(config: ConsoleConfig) -> Self {
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
        // Store in output buffer
        if let Some(port) = self.ports.first_mut() {
            port.output_buffer.extend(data);
        }

        // Forward to I/O handler
        if let Some(io) = &self.io {
            let mut io = io
                .lock()
                .map_err(|e| VirtioError::Io(format!("Failed to lock I/O: {}", e)))?;
            io.write(data)
                .map_err(|e| VirtioError::Io(format!("Write failed: {}", e)))?;
            io.flush()
                .map_err(|e| VirtioError::Io(format!("Flush failed: {}", e)))?;
        }

        tracing::trace!("Console TX: {} bytes", data.len());
        Ok(())
    }

    /// Handles data to the guest (RX).
    fn handle_rx(&mut self, buf: &mut [u8]) -> Result<usize> {
        // First check input buffer
        if let Some(port) = self.ports.first_mut() {
            if !port.input_buffer.is_empty() {
                let len = buf.len().min(port.input_buffer.len());
                for (i, byte) in port.input_buffer.drain(..len).enumerate() {
                    buf[i] = byte;
                }
                return Ok(len);
            }
        }

        // Then try I/O handler
        if let Some(io) = &self.io {
            let mut io = io
                .lock()
                .map_err(|e| VirtioError::Io(format!("Failed to lock I/O: {}", e)))?;
            let n = io
                .read(buf)
                .map_err(|e| VirtioError::Io(format!("Read failed: {}", e)))?;
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
        // Collect all data to transmit first
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
                        // Read data from guest
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

        // Now handle the data
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
                // Emergency character output
                if let Some(c) = char::from_u32(ch) {
                    eprint!("{}", c);
                }
            }
        }
    }

    fn activate(&mut self) -> Result<()> {
        // Create queues
        self.rx_queue = Some(VirtQueue::new(256)?);
        self.tx_queue = Some(VirtQueue::new(256)?);

        // Mark port 0 as open
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

        // Clear buffers
        for port in &mut self.ports {
            port.open = false;
            port.input_buffer.clear();
            port.output_buffer.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic VirtioConsole Tests
    // ========================================================================

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
        assert_eq!(u32::from_le_bytes([data[4], data[5], data[6], data[7]]), 4); // max_ports
    }

    #[test]
    fn test_buffer_console() {
        let mut buffer = BufferConsole::new();

        // Push input
        buffer.push_input(b"Hello");

        // Read it
        let mut buf = [0u8; 10];
        let n = buffer.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"Hello");

        // Write output
        buffer.write(b"World").unwrap();
        let output = buffer.take_output();
        assert_eq!(&output, b"World");
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

    // ========================================================================
    // BufferConsole Tests
    // ========================================================================

    #[test]
    fn test_buffer_console_empty_read() {
        let mut buffer = BufferConsole::new();

        let mut buf = [0u8; 10];
        let n = buffer.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_buffer_console_partial_read() {
        let mut buffer = BufferConsole::new();
        buffer.push_input(b"Hello, World!");

        // Read only part
        let mut buf = [0u8; 5];
        let n = buffer.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"Hello");

        // Read the rest
        let mut buf2 = [0u8; 10];
        let n2 = buffer.read(&mut buf2).unwrap();
        assert_eq!(n2, 8);
        assert_eq!(&buf2[..n2], b", World!");
    }

    #[test]
    fn test_buffer_console_multiple_writes() {
        let mut buffer = BufferConsole::new();

        buffer.write(b"Hello").unwrap();
        buffer.write(b" ").unwrap();
        buffer.write(b"World").unwrap();

        let output = buffer.take_output();
        assert_eq!(&output, b"Hello World");
    }

    #[test]
    fn test_buffer_console_flush() {
        let mut buffer = BufferConsole::new();
        assert!(buffer.flush().is_ok());
    }

    #[test]
    fn test_buffer_console_default() {
        let buffer = BufferConsole::default();
        assert!(buffer.input.is_empty());
        assert!(buffer.output.is_empty());
    }

    // ========================================================================
    // PTY Console Tests
    // ========================================================================

    #[cfg(unix)]
    #[test]
    fn test_pty_console_creation() {
        let pty = PtyConsole::new().unwrap();
        assert!(!pty.slave_path().is_empty());
        assert!(pty.master_fd() >= 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_console_write_read() {
        let mut pty = PtyConsole::new().unwrap();
        pty.set_nonblocking(true).unwrap();

        // Write to master
        let written = pty.write(b"test\n").unwrap();
        assert!(written > 0);

        // Note: Reading from PTY may not return data immediately
        // as it requires the slave side to echo back
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_console_nonblocking() {
        let mut pty = PtyConsole::new().unwrap();

        // Set nonblocking
        pty.set_nonblocking(true).unwrap();
        assert!(pty.nonblocking);

        // Read should return 0 when no data
        let mut buf = [0u8; 10];
        let n = pty.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_console_window_size() {
        let pty = PtyConsole::new().unwrap();

        // Set window size
        assert!(pty.set_window_size(24, 80).is_ok());
        assert!(pty.set_window_size(50, 132).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_console_has_data() {
        let pty = PtyConsole::new().unwrap();

        // Initially no data
        assert!(!pty.has_data());
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_console_flush() {
        let mut pty = PtyConsole::new().unwrap();
        assert!(pty.flush().is_ok());
    }

    // ========================================================================
    // Socket Console Tests
    // ========================================================================

    #[cfg(unix)]
    #[test]
    fn test_socket_console_creation() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_console_{}.sock", std::process::id()));

        let console = SocketConsole::new(&socket_path).unwrap();
        assert_eq!(console.path(), socket_path);
        assert!(!console.is_connected());
    }

    #[cfg(unix)]
    #[test]
    fn test_socket_console_no_client() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!(
            "test_console_no_client_{}.sock",
            std::process::id()
        ));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        // Read with no client should return 0
        let mut buf = [0u8; 10];
        let n = console.read(&mut buf).unwrap();
        assert_eq!(n, 0);

        // Write with no client should succeed (data discarded)
        let written = console.write(b"test").unwrap();
        assert_eq!(written, 4);
    }

    #[cfg(unix)]
    #[test]
    fn test_socket_console_accept_no_client() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_console_accept_{}.sock", std::process::id()));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        // Accept should return false when no client
        assert!(!console.accept().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_socket_console_client_connect() {
        use std::os::unix::net::UnixStream;

        let temp_dir = std::env::temp_dir();
        let socket_path =
            temp_dir.join(format!("test_console_connect_{}.sock", std::process::id()));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        // Connect a client
        let _client = UnixStream::connect(&socket_path).unwrap();

        // Accept should succeed
        assert!(console.accept().unwrap());
        assert!(console.is_connected());
    }

    #[cfg(unix)]
    #[test]
    fn test_socket_console_read_write_with_client() {
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::UnixStream;

        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_console_rw_{}.sock", std::process::id()));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        // Connect a client
        let mut client = UnixStream::connect(&socket_path).unwrap();
        client.set_nonblocking(true).unwrap();
        console.accept().unwrap();

        // Write from console to client
        console.write(b"Hello").unwrap();

        // Read on client side
        let mut buf = [0u8; 10];
        // Small delay for data to arrive
        std::thread::sleep(std::time::Duration::from_millis(10));
        let n = client.read(&mut buf).unwrap_or(0);
        if n > 0 {
            assert_eq!(&buf[..n], b"Hello");
        }

        // Write from client to console
        client.write_all(b"World").unwrap();

        // Read on console side
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut buf2 = [0u8; 10];
        let n2 = console.read(&mut buf2).unwrap();
        if n2 > 0 {
            assert_eq!(&buf2[..n2], b"World");
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_socket_console_flush() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_console_flush_{}.sock", std::process::id()));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        // Flush without client
        assert!(console.flush().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_socket_console_cleanup() {
        let temp_dir = std::env::temp_dir();
        let socket_path =
            temp_dir.join(format!("test_console_cleanup_{}.sock", std::process::id()));

        {
            let _console = SocketConsole::new(&socket_path).unwrap();
            assert!(socket_path.exists());
        }

        // Socket should be removed on drop
        assert!(!socket_path.exists());
    }

    // ========================================================================
    // VirtioConsole Edge Cases
    // ========================================================================

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

        // Activate
        console.activate().unwrap();
        assert!(console.rx_queue.is_some());
        assert!(console.tx_queue.is_some());

        // Reset
        console.reset();
        assert!(console.rx_queue.is_none());
        assert!(console.tx_queue.is_none());
        assert_eq!(console.acked_features, 0);
    }

    #[test]
    fn test_console_read_output() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());
        console.activate().unwrap();

        // Initially empty
        let output = console.read_output();
        assert!(output.is_empty());

        // Handle TX adds to output buffer
        console.handle_tx(b"test output").unwrap();
        let output = console.read_output();
        assert_eq!(&output, b"test output");

        // Should be empty after reading
        let output2 = console.read_output();
        assert!(output2.is_empty());
    }

    #[test]
    fn test_console_queue_input_not_ready() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());
        // Don't activate, so no ports

        // Clear the default port
        console.ports.clear();

        let result = console.queue_input(b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_console_config_write() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());

        // Config is read-only for most fields, but emergency write at offset 8
        let emergency_char = 'X' as u32;
        console.write_config(8, &emergency_char.to_le_bytes());

        // Should not crash - emergency write goes to stderr
    }

    #[test]
    fn test_console_feature_negotiation() {
        let mut console = VirtioConsole::new(ConsoleConfig::default());

        let offered = console.features();
        assert!(offered & VirtioConsole::FEATURE_VERSION_1 != 0);

        // Acknowledge some features
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

        // Read partial config (only cols)
        let mut data = [0u8; 2];
        console.read_config(0, &mut data);
        assert_eq!(u16::from_le_bytes(data), 80);

        // Read at offset
        let mut data2 = [0u8; 2];
        console.read_config(2, &mut data2);
        assert_eq!(u16::from_le_bytes(data2), 25);
    }

    #[test]
    fn test_console_rx_available_empty() {
        let console = VirtioConsole::new(ConsoleConfig::default());
        assert_eq!(console.rx_available(), 0);
    }
}
