//! Console I/O backends — the in-process trait plus stdio and buffer impls.
//!
//! Real terminal (`pty`) and Unix socket (`socket`) backends live in
//! sibling modules so the device file does not have to know about them.

use std::collections::VecDeque;
use std::io::{Read, Write};

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
    pub const fn new() -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_console() {
        let mut buffer = BufferConsole::new();

        buffer.push_input(b"Hello");

        let mut buf = [0u8; 10];
        let n = buffer.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"Hello");

        buffer.write(b"World").unwrap();
        let output = buffer.take_output();
        assert_eq!(&output, b"World");
    }

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

        let mut buf = [0u8; 5];
        let n = buffer.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"Hello");

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
}
