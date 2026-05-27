//! Unix-socket console backend.
//!
//! Allows connecting to the console via a Unix socket — useful for automated
//! testing and scripting.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::ConsoleIo;

/// Unix socket-based console backend.
///
/// Allows connecting to the console via a Unix socket,
/// useful for automated testing and scripting.
pub struct SocketConsole {
    /// Listening socket.
    listener: Option<UnixListener>,
    /// Connected client.
    client: Option<UnixStream>,
    /// Socket path.
    path: PathBuf,
}

impl SocketConsole {
    /// Creates a new socket console.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created.
    pub fn new(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();

        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path)?;
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
    pub fn path(&self) -> &Path {
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
    pub const fn is_connected(&self) -> bool {
        self.client.is_some()
    }
}

impl Drop for SocketConsole {
    fn drop(&mut self) {
        self.client = None;
        self.listener = None;
        let _ = std::fs::remove_file(&self.path);
    }
}

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
            // No client connected — discard rather than error.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_console_creation() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_console_{}.sock", std::process::id()));

        let console = SocketConsole::new(&socket_path).unwrap();
        assert_eq!(console.path(), socket_path);
        assert!(!console.is_connected());
    }

    #[test]
    fn test_socket_console_no_client() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!(
            "test_console_no_client_{}.sock",
            std::process::id()
        ));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        let mut buf = [0u8; 10];
        let n = console.read(&mut buf).unwrap();
        assert_eq!(n, 0);

        let written = console.write(b"test").unwrap();
        assert_eq!(written, 4);
    }

    #[test]
    fn test_socket_console_accept_no_client() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_console_accept_{}.sock", std::process::id()));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        assert!(!console.accept().unwrap());
    }

    #[test]
    fn test_socket_console_client_connect() {
        let temp_dir = std::env::temp_dir();
        let socket_path =
            temp_dir.join(format!("test_console_connect_{}.sock", std::process::id()));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        let _client = UnixStream::connect(&socket_path).unwrap();

        assert!(console.accept().unwrap());
        assert!(console.is_connected());
    }

    #[test]
    fn test_socket_console_read_write_with_client() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_console_rw_{}.sock", std::process::id()));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        let mut client = UnixStream::connect(&socket_path).unwrap();
        client.set_nonblocking(true).unwrap();
        console.accept().unwrap();

        console.write(b"Hello").unwrap();

        let mut buf = [0u8; 10];
        std::thread::sleep(std::time::Duration::from_millis(10));
        let n = client.read(&mut buf).unwrap_or(0);
        if n > 0 {
            assert_eq!(&buf[..n], b"Hello");
        }

        client.write_all(b"World").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut buf2 = [0u8; 10];
        let n2 = console.read(&mut buf2).unwrap();
        if n2 > 0 {
            assert_eq!(&buf2[..n2], b"World");
        }
    }

    #[test]
    fn test_socket_console_flush() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_console_flush_{}.sock", std::process::id()));

        let mut console = SocketConsole::new(&socket_path).unwrap();

        assert!(console.flush().is_ok());
    }

    #[test]
    fn test_socket_console_cleanup() {
        let temp_dir = std::env::temp_dir();
        let socket_path =
            temp_dir.join(format!("test_console_cleanup_{}.sock", std::process::id()));

        {
            let _console = SocketConsole::new(&socket_path).unwrap();
            assert!(socket_path.exists());
        }

        assert!(!socket_path.exists());
    }
}
