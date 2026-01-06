//! Virtio socket (vsock) transport.
//!
//! Provides high-performance communication between host and guest VM.
//!
//! ## Platform Support
//!
//! - **Linux**: Uses AF_VSOCK socket family via nix crate
//! - **macOS**: Uses Virtualization.framework (requires FFI bindings)
//!
//! ## CID (Context ID) Values
//!
//! - `VMADDR_CID_HYPERVISOR` (0): Reserved for hypervisor
//! - `VMADDR_CID_LOCAL` (1): Local communication
//! - `VMADDR_CID_HOST` (2): Host (from guest perspective)
//! - 3+: Guest VMs

use crate::error::{Result, TransportError};
use crate::{Transport, TransportListener};
use async_trait::async_trait;
use bytes::Bytes;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};


/// Default port for ArcBox agent communication.
pub const DEFAULT_AGENT_PORT: u32 = 10000;

/// Vsock address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockAddr {
    /// Context ID.
    pub cid: u32,
    /// Port number.
    pub port: u32,
}

impl VsockAddr {
    /// Hypervisor CID (reserved).
    pub const CID_HYPERVISOR: u32 = 0;
    /// Local CID.
    pub const CID_LOCAL: u32 = 1;
    /// Host CID (from guest perspective).
    pub const CID_HOST: u32 = 2;
    /// Any CID (for binding).
    pub const CID_ANY: u32 = u32::MAX;

    /// Creates a new vsock address.
    #[must_use]
    pub const fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }

    /// Creates an address for the host (from guest perspective).
    #[must_use]
    pub const fn host(port: u32) -> Self {
        Self::new(Self::CID_HOST, port)
    }

    /// Creates an address for any CID (for binding).
    #[must_use]
    pub const fn any(port: u32) -> Self {
        Self::new(Self::CID_ANY, port)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::socket::{
        accept, bind, connect, listen, socket, AddressFamily, Backlog, SockFlag, SockType,
        SockaddrLike,
    };
    use std::mem;

    /// Raw sockaddr_vm structure for vsock.
    #[repr(C)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_flags: u8,
        svm_zero: [u8; 3],
    }

    impl SockaddrVm {
        fn new(cid: u32, port: u32) -> Self {
            Self {
                svm_family: libc::AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: cid,
                svm_flags: 0,
                svm_zero: [0; 3],
            }
        }
    }

    /// Vsock stream wrapper.
    pub struct VsockStream {
        fd: OwnedFd,
        async_fd: Option<tokio::io::unix::AsyncFd<std::os::fd::BorrowedFd<'static>>>,
    }

    impl VsockStream {
        pub fn from_fd(fd: OwnedFd) -> Result<Self> {
            Ok(Self { fd, async_fd: None })
        }

        pub fn as_raw_fd(&self) -> i32 {
            self.fd.as_raw_fd()
        }

        /// Sets the socket to non-blocking mode.
        fn set_nonblocking(&self) -> Result<()> {
            let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(TransportError::Io(std::io::Error::last_os_error()));
            }
            let result =
                unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if result < 0 {
                return Err(TransportError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        }

        /// Reads data from the socket.
        pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.set_nonblocking()?;

            loop {
                let result = unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };

                if result >= 0 {
                    return Ok(result as usize);
                }

                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(TransportError::Io(err));
            }
        }

        /// Writes data to the socket.
        pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.set_nonblocking()?;

            loop {
                let result = unsafe {
                    libc::write(
                        self.fd.as_raw_fd(),
                        buf.as_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };

                if result >= 0 {
                    return Ok(result as usize);
                }

                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(TransportError::Io(err));
            }
        }
    }

    /// Creates a vsock socket.
    pub fn create_socket() -> Result<OwnedFd> {
        let fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|e| TransportError::Io(e.into()))?;
        Ok(fd)
    }

    /// Connects to a vsock address.
    pub fn connect_vsock(addr: VsockAddr) -> Result<VsockStream> {
        let fd = create_socket()?;

        let sockaddr = SockaddrVm::new(addr.cid, addr.port);
        let sockaddr_ptr = &sockaddr as *const SockaddrVm as *const libc::sockaddr;

        let result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                sockaddr_ptr,
                mem::size_of::<SockaddrVm>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TransportError::ConnectionRefused(err.to_string()));
        }

        VsockStream::from_fd(fd)
    }

    /// Binds to a vsock port.
    pub fn bind_vsock(port: u32) -> Result<OwnedFd> {
        let fd = create_socket()?;

        let sockaddr = SockaddrVm::new(VsockAddr::CID_ANY, port);
        let sockaddr_ptr = &sockaddr as *const SockaddrVm as *const libc::sockaddr;

        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                sockaddr_ptr,
                mem::size_of::<SockaddrVm>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TransportError::Io(err));
        }

        let result = unsafe { libc::listen(fd.as_raw_fd(), 128) };
        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TransportError::Io(err));
        }

        Ok(fd)
    }

    /// Accepts a connection on a vsock listener.
    pub fn accept_vsock(listener_fd: &OwnedFd) -> Result<(VsockStream, VsockAddr)> {
        let mut sockaddr = SockaddrVm::new(0, 0);
        let mut len = mem::size_of::<SockaddrVm>() as libc::socklen_t;

        let fd = unsafe {
            libc::accept(
                listener_fd.as_raw_fd(),
                &mut sockaddr as *mut SockaddrVm as *mut libc::sockaddr,
                &mut len,
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TransportError::Io(err));
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let addr = VsockAddr::new(sockaddr.svm_cid, sockaddr.svm_port);

        Ok((VsockStream::from_fd(owned_fd)?, addr))
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd as StdOwnedFd, RawFd};

    /// Vsock stream for macOS.
    ///
    /// On macOS, vsock connections are obtained through the Virtualization.framework
    /// via the hypervisor layer. This struct wraps a file descriptor returned from
    /// VZVirtioSocketDevice's connection.
    pub struct VsockStream {
        fd: StdOwnedFd,
    }

    impl VsockStream {
        /// Creates a new vsock stream from an existing file descriptor.
        ///
        /// On macOS, this fd comes from `DarwinVm::connect_vsock()` which uses
        /// VZVirtioSocketDevice internally.
        ///
        /// # Safety
        /// The caller must ensure the fd is a valid connected vsock fd.
        pub fn from_raw_fd(fd: RawFd) -> Result<Self> {
            if fd < 0 {
                return Err(TransportError::ConnectionRefused(
                    "Invalid file descriptor".to_string(),
                ));
            }
            Ok(Self {
                fd: unsafe { StdOwnedFd::from_raw_fd(fd) },
            })
        }

        /// Returns the raw file descriptor.
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }

        /// Sets the socket to non-blocking mode.
        fn set_nonblocking(&self) -> Result<()> {
            let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(TransportError::Io(std::io::Error::last_os_error()));
            }
            let result = unsafe {
                libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
            };
            if result < 0 {
                return Err(TransportError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        }

        /// Reads data from the socket.
        pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.set_nonblocking()?;

            loop {
                let result = unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };

                if result >= 0 {
                    return Ok(result as usize);
                }

                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    // Yield to allow other tasks to run
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(TransportError::Io(err));
            }
        }

        /// Writes data to the socket.
        pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.set_nonblocking()?;

            loop {
                let result = unsafe {
                    libc::write(
                        self.fd.as_raw_fd(),
                        buf.as_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };

                if result >= 0 {
                    return Ok(result as usize);
                }

                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(TransportError::Io(err));
            }
        }
    }

    /// On macOS, direct vsock connection is not supported.
    /// Use `VsockStream::from_raw_fd()` with a fd obtained from the hypervisor layer.
    pub fn connect_vsock(_addr: VsockAddr) -> Result<VsockStream> {
        // On macOS, vsock connections must go through the hypervisor's VZVirtioSocketDevice.
        // The connection fd should be obtained from DarwinVm::connect_vsock() and then
        // wrapped using VsockStream::from_raw_fd().
        Err(TransportError::Protocol(
            "macOS vsock requires connection through hypervisor".to_string(),
        ))
    }

    /// On macOS, vsock binding is not supported from the host side.
    /// The guest uses vsock listeners; the host connects to them.
    pub fn bind_vsock(_port: u32) -> Result<StdOwnedFd> {
        Err(TransportError::Protocol(
            "vsock bind not supported on macOS host".to_string(),
        ))
    }

    #[allow(dead_code)]
    pub fn accept_vsock(_listener_fd: &StdOwnedFd) -> Result<(VsockStream, VsockAddr)> {
        Err(TransportError::Protocol(
            "vsock accept not supported on macOS host".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
use linux::VsockStream;

#[cfg(target_os = "macos")]
use darwin::VsockStream;

/// Vsock transport for host-guest communication.
pub struct VsockTransport {
    addr: VsockAddr,
    stream: Option<VsockStream>,
}

impl VsockTransport {
    /// Creates a new vsock transport for the given address.
    #[must_use]
    pub fn new(addr: VsockAddr) -> Self {
        Self { addr, stream: None }
    }

    /// Creates a transport to the host on the default agent port.
    #[must_use]
    pub fn to_host() -> Self {
        Self::new(VsockAddr::host(DEFAULT_AGENT_PORT))
    }

    /// Returns the vsock address.
    #[must_use]
    pub fn addr(&self) -> VsockAddr {
        self.addr
    }

    /// Creates a transport from an existing stream.
    #[cfg(target_os = "linux")]
    pub fn from_stream(stream: VsockStream, addr: VsockAddr) -> Self {
        Self {
            addr,
            stream: Some(stream),
        }
    }

    /// Creates a transport from an existing stream (macOS).
    #[cfg(target_os = "macos")]
    pub fn from_stream(stream: VsockStream, addr: VsockAddr) -> Self {
        Self {
            addr,
            stream: Some(stream),
        }
    }

    /// Creates a transport from a raw file descriptor (macOS).
    ///
    /// On macOS, vsock connections are obtained through the hypervisor layer
    /// (DarwinVm::connect_vsock). This method allows wrapping that fd into
    /// a transport.
    ///
    /// # Arguments
    /// * `fd` - A connected vsock file descriptor from the hypervisor
    /// * `addr` - The vsock address (for tracking purposes)
    ///
    /// # Example
    /// ```ignore
    /// let fd = vm.connect_vsock(1024)?;
    /// let transport = VsockTransport::from_raw_fd(fd, VsockAddr::new(cid, 1024))?;
    /// ```
    #[cfg(target_os = "macos")]
    pub fn from_raw_fd(fd: std::os::unix::io::RawFd, addr: VsockAddr) -> Result<Self> {
        let stream = darwin::VsockStream::from_raw_fd(fd)?;
        Ok(Self {
            addr,
            stream: Some(stream),
        })
    }
}

#[async_trait]
impl Transport for VsockTransport {
    async fn connect(&mut self) -> Result<()> {
        if self.stream.is_some() {
            return Err(TransportError::AlreadyConnected);
        }

        #[cfg(target_os = "linux")]
        {
            let stream = linux::connect_vsock(self.addr)?;
            self.stream = Some(stream);
        }

        #[cfg(target_os = "macos")]
        {
            let stream = darwin::connect_vsock(self.addr)?;
            self.stream = Some(stream);
        }

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.stream.take();
        Ok(())
    }

    async fn send(&mut self, data: Bytes) -> Result<()> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;

        // Write length prefix (4 bytes, little-endian)
        let len = data.len() as u32;
        let len_bytes = len.to_le_bytes();

        let mut written = 0;
        while written < 4 {
            written += stream.write(&len_bytes[written..]).await?;
        }

        // Write data
        written = 0;
        while written < data.len() {
            written += stream.write(&data[written..]).await?;
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Bytes> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;

        // Read length prefix (4 bytes, little-endian)
        let mut len_buf = [0u8; 4];
        let mut read = 0;
        while read < 4 {
            read += stream.read(&mut len_buf[read..]).await?;
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        // Read data
        let mut buf = vec![0u8; len];
        read = 0;
        while read < len {
            read += stream.read(&mut buf[read..]).await?;
        }

        Ok(Bytes::from(buf))
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

/// Vsock listener for accepting connections.
pub struct VsockListener {
    port: u32,
    #[cfg(target_os = "linux")]
    listener_fd: Option<OwnedFd>,
    #[cfg(target_os = "macos")]
    _bound: bool,
}

impl VsockListener {
    /// Creates a new vsock listener on the given port.
    #[must_use]
    pub fn new(port: u32) -> Self {
        Self {
            port,
            #[cfg(target_os = "linux")]
            listener_fd: None,
            #[cfg(target_os = "macos")]
            _bound: false,
        }
    }

    /// Creates a listener on the default agent port.
    #[must_use]
    pub fn default_agent() -> Self {
        Self::new(DEFAULT_AGENT_PORT)
    }

    /// Returns the port number.
    #[must_use]
    pub fn port(&self) -> u32 {
        self.port
    }
}

#[async_trait]
impl TransportListener for VsockListener {
    type Transport = VsockTransport;

    async fn bind(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let fd = linux::bind_vsock(self.port)?;
            self.listener_fd = Some(fd);
        }

        #[cfg(target_os = "macos")]
        {
            darwin::bind_vsock(self.port)?;
        }

        Ok(())
    }

    async fn accept(&mut self) -> Result<Self::Transport> {
        #[cfg(target_os = "linux")]
        {
            let listener_fd = self
                .listener_fd
                .as_ref()
                .ok_or(TransportError::NotConnected)?;

            let (stream, addr) = linux::accept_vsock(listener_fd)?;
            Ok(VsockTransport::from_stream(stream, addr))
        }

        #[cfg(target_os = "macos")]
        {
            Err(TransportError::Protocol(
                "vsock not yet implemented on macOS".to_string(),
            ))
        }
    }

    async fn close(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.listener_fd.take();
        }

        #[cfg(target_os = "macos")]
        {
            self._bound = false;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_addr() {
        let addr = VsockAddr::new(3, 1234);
        assert_eq!(addr.cid, 3);
        assert_eq!(addr.port, 1234);

        let host = VsockAddr::host(DEFAULT_AGENT_PORT);
        assert_eq!(host.cid, VsockAddr::CID_HOST);
        assert_eq!(host.port, DEFAULT_AGENT_PORT);
    }

    #[test]
    fn test_vsock_transport_not_connected() {
        let transport = VsockTransport::new(VsockAddr::host(1234));
        assert!(!transport.is_connected());
    }
}
