//! Virtio socket (vsock) transport.
//!
//! Provides high-performance communication between host and guest VM.
//!
//! ## Platform Support
//!
//! - **Linux**: Uses AF_VSOCK socket family directly via nix crate.
//!   Standard `bind()` and `connect()` operations work as expected.
//!
//! - **macOS**: Uses Virtualization.framework (`VZVirtioSocketDevice`).
//!   Requires integration with the hypervisor layer:
//!   - For connections: Use [`VsockTransport::from_raw_fd()`] with an fd
//!     obtained from `VirtioSocketDevice::connect()`.
//!   - For listening: Use [`VsockListener::from_channel()`] with a channel
//!     connected to `VirtioSocketListener::accept()`.
//!
//! ## CID (Context ID) Values
//!
//! - `VMADDR_CID_HYPERVISOR` (0): Reserved for hypervisor
//! - `VMADDR_CID_LOCAL` (1): Local communication
//! - `VMADDR_CID_HOST` (2): Host (from guest perspective)
//! - 3+: Guest VMs
//!
//! ## macOS Usage Example
//!
//! ```rust,ignore
//! use arcbox_vz::{VirtualMachine, VirtioSocketDevice};
//! use arcbox_transport::vsock::{VsockListener, VsockTransport, VsockAddr, IncomingVsockConnection};
//! use tokio::sync::mpsc;
//!
//! // Get socket device from running VM
//! let vm: VirtualMachine = /* ... */;
//! let device = &vm.socket_devices()[0];
//!
//! // === Connecting to guest ===
//! let conn = device.connect(1024).await?;
//! let fd = conn.into_raw_fd();
//! let transport = VsockTransport::from_raw_fd(fd, VsockAddr::new(cid, 1024))?;
//!
//! // === Listening for guest connections ===
//! let mut vz_listener = device.listen(1024)?;
//! let (tx, rx) = mpsc::unbounded_channel();
//!
//! // Bridge VZ listener to transport layer
//! tokio::spawn(async move {
//!     loop {
//!         match vz_listener.accept().await {
//!             Ok(conn) => {
//!                 let incoming = IncomingVsockConnection {
//!                     fd: conn.into_raw_fd(),
//!                     source_port: conn.source_port(),
//!                     destination_port: conn.destination_port(),
//!                 };
//!                 if tx.send(incoming).is_err() {
//!                     break;
//!                 }
//!             }
//!             Err(_) => break,
//!         }
//!     }
//! });
//!
//! let mut listener = VsockListener::from_channel(1024, rx);
//! let transport = listener.accept().await?;
//! ```

use crate::error::{Result, TransportError};
use crate::{Transport, TransportListener};
use async_trait::async_trait;
use bytes::Bytes;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Default port for ArcBox agent communication.
pub use arcbox_constants::ports::AGENT_PORT as DEFAULT_AGENT_PORT;

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
        AddressFamily, Backlog, SockFlag, SockType, SockaddrLike, accept, bind, connect, listen,
        socket,
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
                return Err(TransportError::io(std::io::Error::last_os_error()));
            }
            let result = unsafe {
                libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
            };
            if result < 0 {
                return Err(TransportError::io(std::io::Error::last_os_error()));
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
                return Err(TransportError::io(err));
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
                return Err(TransportError::io(err));
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
        .map_err(|e| TransportError::io(e.into()))?;
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
            return Err(TransportError::io(err));
        }

        let result = unsafe { libc::listen(fd.as_raw_fd(), 128) };
        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TransportError::io(err));
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
            return Err(TransportError::io(err));
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
    use tokio::sync::mpsc;

    /// Information about an incoming vsock connection.
    #[derive(Debug, Clone)]
    pub struct IncomingVsockConnection {
        /// File descriptor for the connection.
        pub fd: RawFd,
        /// Source port (guest port).
        pub source_port: u32,
        /// Destination port (host port).
        pub destination_port: u32,
    }

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
                return Err(TransportError::io(std::io::Error::last_os_error()));
            }
            let result = unsafe {
                libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
            };
            if result < 0 {
                return Err(TransportError::io(std::io::Error::last_os_error()));
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
                return Err(TransportError::io(err));
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
                return Err(TransportError::io(err));
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
    #[allow(dead_code)]
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

    /// Vsock listener handle for macOS.
    ///
    /// On macOS, vsock listening is done through VZVirtioSocketDevice.
    /// This handle wraps a channel that receives incoming connections
    /// from the Virtualization.framework layer.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use arcbox_vz::VirtioSocketDevice;
    /// use arcbox_transport::vsock::{VsockListener, IncomingVsockConnection};
    /// use tokio::sync::mpsc;
    ///
    /// // In arcbox-core or higher layer:
    /// let device: &VirtioSocketDevice = /* from VM */;
    /// let vz_listener = device.listen(port)?;
    ///
    /// // Create channel for bridging
    /// let (tx, rx) = mpsc::unbounded_channel();
    ///
    /// // Spawn task to forward connections
    /// tokio::spawn(async move {
    ///     loop {
    ///         if let Ok(conn) = vz_listener.accept().await {
    ///             let _ = tx.send(IncomingVsockConnection {
    ///                 fd: conn.as_raw_fd(),
    ///                 source_port: conn.source_port(),
    ///                 destination_port: conn.destination_port(),
    ///             });
    ///         }
    ///     }
    /// });
    ///
    /// // Create transport listener
    /// let listener = VsockListener::from_channel(port, rx);
    /// ```
    #[allow(dead_code)]
    pub struct VsockListenerHandle {
        /// Port number being listened on.
        port: u32,
        /// Channel receiver for incoming connections.
        receiver: mpsc::UnboundedReceiver<IncomingVsockConnection>,
    }

    #[allow(dead_code)]
    impl VsockListenerHandle {
        /// Creates a new listener handle from a channel.
        ///
        /// # Arguments
        ///
        /// * `port` - The port number being listened on
        /// * `receiver` - Channel receiver for incoming connections from VZ layer
        pub fn new(port: u32, receiver: mpsc::UnboundedReceiver<IncomingVsockConnection>) -> Self {
            Self { port, receiver }
        }

        /// Returns the port number.
        pub fn port(&self) -> u32 {
            self.port
        }

        /// Accepts an incoming connection.
        ///
        /// Waits for a connection to arrive on the channel.
        pub async fn accept(&mut self) -> Result<(VsockStream, VsockAddr)> {
            match self.receiver.recv().await {
                Some(conn) => {
                    let stream = VsockStream::from_raw_fd(conn.fd)?;
                    let addr = VsockAddr::new(VsockAddr::CID_ANY, conn.source_port);
                    Ok((stream, addr))
                }
                None => Err(TransportError::ConnectionReset),
            }
        }

        /// Tries to accept a connection without blocking.
        pub fn try_accept(&mut self) -> Option<Result<(VsockStream, VsockAddr)>> {
            match self.receiver.try_recv() {
                Ok(conn) => {
                    let stream = VsockStream::from_raw_fd(conn.fd);
                    match stream {
                        Ok(s) => {
                            let addr = VsockAddr::new(VsockAddr::CID_ANY, conn.source_port);
                            Some(Ok((s, addr)))
                        }
                        Err(e) => Some(Err(e)),
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => None,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    Some(Err(TransportError::ConnectionReset))
                }
            }
        }
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

        // Write data as-is (RPC framing includes length + type + payload).
        let mut written = 0;
        while written < data.len() {
            written += stream.write(&data[written..]).await?;
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Bytes> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;

        // Read length prefix (4 bytes, big-endian).
        let mut len_buf = [0u8; 4];
        let mut read = 0;
        while read < 4 {
            let n = stream.read(&mut len_buf[read..]).await?;
            if n == 0 {
                tracing::debug!("VsockTransport::recv: EOF while reading length prefix");
                return Err(TransportError::io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF while reading length prefix",
                )));
            }
            read += n;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        tracing::debug!("VsockTransport::recv: message length={}", len);

        // Read data and return the full framed message (length + payload).
        let mut buf = Vec::with_capacity(4 + len);
        buf.extend_from_slice(&len_buf);
        let mut payload = vec![0u8; len];
        read = 0;
        while read < len {
            let n = stream.read(&mut payload[read..]).await?;
            if n == 0 {
                tracing::debug!(
                    "VsockTransport::recv: EOF while reading payload, read={}/{}",
                    read,
                    len
                );
                return Err(TransportError::io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF while reading payload",
                )));
            }
            read += n;
        }

        buf.extend_from_slice(&payload);
        Ok(Bytes::from(buf))
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

/// Vsock listener for accepting connections.
///
/// On Linux, this uses AF_VSOCK sockets directly.
/// On macOS, this requires a channel connected to VZVirtioSocketDevice.
pub struct VsockListener {
    port: u32,
    #[cfg(target_os = "linux")]
    listener_fd: Option<OwnedFd>,
    #[cfg(target_os = "macos")]
    handle: Option<darwin::VsockListenerHandle>,
}

impl VsockListener {
    /// Creates a new vsock listener on the given port.
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: After calling `bind()`, the listener will be ready to accept connections.
    /// - **macOS**: Use `from_channel()` instead to provide a channel connected to
    ///   VZVirtioSocketDevice. Calling `bind()` on this listener will fail.
    #[must_use]
    pub fn new(port: u32) -> Self {
        Self {
            port,
            #[cfg(target_os = "linux")]
            listener_fd: None,
            #[cfg(target_os = "macos")]
            handle: None,
        }
    }

    /// Creates a listener from a channel (macOS).
    ///
    /// On macOS, vsock listening is done through VZVirtioSocketDevice.
    /// This method creates a listener that receives connections from a channel
    /// bridged to the Virtualization.framework layer.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number being listened on
    /// * `receiver` - Channel receiver for incoming connections
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use arcbox_vz::VirtioSocketDevice;
    /// use arcbox_transport::vsock::{VsockListener, IncomingVsockConnection};
    /// use tokio::sync::mpsc;
    ///
    /// // Get socket device from running VM
    /// let device: &VirtioSocketDevice = &vm.socket_devices()[0];
    ///
    /// // Create VZ listener
    /// let mut vz_listener = device.listen(port)?;
    ///
    /// // Create channel for bridging
    /// let (tx, rx) = mpsc::unbounded_channel();
    ///
    /// // Spawn task to forward connections
    /// tokio::spawn(async move {
    ///     loop {
    ///         match vz_listener.accept().await {
    ///             Ok(conn) => {
    ///                 let incoming = IncomingVsockConnection {
    ///                     fd: conn.into_raw_fd(),
    ///                     source_port: conn.source_port(),
    ///                     destination_port: conn.destination_port(),
    ///                 };
    ///                 if tx.send(incoming).is_err() {
    ///                     break;
    ///                 }
    ///             }
    ///             Err(_) => break,
    ///         }
    ///     }
    /// });
    ///
    /// // Create transport listener
    /// let mut listener = VsockListener::from_channel(port, rx);
    /// let transport = listener.accept().await?;
    /// ```
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn from_channel(
        port: u32,
        receiver: tokio::sync::mpsc::UnboundedReceiver<darwin::IncomingVsockConnection>,
    ) -> Self {
        Self {
            port,
            handle: Some(darwin::VsockListenerHandle::new(port, receiver)),
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
            // On macOS, binding is done through VZVirtioSocketDevice.
            // If a handle was provided via from_channel(), we're already "bound".
            // Otherwise, return an error explaining the correct usage.
            if self.handle.is_none() {
                return Err(TransportError::Protocol(
                    "macOS vsock requires VZVirtioSocketDevice. Use VsockListener::from_channel() \
                     with a channel connected to VirtioSocketListener."
                        .to_string(),
                ));
            }
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
            let handle = self.handle.as_mut().ok_or_else(|| {
                TransportError::Protocol(
                    "macOS vsock listener not initialized. Use VsockListener::from_channel()."
                        .to_string(),
                )
            })?;

            let (stream, addr) = handle.accept().await?;
            Ok(VsockTransport::from_stream(stream, addr))
        }
    }

    async fn close(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.listener_fd.take();
        }

        #[cfg(target_os = "macos")]
        {
            self.handle.take();
        }

        Ok(())
    }
}

// Re-export macOS-specific types for use by callers.
#[cfg(target_os = "macos")]
pub use darwin::IncomingVsockConnection;

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

    #[cfg(target_os = "macos")]
    #[test]
    fn test_vsock_listener_from_channel() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::unbounded_channel();
        let listener = VsockListener::from_channel(1024, rx);
        assert_eq!(listener.port(), 1024);

        // Channel can send connections
        let conn = IncomingVsockConnection {
            fd: 42,
            source_port: 2000,
            destination_port: 1024,
        };
        assert!(tx.send(conn).is_ok());
    }
}
