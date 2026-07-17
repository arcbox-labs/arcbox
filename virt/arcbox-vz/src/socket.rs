//! Vsock communication with the guest.
//!
//! This module provides types for communicating with the guest VM
//! via virtio-vsock.
//!
//! # Example
//!
//! ```rust,no_run
//! # fn example() -> Result<(), arcbox_vz::VZError> {
//! use arcbox_vz::VirtualMachine;
//! use std::time::Duration;
//!
//! // Get socket device from running VM
//! # let vm: VirtualMachine = todo!();
//! let devices = vm.socket_devices();
//! let device = &devices[0];
//!
//! // Connect to guest port 1024
//! let conn = device.connect_blocking(1024, Duration::from_secs(10))?;
//! println!("Connected! fd={}", conn.as_raw_fd());
//! # Ok(())
//! # }
//! ```

use crate::error::{VZError, VZResult};
use crate::ffi::block::{_Block_release, VsockResult, create_blocking_vsock_context_block};
use objc2::runtime::AnyObject;
use std::ffi::c_void;
use std::os::unix::io::RawFd;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

// ============================================================================
// FFI Declarations
// ============================================================================

// SAFETY: dispatch_async_f is a GCD function from libdispatch, always available on macOS.
unsafe extern "C" {
    fn dispatch_async_f(
        queue: *mut AnyObject,
        context: *mut c_void,
        work: unsafe extern "C" fn(*mut c_void),
    );
}

// ============================================================================
// Connect Context
// ============================================================================

/// Context passed to `dispatch_async_f` for vsock connection.
struct ConnectContext {
    /// Socket device pointer.
    device: *mut AnyObject,
    /// Port to connect to.
    port: u32,
    /// Block pointer (will be released after use).
    block: *const c_void,
}

// SAFETY: The pointers are only used on the VM's dispatch queue
unsafe impl Send for ConnectContext {}

/// Work function executed on VM's dispatch queue.
unsafe extern "C" fn connect_work(ctx: *mut c_void) {
    // SAFETY: ctx is a valid pointer to a Box<ConnectContext> leaked via Box::into_raw in connect_blocking().
    // We reclaim ownership here. objc_msgSend is called with a valid device pointer and selector.
    unsafe {
        let context = Box::from_raw(ctx as *mut ConnectContext);

        tracing::debug!(
            "connect_work: calling connectToPort:{} on device {:?}",
            context.port,
            context.device
        );

        // Call [device connectToPort:port completionHandler:block]
        let sel = objc2::sel!(connectToPort:completionHandler:);
        let func: unsafe extern "C" fn(*mut AnyObject, objc2::runtime::Sel, u32, *const c_void) =
            std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);

        func(context.device, sel, context.port, context.block);

        // Note: The block will be released by the runtime after completion handler is called.
        // We don't release it here because VZ Framework retains it during the async operation.
    }
}

// ============================================================================
// Virtio Socket Device
// ============================================================================

/// A virtio socket device for host-guest communication.
///
/// This device enables bidirectional socket communication between
/// the host and guest using the vsock protocol.
///
/// # Getting a Device
///
/// Socket devices are obtained from a running `VirtualMachine`:
///
/// ```rust,no_run
/// # use arcbox_vz::VirtualMachine;
/// # let vm: VirtualMachine = todo!();
/// let devices = vm.socket_devices();
/// if let Some(device) = devices.first() {
///     // Use device...
/// }
/// ```
pub struct VirtioSocketDevice {
    inner: *mut AnyObject,
    queue: *mut AnyObject,
}

// SAFETY: The inner ObjC pointer is only accessed via Virtualization.framework's dispatch queue.
// queue is a thread-safe GCD queue pointer.
unsafe impl Send for VirtioSocketDevice {}
// SAFETY: See above — all access goes through the VM's dispatch queue.
unsafe impl Sync for VirtioSocketDevice {}

impl VirtioSocketDevice {
    /// Creates a device wrapper from raw pointers.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is a valid `VZVirtioSocketDevice`
    /// and `queue` is the VM's dispatch queue.
    pub(crate) fn from_raw(ptr: *mut AnyObject, queue: *mut AnyObject) -> Self {
        Self { inner: ptr, queue }
    }

    /// Connects to a guest port without using Tokio.
    ///
    /// This is used by synchronous host-side probe paths that already run on a
    /// blocking thread and must not nest `Handle::block_on` or Tokio timers.
    pub fn connect_blocking(
        &self,
        port: u32,
        timeout: Duration,
    ) -> VZResult<VirtioSocketConnection> {
        tracing::debug!("VirtioSocketDevice::connect_blocking(port={})", port);

        let (tx, rx) = std_mpsc::channel::<VsockResult>();
        let block = create_blocking_vsock_context_block(tx);

        let context = Box::new(ConnectContext {
            device: self.inner,
            port,
            block,
        });
        let context_ptr = Box::into_raw(context);

        unsafe {
            tracing::debug!("Dispatching blocking connect to VM queue {:?}", self.queue);
            dispatch_async_f(self.queue, context_ptr as *mut c_void, connect_work);
        }

        match rx.recv_timeout(timeout) {
            Ok(Ok(info)) => {
                // SAFETY: block was heap-allocated by create_blocking_vsock_context_block
                // via _Block_copy and the completion handler has already fired.
                unsafe {
                    _Block_release(block);
                }
                tracing::info!(
                    "Vsock connected: fd={}, src_port={}, dst_port={}",
                    info.fd,
                    info.source_port,
                    info.destination_port
                );
                Ok(VirtioSocketConnection {
                    fd: info.fd,
                    source_port: info.source_port,
                    destination_port: info.destination_port,
                })
            }
            Ok(Err(e)) => {
                // SAFETY: block was heap-allocated by create_blocking_vsock_context_block
                // via _Block_copy and the completion handler has already fired.
                unsafe {
                    _Block_release(block);
                }
                if is_transient_connect_error(&e.message) {
                    tracing::debug!(
                        port,
                        error = %e.message,
                        "Vsock connection not ready yet"
                    );
                } else {
                    tracing::warn!(
                        port,
                        error = %e.message,
                        "Vsock connection failed"
                    );
                }
                Err(VZError::ConnectionFailed(e.message))
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                // Do not release the block here. Virtualization.framework may
                // still invoke the completion handler later, and the block owns
                // the sender that callback will consume.
                tracing::warn!("Vsock connection timed out after {:?}", timeout);
                Err(VZError::Timeout(format!(
                    "Vsock connection to port {port} timed out"
                )))
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                // SAFETY: the sender side is already gone, so the block has
                // completed or been disposed and our retained copy can be released.
                unsafe {
                    _Block_release(block);
                }
                Err(VZError::Internal {
                    code: -1,
                    message: "Connection channel closed unexpectedly".into(),
                })
            }
        }
    }
}

fn is_transient_connect_error(message: &str) -> bool {
    let msg = message.to_ascii_lowercase();
    msg.contains("connection reset")
        || msg.contains("connection refused")
        || msg.contains("connection aborted")
        || msg.contains("broken pipe")
}

// ============================================================================
// Virtio Socket Connection
// ============================================================================

/// A vsock connection to the guest.
///
/// This represents an established connection to a guest VM port.
/// The connection can be used for reading and writing data.
///
/// # File Descriptor
///
/// The underlying file descriptor can be obtained with `as_raw_fd()`.
/// This can be used with tokio's `AsyncFd` for async I/O:
///
/// ```rust,no_run
/// use tokio::io::unix::AsyncFd;
/// use std::os::unix::io::AsRawFd;
///
/// # fn example(conn: arcbox_vz::VirtioSocketConnection) {
/// // For async I/O, wrap the fd
/// // let async_fd = AsyncFd::new(conn.as_raw_fd()).unwrap();
/// # }
/// ```
///
/// # Ownership
///
/// When the `VirtioSocketConnection` is dropped, the underlying file
/// descriptor is closed.
pub struct VirtioSocketConnection {
    fd: RawFd,
    source_port: u32,
    destination_port: u32,
}

impl VirtioSocketConnection {
    /// Returns the file descriptor for this connection.
    ///
    /// This can be used with tokio's `AsyncFd` for async I/O.
    #[inline]
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the source port (assigned by the framework).
    #[inline]
    #[must_use]
    pub fn source_port(&self) -> u32 {
        self.source_port
    }

    /// Returns the destination port (the port we connected to).
    #[inline]
    #[must_use]
    pub fn destination_port(&self) -> u32 {
        self.destination_port
    }

    /// Reads data from the connection.
    ///
    /// This is a **blocking** read. For async I/O, use tokio's `AsyncFd`.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to read into
    ///
    /// # Returns
    ///
    /// The number of bytes read, or an error.
    pub fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: self.fd is a valid file descriptor. buf.as_mut_ptr() and buf.len() provide a valid write target.
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Writes data to the connection.
    ///
    /// This is a **blocking** write. For async I/O, use tokio's `AsyncFd`.
    ///
    /// # Arguments
    ///
    /// * `buf` - Data to write
    ///
    /// # Returns
    ///
    /// The number of bytes written, or an error.
    pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: self.fd is a valid file descriptor. buf.as_ptr() and buf.len() provide valid read source.
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const c_void, buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Consumes the connection and returns the raw file descriptor.
    ///
    /// The caller is responsible for closing the file descriptor.
    #[must_use]
    pub fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

impl Drop for VirtioSocketConnection {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: self.fd is a valid file descriptor obtained via dup() during connection setup.
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}
