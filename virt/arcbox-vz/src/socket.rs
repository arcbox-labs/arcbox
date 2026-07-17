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
use crate::shim_ffi;
use objc2::runtime::AnyObject;
use std::ffi::{c_char, c_void};
use std::os::unix::io::RawFd;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

/// Result of a vsock connect delivered by the shim callback.
///
/// Owns the dup'd fd: closes it on drop unless [`connect_blocking`] transfers
/// it into a [`VirtioSocketConnection`]. This makes every abandonment path
/// leak-free — a send to a dropped receiver, and also the race where a late
/// completion sends successfully into the channel just before the receiver is
/// dropped (the buffered value then closes the fd when the channel drops).
struct VsockConnectionInfo {
    fd: RawFd,
    source_port: u32,
    destination_port: u32,
}

impl Drop for VsockConnectionInfo {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: self.fd is the dup'd fd this struct owns; -1 means it was
            // transferred out and must not be closed here.
            unsafe { libc::close(self.fd) };
        }
    }
}

type VsockResult = Result<VsockConnectionInfo, String>;

/// Shim callback trampoline: consumes the boxed sender exactly once.
///
/// On any abandonment (timed-out receiver dropped, or a late send that lands
/// in a channel no one reads) the `VsockConnectionInfo`'s drop closes the
/// dup'd fd, so no explicit close is needed here.
unsafe extern "C" fn vsock_trampoline(
    ctx: *mut c_void,
    fd: i32,
    src_port: u32,
    dst_port: u32,
    err: *mut c_char,
) {
    // SAFETY: ctx is the Box<Sender> leaked in connect_blocking; the shim
    // guarantees exactly-once invocation. err is null or a shim string that
    // take_error_string frees.
    unsafe {
        let sender = Box::from_raw(ctx as *mut std_mpsc::Sender<VsockResult>);
        let result = if err.is_null() {
            Ok(VsockConnectionInfo {
                fd,
                source_port: src_port,
                destination_port: dst_port,
            })
        } else {
            Err(shim_ffi::take_error_string(err))
        };
        // If the receiver is gone the result (and its owned fd) drops here and
        // closes the fd; if it sends successfully but is never received, the
        // channel's buffered value closes it when the channel drops.
        let _ = sender.send(result);
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
    /// ABXSocketDeviceBox handle (pairs the VZ device with the VM's queue).
    device_box: *mut c_void,
}

// SAFETY: The box handle is only used through the shim, which issues every
// device operation on the VM's dispatch queue.
unsafe impl Send for VirtioSocketDevice {}
// SAFETY: See above — all access goes through the VM's dispatch queue.
unsafe impl Sync for VirtioSocketDevice {}

impl VirtioSocketDevice {
    /// Creates a device wrapper from raw pointers.
    ///
    /// The caller must ensure that `ptr` is a valid `VZVirtioSocketDevice`
    /// and `queue` is the VM's dispatch queue.
    pub(crate) fn from_raw(ptr: *mut AnyObject, queue: *mut AnyObject) -> Self {
        // SAFETY: per the caller contract both pointers are valid; the shim
        // box retains them, released by Drop.
        let device_box =
            unsafe { shim_ffi::abx_socket_device_box_from_raw(ptr.cast(), queue.cast()) };
        Self { device_box }
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
        let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;

        // SAFETY: device_box is valid; ctx ownership transfers to the
        // exactly-once trampoline.
        unsafe {
            shim_ffi::abx_vsock_connect(self.device_box, port, ctx, vsock_trampoline);
        }

        match rx.recv_timeout(timeout) {
            Ok(Ok(mut info)) => {
                tracing::info!(
                    "Vsock connected: fd={}, src_port={}, dst_port={}",
                    info.fd,
                    info.source_port,
                    info.destination_port
                );
                // Transfer fd ownership to the connection; disarm info's drop
                // so it isn't double-closed.
                let fd = info.fd;
                info.fd = -1;
                Ok(VirtioSocketConnection {
                    fd,
                    source_port: info.source_port,
                    destination_port: info.destination_port,
                })
            }
            Ok(Err(message)) => {
                if is_transient_connect_error(&message) {
                    tracing::debug!(port, error = %message, "Vsock connection not ready yet");
                } else {
                    tracing::warn!(port, error = %message, "Vsock connection failed");
                }
                Err(VZError::ConnectionFailed(message))
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                // The completion may still fire later; the trampoline then
                // frees its context and closes the fd.
                tracing::warn!("Vsock connection timed out after {:?}", timeout);
                Err(VZError::Timeout(format!(
                    "Vsock connection to port {port} timed out"
                )))
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => Err(VZError::Internal {
                code: -1,
                message: "Connection channel closed unexpectedly".into(),
            }),
        }
    }
}

impl Drop for VirtioSocketDevice {
    fn drop(&mut self) {
        if !self.device_box.is_null() {
            // SAFETY: releasing the +1 box handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.device_box) };
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
