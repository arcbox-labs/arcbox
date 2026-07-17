//! Serial port configuration.

use crate::error::{VZError, VZResult};
use crate::shim_ffi;
use std::ffi::c_void;
use std::os::unix::io::RawFd;

/// Configuration for a serial port.
pub struct SerialPortConfiguration {
    inner: *mut c_void,
    /// File descriptors for the serial port (`read_fd`, `write_fd`).
    fds: Option<(RawFd, RawFd)>,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for SerialPortConfiguration {}

impl SerialPortConfiguration {
    /// Creates a `VirtIO` console serial port configuration using pipes.
    ///
    /// This creates a serial port that appears as `hvc0` in the guest.
    /// Returns the configuration and the file descriptors for reading/writing.
    pub fn virtio_console() -> VZResult<Self> {
        // Pipes are created and owned on the Rust side; the shim only wraps
        // the VZ-facing ends in FileHandles (without closing them).
        let mut input_pipe: [libc::c_int; 2] = [0, 0];
        let mut output_pipe: [libc::c_int; 2] = [0, 0];

        // SAFETY: libc::pipe writes two valid fds on success.
        unsafe {
            if libc::pipe(input_pipe.as_mut_ptr()) != 0 {
                return Err(VZError::OperationFailed(
                    "Failed to create input pipe".to_string(),
                ));
            }
            if libc::pipe(output_pipe.as_mut_ptr()) != 0 {
                libc::close(input_pipe[0]);
                libc::close(input_pipe[1]);
                return Err(VZError::OperationFailed(
                    "Failed to create output pipe".to_string(),
                ));
            }
        }

        // VZ reads guest input from input_pipe[0] and writes guest output to
        // output_pipe[1].
        // SAFETY: both fds are valid; the shim returns a +1 handle.
        let obj = unsafe { shim_ffi::abx_serial_console_new(input_pipe[0], output_pipe[1]) };

        // Host-side ends: read guest output from output_pipe[0], write guest
        // input to input_pipe[1].
        Ok(Self {
            inner: obj,
            fds: Some((output_pipe[0], input_pipe[1])),
        })
    }

    /// Returns the file descriptor for reading output from the VM.
    #[must_use]
    pub fn read_fd(&self) -> Option<RawFd> {
        self.fds.map(|(r, _)| r)
    }

    /// Returns the file descriptor for writing input to the VM.
    #[must_use]
    pub fn write_fd(&self) -> Option<RawFd> {
        self.fds.map(|(_, w)| w)
    }

    /// Consumes the configuration and returns the raw pointer.
    ///
    /// Note: The file descriptors are NOT closed when this is called.
    /// The caller is responsible for managing them.
    #[must_use]
    pub(crate) fn into_ptr(self) -> *mut c_void {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for SerialPortConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
        // Note: We don't close fds here as they may still be in use
    }
}
