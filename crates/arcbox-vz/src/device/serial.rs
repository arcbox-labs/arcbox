//! Serial port configuration.

use crate::error::{VZError, VZResult};
use crate::ffi::{file_handle_for_fd, get_class};
use crate::{msg_send, msg_send_void};
use objc2::runtime::AnyObject;
use std::os::unix::io::RawFd;

/// Configuration for a serial port.
pub struct SerialPortConfiguration {
    inner: *mut AnyObject,
    /// File descriptors for the serial port (read_fd, write_fd).
    fds: Option<(RawFd, RawFd)>,
}

unsafe impl Send for SerialPortConfiguration {}

impl SerialPortConfiguration {
    /// Creates a VirtIO console serial port configuration using pipes.
    ///
    /// This creates a serial port that appears as `hvc0` in the guest.
    /// Returns the configuration and the file descriptors for reading/writing.
    pub fn virtio_console() -> VZResult<Self> {
        // Create pipes for bidirectional communication
        let mut input_pipe: [libc::c_int; 2] = [0, 0];
        let mut output_pipe: [libc::c_int; 2] = [0, 0];

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

            // Create file handles
            // For VZ: read from input_pipe[0], write to output_pipe[1]
            let read_handle = file_handle_for_fd(input_pipe[0]);
            let write_handle = file_handle_for_fd(output_pipe[1]);

            if read_handle.is_null() || write_handle.is_null() {
                libc::close(input_pipe[0]);
                libc::close(input_pipe[1]);
                libc::close(output_pipe[0]);
                libc::close(output_pipe[1]);
                return Err(VZError::OperationFailed(
                    "Failed to create file handles".to_string(),
                ));
            }

            // Create serial port attachment
            let attachment = create_serial_port_attachment(read_handle, write_handle)?;

            // Create VirtIO console serial port configuration
            let cls = get_class("VZVirtioConsoleDeviceSerialPortConfiguration").ok_or_else(
                || VZError::Internal {
                    code: -1,
                    message: "VZVirtioConsoleDeviceSerialPortConfiguration class not found".into(),
                },
            )?;

            let port = msg_send!(cls, new);
            if port.is_null() {
                libc::close(input_pipe[0]);
                libc::close(input_pipe[1]);
                libc::close(output_pipe[0]);
                libc::close(output_pipe[1]);
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create serial port configuration".into(),
                });
            }

            msg_send_void!(port, setAttachment: attachment);

            // Store FDs for user access:
            // output_pipe[0] = read from VM
            // input_pipe[1] = write to VM
            Ok(Self {
                inner: port,
                fds: Some((output_pipe[0], input_pipe[1])),
            })
        }
    }

    /// Returns the file descriptor for reading output from the VM.
    pub fn read_fd(&self) -> Option<RawFd> {
        self.fds.map(|(r, _)| r)
    }

    /// Returns the file descriptor for writing input to the VM.
    pub fn write_fd(&self) -> Option<RawFd> {
        self.fds.map(|(_, w)| w)
    }

    /// Consumes the configuration and returns the raw pointer.
    ///
    /// Note: The file descriptors are NOT closed when this is called.
    /// The caller is responsible for managing them.
    pub fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for SerialPortConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            crate::ffi::release(self.inner);
        }
        // Note: We don't close fds here as they may still be in use
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn create_serial_port_attachment(
    read_handle: *mut AnyObject,
    write_handle: *mut AnyObject,
) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls =
            get_class("VZFileHandleSerialPortAttachment").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZFileHandleSerialPortAttachment class not found".into(),
            })?;

        let obj = msg_send!(cls, alloc);
        let attachment = msg_send!(obj, initWithFileHandleForReading: read_handle, fileHandleForWriting: write_handle);

        if attachment.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create serial port attachment".into(),
            });
        }

        Ok(attachment)
    }
}
