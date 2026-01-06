//! Vsock communication with the guest.
//!
//! This module provides types for communicating with the guest VM
//! via virtio-vsock.
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), arcbox_vz::VZError> {
//! use arcbox_vz::VirtualMachine;
//!
//! // Get socket device from running VM
//! # let vm: VirtualMachine = todo!();
//! let devices = vm.socket_devices();
//! let device = &devices[0];
//!
//! // Connect to guest port 1024
//! let conn = device.connect(1024).await?;
//! println!("Connected! fd={}", conn.as_raw_fd());
//! # Ok(())
//! # }
//! ```

use crate::delegate::{
    create_delegate_instance, register_listener, unregister_listener, IncomingConnection,
    ListenerHandle,
};
use crate::error::{VZError, VZResult};
use crate::ffi::block::{create_vsock_context_block, VsockResult, _Block_release};
use crate::ffi::get_class;
use crate::msg_send;
use objc2::runtime::AnyObject;
use std::ffi::c_void;
use std::os::unix::io::RawFd;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

// ============================================================================
// FFI Declarations
// ============================================================================

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

/// Context passed to dispatch_async_f for vsock connection.
struct ConnectContext {
    /// Socket device pointer.
    device: *mut AnyObject,
    /// Port to connect to.
    port: u32,
    /// Block pointer (will be released after use).
    block: *const c_void,
}

// Safety: The pointers are only used on the VM's dispatch queue
unsafe impl Send for ConnectContext {}

/// Work function executed on VM's dispatch queue.
unsafe extern "C" fn connect_work(ctx: *mut c_void) {
    unsafe {
        let context = Box::from_raw(ctx as *mut ConnectContext);

        tracing::debug!(
            "connect_work: calling connectToPort:{} on device {:?}",
            context.port,
            context.device
        );

        // Call [device connectToPort:port completionHandler:block]
        let sel = objc2::sel!(connectToPort:completionHandler:);
        let func: unsafe extern "C" fn(
            *mut AnyObject,
            objc2::runtime::Sel,
            u32,
            *const c_void,
        ) = std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);

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

unsafe impl Send for VirtioSocketDevice {}
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

    /// Connects to a port on the guest.
    ///
    /// This initiates a connection to the specified port on the guest VM.
    /// The guest must have a service listening on that port.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to connect to (e.g., 1024 for arcbox-agent)
    ///
    /// # Returns
    ///
    /// A `VirtioSocketConnection` that can be used for reading and writing.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection times out (10 seconds)
    /// - The guest is not listening on the specified port
    /// - The VM is not in a running state
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example(device: &arcbox_vz::VirtioSocketDevice) -> Result<(), arcbox_vz::VZError> {
    /// let conn = device.connect(1024).await?;
    /// println!("Connected to port 1024, fd={}", conn.as_raw_fd());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(&self, port: u32) -> VZResult<VirtioSocketConnection> {
        tracing::debug!("VirtioSocketDevice::connect(port={})", port);

        // Create oneshot channel for receiving result
        let (tx, rx) = oneshot::channel::<VsockResult>();

        // Create block with captured sender
        let block = create_vsock_context_block(tx);

        tracing::debug!("Created vsock context block: {:?}", block);

        // Create context for dispatch
        let context = Box::new(ConnectContext {
            device: self.inner,
            port,
            block,
        });
        let context_ptr = Box::into_raw(context);

        // Dispatch connection to VM queue
        // CRITICAL: Must use dispatch_async, not dispatch_sync
        // The completion handler will be called on the same queue
        unsafe {
            tracing::debug!(
                "Dispatching connect to VM queue {:?}",
                self.queue
            );
            dispatch_async_f(self.queue, context_ptr as *mut c_void, connect_work);
        }

        // Wait for result with timeout
        let timeout = Duration::from_secs(10);

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => {
                // Release the block now that we're done
                unsafe {
                    _Block_release(block);
                }

                match result {
                    Ok(info) => {
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
                    Err(e) => {
                        tracing::warn!("Vsock connection failed: {}", e.message);
                        Err(VZError::ConnectionFailed(e.message))
                    }
                }
            }
            Ok(Err(_)) => {
                // Channel was closed without sending (shouldn't happen)
                unsafe {
                    _Block_release(block);
                }
                Err(VZError::Internal {
                    code: -1,
                    message: "Connection channel closed unexpectedly".into(),
                })
            }
            Err(_) => {
                // Timeout
                // Note: The block may still be called later, but the sender is dropped
                // so it will just fail to send
                tracing::warn!("Vsock connection timed out after {:?}", timeout);
                Err(VZError::Timeout(format!(
                    "Vsock connection to port {} timed out",
                    port
                )))
            }
        }
    }

    /// Listens for incoming connections on a port.
    ///
    /// This sets up a listener for the specified port. When a guest initiates
    /// a connection to this port, the connection will be available through
    /// the returned `VirtioSocketListener`.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to listen on (e.g., 1024 for arcbox-agent)
    ///
    /// # Returns
    ///
    /// A `VirtioSocketListener` that can accept incoming connections.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example(device: &arcbox_vz::VirtioSocketDevice) -> Result<(), arcbox_vz::VZError> {
    /// let mut listener = device.listen(1024)?;
    /// println!("Listening on port 1024");
    ///
    /// // Accept incoming connection
    /// let conn = listener.accept().await?;
    /// println!("Connection accepted, fd={}", conn.as_raw_fd());
    /// # Ok(())
    /// # }
    /// ```
    pub fn listen(&self, port: u32) -> VZResult<VirtioSocketListener> {
        tracing::debug!("VirtioSocketDevice::listen(port={})", port);

        unsafe {
            // Create VZVirtioSocketListener object
            let listener_cls = get_class("VZVirtioSocketListener").ok_or_else(|| {
                VZError::Internal {
                    code: -1,
                    message: "VZVirtioSocketListener class not found".into(),
                }
            })?;
            let listener_obj: *mut AnyObject = msg_send!(listener_cls, new);
            if listener_obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create VZVirtioSocketListener".into(),
                });
            }

            // Create channel for incoming connections
            let (tx, rx) = mpsc::unbounded_channel::<IncomingConnection>();

            // Register listener and get handle
            let handle = register_listener(tx);

            // Create delegate instance with handle
            let delegate = create_delegate_instance(handle);
            if delegate.is_null() {
                unregister_listener(handle);
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create delegate instance".into(),
                });
            }

            // Set delegate on listener: [listener setDelegate:delegate]
            tracing::debug!("Setting delegate {:?} on listener {:?}", delegate, listener_obj);
            let set_delegate_sel = objc2::sel!(setDelegate:);
            let set_delegate_fn: unsafe extern "C" fn(
                *mut AnyObject,
                objc2::runtime::Sel,
                *mut AnyObject,
            ) = std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            set_delegate_fn(listener_obj, set_delegate_sel, delegate);
            tracing::debug!("Delegate set successfully");

            // Register listener with socket device: [device setSocketListener:listener forPort:port]
            // IMPORTANT: This must be called on the VM's dispatch queue
            tracing::debug!(
                "Calling setSocketListener:forPort: on device {:?} via dispatch queue {:?}",
                self.inner,
                self.queue
            );

            // Create context for dispatch
            struct SetListenerContext {
                device: *mut AnyObject,
                listener: *mut AnyObject,
                port: u32,
            }
            unsafe impl Send for SetListenerContext {}

            unsafe extern "C" fn set_listener_work(ctx: *mut c_void) {
                unsafe {
                    let context = Box::from_raw(ctx as *mut SetListenerContext);
                    tracing::debug!(
                        "set_listener_work: device={:?}, listener={:?}, port={}",
                        context.device,
                        context.listener,
                        context.port
                    );

                    let set_listener_sel = objc2::sel!(setSocketListener:forPort:);
                    let set_listener_fn: unsafe extern "C" fn(
                        *mut AnyObject,
                        objc2::runtime::Sel,
                        *mut AnyObject,
                        u32,
                    ) = std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
                    set_listener_fn(
                        context.device,
                        set_listener_sel,
                        context.listener,
                        context.port,
                    );
                    tracing::debug!("set_listener_work completed");
                }
            }

            let context = Box::new(SetListenerContext {
                device: self.inner,
                listener: listener_obj,
                port,
            });
            let context_ptr = Box::into_raw(context);

            // Use dispatch_sync_f to wait for completion
            unsafe extern "C" {
                fn dispatch_sync_f(
                    queue: *mut AnyObject,
                    context: *mut c_void,
                    work: unsafe extern "C" fn(*mut c_void),
                );
            }

            dispatch_sync_f(self.queue, context_ptr as *mut c_void, set_listener_work);
            tracing::debug!("setSocketListener completed");

            tracing::info!("Listening on port {} with handle {}", port, handle);

            Ok(VirtioSocketListener {
                port,
                handle,
                receiver: rx,
                listener_obj,
                delegate,
            })
        }
    }

    /// Removes a listener for a specific port.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to stop listening on
    pub fn remove_listener(&self, port: u32) {
        tracing::debug!("VirtioSocketDevice::remove_listener(port={})", port);

        unsafe {
            // [device setSocketListener:nil forPort:port]
            let set_listener_sel = objc2::sel!(setSocketListener:forPort:);
            let set_listener_fn: unsafe extern "C" fn(
                *mut AnyObject,
                objc2::runtime::Sel,
                *mut AnyObject,
                u32,
            ) = std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            set_listener_fn(self.inner, set_listener_sel, std::ptr::null_mut(), port);
        }
    }
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
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the source port (assigned by the framework).
    #[inline]
    pub fn source_port(&self) -> u32 {
        self.source_port
    }

    /// Returns the destination port (the port we connected to).
    #[inline]
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
    pub fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

impl Drop for VirtioSocketConnection {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

// ============================================================================
// Virtio Socket Listener
// ============================================================================

/// A listener for incoming vsock connections from the guest.
///
/// This allows the host to accept connections initiated by the guest.
/// Use `accept()` to wait for and receive incoming connections.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example(device: &arcbox_vz::VirtioSocketDevice) -> Result<(), arcbox_vz::VZError> {
/// let mut listener = device.listen(1024)?;
///
/// loop {
///     let conn = listener.accept().await?;
///     println!("New connection from guest: fd={}", conn.as_raw_fd());
///     // Handle connection...
/// }
/// # }
/// ```
///
/// # Cleanup
///
/// When the listener is dropped, it automatically:
/// - Unregisters from the socket device
/// - Closes the accept channel
/// - Cleans up Objective-C objects
pub struct VirtioSocketListener {
    /// Port we're listening on.
    port: u32,
    /// Handle in the listener registry.
    handle: ListenerHandle,
    /// Channel receiver for incoming connections.
    receiver: mpsc::UnboundedReceiver<IncomingConnection>,
    /// VZVirtioSocketListener object.
    listener_obj: *mut AnyObject,
    /// Delegate object.
    delegate: *mut AnyObject,
}

// Safety: The Objective-C objects are only accessed from the main thread
// through Virtualization.framework's internal dispatch queue.
unsafe impl Send for VirtioSocketListener {}

impl VirtioSocketListener {
    /// Returns the port this listener is bound to.
    #[inline]
    pub fn port(&self) -> u32 {
        self.port
    }

    /// Accepts an incoming connection from the guest.
    ///
    /// This method waits for a guest to connect to the port this listener
    /// is bound to.
    ///
    /// # Returns
    ///
    /// A `VirtioSocketConnection` representing the established connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener has been closed.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example(mut listener: arcbox_vz::VirtioSocketListener) -> Result<(), arcbox_vz::VZError> {
    /// let conn = listener.accept().await?;
    /// println!("Accepted connection: fd={}, src_port={}", conn.as_raw_fd(), conn.source_port());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn accept(&mut self) -> VZResult<VirtioSocketConnection> {
        match self.receiver.recv().await {
            Some(incoming) => {
                tracing::debug!(
                    "Accepted connection: fd={}, src={}, dst={}",
                    incoming.fd,
                    incoming.source_port,
                    incoming.destination_port
                );
                Ok(VirtioSocketConnection {
                    fd: incoming.fd,
                    source_port: incoming.source_port,
                    destination_port: incoming.destination_port,
                })
            }
            None => {
                // Channel closed
                Err(VZError::OperationFailed("Listener closed".into()))
            }
        }
    }

    /// Tries to accept a connection without blocking.
    ///
    /// Returns `None` if no connection is available.
    pub fn try_accept(&mut self) -> Option<VirtioSocketConnection> {
        match self.receiver.try_recv() {
            Ok(incoming) => Some(VirtioSocketConnection {
                fd: incoming.fd,
                source_port: incoming.source_port,
                destination_port: incoming.destination_port,
            }),
            Err(_) => None,
        }
    }
}

impl Drop for VirtioSocketListener {
    fn drop(&mut self) {
        tracing::debug!("Dropping VirtioSocketListener for port {}", self.port);

        // Note: VZVirtioSocketDevice doesn't have a removeSocketListener method.
        // Setting nil is not allowed. The listener will be cleaned up when the
        // VM is stopped. We just need to:
        // 1. Unregister from our callback registry (so we don't send to closed channel)
        // 2. Release the Objective-C objects

        // Unregister from callback registry first
        unregister_listener(self.handle);

        // Release Objective-C objects
        if !self.listener_obj.is_null() {
            crate::ffi::release(self.listener_obj);
        }
        if !self.delegate.is_null() {
            crate::ffi::release(self.delegate);
        }

        tracing::debug!("VirtioSocketListener dropped for port {}", self.port);
    }
}
