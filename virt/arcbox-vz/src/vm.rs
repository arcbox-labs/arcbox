//! Virtual machine runtime.

use crate::device::{MemoryBalloonDevice, vm_memory_balloon_devices};
use crate::error::{VZError, VZResult};
use crate::ffi::{
    _Block_copy, _Block_release, _NSConcreteStackBlock, BlockPtr, DispatchQueue,
    SIMPLE_BLOCK_DESCRIPTOR, create_state_completion_block, extract_nserror, nsstring_to_string,
};
use crate::socket::VirtioSocketDevice;
use crate::{msg_send, msg_send_bool, msg_send_i64};
use objc2::runtime::AnyObject;
use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::oneshot;

// ============================================================================
// VM State
// ============================================================================

/// The execution state of a virtual machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum VirtualMachineState {
    /// The VM is stopped.
    Stopped = 0,
    /// The VM is running.
    Running = 1,
    /// The VM is paused.
    Paused = 2,
    /// The VM is in an error state.
    Error = 3,
    /// The VM is starting.
    Starting = 4,
    /// The VM is pausing.
    Pausing = 5,
    /// The VM is resuming.
    Resuming = 6,
    /// The VM is stopping.
    Stopping = 7,
    /// The VM is saving state (macOS 14+).
    Saving = 8,
    /// The VM is restoring state (macOS 14+).
    Restoring = 9,
}

impl From<i64> for VirtualMachineState {
    fn from(value: i64) -> Self {
        match value {
            0 => Self::Stopped,
            1 => Self::Running,
            2 => Self::Paused,
            3 => Self::Error,
            4 => Self::Starting,
            5 => Self::Pausing,
            6 => Self::Resuming,
            7 => Self::Stopping,
            8 => Self::Saving,
            9 => Self::Restoring,
            _ => Self::Error,
        }
    }
}

// ============================================================================
// Virtual Machine
// ============================================================================

/// A running virtual machine.
///
/// This represents a VM that has been created from a `VirtualMachineConfiguration`.
/// Use the async methods to control the VM lifecycle.
pub struct VirtualMachine {
    inner: *mut AnyObject,
    queue: DispatchQueue,
}

// SAFETY: The VZ handles are properly synchronized through the dispatch queue.
unsafe impl Send for VirtualMachine {}
// SAFETY: See above — all VZ operations are dispatched to the VM's serial queue.
unsafe impl Sync for VirtualMachine {}

impl VirtualMachine {
    /// Creates a `VirtualMachine` from raw pointers.
    ///
    /// This is called internally by `VirtualMachineConfiguration::build()`.
    pub(crate) fn from_raw(ptr: *mut AnyObject, queue: DispatchQueue) -> Self {
        Self { inner: ptr, queue }
    }

    /// Returns the underlying `VZVirtualMachine` pointer.
    pub(crate) fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }

    /// Runs `f` synchronously on the VM's dispatch queue.
    ///
    /// All operations on a `VZVirtualMachine` must be issued on the queue it was
    /// created with; this lets associated objects (such as the macOS installer)
    /// dispatch onto it.
    pub(crate) fn dispatch_sync<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.queue.sync(f)
    }

    /// Returns the current state of the VM.
    pub fn state(&self) -> VirtualMachineState {
        // SAFETY: self.inner is a valid VZVirtualMachine pointer; dispatched
        // onto the VM's queue (VZVirtualMachine properties are queue-affine
        // and assert when read from any other thread).
        self.queue.sync(|| unsafe {
            let state = msg_send_i64!(self.inner, state);
            VirtualMachineState::from(state)
        })
    }

    /// Returns whether the VM can be stopped.
    pub fn can_stop(&self) -> bool {
        // SAFETY: Sending canStop to a valid VZVirtualMachine on its queue.
        self.queue
            .sync(|| unsafe { msg_send_bool!(self.inner, canStop).as_bool() })
    }

    /// Returns whether the VM can be paused (internal pre-check for `pause`).
    fn can_pause(&self) -> bool {
        // SAFETY: Sending canPause to a valid VZVirtualMachine on its queue.
        self.queue
            .sync(|| unsafe { msg_send_bool!(self.inner, canPause).as_bool() })
    }

    /// Returns whether the VM can be resumed (internal pre-check for `resume`).
    fn can_resume(&self) -> bool {
        // SAFETY: Sending canResume to a valid VZVirtualMachine on its queue.
        self.queue
            .sync(|| unsafe { msg_send_bool!(self.inner, canResume).as_bool() })
    }

    /// Starts the virtual machine.
    ///
    /// This is an async operation that completes when the VM reaches
    /// the Running state.
    pub async fn start(&self) -> VZResult<()> {
        // Per-call oneshot; the block captures the sender so multiple
        // concurrent VM instances don't clobber each other's completion
        // state (unlike the previous global-static approach).
        let (tx, rx) = oneshot::channel::<crate::ffi::StateResult>();
        let block_ptr = create_state_completion_block(tx);

        let inner = self.inner;
        // SAFETY: Sending startWithCompletionHandler: to a valid VZVirtualMachine on its
        // dispatch queue; `block_ptr` is a freshly heap-copied block.
        self.queue.sync(|| unsafe {
            let sel = objc2::sel!(startWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel, *const c_void) =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            func(inner as *const AnyObject, sel, block_ptr);
        });

        // Wait for completion. The block will fire at most once; its dispose
        // helper cleans up the captured sender on any remaining reference.
        let result = rx.await.map_err(|_| VZError::Internal {
            code: -1,
            message: "Start operation cancelled".into(),
        })?;

        // Release our reference. VZ has retained its own copy; the block will
        // survive until VZ releases it too (normally right after invoke).
        // SAFETY: block_ptr was returned by create_state_completion_block and
        // has not been released elsewhere.
        unsafe { _Block_release(block_ptr) };

        result.map_err(|msg| VZError::Internal {
            code: -1,
            message: format!("VM start failed: {msg}"),
        })
    }

    /// Stops the virtual machine.
    ///
    /// **Warning**: This is a destructive operation. It stops the VM without
    /// giving the guest a chance to stop cleanly. Use `request_stop()` for
    /// a graceful shutdown.
    pub async fn stop(&self) -> VZResult<()> {
        if !self.can_stop() {
            return Err(VZError::InvalidState {
                expected: "can_stop=true".into(),
                actual: format!("state={:?}", self.state()),
            });
        }

        // For simplicity, use polling instead of completion handler
        let inner = self.inner;
        // SAFETY: Calling stopWithCompletionHandler: on a valid VZVirtualMachine on its dispatch
        // queue. ObjC exceptions are caught.
        let stop_dispatch: VZResult<()> = self.queue.sync(|| unsafe {
            // Create a simple completion block
            static STOP_BLOCK: OnceLock<BlockPtr> = OnceLock::new();

            let block_ptr = STOP_BLOCK.get_or_init(|| {
                #[repr(C)]
                struct CompletionBlock {
                    isa: *const c_void,
                    flags: i32,
                    reserved: i32,
                    invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
                    descriptor: *const crate::ffi::BlockDescriptor,
                }

                unsafe extern "C" fn stop_handler(_block: *const c_void, error: *mut AnyObject) {
                    // SAFETY: error is checked non-null. Sending localizedDescription to a valid NSError.
                    unsafe {
                        if !error.is_null() {
                            let desc = msg_send!(error, localizedDescription);
                            tracing::error!("VM stop failed: {}", nsstring_to_string(desc));
                        }
                    }
                }

                let stack_block = CompletionBlock {
                    isa: _NSConcreteStackBlock,
                    flags: 0,
                    reserved: 0,
                    invoke: stop_handler,
                    descriptor: &SIMPLE_BLOCK_DESCRIPTOR,
                };

                let heap_block =
                    _Block_copy(&stack_block as *const CompletionBlock as *const c_void);
                BlockPtr(heap_block)
            });

            let sel = objc2::sel!(stopWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel, *const c_void) =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            let result = objc2::exception::catch(std::panic::AssertUnwindSafe(|| {
                func(inner as *const AnyObject, sel, block_ptr.0);
            }));

            match result {
                Ok(()) => Ok(()),
                Err(exception) => {
                    let desc = match exception {
                        Some(exc) => {
                            let raw = &*exc as *const _ as *const AnyObject as *mut AnyObject;
                            crate::ffi::nsstring_to_string(msg_send!(raw, description))
                        }
                        None => "unknown ObjC exception (nil)".to_string(),
                    };
                    Err(VZError::Internal {
                        code: -2,
                        message: format!("VM stop threw ObjC exception: {desc}"),
                    })
                }
            }
        });
        stop_dispatch?;

        // Poll for stopped state
        let timeout = Duration::from_secs(10);
        let start = std::time::Instant::now();

        while self.state() != VirtualMachineState::Stopped {
            if start.elapsed() > timeout {
                return Err(VZError::Timeout("Stop operation timed out".into()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Pauses the virtual machine.
    ///
    /// The VM must be in the Running state. After pausing, the VM will be
    /// in the Paused state and can be resumed with `resume()`.
    pub async fn pause(&self) -> VZResult<()> {
        if !self.can_pause() {
            return Err(VZError::InvalidState {
                expected: "can_pause=true".into(),
                actual: format!("state={:?}", self.state()),
            });
        }

        let inner = self.inner;
        // SAFETY: Calling pauseWithCompletionHandler: on a valid VZVirtualMachine on its dispatch queue.
        self.queue.sync(|| unsafe {
            static PAUSE_BLOCK: OnceLock<BlockPtr> = OnceLock::new();

            let block_ptr = PAUSE_BLOCK.get_or_init(|| {
                #[repr(C)]
                struct CompletionBlock {
                    isa: *const c_void,
                    flags: i32,
                    reserved: i32,
                    invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
                    descriptor: *const crate::ffi::BlockDescriptor,
                }

                unsafe extern "C" fn pause_handler(_block: *const c_void, error: *mut AnyObject) {
                    // SAFETY: error is checked non-null. Sending localizedDescription to a valid NSError.
                    unsafe {
                        if !error.is_null() {
                            let desc = msg_send!(error, localizedDescription);
                            tracing::error!("VM pause failed: {}", nsstring_to_string(desc));
                        }
                    }
                }

                let stack_block = CompletionBlock {
                    isa: _NSConcreteStackBlock,
                    flags: 0,
                    reserved: 0,
                    invoke: pause_handler,
                    descriptor: &SIMPLE_BLOCK_DESCRIPTOR,
                };

                let heap_block =
                    _Block_copy(&stack_block as *const CompletionBlock as *const c_void);
                BlockPtr(heap_block)
            });

            let sel = objc2::sel!(pauseWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel, *const c_void) =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            func(inner as *const AnyObject, sel, block_ptr.0);
        });

        // Poll for paused state.
        let timeout = Duration::from_secs(10);
        let start = std::time::Instant::now();

        while self.state() != VirtualMachineState::Paused {
            if start.elapsed() > timeout {
                return Err(VZError::Timeout("Pause operation timed out".into()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Resumes a paused virtual machine.
    ///
    /// The VM must be in the Paused state. After resuming, the VM will
    /// return to the Running state.
    pub async fn resume(&self) -> VZResult<()> {
        if !self.can_resume() {
            return Err(VZError::InvalidState {
                expected: "can_resume=true".into(),
                actual: format!("state={:?}", self.state()),
            });
        }

        let inner = self.inner;
        // SAFETY: Calling resumeWithCompletionHandler: on a valid VZVirtualMachine on its dispatch queue.
        self.queue.sync(|| unsafe {
            static RESUME_BLOCK: OnceLock<BlockPtr> = OnceLock::new();

            let block_ptr = RESUME_BLOCK.get_or_init(|| {
                #[repr(C)]
                struct CompletionBlock {
                    isa: *const c_void,
                    flags: i32,
                    reserved: i32,
                    invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
                    descriptor: *const crate::ffi::BlockDescriptor,
                }

                unsafe extern "C" fn resume_handler(_block: *const c_void, error: *mut AnyObject) {
                    // SAFETY: error is checked non-null. Sending localizedDescription to a valid NSError.
                    unsafe {
                        if !error.is_null() {
                            let desc = msg_send!(error, localizedDescription);
                            tracing::error!("VM resume failed: {}", nsstring_to_string(desc));
                        }
                    }
                }

                let stack_block = CompletionBlock {
                    isa: _NSConcreteStackBlock,
                    flags: 0,
                    reserved: 0,
                    invoke: resume_handler,
                    descriptor: &SIMPLE_BLOCK_DESCRIPTOR,
                };

                let heap_block =
                    _Block_copy(&stack_block as *const CompletionBlock as *const c_void);
                BlockPtr(heap_block)
            });

            let sel = objc2::sel!(resumeWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel, *const c_void) =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            func(inner as *const AnyObject, sel, block_ptr.0);
        });

        // Poll for running state.
        let timeout = Duration::from_secs(10);
        let start = std::time::Instant::now();

        while self.state() != VirtualMachineState::Running {
            if start.elapsed() > timeout {
                return Err(VZError::Timeout("Resume operation timed out".into()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Requests a graceful stop, asking the guest to shut down cleanly.
    ///
    /// Unlike [`stop`](Self::stop), this gives the guest a chance to shut down. The
    /// request is issued on the VM's queue and returns once accepted; the VM
    /// transitions to `Stopped` asynchronously (poll [`state`](Self::state)).
    ///
    /// # Errors
    ///
    /// Returns an error if the guest cannot be asked to stop (for example, the VM is
    /// not running).
    pub fn request_stop(&self) -> VZResult<()> {
        let inner = self.inner;
        self.queue.sync(|| {
            // SAFETY: requestStopWithError: on a valid VZVirtualMachine; the error
            // out-parameter is written only when the call returns NO.
            unsafe {
                let mut error: *mut AnyObject = std::ptr::null_mut();
                if msg_send_bool!(inner, requestStopWithError: &mut error).as_bool() {
                    Ok(())
                } else {
                    Err(extract_nserror(error))
                }
            }
        })
    }

    /// Returns the socket devices configured on this VM.
    ///
    /// These can be used for vsock communication with the guest.
    pub fn socket_devices(&self) -> Vec<VirtioSocketDevice> {
        // SAFETY: Sending socketDevices to a valid VZVirtualMachine on its
        // queue (device-array properties are queue-affine). NSArray elements
        // are valid VZVirtioSocketDevice pointers retained by the framework.
        self.queue.sync(|| unsafe {
            let devices: *mut AnyObject = msg_send!(self.inner, socketDevices);
            if devices.is_null() {
                return Vec::new();
            }

            let count = crate::ffi::nsarray_count(devices);
            let mut result = Vec::with_capacity(count);

            for i in 0..count {
                let device = crate::ffi::nsarray_object_at_index(devices, i);
                if !device.is_null() {
                    result.push(VirtioSocketDevice::from_raw(device, self.queue.as_ptr()));
                }
            }

            result
        })
    }

    /// Returns the memory balloon devices configured on this VM.
    ///
    /// These can be used for dynamic memory management between host and guest.
    #[must_use]
    pub fn memory_balloon_devices(&self) -> Vec<MemoryBalloonDevice> {
        self.queue
            .sync(|| vm_memory_balloon_devices(self.inner, self.queue.as_ptr()))
    }

    /// Returns the first memory balloon device, if any.
    ///
    /// This is a convenience method for VMs with a single balloon device.
    #[must_use]
    pub fn first_balloon_device(&self) -> Option<MemoryBalloonDevice> {
        self.memory_balloon_devices().into_iter().next()
    }
}

impl Drop for VirtualMachine {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            crate::ffi::release(self.inner);
        }
    }
}
