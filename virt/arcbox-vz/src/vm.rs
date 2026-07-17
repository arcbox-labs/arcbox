//! Virtual machine runtime.

use crate::device::MemoryBalloonDevice;
use crate::error::{VZError, VZResult};
use crate::ffi::DispatchQueue;
use crate::socket::VirtioSocketDevice;
use objc2::runtime::AnyObject;
use std::ffi::c_void;
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
    /// ABXVMBox handle pairing the VM with its queue for shim calls.
    vm_box: *mut c_void,
}

// SAFETY: The VZ handles are properly synchronized through the dispatch queue.
unsafe impl Send for VirtualMachine {}
// SAFETY: See above — all VZ operations are dispatched to the VM's serial queue.
unsafe impl Sync for VirtualMachine {}

/// Shim lifecycle-completion trampoline: consumes the boxed sender exactly once.
unsafe extern "C" fn state_trampoline(ctx: *mut c_void, err: *mut std::ffi::c_char) {
    // SAFETY: ctx is the Box<Sender> leaked by the caller; the shim
    // guarantees exactly-once invocation. err is null or a shim string that
    // take_error_string frees.
    unsafe {
        let sender = Box::from_raw(ctx as *mut oneshot::Sender<Result<(), String>>);
        let result = if err.is_null() {
            Ok(())
        } else {
            Err(crate::shim_ffi::take_error_string(err))
        };
        let _ = sender.send(result);
    }
}

impl VirtualMachine {
    /// Creates a `VirtualMachine` from a shim box plus transitional raw views.
    ///
    /// This is called internally by `VirtualMachineConfiguration::build()`.
    /// `raw_vm`/`raw_queue` are borrows kept alive by `vm_box`; they exist
    /// only for the installer path and die with its migration.
    pub(crate) fn from_box(
        vm_box: *mut c_void,
        raw_vm: *mut AnyObject,
        raw_queue: *mut AnyObject,
    ) -> Self {
        Self {
            inner: raw_vm,
            // SAFETY: raw_queue is a valid dispatch queue kept alive by
            // vm_box; the wrapper is non-owning.
            queue: unsafe { DispatchQueue::from_raw(raw_queue) },
            vm_box,
        }
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
        // SAFETY: vm_box is a valid handle; the shim queue-syncs the read.
        VirtualMachineState::from(unsafe { crate::shim_ffi::abx_vm_state(self.vm_box) })
    }

    /// Returns whether the VM can be stopped.
    pub fn can_stop(&self) -> bool {
        // SAFETY: vm_box is a valid handle; the shim queue-syncs the read.
        unsafe { crate::shim_ffi::abx_vm_can_stop(self.vm_box) }
    }

    /// Returns whether the VM can be paused (internal pre-check for `pause`).
    fn can_pause(&self) -> bool {
        // SAFETY: vm_box is a valid handle; the shim queue-syncs the read.
        unsafe { crate::shim_ffi::abx_vm_can_pause(self.vm_box) }
    }

    /// Returns whether the VM can be resumed (internal pre-check for `resume`).
    fn can_resume(&self) -> bool {
        // SAFETY: vm_box is a valid handle; the shim queue-syncs the read.
        unsafe { crate::shim_ffi::abx_vm_can_resume(self.vm_box) }
    }

    /// Starts the virtual machine.
    ///
    /// This is an async operation that completes when the VM reaches
    /// the Running state.
    pub async fn start(&self) -> VZResult<()> {
        let (tx, rx) = oneshot::channel::<Result<(), String>>();
        let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;

        // SAFETY: vm_box is valid; ctx ownership transfers to the
        // exactly-once trampoline. Dropping this future before the callback
        // fires is leak-free: the trampoline consumes ctx and its send to the
        // dropped receiver fails harmlessly.
        unsafe {
            crate::shim_ffi::abx_vm_start(self.vm_box, ctx, state_trampoline);
        }

        let result = rx.await.map_err(|_| VZError::Internal {
            code: -1,
            message: "Start operation cancelled".into(),
        })?;

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

        let (tx, rx) = oneshot::channel::<Result<(), String>>();
        let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;
        // SAFETY: vm_box is valid; ctx ownership transfers to the
        // exactly-once trampoline. The completion fires when the VM has
        // stopped (or on error) per the VZ contract — no state polling.
        unsafe {
            crate::shim_ffi::abx_vm_stop(self.vm_box, ctx, state_trampoline);
        }

        let result = rx.await.map_err(|_| VZError::Internal {
            code: -1,
            message: "Stop operation cancelled".into(),
        })?;
        result.map_err(|msg| VZError::OperationFailed(format!("VM stop failed: {msg}")))
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

        let (tx, rx) = oneshot::channel::<Result<(), String>>();
        let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;
        // SAFETY: vm_box is valid; ctx ownership transfers to the
        // exactly-once trampoline. The completion fires once the VM is
        // paused (or on error) — no state polling.
        unsafe {
            crate::shim_ffi::abx_vm_pause(self.vm_box, ctx, state_trampoline);
        }

        let result = rx.await.map_err(|_| VZError::Internal {
            code: -1,
            message: "Pause operation cancelled".into(),
        })?;
        result.map_err(|msg| VZError::OperationFailed(format!("VM pause failed: {msg}")))
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

        let (tx, rx) = oneshot::channel::<Result<(), String>>();
        let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;
        // SAFETY: vm_box is valid; ctx ownership transfers to the
        // exactly-once trampoline. The completion fires once the VM is
        // running again (or on error) — no state polling.
        unsafe {
            crate::shim_ffi::abx_vm_resume(self.vm_box, ctx, state_trampoline);
        }

        let result = rx.await.map_err(|_| VZError::Internal {
            code: -1,
            message: "Resume operation cancelled".into(),
        })?;
        result.map_err(|msg| VZError::OperationFailed(format!("VM resume failed: {msg}")))
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
        // SAFETY: vm_box is valid; on failure the shim writes a strdup'd
        // message that take_error_string frees.
        unsafe {
            let mut error: *mut std::ffi::c_char = std::ptr::null_mut();
            if crate::shim_ffi::abx_vm_request_stop(self.vm_box, &mut error) {
                Ok(())
            } else {
                Err(VZError::OperationFailed(
                    crate::shim_ffi::take_error_string(error),
                ))
            }
        }
    }

    /// Returns the socket devices configured on this VM.
    ///
    /// These can be used for vsock communication with the guest.
    pub fn socket_devices(&self) -> Vec<VirtioSocketDevice> {
        // SAFETY: vm_box is valid; the shim queue-syncs the reads and hands
        // out +1 ABXSocketDeviceBox handles.
        unsafe {
            let count = crate::shim_ffi::abx_vm_socket_device_count(self.vm_box);
            (0..count)
                .filter_map(|i| {
                    let device_box = crate::shim_ffi::abx_vm_socket_device_at(self.vm_box, i);
                    (!device_box.is_null()).then(|| VirtioSocketDevice::from_box(device_box))
                })
                .collect()
        }
    }

    /// Returns the memory balloon devices configured on this VM.
    ///
    /// These can be used for dynamic memory management between host and guest.
    #[must_use]
    pub fn memory_balloon_devices(&self) -> Vec<MemoryBalloonDevice> {
        // SAFETY: vm_box is valid; the shim queue-syncs the reads and hands
        // out +1 ABXBalloonBox handles.
        unsafe {
            let count = crate::shim_ffi::abx_vm_balloon_count(self.vm_box);
            (0..count)
                .filter_map(|i| {
                    let balloon_box = crate::shim_ffi::abx_vm_balloon_at(self.vm_box, i);
                    (!balloon_box.is_null()).then(|| MemoryBalloonDevice::from_box(balloon_box))
                })
                .collect()
        }
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
        // `inner`/`queue` are borrows kept alive by the box — only the box's
        // +1 is ours to release.
        if !self.vm_box.is_null() {
            // SAFETY: releasing the +1 box handle returned by the shim.
            unsafe { crate::shim_ffi::abx_object_release(self.vm_box) };
        }
    }
}
