//! Objective-C Block handling for completion handlers.
//!
//! This module provides utilities for creating Objective-C blocks
//! that can be used as completion handlers in Virtualization.framework APIs.
//!
//! # Block ABI
//!
//! Blocks in Objective-C have a specific ABI. A block with captured variables
//! has the following layout:
//!
//! ```text
//! struct Block {
//!     isa: *const c_void,           // Class pointer (_NSConcreteStackBlock or _NSConcreteMallocBlock)
//!     flags: i32,                   // Block flags
//!     reserved: i32,                // Reserved
//!     invoke: fn(*const Block, ...), // Invoke function
//!     descriptor: *const Descriptor, // Block descriptor
//!     // Captured variables follow...
//! }
//! ```

use objc2::runtime::AnyObject;
use std::ffi::c_void;
use std::ptr;
use std::sync::mpsc as std_mpsc;
use tokio::sync::oneshot;

// ============================================================================
// Block Flags
// ============================================================================

/// Block has copy/dispose helpers.
const BLOCK_HAS_COPY_DISPOSE: i32 = 1 << 25;

// ============================================================================
// Block ABI Structures
// ============================================================================

/// Block descriptor structure (without helpers).
#[repr(C)]
pub struct BlockDescriptor {
    /// Reserved field.
    pub reserved: u64,
    /// Size of the block.
    pub size: u64,
}

/// Block descriptor structure with copy/dispose helpers.
#[repr(C)]
pub struct BlockDescriptorWithHelpers {
    /// Reserved field.
    pub reserved: u64,
    /// Size of the block.
    pub size: u64,
    /// Copy helper function.
    pub copy_helper: unsafe extern "C" fn(*mut c_void, *const c_void),
    /// Dispose helper function.
    pub dispose_helper: unsafe extern "C" fn(*mut c_void),
}

/// Block structure for completion handlers that take (`NSError` *).
#[repr(C)]
pub struct CompletionBlock {
    /// ISA pointer (class pointer).
    pub isa: *const c_void,
    /// Block flags.
    pub flags: i32,
    /// Reserved.
    pub reserved: i32,
    /// Invoke function pointer.
    pub invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
    /// Block descriptor.
    pub descriptor: *const BlockDescriptor,
}

// ============================================================================
// Vsock Block with Context
// ============================================================================

/// Result of a vsock connection.
pub struct VsockConnectionInfo {
    /// File descriptor for the connection.
    pub fd: i32,
    /// Source port.
    pub source_port: u32,
    /// Destination port.
    pub destination_port: u32,
}

/// Error from a vsock connection.
pub struct VsockConnectionError {
    /// Error message.
    pub message: String,
}

/// Result type for vsock connection.
pub type VsockResult = Result<VsockConnectionInfo, VsockConnectionError>;

/// Block structure for vsock completion with captured context.
///
/// This block captures a pointer to a `oneshot::Sender` that will receive
/// the connection result.
#[repr(C)]
pub struct VsockContextBlock {
    /// ISA pointer.
    pub isa: *const c_void,
    /// Block flags.
    pub flags: i32,
    /// Reserved.
    pub reserved: i32,
    /// Invoke function pointer.
    pub invoke: unsafe extern "C" fn(*mut Self, *mut AnyObject, *mut AnyObject),
    /// Block descriptor.
    pub descriptor: *const BlockDescriptorWithHelpers,
    /// Captured context: raw pointer to Box<`oneshot::Sender`<VsockResult>>.
    pub sender_ptr: *mut c_void,
}

/// Block structure for vsock completion with captured std sender.
///
/// Used by blocking host-side connect paths that must not re-enter Tokio.
#[repr(C)]
pub struct BlockingVsockContextBlock {
    /// ISA pointer.
    pub isa: *const c_void,
    /// Block flags.
    pub flags: i32,
    /// Reserved.
    pub reserved: i32,
    /// Invoke function pointer.
    pub invoke: unsafe extern "C" fn(*mut Self, *mut AnyObject, *mut AnyObject),
    /// Block descriptor.
    pub descriptor: *const BlockDescriptorWithHelpers,
    /// Captured context: raw pointer to Box<`std::sync::mpsc::Sender`<VsockResult>>.
    pub sender_ptr: *mut c_void,
}

/// Descriptor for `VsockContextBlock`.
static VSOCK_CONTEXT_BLOCK_DESCRIPTOR: BlockDescriptorWithHelpers = BlockDescriptorWithHelpers {
    reserved: 0,
    size: std::mem::size_of::<VsockContextBlock>() as u64,
    copy_helper: vsock_block_copy,
    dispose_helper: vsock_block_dispose,
};

/// Descriptor for `BlockingVsockContextBlock`.
static BLOCKING_VSOCK_CONTEXT_BLOCK_DESCRIPTOR: BlockDescriptorWithHelpers =
    BlockDescriptorWithHelpers {
        reserved: 0,
        size: std::mem::size_of::<BlockingVsockContextBlock>() as u64,
        copy_helper: blocking_vsock_block_copy,
        dispose_helper: blocking_vsock_block_dispose,
    };

/// Copy helper for `VsockContextBlock`.
///
/// When a block is copied from stack to heap, this function is called.
/// We don't need to do anything special since we're using raw pointers.
unsafe extern "C" fn vsock_block_copy(_dst: *mut c_void, _src: *const c_void) {
    // The sender_ptr is already a raw pointer, no need to copy
    // The ownership is transferred with the block
}

/// Copy helper for `BlockingVsockContextBlock`.
unsafe extern "C" fn blocking_vsock_block_copy(_dst: *mut c_void, _src: *const c_void) {}

/// Dispose helper for `VsockContextBlock`.
///
/// When a block is released, this function is called.
/// We need to drop the sender if it hasn't been used.
unsafe extern "C" fn vsock_block_dispose(block: *mut c_void) {
    // SAFETY: block is a valid VsockContextBlock pointer provided by the block runtime. sender_ptr is either null (already consumed) or a valid Box pointer from create_vsock_context_block.
    unsafe {
        let block = block as *mut VsockContextBlock;
        let sender_ptr = (*block).sender_ptr;
        if !sender_ptr.is_null() {
            // Drop the boxed sender
            let _ = Box::from_raw(sender_ptr as *mut oneshot::Sender<VsockResult>);
        }
    }
}

/// Dispose helper for `BlockingVsockContextBlock`.
unsafe extern "C" fn blocking_vsock_block_dispose(block: *mut c_void) {
    unsafe {
        let block = block as *mut BlockingVsockContextBlock;
        let sender_ptr = (*block).sender_ptr;
        if !sender_ptr.is_null() {
            let _ = Box::from_raw(sender_ptr as *mut std_mpsc::Sender<VsockResult>);
        }
    }
}

/// Invoke function for `VsockContextBlock`.
///
/// This is called when the block is invoked by Virtualization.framework.
unsafe extern "C" fn vsock_block_invoke(
    block: *mut VsockContextBlock,
    connection: *mut AnyObject,
    error: *mut AnyObject,
) {
    // SAFETY: block is a valid VsockContextBlock pointer invoked by Virtualization.framework. sender_ptr was set by create_vsock_context_block. We take ownership via Box::from_raw and null out the pointer to prevent double-free in dispose.
    unsafe {
        let sender_ptr = (*block).sender_ptr;
        if sender_ptr.is_null() {
            tracing::error!("vsock_block_invoke: sender_ptr is null");
            return;
        }

        // Take ownership of the sender (it will be consumed)
        let sender = Box::from_raw(sender_ptr as *mut oneshot::Sender<VsockResult>);
        // Clear the pointer so dispose won't double-free
        (*block).sender_ptr = ptr::null_mut();

        let result = if !error.is_null() {
            // Get error description
            let desc: *mut AnyObject = crate::msg_send!(error, localizedDescription);
            let message = crate::ffi::nsstring_to_string(desc);
            tracing::debug!("vsock connection error: {}", message);
            Err(VsockConnectionError { message })
        } else if !connection.is_null() {
            // Get file descriptor from VZVirtioSocketConnection
            let original_fd: i32 = crate::msg_send_i32!(connection, fileDescriptor);

            // IMPORTANT: We must dup() the fd because VZVirtioSocketConnection will close
            // the original fd when it's released (after this callback returns).
            let fd = libc::dup(original_fd);
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                tracing::error!("Failed to dup vsock fd: {}", err);
                let _ = sender.send(Err(VsockConnectionError {
                    message: format!("Failed to dup fd: {err}"),
                }));
                return;
            }
            tracing::debug!("Duplicated vsock fd: {} -> {}", original_fd, fd);

            // Get source and destination ports
            let src_port: u32 = {
                let sel = objc2::sel!(sourcePort);
                let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel) -> u32 =
                    std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
                func(connection as *const AnyObject, sel)
            };
            let dst_port: u32 = {
                let sel = objc2::sel!(destinationPort);
                let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel) -> u32 =
                    std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
                func(connection as *const AnyObject, sel)
            };

            tracing::debug!(
                "vsock connection success: fd={}, src_port={}, dst_port={}",
                fd,
                src_port,
                dst_port
            );

            Ok(VsockConnectionInfo {
                fd,
                source_port: src_port,
                destination_port: dst_port,
            })
        } else {
            tracing::error!("vsock_block_invoke: both connection and error are null");
            Err(VsockConnectionError {
                message: "Connection and error are both null".to_string(),
            })
        };

        // Send result (ignore error if receiver is dropped)
        let _ = sender.send(result);
    }
}

/// Invoke function for `BlockingVsockContextBlock`.
unsafe extern "C" fn blocking_vsock_block_invoke(
    block: *mut BlockingVsockContextBlock,
    connection: *mut AnyObject,
    error: *mut AnyObject,
) {
    unsafe {
        let sender_ptr = (*block).sender_ptr;
        if sender_ptr.is_null() {
            tracing::error!("blocking_vsock_block_invoke: sender_ptr is null");
            return;
        }

        let sender = Box::from_raw(sender_ptr as *mut std_mpsc::Sender<VsockResult>);
        (*block).sender_ptr = ptr::null_mut();

        let result = if !error.is_null() {
            let desc: *mut AnyObject = crate::msg_send!(error, localizedDescription);
            let message = crate::ffi::nsstring_to_string(desc);
            tracing::debug!("vsock connection error: {}", message);
            Err(VsockConnectionError { message })
        } else if !connection.is_null() {
            let original_fd: i32 = crate::msg_send_i32!(connection, fileDescriptor);
            let fd = libc::dup(original_fd);
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                tracing::error!("Failed to dup vsock fd: {}", err);
                let _ = sender.send(Err(VsockConnectionError {
                    message: format!("Failed to dup fd: {err}"),
                }));
                return;
            }
            tracing::debug!("Duplicated vsock fd: {} -> {}", original_fd, fd);

            let src_port: u32 = {
                let sel = objc2::sel!(sourcePort);
                let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel) -> u32 =
                    std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
                func(connection as *const AnyObject, sel)
            };
            let dst_port: u32 = {
                let sel = objc2::sel!(destinationPort);
                let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel) -> u32 =
                    std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
                func(connection as *const AnyObject, sel)
            };

            tracing::debug!(
                "vsock connection success: fd={}, src_port={}, dst_port={}",
                fd,
                src_port,
                dst_port
            );

            Ok(VsockConnectionInfo {
                fd,
                source_port: src_port,
                destination_port: dst_port,
            })
        } else {
            tracing::error!("blocking_vsock_block_invoke: both connection and error are null");
            Err(VsockConnectionError {
                message: "Connection and error are both null".to_string(),
            })
        };

        let _ = sender.send(result);
    }
}

/// Creates a vsock completion block with captured oneshot sender.
///
/// The returned block will send the connection result through the sender
/// when the block is invoked.
///
/// # Safety
///
/// The returned block must be used with Virtualization.framework's
/// `connectToPort:completionHandler:` method.
#[must_use]
pub fn create_vsock_context_block(sender: oneshot::Sender<VsockResult>) -> *const c_void {
    // Box the sender and get a raw pointer
    let sender_box = Box::new(sender);
    let sender_ptr = Box::into_raw(sender_box) as *mut c_void;

    // SAFETY: Constructing a stack block with the correct ABI layout (isa, flags, invoke, descriptor). _NSConcreteStackBlock is the correct ISA for stack-allocated blocks. _Block_copy copies it to the heap, making the returned pointer valid for the block's lifetime.
    unsafe {
        // Create block on stack
        let stack_block = VsockContextBlock {
            isa: _NSConcreteStackBlock,
            flags: BLOCK_HAS_COPY_DISPOSE,
            reserved: 0,
            invoke: vsock_block_invoke,
            descriptor: &VSOCK_CONTEXT_BLOCK_DESCRIPTOR,
            sender_ptr,
        };

        // Copy to heap
        _Block_copy(&stack_block as *const VsockContextBlock as *const c_void)
    }
}

/// Creates a vsock completion block with captured std sender.
#[must_use]
pub fn create_blocking_vsock_context_block(sender: std_mpsc::Sender<VsockResult>) -> *const c_void {
    let sender_box = Box::new(sender);
    let sender_ptr = Box::into_raw(sender_box) as *mut c_void;

    unsafe {
        let stack_block = BlockingVsockContextBlock {
            isa: _NSConcreteStackBlock,
            flags: BLOCK_HAS_COPY_DISPOSE,
            reserved: 0,
            invoke: blocking_vsock_block_invoke,
            descriptor: &BLOCKING_VSOCK_CONTEXT_BLOCK_DESCRIPTOR,
            sender_ptr,
        };

        _Block_copy(&stack_block as *const BlockingVsockContextBlock as *const c_void)
    }
}

// ============================================================================
// Lifecycle Completion Block (start / request_stop / pause / resume)
// ============================================================================

/// Result type for VM lifecycle operations that only report success / NSError.
pub type StateResult = Result<(), String>;

/// Block for VM lifecycle completion handlers.
///
/// Captures a oneshot sender so each async `start()` / `stop()` / `pause()`
/// / `resume()` call has its own private channel, avoiding the global-static
/// race that occurs when multiple VM instances issue lifecycle operations
/// concurrently.
#[repr(C)]
pub struct StateContextBlock {
    /// ISA pointer.
    pub isa: *const c_void,
    /// Block flags.
    pub flags: i32,
    /// Reserved.
    pub reserved: i32,
    /// Invoke function pointer — matches `(NSError *)` completion handler.
    pub invoke: unsafe extern "C" fn(*mut Self, *mut AnyObject),
    /// Block descriptor.
    pub descriptor: *const BlockDescriptorWithHelpers,
    /// Captured context: raw pointer to Box<`oneshot::Sender`<StateResult>>.
    pub sender_ptr: *mut c_void,
}

unsafe extern "C" fn state_block_copy(_dst: *mut c_void, _src: *const c_void) {
    // sender_ptr is a raw pointer; ownership transfers with the block copy.
}

unsafe extern "C" fn state_block_dispose(block: *mut c_void) {
    // SAFETY: `block` is a `StateContextBlock` pointer supplied by the block
    // runtime. `sender_ptr` is either null (already consumed by invoke) or a
    // valid Box pointer set by `create_state_completion_block`.
    unsafe {
        let block = block as *mut StateContextBlock;
        let sender_ptr = (*block).sender_ptr;
        if !sender_ptr.is_null() {
            let _ = Box::from_raw(sender_ptr as *mut oneshot::Sender<StateResult>);
        }
    }
}

unsafe extern "C" fn state_block_invoke(block: *mut StateContextBlock, error: *mut AnyObject) {
    // SAFETY: `block` is a valid `StateContextBlock` invoked by VZ. We take
    // ownership of the boxed sender via `Box::from_raw` and null the pointer
    // so dispose can't double-free.
    unsafe {
        let sender_ptr = (*block).sender_ptr;
        if sender_ptr.is_null() {
            return;
        }
        let sender = Box::from_raw(sender_ptr as *mut oneshot::Sender<StateResult>);
        (*block).sender_ptr = ptr::null_mut();

        let result = if error.is_null() {
            Ok(())
        } else {
            let desc: *mut AnyObject = crate::msg_send!(error, localizedDescription);
            Err(crate::ffi::nsstring_to_string(desc))
        };
        let _ = sender.send(result);
    }
}

/// Descriptor for `StateContextBlock`.
static STATE_CONTEXT_BLOCK_DESCRIPTOR: BlockDescriptorWithHelpers = BlockDescriptorWithHelpers {
    reserved: 0,
    size: std::mem::size_of::<StateContextBlock>() as u64,
    copy_helper: state_block_copy,
    dispose_helper: state_block_dispose,
};

/// Creates a lifecycle-completion block with a captured sender.
///
/// The caller passes the returned pointer to the VZ completion-handler API;
/// the block retains/releases itself according to normal block-runtime
/// semantics.
#[must_use]
pub fn create_state_completion_block(sender: oneshot::Sender<StateResult>) -> *const c_void {
    let sender_box = Box::new(sender);
    let sender_ptr = Box::into_raw(sender_box) as *mut c_void;

    // SAFETY: Stack block with correct ABI layout. `_Block_copy` heap-allocates
    // a copy and returns its pointer.
    unsafe {
        let stack_block = StateContextBlock {
            isa: _NSConcreteStackBlock,
            flags: BLOCK_HAS_COPY_DISPOSE,
            reserved: 0,
            invoke: state_block_invoke,
            descriptor: &STATE_CONTEXT_BLOCK_DESCRIPTOR,
            sender_ptr,
        };
        _Block_copy(&stack_block as *const StateContextBlock as *const c_void)
    }
}

// ============================================================================
// Block Runtime FFI
// ============================================================================

// SAFETY: These are well-known block runtime symbols provided by the system.
unsafe extern "C" {
    /// Global block ISA for stack blocks.
    pub static _NSConcreteStackBlock: *const c_void;

    /// Copy a block to the heap.
    pub fn _Block_copy(block: *const c_void) -> *const c_void;

    /// Release a block.
    pub fn _Block_release(block: *const c_void);
}

// ============================================================================
// Block Utilities
// ============================================================================

/// Wrapper for block pointers that are Send + Sync.
pub struct BlockPtr(pub *const c_void);

// SAFETY: BlockPtr wraps a heap-copied block pointer that is only used as an opaque handle passed to ObjC APIs. The block is created once and never mutated.
unsafe impl Send for BlockPtr {}
// SAFETY: See above — the block pointer is immutable after creation.
unsafe impl Sync for BlockPtr {}

/// Standard block descriptor for simple blocks.
pub static SIMPLE_BLOCK_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: 40, // Size of CompletionBlock
};

/// Creates a completion block and copies it to the heap.
///
/// # Safety
///
/// The returned block must eventually be released with `_Block_release`.
/// The `invoke` function must have the correct signature for the block type.
pub unsafe fn create_completion_block(
    invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
) -> *const c_void {
    // SAFETY: Constructing a stack block with correct ABI layout. _Block_copy copies to heap. Caller ensures the returned pointer is eventually released.
    unsafe {
        let stack_block = CompletionBlock {
            isa: _NSConcreteStackBlock,
            flags: 0,
            reserved: 0,
            invoke,
            descriptor: &SIMPLE_BLOCK_DESCRIPTOR,
        };

        _Block_copy(&stack_block as *const CompletionBlock as *const c_void)
    }
}
