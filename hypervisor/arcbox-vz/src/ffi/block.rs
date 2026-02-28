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
use tokio::sync::oneshot;

// ============================================================================
// Block Flags
// ============================================================================

/// Block has copy/dispose helpers.
const BLOCK_HAS_COPY_DISPOSE: i32 = 1 << 25;

/// Block has a C++ style destructor.
#[allow(dead_code)]
const BLOCK_HAS_CTOR: i32 = 1 << 26;

/// Block is a global block.
#[allow(dead_code)]
const BLOCK_IS_GLOBAL: i32 = 1 << 28;

/// Block has a signature.
#[allow(dead_code)]
const BLOCK_HAS_SIGNATURE: i32 = 1 << 30;

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

/// Block structure for completion handlers that take (NSError *).
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

/// Block structure for vsock completion handlers that take (VZVirtioSocketConnection *, NSError *).
#[repr(C)]
pub struct VsockCompletionBlock {
    /// ISA pointer.
    pub isa: *const c_void,
    /// Block flags.
    pub flags: i32,
    /// Reserved.
    pub reserved: i32,
    /// Invoke function pointer.
    pub invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject, *mut AnyObject),
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
/// This block captures a pointer to a oneshot::Sender that will receive
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
    pub invoke: unsafe extern "C" fn(*mut VsockContextBlock, *mut AnyObject, *mut AnyObject),
    /// Block descriptor.
    pub descriptor: *const BlockDescriptorWithHelpers,
    /// Captured context: raw pointer to Box<oneshot::Sender<VsockResult>>.
    pub sender_ptr: *mut c_void,
}

/// Descriptor for VsockContextBlock.
static VSOCK_CONTEXT_BLOCK_DESCRIPTOR: BlockDescriptorWithHelpers = BlockDescriptorWithHelpers {
    reserved: 0,
    size: std::mem::size_of::<VsockContextBlock>() as u64,
    copy_helper: vsock_block_copy,
    dispose_helper: vsock_block_dispose,
};

/// Copy helper for VsockContextBlock.
///
/// When a block is copied from stack to heap, this function is called.
/// We don't need to do anything special since we're using raw pointers.
unsafe extern "C" fn vsock_block_copy(_dst: *mut c_void, _src: *const c_void) {
    // The sender_ptr is already a raw pointer, no need to copy
    // The ownership is transferred with the block
}

/// Dispose helper for VsockContextBlock.
///
/// When a block is released, this function is called.
/// We need to drop the sender if it hasn't been used.
unsafe extern "C" fn vsock_block_dispose(block: *mut c_void) {
    unsafe {
        let block = block as *mut VsockContextBlock;
        let sender_ptr = (*block).sender_ptr;
        if !sender_ptr.is_null() {
            // Drop the boxed sender
            let _ = Box::from_raw(sender_ptr as *mut oneshot::Sender<VsockResult>);
        }
    }
}

/// Invoke function for VsockContextBlock.
///
/// This is called when the block is invoked by Virtualization.framework.
unsafe extern "C" fn vsock_block_invoke(
    block: *mut VsockContextBlock,
    connection: *mut AnyObject,
    error: *mut AnyObject,
) {
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
                    message: format!("Failed to dup fd: {}", err),
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

/// Creates a vsock completion block with captured oneshot sender.
///
/// The returned block will send the connection result through the sender
/// when the block is invoked.
///
/// # Safety
///
/// The returned block must be used with Virtualization.framework's
/// `connectToPort:completionHandler:` method.
pub fn create_vsock_context_block(sender: oneshot::Sender<VsockResult>) -> *const c_void {
    // Box the sender and get a raw pointer
    let sender_box = Box::new(sender);
    let sender_ptr = Box::into_raw(sender_box) as *mut c_void;

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

// ============================================================================
// Block Runtime FFI
// ============================================================================

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

unsafe impl Send for BlockPtr {}
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

/// Creates a vsock completion block and copies it to the heap.
///
/// # Safety
///
/// The returned block must eventually be released with `_Block_release`.
#[allow(dead_code)]
pub unsafe fn create_vsock_completion_block(
    invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject, *mut AnyObject),
) -> *const c_void {
    unsafe {
        let stack_block = VsockCompletionBlock {
            isa: _NSConcreteStackBlock,
            flags: 0,
            reserved: 0,
            invoke,
            descriptor: &SIMPLE_BLOCK_DESCRIPTOR,
        };

        _Block_copy(&stack_block as *const VsockCompletionBlock as *const c_void)
    }
}
