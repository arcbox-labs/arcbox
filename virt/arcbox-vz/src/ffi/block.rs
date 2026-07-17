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
            Err(crate::ffi::describe_nserror(error))
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

/// Result of an async call that yields a retained object pointer or an error.
///
/// On success the pointer bits (`usize`) of the result object are returned; the
/// object is retained in the invoke handler so it outlives the callback, and the
/// receiver owns that `+1` reference.
pub type ObjectResult = Result<usize, String>;

/// Block for completion handlers shaped `(id result, NSError *error)`.
///
/// Captures a oneshot sender; on invoke it retains a non-null result object and
/// sends its pointer bits, or sends the error's localized description.
#[repr(C)]
pub struct ObjectContextBlock {
    /// ISA pointer.
    pub isa: *const c_void,
    /// Block flags.
    pub flags: i32,
    /// Reserved.
    pub reserved: i32,
    /// Invoke function pointer — matches `(id, NSError *)` completion handlers.
    pub invoke: unsafe extern "C" fn(*mut Self, *mut AnyObject, *mut AnyObject),
    /// Block descriptor.
    pub descriptor: *const BlockDescriptorWithHelpers,
    /// Captured context: raw pointer to Box<`oneshot::Sender`<ObjectResult>>.
    pub sender_ptr: *mut c_void,
}

unsafe extern "C" fn object_block_copy(_dst: *mut c_void, _src: *const c_void) {
    // sender_ptr is a raw pointer; ownership transfers with the block copy.
}

unsafe extern "C" fn object_block_dispose(block: *mut c_void) {
    // SAFETY: `block` is an `ObjectContextBlock` from the block runtime; `sender_ptr`
    // is null (already consumed) or a valid Box pointer from create_object_completion_block.
    unsafe {
        let block = block as *mut ObjectContextBlock;
        let sender_ptr = (*block).sender_ptr;
        if !sender_ptr.is_null() {
            let _ = Box::from_raw(sender_ptr as *mut oneshot::Sender<ObjectResult>);
        }
    }
}

unsafe extern "C" fn object_block_invoke(
    block: *mut ObjectContextBlock,
    object: *mut AnyObject,
    error: *mut AnyObject,
) {
    // SAFETY: `block` is a valid `ObjectContextBlock` invoked by VZ. We take ownership
    // of the boxed sender and null the pointer so dispose can't double-free. A non-null
    // result object is retained so it outlives this callback.
    unsafe {
        let sender_ptr = (*block).sender_ptr;
        if sender_ptr.is_null() {
            return;
        }
        let sender = Box::from_raw(sender_ptr as *mut oneshot::Sender<ObjectResult>);
        (*block).sender_ptr = ptr::null_mut();

        let result = if !error.is_null() {
            let desc: *mut AnyObject = crate::msg_send!(error, localizedDescription);
            Err(crate::ffi::nsstring_to_string(desc))
        } else if !object.is_null() {
            let _: *mut AnyObject = crate::msg_send!(object, retain);
            Ok(object as usize)
        } else {
            Err("completion handler received neither result nor error".to_string())
        };
        let _ = sender.send(result);
    }
}

/// Descriptor for `ObjectContextBlock`.
static OBJECT_CONTEXT_BLOCK_DESCRIPTOR: BlockDescriptorWithHelpers = BlockDescriptorWithHelpers {
    reserved: 0,
    size: std::mem::size_of::<ObjectContextBlock>() as u64,
    copy_helper: object_block_copy,
    dispose_helper: object_block_dispose,
};

/// Creates an `(id, NSError *)` completion block with a captured sender.
///
/// On invoke, a non-null result object is retained and its pointer bits are sent
/// through `sender`; the receiver owns that `+1` reference.
#[must_use]
pub fn create_object_completion_block(sender: oneshot::Sender<ObjectResult>) -> *const c_void {
    let sender_box = Box::new(sender);
    let sender_ptr = Box::into_raw(sender_box) as *mut c_void;

    // SAFETY: Stack block with the correct ABI layout; `_Block_copy` heap-copies it.
    unsafe {
        let stack_block = ObjectContextBlock {
            isa: _NSConcreteStackBlock,
            flags: BLOCK_HAS_COPY_DISPOSE,
            reserved: 0,
            invoke: object_block_invoke,
            descriptor: &OBJECT_CONTEXT_BLOCK_DESCRIPTOR,
            sender_ptr,
        };
        _Block_copy(&stack_block as *const ObjectContextBlock as *const c_void)
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
