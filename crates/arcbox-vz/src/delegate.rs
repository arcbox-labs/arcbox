//! Objective-C delegate implementations.
//!
//! This module provides delegate implementations for Virtualization.framework
//! callbacks using dynamically created Objective-C classes.

use objc2::ffi::{objc_allocateClassPair, objc_registerClassPair};
use objc2::runtime::{AnyClass, AnyObject, Bool, Sel};
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CString};
use std::sync::{Mutex, OnceLock};
use tokio::sync::mpsc;

// ============================================================================
// FFI Declarations
// ============================================================================

unsafe extern "C" {
    fn class_addMethod(
        cls: *const AnyClass,
        sel: Sel,
        imp: *const c_void,
        types: *const c_char,
    ) -> Bool;
    fn class_addIvar(
        cls: *const AnyClass,
        name: *const c_char,
        size: usize,
        alignment: u8,
        types: *const c_char,
    ) -> Bool;
    fn object_getInstanceVariable(
        obj: *mut AnyObject,
        name: *const c_char,
        outValue: *mut *mut c_void,
    ) -> *mut c_void;
    fn object_setInstanceVariable(
        obj: *mut AnyObject,
        name: *const c_char,
        value: *mut c_void,
    ) -> *mut c_void;
    fn sel_registerName(name: *const c_char) -> Sel;
}

// ============================================================================
// Listener Registry
// ============================================================================

/// Handle type for listener callbacks.
pub type ListenerHandle = u64;

/// Connection info sent through the channel.
pub struct IncomingConnection {
    /// File descriptor.
    pub fd: i32,
    /// Source port (from guest).
    pub source_port: u32,
    /// Destination port (host port we're listening on).
    pub destination_port: u32,
}

/// Entry in the listener registry.
struct ListenerEntry {
    /// Channel to send incoming connections.
    sender: mpsc::UnboundedSender<IncomingConnection>,
}

/// Global registry mapping listener handles to channels.
static LISTENER_REGISTRY: OnceLock<Mutex<HashMap<ListenerHandle, ListenerEntry>>> = OnceLock::new();

/// Next handle to assign.
static NEXT_HANDLE: OnceLock<Mutex<ListenerHandle>> = OnceLock::new();

fn get_registry() -> &'static Mutex<HashMap<ListenerHandle, ListenerEntry>> {
    LISTENER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_next_handle() -> ListenerHandle {
    let mut handle = NEXT_HANDLE.get_or_init(|| Mutex::new(1)).lock().unwrap();
    let h = *handle;
    *handle += 1;
    h
}

/// Registers a listener and returns a handle.
pub fn register_listener(
    sender: mpsc::UnboundedSender<IncomingConnection>,
) -> ListenerHandle {
    let handle = get_next_handle();
    let mut registry = get_registry().lock().unwrap();
    registry.insert(handle, ListenerEntry { sender });
    handle
}

/// Unregisters a listener.
pub fn unregister_listener(handle: ListenerHandle) {
    let mut registry = get_registry().lock().unwrap();
    registry.remove(&handle);
}

/// Sends a connection to the registered listener.
fn send_connection(handle: ListenerHandle, conn: IncomingConnection) -> bool {
    let registry = get_registry().lock().unwrap();
    if let Some(entry) = registry.get(&handle) {
        entry.sender.send(conn).is_ok()
    } else {
        tracing::warn!("Listener handle {} not found in registry", handle);
        false
    }
}

// ============================================================================
// VZVirtioSocketListenerDelegate Implementation
// ============================================================================

/// Wrapper for class pointer that implements Send + Sync.
struct ClassPtr(*const AnyClass);

// Safety: The class is registered once and never modified.
// Objective-C classes are thread-safe for reading.
unsafe impl Send for ClassPtr {}
unsafe impl Sync for ClassPtr {}

/// Class pointer for our delegate implementation.
static DELEGATE_CLASS: OnceLock<ClassPtr> = OnceLock::new();

/// Name of the ivar storing the handle.
const HANDLE_IVAR: &[u8] = b"_listenerHandle\0";

/// Gets or creates the delegate class.
pub fn get_delegate_class() -> *const AnyClass {
    DELEGATE_CLASS.get_or_init(|| {
        ClassPtr(unsafe { create_delegate_class() })
    }).0
}

/// Creates the VZSocketListenerDelegate Objective-C class dynamically.
unsafe fn create_delegate_class() -> *const AnyClass {
    unsafe {
        // Get NSObject as superclass
        let nsobj_name = CString::new("NSObject").unwrap();
        let superclass = objc2::ffi::objc_getClass(nsobj_name.as_ptr()) as *const AnyClass;

        // Create new class
        let class_name = CString::new("ArcBoxSocketListenerDelegate").unwrap();
        let new_class = objc_allocateClassPair(superclass, class_name.as_ptr(), 0);

        if new_class.is_null() {
            // Class might already exist (from previous run)
            let existing = objc2::ffi::objc_getClass(class_name.as_ptr()) as *const AnyClass;
            if !existing.is_null() {
                tracing::debug!("Delegate class already exists, reusing");
                return existing;
            }
            panic!("Failed to create delegate class");
        }

        // Add instance variable to store handle
        let ivar_type = CString::new("Q").unwrap(); // Q = unsigned long long (u64)
        let added = class_addIvar(
            new_class,
            HANDLE_IVAR.as_ptr() as *const c_char,
            std::mem::size_of::<ListenerHandle>(),
            std::mem::align_of::<ListenerHandle>() as u8,
            ivar_type.as_ptr(),
        );
        if !added.as_bool() {
            panic!("Failed to add handle ivar to delegate class");
        }

        // Add the delegate method
        // selector: listener:shouldAcceptNewConnection:fromSocketDevice:
        let sel_name = CString::new("listener:shouldAcceptNewConnection:fromSocketDevice:").unwrap();
        let sel = sel_registerName(sel_name.as_ptr());

        // Method signature: BOOL method(id self, SEL _cmd, id listener, id connection, id device)
        // Encoding: B@:@@@ (return BOOL, self, _cmd, 3 object args)
        let method_types = CString::new("B@:@@@").unwrap();
        let added = class_addMethod(
            new_class,
            sel,
            should_accept_connection as *const c_void,
            method_types.as_ptr(),
        );
        if !added.as_bool() {
            panic!("Failed to add delegate method");
        }

        // Register the class
        objc_registerClassPair(new_class);

        tracing::debug!("Created delegate class: ArcBoxSocketListenerDelegate");

        new_class as *const AnyClass
    }
}

/// The delegate method implementation.
///
/// Called when a guest connection comes in.
/// Signature: BOOL listener:shouldAcceptNewConnection:fromSocketDevice:
unsafe extern "C" fn should_accept_connection(
    this: *mut AnyObject,
    _cmd: Sel,
    _listener: *mut AnyObject,
    connection: *mut AnyObject,
    _device: *mut AnyObject,
) -> Bool {
    unsafe {
        tracing::debug!("should_accept_connection called");

        // Get the handle from instance variable
        let mut handle_ptr: *mut c_void = std::ptr::null_mut();
        object_getInstanceVariable(
            this,
            HANDLE_IVAR.as_ptr() as *const c_char,
            &mut handle_ptr,
        );
        let handle = handle_ptr as ListenerHandle;

        if handle == 0 {
            tracing::error!("Delegate has no handle set");
            return Bool::NO;
        }

        // Extract connection info
        if connection.is_null() {
            tracing::error!("Connection is null");
            return Bool::NO;
        }

        // Get file descriptor - MUST dup() it!
        let original_fd: i32 = crate::msg_send_i32!(connection, fileDescriptor);
        let fd = libc::dup(original_fd);
        if fd < 0 {
            tracing::error!("Failed to dup fd: {}", std::io::Error::last_os_error());
            return Bool::NO;
        }

        // Get ports
        let src_port: u32 = {
            let sel = objc2::sel!(sourcePort);
            let func: unsafe extern "C" fn(*const AnyObject, Sel) -> u32 =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            func(connection as *const AnyObject, sel)
        };
        let dst_port: u32 = {
            let sel = objc2::sel!(destinationPort);
            let func: unsafe extern "C" fn(*const AnyObject, Sel) -> u32 =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            func(connection as *const AnyObject, sel)
        };

        tracing::debug!(
            "Incoming connection: fd={} (dup from {}), src_port={}, dst_port={}",
            fd, original_fd, src_port, dst_port
        );

        // Send to channel
        let conn = IncomingConnection {
            fd,
            source_port: src_port,
            destination_port: dst_port,
        };

        if send_connection(handle, conn) {
            Bool::YES
        } else {
            // Channel closed, reject connection
            libc::close(fd);
            Bool::NO
        }
    }
}

// ============================================================================
// Delegate Instance Creation
// ============================================================================

/// Creates a new delegate instance with the given handle.
pub fn create_delegate_instance(handle: ListenerHandle) -> *mut AnyObject {
    unsafe {
        let cls = get_delegate_class();

        // Alloc and init
        let alloc_sel = objc2::sel!(alloc);
        let init_sel = objc2::sel!(init);

        let alloc_fn: unsafe extern "C" fn(*const AnyClass, Sel) -> *mut AnyObject =
            std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
        let instance = alloc_fn(cls, alloc_sel);

        let init_fn: unsafe extern "C" fn(*mut AnyObject, Sel) -> *mut AnyObject =
            std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
        let instance = init_fn(instance, init_sel);

        if instance.is_null() {
            panic!("Failed to create delegate instance");
        }

        // Set the handle ivar
        object_setInstanceVariable(
            instance,
            HANDLE_IVAR.as_ptr() as *const c_char,
            handle as *mut c_void,
        );

        tracing::debug!("Created delegate instance {:?} with handle {}", instance, handle);

        instance
    }
}
