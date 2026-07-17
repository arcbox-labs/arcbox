//! Objective-C runtime helpers.

use objc2::ffi::objc_getClass;
use objc2::runtime::AnyClass;

// ============================================================================
// Class Access
// ============================================================================

/// Gets an Objective-C class by name.
///
/// Virtualization.framework is linked at build time (build.rs), so its
/// classes are registered before `main` and lookups need no load step.
#[must_use]
pub fn get_class(name: &str) -> Option<&'static AnyClass> {
    let name_cstr = std::ffi::CString::new(name).ok()?;
    // SAFETY: objc_getClass returns null for unknown classes (checked below) or a valid class pointer that lives for the program's lifetime.
    unsafe {
        let cls = objc_getClass(name_cstr.as_ptr());
        if cls.is_null() {
            None
        } else {
            Some(&*(cls as *const AnyClass))
        }
    }
}

// ============================================================================
// Message Send Macros
// ============================================================================

// FFI function pointer for objc_msgSend.
#[allow(improper_ctypes)]
#[allow(missing_docs)]
// SAFETY: objc_msgSend is the ObjC message dispatch function, always available in the ObjC runtime.
unsafe extern "C" {
    pub fn objc_msgSend();
}

/// Sends a message to an object returning an object pointer.
#[macro_export]
macro_rules! msg_send {
    ($obj:expr, $sel:ident) => {{
        let sel = objc2::sel!($sel);
        let func: unsafe extern "C" fn(*const objc2::runtime::AnyObject, objc2::runtime::Sel) -> *mut objc2::runtime::AnyObject =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel)
    }};
    ($obj:expr, $sel:ident : $arg1:expr) => {{
        let sel = objc2::sel!($sel:);
        let func: unsafe extern "C" fn(*const objc2::runtime::AnyObject, objc2::runtime::Sel, *const std::ffi::c_void) -> *mut objc2::runtime::AnyObject =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel, $arg1 as *const _ as *const std::ffi::c_void)
    }};
    ($obj:expr, $sel:ident : $arg1:expr, $sel2:ident : $arg2:expr) => {{
        let sel = objc2::sel!($sel:$sel2:);
        let func: unsafe extern "C" fn(*const objc2::runtime::AnyObject, objc2::runtime::Sel, *const std::ffi::c_void, *const std::ffi::c_void) -> *mut objc2::runtime::AnyObject =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel, $arg1 as *const _ as *const std::ffi::c_void, $arg2 as *const _ as *const std::ffi::c_void)
    }};
}

/// Sends a message returning a u64.
#[macro_export]
macro_rules! msg_send_u64 {
    ($obj:expr, $sel:ident) => {{
        let sel = objc2::sel!($sel);
        let func: unsafe extern "C" fn(
            *const objc2::runtime::AnyObject,
            objc2::runtime::Sel,
        ) -> u64 =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel)
    }};
}

/// Sends a message returning an i64.
#[macro_export]
macro_rules! msg_send_i64 {
    ($obj:expr, $sel:ident) => {{
        let sel = objc2::sel!($sel);
        let func: unsafe extern "C" fn(
            *const objc2::runtime::AnyObject,
            objc2::runtime::Sel,
        ) -> i64 =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel)
    }};
}

/// Sends a message returning an i32.
#[macro_export]
macro_rules! msg_send_i32 {
    ($obj:expr, $sel:ident) => {{
        let sel = objc2::sel!($sel);
        let func: unsafe extern "C" fn(
            *const objc2::runtime::AnyObject,
            objc2::runtime::Sel,
        ) -> i32 =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel)
    }};
}

/// Sends a message returning void with u64 arg.
#[macro_export]
macro_rules! msg_send_void_u64 {
    ($obj:expr, $sel:ident : $arg:expr) => {{
        let sel = objc2::sel!($sel:);
        let func: unsafe extern "C" fn(*const objc2::runtime::AnyObject, objc2::runtime::Sel, u64) =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel, $arg)
    }};
}

/// Sends a message returning Bool.
#[macro_export]
macro_rules! msg_send_bool {
    ($obj:expr, $sel:ident) => {{
        let sel = objc2::sel!($sel);
        let func: unsafe extern "C" fn(*const objc2::runtime::AnyObject, objc2::runtime::Sel) -> objc2::runtime::Bool =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel)
    }};
    ($obj:expr, $sel:ident : $arg:expr) => {{
        let sel = objc2::sel!($sel:);
        let func: unsafe extern "C" fn(*const objc2::runtime::AnyObject, objc2::runtime::Sel, *mut *mut objc2::runtime::AnyObject) -> objc2::runtime::Bool =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel, $arg)
    }};
}

/// Sends a message with void return and a Bool argument.
#[macro_export]
macro_rules! msg_send_void_bool {
    ($obj:expr, $sel:ident : $arg:expr) => {{
        let sel = objc2::sel!($sel:);
        let func: unsafe extern "C" fn(*const objc2::runtime::AnyObject, objc2::runtime::Sel, objc2::runtime::Bool) =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel, $arg)
    }};
}

/// Sends a message with void return.
#[macro_export]
macro_rules! msg_send_void {
    ($obj:expr, $sel:ident : $arg:expr) => {{
        let sel = objc2::sel!($sel:);
        let func: unsafe extern "C" fn(*const objc2::runtime::AnyObject, objc2::runtime::Sel, *const std::ffi::c_void) =
            std::mem::transmute($crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void);
        func($obj as *const _ as *const objc2::runtime::AnyObject, sel, $arg as *const _ as *const std::ffi::c_void)
    }};
}

// Re-export macros at crate level
pub use msg_send;
pub use msg_send_bool;
pub use msg_send_i32;
pub use msg_send_i64;
pub use msg_send_u64;
pub use msg_send_void;
pub use msg_send_void_bool;
pub use msg_send_void_u64;
