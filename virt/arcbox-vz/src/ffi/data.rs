//! `NSData` helpers.

use objc2::runtime::AnyObject;
use std::ffi::c_void;

use super::runtime::get_class;
use crate::msg_send;

/// Creates an `NSData` that owns a copy of `bytes`.
///
/// Returns a `+1`-retained object (`alloc` + `initWithBytes:length:`); the caller is
/// responsible for releasing it once any consumer has copied or retained the data.
pub fn nsdata_from_bytes(bytes: &[u8]) -> *mut AnyObject {
    // SAFETY: NSData is always available in the ObjC runtime. initWithBytes:length:
    // copies `len` bytes from the valid slice pointer; an empty slice yields empty data.
    unsafe {
        let cls = get_class("NSData").expect("NSData class not found");
        let alloc = msg_send!(cls, alloc);
        let sel = objc2::sel!(initWithBytes:length:);
        let func: unsafe extern "C" fn(
            *mut AnyObject,
            objc2::runtime::Sel,
            *const c_void,
            usize,
        ) -> *mut AnyObject = std::mem::transmute(super::runtime::objc_msgSend as *const c_void);
        func(alloc, sel, bytes.as_ptr() as *const c_void, bytes.len())
    }
}

/// Copies the contents of an `NSData` into a `Vec<u8>`.
///
/// Returns an empty vector when `obj` is null or empty. The `NSData` is only read;
/// its ownership is unchanged.
#[must_use]
pub fn nsdata_to_vec(obj: *mut AnyObject) -> Vec<u8> {
    if obj.is_null() {
        return Vec::new();
    }
    // SAFETY: obj is checked non-null. `length`/`bytes` return a buffer of `length`
    // bytes owned by the NSData and valid for the duration of this read.
    unsafe {
        let len_sel = objc2::sel!(length);
        let len_func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel) -> usize =
            std::mem::transmute(super::runtime::objc_msgSend as *const c_void);
        let len = len_func(obj as *const AnyObject, len_sel);
        if len == 0 {
            return Vec::new();
        }
        let bytes_sel = objc2::sel!(bytes);
        let bytes_func: unsafe extern "C" fn(
            *const AnyObject,
            objc2::runtime::Sel,
        ) -> *const c_void = std::mem::transmute(super::runtime::objc_msgSend as *const c_void);
        let ptr = bytes_func(obj as *const AnyObject, bytes_sel).cast::<u8>();
        if ptr.is_null() {
            return Vec::new();
        }
        std::slice::from_raw_parts(ptr, len).to_vec()
    }
}
