// Error/string/handle conventions shared by every export in Exports.swift.
//
// ABI contract with the Rust side (src/shim_ffi.rs):
// - Every C string handed to Rust is strdup'd here and freed by Rust via
//   abx_string_free. NULL means "no error" / "no value".
// - Opaque handles are Unmanaged object pointers: +1 (passRetained) when a
//   handle is returned to Rust, balanced by abx_object_release; borrowed
//   parameters use takeUnretainedValue and do not consume the +1.
// - ObjC exceptions are NOT caught anywhere in the shim: every throwing VZ
//   call site is precondition-guarded, so an NSException is a programmer
//   error and must crash loudly rather than unwind into Rust frames.

import Foundation

/// Mirrors `ABX_SHIM_ABI_VERSION` in src/shim_ffi.rs.
/// Bump BOTH on any change to an exported symbol's signature or semantics.
/// v2: abx_vm_new dropped its transitional raw vm/queue out-params.
let abxShimABIVersion: UInt32 = 2

/// Copies a Swift string into a malloc'd C string owned by the caller (Rust).
func abxStrdup(_ string: String) -> UnsafeMutablePointer<CChar>? {
    strdup(string)
}

/// Renders an error into a malloc'd C string owned by the caller (Rust).
func abxErrorString(_ error: Error) -> UnsafeMutablePointer<CChar>? {
    abxStrdup(error.localizedDescription)
}

/// Returns a +1 opaque handle for `object`; balanced by `abx_object_release`.
func abxRetainedHandle<T: AnyObject>(_ object: T) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(object).toOpaque()
}

/// Borrows the object behind a handle without consuming its +1.
func abxBorrow<T: AnyObject>(_ handle: UnsafeMutableRawPointer, as type: T.Type) -> T {
    Unmanaged<T>.fromOpaque(handle).takeUnretainedValue()
}
