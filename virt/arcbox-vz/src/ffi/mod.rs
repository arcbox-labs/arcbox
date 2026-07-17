//! Low-level FFI bindings to Virtualization.framework.
//!
//! This module provides the raw Objective-C bindings used by the higher-level
//! safe API. Most users should not need to use this module directly.

pub mod block;
pub mod data;
pub mod dispatch;
pub mod foundation;
pub mod memory;
pub mod runloop;
pub mod runtime;

pub use block::*;
pub use data::*;
pub use dispatch::*;
pub use foundation::*;
pub use memory::*;
pub use runloop::*;
pub use runtime::*;

use crate::error::VZError;
use objc2::runtime::AnyObject;

// ============================================================================
// System Queries (served by the ArcBoxVZShim Swift static library)
// ============================================================================
//
// Virtualization.framework is linked at build time (build.rs emits
// `-framework Virtualization`), so it is loaded before main; the old runtime
// dlopen is gone and `get_class` lookups work unconditionally.

/// Checks if virtualization is supported on this system.
pub fn is_supported() -> bool {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { crate::shim_ffi::abx_vz_supported() }
}

/// Gets the maximum supported CPU count.
pub fn max_cpu_count() -> u64 {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { crate::shim_ffi::abx_vz_max_cpu_count() }
}

/// Gets the minimum supported CPU count.
pub fn min_cpu_count() -> u64 {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { crate::shim_ffi::abx_vz_min_cpu_count() }
}

/// Gets the maximum supported memory size.
pub fn max_memory_size() -> u64 {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { crate::shim_ffi::abx_vz_max_memory_size() }
}

/// Gets the minimum supported memory size.
pub fn min_memory_size() -> u64 {
    // SAFETY: shim reads a class property; no preconditions.
    unsafe { crate::shim_ffi::abx_vz_min_memory_size() }
}

// ============================================================================
// Error Handling
// ============================================================================

/// Extracts error information from an `NSError` object.
pub fn extract_nserror(error: *mut AnyObject) -> VZError {
    if error.is_null() {
        return VZError::Internal {
            code: -1,
            message: "Unknown error".to_string(),
        };
    }
    // SAFETY: error is checked non-null above. Sending localizedDescription and code to a valid NSError object.
    unsafe {
        let desc = msg_send!(error, localizedDescription);
        let code: i64 = msg_send_i64!(error, code);
        VZError::Internal {
            code: code as i32,
            message: nsstring_to_string(desc),
        }
    }
}

/// Builds a detailed description of an `NSError`.
///
/// Includes the domain, code, and `userInfo` dictionary, which surfaces the
/// underlying error and failure reason that `localizedDescription` alone hides.
#[must_use]
pub fn describe_nserror(error: *mut AnyObject) -> String {
    if error.is_null() {
        return "unknown error".to_string();
    }
    // SAFETY: error is non-null; localizedDescription/domain/userInfo and the userInfo
    // dictionary's description return objects owned by the error or autoreleased; read-only.
    unsafe {
        let desc = nsstring_to_string(msg_send!(error, localizedDescription));
        let code: i64 = msg_send_i64!(error, code);
        let domain = nsstring_to_string(msg_send!(error, domain));
        let info = msg_send!(error, userInfo);
        let info_str = if info.is_null() {
            String::new()
        } else {
            nsstring_to_string(msg_send!(info, description))
        };
        if info_str.is_empty() {
            format!("{desc} (domain={domain}, code={code})")
        } else {
            format!("{desc} (domain={domain}, code={code}); userInfo={info_str}")
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_supported() {
        let supported = is_supported();
        println!("Virtualization supported: {supported}");
    }

    #[test]
    fn test_cpu_limits() {
        if !is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }
        let min = min_cpu_count();
        let max = max_cpu_count();
        println!("CPU count: min={min}, max={max}");
        assert!(min > 0);
        assert!(max >= min);
    }

    #[test]
    fn test_memory_limits() {
        if !is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }
        let min = min_memory_size();
        let max = max_memory_size();
        println!(
            "Memory size: min={}MB, max={}MB",
            min / (1024 * 1024),
            max / (1024 * 1024)
        );
        assert!(min > 0);
        assert!(max >= min);
    }
}
