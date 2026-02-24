//! Low-level FFI bindings to Virtualization.framework.
//!
//! This module provides the raw Objective-C bindings used by the higher-level
//! safe API. Most users should not need to use this module directly.

pub mod block;
pub mod dispatch;
pub mod foundation;
pub mod memory;
pub mod runloop;
pub mod runtime;

pub use block::*;
pub use dispatch::*;
pub use foundation::*;
pub use memory::*;
pub use runloop::*;
pub use runtime::*;

use crate::error::VZError;
use objc2::runtime::AnyObject;
use std::sync::Once;

// ============================================================================
// Framework Loading
// ============================================================================

static FRAMEWORK_INIT: Once = Once::new();

/// Ensures Virtualization.framework is loaded.
fn ensure_framework_loaded() {
    FRAMEWORK_INIT.call_once(|| unsafe {
        let path = std::ffi::CString::new(
            "/System/Library/Frameworks/Virtualization.framework/Virtualization",
        )
        .unwrap();
        let handle = libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if handle.is_null() {
            let err = libc::dlerror();
            if !err.is_null() {
                let err_str = std::ffi::CStr::from_ptr(err).to_string_lossy();
                tracing::error!("Failed to load Virtualization.framework: {}", err_str);
            }
        } else {
            tracing::debug!("Virtualization.framework loaded successfully");
        }
    });
}

// ============================================================================
// System Queries
// ============================================================================

/// Checks if virtualization is supported on this system.
pub fn is_supported() -> bool {
    ensure_framework_loaded();
    unsafe {
        let cls = match get_class("VZVirtualMachine") {
            Some(c) => c,
            None => return false,
        };
        msg_send_bool!(cls, isSupported).as_bool()
    }
}

/// Gets the maximum supported CPU count.
pub fn max_cpu_count() -> u64 {
    ensure_framework_loaded();
    unsafe {
        let cls = get_class("VZVirtualMachineConfiguration").unwrap();
        msg_send_u64!(cls, maximumAllowedCPUCount)
    }
}

/// Gets the minimum supported CPU count.
pub fn min_cpu_count() -> u64 {
    ensure_framework_loaded();
    unsafe {
        let cls = get_class("VZVirtualMachineConfiguration").unwrap();
        msg_send_u64!(cls, minimumAllowedCPUCount)
    }
}

/// Gets the maximum supported memory size.
pub fn max_memory_size() -> u64 {
    ensure_framework_loaded();
    unsafe {
        let cls = get_class("VZVirtualMachineConfiguration").unwrap();
        msg_send_u64!(cls, maximumAllowedMemorySize)
    }
}

/// Gets the minimum supported memory size.
pub fn min_memory_size() -> u64 {
    ensure_framework_loaded();
    unsafe {
        let cls = get_class("VZVirtualMachineConfiguration").unwrap();
        msg_send_u64!(cls, minimumAllowedMemorySize)
    }
}

// ============================================================================
// Error Handling
// ============================================================================

/// Extracts error information from an NSError object.
pub fn extract_nserror(error: *mut AnyObject) -> VZError {
    if error.is_null() {
        return VZError::Internal {
            code: -1,
            message: "Unknown error".to_string(),
        };
    }
    unsafe {
        let desc = msg_send!(error, localizedDescription);
        let code: i64 = msg_send_i64!(error, code);
        VZError::Internal {
            code: code as i32,
            message: nsstring_to_string(desc),
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
