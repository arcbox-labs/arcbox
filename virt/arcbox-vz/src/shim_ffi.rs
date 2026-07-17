//! Hand-written C ABI declarations for the ArcBoxVZShim Swift static library.
//!
//! CONTRACT: every extern declaration below stays in the same NORMATIVE SYMBOL
//! ORDER as the `@_cdecl` exports in `shim/Sources/ArcBoxVZShim/Exports.swift`
//! — review the two files side by side. Any signature or semantics change
//! bumps [`ABX_SHIM_ABI_VERSION`] here and `abxShimABIVersion` in the shim.
//!
//! Conventions (mirrored in the shim's Errors.swift header):
//! - C strings returned by the shim are malloc'd there and freed here via
//!   [`abx_string_free`]; NULL means "no error" / "no value".
//! - Opaque handles are `Unmanaged` object pointers at +1, balanced by
//!   [`abx_object_release`]; borrowed parameters do not consume the +1.
//! - The shim never catches ObjC exceptions; throwing VZ call sites are
//!   precondition-guarded, so an NSException crashes instead of unwinding
//!   through Rust frames.

use std::ffi::{c_char, c_void};

/// Mirrors `abxShimABIVersion` in the shim; bump both on any signature change.
#[allow(
    dead_code,
    reason = "drift detector: compared against abx_shim_version() by the boundary tests"
)]
pub const ABX_SHIM_ABI_VERSION: u32 = 1;

unsafe extern "C" {
    // Errors / strings / handles
    //
    // The four utility symbols below gain production callers as the shim
    // migration lands (PR3+); today only the boundary tests exercise them.
    #[allow(
        dead_code,
        reason = "consumed by later shim migration PRs; covered by boundary tests"
    )]
    pub fn abx_shim_version() -> u32;
    #[allow(
        dead_code,
        reason = "consumed by later shim migration PRs; covered by boundary tests"
    )]
    pub fn abx_string_free(ptr: *mut c_char);
    #[allow(
        dead_code,
        reason = "consumed by later shim migration PRs; covered by boundary tests"
    )]
    pub fn abx_bytes_free(ptr: *mut c_void);
    #[allow(
        dead_code,
        reason = "consumed by later shim migration PRs; covered by boundary tests"
    )]
    pub fn abx_object_release(handle: *mut c_void);

    // Support (host capability queries)
    pub fn abx_vz_supported() -> bool;
    pub fn abx_vz_min_cpu_count() -> u64;
    pub fn abx_vz_max_cpu_count() -> u64;
    pub fn abx_vz_min_memory_size() -> u64;
    pub fn abx_vz_max_memory_size() -> u64;

    // Configuration
    pub fn abx_config_new() -> *mut c_void;
    pub fn abx_config_set_cpu_count(config: *mut c_void, count: u64);
    pub fn abx_config_cpu_count(config: *mut c_void) -> u64;
    pub fn abx_config_set_memory_size(config: *mut c_void, bytes: u64);
    pub fn abx_config_memory_size(config: *mut c_void) -> u64;
    pub fn abx_config_set_boot_loader(config: *mut c_void, boot_loader: *mut c_void);
    pub fn abx_config_set_platform(config: *mut c_void, platform: *mut c_void);
    pub fn abx_config_validate(config: *mut c_void, error_out: *mut *mut c_char) -> bool;

    // Boot loaders
    pub fn abx_bootloader_linux_new(kernel_path: *const c_char) -> *mut c_void;
    pub fn abx_bootloader_linux_set_initrd(boot_loader: *mut c_void, path: *const c_char);
    pub fn abx_bootloader_linux_set_cmdline(boot_loader: *mut c_void, cmdline: *const c_char);
    pub fn abx_bootloader_macos_new() -> *mut c_void;

    // Platforms (generic; MacPlatform arrives with the identity types)
    pub fn abx_platform_generic_new() -> *mut c_void;
    pub fn abx_platform_generic_nested_supported() -> bool;
    pub fn abx_platform_generic_set_nested(platform: *mut c_void, enabled: bool);
}

/// Takes ownership of a shim-returned error string and frees it.
///
/// # Safety
///
/// `err` must be null or a string allocated by the shim (strdup'd) that has
/// not been freed yet.
pub unsafe fn take_error_string(err: *mut c_char) -> String {
    if err.is_null() {
        return "unknown error".to_string();
    }
    // SAFETY: per contract, `err` is a valid NUL-terminated C string owned by us.
    unsafe {
        let message = std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned();
        abx_string_free(err);
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    /// Every exported symbol, in normative order. Taking each address forces
    /// the symbol to resolve at link time, so a renamed or dropped `@_cdecl`
    /// export breaks `cargo test -p arcbox-vz` instead of surfacing at e2e.
    const SYMBOLS: &[*const ()] = &[
        abx_shim_version as *const (),
        abx_string_free as *const (),
        abx_bytes_free as *const (),
        abx_object_release as *const (),
        abx_vz_supported as *const (),
        abx_vz_min_cpu_count as *const (),
        abx_vz_max_cpu_count as *const (),
        abx_vz_min_memory_size as *const (),
        abx_vz_max_memory_size as *const (),
        abx_config_new as *const (),
        abx_config_set_cpu_count as *const (),
        abx_config_cpu_count as *const (),
        abx_config_set_memory_size as *const (),
        abx_config_memory_size as *const (),
        abx_config_set_boot_loader as *const (),
        abx_config_set_platform as *const (),
        abx_config_validate as *const (),
        abx_bootloader_linux_new as *const (),
        abx_bootloader_linux_set_initrd as *const (),
        abx_bootloader_linux_set_cmdline as *const (),
        abx_bootloader_macos_new as *const (),
        abx_platform_generic_new as *const (),
        abx_platform_generic_nested_supported as *const (),
        abx_platform_generic_set_nested as *const (),
    ];

    /// Update when symbols are added; a mismatch means Exports.swift and this
    /// file have drifted.
    const EXPECTED_SYMBOL_COUNT: usize = 24;

    #[test]
    fn link_coverage() {
        assert_eq!(SYMBOLS.len(), EXPECTED_SYMBOL_COUNT);
        for (i, sym) in SYMBOLS.iter().enumerate() {
            assert!(!sym.is_null(), "symbol #{i} resolved to null");
        }
    }

    #[test]
    fn shim_version_matches() {
        // SAFETY: no preconditions; returns a constant.
        let version = unsafe { abx_shim_version() };
        assert_eq!(version, ABX_SHIM_ABI_VERSION);
    }

    #[test]
    fn null_frees_are_noops() {
        // SAFETY: the shim documents NULL as a no-op for all three.
        unsafe {
            abx_string_free(ptr::null_mut());
            abx_bytes_free(ptr::null_mut());
            abx_object_release(ptr::null_mut());
        }
    }

    #[test]
    fn config_create_free_roundtrip() {
        // SAFETY: configuration objects are plain allocations — the
        // virtualization entitlement is enforced at VM init, not here.
        unsafe {
            let cfg = abx_config_new();
            assert!(!cfg.is_null());
            abx_config_set_cpu_count(cfg, 2);
            assert_eq!(abx_config_cpu_count(cfg), 2);
            abx_config_set_memory_size(cfg, 512 * 1024 * 1024);
            assert_eq!(abx_config_memory_size(cfg), 512 * 1024 * 1024);

            let platform = abx_platform_generic_new();
            assert!(!platform.is_null());
            abx_config_set_platform(cfg, platform);
            // Reading the class support flag must not crash regardless of host.
            let _ = abx_platform_generic_nested_supported();

            abx_object_release(platform);
            abx_object_release(cfg);
        }
    }

    #[test]
    fn linux_boot_loader_roundtrip() {
        let dir = std::env::temp_dir().join("abx-shim-ffi-test");
        std::fs::create_dir_all(&dir).unwrap();
        let kernel = dir.join("fake-kernel");
        std::fs::write(&kernel, b"not a kernel").unwrap();
        let c_path = std::ffi::CString::new(kernel.to_str().unwrap()).unwrap();
        let c_cmdline = std::ffi::CString::new("console=hvc0").unwrap();

        // SAFETY: boot-loader objects are plain allocations; the paths are
        // valid NUL-terminated strings for the duration of the calls.
        unsafe {
            let bl = abx_bootloader_linux_new(c_path.as_ptr());
            assert!(!bl.is_null());
            abx_bootloader_linux_set_initrd(bl, c_path.as_ptr());
            abx_bootloader_linux_set_cmdline(bl, c_cmdline.as_ptr());
            abx_object_release(bl);
        }
    }

    #[test]
    fn support_queries() {
        // SAFETY: class-property reads; no entitlement required (CI runs
        // these on unsigned binaries — same class as the old ffi tests).
        unsafe {
            let supported = abx_vz_supported();
            println!("virtualization supported: {supported}");
            if supported {
                assert!(abx_vz_min_cpu_count() > 0);
                assert!(abx_vz_max_cpu_count() >= abx_vz_min_cpu_count());
                assert!(abx_vz_min_memory_size() > 0);
                assert!(abx_vz_max_memory_size() >= abx_vz_min_memory_size());
            }
        }
    }
}
