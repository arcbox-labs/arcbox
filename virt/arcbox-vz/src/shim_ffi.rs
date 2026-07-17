//! Hand-written C ABI declarations for the ArcBoxVZShim Swift static library.
//!
//! CONTRACT: every extern declaration below stays in the same NORMATIVE SYMBOL
//! ORDER as the `@_cdecl` exports in `shim/Sources/ArcBoxVZShim/Exports.swift`
//! — review the two files side by side. The shim is statically linked from
//! this same source tree in the same build, so version skew is impossible;
//! `link_coverage` (below) catches symbol-presence drift at link time. There
//! is no runtime ABI-version handshake because there is no separate artifact
//! to handshake with.
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

/// Vsock connect completion: fires exactly once from the VM's dispatch queue
/// with either a dup'd fd (+ ports, `err` null) or `fd == -1` and a strdup'd
/// error message (freed by the receiver via [`take_error_string`]).
pub type VsockCb =
    unsafe extern "C" fn(ctx: *mut c_void, fd: i32, src_port: u32, dst_port: u32, err: *mut c_char);

/// Lifecycle completion: fires exactly once from the VM's dispatch queue with
/// null on success or a strdup'd error message (freed via
/// [`take_error_string`]).
pub type StateCb = unsafe extern "C" fn(ctx: *mut c_void, err: *mut c_char);

/// Object-producing completion: fires exactly once with either a +1 handle
/// (owned by the receiver) or a strdup'd error message.
pub type ObjectCb = unsafe extern "C" fn(ctx: *mut c_void, handle: *mut c_void, err: *mut c_char);

unsafe extern "C" {
    // Errors / strings / handles
    pub fn abx_string_free(ptr: *mut c_char);
    pub fn abx_bytes_free(ptr: *mut c_void);
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

    // Device configurations
    pub fn abx_storage_disk_image_new(
        path: *const c_char,
        read_only: bool,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn abx_network_nat_new(
        mac: *const c_char,
        mtu: u64,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn abx_network_file_handle_new(
        fd: i32,
        mac: *const c_char,
        mtu: u64,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn abx_serial_console_new(read_fd: i32, write_fd: i32) -> *mut c_void;
    pub fn abx_socket_device_config_new() -> *mut c_void;
    pub fn abx_entropy_new() -> *mut c_void;
    pub fn abx_balloon_config_new() -> *mut c_void;
    pub fn abx_graphics_mac_new(width: i64, height: i64, ppi: i64) -> *mut c_void;

    // Directory shares / VirtioFS
    pub fn abx_shared_directory_new(path: *const c_char, read_only: bool) -> *mut c_void;
    pub fn abx_single_share_new(directory: *mut c_void) -> *mut c_void;
    pub fn abx_rosetta_availability() -> i64;
    pub fn abx_rosetta_share_new(error_out: *mut *mut c_char) -> *mut c_void;
    pub fn abx_virtiofs_new(tag: *const c_char, error_out: *mut *mut c_char) -> *mut c_void;
    pub fn abx_virtiofs_set_share(config: *mut c_void, share: *mut c_void);

    // macOS identity + platform
    pub fn abx_mac_hw_model_from_data(bytes: *const c_void, length: usize) -> *mut c_void;
    pub fn abx_mac_hw_model_supported(handle: *mut c_void) -> bool;
    pub fn abx_mac_hw_model_data(handle: *mut c_void, length_out: *mut usize) -> *mut c_void;
    pub fn abx_mac_machine_id_new() -> *mut c_void;
    pub fn abx_mac_machine_id_from_data(bytes: *const c_void, length: usize) -> *mut c_void;
    pub fn abx_mac_machine_id_data(handle: *mut c_void, length_out: *mut usize) -> *mut c_void;
    pub fn abx_aux_storage_open(path: *const c_char) -> *mut c_void;
    pub fn abx_aux_storage_create(
        path: *const c_char,
        hardware_model: *mut c_void,
        overwrite: bool,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn abx_platform_mac_new(
        hardware_model: *mut c_void,
        machine_identifier: *mut c_void,
        auxiliary_storage: *mut c_void,
    ) -> *mut c_void;

    // Vsock
    pub fn abx_vsock_connect(device_box: *mut c_void, port: u32, ctx: *mut c_void, cb: VsockCb);

    // VM lifecycle
    /// `kind` values mirror the shim's `ABXDeviceKind` (storage=0, network=1,
    /// serial=2, socket=3, entropy=4, directory_sharing=5, memory_balloon=6,
    /// graphics=7). The configuration retains the borrowed handles.
    pub fn abx_config_set_devices(
        config: *mut c_void,
        kind: u32,
        items: *const *mut c_void,
        count: usize,
    );
    pub fn abx_vm_new(config: *mut c_void) -> *mut c_void;
    pub fn abx_vm_state(vm_box: *mut c_void) -> i64;
    pub fn abx_vm_can_stop(vm_box: *mut c_void) -> bool;
    pub fn abx_vm_can_pause(vm_box: *mut c_void) -> bool;
    pub fn abx_vm_can_resume(vm_box: *mut c_void) -> bool;
    pub fn abx_vm_request_stop(vm_box: *mut c_void, error_out: *mut *mut c_char) -> bool;
    pub fn abx_vm_start(vm_box: *mut c_void, ctx: *mut c_void, cb: StateCb);
    pub fn abx_vm_stop(vm_box: *mut c_void, ctx: *mut c_void, cb: StateCb);
    pub fn abx_vm_pause(vm_box: *mut c_void, ctx: *mut c_void, cb: StateCb);
    pub fn abx_vm_resume(vm_box: *mut c_void, ctx: *mut c_void, cb: StateCb);
    pub fn abx_vm_socket_device_count(vm_box: *mut c_void) -> u64;
    pub fn abx_vm_socket_device_at(vm_box: *mut c_void, index: u64) -> *mut c_void;
    pub fn abx_vm_balloon_count(vm_box: *mut c_void) -> u64;
    pub fn abx_vm_balloon_at(vm_box: *mut c_void, index: u64) -> *mut c_void;
    pub fn abx_balloon_target(balloon_box: *mut c_void) -> u64;
    pub fn abx_balloon_set_target(balloon_box: *mut c_void, bytes: u64);

    // Restore images / installer
    pub fn abx_restore_image_load(path: *const c_char, ctx: *mut c_void, cb: ObjectCb);
    pub fn abx_restore_image_fetch_latest(ctx: *mut c_void, cb: ObjectCb);
    pub fn abx_restore_image_requirements(
        image: *mut c_void,
        hardware_model_out: *mut *mut c_void,
        min_cpu_out: *mut u64,
        min_memory_out: *mut u64,
        error_out: *mut *mut c_char,
    ) -> bool;
    pub fn abx_restore_image_url(image: *mut c_void) -> *mut c_char;
    pub fn abx_installer_new(vm_box: *mut c_void, ipsw_path: *const c_char) -> *mut c_void;
    pub fn abx_installer_fraction(installer_box: *mut c_void) -> f64;
    pub fn abx_installer_install(installer_box: *mut c_void, ctx: *mut c_void, cb: StateCb);
}

/// Takes ownership of a shim-returned string, or `None` if null.
///
/// # Safety
///
/// `ptr` must be null or a string allocated by the shim (strdup'd) that has
/// not been freed yet.
pub unsafe fn take_string(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: per contract, `ptr` is a valid NUL-terminated C string owned by us.
    unsafe {
        let out = std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned();
        abx_string_free(ptr);
        Some(out)
    }
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
        abx_storage_disk_image_new as *const (),
        abx_network_nat_new as *const (),
        abx_network_file_handle_new as *const (),
        abx_serial_console_new as *const (),
        abx_socket_device_config_new as *const (),
        abx_entropy_new as *const (),
        abx_balloon_config_new as *const (),
        abx_graphics_mac_new as *const (),
        abx_shared_directory_new as *const (),
        abx_single_share_new as *const (),
        abx_rosetta_availability as *const (),
        abx_rosetta_share_new as *const (),
        abx_virtiofs_new as *const (),
        abx_virtiofs_set_share as *const (),
        abx_mac_hw_model_from_data as *const (),
        abx_mac_hw_model_supported as *const (),
        abx_mac_hw_model_data as *const (),
        abx_mac_machine_id_new as *const (),
        abx_mac_machine_id_from_data as *const (),
        abx_mac_machine_id_data as *const (),
        abx_aux_storage_open as *const (),
        abx_aux_storage_create as *const (),
        abx_platform_mac_new as *const (),
        abx_vsock_connect as *const (),
        abx_config_set_devices as *const (),
        abx_vm_new as *const (),
        abx_vm_state as *const (),
        abx_vm_can_stop as *const (),
        abx_vm_can_pause as *const (),
        abx_vm_can_resume as *const (),
        abx_vm_request_stop as *const (),
        abx_vm_start as *const (),
        abx_vm_stop as *const (),
        abx_vm_pause as *const (),
        abx_vm_resume as *const (),
        abx_vm_socket_device_count as *const (),
        abx_vm_socket_device_at as *const (),
        abx_vm_balloon_count as *const (),
        abx_vm_balloon_at as *const (),
        abx_balloon_target as *const (),
        abx_balloon_set_target as *const (),
        abx_restore_image_load as *const (),
        abx_restore_image_fetch_latest as *const (),
        abx_restore_image_requirements as *const (),
        abx_restore_image_url as *const (),
        abx_installer_new as *const (),
        abx_installer_fraction as *const (),
        abx_installer_install as *const (),
    ];

    /// Update when symbols are added; a mismatch means Exports.swift and this
    /// file have drifted.
    const EXPECTED_SYMBOL_COUNT: usize = 71;

    #[test]
    fn link_coverage() {
        assert_eq!(SYMBOLS.len(), EXPECTED_SYMBOL_COUNT);
        for (i, sym) in SYMBOLS.iter().enumerate() {
            assert!(!sym.is_null(), "symbol #{i} resolved to null");
        }
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
    fn machine_id_data_roundtrip() {
        // SAFETY: identity objects are plain allocations (no entitlement);
        // buffers are shim-malloc'd and freed via abx_bytes_free.
        unsafe {
            let id = abx_mac_machine_id_new();
            assert!(!id.is_null());

            let mut len: usize = 0;
            let bytes = abx_mac_machine_id_data(id, &raw mut len);
            assert!(!bytes.is_null());
            assert!(len > 0);

            let id2 = abx_mac_machine_id_from_data(bytes, len);
            assert!(!id2.is_null(), "round-trip through data representation");
            let mut len2: usize = 0;
            let bytes2 = abx_mac_machine_id_data(id2, &raw mut len2);
            assert_eq!(len, len2);
            let a = std::slice::from_raw_parts(bytes as *const u8, len);
            let b = std::slice::from_raw_parts(bytes2 as *const u8, len2);
            assert_eq!(a, b);

            abx_bytes_free(bytes);
            abx_bytes_free(bytes2);
            abx_object_release(id2);
            abx_object_release(id);

            // Garbage bytes must be rejected, not crash.
            let garbage = [0u8; 16];
            let bad = abx_mac_machine_id_from_data(garbage.as_ptr().cast(), garbage.len());
            assert!(bad.is_null());
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
