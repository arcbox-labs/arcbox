//! FFI bindings for macOS Virtualization.framework.
//!
//! This module provides safe Rust wrappers around Apple's Virtualization.framework
//! using direct Objective-C runtime calls.

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr;

use objc2::ffi::{objc_getClass, objc_msgSend};
use objc2::runtime::{AnyClass, AnyObject, Bool, Sel};
use objc2::sel;

// ============================================================================
// Objective-C Runtime Helpers
// ============================================================================

/// Gets an Objective-C class by name.
fn get_class(name: &str) -> Option<&'static AnyClass> {
    let name_cstr = std::ffi::CString::new(name).ok()?;
    unsafe {
        let cls = objc_getClass(name_cstr.as_ptr());
        if cls.is_null() {
            None
        } else {
            Some(&*(cls as *const AnyClass))
        }
    }
}

/// Sends a message to an object.
macro_rules! msg_send {
    ($obj:expr, $sel:ident) => {{
        let sel = sel!($sel);
        let func: unsafe extern "C" fn(*const AnyObject, Sel) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel)
    }};
    ($obj:expr, $sel:ident : $arg1:expr) => {{
        let sel = sel!($sel:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel, $arg1 as *const _ as *const c_void)
    }};
    ($obj:expr, $sel:ident : $arg1:expr, $sel2:ident : $arg2:expr) => {{
        let sel = sel!($sel:$sel2:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void, *const c_void) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel, $arg1 as *const _ as *const c_void, $arg2 as *const _ as *const c_void)
    }};
    ($obj:expr, $sel:ident : $arg1:expr, $sel2:ident : $arg2:expr, $sel3:ident : $arg3:expr) => {{
        let sel = sel!($sel:$sel2:$sel3:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void, *const c_void, *const c_void) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel, $arg1 as *const _ as *const c_void, $arg2 as *const _ as *const c_void, $arg3 as *const _ as *const c_void)
    }};
}

/// Sends a message returning a u64.
macro_rules! msg_send_u64 {
    ($obj:expr, $sel:ident) => {{
        let sel = sel!($sel);
        let func: unsafe extern "C" fn(*const AnyObject, Sel) -> u64 =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel)
    }};
}

/// Sends a message returning a i64.
macro_rules! msg_send_i64 {
    ($obj:expr, $sel:ident) => {{
        let sel = sel!($sel);
        let func: unsafe extern "C" fn(*const AnyObject, Sel) -> i64 =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel)
    }};
}

/// Sends a message returning void with u64 arg.
macro_rules! msg_send_void_u64 {
    ($obj:expr, $sel:ident : $arg:expr) => {{
        let sel = sel!($sel:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, u64) =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel, $arg)
    }};
}

/// Sends a message returning Bool.
macro_rules! msg_send_bool {
    ($obj:expr, $sel:ident) => {{
        let sel = sel!($sel);
        let func: unsafe extern "C" fn(*const AnyObject, Sel) -> Bool =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel)
    }};
    ($obj:expr, $sel:ident : $arg:expr) => {{
        let sel = sel!($sel:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, *mut *mut AnyObject) -> Bool =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel, $arg)
    }};
}

/// Sends a message with void return.
macro_rules! msg_send_void {
    ($obj:expr, $sel:ident : $arg:expr) => {{
        let sel = sel!($sel:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel, $arg as *const _ as *const c_void)
    }};
}

// ============================================================================
// NSString Helper
// ============================================================================

/// Creates an NSString from a Rust string.
fn nsstring(s: &str) -> *mut AnyObject {
    unsafe {
        let cls = get_class("NSString").expect("NSString class not found");
        let alloc = msg_send!(cls, alloc);

        let sel = sel!(initWithBytes:length:encoding:);
        let func: unsafe extern "C" fn(*mut AnyObject, Sel, *const u8, usize, u64) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        func(alloc, sel, s.as_ptr(), s.len(), 4) // 4 = NSUTF8StringEncoding
    }
}

/// Creates an NSURL from a file path.
fn nsurl_file_path(path: &str) -> *mut AnyObject {
    unsafe {
        let cls = get_class("NSURL").expect("NSURL class not found");
        let path_str = nsstring(path);
        msg_send!(cls, fileURLWithPath: path_str)
    }
}

/// Gets NSString description as Rust String.
fn nsstring_to_string(obj: *mut AnyObject) -> String {
    if obj.is_null() {
        return String::new();
    }
    unsafe {
        let sel_utf8 = sel!(UTF8String);
        let func: unsafe extern "C" fn(*const AnyObject, Sel) -> *const i8 =
            std::mem::transmute(objc_msgSend as *const c_void);
        let cstr = func(obj as *const AnyObject, sel_utf8);
        if cstr.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(cstr).to_string_lossy().into_owned()
        }
    }
}

/// Creates an NSArray from raw pointers.
fn nsarray(objects: &[*mut AnyObject]) -> *mut AnyObject {
    unsafe {
        let cls = get_class("NSArray").expect("NSArray class not found");
        let sel = sel!(arrayWithObjects:count:);
        let func: unsafe extern "C" fn(*const AnyClass, Sel, *const *mut AnyObject, usize) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        func(cls, sel, objects.as_ptr(), objects.len())
    }
}

// ============================================================================
// VZVirtualMachine State
// ============================================================================

/// Virtual machine state.
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VZVirtualMachineState {
    Stopped = 0,
    Running = 1,
    Paused = 2,
    Error = 3,
    Starting = 4,
    Pausing = 5,
    Resuming = 6,
    Stopping = 7,
    Saving = 8,
    Restoring = 9,
}

impl From<i64> for VZVirtualMachineState {
    fn from(value: i64) -> Self {
        match value {
            0 => Self::Stopped,
            1 => Self::Running,
            2 => Self::Paused,
            3 => Self::Error,
            4 => Self::Starting,
            5 => Self::Pausing,
            6 => Self::Resuming,
            7 => Self::Stopping,
            8 => Self::Saving,
            9 => Self::Restoring,
            _ => Self::Error,
        }
    }
}

// ============================================================================
// Error Handling
// ============================================================================

/// FFI result type.
pub type VZResult<T> = Result<T, VZError>;

/// FFI error type.
#[derive(Debug, Clone)]
pub struct VZError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for VZError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VZError({}): {}", self.code, self.message)
    }
}

impl std::error::Error for VZError {}

/// Extracts error message from NSError.
fn extract_nserror(error: *mut AnyObject) -> VZError {
    if error.is_null() {
        return VZError {
            code: -1,
            message: "Unknown error".to_string(),
        };
    }
    unsafe {
        let desc = msg_send!(error, localizedDescription);
        let code: i64 = msg_send_i64!(error, code);
        VZError {
            code: code as i32,
            message: nsstring_to_string(desc),
        }
    }
}

// ============================================================================
// Safe Wrapper Types
// ============================================================================

/// Safe wrapper for VZVirtualMachineConfiguration.
pub struct VmConfiguration {
    inner: *mut AnyObject,
}

unsafe impl Send for VmConfiguration {}

impl Drop for VmConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe {
                let _: *mut AnyObject = msg_send!(self.inner, release);
            }
        }
    }
}

impl VmConfiguration {
    /// Creates a new VM configuration.
    pub fn new() -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZVirtualMachineConfiguration").ok_or_else(|| VZError {
                code: -1,
                message: "VZVirtualMachineConfiguration class not found".into(),
            })?;
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, init);
            if obj.is_null() {
                return Err(VZError {
                    code: -1,
                    message: "Failed to create VZVirtualMachineConfiguration".into(),
                });
            }
            Ok(Self { inner: obj })
        }
    }

    /// Sets the CPU count.
    pub fn set_cpu_count(&self, count: u64) {
        unsafe {
            msg_send_void_u64!(self.inner, setCPUCount: count);
        }
    }

    /// Gets the CPU count.
    pub fn cpu_count(&self) -> u64 {
        unsafe { msg_send_u64!(self.inner, CPUCount) }
    }

    /// Sets the memory size in bytes.
    pub fn set_memory_size(&self, size: u64) {
        unsafe {
            msg_send_void_u64!(self.inner, setMemorySize: size);
        }
    }

    /// Gets the memory size in bytes.
    pub fn memory_size(&self) -> u64 {
        unsafe { msg_send_u64!(self.inner, memorySize) }
    }

    /// Sets the boot loader.
    pub fn set_boot_loader(&self, boot_loader: &LinuxBootLoader) {
        unsafe {
            msg_send_void!(self.inner, setBootLoader: boot_loader.inner);
        }
    }

    /// Sets entropy devices.
    pub fn set_entropy_devices(&self, devices: &[*mut AnyObject]) {
        unsafe {
            let array = nsarray(devices);
            msg_send_void!(self.inner, setEntropyDevices: array);
        }
    }

    /// Sets storage devices.
    pub fn set_storage_devices(&self, devices: &[*mut AnyObject]) {
        unsafe {
            let array = nsarray(devices);
            msg_send_void!(self.inner, setStorageDevices: array);
        }
    }

    /// Sets network devices.
    pub fn set_network_devices(&self, devices: &[*mut AnyObject]) {
        unsafe {
            let array = nsarray(devices);
            msg_send_void!(self.inner, setNetworkDevices: array);
        }
    }

    /// Sets socket devices.
    pub fn set_socket_devices(&self, devices: &[*mut AnyObject]) {
        unsafe {
            let array = nsarray(devices);
            msg_send_void!(self.inner, setSocketDevices: array);
        }
    }

    /// Sets console devices.
    pub fn set_console_devices(&self, devices: &[*mut AnyObject]) {
        unsafe {
            let array = nsarray(devices);
            msg_send_void!(self.inner, setConsoleDevices: array);
        }
    }

    /// Sets directory sharing devices.
    pub fn set_directory_sharing_devices(&self, devices: &[*mut AnyObject]) {
        unsafe {
            let array = nsarray(devices);
            msg_send_void!(self.inner, setDirectorySharingDevices: array);
        }
    }

    /// Validates the configuration.
    pub fn validate(&self) -> VZResult<()> {
        unsafe {
            let mut error: *mut AnyObject = ptr::null_mut();
            let valid = msg_send_bool!(self.inner, validateWithError: &mut error);
            if valid.as_bool() {
                Ok(())
            } else {
                Err(extract_nserror(error))
            }
        }
    }

    /// Returns the inner object pointer.
    pub fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }
}

impl Default for VmConfiguration {
    fn default() -> Self {
        Self::new().expect("Failed to create default VM configuration")
    }
}

/// Safe wrapper for VZLinuxBootLoader.
pub struct LinuxBootLoader {
    inner: *mut AnyObject,
}

impl Drop for LinuxBootLoader {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe {
                let _: *mut AnyObject = msg_send!(self.inner, release);
            }
        }
    }
}

impl LinuxBootLoader {
    /// Creates a new Linux boot loader.
    pub fn new(kernel_path: &str) -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZLinuxBootLoader").ok_or_else(|| VZError {
                code: -1,
                message: "VZLinuxBootLoader class not found".into(),
            })?;
            let kernel_url = nsurl_file_path(kernel_path);
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, initWithKernelURL: kernel_url);
            if obj.is_null() {
                return Err(VZError {
                    code: -1,
                    message: "Failed to create VZLinuxBootLoader".into(),
                });
            }
            Ok(Self { inner: obj })
        }
    }

    /// Sets the initial ramdisk path.
    pub fn set_initial_ramdisk(&self, path: &str) {
        unsafe {
            let url = nsurl_file_path(path);
            msg_send_void!(self.inner, setInitialRamdiskURL: url);
        }
    }

    /// Sets the command line arguments.
    pub fn set_command_line(&self, cmdline: &str) {
        unsafe {
            let s = nsstring(cmdline);
            msg_send_void!(self.inner, setCommandLine: s);
        }
    }
}

/// Safe wrapper for VZVirtualMachine.
pub struct VirtualMachine {
    inner: *mut AnyObject,
}

unsafe impl Send for VirtualMachine {}

impl Drop for VirtualMachine {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe {
                let _: *mut AnyObject = msg_send!(self.inner, release);
            }
        }
    }
}

impl VirtualMachine {
    /// Creates a new virtual machine from configuration.
    pub fn new(config: &VmConfiguration) -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZVirtualMachine").ok_or_else(|| VZError {
                code: -1,
                message: "VZVirtualMachine class not found".into(),
            })?;
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, initWithConfiguration: config.as_ptr());
            if obj.is_null() {
                return Err(VZError {
                    code: -1,
                    message: "Failed to create VZVirtualMachine".into(),
                });
            }
            Ok(Self { inner: obj })
        }
    }

    /// Creates a new virtual machine with a dispatch queue.
    pub fn new_with_queue(config: &VmConfiguration, queue: *mut AnyObject) -> VZResult<Self> {
        unsafe {
            let cls = get_class("VZVirtualMachine").ok_or_else(|| VZError {
                code: -1,
                message: "VZVirtualMachine class not found".into(),
            })?;
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, initWithConfiguration: config.as_ptr(), queue: queue);
            if obj.is_null() {
                return Err(VZError {
                    code: -1,
                    message: "Failed to create VZVirtualMachine".into(),
                });
            }
            Ok(Self { inner: obj })
        }
    }

    /// Returns the inner object pointer.
    pub fn as_ptr(&self) -> *mut AnyObject {
        self.inner
    }

    /// Gets the current state.
    pub fn state(&self) -> VZVirtualMachineState {
        unsafe {
            let state = msg_send_i64!(self.inner, state);
            VZVirtualMachineState::from(state)
        }
    }

    /// Checks if the VM can start.
    pub fn can_start(&self) -> bool {
        unsafe { msg_send_bool!(self.inner, canStart).as_bool() }
    }

    /// Checks if the VM can pause.
    pub fn can_pause(&self) -> bool {
        unsafe { msg_send_bool!(self.inner, canPause).as_bool() }
    }

    /// Checks if the VM can resume.
    pub fn can_resume(&self) -> bool {
        unsafe { msg_send_bool!(self.inner, canResume).as_bool() }
    }

    /// Checks if the VM can request stop.
    pub fn can_request_stop(&self) -> bool {
        unsafe { msg_send_bool!(self.inner, canRequestStop).as_bool() }
    }

    /// Stops the VM synchronously.
    pub fn stop(&self) -> VZResult<()> {
        unsafe {
            let mut error: *mut AnyObject = ptr::null_mut();
            let result = msg_send_bool!(self.inner, stopWithError: &mut error);
            if result.as_bool() {
                Ok(())
            } else {
                Err(extract_nserror(error))
            }
        }
    }

    /// Requests graceful stop.
    pub fn request_stop(&self) -> VZResult<()> {
        unsafe {
            let mut error: *mut AnyObject = ptr::null_mut();
            let result = msg_send_bool!(self.inner, requestStopWithError: &mut error);
            if result.as_bool() {
                Ok(())
            } else {
                Err(extract_nserror(error))
            }
        }
    }

    /// Starts the VM asynchronously.
    ///
    /// This dispatches the start operation and returns immediately.
    /// Use `state()` to poll for completion.
    pub fn start_async(&self) {
        unsafe {
            // Create a simple completion handler block that does nothing
            // The actual completion is detected by polling state()
            let sel = sel!(startWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) =
                std::mem::transmute(objc_msgSend as *const c_void);

            // Pass nil as completion handler - we'll poll state instead
            func(self.inner as *const AnyObject, sel, ptr::null());
        }
    }

    /// Pauses the VM asynchronously.
    pub fn pause_async(&self) {
        unsafe {
            let sel = sel!(pauseWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) =
                std::mem::transmute(objc_msgSend as *const c_void);
            func(self.inner as *const AnyObject, sel, ptr::null());
        }
    }

    /// Resumes the VM asynchronously.
    pub fn resume_async(&self) {
        unsafe {
            let sel = sel!(resumeWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) =
                std::mem::transmute(objc_msgSend as *const c_void);
            func(self.inner as *const AnyObject, sel, ptr::null());
        }
    }
}

// ============================================================================
// Device Configuration Helpers
// ============================================================================

/// Creates a disk image storage attachment.
pub fn create_disk_attachment(path: &str, read_only: bool) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZDiskImageStorageDeviceAttachment").ok_or_else(|| VZError {
            code: -1,
            message: "VZDiskImageStorageDeviceAttachment class not found".into(),
        })?;
        let url = nsurl_file_path(path);
        let mut error: *mut AnyObject = ptr::null_mut();

        let sel = sel!(initWithURL:readOnly:error:);
        let alloc = msg_send!(cls, alloc);
        let func: unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, Bool, *mut *mut AnyObject) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        let obj = func(alloc, sel, url, Bool::new(read_only), &mut error);

        if obj.is_null() {
            return Err(extract_nserror(error));
        }
        Ok(obj)
    }
}

/// Creates a VirtIO block device configuration.
pub fn create_block_device(attachment: *mut AnyObject) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZVirtioBlockDeviceConfiguration").ok_or_else(|| VZError {
            code: -1,
            message: "VZVirtioBlockDeviceConfiguration class not found".into(),
        })?;
        let alloc = msg_send!(cls, alloc);
        let obj = msg_send!(alloc, initWithAttachment: attachment);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create block device".into(),
            });
        }
        Ok(obj)
    }
}

/// Creates a NAT network device attachment.
pub fn create_nat_attachment() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZNATNetworkDeviceAttachment").ok_or_else(|| VZError {
            code: -1,
            message: "VZNATNetworkDeviceAttachment class not found".into(),
        })?;
        let obj = msg_send!(cls, new);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create NAT attachment".into(),
            });
        }
        Ok(obj)
    }
}

/// Creates a VirtIO network device configuration.
pub fn create_network_device(attachment: *mut AnyObject) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZVirtioNetworkDeviceConfiguration").ok_or_else(|| VZError {
            code: -1,
            message: "VZVirtioNetworkDeviceConfiguration class not found".into(),
        })?;
        let obj = msg_send!(cls, new);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create network device".into(),
            });
        }
        msg_send_void!(obj, setAttachment: attachment);
        Ok(obj)
    }
}

/// Creates a random MAC address.
pub fn create_random_mac() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZMACAddress").ok_or_else(|| VZError {
            code: -1,
            message: "VZMACAddress class not found".into(),
        })?;
        let obj = msg_send!(cls, randomLocallyAdministeredAddress);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create random MAC".into(),
            });
        }
        Ok(obj)
    }
}

/// Sets MAC address on network device.
pub fn set_network_mac(device: *mut AnyObject, mac: *mut AnyObject) {
    unsafe {
        msg_send_void!(device, setMACAddress: mac);
    }
}

/// Creates a VirtIO entropy device.
pub fn create_entropy_device() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZVirtioEntropyDeviceConfiguration").ok_or_else(|| VZError {
            code: -1,
            message: "VZVirtioEntropyDeviceConfiguration class not found".into(),
        })?;
        let obj = msg_send!(cls, new);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create entropy device".into(),
            });
        }
        Ok(obj)
    }
}

/// Creates a VirtIO socket device.
pub fn create_socket_device() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZVirtioSocketDeviceConfiguration").ok_or_else(|| VZError {
            code: -1,
            message: "VZVirtioSocketDeviceConfiguration class not found".into(),
        })?;
        let obj = msg_send!(cls, new);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create socket device".into(),
            });
        }
        Ok(obj)
    }
}

/// Creates a VirtIO console device.
pub fn create_console_device() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZVirtioConsoleDeviceConfiguration").ok_or_else(|| VZError {
            code: -1,
            message: "VZVirtioConsoleDeviceConfiguration class not found".into(),
        })?;
        let obj = msg_send!(cls, new);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create console device".into(),
            });
        }
        Ok(obj)
    }
}

/// Creates a shared directory.
pub fn create_shared_directory(path: &str, read_only: bool) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZSharedDirectory").ok_or_else(|| VZError {
            code: -1,
            message: "VZSharedDirectory class not found".into(),
        })?;
        let url = nsurl_file_path(path);
        let alloc = msg_send!(cls, alloc);

        let sel = sel!(initWithURL:readOnly:);
        let func: unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, Bool) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        let obj = func(alloc, sel, url, Bool::new(read_only));

        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create shared directory".into(),
            });
        }
        Ok(obj)
    }
}

/// Creates a single directory share.
pub fn create_single_directory_share(directory: *mut AnyObject) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZSingleDirectoryShare").ok_or_else(|| VZError {
            code: -1,
            message: "VZSingleDirectoryShare class not found".into(),
        })?;
        let alloc = msg_send!(cls, alloc);
        let obj = msg_send!(alloc, initWithDirectory: directory);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create single directory share".into(),
            });
        }
        Ok(obj)
    }
}

/// Creates a VirtIO filesystem device.
pub fn create_fs_device(tag: &str, share: *mut AnyObject) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZVirtioFileSystemDeviceConfiguration").ok_or_else(|| VZError {
            code: -1,
            message: "VZVirtioFileSystemDeviceConfiguration class not found".into(),
        })?;
        let tag_str = nsstring(tag);
        let alloc = msg_send!(cls, alloc);
        let obj = msg_send!(alloc, initWithTag: tag_str);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create filesystem device".into(),
            });
        }
        msg_send_void!(obj, setShare: share);
        Ok(obj)
    }
}

// ============================================================================
// System Queries
// ============================================================================

/// Checks if virtualization is supported on this system.
pub fn is_supported() -> bool {
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
    unsafe {
        let cls = get_class("VZVirtualMachineConfiguration").unwrap();
        msg_send_u64!(cls, maximumAllowedCPUCount)
    }
}

/// Gets the minimum supported CPU count.
pub fn min_cpu_count() -> u64 {
    unsafe {
        let cls = get_class("VZVirtualMachineConfiguration").unwrap();
        msg_send_u64!(cls, minimumAllowedCPUCount)
    }
}

/// Gets the maximum supported memory size.
pub fn max_memory_size() -> u64 {
    unsafe {
        let cls = get_class("VZVirtualMachineConfiguration").unwrap();
        msg_send_u64!(cls, maximumAllowedMemorySize)
    }
}

/// Gets the minimum supported memory size.
pub fn min_memory_size() -> u64 {
    unsafe {
        let cls = get_class("VZVirtualMachineConfiguration").unwrap();
        msg_send_u64!(cls, minimumAllowedMemorySize)
    }
}

// ============================================================================
// Dispatch Queue
// ============================================================================

// Dispatch queue FFI
unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> *mut AnyObject;
}

/// Creates a dispatch queue for VM operations.
pub fn create_dispatch_queue(label: &str) -> *mut AnyObject {
    unsafe {
        let label_cstr = std::ffi::CString::new(label).unwrap();
        let queue = dispatch_queue_create(
            label_cstr.as_ptr(),
            ptr::null(), // DISPATCH_QUEUE_SERIAL
        );
        queue
    }
}

// dispatch_release FFI
unsafe extern "C" {
    fn dispatch_release(object: *mut AnyObject);
}

/// Releases a dispatch queue.
pub fn release_dispatch_queue(queue: *mut AnyObject) {
    if !queue.is_null() {
        unsafe {
            dispatch_release(queue);
        }
    }
}

// ============================================================================
// Serial Port / Console
// ============================================================================

/// Creates a file handle for serial port attachment.
pub fn create_file_handle_for_reading(fd: i32) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("NSFileHandle").ok_or_else(|| VZError {
            code: -1,
            message: "NSFileHandle class not found".into(),
        })?;
        let obj = msg_send!(cls, alloc);

        let sel = sel!(initWithFileDescriptor:);
        let func: unsafe extern "C" fn(*mut AnyObject, Sel, i32) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        let handle = func(obj, sel, fd);

        if handle.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create NSFileHandle".into(),
            });
        }
        Ok(handle)
    }
}

/// Creates a serial port attachment from file handles.
pub fn create_serial_port_attachment(
    read_handle: *mut AnyObject,
    write_handle: *mut AnyObject,
) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZFileHandleSerialPortAttachment").ok_or_else(|| VZError {
            code: -1,
            message: "VZFileHandleSerialPortAttachment class not found".into(),
        })?;
        let obj = msg_send!(cls, alloc);
        let attachment = msg_send!(obj, initWithFileHandleForReading: read_handle, fileHandleForWriting: write_handle);

        if attachment.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create serial port attachment".into(),
            });
        }
        Ok(attachment)
    }
}

/// Creates a VirtIO console port configuration.
pub fn create_console_port_configuration() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZVirtioConsolePortConfiguration").ok_or_else(|| VZError {
            code: -1,
            message: "VZVirtioConsolePortConfiguration class not found".into(),
        })?;
        let obj = msg_send!(cls, new);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create console port configuration".into(),
            });
        }
        Ok(obj)
    }
}

/// Sets the attachment on a console port.
pub fn set_console_port_attachment(port: *mut AnyObject, attachment: *mut AnyObject) {
    unsafe {
        msg_send_void!(port, setAttachment: attachment);
    }
}

/// Sets the name on a console port.
pub fn set_console_port_name(port: *mut AnyObject, name: &str) {
    unsafe {
        let name_str = nsstring(name);
        msg_send_void!(port, setName: name_str);
    }
}

/// Marks a console port as the console.
pub fn set_console_port_is_console(port: *mut AnyObject, is_console: bool) {
    unsafe {
        let sel = sel!(setIsConsole:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, Bool) =
            std::mem::transmute(objc_msgSend as *const c_void);
        func(port as *const AnyObject, sel, Bool::new(is_console));
    }
}

/// Sets console ports on a console device.
pub fn set_console_device_ports(device: *mut AnyObject, ports: &[*mut AnyObject]) {
    unsafe {
        let array = nsarray(ports);
        msg_send_void!(device, setPorts: array);
    }
}

// ============================================================================
// Memory Allocation (using mmap)
// ============================================================================

/// Allocates guest memory using mmap.
pub fn allocate_memory(size: u64) -> VZResult<*mut u8> {
    unsafe {
        let ptr = libc::mmap(
            ptr::null_mut(),
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if ptr == libc::MAP_FAILED {
            return Err(VZError {
                code: *libc::__error(),
                message: "mmap failed".to_string(),
            });
        }

        libc::memset(ptr, 0, size as usize);
        tracing::debug!("Allocated {}MB of guest memory", size / (1024 * 1024));

        Ok(ptr.cast::<u8>())
    }
}

/// Frees guest memory.
pub fn free_memory(ptr: *mut u8, size: u64) {
    if !ptr.is_null() {
        unsafe {
            libc::munmap(ptr.cast(), size as usize);
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
        println!("Virtualization supported: {}", supported);
    }

    #[test]
    fn test_cpu_limits() {
        if !is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }
        let min = min_cpu_count();
        let max = max_cpu_count();
        println!("CPU count: min={}, max={}", min, max);
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

    #[test]
    fn test_allocate_memory() {
        let size = 16 * 1024 * 1024; // 16MB
        let ptr = allocate_memory(size).expect("allocation failed");
        assert!(!ptr.is_null());

        unsafe {
            *ptr = 42;
            assert_eq!(*ptr, 42);
        }

        free_memory(ptr, size);
    }

    #[test]
    fn test_vm_configuration() {
        if !is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        let config = VmConfiguration::new().expect("Failed to create config");
        config.set_cpu_count(2);
        config.set_memory_size(512 * 1024 * 1024);

        assert_eq!(config.cpu_count(), 2);
        assert_eq!(config.memory_size(), 512 * 1024 * 1024);
    }
}
