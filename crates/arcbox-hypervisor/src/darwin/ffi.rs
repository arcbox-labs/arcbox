//! FFI bindings for macOS Virtualization.framework.
//!
//! This module provides safe Rust wrappers around Apple's Virtualization.framework
//! using direct Objective-C runtime calls.

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr;
use std::sync::Once;

use objc2::ffi::{objc_getClass, objc_msgSend};
use objc2::runtime::{AnyClass, AnyObject, Bool, Sel};
use objc2::sel;

// ============================================================================
// Framework Loading
// ============================================================================

static FRAMEWORK_INIT: Once = Once::new();

/// Ensures Virtualization.framework is loaded.
fn ensure_framework_loaded() {
    FRAMEWORK_INIT.call_once(|| {
        unsafe {
            // Load Virtualization.framework using dlopen
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
        }
    });
}

// ============================================================================
// Objective-C Runtime Helpers
// ============================================================================

/// Gets an Objective-C class by name.
fn get_class(name: &str) -> Option<&'static AnyClass> {
    ensure_framework_loaded();
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
        let func: unsafe extern "C" fn(
            *mut AnyObject,
            Sel,
            *const u8,
            usize,
            u64,
        ) -> *mut AnyObject = std::mem::transmute(objc_msgSend as *const c_void);
        func(alloc, sel, s.as_ptr(), s.len(), 4) // 4 = NSUTF8StringEncoding
    }
}

/// Creates an NSURL from a file path.
/// Converts relative paths to absolute paths to ensure correct URL creation.
fn nsurl_file_path(path: &str) -> *mut AnyObject {
    // Convert relative paths to absolute paths
    let abs_path = if std::path::Path::new(path).is_absolute() {
        path.to_string()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path).to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string())
    };

    unsafe {
        let cls = get_class("NSURL").expect("NSURL class not found");
        let path_str = nsstring(&abs_path);
        let url: *mut AnyObject = msg_send!(cls, fileURLWithPath: path_str);
        // Retain to prevent autorelease - caller is responsible for release
        let _: *mut AnyObject = msg_send!(url, retain);
        url
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
            std::ffi::CStr::from_ptr(cstr)
                .to_string_lossy()
                .into_owned()
        }
    }
}

/// Creates an NSArray from raw pointers.
fn nsarray(objects: &[*mut AnyObject]) -> *mut AnyObject {
    unsafe {
        let cls = get_class("NSArray").expect("NSArray class not found");
        let sel = sel!(arrayWithObjects:count:);
        let func: unsafe extern "C" fn(
            *const AnyClass,
            Sel,
            *const *mut AnyObject,
            usize,
        ) -> *mut AnyObject = std::mem::transmute(objc_msgSend as *const c_void);
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

    /// Sets serial ports.
    pub fn set_serial_ports(&self, ports: &[*mut AnyObject]) {
        unsafe {
            let array = nsarray(ports);
            msg_send_void!(self.inner, setSerialPorts: array);
        }
    }

    /// Sets directory sharing devices.
    pub fn set_directory_sharing_devices(&self, devices: &[*mut AnyObject]) {
        unsafe {
            let array = nsarray(devices);
            msg_send_void!(self.inner, setDirectorySharingDevices: array);
        }
    }

    /// Sets the platform configuration.
    pub fn set_platform(&self, platform: *mut AnyObject) {
        unsafe {
            msg_send_void!(self.inner, setPlatform: platform);
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

/// Creates a generic platform configuration for Linux VMs.
pub fn create_generic_platform() -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("VZGenericPlatformConfiguration").ok_or_else(|| VZError {
            code: -1,
            message: "VZGenericPlatformConfiguration class not found".into(),
        })?;
        let obj = msg_send!(cls, new);
        if obj.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create generic platform".into(),
            });
        }
        // Retain to prevent autorelease
        let _: *mut AnyObject = msg_send!(obj, retain);
        Ok(obj)
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

    /// Checks if the VM can stop.
    pub fn can_stop(&self) -> bool {
        unsafe { msg_send_bool!(self.inner, canStop).as_bool() }
    }

    /// Stops the VM asynchronously (macOS 12.0+).
    ///
    /// WARNING: This is a destructive operation. It stops the VM without
    /// giving the guest a chance to stop cleanly.
    pub fn stop_async(&self) {
        // Block layout for void (^)(NSError *)
        #[repr(C)]
        struct CompletionBlock {
            isa: *const c_void,
            flags: i32,
            reserved: i32,
            invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
            descriptor: *const BlockDescriptor,
        }

        #[repr(C)]
        struct BlockDescriptor {
            reserved: u64,
            size: u64,
        }

        unsafe extern "C" fn stop_completion_handler(_block: *const c_void, error: *mut AnyObject) {
            unsafe {
                if !error.is_null() {
                    let desc: *mut AnyObject = msg_send!(error, localizedDescription);
                    let error_msg = if !desc.is_null() {
                        nsstring_to_string(desc)
                    } else {
                        "Unknown error".to_string()
                    };
                    tracing::error!("VM stop failed: {}", error_msg);
                } else {
                    tracing::debug!("VM stop completion handler called (success)");
                }
            }
        }

        unsafe extern "C" {
            static _NSConcreteStackBlock: *const c_void;
            fn _Block_copy(block: *const c_void) -> *const c_void;
        }

        struct BlockPtr(*const c_void);
        unsafe impl Send for BlockPtr {}
        unsafe impl Sync for BlockPtr {}

        static STOP_BLOCK_PTR: std::sync::OnceLock<BlockPtr> = std::sync::OnceLock::new();

        let block_ptr = STOP_BLOCK_PTR.get_or_init(|| unsafe {
            static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
                reserved: 0,
                size: 40,
            };

            let stack_block = CompletionBlock {
                isa: _NSConcreteStackBlock,
                flags: 0,
                reserved: 0,
                invoke: stop_completion_handler,
                descriptor: &DESCRIPTOR,
            };

            let heap_block = _Block_copy(&stack_block as *const CompletionBlock as *const c_void);
            BlockPtr(heap_block)
        });

        unsafe {
            let sel = sel!(stopWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) =
                std::mem::transmute(objc_msgSend as *const c_void);

            func(self.inner as *const AnyObject, sel, block_ptr.0);
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
        // Block layout for void (^)(NSError *)
        #[repr(C)]
        struct CompletionBlock {
            isa: *const c_void,
            flags: i32,
            reserved: i32,
            invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
            descriptor: *const BlockDescriptor,
        }

        #[repr(C)]
        struct BlockDescriptor {
            reserved: u64,
            size: u64,
        }

        // Static completion handler function - block pointer is first arg
        unsafe extern "C" fn completion_handler(_block: *const c_void, error: *mut AnyObject) {
            unsafe {
                if !error.is_null() {
                    // Extract error description from NSError
                    let desc: *mut AnyObject = msg_send!(error, localizedDescription);
                    let error_msg = if !desc.is_null() {
                        nsstring_to_string(desc)
                    } else {
                        "Unknown error".to_string()
                    };
                    tracing::error!("VM start failed: {}", error_msg);
                } else {
                    tracing::debug!("VM start completion handler called (success)");
                }
            }
        }

        // Block runtime functions
        unsafe extern "C" {
            static _NSConcreteStackBlock: *const c_void;
            fn _Block_copy(block: *const c_void) -> *const c_void;
        }

        // Wrapper to make raw pointer Send + Sync safe
        struct BlockPtr(*const c_void);
        unsafe impl Send for BlockPtr {}
        unsafe impl Sync for BlockPtr {}

        // Use a properly copied block that lives forever
        static BLOCK_PTR: std::sync::OnceLock<BlockPtr> = std::sync::OnceLock::new();

        let block_ptr = BLOCK_PTR.get_or_init(|| {
            unsafe {
                static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
                    reserved: 0,
                    size: 40, // size of CompletionBlock
                };

                // Create a stack block and copy it to heap
                let stack_block = CompletionBlock {
                    isa: _NSConcreteStackBlock,
                    flags: 0, // No special flags for stack block
                    reserved: 0,
                    invoke: completion_handler,
                    descriptor: &DESCRIPTOR,
                };

                // _Block_copy moves the block to the heap and makes it permanent
                let heap_block =
                    _Block_copy(&stack_block as *const CompletionBlock as *const c_void);
                BlockPtr(heap_block)
            }
        });

        unsafe {
            let sel = sel!(startWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) =
                std::mem::transmute(objc_msgSend as *const c_void);

            func(self.inner as *const AnyObject, sel, block_ptr.0);
        }
    }

    /// Pauses the VM asynchronously.
    pub fn pause_async(&self) {
        // Block layout for void (^)(NSError *)
        #[repr(C)]
        struct CompletionBlock {
            isa: *const c_void,
            flags: i32,
            reserved: i32,
            invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
            descriptor: *const BlockDescriptor,
        }

        #[repr(C)]
        struct BlockDescriptor {
            reserved: u64,
            size: u64,
        }

        unsafe extern "C" fn pause_completion_handler(
            _block: *const c_void,
            error: *mut AnyObject,
        ) {
            unsafe {
                if !error.is_null() {
                    let desc: *mut AnyObject = msg_send!(error, localizedDescription);
                    let error_msg = if !desc.is_null() {
                        nsstring_to_string(desc)
                    } else {
                        "Unknown error".to_string()
                    };
                    tracing::error!("VM pause failed: {}", error_msg);
                } else {
                    tracing::debug!("VM pause completion handler called (success)");
                }
            }
        }

        unsafe extern "C" {
            static _NSConcreteStackBlock: *const c_void;
            fn _Block_copy(block: *const c_void) -> *const c_void;
        }

        struct BlockPtr(*const c_void);
        unsafe impl Send for BlockPtr {}
        unsafe impl Sync for BlockPtr {}

        static PAUSE_BLOCK_PTR: std::sync::OnceLock<BlockPtr> = std::sync::OnceLock::new();

        let block_ptr = PAUSE_BLOCK_PTR.get_or_init(|| unsafe {
            static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
                reserved: 0,
                size: 40,
            };

            let stack_block = CompletionBlock {
                isa: _NSConcreteStackBlock,
                flags: 0,
                reserved: 0,
                invoke: pause_completion_handler,
                descriptor: &DESCRIPTOR,
            };

            let heap_block = _Block_copy(&stack_block as *const CompletionBlock as *const c_void);
            BlockPtr(heap_block)
        });

        unsafe {
            let sel = sel!(pauseWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) =
                std::mem::transmute(objc_msgSend as *const c_void);

            func(self.inner as *const AnyObject, sel, block_ptr.0);
        }
    }

    /// Resumes the VM asynchronously.
    pub fn resume_async(&self) {
        // Block layout for void (^)(NSError *)
        #[repr(C)]
        struct CompletionBlock {
            isa: *const c_void,
            flags: i32,
            reserved: i32,
            invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject),
            descriptor: *const BlockDescriptor,
        }

        #[repr(C)]
        struct BlockDescriptor {
            reserved: u64,
            size: u64,
        }

        unsafe extern "C" fn resume_completion_handler(
            _block: *const c_void,
            error: *mut AnyObject,
        ) {
            unsafe {
                if !error.is_null() {
                    let desc: *mut AnyObject = msg_send!(error, localizedDescription);
                    let error_msg = if !desc.is_null() {
                        nsstring_to_string(desc)
                    } else {
                        "Unknown error".to_string()
                    };
                    tracing::error!("VM resume failed: {}", error_msg);
                } else {
                    tracing::debug!("VM resume completion handler called (success)");
                }
            }
        }

        unsafe extern "C" {
            static _NSConcreteStackBlock: *const c_void;
            fn _Block_copy(block: *const c_void) -> *const c_void;
        }

        struct BlockPtr(*const c_void);
        unsafe impl Send for BlockPtr {}
        unsafe impl Sync for BlockPtr {}

        static RESUME_BLOCK_PTR: std::sync::OnceLock<BlockPtr> = std::sync::OnceLock::new();

        let block_ptr = RESUME_BLOCK_PTR.get_or_init(|| unsafe {
            static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
                reserved: 0,
                size: 40,
            };

            let stack_block = CompletionBlock {
                isa: _NSConcreteStackBlock,
                flags: 0,
                reserved: 0,
                invoke: resume_completion_handler,
                descriptor: &DESCRIPTOR,
            };

            let heap_block = _Block_copy(&stack_block as *const CompletionBlock as *const c_void);
            BlockPtr(heap_block)
        });

        unsafe {
            let sel = sel!(resumeWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyObject, Sel, *const c_void) =
                std::mem::transmute(objc_msgSend as *const c_void);

            func(self.inner as *const AnyObject, sel, block_ptr.0);
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
        let func: unsafe extern "C" fn(
            *mut AnyObject,
            Sel,
            *mut AnyObject,
            Bool,
            *mut *mut AnyObject,
        ) -> *mut AnyObject = std::mem::transmute(objc_msgSend as *const c_void);
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
        // Retain to prevent autorelease
        let _: *mut AnyObject = msg_send!(obj, retain);
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
        let func: unsafe extern "C" fn(
            *mut AnyObject,
            Sel,
            *mut AnyObject,
            Bool,
        ) -> *mut AnyObject = std::mem::transmute(objc_msgSend as *const c_void);
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
// CFRunLoop
// ============================================================================

/// Opaque type for CFRunLoop
pub type CFRunLoopRef = *mut c_void;

/// Run loop run result
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CFRunLoopRunResult {
    Finished = 1,
    Stopped = 2,
    TimedOut = 3,
    HandledSource = 4,
}

// CFRunLoop FFI
unsafe extern "C" {
    fn CFRunLoopGetMain() -> CFRunLoopRef;
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopRun();
    fn CFRunLoopStop(rl: CFRunLoopRef);
    fn CFRunLoopRunInMode(mode: *const c_void, seconds: f64, returnAfterSourceHandled: bool)
    -> i32;
}

// kCFRunLoopDefaultMode is a CFStringRef constant
unsafe extern "C" {
    static kCFRunLoopDefaultMode: *const c_void;
}

/// Gets the main CFRunLoop.
pub fn cf_run_loop_get_main() -> CFRunLoopRef {
    unsafe { CFRunLoopGetMain() }
}

/// Gets the current thread's CFRunLoop.
pub fn cf_run_loop_get_current() -> CFRunLoopRef {
    unsafe { CFRunLoopGetCurrent() }
}

/// Runs the current run loop indefinitely.
pub fn cf_run_loop_run() {
    unsafe { CFRunLoopRun() }
}

/// Stops a run loop.
pub fn cf_run_loop_stop(rl: CFRunLoopRef) {
    unsafe { CFRunLoopStop(rl) }
}

/// Runs the run loop in default mode for up to the specified duration.
/// Returns the result indicating why the run loop exited.
pub fn cf_run_loop_run_in_mode(
    seconds: f64,
    return_after_source_handled: bool,
) -> CFRunLoopRunResult {
    unsafe {
        let result =
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, seconds, return_after_source_handled);
        match result {
            1 => CFRunLoopRunResult::Finished,
            2 => CFRunLoopRunResult::Stopped,
            3 => CFRunLoopRunResult::TimedOut,
            4 => CFRunLoopRunResult::HandledSource,
            _ => CFRunLoopRunResult::TimedOut,
        }
    }
}

/// Runs the run loop, processing events until the predicate returns true or timeout.
pub fn run_loop_until<F>(mut predicate: F, timeout_secs: f64) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs_f64(timeout_secs);

    while !predicate() {
        if start.elapsed() > timeout {
            return false;
        }

        // Run the run loop for a short interval
        cf_run_loop_run_in_mode(0.01, true);
    }

    true
}

// ============================================================================
// Dispatch Queue
// ============================================================================

// Dispatch queue FFI
unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> *mut AnyObject;
    fn dispatch_sync(queue: *mut AnyObject, block: *const c_void);
    fn dispatch_async(queue: *mut AnyObject, block: *const c_void);
    // dispatch_get_main_queue is a macro - we access _dispatch_main_q directly
    static _dispatch_main_q: *mut AnyObject;
}

/// Executes a closure synchronously on the given dispatch queue.
///
/// Uses dispatch_sync_f which is simpler than block-based dispatch_sync.
pub fn dispatch_sync_closure<F: FnMut()>(queue: *mut AnyObject, mut f: F) {
    if queue.is_null() {
        // If no queue, just execute directly
        f();
        return;
    }

    // Use dispatch_sync_f instead of dispatch_sync with blocks
    // dispatch_sync_f takes a function pointer and context directly
    unsafe extern "C" {
        fn dispatch_sync_f(
            queue: *mut AnyObject,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
    }

    unsafe extern "C" fn trampoline<F: FnMut()>(context: *mut c_void) {
        unsafe {
            let f = &mut *(context as *mut F);
            f();
        }
    }

    unsafe {
        dispatch_sync_f(queue, &mut f as *mut F as *mut c_void, trampoline::<F>);
    }
}

/// Gets the main dispatch queue.
pub fn get_main_queue() -> *mut AnyObject {
    unsafe { _dispatch_main_q }
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
/// Uses `initWithFileDescriptor:closeOnDealloc:NO` to prevent NSFileHandle from
/// closing the file descriptor when deallocated.
pub fn create_file_handle_for_reading(fd: i32) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls = get_class("NSFileHandle").ok_or_else(|| VZError {
            code: -1,
            message: "NSFileHandle class not found".into(),
        })?;
        let obj = msg_send!(cls, alloc);

        // Use initWithFileDescriptor:closeOnDealloc: to prevent double-close
        let sel = sel!(initWithFileDescriptor:closeOnDealloc:);
        let func: unsafe extern "C" fn(*mut AnyObject, Sel, i32, bool) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        let handle = func(obj, sel, fd, false);

        if handle.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create NSFileHandle".into(),
            });
        }

        tracing::debug!("Created NSFileHandle for fd {}", fd);
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

/// Creates a VirtIO console device serial port configuration.
/// This is simpler than VZVirtioConsoleDeviceConfiguration - it creates a single
/// serial port that appears as hvc0 in the guest.
pub fn create_virtio_serial_port_configuration(
    attachment: *mut AnyObject,
) -> VZResult<*mut AnyObject> {
    unsafe {
        let cls =
            get_class("VZVirtioConsoleDeviceSerialPortConfiguration").ok_or_else(|| VZError {
                code: -1,
                message: "VZVirtioConsoleDeviceSerialPortConfiguration class not found".into(),
            })?;
        // Use new and then set attachment (inherited from VZSerialPortConfiguration)
        let port: *mut AnyObject = msg_send!(cls, new);
        if port.is_null() {
            return Err(VZError {
                code: -1,
                message: "Failed to create virtio serial port configuration".into(),
            });
        }
        // Set the attachment property
        msg_send_void!(port, setAttachment: attachment);
        Ok(port)
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

/// Gets the ports array from a console device.
/// Returns VZVirtioConsolePortConfigurationArray, not a standard NSArray.
pub fn get_console_device_ports(device: *mut AnyObject) -> *mut AnyObject {
    unsafe { msg_send!(device, ports) }
}

/// Sets maximum port count on the console ports array.
pub fn set_ports_array_max_count(ports_array: *mut AnyObject, count: u64) {
    unsafe {
        msg_send_void_u64!(ports_array, setMaximumPortCount: count);
    }
}

/// Sets a port at a specific index in the console ports array.
pub fn set_port_at_index(ports_array: *mut AnyObject, port: *mut AnyObject, index: u64) {
    unsafe {
        let sel = sel!(setObject:atIndexedSubscript:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, *mut AnyObject, u64) =
            std::mem::transmute(objc_msgSend as *const c_void);
        func(ports_array as *const AnyObject, sel, port, index);
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
// Vsock Support
// ============================================================================

/// Gets the socket devices from a running VM.
///
/// Returns an NSArray of VZVirtioSocketDevice objects.
pub fn vm_socket_devices(vm: *mut AnyObject) -> *mut AnyObject {
    if vm.is_null() {
        return ptr::null_mut();
    }
    unsafe { msg_send!(vm, socketDevices) }
}

/// Represents a vsock connection result.
pub struct VsockConnectionResult {
    /// The file descriptor for the connection, or -1 on error.
    pub fd: i32,
    /// Error message if connection failed.
    pub error: Option<String>,
}

/// Global state for vsock connection completion.
/// This is used because Objective-C blocks with captured Rust state are complex.
static VSOCK_CONN_RESULT: std::sync::OnceLock<std::sync::Mutex<Option<VsockConnectionResult>>> =
    std::sync::OnceLock::new();
static VSOCK_CONN_CONDVAR: std::sync::OnceLock<std::sync::Condvar> = std::sync::OnceLock::new();

/// Connects to a port on a vsock device.
///
/// This is an async operation that uses a completion handler.
/// The function blocks until the connection completes or fails.
///
/// # Arguments
/// * `socket_device` - The VZVirtioSocketDevice to connect through
/// * `vm_queue` - The dispatch queue for the VM (required for async operations)
/// * `port` - The port number to connect to
///
/// # Returns
/// The file descriptor for the connection, or an error.
///
/// # Safety
/// This function is NOT thread-safe for concurrent vsock connections.
/// Only one vsock connection should be made at a time.
pub fn vsock_connect_to_port(
    socket_device: *mut AnyObject,
    vm_queue: *mut AnyObject,
    port: u32,
) -> VZResult<i32> {
    if socket_device.is_null() {
        return Err(VZError {
            code: -1,
            message: "socket_device is null".to_string(),
        });
    }

    if vm_queue.is_null() {
        return Err(VZError {
            code: -1,
            message: "vm_queue is null".to_string(),
        });
    }

    // Initialize globals
    let result_mutex = VSOCK_CONN_RESULT.get_or_init(|| std::sync::Mutex::new(None));
    let _condvar = VSOCK_CONN_CONDVAR.get_or_init(|| std::sync::Condvar::new());

    // Clear previous result
    {
        let mut guard = result_mutex.lock().unwrap();
        *guard = None;
    }

    // Block layout for void (^)(VZVirtioSocketConnection *, NSError *)
    #[repr(C)]
    struct VsockCompletionBlock {
        isa: *const c_void,
        flags: i32,
        reserved: i32,
        invoke: unsafe extern "C" fn(*const c_void, *mut AnyObject, *mut AnyObject),
        descriptor: *const BlockDescriptor,
    }

    #[repr(C)]
    struct BlockDescriptor {
        reserved: u64,
        size: u64,
    }

    unsafe extern "C" fn vsock_completion_handler(
        _block: *const c_void,
        connection: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        tracing::debug!(
            "vsock_completion_handler called: connection={:?}, error={:?}",
            connection,
            error
        );

        let conn_result = unsafe {
            if !error.is_null() {
                let description: *mut AnyObject = msg_send!(error, localizedDescription);
                let error_msg = if !description.is_null() {
                    nsstring_to_string(description)
                } else {
                    "Unknown error".to_string()
                };
                tracing::debug!("vsock connection error: {}", error_msg);
                VsockConnectionResult {
                    fd: -1,
                    error: Some(error_msg),
                }
            } else if !connection.is_null() {
                let fd: i32 = msg_send_i32!(connection, fileDescriptor);
                // Duplicate the fd so it stays valid even if the connection object is released.
                let dup_fd = unsafe { libc::dup(fd) };
                if dup_fd < 0 {
                    let errno = *libc::__error();
                    tracing::debug!("vsock connection dup failed: errno={}", errno);
                    VsockConnectionResult {
                        fd: -1,
                        error: Some(format!("dup failed: errno={}", errno)),
                    }
                } else {
                    tracing::debug!("vsock connection success: fd={} (dup={})", fd, dup_fd);
                    VsockConnectionResult {
                        fd: dup_fd,
                        error: None,
                    }
                }
            } else {
                tracing::debug!("vsock connection: both connection and error are null");
                VsockConnectionResult {
                    fd: -1,
                    error: Some("Connection is null".to_string()),
                }
            }
        };

        // Store result and signal
        if let Some(mutex) = VSOCK_CONN_RESULT.get() {
            if let Ok(mut guard) = mutex.lock() {
                *guard = Some(conn_result);
                tracing::debug!("vsock result stored in mutex");
            }
        }
        if let Some(cv) = VSOCK_CONN_CONDVAR.get() {
            cv.notify_one();
            tracing::debug!("vsock condvar notified");
        }
    }

    unsafe extern "C" {
        static _NSConcreteStackBlock: *const c_void;
        fn _Block_copy(block: *const c_void) -> *const c_void;
    }

    struct BlockPtr(*const c_void);
    unsafe impl Send for BlockPtr {}
    unsafe impl Sync for BlockPtr {}

    // Create and copy the block
    static VSOCK_BLOCK_PTR: std::sync::OnceLock<BlockPtr> = std::sync::OnceLock::new();

    let block_ptr = VSOCK_BLOCK_PTR.get_or_init(|| unsafe {
        static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            size: 40,
        };

        let stack_block = VsockCompletionBlock {
            isa: _NSConcreteStackBlock,
            flags: 0,
            reserved: 0,
            invoke: vsock_completion_handler,
            descriptor: &DESCRIPTOR,
        };

        let heap_block = _Block_copy(&stack_block as *const VsockCompletionBlock as *const c_void);
        BlockPtr(heap_block)
    });

    // Context for dispatch_async_f
    #[repr(C)]
    struct VsockConnectContext {
        socket_device: *mut AnyObject,
        port: u32,
        completion_block: *const c_void,
    }

    unsafe impl Send for VsockConnectContext {}
    unsafe impl Sync for VsockConnectContext {}

    // Function to be called on the VM's dispatch queue
    unsafe extern "C" fn vsock_connect_on_queue(context: *mut c_void) {
        // SAFETY: context is a valid pointer to VsockConnectContext created by Box::into_raw
        let ctx = unsafe { &*(context as *const VsockConnectContext) };
        tracing::debug!(
            "vsock_connect_on_queue: device={:?}, port={}, block={:?}",
            ctx.socket_device,
            ctx.port,
            ctx.completion_block
        );

        // Call connectToPort:completionHandler:
        let sel = sel!(connectToPort:completionHandler:);
        // SAFETY: objc_msgSend is a valid function pointer
        let func: unsafe extern "C" fn(*mut AnyObject, Sel, u32, *const c_void) =
            unsafe { std::mem::transmute(objc_msgSend as *const c_void) };
        // SAFETY: ctx fields are valid pointers set during context creation
        unsafe { func(ctx.socket_device, sel, ctx.port, ctx.completion_block) };
    }

    unsafe extern "C" {
        fn dispatch_async_f(
            queue: *mut AnyObject,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
    }

    // Create context on heap so it lives until the async work completes
    let context = Box::new(VsockConnectContext {
        socket_device,
        port,
        completion_block: block_ptr.0,
    });
    let context_ptr = Box::into_raw(context);

    unsafe {
        tracing::debug!(
            "Dispatching vsock connect to VM queue: queue={:?}, port={}",
            vm_queue,
            port
        );

        // Dispatch the connect call to the VM's queue
        dispatch_async_f(vm_queue, context_ptr as *mut c_void, vsock_connect_on_queue);

        // Wait for completion with timeout
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(10);

        loop {
            // Sleep briefly to allow the dispatch queue to process
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Check if we have a result
            let guard = result_mutex.lock().unwrap();
            if guard.is_some() {
                // Clean up context
                drop(Box::from_raw(context_ptr));

                // We have a result
                match &*guard {
                    Some(conn_result) => {
                        if let Some(ref err) = conn_result.error {
                            return Err(VZError {
                                code: -1,
                                message: err.clone(),
                            });
                        } else if conn_result.fd >= 0 {
                            return Ok(conn_result.fd);
                        } else {
                            return Err(VZError {
                                code: -1,
                                message: "Invalid file descriptor".to_string(),
                            });
                        }
                    }
                    None => unreachable!(),
                }
            }
            drop(guard);

            // Check timeout
            if start.elapsed() > timeout {
                // Clean up context
                drop(Box::from_raw(context_ptr));
                return Err(VZError {
                    code: -1,
                    message: "Connection timed out".to_string(),
                });
            }
        }
    }
}

/// Gets the first socket device from a VM, if any.
pub fn vm_first_socket_device(vm: *mut AnyObject) -> Option<*mut AnyObject> {
    let devices = vm_socket_devices(vm);
    if devices.is_null() {
        return None;
    }

    unsafe {
        let count: usize = msg_send_u64!(devices, count) as usize;
        if count == 0 {
            return None;
        }

        // Use specific function for objectAtIndex: which takes NSUInteger
        let sel = sel!(objectAtIndex:);
        let func: unsafe extern "C" fn(*const AnyObject, Sel, usize) -> *mut AnyObject =
            std::mem::transmute(objc_msgSend as *const c_void);
        let device = func(devices as *const AnyObject, sel, 0usize);

        if device.is_null() { None } else { Some(device) }
    }
}

/// Sends a message returning an i32.
macro_rules! msg_send_i32 {
    ($obj:expr, $sel:ident) => {{
        let sel = sel!($sel);
        let func: unsafe extern "C" fn(*const AnyObject, Sel) -> i32 =
            std::mem::transmute(objc_msgSend as *const c_void);
        func($obj as *const _ as *const AnyObject, sel)
    }};
}

pub(crate) use msg_send_i32;

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

    #[test]
    fn test_run_loop_until_immediate() {
        // Test immediate completion
        let result = run_loop_until(|| true, 1.0);
        assert!(
            result,
            "run_loop_until should return true when predicate is immediately true"
        );
    }

    #[test]
    fn test_run_loop_until_timeout() {
        // Test timeout
        let start = std::time::Instant::now();
        let result = run_loop_until(|| false, 0.1);
        let elapsed = start.elapsed();

        assert!(!result, "run_loop_until should return false on timeout");
        assert!(
            elapsed.as_secs_f64() >= 0.1,
            "Should have waited at least 0.1 seconds"
        );
        assert!(
            elapsed.as_secs_f64() < 0.5,
            "Should not have waited too long"
        );
    }

    #[test]
    fn test_run_loop_until_delayed() {
        // Test delayed completion
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = flag.clone();

        // Spawn a thread to set the flag after 50ms
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            flag_clone.store(true, Ordering::SeqCst);
        });

        let result = run_loop_until(|| flag.load(Ordering::SeqCst), 1.0);
        assert!(
            result,
            "run_loop_until should return true when predicate becomes true"
        );
    }

    #[test]
    fn test_cf_run_loop_run_in_mode() {
        // Test running the run loop for a short interval
        let result = cf_run_loop_run_in_mode(0.01, true);

        // Result should be Finished (no sources) or TimedOut
        // When there are no run loop sources, the run loop exits immediately with Finished
        assert!(
            result == CFRunLoopRunResult::Finished || result == CFRunLoopRunResult::TimedOut,
            "Expected Finished or TimedOut, got {:?}",
            result
        );
    }

    #[test]
    fn test_main_queue() {
        let queue = get_main_queue();
        assert!(!queue.is_null(), "Main dispatch queue should not be null");
    }
}
