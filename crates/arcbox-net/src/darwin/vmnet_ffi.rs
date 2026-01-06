//! vmnet.framework FFI bindings.
//!
//! This module provides low-level bindings to Apple's vmnet.framework
//! for creating virtual network interfaces on macOS.
//!
//! # Architecture
//!
//! vmnet.framework uses Grand Central Dispatch (GCD) for asynchronous operations.
//! All callbacks are delivered on dispatch queues.
//!
//! # References
//!
//! - Apple vmnet documentation: https://developer.apple.com/documentation/vmnet
//! - lima-vm/socket_vmnet: https://github.com/lima-vm/socket_vmnet

use std::ffi::{c_char, c_void};
use std::os::raw::c_int;
use std::ptr;

/// vmnet interface handle (opaque pointer).
pub type VmnetInterfaceRef = *mut c_void;

/// Dispatch queue (opaque pointer).
pub type DispatchQueue = *mut c_void;

/// vmnet return status.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmnetReturnT {
    /// Operation succeeded.
    Success = 1000,
    /// Operation failed.
    Failure = 1001,
    /// Memory allocation failed.
    MemFailure = 1002,
    /// Invalid argument.
    InvalidArgument = 1003,
    /// Setup incomplete.
    SetupIncomplete = 1004,
    /// Invalid access.
    InvalidAccess = 1005,
    /// Packet too big.
    PacketTooBig = 1006,
    /// Buffer exhausted.
    BufferExhausted = 1007,
    /// Too many packets.
    TooManyPackets = 1008,
    /// Sharing service busy.
    SharingServiceBusy = 1009,
}

impl VmnetReturnT {
    /// Returns true if the status indicates success.
    #[must_use]
    pub fn is_success(self) -> bool {
        self == Self::Success
    }

    /// Returns an error message for the status.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "operation failed",
            Self::MemFailure => "memory allocation failed",
            Self::InvalidArgument => "invalid argument",
            Self::SetupIncomplete => "setup incomplete",
            Self::InvalidAccess => "invalid access",
            Self::PacketTooBig => "packet too big",
            Self::BufferExhausted => "buffer exhausted",
            Self::TooManyPackets => "too many packets",
            Self::SharingServiceBusy => "sharing service busy",
        }
    }
}

/// vmnet operation mode.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmnetOperatingMode {
    /// Host mode (isolated network between VMs and host).
    Host = 1000,
    /// Shared mode (NAT with host network).
    Shared = 1001,
    /// Bridged mode (direct access to physical network).
    Bridged = 1002,
}

/// vmnet interface event.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmnetInterfaceEvent {
    /// Packets are available for reading.
    PacketsAvailable = 1,
}

/// Packet descriptor for vmnet read/write operations.
#[repr(C)]
#[derive(Debug)]
pub struct VmnetPacket {
    /// Pointer to packet data.
    pub vm_pkt_iov: *mut iovec,
    /// Number of iovec entries.
    pub vm_pkt_iovcnt: u32,
    /// Packet size in bytes.
    pub vm_pkt_size: u32,
    /// Flags.
    pub vm_flags: u32,
}

/// IO vector for scatter-gather I/O.
#[repr(C)]
#[derive(Debug)]
pub struct iovec {
    /// Pointer to data.
    pub iov_base: *mut c_void,
    /// Length of data.
    pub iov_len: usize,
}

// CFDictionary types (Core Foundation).
pub type CFDictionaryRef = *const c_void;
pub type CFMutableDictionaryRef = *mut c_void;
pub type CFStringRef = *const c_void;
pub type CFNumberRef = *const c_void;
pub type CFTypeRef = *const c_void;
pub type CFAllocatorRef = *const c_void;
pub type CFUUIDRef = *const c_void;

/// Core Foundation number types.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CFNumberType {
    SInt8 = 1,
    SInt16 = 2,
    SInt32 = 3,
    SInt64 = 4,
    Float32 = 5,
    Float64 = 6,
    Char = 7,
    Short = 8,
    Int = 9,
    Long = 10,
    LongLong = 11,
    Float = 12,
    Double = 13,
}

// Dispatch block type.
pub type DispatchBlock = extern "C" fn();

#[link(name = "vmnet", kind = "framework")]
unsafe extern "C" {
    /// Starts a vmnet interface.
    ///
    /// # Parameters
    /// - `interface_desc`: Configuration dictionary
    /// - `queue`: Dispatch queue for completion handler
    /// - `handler`: Completion handler block
    ///
    /// # Returns
    /// vmnet interface handle, or NULL on failure.
    pub fn vmnet_start_interface(
        interface_desc: CFDictionaryRef,
        queue: DispatchQueue,
        handler: *const c_void, // Block
    ) -> VmnetInterfaceRef;

    /// Stops a vmnet interface.
    pub fn vmnet_stop_interface(
        interface: VmnetInterfaceRef,
        queue: DispatchQueue,
        handler: *const c_void, // Block
    ) -> VmnetReturnT;

    /// Reads packets from a vmnet interface.
    ///
    /// # Parameters
    /// - `interface`: vmnet interface handle
    /// - `packets`: Array of packet descriptors
    /// - `pktcnt`: Pointer to packet count (in/out)
    ///
    /// # Returns
    /// Status code.
    pub fn vmnet_read(
        interface: VmnetInterfaceRef,
        packets: *mut VmnetPacket,
        pktcnt: *mut c_int,
    ) -> VmnetReturnT;

    /// Writes packets to a vmnet interface.
    ///
    /// # Parameters
    /// - `interface`: vmnet interface handle
    /// - `packets`: Array of packet descriptors
    /// - `pktcnt`: Pointer to packet count (in/out)
    ///
    /// # Returns
    /// Status code.
    pub fn vmnet_write(
        interface: VmnetInterfaceRef,
        packets: *mut VmnetPacket,
        pktcnt: *mut c_int,
    ) -> VmnetReturnT;

    /// Sets the event callback for a vmnet interface.
    pub fn vmnet_interface_set_event_callback(
        interface: VmnetInterfaceRef,
        event_mask: VmnetInterfaceEvent,
        queue: DispatchQueue,
        handler: *const c_void, // Block
    ) -> VmnetReturnT;

    /// Copies the list of shared interfaces available for bridging.
    pub fn vmnet_copy_shared_interface_list() -> *mut c_void; // xpc_object_t
}

// vmnet configuration keys (CFString).
#[link(name = "vmnet", kind = "framework")]
unsafe extern "C" {
    /// Operating mode key.
    pub static vmnet_operation_mode_key: CFStringRef;
    /// Shared interface name key (for bridged mode).
    pub static vmnet_shared_interface_name_key: CFStringRef;
    /// MAC address key.
    pub static vmnet_mac_address_key: CFStringRef;
    /// Start address key (for shared mode DHCP range).
    pub static vmnet_start_address_key: CFStringRef;
    /// End address key (for shared mode DHCP range).
    pub static vmnet_end_address_key: CFStringRef;
    /// Subnet mask key.
    pub static vmnet_subnet_mask_key: CFStringRef;
    /// Interface ID key (UUID for host mode isolation).
    pub static vmnet_interface_id_key: CFStringRef;
    /// Enable isolation key (for host mode).
    pub static vmnet_enable_isolation_key: CFStringRef;
    /// NAT66 prefix key.
    pub static vmnet_nat66_prefix_key: CFStringRef;
    /// Maximum transmission unit key.
    pub static vmnet_mtu_key: CFStringRef;
    /// Maximum packet size key (returned in interface_param).
    pub static vmnet_max_packet_size_key: CFStringRef;
}

// Core Foundation functions.
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    pub static kCFAllocatorDefault: CFAllocatorRef;
    pub static kCFBooleanTrue: CFTypeRef;
    pub static kCFBooleanFalse: CFTypeRef;

    pub fn CFDictionaryCreateMutable(
        allocator: CFAllocatorRef,
        capacity: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFMutableDictionaryRef;

    pub fn CFDictionarySetValue(
        dict: CFMutableDictionaryRef,
        key: CFTypeRef,
        value: CFTypeRef,
    );

    pub fn CFDictionaryGetValue(
        dict: CFDictionaryRef,
        key: CFTypeRef,
    ) -> CFTypeRef;

    pub fn CFRelease(cf: CFTypeRef);
    pub fn CFRetain(cf: CFTypeRef) -> CFTypeRef;

    pub fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        cstr: *const c_char,
        encoding: u32,
    ) -> CFStringRef;

    pub fn CFNumberCreate(
        allocator: CFAllocatorRef,
        type_: CFNumberType,
        value_ptr: *const c_void,
    ) -> CFNumberRef;

    pub fn CFNumberGetValue(
        number: CFNumberRef,
        type_: CFNumberType,
        value_ptr: *mut c_void,
    ) -> bool;

    pub fn CFUUIDCreate(allocator: CFAllocatorRef) -> CFUUIDRef;

    pub fn CFUUIDCreateString(
        allocator: CFAllocatorRef,
        uuid: CFUUIDRef,
    ) -> CFStringRef;
}

// Dispatch queue functions.
#[link(name = "System")]
unsafe extern "C" {
    pub fn dispatch_queue_create(
        label: *const c_char,
        attr: *const c_void,
    ) -> DispatchQueue;

    pub fn dispatch_release(object: *mut c_void);

    pub fn dispatch_async(
        queue: DispatchQueue,
        block: *const c_void,
    );

    pub fn dispatch_sync(
        queue: DispatchQueue,
        block: *const c_void,
    );

    pub static _dispatch_queue_attr_concurrent: *const c_void;
}

/// UTF-8 string encoding for Core Foundation.
pub const K_CF_STRING_ENCODING_UTF8: u32 = 0x08000100;

/// Helper to create a CFString from a Rust string.
///
/// # Safety
///
/// The returned CFString must be released with CFRelease.
#[must_use]
pub unsafe fn cfstring_from_str(s: &str) -> CFStringRef {
    let cstr = std::ffi::CString::new(s).unwrap();
    unsafe { CFStringCreateWithCString(kCFAllocatorDefault, cstr.as_ptr(), K_CF_STRING_ENCODING_UTF8) }
}

/// Helper to create a CFNumber from an i64.
///
/// # Safety
///
/// The returned CFNumber must be released with CFRelease.
#[must_use]
pub unsafe fn cfnumber_from_i64(value: i64) -> CFNumberRef {
    unsafe { CFNumberCreate(kCFAllocatorDefault, CFNumberType::SInt64, &value as *const _ as *const c_void) }
}

/// Creates a mutable dictionary for vmnet configuration.
///
/// # Safety
///
/// The returned dictionary must be released with CFRelease.
#[must_use]
pub unsafe fn create_vmnet_config_dict() -> CFMutableDictionaryRef {
    unsafe { CFDictionaryCreateMutable(kCFAllocatorDefault, 0, ptr::null(), ptr::null()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmnet_return_messages() {
        assert_eq!(VmnetReturnT::Success.message(), "success");
        assert_eq!(VmnetReturnT::Failure.message(), "operation failed");
        assert!(VmnetReturnT::Success.is_success());
        assert!(!VmnetReturnT::Failure.is_success());
    }

    #[test]
    fn test_operating_modes() {
        assert_eq!(VmnetOperatingMode::Host as i32, 1000);
        assert_eq!(VmnetOperatingMode::Shared as i32, 1001);
        assert_eq!(VmnetOperatingMode::Bridged as i32, 1002);
    }
}
