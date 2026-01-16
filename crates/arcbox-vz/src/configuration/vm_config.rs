//! Virtual machine configuration.

use crate::device::{
    EntropyDeviceConfiguration, NetworkDeviceConfiguration, SerialPortConfiguration,
    SocketDeviceConfiguration, StorageDeviceConfiguration, VirtioFileSystemDeviceConfiguration,
};
use crate::error::{VZError, VZResult};
use crate::ffi::{DispatchQueue, get_class, nsarray, release};
use crate::vm::VirtualMachine;
use crate::{msg_send, msg_send_bool, msg_send_u64, msg_send_void, msg_send_void_u64};
use objc2::runtime::AnyObject;
use std::ptr;

use super::{BootLoader, Platform};

// ============================================================================
// VM Configuration
// ============================================================================

/// Configuration for creating a virtual machine.
///
/// Use the builder methods to configure the VM, then call `build()` to
/// create the `VirtualMachine` instance.
pub struct VirtualMachineConfiguration {
    inner: *mut AnyObject,
    storage_devices: Vec<*mut AnyObject>,
    network_devices: Vec<*mut AnyObject>,
    serial_ports: Vec<*mut AnyObject>,
    socket_devices: Vec<*mut AnyObject>,
    entropy_devices: Vec<*mut AnyObject>,
    directory_sharing_devices: Vec<*mut AnyObject>,
}

unsafe impl Send for VirtualMachineConfiguration {}

impl VirtualMachineConfiguration {
    /// Creates a new VM configuration with default settings.
    pub fn new() -> VZResult<Self> {
        unsafe {
            let cls =
                get_class("VZVirtualMachineConfiguration").ok_or_else(|| VZError::Internal {
                    code: -1,
                    message: "VZVirtualMachineConfiguration class not found".into(),
                })?;
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, init);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create VZVirtualMachineConfiguration".into(),
                });
            }

            Ok(Self {
                inner: obj,
                storage_devices: Vec::new(),
                network_devices: Vec::new(),
                serial_ports: Vec::new(),
                socket_devices: Vec::new(),
                entropy_devices: Vec::new(),
                directory_sharing_devices: Vec::new(),
            })
        }
    }

    /// Sets the number of CPUs for the VM.
    ///
    /// # Panics
    ///
    /// Panics if `count` is outside the allowed range.
    /// Use `arcbox_vz::min_cpu_count()` and `arcbox_vz::max_cpu_count()`
    /// to get the valid range.
    pub fn set_cpu_count(&mut self, count: usize) -> &mut Self {
        unsafe {
            msg_send_void_u64!(self.inner, setCPUCount: count as u64);
        }
        self
    }

    /// Gets the configured CPU count.
    pub fn cpu_count(&self) -> u64 {
        unsafe { msg_send_u64!(self.inner, CPUCount) }
    }

    /// Sets the memory size in bytes.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is outside the allowed range.
    /// Use `arcbox_vz::min_memory_size()` and `arcbox_vz::max_memory_size()`
    /// to get the valid range.
    pub fn set_memory_size(&mut self, bytes: u64) -> &mut Self {
        unsafe {
            msg_send_void_u64!(self.inner, setMemorySize: bytes);
        }
        self
    }

    /// Gets the configured memory size in bytes.
    pub fn memory_size(&self) -> u64 {
        unsafe { msg_send_u64!(self.inner, memorySize) }
    }

    /// Sets the boot loader for the VM.
    pub fn set_boot_loader(&mut self, boot_loader: impl BootLoader) -> &mut Self {
        unsafe {
            msg_send_void!(self.inner, setBootLoader: boot_loader.as_ptr());
        }
        self
    }

    /// Sets the platform configuration.
    pub fn set_platform(&mut self, platform: impl Platform) -> &mut Self {
        unsafe {
            msg_send_void!(self.inner, setPlatform: platform.as_ptr());
        }
        self
    }

    /// Adds a storage device to the VM.
    pub fn add_storage_device(&mut self, device: StorageDeviceConfiguration) -> &mut Self {
        self.storage_devices.push(device.into_ptr());
        self
    }

    /// Adds a network device to the VM.
    pub fn add_network_device(&mut self, device: NetworkDeviceConfiguration) -> &mut Self {
        self.network_devices.push(device.into_ptr());
        self
    }

    /// Adds a serial port to the VM.
    pub fn add_serial_port(&mut self, port: SerialPortConfiguration) -> &mut Self {
        self.serial_ports.push(port.into_ptr());
        self
    }

    /// Adds a socket device (vsock) to the VM.
    pub fn add_socket_device(&mut self, device: SocketDeviceConfiguration) -> &mut Self {
        self.socket_devices.push(device.into_ptr());
        self
    }

    /// Adds an entropy device to the VM.
    pub fn add_entropy_device(&mut self, device: EntropyDeviceConfiguration) -> &mut Self {
        self.entropy_devices.push(device.into_ptr());
        self
    }

    /// Adds a VirtioFS directory sharing device to the VM.
    ///
    /// This allows sharing directories between the host and guest using
    /// the VirtIO file system protocol.
    pub fn add_directory_share(
        &mut self,
        device: VirtioFileSystemDeviceConfiguration,
    ) -> &mut Self {
        self.directory_sharing_devices.push(device.into_ptr());
        self
    }

    /// Validates the configuration.
    ///
    /// This is called automatically by `build()`, but can be called
    /// manually to check for configuration errors early.
    pub fn validate(&self) -> VZResult<()> {
        unsafe {
            let mut error: *mut AnyObject = ptr::null_mut();
            let valid = msg_send_bool!(self.inner, validateWithError: &mut error);
            if valid.as_bool() {
                Ok(())
            } else {
                Err(crate::ffi::extract_nserror(error))
            }
        }
    }

    /// Builds the virtual machine from this configuration.
    ///
    /// This finalizes all device configurations and creates the
    /// `VirtualMachine` instance.
    pub fn build(mut self) -> VZResult<VirtualMachine> {
        // Apply device arrays
        self.apply_devices();

        // Validate
        self.validate()?;

        // Create dispatch queue
        let queue = DispatchQueue::new("com.arcbox.vz.vm");

        // Create VM with queue
        let vm_ptr = unsafe {
            let cls = get_class("VZVirtualMachine").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZVirtualMachine class not found".into(),
            })?;
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(alloc, initWithConfiguration: self.inner, queue: queue.as_ptr());

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create VZVirtualMachine".into(),
                });
            }
            obj
        };

        Ok(VirtualMachine::from_raw(vm_ptr, queue))
    }

    /// Applies all device configurations to the VZ configuration.
    fn apply_devices(&mut self) {
        unsafe {
            if !self.storage_devices.is_empty() {
                let array = nsarray(&self.storage_devices);
                msg_send_void!(self.inner, setStorageDevices: array);
            }

            if !self.network_devices.is_empty() {
                let array = nsarray(&self.network_devices);
                msg_send_void!(self.inner, setNetworkDevices: array);
            }

            if !self.serial_ports.is_empty() {
                let array = nsarray(&self.serial_ports);
                msg_send_void!(self.inner, setSerialPorts: array);
            }

            if !self.socket_devices.is_empty() {
                let array = nsarray(&self.socket_devices);
                msg_send_void!(self.inner, setSocketDevices: array);
            }

            if !self.entropy_devices.is_empty() {
                let array = nsarray(&self.entropy_devices);
                msg_send_void!(self.inner, setEntropyDevices: array);
            }

            if !self.directory_sharing_devices.is_empty() {
                let array = nsarray(&self.directory_sharing_devices);
                msg_send_void!(self.inner, setDirectorySharingDevices: array);
            }
        }
    }
}

impl Drop for VirtualMachineConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}
