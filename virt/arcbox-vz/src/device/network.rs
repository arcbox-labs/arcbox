//! Network device configuration.

use crate::error::{VZError, VZResult};
use crate::ffi::{file_handle_for_fd, get_class, nsstring, release};
use crate::{msg_send, msg_send_void, msg_send_void_u64};
use objc2::runtime::AnyObject;
use std::os::unix::io::RawFd;

/// MTU configured on VZ network devices.
///
/// 4000 is chosen based on macOS XNU internals: the kernel has a 4096-byte
/// internal threshold above which performance degrades for loopback/utun paths.
/// Surge uses 4000, Shadowrocket/Quantumult X use 4064 (4096 - 32 for headers).
/// We round to 4000 to stay safely under the threshold.
///
/// This reduces frame count by ~2.7x vs the default 1500, directly reducing
/// per-frame overhead through the entire datapath.
/// The enhanced MTU value set on VZ network devices when the selector is
/// available (macOS 14+). Exported so the VMM can pass it to the datapath.
pub const VZ_NETWORK_MTU: u64 = 4000;

/// Configuration for a `VirtIO` network device.
pub struct NetworkDeviceConfiguration {
    inner: *mut AnyObject,
    /// Actual MTU that was configured (4000 if setter succeeded, 1500 otherwise).
    mtu: usize,
}

// SAFETY: Inner ObjC pointer is only used via msg_send! which dispatches to the ObjC runtime.
unsafe impl Send for NetworkDeviceConfiguration {}

impl NetworkDeviceConfiguration {
    /// Creates a network device with NAT attachment.
    ///
    /// NAT allows the guest to access external networks through the host.
    pub fn nat() -> VZResult<Self> {
        let attachment = create_nat_attachment()?;
        Self::with_attachment(attachment, None)
    }

    /// Creates a network device with NAT attachment and an explicit MAC address.
    pub fn nat_with_mac(mac_address: &str) -> VZResult<Self> {
        let attachment = create_nat_attachment()?;
        Self::with_attachment(attachment, Some(mac_address))
    }

    /// Creates a network device with file handle attachment.
    ///
    /// This gives the host direct access to raw L2 Ethernet frames from the
    /// guest via a connected datagram socket. The caller is responsible for
    /// all network processing (ARP, DHCP, DNS, NAT) on the host side.
    pub fn file_handle(fd: RawFd) -> VZResult<Self> {
        let net_handle = file_handle_for_fd(fd);

        if net_handle.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create NSFileHandle for network fd".into(),
            });
        }

        let attachment = create_file_handle_attachment(net_handle)?;
        Self::with_attachment(attachment, None)
    }

    /// Creates a network device with file handle attachment and an explicit MAC
    /// address.
    ///
    /// Use this when the VZ-side MAC must match an external interface (e.g.
    /// vmnet) so that bridge FDB lookups resolve correctly.
    pub fn file_handle_with_mac(fd: RawFd, mac_address: &str) -> VZResult<Self> {
        let net_handle = file_handle_for_fd(fd);

        if net_handle.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create NSFileHandle for network fd".into(),
            });
        }

        let attachment = create_file_handle_attachment(net_handle)?;
        Self::with_attachment(attachment, Some(mac_address))
    }

    /// Creates a network device with the given attachment.
    fn with_attachment(attachment: *mut AnyObject, mac_address: Option<&str>) -> VZResult<Self> {
        // SAFETY: ObjC new on valid VZVirtioNetworkDeviceConfiguration class. Result is checked non-null.
        unsafe {
            let cls = get_class("VZVirtioNetworkDeviceConfiguration").ok_or_else(|| {
                VZError::Internal {
                    code: -1,
                    message: "VZVirtioNetworkDeviceConfiguration class not found".into(),
                }
            })?;
            let obj = msg_send!(cls, new);

            if obj.is_null() {
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create network device".into(),
                });
            }

            msg_send_void!(obj, setAttachment: attachment);

            // Set MTU to reduce frame count through the datapath (~2.7x fewer
            // frames vs default 1500). Available since macOS 14 (Sonoma).
            // On older macOS, the selector doesn't exist — we must check
            // respondsToSelector: to avoid an unrecognized-selector crash.
            // Check if the VZ config class supports the MTU setter (macOS 14+).
            // msg_send_bool! doesn't support Sel arguments, so we dispatch manually.
            let mtu_sel = objc2::sel!(setMaximumTransmissionUnit:);
            let responds: bool = {
                let check_sel = objc2::sel!(respondsToSelector:);
                let func: unsafe extern "C" fn(
                    *const objc2::runtime::AnyObject,
                    objc2::runtime::Sel,
                    objc2::runtime::Sel,
                ) -> objc2::runtime::Bool = std::mem::transmute(
                    crate::ffi::runtime::objc_msgSend as *const std::ffi::c_void,
                );
                func(
                    obj as *const _ as *const objc2::runtime::AnyObject,
                    check_sel,
                    mtu_sel,
                )
                .as_bool()
            };
            let mtu = if responds {
                msg_send_void_u64!(obj, setMaximumTransmissionUnit: VZ_NETWORK_MTU);
                tracing::info!("VZ network MTU set to {VZ_NETWORK_MTU}");
                VZ_NETWORK_MTU as usize
            } else {
                tracing::info!(
                    "VZ network MTU setter unavailable (macOS < 14), using default 1500"
                );
                1500
            };

            let mac = match mac_address {
                Some(mac_address) => create_mac_address(mac_address)?,
                None => create_random_mac()?,
            };
            if !mac.is_null() {
                msg_send_void!(obj, setMACAddress: mac);
            }

            Ok(Self { inner: obj, mtu })
        }
    }

    /// Returns the actual MTU that was configured (4000 or 1500).
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Consumes the configuration and returns the raw pointer.
    #[must_use]
    pub fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for NetworkDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            crate::ffi::release(self.inner);
        }
    }
}

fn create_file_handle_attachment(file_handle: *mut AnyObject) -> VZResult<*mut AnyObject> {
    // SAFETY: ObjC alloc/init on valid VZFileHandleNetworkDeviceAttachment. ObjC exceptions are caught to prevent abort.
    unsafe {
        let cls =
            get_class("VZFileHandleNetworkDeviceAttachment").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZFileHandleNetworkDeviceAttachment class not found".into(),
            })?;

        let obj = msg_send!(cls, alloc);

        // Wrap the init call to catch ObjC exceptions (which would
        // otherwise abort the process as "foreign exceptions").
        let obj_safe = std::panic::AssertUnwindSafe(obj);
        let fh_safe = std::panic::AssertUnwindSafe(file_handle);
        let result = objc2::exception::catch(move || {
            let obj = *obj_safe;
            let fh = *fh_safe;
            msg_send!(obj, initWithFileHandle: fh)
        });

        let attachment = match result {
            Ok(ptr) => ptr,
            Err(exception) => {
                // Extract NSException description for diagnostics.
                let desc = match exception {
                    Some(exc) => {
                        let raw = &*exc as *const _ as *const AnyObject as *mut AnyObject;
                        crate::ffi::nsstring_to_string(msg_send!(raw, description))
                    }
                    None => "unknown ObjC exception (nil)".into(),
                };
                tracing::error!("VZFileHandleNetworkDeviceAttachment init threw: {}", desc);
                return Err(VZError::Internal {
                    code: -2,
                    message: format!(
                        "VZFileHandleNetworkDeviceAttachment init threw ObjC exception: {desc}"
                    ),
                });
            }
        };

        if attachment.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create file handle network attachment".into(),
            });
        }

        Ok(attachment)
    }
}

fn create_nat_attachment() -> VZResult<*mut AnyObject> {
    // SAFETY: ObjC new on valid VZNATNetworkDeviceAttachment class. Result is checked non-null.
    unsafe {
        let cls = get_class("VZNATNetworkDeviceAttachment").ok_or_else(|| VZError::Internal {
            code: -1,
            message: "VZNATNetworkDeviceAttachment class not found".into(),
        })?;
        let obj = msg_send!(cls, new);

        if obj.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create NAT attachment".into(),
            });
        }

        Ok(obj)
    }
}

fn create_random_mac() -> VZResult<*mut AnyObject> {
    // SAFETY: Sending randomLocallyAdministeredAddress to valid VZMACAddress class.
    unsafe {
        let cls = get_class("VZMACAddress").ok_or_else(|| VZError::Internal {
            code: -1,
            message: "VZMACAddress class not found".into(),
        })?;
        let obj = msg_send!(cls, randomLocallyAdministeredAddress);

        if obj.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to create random MAC".into(),
            });
        }

        Ok(obj)
    }
}

fn create_mac_address(mac_address: &str) -> VZResult<*mut AnyObject> {
    // SAFETY: ObjC alloc/init on a valid VZMACAddress class with a valid NSString argument.
    unsafe {
        let cls = get_class("VZMACAddress").ok_or_else(|| VZError::Internal {
            code: -1,
            message: "VZMACAddress class not found".into(),
        })?;
        let obj = msg_send!(cls, alloc);
        if obj.is_null() {
            return Err(VZError::Internal {
                code: -1,
                message: "Failed to allocate MAC address".into(),
            });
        }

        let mac_ns = nsstring(mac_address);
        let initialized = msg_send!(obj, initWithString: mac_ns);
        release(mac_ns);

        if initialized.is_null() {
            return Err(VZError::InvalidConfiguration(format!(
                "Invalid MAC address: {mac_address}"
            )));
        }

        Ok(initialized)
    }
}
