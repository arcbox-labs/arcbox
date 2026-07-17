//! Network device configuration.

use crate::error::{VZError, VZResult};
use crate::shim_ffi;
use std::ffi::{CString, c_void};
use std::os::unix::io::RawFd;
use std::ptr;

/// MTU a VZ network device uses when `setMaximumTransmissionUnit:` is not
/// called — Apple's default, and since ABX-423 also ArcBox's default.
pub const VZ_DEFAULT_MTU: usize = 1500;

/// Enhanced MTU applied only under `ARCBOX_DIAG_NET_MTU_4000`.
///
/// 4000 was chosen from macOS XNU internals (the kernel has a 4096-byte
/// threshold above which loopback/utun performance degrades; Surge uses 4000,
/// Shadowrocket/Quantumult X use 4064) and reduces frame count ~2.7x vs 1500.
///
/// It is no longer the default: `VZFileHandleNetworkDeviceAttachment` enters
/// an intermittent, self-healing whole-device stall under sustained bulk
/// transfer once the link MTU is raised above 1500 (ABX-423). The stall was
/// bisected to the VZ device layer, so the only host-side mitigation is to
/// stay at 1500. Keep this constant and the diagnostic knob for reproducing
/// the stall (Apple Feedback evidence) and for throughput A/B runs.
pub const VZ_ENHANCED_MTU: u64 = 4000;

/// The MTU a VZ network device is configured with: [`VZ_DEFAULT_MTU`] unless
/// `ARCBOX_DIAG_NET_MTU_4000` opts into [`VZ_ENHANCED_MTU`].
///
/// This is the policy half of the decision — the VMM sizes its datapath from
/// it before the device exists. The mechanism half (the
/// `setMaximumTransmissionUnit:` call in the shim, applied only to
/// file-handle attachments and only above the default) reads the value passed
/// through [`NetworkDeviceConfiguration`]'s constructors.
#[must_use]
pub fn desired_network_mtu() -> usize {
    if std::env::var_os("ARCBOX_DIAG_NET_MTU_4000").is_some() {
        VZ_ENHANCED_MTU as usize
    } else {
        VZ_DEFAULT_MTU
    }
}

/// The MTU override forwarded to the shim: 0 (leave Apple's default) unless
/// the diagnostic knob raises it.
fn mtu_override() -> u64 {
    let desired = desired_network_mtu();
    if desired > VZ_DEFAULT_MTU {
        tracing::warn!(
            "VZ network MTU raised to {desired} (ARCBOX_DIAG_NET_MTU_4000; \
             expect ABX-423 device stalls under sustained bulk transfer)"
        );
        desired as u64
    } else {
        tracing::info!("VZ network MTU at default {VZ_DEFAULT_MTU} (ABX-423 mitigation)");
        0
    }
}

/// Configuration for a `VirtIO` network device.
pub struct NetworkDeviceConfiguration {
    inner: *mut c_void,
}

// SAFETY: The inner pointer is an ObjC configuration object created by the
// shim; it is not mutated concurrently.
unsafe impl Send for NetworkDeviceConfiguration {}

impl NetworkDeviceConfiguration {
    /// Creates a network device with NAT attachment.
    ///
    /// NAT allows the guest to access external networks through the host.
    pub fn nat() -> VZResult<Self> {
        Self::nat_inner(None)
    }

    /// Creates a network device with NAT attachment and an explicit MAC address.
    pub fn nat_with_mac(mac_address: &str) -> VZResult<Self> {
        Self::nat_inner(Some(mac_address))
    }

    /// Creates a network device with file handle attachment.
    ///
    /// This gives the host direct access to raw L2 Ethernet frames from the
    /// guest via a connected datagram socket. The caller is responsible for
    /// all network processing (ARP, DHCP, DNS, NAT) on the host side.
    pub fn file_handle(fd: RawFd) -> VZResult<Self> {
        Self::file_handle_inner(fd, None)
    }

    /// Creates a network device with file handle attachment and an explicit MAC
    /// address.
    ///
    /// Use this when the VZ-side MAC must match an external interface (e.g.
    /// vmnet) so that bridge FDB lookups resolve correctly.
    pub fn file_handle_with_mac(fd: RawFd, mac_address: &str) -> VZResult<Self> {
        Self::file_handle_inner(fd, Some(mac_address))
    }

    fn nat_inner(mac_address: Option<&str>) -> VZResult<Self> {
        let c_mac = mac_cstring(mac_address)?;
        let mac_ptr = c_mac.as_ref().map_or(ptr::null(), |m| m.as_ptr());
        // SAFETY: mac_ptr is null or a valid NUL-terminated string; on
        // failure the shim writes a strdup'd message.
        unsafe {
            let mut error: *mut std::ffi::c_char = ptr::null_mut();
            let obj = shim_ffi::abx_network_nat_new(mac_ptr, mtu_override(), &raw mut error);
            Self::from_shim(obj, error)
        }
    }

    fn file_handle_inner(fd: RawFd, mac_address: Option<&str>) -> VZResult<Self> {
        // Pre-validate the fd so a bad descriptor surfaces as an error here
        // instead of undefined attachment behavior later.
        // SAFETY: fcntl(F_GETFD) is safe on any integer fd value.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(VZError::InvalidConfiguration(format!(
                "invalid network fd {fd}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let c_mac = mac_cstring(mac_address)?;
        let mac_ptr = c_mac.as_ref().map_or(ptr::null(), |m| m.as_ptr());
        // SAFETY: fd is validated above; mac_ptr is null or valid; on failure
        // the shim writes a strdup'd message.
        unsafe {
            let mut error: *mut std::ffi::c_char = ptr::null_mut();
            let obj =
                shim_ffi::abx_network_file_handle_new(fd, mac_ptr, mtu_override(), &raw mut error);
            Self::from_shim(obj, error)
        }
    }

    /// Wraps a shim result, converting a null handle + error into `VZError`.
    ///
    /// # Safety
    ///
    /// `error` must be null or a shim-allocated string (consumed here).
    unsafe fn from_shim(
        obj: *mut std::ffi::c_void,
        error: *mut std::ffi::c_char,
    ) -> VZResult<Self> {
        if obj.is_null() {
            // SAFETY: per contract, `error` is a shim-allocated string.
            return Err(VZError::InvalidConfiguration(unsafe {
                shim_ffi::take_error_string(error)
            }));
        }
        Ok(Self { inner: obj })
    }

    /// Consumes the configuration and returns the raw pointer.
    #[must_use]
    pub(crate) fn into_ptr(self) -> *mut c_void {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

/// Converts an optional MAC string, rejecting interior NUL bytes.
fn mac_cstring(mac: Option<&str>) -> VZResult<Option<CString>> {
    mac.map(|m| {
        CString::new(m).map_err(|_| VZError::InvalidConfiguration(format!("MAC contains NUL: {m}")))
    })
    .transpose()
}

impl Drop for NetworkDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle returned by the shim.
            unsafe { shim_ffi::abx_object_release(self.inner.cast()) };
        }
    }
}
