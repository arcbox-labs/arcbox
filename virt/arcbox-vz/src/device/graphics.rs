//! macOS graphics device configuration.

use crate::error::{VZError, VZResult};
use crate::ffi::{get_class, nsarray, release};
use crate::{msg_send, msg_send_void};
use objc2::runtime::AnyObject;
use std::ffi::c_void;

/// Configuration for a macOS graphics device with a single display.
///
/// A macOS guest requires at least one graphics device to start. This creates a
/// `VZMacGraphicsDeviceConfiguration` holding one `VZMacGraphicsDisplayConfiguration`.
pub struct MacGraphicsDeviceConfiguration {
    inner: *mut AnyObject,
}

// SAFETY: Inner ObjC pointer is only used via msg_send! which dispatches to the ObjC runtime.
unsafe impl Send for MacGraphicsDeviceConfiguration {}

impl MacGraphicsDeviceConfiguration {
    /// Creates a graphics device with a single display of the given pixel
    /// dimensions and pixel density.
    ///
    /// # Errors
    ///
    /// Returns an error if the graphics/display class is unavailable or cannot be
    /// created.
    pub fn new(
        width_in_pixels: isize,
        height_in_pixels: isize,
        pixels_per_inch: isize,
    ) -> VZResult<Self> {
        // SAFETY: alloc/init on VZMacGraphicsDisplayConfiguration (3 NSInteger args)
        // and VZMacGraphicsDeviceConfiguration; setDisplays: takes an NSArray. The
        // device's `displays` is a copy property, so the temporary display is
        // released after it is set.
        unsafe {
            let display_cls = get_class("VZMacGraphicsDisplayConfiguration").ok_or_else(|| {
                VZError::Internal {
                    code: -1,
                    message: "VZMacGraphicsDisplayConfiguration class not found".into(),
                }
            })?;
            let display_alloc = msg_send!(display_cls, alloc);
            let init_sel = objc2::sel!(initWithWidthInPixels:heightInPixels:pixelsPerInch:);
            let init_fn: unsafe extern "C" fn(
                *mut AnyObject,
                objc2::runtime::Sel,
                isize,
                isize,
                isize,
            ) -> *mut AnyObject =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            let display = init_fn(
                display_alloc,
                init_sel,
                width_in_pixels,
                height_in_pixels,
                pixels_per_inch,
            );
            if display.is_null() {
                return Err(VZError::InvalidConfiguration(
                    "failed to create macOS graphics display".into(),
                ));
            }

            let device_cls = match get_class("VZMacGraphicsDeviceConfiguration") {
                Some(cls) => cls,
                None => {
                    release(display);
                    return Err(VZError::Internal {
                        code: -1,
                        message: "VZMacGraphicsDeviceConfiguration class not found".into(),
                    });
                }
            };
            let device = msg_send!(msg_send!(device_cls, alloc), init);
            if device.is_null() {
                release(display);
                return Err(VZError::Internal {
                    code: -1,
                    message: "Failed to create macOS graphics device".into(),
                });
            }

            let displays = nsarray(&[display]);
            msg_send_void!(device, setDisplays: displays);
            release(display);

            Ok(Self { inner: device })
        }
    }

    /// Consumes the configuration and returns the raw pointer.
    #[must_use]
    pub fn into_ptr(self) -> *mut AnyObject {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for MacGraphicsDeviceConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}
