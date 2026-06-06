//! macOS restore images.
//!
//! A restore image describes a macOS installation source — a local IPSW or the
//! latest version Apple publishes. Its most-featureful supported configuration
//! yields the hardware model and the minimum CPU/memory a guest needs, which are
//! the inputs to a [`MacPlatform`](crate::MacPlatform) and a
//! [`MacAuxiliaryStorage`](crate::MacAuxiliaryStorage).

use std::ffi::c_void;
use std::path::Path;

use objc2::runtime::{AnyClass, AnyObject};
use tokio::sync::oneshot;

use crate::configuration::MacHardwareModel;
use crate::error::{VZError, VZResult};
use crate::ffi::{
    _Block_release, ObjectResult, create_object_completion_block, get_class, nsurl_file_path,
    release,
};
use crate::{msg_send, msg_send_u64};

/// The most-featureful configuration a restore image supports.
pub struct MacOSConfigurationRequirements {
    /// The hardware model the guest must use.
    pub hardware_model: MacHardwareModel,
    /// Minimum number of CPUs the guest requires.
    pub minimum_cpu_count: u64,
    /// Minimum guest memory in bytes.
    pub minimum_memory_size: u64,
}

/// A macOS restore image — a local IPSW or the latest version Apple publishes.
pub struct MacOSRestoreImage {
    inner: *mut AnyObject,
}

// SAFETY: Inner ObjC pointer is only used via msg_send! which dispatches to the ObjC runtime.
unsafe impl Send for MacOSRestoreImage {}

impl MacOSRestoreImage {
    /// Fetches metadata for the latest supported restore image.
    ///
    /// This contacts Apple's servers for the metadata only; it does not download
    /// the multi-gigabyte IPSW.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacOSRestoreImage` is unavailable or the fetch fails.
    pub async fn latest_supported() -> VZResult<Self> {
        let cls = get_class("VZMacOSRestoreImage").ok_or_else(|| VZError::Internal {
            code: -1,
            message: "VZMacOSRestoreImage class not found".into(),
        })?;
        let (tx, rx) = oneshot::channel::<ObjectResult>();
        let block = create_object_completion_block(tx);
        // SAFETY: +latestSupportedWithCompletionHandler: takes one block argument and
        // returns void; `block` is a heap-copied block released after the await.
        unsafe {
            let sel = objc2::sel!(latestSupportedWithCompletionHandler:);
            let func: unsafe extern "C" fn(*const AnyClass, objc2::runtime::Sel, *const c_void) =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            func(cls, sel, block);
        }
        let received = rx.await;
        // SAFETY: `block` was returned by create_object_completion_block and not released elsewhere.
        unsafe { _Block_release(block) };
        Self::from_received(received)
    }

    /// Loads a restore image from a local file (an IPSW).
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacOSRestoreImage` is unavailable or the file cannot
    /// be loaded as a restore image.
    pub async fn load_from_url(path: impl AsRef<Path>) -> VZResult<Self> {
        let path_str = path.as_ref().to_string_lossy();
        let cls = get_class("VZMacOSRestoreImage").ok_or_else(|| VZError::Internal {
            code: -1,
            message: "VZMacOSRestoreImage class not found".into(),
        })?;
        let (tx, rx) = oneshot::channel::<ObjectResult>();
        let block = create_object_completion_block(tx);
        // SAFETY: +loadFromURL:completionHandler: takes an NSURL and a block and returns
        // void; `block` is a heap-copied block released after the await.
        unsafe {
            let url = nsurl_file_path(&path_str);
            let sel = objc2::sel!(loadFromURL:completionHandler:);
            let func: unsafe extern "C" fn(
                *const AnyClass,
                objc2::runtime::Sel,
                *const AnyObject,
                *const c_void,
            ) = std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            func(cls, sel, url as *const AnyObject, block);
        }
        let received = rx.await;
        // SAFETY: `block` was returned by create_object_completion_block and not released elsewhere.
        unsafe { _Block_release(block) };
        Self::from_received(received)
    }

    /// Wraps the result delivered by the completion block into a restore image.
    fn from_received(received: Result<ObjectResult, oneshot::error::RecvError>) -> VZResult<Self> {
        let bits = received
            .map_err(|_| VZError::Internal {
                code: -1,
                message: "restore image completion handler dropped".into(),
            })?
            .map_err(|message| VZError::Internal { code: -1, message })?;
        Ok(Self {
            inner: bits as *mut AnyObject,
        })
    }

    /// Returns the most-featureful configuration this restore image supports.
    ///
    /// # Errors
    ///
    /// Returns an error if the restore image exposes no supported configuration.
    pub fn requirements(&self) -> VZResult<MacOSConfigurationRequirements> {
        // SAFETY: mostFeaturefulSupportedConfiguration and its properties are read from
        // a valid VZMacOSRestoreImage; the returned objects are owned by the framework.
        unsafe {
            let reqs = msg_send!(self.inner, mostFeaturefulSupportedConfiguration);
            if reqs.is_null() {
                return Err(VZError::InvalidConfiguration(
                    "restore image has no supported configuration".into(),
                ));
            }
            let hw_ptr = msg_send!(reqs, hardwareModel);
            let hardware_model = MacHardwareModel::from_retained_ptr(hw_ptr).ok_or_else(|| {
                VZError::InvalidConfiguration("restore image has no hardware model".into())
            })?;
            let minimum_cpu_count = msg_send_u64!(reqs, minimumSupportedCPUCount);
            let minimum_memory_size = msg_send_u64!(reqs, minimumSupportedMemorySize);
            Ok(MacOSConfigurationRequirements {
                hardware_model,
                minimum_cpu_count,
                minimum_memory_size,
            })
        }
    }
}

impl Drop for MacOSRestoreImage {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}
