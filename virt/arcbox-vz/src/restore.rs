//! macOS restore images.
//!
//! A restore image describes a macOS installation source — a local IPSW or the
//! latest version Apple publishes. Its most-featureful supported configuration
//! yields the hardware model and the minimum CPU/memory a guest needs, which are
//! the inputs to a [`MacPlatform`](crate::MacPlatform) and a
//! [`MacAuxiliaryStorage`](crate::MacAuxiliaryStorage).

use std::ffi::c_void;
use std::path::Path;
use std::time::Duration;

use objc2::runtime::{AnyClass, AnyObject};
use tokio::sync::oneshot;
use tokio::time::sleep;

use crate::configuration::MacHardwareModel;
use crate::error::{VZError, VZResult};
use crate::ffi::{
    _Block_release, ObjectResult, StateResult, create_object_completion_block,
    create_state_completion_block, get_class, nsstring_to_string, nsurl_file_path, release,
};
use crate::vm::VirtualMachine;
use crate::{msg_send, msg_send_u64, msg_send_void};

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
        // SAFETY: +fetchLatestSupportedWithCompletionHandler: takes one block argument
        // and returns void; `block` is a heap-copied block released after the await.
        unsafe {
            let sel = objc2::sel!(fetchLatestSupportedWithCompletionHandler:);
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
        // SAFETY: +loadFileURL:completionHandler: takes an NSURL and a block and returns
        // void; `block` is a heap-copied block released after the await.
        unsafe {
            let url = nsurl_file_path(&path_str);
            let sel = objc2::sel!(loadFileURL:completionHandler:);
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

    /// Returns the restore image URL.
    ///
    /// For an image fetched via [`latest_supported`](Self::latest_supported) this is
    /// the remote IPSW download URL; for one loaded via
    /// [`load_from_url`](Self::load_from_url) it is the local file URL.
    #[must_use]
    pub fn url(&self) -> Option<String> {
        // SAFETY: URL is a readonly property returning an NSURL owned by the image;
        // absoluteString returns an NSString that nsstring_to_string only reads.
        unsafe {
            let url = msg_send!(self.inner, URL);
            if url.is_null() {
                return None;
            }
            let s = msg_send!(url, absoluteString);
            let out = nsstring_to_string(s);
            if out.is_empty() { None } else { Some(out) }
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

/// Installs macOS from a restore image onto a virtual machine's disk.
///
/// Wraps `VZMacOSInstaller`. Create it with the VM built for installation and a
/// local restore image (IPSW), then drive [`install`](Self::install) — a long
/// operation (tens of minutes) that reports progress as it runs.
pub struct MacOSInstaller {
    inner: *mut AnyObject,
    progress: *mut AnyObject,
}

// SAFETY: Inner ObjC pointers are only used via msg_send! which dispatches to the ObjC runtime.
unsafe impl Send for MacOSInstaller {}

impl MacOSInstaller {
    /// Creates an installer for `virtual_machine` from a local restore image.
    ///
    /// `restore_image_path` must be a local file (an IPSW); a restore image fetched
    /// via [`MacOSRestoreImage::latest_supported`] must be downloaded first.
    ///
    /// # Errors
    ///
    /// Returns an error if `VZMacOSInstaller` is unavailable or cannot be created.
    pub fn new(
        virtual_machine: &VirtualMachine,
        restore_image_path: impl AsRef<Path>,
    ) -> VZResult<Self> {
        let path_str = restore_image_path.as_ref().to_string_lossy();
        // SAFETY: alloc/initWithVirtualMachine:restoreImageURL: on VZMacOSInstaller with a
        // valid VM pointer and an NSURL from a local path. Result checked non-null.
        unsafe {
            let cls = get_class("VZMacOSInstaller").ok_or_else(|| VZError::Internal {
                code: -1,
                message: "VZMacOSInstaller class not found".into(),
            })?;
            let url = nsurl_file_path(&path_str);
            let alloc = msg_send!(cls, alloc);
            let obj = msg_send!(
                alloc,
                initWithVirtualMachine: virtual_machine.as_ptr(),
                restoreImageURL: url
            );
            if obj.is_null() {
                return Err(VZError::InvalidConfiguration(
                    "failed to create VZMacOSInstaller".into(),
                ));
            }
            let progress = msg_send!(obj, progress);
            Ok(Self {
                inner: obj,
                progress,
            })
        }
    }

    /// Returns installation progress as a fraction in `0.0..=1.0`.
    #[must_use]
    pub fn fraction_completed(&self) -> f64 {
        if self.progress.is_null() {
            return 0.0;
        }
        // SAFETY: fractionCompleted returns a double from a valid NSProgress.
        unsafe {
            let sel = objc2::sel!(fractionCompleted);
            let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel) -> f64 =
                std::mem::transmute(crate::ffi::runtime::objc_msgSend as *const c_void);
            func(self.progress as *const AnyObject, sel)
        }
    }

    /// Installs macOS, invoking `on_progress` with the current fraction as it runs.
    ///
    /// `virtual_machine` must be the VM passed to [`new`](Self::new); the install is
    /// dispatched on that VM's queue.
    ///
    /// # Errors
    ///
    /// Returns an error if installation fails.
    pub async fn install(
        &self,
        virtual_machine: &VirtualMachine,
        mut on_progress: impl FnMut(f64),
    ) -> VZResult<()> {
        let (tx, mut rx) = oneshot::channel::<StateResult>();
        let block = create_state_completion_block(tx);
        let installer = self.inner;
        // Kick off the install on the VM's queue: the call returns immediately and the
        // completion handler fires when installation finishes.
        // SAFETY: installWithCompletionHandler: takes a heap-copied (NSError *) block.
        virtual_machine.dispatch_sync(|| unsafe {
            msg_send_void!(installer, installWithCompletionHandler: block);
        });

        let result = loop {
            match rx.try_recv() {
                Ok(result) => break result,
                Err(oneshot::error::TryRecvError::Empty) => {
                    on_progress(self.fraction_completed());
                    sleep(Duration::from_secs(2)).await;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    break Err("install completion handler dropped".to_string());
                }
            }
        };
        // SAFETY: `block` was returned by create_state_completion_block and not released elsewhere.
        unsafe { _Block_release(block) };
        result.map_err(|message| VZError::Internal { code: -1, message })
    }
}

impl Drop for MacOSInstaller {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            release(self.inner);
        }
    }
}
