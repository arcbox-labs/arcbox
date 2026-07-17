//! macOS restore images.
//!
//! A restore image describes a macOS installation source — a local IPSW or the
//! latest version Apple publishes. Its most-featureful supported configuration
//! yields the hardware model and the minimum CPU/memory a guest needs, which are
//! the inputs to a [`MacPlatform`](crate::MacPlatform) and a
//! [`MacAuxiliaryStorage`](crate::MacAuxiliaryStorage).

use std::ffi::{CString, c_char, c_void};
use std::path::Path;
use std::ptr;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::sleep;

use crate::configuration::MacHardwareModel;
use crate::error::{VZError, VZResult};
use crate::shim_ffi;
use crate::vm::{VirtualMachine, state_trampoline};

/// The most-featureful configuration a restore image supports.
pub struct MacOSConfigurationRequirements {
    /// The hardware model the guest must use.
    pub hardware_model: MacHardwareModel,
    /// Minimum number of CPUs the guest requires.
    pub minimum_cpu_count: u64,
    /// Minimum guest memory in bytes.
    pub minimum_memory_size: u64,
}

/// Shim object-completion trampoline: consumes the boxed sender exactly once.
///
/// If the receiver is gone (cancelled load), the +1 handle is released here
/// so the object doesn't leak.
unsafe extern "C" fn object_trampoline(ctx: *mut c_void, handle: *mut c_void, err: *mut c_char) {
    // SAFETY: ctx is the Box<Sender> leaked by the caller; the shim
    // guarantees exactly-once invocation. err is null or a shim string.
    unsafe {
        let sender = Box::from_raw(ctx as *mut oneshot::Sender<Result<usize, String>>);
        let result = if err.is_null() {
            Ok(handle as usize)
        } else {
            Err(shim_ffi::take_error_string(err))
        };
        if let Err(Ok(bits)) = sender.send(result) {
            // Receiver dropped: release the orphaned +1 handle.
            shim_ffi::abx_object_release(bits as *mut c_void);
        }
    }
}

/// A macOS restore image — a local IPSW or the latest version Apple publishes.
pub struct MacOSRestoreImage {
    inner: *mut c_void,
}

// SAFETY: The handle refers to an immutable VZMacOSRestoreImage; all access
// goes through the shim.
unsafe impl Send for MacOSRestoreImage {}

impl MacOSRestoreImage {
    /// Fetches metadata for the latest supported restore image.
    ///
    /// This contacts Apple's servers for the metadata only; it does not download
    /// the multi-gigabyte IPSW.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails.
    pub async fn latest_supported() -> VZResult<Self> {
        let (tx, rx) = oneshot::channel::<Result<usize, String>>();
        let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;
        // SAFETY: ctx ownership transfers to the exactly-once trampoline.
        unsafe { shim_ffi::abx_restore_image_fetch_latest(ctx, object_trampoline) };
        Self::from_received(rx.await)
    }

    /// Loads a restore image from a local file (an IPSW).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be loaded as a restore image.
    pub async fn load_from_url(path: impl AsRef<Path>) -> VZResult<Self> {
        let c_path = CString::new(path.as_ref().to_string_lossy().as_bytes()).map_err(|_| {
            VZError::InvalidConfiguration(format!("path contains NUL: {}", path.as_ref().display()))
        })?;
        let (tx, rx) = oneshot::channel::<Result<usize, String>>();
        let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;
        // SAFETY: c_path is valid for the duration of the call; ctx ownership
        // transfers to the exactly-once trampoline.
        unsafe { shim_ffi::abx_restore_image_load(c_path.as_ptr(), ctx, object_trampoline) };
        Self::from_received(rx.await)
    }

    /// Wraps the +1 handle delivered by the completion trampoline.
    fn from_received(
        received: Result<Result<usize, String>, oneshot::error::RecvError>,
    ) -> VZResult<Self> {
        let bits = received
            .map_err(|_| VZError::Internal {
                code: -1,
                message: "restore image completion handler dropped".into(),
            })?
            .map_err(|message| VZError::Internal { code: -1, message })?;
        Ok(Self {
            inner: bits as *mut c_void,
        })
    }

    /// Returns the most-featureful configuration this restore image supports.
    ///
    /// # Errors
    ///
    /// Returns an error if the restore image exposes no supported configuration.
    pub fn requirements(&self) -> VZResult<MacOSConfigurationRequirements> {
        // SAFETY: inner is a valid image handle; on success the shim writes a
        // +1 hardware-model handle owned by the returned wrapper.
        unsafe {
            let mut hw: *mut c_void = ptr::null_mut();
            let mut min_cpu: u64 = 0;
            let mut min_memory: u64 = 0;
            let mut error: *mut c_char = ptr::null_mut();
            if !shim_ffi::abx_restore_image_requirements(
                self.inner,
                &mut hw,
                &mut min_cpu,
                &mut min_memory,
                &mut error,
            ) {
                return Err(VZError::InvalidConfiguration(shim_ffi::take_error_string(
                    error,
                )));
            }
            let hardware_model =
                MacHardwareModel::from_owned_handle(hw).ok_or_else(|| VZError::Internal {
                    code: -1,
                    message: "restore image requirements returned no hardware model".into(),
                })?;
            Ok(MacOSConfigurationRequirements {
                hardware_model,
                minimum_cpu_count: min_cpu,
                minimum_memory_size: min_memory,
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
        // SAFETY: inner is a valid image handle; the returned string is
        // shim-allocated and consumed by take_string.
        unsafe {
            let s = shim_ffi::abx_restore_image_url(self.inner);
            shim_ffi::take_string(s).filter(|url| !url.is_empty())
        }
    }
}

impl Drop for MacOSRestoreImage {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 handle delivered by the trampoline.
            unsafe { shim_ffi::abx_object_release(self.inner) };
        }
    }
}

/// Installs macOS from a restore image onto a virtual machine's disk.
///
/// Wraps `VZMacOSInstaller`. Create it with the VM built for installation and a
/// local restore image (IPSW), then drive [`install`](Self::install) — a long
/// operation (tens of minutes) that reports progress as it runs.
pub struct MacOSInstaller {
    inner: *mut c_void,
}

// SAFETY: The box handle is only used through the shim, which serializes the
// queue-affine installer operations on the VM's queue.
unsafe impl Send for MacOSInstaller {}

impl MacOSInstaller {
    /// Creates an installer for `virtual_machine` from a local restore image.
    ///
    /// `restore_image_path` must be a local file (an IPSW); a restore image fetched
    /// via [`MacOSRestoreImage::latest_supported`] must be downloaded first.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not representable.
    pub fn new(
        virtual_machine: &VirtualMachine,
        restore_image_path: impl AsRef<Path>,
    ) -> VZResult<Self> {
        let c_path = CString::new(restore_image_path.as_ref().to_string_lossy().as_bytes())
            .map_err(|_| {
                VZError::InvalidConfiguration(format!(
                    "path contains NUL: {}",
                    restore_image_path.as_ref().display()
                ))
            })?;
        // SAFETY: the VM box handle is valid; the shim constructs the
        // installer on the VM's queue (its initializer asserts affinity) and
        // returns a +1 installer box.
        let obj = unsafe { shim_ffi::abx_installer_new(virtual_machine.vm_box(), c_path.as_ptr()) };
        Ok(Self { inner: obj })
    }

    /// Returns installation progress as a fraction in `0.0..=1.0`.
    #[must_use]
    pub fn fraction_completed(&self) -> f64 {
        // SAFETY: inner is a valid installer box; NSProgress reads are
        // queue-free.
        unsafe { shim_ffi::abx_installer_fraction(self.inner) }
    }

    /// Installs macOS, invoking `on_progress` with the current fraction as it runs.
    ///
    /// The install runs on the queue retained inside the installer box (the
    /// VM's queue, captured at [`new`](Self::new)). `_virtual_machine` is kept
    /// for public-API stability but is no longer read — the queue no longer
    /// comes from this argument, so passing a different VM has no effect.
    ///
    /// # Errors
    ///
    /// Returns an error if installation fails.
    pub async fn install(
        &self,
        _virtual_machine: &VirtualMachine,
        mut on_progress: impl FnMut(f64),
    ) -> VZResult<()> {
        let (tx, mut rx) = oneshot::channel::<Result<(), String>>();
        let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;
        // SAFETY: inner is a valid installer box; ctx ownership transfers to
        // the exactly-once trampoline. The shim issues the install on the
        // VM's queue and the call returns after dispatching.
        unsafe { shim_ffi::abx_installer_install(self.inner, ctx, state_trampoline) };

        let result = loop {
            tokio::select! {
                // Prefer the completion signal so install() returns promptly when the
                // installer finishes, rather than after the next progress tick.
                biased;
                received = &mut rx => {
                    break received
                        .unwrap_or_else(|_| Err("install completion handler dropped".to_string()));
                }
                () = sleep(Duration::from_secs(2)) => {
                    on_progress(self.fraction_completed());
                }
            }
        };
        result.map_err(|message| VZError::Internal { code: -1, message })
    }
}

impl Drop for MacOSInstaller {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: releasing the +1 installer box handle from the shim.
            unsafe { shim_ffi::abx_object_release(self.inner) };
        }
    }
}
