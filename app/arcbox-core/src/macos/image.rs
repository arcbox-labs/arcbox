//! macOS guest base images and their copy-on-write clones.
//!
//! A base image is a directory under `data_dir/macos/images/<name>/` holding an
//! installed macOS system disk plus the auxiliary storage and identity needed to
//! boot it. [`MacImage::clone_into`] produces a per-VM instance from a base by
//! copy-on-write cloning the (large) system disk via `clonefile(2)` — instant
//! and space-shared on APFS — so every VM is a clean, disposable copy.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::validate_name;
use crate::error::{CoreError, Result};

pub(super) const META_FILE: &str = "meta.json";
pub(super) const DISK_FILE: &str = "disk.img";
pub(super) const AUX_FILE: &str = "aux.img";
pub(super) const HARDWARE_MODEL_FILE: &str = "hwmodel.bin";
pub(super) const MACHINE_ID_FILE: &str = "machine-id.bin";

/// Persisted metadata describing a macOS base image template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacImageMeta {
    /// Image name (unique within the registry).
    pub name: String,
    /// Where the image came from (manifest location or IPSW path), if known.
    pub source: Option<String>,
    /// Stream the image was pulled from (e.g. `tahoe-base`), if pulled.
    #[serde(default)]
    pub stream: Option<String>,
    /// Published version label (e.g. `2026.07.02`), if pulled.
    #[serde(default)]
    pub version: Option<String>,
    /// Guest macOS product version (e.g. `26.5`), if known.
    #[serde(default)]
    pub os_version: Option<String>,
    /// Guest macOS build number (e.g. `25F71`), if known.
    #[serde(default)]
    pub os_build: Option<String>,
    /// Preinstalled GitHub Actions runner version, if known.
    #[serde(default)]
    pub runner_version: Option<String>,
    /// Minimum CPU count required by the guest.
    pub minimum_cpu_count: u64,
    /// Minimum guest memory in MiB required by the guest.
    pub minimum_memory_mib: u64,
    /// System disk size in GB (decimal, logical size).
    pub disk_gb: u64,
    /// When the image was created locally.
    pub created_at: DateTime<Utc>,
}

/// A macOS base image template on disk.
#[derive(Debug, Clone)]
pub struct MacImage {
    /// Image metadata.
    pub meta: MacImageMeta,
    /// Directory holding the image artifacts.
    pub dir: PathBuf,
}

impl MacImage {
    /// Path to the installed system disk image.
    #[must_use]
    pub fn disk_path(&self) -> PathBuf {
        self.dir.join(DISK_FILE)
    }
    /// Path to the auxiliary (NVRAM) storage.
    #[must_use]
    pub fn aux_path(&self) -> PathBuf {
        self.dir.join(AUX_FILE)
    }
    /// Path to the hardware-model data representation.
    #[must_use]
    pub fn hardware_model_path(&self) -> PathBuf {
        self.dir.join(HARDWARE_MODEL_FILE)
    }
    /// Path to the base machine-identifier data representation.
    #[must_use]
    pub fn machine_id_path(&self) -> PathBuf {
        self.dir.join(MACHINE_ID_FILE)
    }

    /// Clones this base image into `dst_dir`, producing per-VM disks ready to boot.
    ///
    /// The (large) system disk is copy-on-write cloned via `clonefile(2)` — instant
    /// and space-shared on APFS — while the small auxiliary storage and identity are
    /// copied, so the clone boots the same installed system. Off APFS the disk falls
    /// back to a full copy (logged).
    ///
    /// The base machine identifier is copied into the instance and reused on every
    /// boot. It is the identifier the base's auxiliary storage was created with at
    /// install, so reusing it gives the clone a stable identity that pairs with the
    /// cloned NVRAM.
    ///
    /// # Errors
    /// Returns an error if any clone/copy step fails.
    pub fn clone_into(&self, dst_dir: &Path) -> Result<MacInstanceDisks> {
        std::fs::create_dir_all(dst_dir)?;

        let dst_disk = dst_dir.join(DISK_FILE);
        cow_clone(&self.disk_path(), &dst_disk)?;

        let dst_aux = dst_dir.join(AUX_FILE);
        let _ = std::fs::remove_file(&dst_aux);
        std::fs::copy(self.aux_path(), &dst_aux)?;

        let hardware_model = std::fs::read(self.hardware_model_path())?;
        let machine_id = std::fs::read(self.machine_id_path())?;

        Ok(MacInstanceDisks {
            disk: dst_disk,
            aux: dst_aux,
            hardware_model,
            machine_id,
        })
    }
}

/// Disk artifacts of a cloned per-VM instance, ready to assemble into a VM.
#[derive(Debug, Clone)]
pub struct MacInstanceDisks {
    /// Per-VM system disk (a copy-on-write clone of the base disk).
    pub disk: PathBuf,
    /// Per-VM auxiliary storage.
    pub aux: PathBuf,
    /// Hardware-model data representation (shared with the base).
    pub hardware_model: Vec<u8>,
    /// Machine-identifier data representation for this instance.
    pub machine_id: Vec<u8>,
}

/// Manages macOS base image templates and their copy-on-write clones.
pub struct MacImageManager {
    images_dir: PathBuf,
    /// Per-image-name locks serializing concurrent pulls of the same image so
    /// they cannot corrupt the shared staging directory. Bounded by the number
    /// of distinct image names ever pulled.
    pull_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl MacImageManager {
    /// Creates a manager rooted at `data_dir/macos/images`.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self {
            images_dir: data_dir.join("macos").join("images"),
            pull_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Directory holding a named image's artifacts.
    ///
    /// # Errors
    /// Returns an error if `name` is not a single safe path component (see
    /// [`validate_name`]).
    pub(super) fn image_dir(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.images_dir.join(name))
    }

    /// Directory holding downloaded IPSWs (a sibling of the images dir).
    #[must_use]
    pub fn cache_dir(&self) -> PathBuf {
        self.images_dir
            .parent()
            .map_or_else(|| self.images_dir.join("cache"), |p| p.join("cache"))
    }

    /// Returns the lock serializing pulls of image `name` (creating it on first use).
    pub(super) async fn pull_lock(&self, name: &str) -> Arc<Mutex<()>> {
        Arc::clone(
            self.pull_locks
                .lock()
                .await
                .entry(name.to_string())
                .or_default(),
        )
    }

    /// Loads a base image by name.
    ///
    /// # Errors
    /// Returns a not-found error if no such image exists, an invalid-name error
    /// if `name` is not a safe path component, or a macOS error if its metadata
    /// cannot be parsed.
    pub fn get(&self, name: &str) -> Result<MacImage> {
        let dir = self.image_dir(name)?;
        let meta_path = dir.join(META_FILE);
        if !meta_path.exists() {
            return Err(CoreError::not_found(format!("macOS image '{name}'")));
        }
        let raw = std::fs::read_to_string(&meta_path)?;
        let meta: MacImageMeta = serde_json::from_str(&raw)
            .map_err(|e| CoreError::macos(format!("parse {}: {e}", meta_path.display())))?;
        Ok(MacImage { meta, dir })
    }

    /// Lists all base images. Unreadable entries are skipped with a warning.
    #[must_use]
    pub fn list(&self) -> Vec<MacImage> {
        let Ok(entries) = std::fs::read_dir(&self.images_dir) else {
            return Vec::new();
        };
        let mut images = Vec::new();
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(String::from) else {
                continue;
            };
            match self.get(&name) {
                Ok(image) => images.push(image),
                Err(e) => tracing::warn!("skipping macOS image '{name}': {e}"),
            }
        }
        images
    }

    /// Removes a base image and all its artifacts.
    ///
    /// # Errors
    /// Returns a not-found error if the image does not exist, an invalid-name
    /// error if `name` is not a safe path component, or an I/O error if removal
    /// fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        let dir = self.image_dir(name)?;
        if !dir.exists() {
            return Err(CoreError::not_found(format!("macOS image '{name}'")));
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// Persists the metadata for a base image.
    ///
    /// The disk, auxiliary storage, and identity files are written by the install
    /// flow; this records the accompanying `meta.json`.
    ///
    /// # Errors
    /// Returns an error if the name is invalid or the metadata cannot be
    /// serialized or written.
    pub fn write_meta(&self, meta: &MacImageMeta) -> Result<()> {
        Self::write_meta_in(&self.image_dir(&meta.name)?, meta)
    }

    /// Persists metadata into an explicit directory (used by the pull flow to
    /// assemble an image in a staging directory before renaming it live).
    ///
    /// # Errors
    /// Returns an error if the metadata cannot be serialized or written.
    pub(super) fn write_meta_in(dir: &Path, meta: &MacImageMeta) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(meta)
            .map_err(|e| CoreError::macos(format!("serialize image metadata: {e}")))?;
        std::fs::write(dir.join(META_FILE), json)?;
        Ok(())
    }
}

/// Copy-on-write clones `src` to `dst` via `clonefile(2)`, falling back to a full
/// copy when the destination is not on the same APFS volume.
fn cow_clone(src: &Path, dst: &Path) -> Result<()> {
    let _ = std::fs::remove_file(dst); // clonefile fails if the destination exists.
    let src_c = CString::new(src.as_os_str().as_bytes())
        .map_err(|e| CoreError::macos(format!("path {}: {e}", src.display())))?;
    let dst_c = CString::new(dst.as_os_str().as_bytes())
        .map_err(|e| CoreError::macos(format!("path {}: {e}", dst.display())))?;
    // SAFETY: clonefile takes two valid NUL-terminated C paths and a flags word.
    let rc = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOTSUP | libc::EXDEV) => {
            tracing::warn!(
                "clonefile unsupported for {} ({err}); falling back to a full copy",
                dst.display()
            );
            std::fs::copy(src, dst)?;
            Ok(())
        }
        _ => Err(CoreError::macos(format!(
            "clonefile {} -> {}: {err}",
            src.display(),
            dst.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_meta() -> MacImageMeta {
        MacImageMeta {
            name: "base".into(),
            source: Some("/tmp/UniversalMac.ipsw".into()),
            stream: None,
            version: None,
            os_version: None,
            os_build: None,
            runner_version: None,
            minimum_cpu_count: 2,
            minimum_memory_mib: 4096,
            disk_gb: 64,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn meta_round_trips_through_registry() {
        let dir = tempdir().unwrap();
        let mgr = MacImageManager::new(dir.path());
        let meta = sample_meta();
        mgr.write_meta(&meta).unwrap();

        let loaded = mgr.get("base").unwrap();
        assert_eq!(loaded.meta, meta);
        assert_eq!(
            loaded.disk_path(),
            mgr.image_dir("base").unwrap().join("disk.img")
        );
        assert_eq!(mgr.list().len(), 1);
    }

    #[test]
    fn get_missing_image_is_not_found() {
        let dir = tempdir().unwrap();
        let mgr = MacImageManager::new(dir.path());
        assert!(mgr.get("nope").is_err());
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn traversal_names_are_rejected_before_touching_the_fs() {
        let dir = tempdir().unwrap();
        // A sibling directory that a traversal name would try to escape into.
        let victim = dir.path().join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        let mgr = MacImageManager::new(dir.path());

        assert!(mgr.get("../victim").is_err());
        assert!(mgr.remove("../victim").is_err());
        assert!(mgr.image_dir("a/b").is_err());
        // The rejected names never reached the filesystem.
        assert!(victim.exists());
    }
}
