//! Image layer extraction and rootfs creation.
//!
//! This module handles extracting OCI image layers and merging them into
//! a container rootfs. It supports Docker whiteout files for layer deletion.
//!
//! # Whiteout Handling
//!
//! Docker/OCI uses special "whiteout" files to mark deletions in layers:
//!
//! - `.wh.<filename>` - Delete `<filename>` from lower layers
//! - `.wh..wh..opq` - Make directory opaque (hide all content from lower layers)
//!
//! # Example
//!
//! ```ignore
//! use arcbox_image::extract::RootfsBuilder;
//!
//! let builder = RootfsBuilder::new(rootfs_path);
//! builder.extract_layer(layer1_path)?;
//! builder.extract_layer(layer2_path)?;
//! let rootfs = builder.finalize()?;
//! ```

use crate::ImageRef;
use crate::error::{ImageError, Result};
use crate::manifest::ImageManifest;
use crate::store::ImageStore;

use flate2::read::GzDecoder;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::Archive;
use tracing::{debug, info};

// ============================================================================
// Constants
// ============================================================================

/// Docker whiteout prefix for deleted files.
const WHITEOUT_PREFIX: &str = ".wh.";

/// Docker opaque whiteout marker (hides all content from lower layers).
const WHITEOUT_OPAQUE: &str = ".wh..wh..opq";

// ============================================================================
// RootfsBuilder
// ============================================================================

/// Builder for creating a container rootfs from image layers.
///
/// Layers are applied in order from bottom to top, with whiteout files
/// handling deletions from lower layers.
pub struct RootfsBuilder {
    /// Target rootfs directory.
    rootfs_path: PathBuf,
    /// Set of paths marked as opaque (content from lower layers hidden).
    opaque_dirs: HashSet<PathBuf>,
    /// Set of paths marked for deletion (whiteout files).
    deleted_paths: HashSet<PathBuf>,
    /// Number of layers applied.
    layer_count: usize,
}

impl RootfsBuilder {
    /// Creates a new rootfs builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the rootfs directory cannot be created.
    pub fn new(rootfs_path: impl AsRef<Path>) -> Result<Self> {
        let rootfs_path = rootfs_path.as_ref().to_path_buf();
        fs::create_dir_all(&rootfs_path)?;

        Ok(Self {
            rootfs_path,
            opaque_dirs: HashSet::new(),
            deleted_paths: HashSet::new(),
            layer_count: 0,
        })
    }

    /// Returns the rootfs path.
    #[must_use]
    pub fn rootfs_path(&self) -> &Path {
        &self.rootfs_path
    }

    /// Extracts a layer from a tar.gz file into the rootfs.
    ///
    /// Handles whiteout files for deletion and opaque markers.
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails.
    pub fn extract_layer(&mut self, layer_path: impl AsRef<Path>) -> Result<()> {
        let layer_path = layer_path.as_ref();
        debug!(layer = %layer_path.display(), "extracting layer");

        let file = File::open(layer_path)?;

        // Detect if gzip compressed
        let is_gzip = self.is_gzip(layer_path)?;

        if is_gzip {
            let decoder = GzDecoder::new(file);
            self.extract_tar(decoder)?;
        } else {
            self.extract_tar(file)?;
        }

        self.layer_count += 1;
        debug!(
            layer = %layer_path.display(),
            layer_num = self.layer_count,
            "layer extracted"
        );

        Ok(())
    }

    /// Extracts a tar archive into the rootfs (from a file reader).
    ///
    /// This is a wrapper around `extract_tar_impl` for reading from files.
    #[allow(dead_code)]
    fn extract_tar<R: Read>(&mut self, reader: R) -> Result<()> {
        self.extract_tar_impl(reader)
    }

    /// Extracts a layer from bytes (for in-memory processing).
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails.
    pub fn extract_layer_from_bytes(&mut self, data: &[u8]) -> Result<()> {
        // Detect compression
        let is_gzip = data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b;

        if is_gzip {
            let decoder = GzDecoder::new(data);
            self.extract_tar_impl(decoder)?;
        } else {
            self.extract_tar_impl(data)?;
        }

        self.layer_count += 1;
        Ok(())
    }

    /// Internal tar extraction implementation.
    fn extract_tar_impl<R: Read>(&mut self, reader: R) -> Result<()> {
        let mut archive = Archive::new(reader);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_unpack_xattrs(true);

        for entry_result in archive.entries()? {
            let mut entry = entry_result?;
            let path = entry.path()?.to_path_buf();
            let path_str = path.to_string_lossy();

            // Get the filename
            let file_name = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();

            // Check for whiteout markers
            if file_name == WHITEOUT_OPAQUE {
                // Opaque directory marker - hide content from lower layers
                if let Some(parent) = path.parent() {
                    let opaque_dir = self.rootfs_path.join(parent);
                    debug!(dir = %opaque_dir.display(), "marking directory as opaque");
                    self.opaque_dirs.insert(parent.to_path_buf());

                    // Clear the directory content (simulating opaque behavior)
                    if opaque_dir.exists() {
                        self.clear_directory(&opaque_dir)?;
                    }
                }
                continue;
            }

            if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
                // Whiteout file - mark target for deletion
                if let Some(parent) = path.parent() {
                    let target_path = parent.join(target_name);
                    let full_target = self.rootfs_path.join(&target_path);

                    debug!(target = %full_target.display(), "processing whiteout");
                    self.deleted_paths.insert(target_path);

                    // Remove the target if it exists
                    if full_target.exists() {
                        if full_target.is_dir() {
                            fs::remove_dir_all(&full_target)?;
                        } else {
                            fs::remove_file(&full_target)?;
                        }
                    }
                }
                continue;
            }

            // Skip if this path was deleted by a whiteout
            if self.deleted_paths.contains(&path) {
                continue;
            }

            // Skip if parent is opaque and we're not in the current layer
            // (This is simplified - proper implementation would track layer boundaries)

            // Extract the entry
            let dest_path = self.rootfs_path.join(&path);

            // Create parent directories
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Extract based on entry type
            let entry_type = entry.header().entry_type();

            match entry_type {
                tar::EntryType::Directory => {
                    fs::create_dir_all(&dest_path)?;
                    // Set permissions
                    if let Ok(mode) = entry.header().mode() {
                        let _ = fs::set_permissions(&dest_path, fs::Permissions::from_mode(mode));
                    }
                }
                tar::EntryType::Regular | tar::EntryType::Continuous => {
                    // Create or overwrite file
                    let mut file = File::create(&dest_path)?;
                    io::copy(&mut entry, &mut file)?;

                    // Set permissions
                    if let Ok(mode) = entry.header().mode() {
                        let _ = fs::set_permissions(&dest_path, fs::Permissions::from_mode(mode));
                    }
                }
                tar::EntryType::Symlink => {
                    // Create symlink
                    if let Ok(Some(target)) = entry.link_name() {
                        // Remove existing file/symlink if present
                        let _ = fs::remove_file(&dest_path);
                        std::os::unix::fs::symlink(target, &dest_path)?;
                    }
                }
                tar::EntryType::Link => {
                    // Create hard link
                    if let Ok(Some(target)) = entry.link_name() {
                        let link_src = self.rootfs_path.join(target.as_ref());
                        if link_src.exists() {
                            let _ = fs::remove_file(&dest_path);
                            fs::hard_link(&link_src, &dest_path)?;
                        }
                    }
                }
                tar::EntryType::Char | tar::EntryType::Block => {
                    // Skip device nodes (requires root privileges)
                    debug!(path = %path_str, "skipping device node");
                }
                tar::EntryType::Fifo => {
                    // Skip FIFOs
                    debug!(path = %path_str, "skipping FIFO");
                }
                _ => {
                    // Skip other types
                    debug!(path = %path_str, entry_type = ?entry_type, "skipping unknown entry type");
                }
            }
        }

        Ok(())
    }

    /// Clears all content in a directory (for opaque whiteout).
    #[allow(clippy::unused_self)]
    fn clear_directory(&self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }

        Ok(())
    }

    /// Checks if a file is gzip compressed.
    #[allow(clippy::unused_self)]
    fn is_gzip(&self, path: &Path) -> Result<bool> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 2];
        if file.read_exact(&mut magic).is_ok() {
            Ok(magic[0] == 0x1f && magic[1] == 0x8b)
        } else {
            Ok(false)
        }
    }

    /// Finalizes the rootfs and returns the path.
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility.
    pub fn finalize(self) -> Result<PathBuf> {
        info!(
            rootfs = %self.rootfs_path.display(),
            layers = self.layer_count,
            "rootfs created"
        );
        Ok(self.rootfs_path)
    }
}

/// Type of whiteout entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum WhiteoutType {
    /// Regular whiteout (delete specific file).
    File,
    /// Opaque whiteout (hide all content from lower layers).
    Opaque,
}

// ============================================================================
// ImageStore Extension
// ============================================================================

impl ImageStore {
    /// Extracts an image to a rootfs directory.
    ///
    /// This extracts all layers in order from bottom to top, handling
    /// whiteout files for deletion.
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails.
    pub fn extract_image(&self, reference: &ImageRef, rootfs_dir: &Path) -> Result<PathBuf> {
        info!(image = %reference, rootfs = %rootfs_dir.display(), "extracting image");

        // Get manifest
        let manifest = self.get_manifest(reference)?;

        // Create rootfs builder
        let mut builder = RootfsBuilder::new(rootfs_dir)?;

        // Extract layers in order (bottom to top)
        for (i, layer) in manifest.layers.iter().enumerate() {
            let layer_path = self.blob_path(&layer.digest);
            if !layer_path.exists() {
                return Err(ImageError::Layer(format!(
                    "layer blob not found: {}",
                    layer.digest
                )));
            }

            debug!(
                layer = i + 1,
                total = manifest.layers.len(),
                digest = %layer.digest,
                "extracting layer"
            );

            // Read layer data
            let layer_data = fs::read(&layer_path)?;
            builder.extract_layer_from_bytes(&layer_data)?;
        }

        builder.finalize()
    }

    /// Gets the manifest for an image.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be read.
    pub fn get_manifest(&self, reference: &ImageRef) -> Result<ImageManifest> {
        // Look up manifest digest from reference file
        let ref_path = self
            .base_dir()
            .join("manifests")
            .join(&reference.registry)
            .join(&reference.repository)
            .join(&reference.reference);

        if !ref_path.exists() {
            return Err(ImageError::NotFound(format!(
                "manifest reference not found: {reference}"
            )));
        }

        let digest = fs::read_to_string(&ref_path)?;
        let manifest_data = self.get_blob(&digest)?;
        let manifest: ImageManifest = serde_json::from_slice(&manifest_data)?;

        Ok(manifest)
    }

    /// Gets the image configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be read.
    pub fn get_image_config(&self, reference: &ImageRef) -> Result<crate::manifest::ImageConfig> {
        let manifest = self.get_manifest(reference)?;
        let config_data = self.get_blob(&manifest.config.digest)?;
        let config: crate::manifest::ImageConfig = serde_json::from_slice(&config_data)?;
        Ok(config)
    }

    /// Returns the rootfs path for a container.
    ///
    /// The path is: `~/.arcbox/containers/<container_id>/rootfs`
    pub fn container_rootfs_path(&self, container_id: &str) -> PathBuf {
        let base = self.base_dir();
        base.parent()
            .unwrap_or(base)
            .join("containers")
            .join(container_id)
            .join("rootfs")
    }

    /// Prepares a container rootfs from an image.
    ///
    /// This extracts the image layers to create the container's rootfs.
    ///
    /// # Errors
    ///
    /// Returns an error if the rootfs cannot be prepared.
    pub fn prepare_container_rootfs(
        &self,
        container_id: &str,
        image_ref: &ImageRef,
    ) -> Result<PathBuf> {
        let rootfs_path = self.container_rootfs_path(container_id);

        // Check if already extracted
        if rootfs_path.exists() && rootfs_path.join("bin").exists() {
            debug!(
                container_id = %container_id,
                rootfs = %rootfs_path.display(),
                "rootfs already exists"
            );
            return Ok(rootfs_path);
        }

        // Extract image
        self.extract_image(image_ref, &rootfs_path)?;

        info!(
            container_id = %container_id,
            image = %image_ref,
            rootfs = %rootfs_path.display(),
            "container rootfs prepared"
        );

        Ok(rootfs_path)
    }

    /// Removes a container's rootfs.
    ///
    /// # Errors
    ///
    /// Returns an error if removal fails.
    pub fn remove_container_rootfs(&self, container_id: &str) -> Result<()> {
        let base = self.base_dir();
        let container_dir = base
            .parent()
            .unwrap_or(base)
            .join("containers")
            .join(container_id);

        if container_dir.exists() {
            fs::remove_dir_all(&container_dir)?;
            debug!(container_id = %container_id, "removed container rootfs");
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn create_test_layer(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());

        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, *content).unwrap();
        }

        let tar_data = builder.into_inner().unwrap();

        // Compress with gzip
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_extract_simple_layer() {
        let dir = tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");

        let layer_data = create_test_layer(&[("file1.txt", b"hello"), ("dir/file2.txt", b"world")]);

        let mut builder = RootfsBuilder::new(&rootfs).unwrap();
        builder.extract_layer_from_bytes(&layer_data).unwrap();
        builder.finalize().unwrap();

        assert!(rootfs.join("file1.txt").exists());
        assert!(rootfs.join("dir/file2.txt").exists());

        let content = fs::read_to_string(rootfs.join("file1.txt")).unwrap();
        assert_eq!(content, "hello");
    }

    #[test]
    fn test_whiteout_deletion() {
        let dir = tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");

        // Layer 1: create files
        let layer1 = create_test_layer(&[("file1.txt", b"keep me"), ("file2.txt", b"delete me")]);

        // Layer 2: whiteout file2.txt
        let layer2 = create_test_layer(&[(".wh.file2.txt", b"")]);

        let mut builder = RootfsBuilder::new(&rootfs).unwrap();
        builder.extract_layer_from_bytes(&layer1).unwrap();
        builder.extract_layer_from_bytes(&layer2).unwrap();
        builder.finalize().unwrap();

        assert!(rootfs.join("file1.txt").exists());
        assert!(!rootfs.join("file2.txt").exists());
    }

    #[test]
    fn test_opaque_whiteout() {
        let dir = tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");

        // Layer 1: create directory with files
        let layer1 = create_test_layer(&[
            ("mydir/file1.txt", b"old content"),
            ("mydir/file2.txt", b"also old"),
        ]);

        // Layer 2: opaque marker + new file
        // Note: In real tar, we'd have the opaque marker first, then new content
        let mut builder2 = tar::Builder::new(Vec::new());

        // Add opaque marker
        let mut header = tar::Header::new_gnu();
        header.set_path("mydir/.wh..wh..opq").unwrap();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder2.append(&header, &[][..]).unwrap();

        // Add new file
        let mut header = tar::Header::new_gnu();
        header.set_path("mydir/newfile.txt").unwrap();
        header.set_size(11);
        header.set_mode(0o644);
        header.set_cksum();
        builder2.append(&header, &b"new content"[..]).unwrap();

        let tar_data = builder2.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        let layer2 = encoder.finish().unwrap();

        let mut builder = RootfsBuilder::new(&rootfs).unwrap();
        builder.extract_layer_from_bytes(&layer1).unwrap();
        builder.extract_layer_from_bytes(&layer2).unwrap();
        builder.finalize().unwrap();

        // Old files should be gone (opaque), new file should exist
        assert!(!rootfs.join("mydir/file1.txt").exists());
        assert!(!rootfs.join("mydir/file2.txt").exists());
        assert!(rootfs.join("mydir/newfile.txt").exists());
    }

    #[test]
    fn test_layer_override() {
        let dir = tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");

        // Layer 1: create file
        let layer1 = create_test_layer(&[("file.txt", b"original")]);

        // Layer 2: override file
        let layer2 = create_test_layer(&[("file.txt", b"modified")]);

        let mut builder = RootfsBuilder::new(&rootfs).unwrap();
        builder.extract_layer_from_bytes(&layer1).unwrap();
        builder.extract_layer_from_bytes(&layer2).unwrap();
        builder.finalize().unwrap();

        let content = fs::read_to_string(rootfs.join("file.txt")).unwrap();
        assert_eq!(content, "modified");
    }

    #[test]
    fn test_get_manifest_not_found() {
        let dir = tempdir().unwrap();
        let store = ImageStore::new(dir.path().to_path_buf()).unwrap();

        let reference = ImageRef::parse("nonexistent/image:latest").unwrap();
        let result = store.get_manifest(&reference);

        assert!(result.is_err());
        match result.unwrap_err() {
            ImageError::NotFound(msg) => {
                assert!(
                    msg.contains("manifest reference not found"),
                    "Error should indicate manifest not found: {msg}"
                );
            }
            err => panic!("Expected NotFound error, got: {err:?}"),
        }
    }

    #[test]
    fn test_get_image_config_not_found() {
        let dir = tempdir().unwrap();
        let store = ImageStore::new(dir.path().to_path_buf()).unwrap();

        let reference = ImageRef::parse("alpine:latest").unwrap();
        let result = store.get_image_config(&reference);

        // Should return NotFound since the image hasn't been pulled.
        assert!(result.is_err());
        match result.unwrap_err() {
            ImageError::NotFound(_) => {
                // Expected - image doesn't exist locally.
            }
            err => panic!("Expected NotFound error, got: {err:?}"),
        }
    }

    #[test]
    fn test_image_not_found_triggers_auto_pull_condition() {
        // This test verifies the error type that triggers auto-pull in runtime.
        // The auto-pull logic in runtime.rs checks for ImageError::NotFound.
        let dir = tempdir().unwrap();
        let store = ImageStore::new(dir.path().to_path_buf()).unwrap();

        let reference = ImageRef::parse("busybox:latest").unwrap();
        let result = store.get_image_config(&reference);

        // Verify this returns the exact error type that runtime uses to trigger auto-pull.
        assert!(
            matches!(result, Err(ImageError::NotFound(_))),
            "Missing image should return ImageError::NotFound to trigger auto-pull"
        );
    }
}
