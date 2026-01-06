//! Local image storage.
//!
//! Storage layout:
//! ```text
//! ~/.arcbox/images/
//! ├── blobs/
//! │   └── sha256/
//! │       └── <digest>           # layer and config content
//! ├── manifests/
//! │   └── <registry>/<repo>/<tag>  # manifest JSON
//! └── index.json                 # local image index
//! ```

use crate::{
    error::{ImageError, Result},
    layer::LayerStore,
    manifest::ImageManifest,
    ImageRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tracing::{debug, info};

/// Local image information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalImage {
    /// Image reference.
    pub reference: ImageRef,
    /// Image ID (config digest).
    pub id: String,
    /// Created timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Image size.
    pub size: u64,
}

/// Image index stored on disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ImageIndex {
    images: HashMap<String, LocalImage>,
}

/// Local image store.
pub struct ImageStore {
    /// Base directory.
    base_dir: PathBuf,
    /// Layer store.
    layer_store: LayerStore,
    /// Image index (cached in memory).
    images: RwLock<HashMap<String, LocalImage>>,
}

impl ImageStore {
    /// Creates a new image store.
    ///
    /// # Errors
    ///
    /// Returns an error if the directories cannot be created.
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        // Create directory structure.
        let blobs_dir = base_dir.join("blobs").join("sha256");
        let manifests_dir = base_dir.join("manifests");

        fs::create_dir_all(&blobs_dir)?;
        fs::create_dir_all(&manifests_dir)?;

        let layer_store = LayerStore::new(base_dir.clone());

        // Load existing index.
        let images = Self::load_index(&base_dir).unwrap_or_default();

        Ok(Self {
            base_dir,
            layer_store,
            images: RwLock::new(images),
        })
    }

    /// Opens an existing image store or creates a new one at the default location.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be opened or created.
    pub fn open_default() -> Result<Self> {
        let base_dir = dirs::home_dir()
            .ok_or_else(|| ImageError::Storage("cannot find home directory".to_string()))?
            .join(".arcbox")
            .join("images");
        Self::new(base_dir)
    }

    /// Returns the base directory.
    #[must_use]
    pub const fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    /// Returns the layer store.
    #[must_use]
    pub const fn layer_store(&self) -> &LayerStore {
        &self.layer_store
    }

    /// Returns the path for a blob.
    #[must_use]
    pub fn blob_path(&self, digest: &str) -> PathBuf {
        let hash = digest.strip_prefix("sha256:").unwrap_or(digest);
        self.base_dir.join("blobs").join("sha256").join(hash)
    }

    /// Checks if a blob exists.
    #[must_use]
    pub fn blob_exists(&self, digest: &str) -> bool {
        self.blob_path(digest).exists()
    }

    /// Stores a blob and verifies its digest.
    ///
    /// Returns the digest of the stored blob.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be stored or the digest doesn't match.
    pub fn store_blob(&self, data: &[u8], expected_digest: Option<&str>) -> Result<String> {
        // Calculate digest.
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let digest = format!("sha256:{}", hex::encode(hash));

        // Verify digest if expected.
        if let Some(expected) = expected_digest {
            if digest != expected {
                return Err(ImageError::Layer(format!(
                    "digest mismatch: expected {expected}, got {digest}"
                )));
            }
        }

        // Check if already exists.
        let path = self.blob_path(&digest);
        if path.exists() {
            debug!(digest = %digest, "blob already exists");
            return Ok(digest);
        }

        // Write to temp file and rename for atomicity.
        // Use unique temp name to avoid conflicts with concurrent writes.
        let temp_name = format!(
            "{}.tmp.{}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            std::process::id()
        );
        let temp_path = path.with_file_name(temp_name);
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);

        // Atomic rename (may fail on Windows across volumes, but fine for same dir).
        if let Err(e) = fs::rename(&temp_path, &path) {
            // Clean up temp file on failure.
            let _ = fs::remove_file(&temp_path);
            return Err(e.into());
        }

        debug!(digest = %digest, size = data.len(), "stored blob");
        Ok(digest)
    }

    /// Gets a blob's contents.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be read.
    pub fn get_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(digest);
        if !path.exists() {
            return Err(ImageError::NotFound(format!("blob {digest}")));
        }
        Ok(fs::read(&path)?)
    }

    /// Stores a manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be stored.
    pub fn store_manifest(&self, reference: &ImageRef, manifest: &ImageManifest) -> Result<String> {
        // Store manifest as blob.
        let manifest_json = serde_json::to_vec_pretty(manifest)?;
        let digest = self.store_blob(&manifest_json, None)?;

        // Store manifest reference.
        let manifest_path = self
            .base_dir
            .join("manifests")
            .join(&reference.registry)
            .join(&reference.repository);
        fs::create_dir_all(&manifest_path)?;

        let ref_path = manifest_path.join(&reference.reference);
        fs::write(&ref_path, &digest)?;

        debug!(
            reference = %reference,
            digest = %digest,
            "stored manifest"
        );
        Ok(digest)
    }

    /// Gets an image by reference.
    #[must_use]
    pub fn get(&self, reference: &ImageRef) -> Option<LocalImage> {
        self.images
            .read()
            .ok()?
            .get(&reference.full_name())
            .cloned()
    }

    /// Lists all images.
    #[must_use]
    pub fn list(&self) -> Vec<LocalImage> {
        self.images
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Stores an image record.
    ///
    /// # Errors
    ///
    /// Returns an error if the image cannot be stored.
    pub fn store(&self, reference: &ImageRef, manifest: &ImageManifest) -> Result<String> {
        let image_id = manifest.config.digest.clone();

        let image = LocalImage {
            reference: reference.clone(),
            id: image_id.clone(),
            created: chrono::Utc::now(),
            size: manifest.layers.iter().map(|l| l.size).sum(),
        };

        {
            let mut images = self
                .images
                .write()
                .map_err(|_| ImageError::Storage("lock poisoned".to_string()))?;
            images.insert(reference.full_name(), image);
        }

        // Persist to disk.
        self.save_index()?;

        info!(
            reference = %reference,
            id = %image_id,
            "stored image"
        );
        Ok(image_id)
    }

    /// Removes an image.
    ///
    /// # Errors
    ///
    /// Returns an error if the image cannot be removed.
    pub fn remove(&self, reference: &ImageRef) -> Result<()> {
        {
            let mut images = self
                .images
                .write()
                .map_err(|_| ImageError::Storage("lock poisoned".to_string()))?;
            images
                .remove(&reference.full_name())
                .ok_or_else(|| ImageError::NotFound(reference.full_name()))?;
        }

        // Persist to disk.
        self.save_index()?;

        Ok(())
    }

    /// Loads the image index from disk.
    fn load_index(base_dir: &Path) -> Result<HashMap<String, LocalImage>> {
        let index_path = base_dir.join("index.json");
        if !index_path.exists() {
            return Ok(HashMap::new());
        }

        let data = fs::read(&index_path)?;
        let index: ImageIndex = serde_json::from_slice(&data)?;
        Ok(index.images)
    }

    /// Saves the image index to disk.
    fn save_index(&self) -> Result<()> {
        // Clone the images while holding the lock, then release it before I/O.
        let index = {
            let images = self
                .images
                .read()
                .map_err(|_| ImageError::Storage("lock poisoned".to_string()))?;
            ImageIndex {
                images: images.clone(),
            }
        };

        let data = serde_json::to_vec_pretty(&index)?;
        let index_path = self.base_dir.join("index.json");
        let temp_path = index_path.with_extension("tmp");

        fs::write(&temp_path, &data)?;
        fs::rename(&temp_path, &index_path)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_store_blob() {
        let dir = tempdir().unwrap();
        let store = ImageStore::new(dir.path().to_path_buf()).unwrap();

        let data = b"hello world";
        let digest = store.store_blob(data, None).unwrap();
        assert!(digest.starts_with("sha256:"));

        // Should be able to retrieve it.
        let retrieved = store.get_blob(&digest).unwrap();
        assert_eq!(retrieved, data);

        // Should be idempotent.
        let digest2 = store.store_blob(data, None).unwrap();
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_store_blob_with_digest_verification() {
        let dir = tempdir().unwrap();
        let store = ImageStore::new(dir.path().to_path_buf()).unwrap();

        let data = b"hello world";
        // Correct digest.
        let correct_digest =
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let result = store.store_blob(data, Some(correct_digest));
        assert!(result.is_ok());

        // Wrong digest.
        let wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let result = store.store_blob(data, Some(wrong_digest));
        assert!(result.is_err());
    }

    #[test]
    fn test_image_index_persistence() {
        let dir = tempdir().unwrap();
        let store = ImageStore::new(dir.path().to_path_buf()).unwrap();

        let reference = ImageRef::parse("alpine:latest").unwrap();
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
            config: crate::manifest::Descriptor {
                media_type: "application/vnd.docker.container.image.v1+json".to_string(),
                digest: "sha256:abc123".to_string(),
                size: 1234,
            },
            layers: vec![],
        };

        store.store(&reference, &manifest).unwrap();

        // Create new store instance and verify persistence.
        let store2 = ImageStore::new(dir.path().to_path_buf()).unwrap();
        let image = store2.get(&reference).unwrap();
        assert_eq!(image.id, "sha256:abc123");
    }
}
