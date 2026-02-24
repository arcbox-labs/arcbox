//! Image layer management.

use crate::error::Result;
use std::path::PathBuf;

/// Layer identifier (digest).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LayerId(String);

impl LayerId {
    /// Creates a new layer ID from a digest.
    #[must_use]
    pub fn new(digest: impl Into<String>) -> Self {
        Self(digest.into())
    }

    /// Returns the digest string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the short ID (first 12 characters).
    #[must_use]
    pub fn short(&self) -> &str {
        let s = self.0.strip_prefix("sha256:").unwrap_or(&self.0);
        &s[..12.min(s.len())]
    }
}

impl std::fmt::Display for LayerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Layer information.
#[derive(Debug, Clone)]
pub struct Layer {
    /// Layer ID (digest).
    pub id: LayerId,
    /// Layer size in bytes.
    pub size: u64,
    /// Media type.
    pub media_type: String,
    /// Path to layer data.
    pub path: PathBuf,
}

/// Layer store.
pub struct LayerStore {
    /// Base directory for layer storage.
    base_dir: PathBuf,
}

impl LayerStore {
    /// Creates a new layer store.
    #[must_use]
    pub const fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Returns the path for a layer.
    #[must_use]
    pub fn layer_path(&self, id: &LayerId) -> PathBuf {
        let digest = id.as_str().strip_prefix("sha256:").unwrap_or(id.as_str());
        self.base_dir.join("blobs").join("sha256").join(digest)
    }

    /// Checks if a layer exists.
    #[must_use]
    pub fn exists(&self, id: &LayerId) -> bool {
        self.layer_path(id).exists()
    }

    /// Gets layer information.
    ///
    /// # Errors
    ///
    /// Returns an error if the layer metadata cannot be read.
    pub fn get(&self, id: &LayerId) -> Result<Option<Layer>> {
        let path = self.layer_path(id);
        if !path.exists() {
            return Ok(None);
        }

        let metadata = std::fs::metadata(&path)?;
        Ok(Some(Layer {
            id: id.clone(),
            size: metadata.len(),
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            path,
        }))
    }
}
