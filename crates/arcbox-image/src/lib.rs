//! # arcbox-image
//!
//! Container image management for `ArcBox`.
//!
//! This crate handles OCI image operations:
//!
//! - Image pull from registries
//! - Image push to registries
//! - Local image storage
//! - Layer management
//! - Image building
//!
//! ## OCI Compatibility
//!
//! Fully compatible with OCI Image Specification and Docker registries.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod layer;
pub mod manifest;
pub mod pull;
pub mod registry;
pub mod store;

pub use error::{ImageError, Result};
pub use manifest::{ImageConfig, ImageManifest, ManifestList, Platform, PlatformManifest};
pub use pull::{ImagePuller, PullProgress};
pub use registry::{ManifestResponse, RegistryAuth, RegistryClient};
pub use store::ImageStore;

/// Image reference (e.g., "docker.io/library/nginx:latest").
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ImageRef {
    /// Registry (e.g., "docker.io").
    pub registry: String,
    /// Repository (e.g., "library/nginx").
    pub repository: String,
    /// Tag or digest.
    pub reference: String,
}

impl ImageRef {
    /// Parses an image reference string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        // Simple parser, real implementation would be more robust
        let (registry, rest) = if s.contains('/') && s.split('/').next()?.contains('.') {
            let idx = s.find('/')?;
            (&s[..idx], &s[idx + 1..])
        } else {
            ("docker.io", s)
        };

        let (repository, reference) = if rest.contains(':') {
            let idx = rest.rfind(':')?;
            (&rest[..idx], &rest[idx + 1..])
        } else if rest.contains('@') {
            let idx = rest.find('@')?;
            (&rest[..idx], &rest[idx + 1..])
        } else {
            (rest, "latest")
        };

        // Add library/ prefix for Docker Hub
        let repository = if registry == "docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository.to_string()
        };

        Some(Self {
            registry: registry.to_string(),
            repository,
            reference: reference.to_string(),
        })
    }

    /// Returns the full image name.
    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}/{}:{}", self.registry, self.repository, self.reference)
    }
}

impl std::fmt::Display for ImageRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_name())
    }
}
