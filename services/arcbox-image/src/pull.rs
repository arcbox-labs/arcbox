//! Image pulling from container registries.
//!
//! Implements the complete image pull workflow:
//! 1. Fetch manifest (handle manifest list for multi-arch)
//! 2. Download config blob
//! 3. Download layer blobs in parallel
//! 4. Store in local image store

use std::sync::Arc;

use futures::stream::{self, StreamExt};
use tracing::{debug, info};

use crate::{
    ImageRef,
    error::{ImageError, Result},
    manifest::ImageManifest,
    registry::{ManifestResponse, RegistryClient, select_platform_manifest},
    store::ImageStore,
};

/// Maximum concurrent layer downloads.
const MAX_CONCURRENT_DOWNLOADS: usize = 4;

/// Image puller with progress reporting.
pub struct ImagePuller {
    /// Image store for persisting images.
    store: Arc<ImageStore>,
    /// Registry client.
    client: RegistryClient,
    /// Progress callback.
    progress: Option<Arc<dyn PullProgress>>,
}

impl ImagePuller {
    /// Creates a new image puller.
    #[must_use]
    pub fn new(store: Arc<ImageStore>, client: RegistryClient) -> Self {
        Self {
            store,
            client,
            progress: None,
        }
    }

    /// Sets the progress callback.
    #[must_use]
    pub fn with_progress<P: PullProgress + 'static>(mut self, progress: P) -> Self {
        self.progress = Some(Arc::new(progress));
        self
    }

    /// Pulls an image from the registry.
    ///
    /// Returns the image ID (config digest).
    ///
    /// # Errors
    ///
    /// Returns an error if the image cannot be pulled.
    pub async fn pull(&self, reference: &ImageRef) -> Result<String> {
        info!(reference = %reference, "pulling image");

        // Check if image already exists.
        if let Some(image) = self.store.get(reference) {
            info!(id = %image.id, "image already exists locally");
            if let Some(p) = &self.progress {
                p.complete(&image.id);
            }
            return Ok(image.id);
        }

        // 1. Get manifest (may be manifest list for multi-arch).
        let manifest = self.get_manifest(reference).await?;

        // 2. Download config blob.
        debug!(
            digest = %manifest.config.digest,
            size = manifest.config.size,
            "downloading config"
        );

        if !self.store.blob_exists(&manifest.config.digest) {
            let config_data = self
                .client
                .get_blob(reference, &manifest.config.digest)
                .await?;
            self.store
                .store_blob(&config_data, Some(&manifest.config.digest))?;
        }

        // 3. Download layers in parallel.
        // Clone layers to avoid lifetime issues with async closures.
        let layers_to_download: Vec<_> = manifest
            .layers
            .iter()
            .filter(|l| !self.store.blob_exists(&l.digest))
            .cloned()
            .collect();

        if layers_to_download.is_empty() {
            debug!("all layers already exist locally");
        } else {
            info!(count = layers_to_download.len(), "downloading layers");

            // Report layer starts.
            for layer in &layers_to_download {
                if let Some(p) = &self.progress {
                    p.layer_start(&layer.digest, layer.size);
                }
            }

            // Clone references needed in async tasks.
            let client = &self.client;
            let store = &self.store;
            let repo = reference.repository.clone();

            // Download layers concurrently.
            let results: Vec<Result<()>> = stream::iter(layers_to_download)
                .map(|layer| {
                    let progress = self.progress.clone();
                    let repo = repo.clone();
                    let digest = layer.digest.clone();
                    let size = layer.size;

                    async move {
                        debug!(digest = %digest, size = size, "downloading layer");

                        let data = if let Some(p) = &progress {
                            let p = p.clone();
                            let digest_for_progress = digest.clone();
                            client
                                .get_blob_by_repo(
                                    &repo,
                                    &digest,
                                    size,
                                    Some(move |downloaded, total| {
                                        p.layer_progress(&digest_for_progress, downloaded, total);
                                    }),
                                )
                                .await?
                        } else {
                            client
                                .get_blob_by_repo(&repo, &digest, size, None::<fn(u64, u64)>)
                                .await?
                        };

                        store.store_blob(&data, Some(&digest))?;

                        if let Some(p) = &progress {
                            p.layer_complete(&digest);
                        }

                        debug!(digest = %digest, "layer downloaded");
                        Ok(())
                    }
                })
                .buffer_unordered(MAX_CONCURRENT_DOWNLOADS)
                .collect()
                .await;

            // Check for errors.
            for result in results {
                result?;
            }
        }

        // 4. Store manifest and image record.
        self.store.store_manifest(reference, &manifest)?;
        let image_id = self.store.store(reference, &manifest)?;

        info!(id = %image_id, "image pull complete");

        if let Some(p) = &self.progress {
            p.complete(&image_id);
        }

        Ok(image_id)
    }

    /// Gets the manifest for the current platform.
    ///
    /// Handles manifest list (fat manifest) by selecting the appropriate platform.
    async fn get_manifest(&self, reference: &ImageRef) -> Result<ImageManifest> {
        let response = self.client.get_manifest(reference).await?;

        match response {
            ManifestResponse::Manifest(m) => Ok(m),
            ManifestResponse::ManifestList(list) => {
                // Select manifest for current platform.
                let platform_manifest = select_platform_manifest(&list).ok_or_else(|| {
                    ImageError::Manifest(
                        "no manifest for current platform in manifest list".to_string(),
                    )
                })?;

                debug!(
                    arch = %platform_manifest.platform.architecture,
                    os = %platform_manifest.platform.os,
                    digest = %platform_manifest.digest,
                    "selected platform manifest"
                );

                // Fetch the actual manifest by digest.
                self.client
                    .get_manifest_by_digest(&reference.repository, &platform_manifest.digest)
                    .await
            }
        }
    }
}

/// Pull progress callback.
pub trait PullProgress: Send + Sync {
    /// Called when a layer download starts.
    fn layer_start(&self, digest: &str, size: u64);

    /// Called when layer download progress updates.
    fn layer_progress(&self, digest: &str, downloaded: u64, total: u64);

    /// Called when a layer download completes.
    fn layer_complete(&self, digest: &str);

    /// Called when the entire pull completes.
    fn complete(&self, image_id: &str);
}

/// No-op progress implementation.
pub struct NoProgress;

impl PullProgress for NoProgress {
    fn layer_start(&self, _digest: &str, _size: u64) {}
    fn layer_progress(&self, _digest: &str, _downloaded: u64, _total: u64) {}
    fn layer_complete(&self, _digest: &str) {}
    fn complete(&self, _image_id: &str) {}
}

/// Console progress reporter that prints to stdout.
pub struct ConsoleProgress;

impl ConsoleProgress {
    /// Extracts short digest (12 chars after sha256: prefix).
    fn short_digest(digest: &str) -> &str {
        let s = digest.strip_prefix("sha256:").unwrap_or(digest);
        &s[..12.min(s.len())]
    }
}

impl PullProgress for ConsoleProgress {
    fn layer_start(&self, digest: &str, size: u64) {
        let short = Self::short_digest(digest);
        println!("Downloading layer {short}... ({size} bytes)");
    }

    fn layer_progress(&self, digest: &str, downloaded: u64, total: u64) {
        let short = Self::short_digest(digest);
        let percent = if total > 0 {
            // Safe: result is always 0-100, fits in u64.
            #[allow(clippy::cast_possible_truncation)]
            let p = (u128::from(downloaded) * 100 / u128::from(total)) as u64;
            p
        } else {
            0
        };
        // Only print at 25% intervals to reduce noise.
        if percent % 25 == 0 && downloaded > 0 {
            print!("\r{short}: {percent}%");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }

    fn layer_complete(&self, digest: &str) {
        let short = Self::short_digest(digest);
        println!("\r{short}: complete");
    }

    fn complete(&self, image_id: &str) {
        let short = Self::short_digest(image_id);
        println!("Pull complete: {short}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[allow(dead_code)]
    struct CountingProgress {
        layer_starts: AtomicU32,
        layer_completes: AtomicU32,
        complete_calls: AtomicU32,
    }

    #[allow(dead_code)]
    impl CountingProgress {
        fn new() -> Self {
            Self {
                layer_starts: AtomicU32::new(0),
                layer_completes: AtomicU32::new(0),
                complete_calls: AtomicU32::new(0),
            }
        }
    }

    impl PullProgress for CountingProgress {
        fn layer_start(&self, _digest: &str, _size: u64) {
            self.layer_starts.fetch_add(1, Ordering::Relaxed);
        }

        fn layer_progress(&self, _digest: &str, _downloaded: u64, _total: u64) {}

        fn layer_complete(&self, _digest: &str) {
            self.layer_completes.fetch_add(1, Ordering::Relaxed);
        }

        fn complete(&self, _image_id: &str) {
            self.complete_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_no_progress() {
        let p = NoProgress;
        p.layer_start("sha256:abc", 1000);
        p.layer_progress("sha256:abc", 500, 1000);
        p.layer_complete("sha256:abc");
        p.complete("sha256:xyz");
    }

    #[test]
    fn test_short_digest() {
        // Normal case.
        assert_eq!(
            ConsoleProgress::short_digest("sha256:abc123def456789"),
            "abc123def456"
        );
        // Short digest.
        assert_eq!(ConsoleProgress::short_digest("sha256:abc"), "abc");
        // No prefix.
        assert_eq!(
            ConsoleProgress::short_digest("abc123def456789"),
            "abc123def456"
        );
        // Empty.
        assert_eq!(ConsoleProgress::short_digest(""), "");
        // Just prefix.
        assert_eq!(ConsoleProgress::short_digest("sha256:"), "");
    }
}
