//! Pulling published macOS base images into the local registry.
//!
//! [`MacImageManager::pull_remote`] resolves a reference against the published
//! index (or consumes a manifest directly), validates host support *before*
//! the multi-gigabyte download, then restores the disk: its chunks download
//! with bounded parallelism and stream through decompression into a sparse
//! `disk.img` (the compressed bytes never touch disk — see [`super::disk`]).
//! The image is assembled in a staging directory and renamed live only after
//! every integrity check passes, so a failed pull never leaves a broken
//! registry entry.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::disk::{fetch_disk, verify_sha256};
use super::image::{
    AUX_FILE, DISK_FILE, HARDWARE_MODEL_FILE, MACHINE_ID_FILE, MacImage, MacImageManager,
    MacImageMeta,
};
use super::remote::{ImageManifest, ImageReference, RemoteIndex, RemoteLocation};
use super::{StagingGuard, validate_name};
use crate::error::{CoreError, Result};

/// Manifest schema this client consumes.
const MANIFEST_SCHEMA_VERSION: u32 = 2;
/// Index schema this client consumes.
const INDEX_SCHEMA_VERSION: u32 = 1;

/// Where a [`MacImageManager::pull_remote`] finds its manifest.
#[derive(Debug, Clone)]
pub enum RemoteSource {
    /// Resolve `stream[@version]` via the published index.
    Reference(ImageReference),
    /// Consume a manifest directly (URL or local path), bypassing the index.
    Manifest(RemoteLocation),
}

/// What a [`MacImageManager::resolve_remote`] found, without downloading.
///
/// The concrete version a pull of the same source would land, its
/// requirements, and what is currently installed under that stream name —
/// everything a caller needs to answer "is an update pending" and "does
/// this fit the host".
#[derive(Debug, Clone)]
pub struct ResolvedImage {
    /// Stream name (`tahoe-base`).
    pub name: String,
    /// Concrete version a pull would land (`2026.07.02`), even when the
    /// source reference floats.
    pub version: String,
    /// Guest macOS product version (e.g. `26.5`).
    pub os_version: String,
    /// Guest macOS build number, if published.
    pub os_build: Option<String>,
    /// Preinstalled GitHub Actions runner version, if published.
    pub runner_version: Option<String>,
    /// Minimum CPU count required by the guest.
    pub minimum_cpu_count: u64,
    /// Minimum guest memory in MiB required by the guest.
    pub minimum_memory_mib: u64,
    /// System disk size in GB (decimal, logical).
    pub disk_gb: u64,
    /// The version installed under this stream name locally, if any.
    pub installed_version: Option<String>,
}

/// The stage a [`MacImageManager::pull_remote`] is in, for progress reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullStage {
    /// Resolving the reference and fetching the manifest.
    Resolve,
    /// Validating host support against the manifest.
    Validate,
    /// Downloading and decompressing the system disk (the long stage).
    Disk,
    /// Downloading and decompressing the auxiliary storage.
    Aux,
    /// Final integrity checks and registry landing.
    Verify,
}

/// Decodes a base64 manifest field.
fn decode_field(field: &str, value: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(value)
        .map_err(|e| CoreError::macos(format!("manifest field '{field}' is not valid base64: {e}")))
}

/// Checks the manifest's hardware model against this host.
///
/// Kept synchronous and self-contained so the ObjC hardware-model object never
/// lives across an await point (which would make the pull future `!Send`).
fn validate_hardware_model(data: &[u8]) -> Result<()> {
    let model = arcbox_vz::MacHardwareModel::from_data(data)?;
    if !model.is_supported() {
        return Err(CoreError::macos(
            "this image's hardware model is not supported here (host macOS too old for the guest)",
        ));
    }
    Ok(())
}

/// Resolves `source` to the manifest a pull would consume: index resolution
/// (for a reference), then schema, disk-format, chunk-layout, and name-match
/// checks. Shared by [`MacImageManager::pull_remote`] and
/// [`MacImageManager::resolve_remote`], so "what resolve reported" and
/// "what pull lands" can never drift.
async fn resolve_source(source: &RemoteSource) -> Result<(RemoteLocation, ImageManifest)> {
    let manifest_location = match source {
        RemoteSource::Manifest(location) => location.clone(),
        RemoteSource::Reference(reference) => {
            let base = super::remote::image_base().as_dir();
            let index: RemoteIndex = base.join("index.json")?.fetch_json().await?;
            if index.schema_version != INDEX_SCHEMA_VERSION {
                return Err(CoreError::macos(format!(
                    "unsupported image index schema_version {}",
                    index.schema_version
                )));
            }
            let (_version, manifest_path) = index.resolve(reference)?;
            base.join(&manifest_path)?
        }
    };
    let manifest: ImageManifest = manifest_location.fetch_json().await?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(CoreError::macos(format!(
            "unsupported image manifest schema_version {}",
            manifest.schema_version
        )));
    }
    if manifest.disk.disk_format != "raw" {
        return Err(CoreError::macos(format!(
            "unsupported disk format '{}'",
            manifest.disk.disk_format
        )));
    }
    // The chunk list must exactly tile the declared disk size, so every
    // uncompressed byte is covered by exactly one chunk at a known offset.
    if manifest.disk.chunk_size == 0 || manifest.disk.chunks.is_empty() {
        return Err(CoreError::macos("manifest disk has no chunks"));
    }
    let expected_chunks = manifest
        .disk
        .uncompressed_size
        .div_ceil(manifest.disk.chunk_size);
    if manifest.disk.chunks.len() as u64 != expected_chunks {
        return Err(CoreError::macos(format!(
            "manifest lists {} disk chunks but {expected_chunks} are needed for {} bytes at chunk_size {}",
            manifest.disk.chunks.len(),
            manifest.disk.uncompressed_size,
            manifest.disk.chunk_size
        )));
    }
    // The name becomes a registry directory; reject anything that could escape it
    // (a `--manifest` source is not index-validated like a reference is).
    validate_name(&manifest.name)?;
    if let RemoteSource::Reference(reference) = source {
        if manifest.name != reference.stream {
            return Err(CoreError::macos(format!(
                "manifest name '{}' does not match requested stream '{}'",
                manifest.name, reference.stream
            )));
        }
    }
    Ok((manifest_location, manifest))
}

impl MacImageManager {
    /// Resolves `source` against the published index without downloading
    /// any artifact: the concrete version a pull would land, its
    /// requirements, and the locally installed version of the same stream.
    /// Also validates host support (hardware model), so a caller can reject
    /// an image this host cannot boot before committing to a pull.
    ///
    /// # Errors
    /// Returns an error if resolution fails (unknown stream/version,
    /// unreachable index, malformed manifest) or the image's hardware model
    /// is not supported on this host.
    pub async fn resolve_remote(&self, source: &RemoteSource) -> Result<ResolvedImage> {
        let (_, manifest) = resolve_source(source).await?;
        let hardware_model = decode_field("hardware_model", &manifest.hardware_model)?;
        validate_hardware_model(&hardware_model)?;
        let installed_version = self
            .get(&manifest.name)
            .ok()
            .and_then(|image| image.meta.version);
        Ok(ResolvedImage {
            name: manifest.name,
            version: manifest.version,
            os_version: manifest.os.product_version,
            os_build: (!manifest.os.build.is_empty()).then_some(manifest.os.build),
            runner_version: manifest.runner_version,
            minimum_cpu_count: manifest.minimum_cpu_count,
            minimum_memory_mib: manifest.minimum_memory_mib,
            disk_gb: manifest.disk.uncompressed_size / 1_000_000_000,
            installed_version,
        })
    }

    /// Pulls a published base image into the local registry.
    ///
    /// Validates host support from the manifest before downloading anything
    /// large, keeps the restored disk sparse, verifies every file against its
    /// manifest hash, and lands the image atomically (staging dir + rename).
    /// Re-pulling an already-present version is a no-op.
    ///
    /// # Errors
    /// Returns an error if resolution, validation, download, integrity
    /// verification, or the final registry landing fails.
    pub async fn pull_remote(
        &self,
        source: RemoteSource,
        mut on_progress: impl FnMut(PullStage, f64),
    ) -> Result<MacImage> {
        on_progress(PullStage::Resolve, 0.0);
        let (manifest_location, manifest) = resolve_source(&source).await?;
        on_progress(PullStage::Resolve, 1.0);

        // Serialize pulls of the same image: concurrent pulls would otherwise
        // share the `.pull-<name>` staging directory and corrupt each other's
        // download. A second pull waits here, then no-ops via the check below.
        let lock = self.pull_lock(&manifest.name).await;
        let _pull_guard = lock.lock().await;

        on_progress(PullStage::Validate, 0.0);
        let hardware_model = decode_field("hardware_model", &manifest.hardware_model)?;
        let machine_id = decode_field("machine_id", &manifest.machine_id)?;
        validate_hardware_model(&hardware_model)?;

        if let Ok(existing) = self.get(&manifest.name) {
            if existing.meta.version.as_deref() == Some(manifest.version.as_str()) {
                on_progress(PullStage::Verify, 1.0);
                return Ok(existing);
            }
        }
        on_progress(PullStage::Validate, 1.0);

        // Assemble in a staging directory; rename live only when complete. The
        // guard removes it on any early return — or if this future is dropped
        // (client cancellation) at any await point.
        let staging = self.image_dir(&format!(".pull-{}", manifest.name))?;
        if staging.exists() {
            std::fs::remove_dir_all(&staging)?;
        }
        std::fs::create_dir_all(&staging)?;
        let mut guard = StagingGuard::new(staging.clone());

        self.pull_into(&staging, &manifest_location, &manifest, &mut on_progress)
            .await?;

        std::fs::write(staging.join(HARDWARE_MODEL_FILE), &hardware_model)?;
        std::fs::write(staging.join(MACHINE_ID_FILE), &machine_id)?;
        Self::write_meta_in(&staging, &meta_from_manifest(&manifest, &manifest_location))?;

        on_progress(PullStage::Verify, 0.5);
        let final_dir = self.image_dir(&manifest.name)?;
        if final_dir.exists() {
            std::fs::remove_dir_all(&final_dir)?;
        }
        std::fs::rename(&staging, &final_dir)?;
        guard.disarm();
        on_progress(PullStage::Verify, 1.0);
        self.get(&manifest.name)
    }

    /// Downloads and verifies the disk and aux files into `staging`.
    async fn pull_into(
        &self,
        staging: &Path,
        manifest_location: &RemoteLocation,
        manifest: &ImageManifest,
        on_progress: &mut impl FnMut(PullStage, f64),
    ) -> Result<()> {
        on_progress(PullStage::Disk, 0.0);
        fetch_disk(
            manifest_location,
            &manifest.disk,
            &staging.join(DISK_FILE),
            |frac| on_progress(PullStage::Disk, frac),
        )
        .await?;

        on_progress(PullStage::Aux, 0.0);
        let aux_compressed = manifest_location
            .join(&manifest.aux.path)?
            .fetch_bytes()
            .await?;
        if aux_compressed.len() as u64 != manifest.aux.compressed_size {
            return Err(CoreError::macos(format!(
                "{}: expected {} compressed bytes, got {}",
                manifest.aux.path,
                manifest.aux.compressed_size,
                aux_compressed.len()
            )));
        }
        verify_sha256(
            &manifest.aux.path,
            &Sha256::digest(&aux_compressed),
            &manifest.aux.sha256,
        )?;
        let aux = zstd::decode_all(&aux_compressed[..])
            .map_err(|e| CoreError::macos(format!("decompress {}: {e}", manifest.aux.path)))?;
        if aux.len() as u64 != manifest.aux.uncompressed_size {
            return Err(CoreError::macos(format!(
                "{}: decompressed to {} bytes, manifest says {}",
                manifest.aux.path,
                aux.len(),
                manifest.aux.uncompressed_size
            )));
        }
        std::fs::write(staging.join(AUX_FILE), &aux)?;
        on_progress(PullStage::Aux, 1.0);
        Ok(())
    }
}

/// Builds the local registry metadata for a pulled manifest.
fn meta_from_manifest(manifest: &ImageManifest, location: &RemoteLocation) -> MacImageMeta {
    MacImageMeta {
        name: manifest.name.clone(),
        source: Some(location.to_string()),
        stream: Some(manifest.name.clone()),
        version: Some(manifest.version.clone()),
        os_version: Some(manifest.os.product_version.clone()),
        os_build: (!manifest.os.build.is_empty()).then(|| manifest.os.build.clone()),
        runner_version: manifest.runner_version.clone(),
        minimum_cpu_count: manifest.minimum_cpu_count,
        minimum_memory_mib: manifest.minimum_memory_mib,
        disk_gb: manifest.disk.uncompressed_size / 1_000_000_000,
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::disk::hex;
    use tempfile::tempdir;

    /// Real hardware-model data representation captured from a Tahoe base
    /// image (`config.json .hardwareModel`); decodes on any host, and
    /// `is_supported` is true on the Apple Silicon hosts tests run on.
    const REAL_HARDWARE_MODEL_B64: &str = "YnBsaXN0MDDTAQIDBAQFXxAZRGF0YVJlcHJlc2VudGF0aW9uVmVyc2lvbl8QD1BsYXRmb3JtVmVyc2lvbl8QEk1pbmltdW1TdXBwb3J0ZWRPUxACowYHBxANEAAIDys9UlRYWgAAAAAAAAEBAAAAAAAAAAgAAAAAAAAAAAAAAAAAAABc";
    const REAL_MACHINE_ID_B64: &str = "YnBsaXN0MDDRAQJURUNJRBQAAAAAAAAAAJzeRwpdz1o1CAsQAAAAAAAAAQEAAAAAAAAAAwAAAAAAAAAAAAAAAAAAACE=";

    /// Block granularity the sparse writer uses; test chunk sizes are multiples
    /// of it so chunk offsets stay block-aligned.
    const BLOCK: usize = 64 * 1024;

    /// Splits `raw` into `chunk_size` slices, writes each as a zstd-compressed
    /// `disk.NNN.zst` under `dir`, and returns the manifest `disk` object.
    fn publish_disk(dir: &Path, raw: &[u8], chunk_size: usize) -> serde_json::Value {
        let mut chunks = Vec::new();
        for (i, slice) in raw.chunks(chunk_size).enumerate() {
            let compressed = zstd::encode_all(slice, 3).unwrap();
            let path = format!("disk.{i:03}.zst");
            std::fs::write(dir.join(&path), &compressed).unwrap();
            chunks.push(serde_json::json!({
                "path": path,
                "size": compressed.len(),
                "sha256": hex(&Sha256::digest(&compressed)),
            }));
        }
        serde_json::json!({
            "disk_format": "raw",
            "uncompressed_size": raw.len(),
            "uncompressed_sha256": hex(&Sha256::digest(raw)),
            "chunk_size": chunk_size,
            "chunks": chunks,
        })
    }

    fn write_zstd(path: &Path, raw: &[u8]) -> (u64, String) {
        let compressed = zstd::encode_all(raw, 3).unwrap();
        std::fs::write(path, &compressed).unwrap();
        (compressed.len() as u64, hex(&Sha256::digest(&compressed)))
    }

    #[tokio::test]
    async fn pull_from_local_manifest_round_trips() {
        let images = tempdir().unwrap();
        let publish = tempdir().unwrap();

        // Synthetic sparse disk spanning several chunks, with a zero gap and a
        // partial last chunk: data, zeros, data (partial).
        let mut disk = vec![0u8; 5 * BLOCK];
        disk[0..BLOCK].fill(0xAB);
        disk[4 * BLOCK..].fill(0xCD);
        let disk_json = publish_disk(publish.path(), &disk, 2 * BLOCK);

        let aux = vec![0x5Au8; 8192];
        let (aux_csize, aux_sha) = write_zstd(&publish.path().join("aux.img.zst"), &aux);

        let manifest = serde_json::json!({
            "schema_version": 2,
            "name": "tahoe-base",
            "version": "2026.07.02",
            "variant": "base",
            "built_at": "2026-07-02T00:00:00Z",
            "source_image": "ghcr.io/cirruslabs/macos-tahoe-base@sha256:abc",
            "os": { "product_version": "26.5", "build": "25F71" },
            "runner_version": "2.334.0",
            "xcode": [],
            "hardware_model": REAL_HARDWARE_MODEL_B64,
            "machine_id": REAL_MACHINE_ID_B64,
            "minimum_cpu_count": 2,
            "minimum_memory_mib": 4096,
            "disk": disk_json,
            "aux": {
                "path": "aux.img.zst",
                "uncompressed_size": aux.len(),
                "compressed_size": aux_csize,
                "sha256": aux_sha
            }
        });
        let manifest_path = publish.path().join("manifest.json");
        std::fs::write(&manifest_path, manifest.to_string()).unwrap();

        let mgr = MacImageManager::new(images.path());
        let source = RemoteSource::Manifest(RemoteLocation::File(manifest_path.clone()));
        let image = mgr.pull_remote(source.clone(), |_, _| {}).await.unwrap();

        assert_eq!(image.meta.name, "tahoe-base");
        assert_eq!(image.meta.version.as_deref(), Some("2026.07.02"));
        assert_eq!(image.meta.os_version.as_deref(), Some("26.5"));
        assert_eq!(std::fs::read(image.disk_path()).unwrap(), disk);
        assert_eq!(std::fs::read(image.aux_path()).unwrap(), aux);
        assert!(image.hardware_model_path().exists());
        assert!(image.machine_id_path().exists());

        // Re-pull of the same version is a no-op (returns the existing image).
        let again = mgr.pull_remote(source, |_, _| {}).await.unwrap();
        assert_eq!(again.meta.created_at, image.meta.created_at);
    }

    #[tokio::test]
    async fn manifest_with_traversal_name_is_rejected() {
        let images = tempdir().unwrap();
        let publish = tempdir().unwrap();

        // A `--manifest` source is not index-validated, so a hostile name must be
        // rejected during resolution — before anything is downloaded or landed.
        // The disk is a minimal-but-valid layout so resolution reaches the name.
        let manifest = serde_json::json!({
            "schema_version": 2,
            "name": "../evil",
            "version": "2026.07.02",
            "os": { "product_version": "26.5" },
            "hardware_model": REAL_HARDWARE_MODEL_B64,
            "machine_id": REAL_MACHINE_ID_B64,
            "minimum_cpu_count": 2,
            "minimum_memory_mib": 4096,
            "disk": {
                "disk_format": "raw",
                "uncompressed_size": 1,
                "uncompressed_sha256": "00",
                "chunk_size": 1,
                "chunks": [{ "path": "disk.000.zst", "size": 1, "sha256": "00" }]
            },
            "aux": {
                "path": "aux.img.zst",
                "uncompressed_size": 1, "compressed_size": 1, "sha256": "00"
            }
        });
        let manifest_path = publish.path().join("manifest.json");
        std::fs::write(&manifest_path, manifest.to_string()).unwrap();

        let mgr = MacImageManager::new(images.path());
        let source = RemoteSource::Manifest(RemoteLocation::File(manifest_path));
        assert!(mgr.pull_remote(source.clone(), |_, _| {}).await.is_err());
        assert!(mgr.resolve_remote(&source).await.is_err());
    }

    #[tokio::test]
    async fn manifest_with_inconsistent_chunk_count_is_rejected() {
        let images = tempdir().unwrap();
        let publish = tempdir().unwrap();

        // Declares a 3-chunk disk but lists only one chunk.
        let manifest = serde_json::json!({
            "schema_version": 2,
            "name": "tahoe-base",
            "version": "2026.07.02",
            "os": { "product_version": "26.5" },
            "hardware_model": REAL_HARDWARE_MODEL_B64,
            "machine_id": REAL_MACHINE_ID_B64,
            "minimum_cpu_count": 2,
            "minimum_memory_mib": 4096,
            "disk": {
                "disk_format": "raw",
                "uncompressed_size": 3 * BLOCK,
                "uncompressed_sha256": "00",
                "chunk_size": BLOCK,
                "chunks": [{ "path": "disk.000.zst", "size": 1, "sha256": "00" }]
            },
            "aux": {
                "path": "aux.img.zst",
                "uncompressed_size": 1, "compressed_size": 1, "sha256": "00"
            }
        });
        let manifest_path = publish.path().join("manifest.json");
        std::fs::write(&manifest_path, manifest.to_string()).unwrap();

        let mgr = MacImageManager::new(images.path());
        let source = RemoteSource::Manifest(RemoteLocation::File(manifest_path));
        let err = mgr.resolve_remote(&source).await.unwrap_err();
        assert!(err.to_string().contains("disk chunks"), "{err}");
    }

    /// Resolve answers "what would land / what's installed" without
    /// touching the registry: nothing is downloaded or registered, and
    /// `installed_version` flips from `None` to the landed version once a
    /// pull actually runs.
    #[tokio::test]
    async fn resolve_reports_metadata_without_pulling() {
        let images = tempdir().unwrap();
        let publish = tempdir().unwrap();

        let disk = vec![0xABu8; BLOCK];
        let disk_json = publish_disk(publish.path(), &disk, BLOCK);
        let aux = vec![0x5Au8; 128];
        let (aux_csize, aux_sha) = write_zstd(&publish.path().join("aux.img.zst"), &aux);

        let manifest = serde_json::json!({
            "schema_version": 2,
            "name": "tahoe-base",
            "version": "2026.07.02",
            "os": { "product_version": "26.5", "build": "25F71" },
            "runner_version": "2.334.0",
            "hardware_model": REAL_HARDWARE_MODEL_B64,
            "machine_id": REAL_MACHINE_ID_B64,
            "minimum_cpu_count": 2,
            "minimum_memory_mib": 4096,
            "disk": disk_json,
            "aux": {
                "path": "aux.img.zst",
                "uncompressed_size": aux.len(),
                "compressed_size": aux_csize,
                "sha256": aux_sha
            }
        });
        let manifest_path = publish.path().join("manifest.json");
        std::fs::write(&manifest_path, manifest.to_string()).unwrap();

        let mgr = MacImageManager::new(images.path());
        let source = RemoteSource::Manifest(RemoteLocation::File(manifest_path));

        let resolved = mgr.resolve_remote(&source).await.unwrap();
        assert_eq!(resolved.name, "tahoe-base");
        assert_eq!(resolved.version, "2026.07.02");
        assert_eq!(resolved.os_version, "26.5");
        assert_eq!(resolved.os_build.as_deref(), Some("25F71"));
        assert_eq!(resolved.runner_version.as_deref(), Some("2.334.0"));
        assert_eq!(resolved.minimum_cpu_count, 2);
        assert_eq!(resolved.minimum_memory_mib, 4096);
        assert_eq!(resolved.installed_version, None);
        // Resolution must not have registered or staged anything.
        assert!(mgr.list().is_empty());

        mgr.pull_remote(source.clone(), |_, _| {}).await.unwrap();
        let resolved = mgr.resolve_remote(&source).await.unwrap();
        assert_eq!(resolved.installed_version.as_deref(), Some("2026.07.02"));
    }

    #[tokio::test]
    async fn pull_rejects_corrupted_disk() {
        let images = tempdir().unwrap();
        let publish = tempdir().unwrap();

        let disk = vec![0xABu8; BLOCK];
        let mut disk_json = publish_disk(publish.path(), &disk, BLOCK);
        // Corrupt the first chunk's expected hash: the download succeeds but
        // integrity verification must reject it.
        disk_json["chunks"][0]["sha256"] =
            serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        let aux = vec![0x5Au8; 128];
        let (aux_csize, aux_sha) = write_zstd(&publish.path().join("aux.img.zst"), &aux);

        let manifest = serde_json::json!({
            "schema_version": 2,
            "name": "tahoe-base",
            "version": "2026.07.02",
            "os": { "product_version": "26.5" },
            "hardware_model": REAL_HARDWARE_MODEL_B64,
            "machine_id": REAL_MACHINE_ID_B64,
            "minimum_cpu_count": 2,
            "minimum_memory_mib": 4096,
            "disk": disk_json,
            "aux": {
                "path": "aux.img.zst",
                "uncompressed_size": aux.len(),
                "compressed_size": aux_csize,
                "sha256": aux_sha
            }
        });
        let manifest_path = publish.path().join("manifest.json");
        std::fs::write(&manifest_path, manifest.to_string()).unwrap();

        let mgr = MacImageManager::new(images.path());
        let err = mgr
            .pull_remote(
                RemoteSource::Manifest(RemoteLocation::File(manifest_path)),
                |_, _| {},
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"), "{err}");
        // Nothing may be registered, and no staging debris may remain.
        assert!(mgr.get("tahoe-base").is_err());
        assert!(mgr.list().is_empty());
    }
}
