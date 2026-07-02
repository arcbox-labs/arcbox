//! Pulling published macOS base images into the local registry.
//!
//! [`MacImageManager::pull_remote`] resolves a reference against the published
//! index (or consumes a manifest directly), validates host support *before*
//! the multi-gigabyte download, then streams the zstd-compressed disk through
//! decompression into a sparse `disk.img` — the compressed bytes never touch
//! disk. The image is assembled in a staging directory and renamed live only
//! after every integrity check passes, so a failed pull never leaves a broken
//! registry entry.

use std::io::Write;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::image::{
    AUX_FILE, DISK_FILE, HARDWARE_MODEL_FILE, MACHINE_ID_FILE, MacImage, MacImageManager,
    MacImageMeta,
};
use super::remote::{ImageManifest, ImageReference, RemoteFile, RemoteIndex, RemoteLocation};
use crate::error::{CoreError, Result};

/// Where a [`MacImageManager::pull_remote`] finds its manifest.
#[derive(Debug, Clone)]
pub enum RemoteSource {
    /// Resolve `stream[@version]` via the published index.
    Reference(ImageReference),
    /// Consume a manifest directly (URL or local path), bypassing the index.
    Manifest(RemoteLocation),
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

/// Zero-skipping block writer: keeps `disk.img` sparse by never writing
/// all-zero blocks (the file is pre-sized, so skipped ranges become holes).
///
/// Alignment comes from buffering to fixed-size blocks; `flush` deliberately
/// does not drain a partial block (the decompressor flushes mid-stream), the
/// tail is written by [`SparseWriter::finish`].
struct SparseWriter {
    file: std::fs::File,
    offset: u64,
    buf: Vec<u8>,
}

/// Block granularity for zero detection; a multiple of the APFS block size.
const SPARSE_BLOCK: usize = 64 * 1024;
static ZERO_BLOCK: [u8; SPARSE_BLOCK] = [0u8; SPARSE_BLOCK];

impl SparseWriter {
    fn new(file: std::fs::File) -> Self {
        Self {
            file,
            offset: 0,
            buf: Vec::with_capacity(SPARSE_BLOCK),
        }
    }

    fn flush_block(&mut self) -> std::io::Result<()> {
        // Slice equality is a memcmp — much faster than a per-byte scan.
        if self.buf.as_slice() != &ZERO_BLOCK[..self.buf.len()] {
            use std::os::unix::fs::FileExt;
            self.file.write_all_at(&self.buf, self.offset)?;
        }
        self.offset += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }

    /// Drains the partial tail block and returns the total bytes written.
    fn finish(mut self) -> std::io::Result<u64> {
        if !self.buf.is_empty() {
            self.flush_block()?;
        }
        self.file.flush()?;
        Ok(self.offset)
    }
}

impl Write for SparseWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let take = (SPARSE_BLOCK - self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..take]);
        if self.buf.len() == SPARSE_BLOCK {
            self.flush_block()?;
        }
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

/// Verifies a hex SHA-256 against an expected manifest value.
fn verify_sha256(what: &str, actual: &[u8], expected: &str) -> Result<()> {
    let actual = hex(actual);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(CoreError::macos(format!(
            "{what}: checksum mismatch (expected {expected}, got {actual})"
        )));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Streams a compressed file from `location`, decompressing into a sparse,
/// pre-sized `dst`. Verifies compressed size, SHA-256, and decompressed size
/// against `spec`. `on_progress` receives the downloaded fraction.
async fn fetch_zstd_to_sparse(
    location: &RemoteLocation,
    spec: &RemoteFile,
    dst: &Path,
    mut on_progress: impl FnMut(f64),
) -> Result<()> {
    let file = std::fs::File::create(dst)?;
    file.set_len(spec.uncompressed_size)?;
    let mut decoder = zstd::stream::write::Decoder::new(SparseWriter::new(file))
        .map_err(|e| CoreError::macos(format!("zstd init: {e}")))?;

    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut consume = |bytes: &[u8]| -> Result<()> {
        hasher.update(bytes);
        decoder
            .write_all(bytes)
            .map_err(|e| CoreError::macos(format!("decompress {}: {e}", spec.path)))?;
        received += bytes.len() as u64;
        if spec.compressed_size > 0 {
            on_progress((received as f64 / spec.compressed_size as f64).min(1.0));
        }
        Ok(())
    };

    match location {
        RemoteLocation::Http(url) => {
            let mut resp = reqwest::get(url.clone())
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|e| CoreError::macos(format!("download {url}: {e}")))?;
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| CoreError::macos(format!("download {url}: {e}")))?
            {
                consume(&chunk)?;
            }
        }
        RemoteLocation::File(path) => {
            use std::io::Read;
            let mut src = std::fs::File::open(path)?;
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                let n = src.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                consume(&buf[..n])?;
            }
        }
    }

    decoder
        .flush()
        .map_err(|e| CoreError::macos(format!("decompress {}: {e}", spec.path)))?;
    let written = decoder
        .into_inner()
        .finish()
        .map_err(|e| CoreError::macos(format!("finalize {}: {e}", dst.display())))?;

    if received != spec.compressed_size {
        return Err(CoreError::macos(format!(
            "{}: truncated download (expected {} compressed bytes, got {received})",
            spec.path, spec.compressed_size
        )));
    }
    verify_sha256(&spec.path, &hasher.finalize(), &spec.sha256)?;
    if written != spec.uncompressed_size {
        return Err(CoreError::macos(format!(
            "{}: decompressed to {written} bytes, manifest says {}",
            spec.path, spec.uncompressed_size
        )));
    }
    Ok(())
}

impl MacImageManager {
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
        let manifest_location = match &source {
            RemoteSource::Manifest(location) => location.clone(),
            RemoteSource::Reference(reference) => {
                let base = super::remote::image_base().as_dir();
                let index: RemoteIndex = base.join("index.json")?.fetch_json().await?;
                if index.schema_version != 1 {
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
        if manifest.schema_version != 1 {
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
        if let RemoteSource::Reference(reference) = &source {
            if manifest.name != reference.stream {
                return Err(CoreError::macos(format!(
                    "manifest name '{}' does not match requested stream '{}'",
                    manifest.name, reference.stream
                )));
            }
        }
        on_progress(PullStage::Resolve, 1.0);

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

        // Assemble in a staging directory; rename live only when complete.
        let staging = self.image_dir(&format!(".pull-{}", manifest.name));
        if staging.exists() {
            std::fs::remove_dir_all(&staging)?;
        }
        std::fs::create_dir_all(&staging)?;

        let result = self
            .pull_into(&staging, &manifest_location, &manifest, &mut on_progress)
            .await;
        if let Err(e) = result {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }

        std::fs::write(staging.join(HARDWARE_MODEL_FILE), &hardware_model)?;
        std::fs::write(staging.join(MACHINE_ID_FILE), &machine_id)?;
        Self::write_meta_in(&staging, &meta_from_manifest(&manifest, &manifest_location))?;

        on_progress(PullStage::Verify, 0.5);
        let final_dir = self.image_dir(&manifest.name);
        if final_dir.exists() {
            std::fs::remove_dir_all(&final_dir)?;
        }
        std::fs::rename(&staging, &final_dir)?;
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
        fetch_zstd_to_sparse(
            &manifest_location.join(&manifest.disk.file.path)?,
            &manifest.disk.file,
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
        disk_gb: manifest.disk.file.uncompressed_size / 1_000_000_000,
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::tempdir;

    /// Real hardware-model data representation captured from a Tahoe base
    /// image (`config.json .hardwareModel`); decodes on any host, and
    /// `is_supported` is true on the Apple Silicon hosts tests run on.
    const REAL_HARDWARE_MODEL_B64: &str = "YnBsaXN0MDDTAQIDBAQFXxAZRGF0YVJlcHJlc2VudGF0aW9uVmVyc2lvbl8QD1BsYXRmb3JtVmVyc2lvbl8QEk1pbmltdW1TdXBwb3J0ZWRPUxACowYHBxANEAAIDys9UlRYWgAAAAAAAAEBAAAAAAAAAAgAAAAAAAAAAAAAAAAAAABc";
    const REAL_MACHINE_ID_B64: &str = "YnBsaXN0MDDRAQJURUNJRBQAAAAAAAAAAJzeRwpdz1o1CAsQAAAAAAAAAQEAAAAAAAAAAwAAAAAAAAAAAAAAAAAAACE=";

    fn write_zstd(path: &Path, raw: &[u8]) -> (u64, String) {
        let compressed = zstd::encode_all(raw, 3).unwrap();
        std::fs::write(path, &compressed).unwrap();
        (compressed.len() as u64, hex(&Sha256::digest(&compressed)))
    }

    #[test]
    fn sparse_writer_skips_zero_blocks() {
        // APFS only keeps holes in files above a size threshold (verified
        // empirically: fully materialized at 16 MiB, sparse at 256 MiB), so
        // this test must run at realistic scale. Data is streamed block-wise
        // to keep the test memory-light.
        const TOTAL: u64 = 256 * 1024 * 1024;
        let dir = tempdir().unwrap();
        let path = dir.path().join("sparse.bin");

        let file = std::fs::File::create(&path).unwrap();
        file.set_len(TOTAL).unwrap();
        let mut w = SparseWriter::new(file);
        let data = vec![7u8; SPARSE_BLOCK];
        let zeros = vec![0u8; SPARSE_BLOCK];
        let blocks = TOTAL / SPARSE_BLOCK as u64;
        for i in 0..blocks {
            // Non-zero first and last blocks, zeros everywhere between.
            if i == 0 || i == blocks - 1 {
                w.write_all(&data).unwrap();
            } else {
                w.write_all(&zeros).unwrap();
            }
        }
        assert_eq!(w.finish().unwrap(), TOTAL);

        // Content: first/last blocks hold data, an interior block reads zero.
        use std::os::unix::fs::FileExt;
        let f = std::fs::File::open(&path).unwrap();
        let mut buf = vec![0u8; SPARSE_BLOCK];
        f.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(buf, data);
        f.read_exact_at(&mut buf, TOTAL - SPARSE_BLOCK as u64)
            .unwrap();
        assert_eq!(buf, data);
        f.read_exact_at(&mut buf, TOTAL / 2).unwrap();
        assert_eq!(buf, zeros);

        // Allocation: the zero interior must be holes, not written blocks.
        let allocated = std::fs::metadata(&path)
            .map(|m| std::os::unix::fs::MetadataExt::blocks(&m) * 512)
            .unwrap();
        assert!(
            allocated < 8 * 1024 * 1024,
            "expected sparse file, got {allocated} bytes allocated for {TOTAL}"
        );
    }

    #[tokio::test]
    async fn pull_from_local_manifest_round_trips() {
        let images = tempdir().unwrap();
        let publish = tempdir().unwrap();

        // Synthetic sparse disk: data, a zero gap, more data.
        let mut disk = vec![0u8; 4 * SPARSE_BLOCK];
        disk[0..SPARSE_BLOCK].fill(0xAB);
        disk[3 * SPARSE_BLOCK..].fill(0xCD);
        let (disk_csize, disk_sha) = write_zstd(&publish.path().join("disk.img.zst"), &disk);

        let aux = vec![0x5Au8; 8192];
        let (aux_csize, aux_sha) = write_zstd(&publish.path().join("aux.img.zst"), &aux);

        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": "tahoe-base",
            "version": "2026.07.02",
            "variant": "base",
            "built_at": "2026-07-02T00:00:00Z",
            "os": { "product_version": "26.5", "build": "25F71" },
            "runner_version": "2.334.0",
            "xcode": [],
            "hardware_model": REAL_HARDWARE_MODEL_B64,
            "machine_id": REAL_MACHINE_ID_B64,
            "minimum_cpu_count": 2,
            "minimum_memory_mib": 4096,
            "disk": {
                "path": "disk.img.zst",
                "disk_format": "raw",
                "uncompressed_size": disk.len(),
                "compressed_size": disk_csize,
                "sha256": disk_sha
            },
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
    async fn pull_rejects_corrupted_disk() {
        let images = tempdir().unwrap();
        let publish = tempdir().unwrap();

        let disk = vec![0xABu8; SPARSE_BLOCK];
        let (disk_csize, _) = write_zstd(&publish.path().join("disk.img.zst"), &disk);
        let aux = vec![0x5Au8; 128];
        let (aux_csize, aux_sha) = write_zstd(&publish.path().join("aux.img.zst"), &aux);

        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": "tahoe-base",
            "version": "2026.07.02",
            "os": { "product_version": "26.5" },
            "hardware_model": REAL_HARDWARE_MODEL_B64,
            "machine_id": REAL_MACHINE_ID_B64,
            "minimum_cpu_count": 2,
            "minimum_memory_mib": 4096,
            "disk": {
                "path": "disk.img.zst",
                "disk_format": "raw",
                "uncompressed_size": disk.len(),
                "compressed_size": disk_csize,
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            },
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
