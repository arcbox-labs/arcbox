//! Remote macOS image distribution: the published per-version manifest format
//! and the base location of the `darwin/` namespace.
//!
//! The wire format is owned by the `macos-runner-image-builder` repo (the
//! producer); this module is the consuming side. The generic discovery shape
//! (index, references, fetchable locations) lives in [`crate::remote_image`]
//! and is shared with the Linux machine-image registry.

use serde::Deserialize;

pub use crate::remote_image::{ImageReference, RemoteIndex, RemoteLocation};

/// Default base location of the published image index: the `darwin/` platform
/// namespace at the CDN root (the `arcboxcdn-image` bucket fronted by
/// `image.arcboxcdn.com`). `index.json` and every manifest resolve relative
/// to this, so the namespace can move or gain a vanity domain without touching
/// any published file.
///
/// Overridable with the `ARCBOX_MACOS_IMAGE_BASE` environment variable.
pub const DEFAULT_IMAGE_BASE: &str = "https://image.arcboxcdn.com/darwin";

/// Environment variable overriding [`DEFAULT_IMAGE_BASE`].
pub const IMAGE_BASE_ENV: &str = "ARCBOX_MACOS_IMAGE_BASE";

/// Returns the effective image base location (env override or default).
#[must_use]
pub fn image_base() -> RemoteLocation {
    let base = std::env::var(IMAGE_BASE_ENV).unwrap_or_else(|_| DEFAULT_IMAGE_BASE.to_string());
    RemoteLocation::parse(&base)
}

/// A published image manifest (one immutable version of a stream).
#[derive(Debug, Deserialize)]
pub struct ImageManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Stream name.
    pub name: String,
    /// Version label (`YYYY.MM.DD[.N]`).
    pub version: String,
    /// Variant (`base` / `full`).
    #[serde(default)]
    #[allow(dead_code, reason = "published schema field; not yet surfaced locally")]
    pub variant: String,
    /// Guest OS identity.
    pub os: OsInfo,
    /// Preinstalled GitHub Actions runner version, if any.
    #[serde(default)]
    pub runner_version: Option<String>,
    /// Preinstalled Xcode versions (empty for base images).
    #[serde(default)]
    #[allow(dead_code, reason = "published schema field; not yet surfaced locally")]
    pub xcode: Vec<String>,
    /// VZ hardware-model `dataRepresentation`, base64.
    pub hardware_model: String,
    /// VZ machine-identifier `dataRepresentation`, base64.
    pub machine_id: String,
    /// Minimum CPU count required by the guest.
    pub minimum_cpu_count: u64,
    /// Minimum guest memory in MiB.
    pub minimum_memory_mib: u64,
    /// The compressed, chunked system disk.
    pub disk: DiskManifest,
    /// The compressed auxiliary (NVRAM) storage.
    pub aux: RemoteFile,
}

/// Guest OS identity in a manifest.
#[derive(Debug, Deserialize)]
pub struct OsInfo {
    /// macOS product version, e.g. `26.5`.
    pub product_version: String,
    /// macOS build number, e.g. `25F71`.
    #[serde(default)]
    pub build: String,
}

/// A compressed file entry in a manifest.
#[derive(Debug, Deserialize)]
pub struct RemoteFile {
    /// File name relative to the manifest's directory.
    pub path: String,
    /// Decompressed size in bytes.
    pub uncompressed_size: u64,
    /// Compressed (stored) size in bytes.
    pub compressed_size: u64,
    /// Hex SHA-256 of the compressed bytes.
    pub sha256: String,
}

/// The system disk in a manifest: split at fixed `chunk_size` offsets into
/// independently decompressible zstd frames. Chunk `i` covers uncompressed
/// bytes `[i * chunk_size, (i + 1) * chunk_size)`; the last chunk holds the
/// remainder. Splitting keeps every stored object under the CDN's cacheable
/// size limit and lets the client fetch, verify, and sparse-write chunks in
/// parallel.
///
/// Integrity model: each chunk is verified against its own compressed
/// SHA-256 before it is decoded, and placed at the offset given by its array
/// index — so the assembled disk is correct without re-reading the multi-GB
/// result. This trusts the producer to emit chunks in offset order (they are:
/// `disk.000.zst`, `disk.001.zst`, …). The manifest also carries a whole-disk
/// `uncompressed_sha256` for out-of-band/publisher-side auditing; the client
/// does not consume it (a client-side re-read would defeat the streaming
/// design).
#[derive(Debug, Deserialize)]
pub struct DiskManifest {
    /// Raw disk image format (currently always `raw`).
    pub disk_format: String,
    /// Decompressed size of the assembled disk, in bytes.
    pub uncompressed_size: u64,
    /// Uncompressed run length each non-final chunk decompresses to.
    pub chunk_size: u64,
    /// Ordered chunks; each an independent zstd frame.
    pub chunks: Vec<DiskChunk>,
}

/// One compressed disk chunk, stored as its own object next to the manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct DiskChunk {
    /// File name relative to the manifest's directory (`disk.NNN.zst`).
    pub path: String,
    /// Compressed (stored) size in bytes.
    pub size: u64,
    /// Hex SHA-256 of the compressed bytes.
    pub sha256: String,
}
