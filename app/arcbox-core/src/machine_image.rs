//! Linux machine image registry: pulling published distro rootfs images.
//!
//! Machines boot the ArcBox kernel with a distro rootfs image published on
//! the `linux/` namespace of `image.arcboxcdn.com` (produced by the
//! `arcboxlabs/machine-images` mirror of images.linuxcontainers.org).
//! [`MachineImageManager::pull`] resolves a selector against the published
//! index, downloads the rootfs with streaming SHA-256 verification into a
//! staging directory, and renames it into the local registry only after the
//! digest checks out — a failed pull never leaves a broken entry.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};
use crate::remote_image::{ImageReference, RemoteLocation, StagingGuard, validate_name};

/// Default base location of the published image index (the `linux/` namespace
/// at the CDN root). Overridable with the `ARCBOX_MACHINE_IMAGE_BASE`
/// environment variable.
pub const DEFAULT_IMAGE_BASE: &str = "https://image.arcboxcdn.com/linux";

/// Environment variable overriding [`DEFAULT_IMAGE_BASE`].
pub const IMAGE_BASE_ENV: &str = "ARCBOX_MACHINE_IMAGE_BASE";

/// Index schema this client consumes.
const INDEX_SCHEMA_VERSION: u32 = 1;
/// Manifest schema this client consumes.
const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Local registry file holding the pulled manifest.
const MANIFEST_FILE: &str = "manifest.json";

/// Returns the effective image base location (env override or default).
#[must_use]
pub fn image_base() -> RemoteLocation {
    let base = std::env::var(IMAGE_BASE_ENV).unwrap_or_else(|_| DEFAULT_IMAGE_BASE.to_string());
    RemoteLocation::parse(&base)
}

/// Maps a host/CLI architecture name onto the published image arch naming
/// (`aarch64` → `arm64`, `x86_64` → `amd64`); already-mapped names pass
/// through.
#[must_use]
pub fn image_arch(arch: &str) -> &str {
    match arch {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

/// The published image arch for this host.
#[must_use]
pub fn host_image_arch() -> &'static str {
    image_arch(std::env::consts::ARCH)
}

/// The published discovery index of the `linux/` namespace.
///
/// Same shape as [`crate::remote_image::RemoteIndex`], plus per-stream
/// denormalized identity fields so a distro/release/arch selector can resolve
/// without fetching any manifest.
#[derive(Debug, Deserialize)]
pub struct MachineImageIndex {
    /// Index schema version.
    pub schema_version: u32,
    /// Streams by name (`{distro}-{release}-{arch}`).
    pub images: HashMap<String, MachineImageStream>,
}

/// One image stream in the index.
#[derive(Debug, Deserialize)]
pub struct MachineImageStream {
    /// Distro id (`ubuntu`).
    pub distro: String,
    /// Distro release (`noble`).
    pub release: String,
    /// Human-readable release title (`24.04`); absent on indexes published
    /// before the field existed.
    #[serde(default)]
    pub release_title: Option<String>,
    /// Image architecture (`arm64` / `amd64`).
    pub arch: String,
    /// Image variant (`default`).
    pub variant: String,
    /// The version a floating pull resolves to.
    pub latest: String,
    /// All retained versions.
    pub versions: HashMap<String, MachineImageIndexEntry>,
}

/// One published version of a stream.
#[derive(Debug, Deserialize)]
pub struct MachineImageIndexEntry {
    /// Manifest path relative to the index location.
    pub manifest: String,
}

/// A published machine image manifest (one immutable version of a stream).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineImageManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Stream name.
    pub name: String,
    /// Version label (normalized upstream build stamp).
    pub version: String,
    /// Distro id (`ubuntu`).
    pub distro: String,
    /// Distro release (`noble`).
    pub release: String,
    /// Human-readable release title (`24.04`).
    pub release_title: String,
    /// Image architecture (`arm64` / `amd64`).
    pub arch: String,
    /// Image variant (`default`).
    pub variant: String,
    /// Provenance: where the mirror sourced this build.
    pub upstream: UpstreamRef,
    /// The rootfs image, stored next to the manifest.
    pub rootfs: RootfsFile,
}

/// Provenance of a mirrored build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamRef {
    /// Upstream server (`https://images.linuxcontainers.org`).
    pub server: String,
    /// Upstream product key (`distro:release:arch:variant`).
    pub product: String,
    /// Verbatim upstream build stamp.
    pub version: String,
}

/// A rootfs file entry in a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootfsFile {
    /// File name relative to the manifest's directory.
    pub path: String,
    /// Image format (`squashfs`).
    pub format: String,
    /// Size in bytes.
    pub size: u64,
    /// Hex SHA-256 of the file.
    pub sha256: String,
}

/// How a pull selects its image.
#[derive(Debug, Clone)]
pub enum ImageSelector {
    /// `stream[@version]`, e.g. `ubuntu-noble-arm64@20260716_0947`.
    Reference(ImageReference),
    /// Resolve by identity fields against the index.
    Distro {
        /// Distro id (`ubuntu`).
        distro: String,
        /// Release; `None` is allowed only when the distro+arch has exactly
        /// one published release.
        release: Option<String>,
        /// Published image arch (`arm64` / `amd64`).
        arch: String,
    },
}

/// A locally registered machine image.
#[derive(Debug, Clone)]
pub struct MachineImage {
    /// Registry directory holding the manifest and rootfs.
    pub dir: PathBuf,
    /// The pulled manifest.
    pub manifest: MachineImageManifest,
}

impl MachineImage {
    /// Absolute path of the rootfs image file.
    #[must_use]
    pub fn rootfs_path(&self) -> PathBuf {
        self.dir.join(&self.manifest.rootfs.path)
    }
}

/// Local registry of pulled machine images
/// (`<data_dir>/machine-images/<stream>/<version>/`).
pub struct MachineImageManager {
    images_dir: PathBuf,
    /// Published index base location this manager resolves against.
    base: RemoteLocation,
    /// Per-stream locks serializing concurrent pulls of the same stream so
    /// they cannot corrupt the shared staging directory. Bounded by the
    /// number of distinct streams ever pulled.
    pull_locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl MachineImageManager {
    /// Creates a manager rooted at `<data_dir>/machine-images`, resolving
    /// against [`image_base`].
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self::with_base(data_dir, image_base())
    }

    /// Creates a manager resolving against an explicit base location
    /// (tests, mirrors).
    #[must_use]
    pub fn with_base(data_dir: &Path, base: RemoteLocation) -> Self {
        Self {
            images_dir: data_dir.join("machine-images"),
            base,
            pull_locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns a locally registered image, if fully present.
    ///
    /// # Errors
    /// Returns a not-found error when the image is absent or incomplete.
    pub fn get(&self, stream: &str, version: &str) -> Result<MachineImage> {
        validate_name(stream)?;
        validate_name(version)?;
        let dir = self.images_dir.join(stream).join(version);
        let manifest_path = dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(CoreError::not_found(format!(
                "machine image {stream}@{version}"
            )));
        }
        let manifest: MachineImageManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)
                .map_err(|e| CoreError::image(format!("parse {}: {e}", manifest_path.display())))?;
        let image = MachineImage { dir, manifest };
        if !image.rootfs_path().exists() {
            return Err(CoreError::not_found(format!(
                "machine image {stream}@{version} (rootfs missing)"
            )));
        }
        Ok(image)
    }

    /// Lists all locally registered images.
    #[must_use]
    pub fn list(&self) -> Vec<MachineImage> {
        let mut images = Vec::new();
        let Ok(streams) = std::fs::read_dir(&self.images_dir) else {
            return images;
        };
        for stream in streams.flatten() {
            let stream_name = stream.file_name().to_string_lossy().into_owned();
            if stream_name.starts_with('.') {
                continue; // staging directories
            }
            let Ok(versions) = std::fs::read_dir(stream.path()) else {
                continue;
            };
            for version in versions.flatten() {
                let version_name = version.file_name().to_string_lossy().into_owned();
                if let Ok(image) = self.get(&stream_name, &version_name) {
                    images.push(image);
                }
            }
        }
        images
    }

    /// Pulls a published machine image into the local registry.
    ///
    /// Resolves `selector` against the published index, verifies the rootfs
    /// against its manifest hash while streaming it to disk, and lands the
    /// image atomically (staging dir + rename). Re-pulling an already-present
    /// version is a no-op. `on_progress` receives `(downloaded, total)` bytes.
    ///
    /// # Errors
    /// Returns an error if resolution, download, integrity verification, or
    /// the final registry landing fails.
    pub async fn pull(
        &self,
        selector: &ImageSelector,
        mut on_progress: impl FnMut(u64, u64),
    ) -> Result<MachineImage> {
        let (manifest_location, manifest) = self.resolve(selector).await?;

        // Serialize pulls of the same stream: concurrent pulls would otherwise
        // share the staging directory and corrupt each other's download.
        let lock = self.pull_lock(&manifest.name);
        let _pull_guard = lock.lock().await;

        if let Ok(existing) = self.get(&manifest.name, &manifest.version) {
            on_progress(existing.manifest.rootfs.size, existing.manifest.rootfs.size);
            return Ok(existing);
        }

        // Assemble in a staging directory; rename live only when complete. The
        // guard removes it on any early return — or if this future is dropped
        // (client cancellation) at any await point.
        let staging = self
            .images_dir
            .join(format!(".pull-{}-{}", manifest.name, manifest.version));
        if staging.exists() {
            std::fs::remove_dir_all(&staging)?;
        }
        std::fs::create_dir_all(&staging)?;
        let mut guard = StagingGuard::new(staging.clone());

        let rootfs_location = manifest_location.join(&manifest.rootfs.path)?;
        fetch_rootfs(
            &rootfs_location,
            &manifest.rootfs,
            &staging.join(&manifest.rootfs.path),
            &mut on_progress,
        )
        .await?;

        let mut manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| CoreError::image(format!("serialize manifest: {e}")))?;
        manifest_json.push('\n');
        std::fs::write(staging.join(MANIFEST_FILE), manifest_json)?;

        let final_dir = self.images_dir.join(&manifest.name).join(&manifest.version);
        if let Some(parent) = final_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if final_dir.exists() {
            std::fs::remove_dir_all(&final_dir)?;
        }
        std::fs::rename(&staging, &final_dir)?;
        guard.disarm();
        self.get(&manifest.name, &manifest.version)
    }

    /// Resolves `selector` to the manifest a pull would consume, validating
    /// schema versions and that the manifest's identity matches the request.
    ///
    /// # Errors
    /// Returns an error on fetch failure, schema mismatch, or when the
    /// selector matches no (or more than one) published stream.
    pub async fn resolve(
        &self,
        selector: &ImageSelector,
    ) -> Result<(RemoteLocation, MachineImageManifest)> {
        let base = self.base.as_dir();
        let index: MachineImageIndex = base.join("index.json")?.fetch_json().await?;
        if index.schema_version != INDEX_SCHEMA_VERSION {
            return Err(CoreError::image(format!(
                "unsupported image index schema_version {}",
                index.schema_version
            )));
        }

        let (stream_name, stream, version) = match selector {
            ImageSelector::Reference(reference) => {
                let stream = index.images.get(&reference.stream).ok_or_else(|| {
                    CoreError::not_found(format!("image stream '{}'", reference.stream))
                })?;
                let version = reference
                    .version
                    .clone()
                    .unwrap_or_else(|| stream.latest.clone());
                (reference.stream.clone(), stream, version)
            }
            ImageSelector::Distro {
                distro,
                release,
                arch,
            } => {
                let mut matches: Vec<(&String, &MachineImageStream)> = index
                    .images
                    .iter()
                    .filter(|(_, s)| {
                        s.distro == *distro
                            && s.arch == *arch
                            && s.variant == "default"
                            // Accept the codename (`noble`) or the
                            // user-facing title (`24.04`).
                            && release.as_ref().is_none_or(|r| {
                                s.release == *r || s.release_title.as_deref() == Some(r)
                            })
                    })
                    .collect();
                matches.sort_by_key(|(name, _)| (*name).clone());
                match matches.as_slice() {
                    [] => {
                        let mut releases: Vec<&str> = index
                            .images
                            .values()
                            .filter(|s| s.distro == *distro && s.arch == *arch)
                            .map(|s| s.release.as_str())
                            .collect();
                        releases.sort_unstable();
                        return Err(CoreError::not_found(if releases.is_empty() {
                            format!("no published image for distro '{distro}' on {arch}")
                        } else {
                            format!(
                                "no published image for distro '{distro}' release \
                                 {release:?} on {arch}; available releases: {}",
                                releases.join(", ")
                            )
                        }));
                    }
                    [(name, stream)] => ((*name).clone(), *stream, stream.latest.clone()),
                    multiple => {
                        let releases: Vec<&str> =
                            multiple.iter().map(|(_, s)| s.release.as_str()).collect();
                        return Err(CoreError::image(format!(
                            "distro '{distro}' has multiple releases on {arch} \
                             ({}); specify one",
                            releases.join(", ")
                        )));
                    }
                }
            }
        };

        let entry = stream.versions.get(&version).ok_or_else(|| {
            CoreError::not_found(format!("machine image '{stream_name}@{version}'"))
        })?;
        let manifest_location = base.join(&entry.manifest)?;
        let manifest: MachineImageManifest = manifest_location.fetch_json().await?;
        if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(CoreError::image(format!(
                "unsupported image manifest schema_version {}",
                manifest.schema_version
            )));
        }
        // Names become registry directories; the manifest must identify as
        // what the index said it was.
        validate_name(&manifest.name)?;
        validate_name(&manifest.version)?;
        validate_name(&manifest.rootfs.path)?;
        if manifest.name != stream_name || manifest.version != version {
            return Err(CoreError::image(format!(
                "manifest identifies as {}@{}, expected {stream_name}@{version}",
                manifest.name, manifest.version
            )));
        }
        Ok((manifest_location, manifest))
    }

    fn pull_lock(&self, stream: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.pull_locks.lock().expect("pull lock map poisoned");
        Arc::clone(locks.entry(stream.to_string()).or_default())
    }
}

/// Downloads the rootfs to `dst`, streaming through SHA-256. `dst` may hold a
/// partial file on error; the caller stages it under a [`StagingGuard`], which
/// removes the whole staging directory on failure.
async fn fetch_rootfs(
    location: &RemoteLocation,
    rootfs: &RootfsFile,
    dst: &Path,
    on_progress: &mut impl FnMut(u64, u64),
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    let mut file = tokio::fs::File::create(dst).await?;

    match location {
        RemoteLocation::Http(url) => {
            let mut resp = reqwest::get(url.clone())
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|e| CoreError::image(format!("download {url}: {e}")))?;
            on_progress(0, rootfs.size);
            while let Some(bytes) = resp
                .chunk()
                .await
                .map_err(|e| CoreError::image(format!("download {url}: {e}")))?
            {
                written += bytes.len() as u64;
                if written > rootfs.size {
                    return Err(CoreError::image(format!(
                        "{}: response exceeds manifest size {}",
                        rootfs.path, rootfs.size
                    )));
                }
                hasher.update(&bytes);
                file.write_all(&bytes).await?;
                on_progress(written, rootfs.size);
            }
        }
        RemoteLocation::File(path) => {
            let bytes = tokio::fs::read(path).await?;
            written = bytes.len() as u64;
            hasher.update(&bytes);
            file.write_all(&bytes).await?;
            on_progress(written, rootfs.size);
        }
    }
    file.flush().await?;
    drop(file);

    let digest = format!("{:x}", hasher.finalize());
    if written != rootfs.size || digest != rootfs.sha256 {
        return Err(CoreError::image(format!(
            "{}: expected {} bytes sha256:{}, got {written} bytes sha256:{digest}",
            rootfs.path, rootfs.size, rootfs.sha256
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Publishes a fake `linux/` namespace (index + one manifest + rootfs
    /// blob) under `dir` and returns the rootfs bytes.
    fn publish(dir: &Path, stream: &str, version: &str, body: &[u8]) -> Vec<u8> {
        let (distro, rest) = stream.split_once('-').unwrap();
        let (release, arch) = rest.rsplit_once('-').unwrap();
        let build_dir = dir.join(stream).join(version);
        std::fs::create_dir_all(&build_dir).unwrap();
        std::fs::write(build_dir.join("rootfs.squashfs"), body).unwrap();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": stream,
            "version": version,
            "distro": distro,
            "release": release,
            "release_title": release,
            "arch": arch,
            "variant": "default",
            "upstream": {
                "server": "https://images.linuxcontainers.org",
                "product": format!("{distro}:{release}:{arch}:default"),
                "version": "20260716_09:47"
            },
            "rootfs": {
                "path": "rootfs.squashfs",
                "format": "squashfs",
                "size": body.len(),
                "sha256": format!("{:x}", Sha256::digest(body)),
            }
        });
        std::fs::write(build_dir.join("manifest.json"), manifest.to_string()).unwrap();

        // (Re)build the index over everything published so far.
        let mut images = serde_json::Map::new();
        for stream_dir in std::fs::read_dir(dir).unwrap().flatten() {
            if !stream_dir.file_type().unwrap().is_dir() {
                continue;
            }
            let name = stream_dir.file_name().to_string_lossy().into_owned();
            let mut versions = serde_json::Map::new();
            let mut latest = String::new();
            for v in std::fs::read_dir(stream_dir.path()).unwrap().flatten() {
                let vname = v.file_name().to_string_lossy().into_owned();
                if vname > latest {
                    latest.clone_from(&vname);
                }
                versions.insert(
                    vname.clone(),
                    serde_json::json!({ "manifest": format!("{name}/{vname}/manifest.json") }),
                );
            }
            let (d, rest) = name.split_once('-').unwrap();
            let (r, a) = rest.rsplit_once('-').unwrap();
            images.insert(
                name.clone(),
                serde_json::json!({
                    "distro": d, "release": r, "release_title": format!("title-{r}"), "arch": a, "variant": "default",
                    "latest": latest, "versions": versions,
                }),
            );
        }
        let index = serde_json::json!({ "schema_version": 1, "images": images });
        std::fs::write(dir.join("index.json"), index.to_string()).unwrap();
        body.to_vec()
    }

    fn test_manager(publish_dir: &Path, data_dir: &Path) -> MachineImageManager {
        MachineImageManager::with_base(data_dir, RemoteLocation::File(publish_dir.to_path_buf()))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pull_by_distro_lands_and_is_idempotent() {
        let publish_dir = tempdir().unwrap();
        let data_dir = tempdir().unwrap();
        let body = publish(
            publish_dir.path(),
            "ubuntu-noble-arm64",
            "20260716_0947",
            b"ubuntu-rootfs",
        );

        let manager = test_manager(publish_dir.path(), data_dir.path());
        let selector = ImageSelector::Distro {
            distro: "ubuntu".into(),
            release: None,
            arch: "arm64".into(),
        };

        let image = manager.pull(&selector, |_, _| {}).await.unwrap();
        assert_eq!(image.manifest.name, "ubuntu-noble-arm64");
        assert_eq!(image.manifest.version, "20260716_0947");
        assert_eq!(std::fs::read(image.rootfs_path()).unwrap(), body);

        // Second pull is a cached no-op reporting full progress.
        let mut seen = Vec::new();
        let again = manager
            .pull(&selector, |done, total| seen.push((done, total)))
            .await
            .unwrap();
        assert_eq!(again.rootfs_path(), image.rootfs_path());
        assert_eq!(seen, vec![(body.len() as u64, body.len() as u64)]);
        assert_eq!(manager.list().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn distro_selector_requires_release_when_ambiguous() {
        let publish_dir = tempdir().unwrap();
        let data_dir = tempdir().unwrap();
        publish(
            publish_dir.path(),
            "ubuntu-noble-arm64",
            "20260716_0947",
            b"a",
        );
        publish(
            publish_dir.path(),
            "ubuntu-resolute-arm64",
            "20260716_0947",
            b"b",
        );

        let manager = test_manager(publish_dir.path(), data_dir.path());
        let ambiguous = ImageSelector::Distro {
            distro: "ubuntu".into(),
            release: None,
            arch: "arm64".into(),
        };
        let err = manager.resolve(&ambiguous).await.unwrap_err();
        assert!(err.to_string().contains("multiple releases"), "{err}");

        let pinned = ImageSelector::Distro {
            distro: "ubuntu".into(),
            release: Some("resolute".into()),
            arch: "arm64".into(),
        };
        let (_, manifest) = manager.resolve(&pinned).await.unwrap();
        assert_eq!(manifest.name, "ubuntu-resolute-arm64");

        let unknown = ImageSelector::Distro {
            distro: "ubuntu".into(),
            release: Some("jammy".into()),
            arch: "arm64".into(),
        };
        let err = manager.resolve(&unknown).await.unwrap_err();
        assert!(err.to_string().contains("available releases"), "{err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn corrupted_rootfs_is_rejected_and_leaves_no_entry() {
        let publish_dir = tempdir().unwrap();
        let data_dir = tempdir().unwrap();
        publish(
            publish_dir.path(),
            "alpine-3.24-arm64",
            "20260716_1300",
            b"alpine-rootfs",
        );
        // Corrupt the published blob after the manifest was written.
        std::fs::write(
            publish_dir
                .path()
                .join("alpine-3.24-arm64/20260716_1300/rootfs.squashfs"),
            b"tampered!!!!!",
        )
        .unwrap();

        let manager = test_manager(publish_dir.path(), data_dir.path());
        let selector = ImageSelector::Reference("alpine-3.24-arm64".parse().unwrap());
        let err = manager.pull(&selector, |_, _| {}).await.unwrap_err();
        assert!(err.to_string().contains("sha256"), "{err}");
        assert!(manager.get("alpine-3.24-arm64", "20260716_1300").is_err());
        assert!(manager.list().is_empty());
    }

    #[test]
    fn arch_mapping_covers_host_names() {
        assert_eq!(image_arch("aarch64"), "arm64");
        assert_eq!(image_arch("x86_64"), "amd64");
        assert_eq!(image_arch("arm64"), "arm64");
        assert_eq!(image_arch("amd64"), "amd64");
    }
}
