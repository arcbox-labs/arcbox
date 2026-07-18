//! Shared plumbing for CDN-published image registries.
//!
//! Both the macOS base-image registry (`darwin/` namespace of
//! `image.arcboxcdn.com`) and the Linux machine-image mirror (`linux/`
//! namespace) publish the same discovery shape: a mutable `index.json`
//! mapping streams to versioned, immutable manifests, with every path
//! relative to the index location. This module owns that shape plus the
//! fetch/staging primitives; the per-platform manifest formats stay with
//! their consumers ([`crate::macos`], [`crate::machine_image`]).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use crate::error::{CoreError, Result};

/// A parsed image reference: `stream` or `stream@version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    /// Stream name, e.g. `tahoe-base` or `ubuntu-noble-arm64`.
    pub stream: String,
    /// Pinned version; `None` follows the index's latest.
    pub version: Option<String>,
}

impl FromStr for ImageReference {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self> {
        let (stream, version) = match s.split_once('@') {
            Some((stream, version)) => (stream, Some(version.to_string())),
            None => (s, None),
        };
        if stream.is_empty()
            || !stream
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(CoreError::image(format!("invalid image reference '{s}'")));
        }
        if let Some(v) = &version {
            if v.is_empty() {
                return Err(CoreError::image(format!("invalid image reference '{s}'")));
            }
        }
        Ok(Self {
            stream: stream.to_string(),
            version,
        })
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(v) => write!(f, "{}@{v}", self.stream),
            None => write!(f, "{}", self.stream),
        }
    }
}

/// The published discovery index (`index.json` at the namespace root).
#[derive(Debug, Deserialize)]
pub struct RemoteIndex {
    /// Index schema version.
    pub schema_version: u32,
    /// Streams by name.
    pub images: HashMap<String, RemoteStream>,
}

/// One image stream in the index.
#[derive(Debug, Deserialize)]
pub struct RemoteStream {
    /// The version `pull <stream>` resolves to.
    pub latest: String,
    /// All retained versions.
    pub versions: HashMap<String, RemoteVersion>,
}

/// One published version of a stream.
#[derive(Debug, Deserialize)]
pub struct RemoteVersion {
    /// Manifest path relative to the index location.
    pub manifest: String,
}

impl RemoteIndex {
    /// Resolves a reference to `(version, manifest path relative to the index)`.
    ///
    /// # Errors
    /// Returns a not-found error for an unknown stream or version.
    pub fn resolve(&self, reference: &ImageReference) -> Result<(String, String)> {
        let stream = self
            .images
            .get(&reference.stream)
            .ok_or_else(|| CoreError::not_found(format!("image stream '{}'", reference.stream)))?;
        let version = reference
            .version
            .clone()
            .unwrap_or_else(|| stream.latest.clone());
        let entry = stream.versions.get(&version).ok_or_else(|| {
            CoreError::not_found(format!("image '{}@{version}'", reference.stream))
        })?;
        Ok((version, entry.manifest.clone()))
    }
}

/// A fetchable location: an HTTP(S) URL or a local filesystem path.
///
/// Locations are joined relatively (sibling files next to a manifest, the
/// index at the base root), so published artifacts never contain absolute URLs.
#[derive(Debug, Clone)]
pub enum RemoteLocation {
    /// An HTTP(S) URL.
    Http(reqwest::Url),
    /// A local file path (used by tests and `pull --manifest <path>`).
    File(PathBuf),
}

impl RemoteLocation {
    /// Parses a location: `http(s)://` becomes [`RemoteLocation::Http`],
    /// anything else a local path.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        if s.starts_with("http://") || s.starts_with("https://") {
            match reqwest::Url::parse(s) {
                Ok(url) => return Self::Http(url),
                Err(_) => return Self::File(PathBuf::from(s)),
            }
        }
        Self::File(PathBuf::from(s))
    }

    /// Resolves `relative` against this location's directory.
    ///
    /// For a location pointing at a file (e.g. a manifest), the result is a
    /// sibling; for a base location, a child.
    ///
    /// # Errors
    /// Returns an error if URL joining fails.
    pub fn join(&self, relative: &str) -> Result<Self> {
        match self {
            Self::Http(url) => {
                let joined = url
                    .join(relative)
                    .map_err(|e| CoreError::image(format!("join '{relative}' to {url}: {e}")))?;
                Ok(Self::Http(joined))
            }
            Self::File(path) => {
                let dir = path.parent().unwrap_or(path);
                Ok(Self::File(dir.join(relative)))
            }
        }
    }

    /// Returns a location that treats the current one as a directory, so
    /// [`RemoteLocation::join`] resolves children instead of siblings.
    #[must_use]
    pub fn as_dir(&self) -> Self {
        match self {
            Self::Http(url) => {
                let mut s = url.to_string();
                if !s.ends_with('/') {
                    s.push('/');
                }
                Self::parse(&s)
            }
            Self::File(path) => Self::File(path.join("placeholder")),
        }
    }

    /// Fetches the location's full contents into memory (small files only:
    /// index, manifest, aux image).
    ///
    /// # Errors
    /// Returns an error on network/IO failure or non-success HTTP status.
    pub async fn fetch_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Http(url) => {
                let resp = reqwest::get(url.clone())
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|e| CoreError::image(format!("fetch {url}: {e}")))?;
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| CoreError::image(format!("fetch {url}: {e}")))?;
                Ok(bytes.to_vec())
            }
            Self::File(path) => Ok(std::fs::read(path)?),
        }
    }

    /// Fetches and JSON-decodes the location's contents.
    ///
    /// # Errors
    /// Returns an error on fetch failure or JSON that does not match `T`.
    pub async fn fetch_json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let bytes = self.fetch_bytes().await?;
        serde_json::from_slice(&bytes).map_err(|e| CoreError::image(format!("parse {self}: {e}")))
    }
}

impl fmt::Display for RemoteLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(url) => write!(f, "{url}"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Validates that `name` is a single, safe path component.
///
/// Image and machine names are used verbatim as a directory under a managed
/// root (`macos/images/<name>`, `machine-images/<name>`). A name must
/// therefore be exactly one normal path component: this rejects empty names,
/// embedded NUL, absolute paths, path separators, and `.`/`..`, so a caller-
/// or manifest-supplied name can never escape its root.
pub(crate) fn validate_name(name: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(only)), None)
            if only == OsStr::new(name) && !name.contains('\0') =>
        {
            Ok(())
        }
        _ => Err(CoreError::image(format!("invalid name '{name}'"))),
    }
}

/// Removes a staging directory on drop unless disarmed.
///
/// Image pull and machine create flows assemble their artifacts in a staging
/// directory and rename it into place only when complete. This guard is what
/// makes those flows safe against early return and cancellation: if it is
/// dropped before `disarm` (an error, or the future being dropped at an await
/// point), the partial directory is removed rather than leaked.
pub(crate) struct StagingGuard {
    path: Option<PathBuf>,
}

impl StagingGuard {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Keeps the directory (it has been renamed into its final location).
    pub(crate) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_parses_stream_and_version() {
        let r: ImageReference = "tahoe-base".parse().unwrap();
        assert_eq!(r.stream, "tahoe-base");
        assert_eq!(r.version, None);

        let r: ImageReference = "tahoe-base@2026.07.02".parse().unwrap();
        assert_eq!(r.stream, "tahoe-base");
        assert_eq!(r.version.as_deref(), Some("2026.07.02"));
        assert_eq!(r.to_string(), "tahoe-base@2026.07.02");
    }

    #[test]
    fn reference_rejects_garbage() {
        assert!("".parse::<ImageReference>().is_err());
        assert!("tahoe base".parse::<ImageReference>().is_err());
        assert!("tahoe-base@".parse::<ImageReference>().is_err());
        assert!("../evil".parse::<ImageReference>().is_err());
    }

    #[test]
    fn index_resolves_latest_and_pinned() {
        let index: RemoteIndex = serde_json::from_str(
            r#"{
                "schema_version": 1,
                "images": {
                    "tahoe-base": {
                        "latest": "2026.07.02",
                        "versions": {
                            "2026.07.02": { "manifest": "tahoe-base/2026.07.02/manifest.json" },
                            "2026.06.01": { "manifest": "tahoe-base/2026.06.01/manifest.json" }
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let latest = index.resolve(&"tahoe-base".parse().unwrap()).unwrap();
        assert_eq!(latest.0, "2026.07.02");
        assert_eq!(latest.1, "tahoe-base/2026.07.02/manifest.json");

        let pinned = index
            .resolve(&"tahoe-base@2026.06.01".parse().unwrap())
            .unwrap();
        assert_eq!(pinned.0, "2026.06.01");

        assert!(index.resolve(&"nope".parse().unwrap()).is_err());
        assert!(
            index
                .resolve(&"tahoe-base@1999.01.01".parse().unwrap())
                .is_err()
        );
    }

    #[test]
    fn location_joins_relatively() {
        let base = RemoteLocation::parse("https://images.arcbox.dev");
        let index = base.as_dir().join("index.json").unwrap();
        assert_eq!(index.to_string(), "https://images.arcbox.dev/index.json");

        let manifest = base
            .as_dir()
            .join("tahoe-base/2026.07.02/manifest.json")
            .unwrap();
        let disk = manifest.join("disk.img.zst").unwrap();
        assert_eq!(
            disk.to_string(),
            "https://images.arcbox.dev/tahoe-base/2026.07.02/disk.img.zst"
        );

        let manifest = RemoteLocation::parse("/tmp/out/manifest.json");
        let disk = manifest.join("disk.img.zst").unwrap();
        assert_eq!(disk.to_string(), "/tmp/out/disk.img.zst");
    }

    #[test]
    fn validate_name_accepts_plain_and_dotted_components() {
        for ok in [
            "tahoe-base",
            "tahoe-base@2026.07.02",
            "ubuntu-noble-arm64",
            ".pull-x",
            ".create-ci-1",
        ] {
            assert!(validate_name(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn validate_name_rejects_traversal_and_separators() {
        for bad in ["", ".", "..", "a/b", "/abs", "a/../b", "a\0b", "sub/dir"] {
            assert!(validate_name(bad).is_err(), "should reject {bad:?}");
        }
    }
}
