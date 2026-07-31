//! Resolve a sandbox template reference to a bootable rootfs (CORE-54).
//!
//! The product API names *what runs* in a sandbox with one opaque string;
//! nothing in it is a host path. Local mode understands two forms:
//!
//! - `""` — the built-in minimal template (busybox + `vm-agent`), built on
//!   first use.
//! - `"docker:<ref>"` — a Docker image available to the guest's own dockerd,
//!   exported and converted to ext4 entirely inside the VM.
//!
//! Cloud mode will resolve names against the tenant's template registry
//! (CORE-21); an unrecognised form is rejected rather than guessed at.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt as _;

use crate::error::SandboxError;

/// Prefix selecting a Docker image from the guest's own dockerd.
const DOCKER_PREFIX: &str = "docker:";

/// Staging root for image layouts exported out of the guest's dockerd.
const LAYOUT_STAGING_DIR: &str = "/var/lib/arcbox/sandbox/templates";

/// Marker file identifying an OCI image layout directory.
const OCI_LAYOUT_MARKER: &str = "oci-layout";

/// A template reference the guest knows how to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Template {
    /// Built-in busybox + `vm-agent` image.
    Default,
    /// A Docker image reference resolved against the guest's dockerd.
    DockerImage(String),
}

impl Template {
    /// Parse a wire template reference.
    ///
    /// Unknown forms are rejected: silently treating them as an image name
    /// would turn a typo into a confusing pull failure minutes later, and a
    /// future registry form must not be swallowed by this arm.
    pub(super) fn parse(reference: &str) -> Result<Self, SandboxError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Ok(Self::Default);
        }
        if let Some(image) = reference.strip_prefix(DOCKER_PREFIX) {
            if image.is_empty() {
                return Err(SandboxError::InvalidArgument(
                    "template 'docker:' is missing an image reference".into(),
                ));
            }
            return Ok(Self::DockerImage(image.to_owned()));
        }
        Err(SandboxError::InvalidArgument(format!(
            "unknown template {reference:?}; expected \"\" (built-in) or \"docker:<image>\""
        )))
    }
}

/// Export `image_ref` from the guest's dockerd into an OCI image layout and
/// return its directory.
///
/// Reuses an existing export for the same image content, so a repeat create
/// skips both the export and the ext4 conversion (the rootfs cache keys off
/// this path, which is content-derived and therefore stable across rebuilds
/// that do not change the filesystem).
pub(super) async fn export_docker_image(image_ref: &str) -> Result<String> {
    let key = image_content_key(image_ref).await?;
    let dest = PathBuf::from(LAYOUT_STAGING_DIR).join(format!("layers-{key}"));
    if dest.join(OCI_LAYOUT_MARKER).is_file() {
        tracing::info!(image = image_ref, path = %dest.display(), "using cached image layout");
        return Ok(dest.to_string_lossy().into_owned());
    }

    tokio::fs::create_dir_all(LAYOUT_STAGING_DIR)
        .await
        .with_context(|| format!("failed to create {LAYOUT_STAGING_DIR}"))?;

    // Stage into private temp paths and rename only once complete, so a
    // concurrent or crashed export is never observed as a finished layout.
    let unique = uuid::Uuid::new_v4();
    let archive = PathBuf::from(LAYOUT_STAGING_DIR).join(format!(".save-{unique}.tar"));
    let staged = PathBuf::from(LAYOUT_STAGING_DIR).join(format!(".layout-{unique}"));

    let result = stage_layout(image_ref, &archive, &staged).await;
    let _ = tokio::fs::remove_file(&archive).await;
    if let Err(e) = result {
        let _ = tokio::fs::remove_dir_all(&staged).await;
        return Err(e);
    }

    match tokio::fs::rename(&staged, &dest).await {
        Ok(()) => {}
        // A concurrent create finished first; its layout is equivalent
        // (same content key), so adopt it and drop ours.
        Err(_) if dest.join(OCI_LAYOUT_MARKER).is_file() => {
            let _ = tokio::fs::remove_dir_all(&staged).await;
        }
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&staged).await;
            return Err(e).with_context(|| format!("failed to publish layout {}", dest.display()));
        }
    }

    tracing::info!(image = image_ref, path = %dest.display(), "exported image layout");
    Ok(dest.to_string_lossy().into_owned())
}

/// Download the image export and unpack it into `staged`.
async fn stage_layout(image_ref: &str, archive: &Path, staged: &Path) -> Result<()> {
    let mut file = tokio::fs::File::create(archive)
        .await
        .with_context(|| format!("failed to create {}", archive.display()))?;
    docker::get_image_export(image_ref, &mut file)
        .await
        .with_context(|| format!("failed to export image {image_ref} from the guest dockerd"))?;
    file.flush().await.context("failed to flush image export")?;
    drop(file);

    tokio::fs::create_dir_all(staged)
        .await
        .with_context(|| format!("failed to create {}", staged.display()))?;

    let archive = archive.to_owned();
    let staged_dir = staged.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let file = std::fs::File::open(&archive)
            .with_context(|| format!("failed to open {}", archive.display()))?;
        tar::Archive::new(file)
            .unpack(&staged_dir)
            .context("failed to unpack the image export")?;
        Ok(())
    })
    .await
    .context("image unpack task panicked")??;

    if !staged.join(OCI_LAYOUT_MARKER).is_file() {
        bail!(
            "image export is not an OCI image layout (no {OCI_LAYOUT_MARKER}); \
             the guest dockerd must use the containerd image store"
        );
    }
    Ok(())
}

/// Identify an image by the content of its filesystem (its layer diff IDs).
///
/// Deliberately NOT the image config digest: BuildKit stamps fresh metadata
/// into the config on every build, so keying on it would re-export and
/// re-convert a byte-identical image on every create. Diff IDs change exactly
/// when the filesystem changes, which is what the converter consumes.
async fn image_content_key(image_ref: &str) -> Result<String> {
    let inspect = docker::inspect_image(image_ref).await?;
    let layers = inspect
        .get("RootFS")
        .and_then(|fs| fs.get("Layers"))
        .and_then(|l| l.as_array())
        .filter(|layers| !layers.is_empty())
        .with_context(|| format!("docker reported no layers for image {image_ref}"))?;

    let joined = layers
        .iter()
        .filter_map(|l| l.as_str())
        .collect::<Vec<_>>()
        .join(",");
    if joined.is_empty() {
        bail!("docker reported unreadable layer digests for image {image_ref}");
    }

    use std::hash::Hasher as _;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(joined.as_bytes());
    Ok(format!("{:016x}", hasher.finish()))
}

/// Minimal Docker Engine API client over the guest's own dockerd socket.
///
/// Two calls, both raw HTTP/1.1: inspect (small JSON) and export (a tar
/// stream of unbounded size, so it is written straight to disk rather than
/// buffered). The daemon-side proxy is not involved — dockerd is a local
/// socket away from the agent.
mod docker {
    use anyhow::{Context, Result, bail};
    use arcbox_constants::paths::DOCKER_API_UNIX_SOCKET;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
    use tokio::net::UnixStream;

    /// Largest inspect response accepted (guards a hostile/broken dockerd).
    const MAX_INSPECT_BYTES: usize = 4 * 1024 * 1024;

    /// `GET /images/{ref}/json`, parsed as JSON.
    pub(super) async fn inspect_image(image_ref: &str) -> Result<serde_json::Value> {
        let path = format!("/images/{}/json", urlencode(image_ref));
        let mut stream = request(&path).await?;
        let (status, reader) = read_headers(&mut stream).await?;
        if status != 200 {
            bail!("docker image inspect {image_ref} returned HTTP {status}");
        }

        let mut body = Vec::new();
        reader
            .take(MAX_INSPECT_BYTES as u64)
            .read_to_end(&mut body)
            .await
            .context("failed to read the docker inspect response")?;
        // dockerd answers inspect with Content-Length, so the body is the
        // remaining bytes verbatim.
        serde_json::from_slice(&body).context("failed to parse the docker inspect response")
    }

    /// `GET /images/{ref}/get`, streamed into `sink` (an OCI-layout tar).
    pub(super) async fn get_image_export<W>(image_ref: &str, sink: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let path = format!("/images/{}/get", urlencode(image_ref));
        let mut stream = request(&path).await?;
        let (status, mut reader) = read_headers(&mut stream).await?;
        if status != 200 {
            bail!("docker image export {image_ref} returned HTTP {status}");
        }

        // The export is sent with `Connection: close` and no chunking, so the
        // rest of the connection is the tar stream.
        tokio::io::copy(&mut reader, sink)
            .await
            .context("failed to stream the docker image export")?;
        Ok(())
    }

    /// Open the socket and send a `GET` with `Connection: close`.
    async fn request(path: &str) -> Result<UnixStream> {
        let mut stream = UnixStream::connect(DOCKER_API_UNIX_SOCKET)
            .await
            .with_context(|| format!("failed to connect {DOCKER_API_UNIX_SOCKET}"))?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .context("failed to send the docker request")?;
        Ok(stream)
    }

    /// Read the status line and headers, returning the status code and a
    /// reader positioned at the first body byte.
    async fn read_headers(
        stream: &mut UnixStream,
    ) -> Result<(u16, tokio::io::BufReader<&mut UnixStream>)> {
        let mut reader = tokio::io::BufReader::new(stream);

        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .await
            .context("failed to read the docker response status")?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .with_context(|| format!("unparseable docker status line: {status_line:?}"))?;

        loop {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .await
                .context("failed to read the docker response headers")?;
            if n == 0 {
                bail!("docker closed the connection mid-headers");
            }
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        Ok((status, reader))
    }

    /// Percent-encode an image reference for a path segment.
    ///
    /// References carry `/` and `:` (`ghcr.io/org/img:tag`), which would
    /// otherwise split the path or be read as a port.
    fn urlencode(value: &str) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(value.len());
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                other => {
                    let _ = write!(out, "%{other:02X}");
                }
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::urlencode;

        #[test]
        fn urlencode_escapes_registry_refs() {
            assert_eq!(urlencode("alpine"), "alpine");
            assert_eq!(urlencode("alpine:3.20"), "alpine%3A3.20");
            assert_eq!(
                urlencode("ghcr.io/org/img:tag"),
                "ghcr.io%2Forg%2Fimg%3Atag"
            );
            // A digest reference keeps its separators escaped too.
            assert_eq!(urlencode("img@sha256:ab"), "img%40sha256%3Aab");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_the_built_in_and_docker_forms() {
        assert_eq!(Template::parse("").unwrap(), Template::Default);
        assert_eq!(Template::parse("   ").unwrap(), Template::Default);
        assert_eq!(
            Template::parse("docker:alpine:3.20").unwrap(),
            Template::DockerImage("alpine:3.20".into())
        );
    }

    #[test]
    fn parse_rejects_unknown_forms_instead_of_guessing() {
        // A bare image name is NOT accepted: it is the future registry-name
        // form, and guessing would make a typo surface much later.
        assert!(matches!(
            Template::parse("alpine"),
            Err(SandboxError::InvalidArgument(_))
        ));
        // A host path must never resolve (the whole point of CORE-54).
        assert!(matches!(
            Template::parse("/var/lib/arcbox/rootfs.ext4"),
            Err(SandboxError::InvalidArgument(_))
        ));
        assert!(matches!(
            Template::parse("docker:"),
            Err(SandboxError::InvalidArgument(_))
        ));
    }
}
