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
///
/// The key names a **persisted** directory that is trusted as authoritative
/// on a later hit, so it must be stable across toolchains (`DefaultHasher`
/// is not — its algorithm is unspecified per release) and collision-resistant
/// against attacker-chosen layer content. SHA-256 with a 16-byte hex prefix,
/// matching the host-side rootfs cache key (`RootfsBuilder`'s `rootfs-<layer>-<agent>` stem).
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

    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(joined.as_bytes());
    use std::fmt::Write as _;
    Ok(digest.iter().take(16).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    }))
}

/// Minimal Docker Engine API client over the guest's own dockerd socket.
///
/// Two calls: inspect (small JSON) and export (a tar stream of unbounded
/// size, written straight to disk rather than buffered). The daemon-side
/// proxy is not involved — dockerd is a local socket away from the agent.
///
/// Both go through hyper rather than hand-rolled HTTP. dockerd is Go
/// `net/http`, which sends a streamed body with no Content-Length as
/// **chunked** transfer-encoding; copying the raw connection bytes splices
/// the chunk headers into the tar and it fails to unpack with an opaque
/// "archive header checksum mismatch". Let the HTTP library do framing.
pub(super) use docker::{build_image, inspect_image};

mod docker {
    use anyhow::{Context, Result, bail};
    use arcbox_constants::paths::DOCKER_API_UNIX_SOCKET;
    use http_body_util::{BodyExt as _, Empty};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncWrite, AsyncWriteExt as _};
    use tokio::net::UnixStream;

    /// Largest inspect response accepted (guards a hostile/broken dockerd).
    const MAX_INSPECT_BYTES: usize = 4 * 1024 * 1024;

    /// `GET /images/{ref}/json`, parsed as JSON.
    pub(in crate::sandbox) async fn inspect_image(image_ref: &str) -> Result<serde_json::Value> {
        let path = format!("/images/{}/json", urlencode(image_ref));
        let mut response = get(&path).await?;
        let status = response.status();
        if !status.is_success() {
            bail!("docker image inspect {image_ref} returned HTTP {status}");
        }

        let mut body = Vec::new();
        while let Some(frame) = response.frame().await {
            let frame = frame.context("failed to read the docker inspect response")?;
            if let Some(chunk) = frame.data_ref() {
                if body.len() + chunk.len() > MAX_INSPECT_BYTES {
                    bail!("docker inspect response exceeds {MAX_INSPECT_BYTES} bytes");
                }
                body.extend_from_slice(chunk);
            }
        }
        serde_json::from_slice(&body).context("failed to parse the docker inspect response")
    }

    /// `GET /images/{ref}/get`, streamed into `sink` (an OCI-layout tar).
    ///
    /// The export is pinned to this guest's platform. A multi-platform image
    /// otherwise exports an index naming manifests for platforms that were
    /// never pulled, and the converter fails on the first missing layer with
    /// a bare `blob not found: sha256:…` that names nothing about platforms.
    pub(super) async fn get_image_export<W>(image_ref: &str, sink: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let path = format!(
            "/images/{}/get?platform={}",
            urlencode(image_ref),
            urlencode(&platform_json()?)
        );
        let mut response = get(&path).await?;
        let status = response.status();
        if !status.is_success() {
            bail!("docker image export {image_ref} returned HTTP {status}");
        }

        while let Some(frame) = response.frame().await {
            let frame = frame.context("failed to stream the docker image export")?;
            if let Some(chunk) = frame.data_ref() {
                sink.write_all(chunk)
                    .await
                    .context("failed to write the docker image export")?;
            }
        }
        Ok(())
    }

    /// Largest build-progress stream accepted before bailing (a runaway
    /// build log, not a hostile dockerd, is the realistic trigger).
    const MAX_BUILD_LOG_BYTES: usize = 64 * 1024 * 1024;

    /// `POST /build` with an in-memory tar context holding one `Dockerfile`,
    /// tagging the result `tag`.
    ///
    /// dockerd answers HTTP 200 even when the build fails: failure arrives
    /// as `{"error":…,"errorDetail":…}` objects inside the newline-delimited
    /// JSON progress stream, so the stream is parsed and the last progress
    /// line is folded into the error. The context contains only the
    /// Dockerfile — `COPY`/`ADD` of local paths cannot work and fails inside
    /// the build with dockerd's own "not found" message.
    pub(in crate::sandbox) async fn build_image(dockerfile: &[u8], tag: &str) -> Result<()> {
        let mut context_tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(dockerfile.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        context_tar
            .append_data(&mut header, "Dockerfile", dockerfile)
            .context("failed to build the in-memory build context")?;
        let context_bytes = context_tar
            .into_inner()
            .context("failed to finish the in-memory build context")?;

        let path = format!(
            "/build?t={}&platform={}",
            urlencode(tag),
            urlencode(&platform_slug()?)
        );
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(path)
            .header(hyper::header::HOST, "localhost")
            .header(hyper::header::CONTENT_TYPE, "application/x-tar")
            .body(http_body_util::Full::new(Bytes::from(context_bytes)))
            .context("failed to build the docker build request")?;
        let mut response = send(request).await?;
        let status = response.status();
        if !status.is_success() {
            bail!("docker build returned HTTP {status}");
        }

        // Newline-delimited JSON progress; remember the last stream line so
        // a failure names the step that produced it.
        let mut buffer = Vec::new();
        let mut last_progress = String::new();
        let mut seen = 0usize;
        while let Some(frame) = response.frame().await {
            let frame = frame.context("failed to stream the docker build progress")?;
            let Some(chunk) = frame.data_ref() else {
                continue;
            };
            seen += chunk.len();
            if seen > MAX_BUILD_LOG_BYTES {
                bail!("docker build progress exceeds {MAX_BUILD_LOG_BYTES} bytes");
            }
            buffer.extend_from_slice(chunk);
            while let Some(newline) = buffer.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buffer.drain(..=newline).collect();
                check_build_progress_line(&line, &mut last_progress)?;
            }
        }
        if !buffer.is_empty() {
            check_build_progress_line(&buffer, &mut last_progress)?;
        }
        Ok(())
    }

    /// Parse one build-progress line; `error` objects become failures.
    fn check_build_progress_line(line: &[u8], last_progress: &mut String) -> Result<()> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            // Interleaved non-JSON output is progress noise, not a failure.
            return Ok(());
        };
        if let Some(error) = value.get("error").and_then(|e| e.as_str()) {
            let at = if last_progress.is_empty() {
                String::new()
            } else {
                format!(" (last step: {})", last_progress.trim())
            };
            bail!("docker build failed: {error}{at}");
        }
        if let Some(stream) = value.get("stream").and_then(|s| s.as_str())
            && !stream.trim().is_empty()
        {
            stream.clone_into(last_progress);
        }
        Ok(())
    }

    /// Dial the docker socket and issue a `GET`, returning the response.
    async fn get(path: &str) -> Result<hyper::Response<hyper::body::Incoming>> {
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(path)
            .header(hyper::header::HOST, "localhost")
            .body(Empty::<Bytes>::new())
            .context("failed to build the docker request")?;
        send(request).await
    }

    /// Dial the docker socket and send `request`, returning the response.
    ///
    /// The connection task is detached: it drives the HTTP state machine
    /// while the caller consumes the body, and ends when the body does.
    /// The authority is unused (the connector dials a fixed socket) but
    /// HTTP/1.1 requires a Host header, which callers set.
    async fn send<B>(request: hyper::Request<B>) -> Result<hyper::Response<hyper::body::Incoming>>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: std::error::Error + Send + Sync,
    {
        let stream = UnixStream::connect(DOCKER_API_UNIX_SOCKET)
            .await
            .with_context(|| format!("failed to connect {DOCKER_API_UNIX_SOCKET}"))?;

        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .context("docker HTTP handshake failed")?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(error = %e, "docker connection closed");
            }
        });

        sender
            .send_request(request)
            .await
            .context("failed to send the docker request")
    }

    /// This guest's platform in the `os/arch` form `/build` expects (unlike
    /// `/images/{ref}/get`, whose `platform` is the JSON OCI shape).
    fn platform_slug() -> Result<String> {
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => bail!("unsupported guest architecture for sandbox images: {other}"),
        };
        Ok(format!("linux/{arch}"))
    }

    /// This guest's platform as the JSON-encoded OCI platform the Engine API
    /// expects (`{"architecture":…,"os":"linux"}`).
    fn platform_json() -> Result<String> {
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => bail!("unsupported guest architecture for sandbox images: {other}"),
        };
        Ok(format!(r#"{{"architecture":"{arch}","os":"linux"}}"#))
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
        use super::{check_build_progress_line, platform_json, platform_slug, urlencode};

        #[test]
        fn build_progress_error_objects_fail_and_name_the_last_step() {
            let mut last = String::new();
            check_build_progress_line(br#"{"stream":"Step 2/3 : RUN false\n"}"#, &mut last)
                .expect("progress is not a failure");
            assert_eq!(last, "Step 2/3 : RUN false\n");

            let err = check_build_progress_line(
                br#"{"error":"process did not complete successfully"}"#,
                &mut last,
            )
            .expect_err("error objects must fail the build");
            let message = err.to_string();
            assert!(
                message.contains("process did not complete successfully"),
                "{message}"
            );
            assert!(message.contains("Step 2/3 : RUN false"), "{message}");
        }

        #[test]
        fn build_progress_tolerates_noise_and_skips_blank_streams() {
            let mut last = String::from("Step 1/1 : FROM alpine\n");
            // Interleaved non-JSON output is progress noise, not a failure.
            check_build_progress_line(b"not json at all", &mut last).expect("noise tolerated");
            // Whitespace-only stream frames must not clobber the last step.
            check_build_progress_line(br#"{"stream":"\n"}"#, &mut last).expect("blank stream");
            assert_eq!(last, "Step 1/1 : FROM alpine\n");
            // Non-error JSON (status/aux frames) passes through.
            check_build_progress_line(br#"{"aux":{"ID":"sha256:ab"}}"#, &mut last)
                .expect("aux frame");
        }

        #[test]
        fn build_platform_is_the_os_arch_slug() {
            let slug = platform_slug().expect("supported test architecture");
            assert!(slug == "linux/arm64" || slug == "linux/amd64", "{slug}");
        }

        #[test]
        fn platform_json_is_the_guest_platform() {
            let platform = platform_json().expect("supported test architecture");
            assert!(platform.contains(r#""os":"linux""#), "{platform}");
            // Docker's OCI platform names, not Rust's target names.
            assert!(
                platform.contains(r#""architecture":"arm64""#)
                    || platform.contains(r#""architecture":"amd64""#),
                "{platform}"
            );
            assert!(!platform.contains("aarch64"), "{platform}");
        }

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
