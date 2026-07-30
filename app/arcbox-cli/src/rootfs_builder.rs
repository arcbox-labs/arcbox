//! Resolve Docker images to guest-visible OCI image layout directories.
//!
//! For `--from-dockerfile`, runs `docker build` via the ArcBox Docker context
//! (proxied to guest dockerd); for `--from-image`, an existing image is used
//! as-is. Either way the image is exported with `docker save` into an OCI
//! image layout directory, which the guest agent feeds to `oci2rootfs` for
//! ext4 conversion.
//!
//! There is deliberately no overlay2 layer path here: guest dockerd uses the
//! containerd snapshotter image store, so `docker inspect` reports no
//! `GraphDriver` and there is no `UpperDir` to point at.
//!
//! The export is staged where the guest can read it back over VirtioFS —
//! `~/Library/Caches/arcbox/sandbox-oci/<content-key>` when the user's cache
//! directory is under `/Users`, since the `users` share maps it to the
//! identical guest path and macOS reclaims `Library/Caches` on its own.
//! Otherwise it falls back to `<data_dir>/cache/sandbox-oci/<content-key>`, which
//! the guest sees below `/arcbox`. Staging in `$TMPDIR` would be preferable
//! but the `/private` share never mounts in the guest (CORE-41).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use arcbox_constants::paths::{ArcboxProfile, HostLayout, guest};
use sha2::{Digest, Sha256};
use tokio::process::Command;

/// Directory holding exported image layouts, under the staging root.
const OCI_STAGING_DIR: &str = "sandbox-oci";

/// Marker file that identifies an OCI image layout directory.
const OCI_LAYOUT_MARKER: &str = "oci-layout";

/// Check if a file has a valid ext4 superblock magic.
pub fn has_ext4_magic(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 2];
    file.seek(SeekFrom::Start(0x438)).is_ok()
        && file.read_exact(&mut magic).is_ok()
        && magic == [0x53, 0xEF]
}

/// Check if a file looks like a Dockerfile (first non-comment line starts with FROM).
pub fn looks_like_dockerfile(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content
        .lines()
        .find(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .is_some_and(|line| line.trim().to_ascii_uppercase().starts_with("FROM "))
}

/// Build a Docker image from a Dockerfile and return the guest-visible path
/// of its exported OCI image layout.
pub async fn resolve_from_dockerfile(dockerfile_path: &str) -> Result<String> {
    let dockerfile = Path::new(dockerfile_path);
    if !dockerfile.exists() {
        bail!("Dockerfile not found: {dockerfile_path}");
    }
    if !looks_like_dockerfile(dockerfile) {
        bail!(
            "{dockerfile_path} does not appear to be a Dockerfile \
             (expected first non-comment line to start with FROM)"
        );
    }

    let content = tokio::fs::read(dockerfile)
        .await
        .context("failed to read Dockerfile")?;
    let context_dir = dockerfile.parent().unwrap_or_else(|| Path::new("."));

    build_and_resolve(&content, dockerfile, context_dir).await
}

/// Build an in-memory Dockerfile and return the guest-visible path of its
/// exported OCI image layout.
///
/// Used for the built-in templates ([`crate::templates`]), which have no file
/// on disk. The Dockerfile is written into a private temp directory that also
/// serves as the (empty) build context, so a template must not `COPY` local
/// paths.
pub async fn resolve_from_dockerfile_contents(contents: &[u8]) -> Result<String> {
    let context = tempfile::TempDir::new().context("failed to create image build directory")?;
    let dockerfile = context.path().join("Dockerfile");
    tokio::fs::write(&dockerfile, contents)
        .await
        .context("failed to stage Dockerfile")?;

    build_and_resolve(contents, &dockerfile, context.path()).await
}

/// Shared `docker build` step: tag by content hash, then export the layout.
///
/// The tag is derived from the Dockerfile contents, so an unchanged
/// Dockerfile resolves to the same image (and therefore the same exported
/// layout and guest-side ext4) on every run.
async fn build_and_resolve(
    contents: &[u8],
    dockerfile: &Path,
    context_dir: &Path,
) -> Result<String> {
    let tag = format!("arcbox-sandbox:{}", cache_key(contents));

    eprintln!("Building Docker image...");
    let output = Command::new("docker")
        .args(["--context", docker_context(), "build", "-t", &tag, "-f"])
        .arg(dockerfile)
        .arg(context_dir)
        .output()
        .await
        .context("failed to spawn docker build")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("docker build failed:\n{stderr}");
    }

    resolve_layout(&tag).await
}

/// Export an existing Docker image and return the guest-visible path of its
/// OCI image layout.
pub async fn resolve_from_image(image_ref: &str) -> Result<String> {
    resolve_layout(image_ref).await
}

/// Docker context for the active runtime profile.
///
/// `main` mirrors `--profile` into `ARCBOX_PROFILE`, so this follows the flag
/// as well as the environment.
fn docker_context() -> &'static str {
    ArcboxProfile::from_env_or_default().docker_context_name()
}

/// Platform selector for `docker save`, pinning a single manifest so the
/// exported layout is unambiguous for the converter.
fn docker_platform() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("linux/arm64"),
        "x86_64" => Ok("linux/amd64"),
        other => bail!("unsupported host architecture for sandbox images: {other}"),
    }
}

/// Export `image_ref` to an OCI image layout and return its guest-visible path.
///
/// Reuses an existing export for the same filesystem content, so repeat runs skip
/// both the `docker save` and the guest-side ext4 conversion (the guest keys
/// its rootfs cache off this path, which is content-derived and therefore
/// stable across rebuilds).
async fn resolve_layout(image_ref: &str) -> Result<String> {
    let dir_name = format!("layers-{}", image_fs_key(image_ref).await?);
    let (host_root, guest_root) = staging_paths(dirs::cache_dir().as_deref(), &data_dir());
    let host_dir = host_root.join(&dir_name);
    let guest_path = format!("{guest_root}/{dir_name}");

    if host_dir.join(OCI_LAYOUT_MARKER).is_file() {
        return Ok(guest_path);
    }

    export_oci_layout(image_ref, &host_root, &host_dir).await?;
    Ok(guest_path)
}

/// Root data directory for the active profile.
fn data_dir() -> PathBuf {
    HostLayout::from_env_or_default().data_dir
}

/// Pick the staging root, returning the host directory and the path the guest
/// sees it at.
///
/// The guest mounts the host's `/Users` at the identical path, so a cache
/// directory below it needs no translation and macOS is free to reclaim it.
/// Anything else falls back to the data directory, which the guest always has
/// mounted at [`guest::MOUNT`].
fn staging_paths(cache_dir: Option<&Path>, data_dir: &Path) -> (PathBuf, String) {
    if let Some(cache) = cache_dir
        && cache.starts_with("/Users/")
    {
        let root = cache.join("arcbox").join(OCI_STAGING_DIR);
        let guest = root.to_string_lossy().into_owned();
        return (root, guest);
    }

    (
        data_dir.join(guest::CACHE).join(OCI_STAGING_DIR),
        format!("{}/{}/{OCI_STAGING_DIR}", guest::MOUNT, guest::CACHE),
    )
}

/// Identify an image by the content of its filesystem.
///
/// Deliberately NOT `.Id`: the config digest changes on every `docker build`
/// even when the result is byte-identical, because BuildKit stamps fresh
/// metadata into the config. Keying the export on it meant every create
/// re-ran `docker save` and re-converted the image to ext4 in the guest —
/// minutes of work per sandbox. The layer diff IDs are stable across such
/// rebuilds and change exactly when the filesystem changes, which is both
/// what the converter consumes and what the guest's rootfs cache keys on
/// (by path).
///
/// Hashing the list also makes the key safe as a path component whatever
/// `docker` reported.
async fn image_fs_key(image_ref: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "--context",
            docker_context(),
            "image",
            "inspect",
            "--format",
            "{{join .RootFS.Layers \",\"}}",
            image_ref,
        ])
        .output()
        .await
        .context("failed to spawn docker image inspect")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("docker image inspect failed (is the image present?):\n{stderr}");
    }

    let layers = String::from_utf8(output.stdout)
        .context("docker image inspect returned non-UTF-8 output")?
        .trim()
        .to_string();
    if layers.is_empty() {
        bail!("docker image inspect reported no layers for {image_ref}");
    }
    Ok(cache_key(layers.as_bytes()))
}

/// Export an image into `dest` as an OCI image layout.
///
/// Streams `docker save` to a private temp file, unpacks it into a private
/// temp directory, and only then renames into place, so a concurrent or
/// crashed export can never be observed as a complete layout.
async fn export_oci_layout(image_ref: &str, root: &Path, dest: &Path) -> Result<()> {
    let platform = docker_platform()?;
    tokio::fs::create_dir_all(root)
        .await
        .with_context(|| format!("failed to create image staging dir {}", root.display()))?;

    let archive = unique_temp_path(root, "save");
    let staged = unique_temp_path(root, "layout");

    eprintln!("Exporting {image_ref} for the sandbox...");
    let saved = Command::new("docker")
        .args([
            "--context",
            docker_context(),
            "save",
            "--platform",
            platform,
            "-o",
        ])
        .arg(&archive)
        .arg(image_ref)
        .output()
        .await
        .context("failed to spawn docker save");

    let result = async {
        let output = saved?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("docker save failed for {image_ref}:\n{stderr}");
        }

        let (from, into) = (archive.clone(), staged.clone());
        tokio::task::spawn_blocking(move || unpack_archive(&from, &into))
            .await
            .context("image unpack task panicked")??;

        if !staged.join(OCI_LAYOUT_MARKER).is_file() {
            bail!(
                "docker save produced no OCI image layout for {image_ref} \
                 (missing {OCI_LAYOUT_MARKER})"
            );
        }
        Ok(())
    }
    .await;

    let _ = tokio::fs::remove_file(&archive).await;

    if let Err(error) = result {
        let _ = tokio::fs::remove_dir_all(&staged).await;
        return Err(error);
    }

    // A concurrent export may have published the same digest first; its
    // contents are equivalent, so keep the winner and drop our copy.
    if dest.exists() {
        let _ = tokio::fs::remove_dir_all(&staged).await;
        return Ok(());
    }
    if let Err(error) = tokio::fs::rename(&staged, dest).await {
        let _ = tokio::fs::remove_dir_all(&staged).await;
        return Err(error)
            .with_context(|| format!("failed to publish image layout at {}", dest.display()));
    }
    Ok(())
}

/// Unpack a `docker save` archive into `dest`.
fn unpack_archive(archive: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(archive)
        .with_context(|| format!("failed to open {}", archive.display()))?;
    // Blob permissions are irrelevant to the converter, and preserving them
    // would need ownership the CLI does not have.
    let mut tar = tar::Archive::new(file);
    tar.set_preserve_permissions(false);
    tar.unpack(dest)
        .with_context(|| format!("failed to unpack image archive into {}", dest.display()))
}

/// Build a private temp path inside `root`.
///
/// Per-process unique so concurrent exports never share a partially written
/// file — the same rule `arcbox-asset` follows for downloads.
fn unique_temp_path(root: &Path, kind: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    root.join(format!(".{kind}.{}.{seq}.tmp", std::process::id()))
}

/// Full SHA-256 hex digest of content.
fn cache_key(content: &[u8]) -> String {
    let hash = Sha256::digest(content);
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_deterministic() {
        let a = cache_key(b"FROM ubuntu:22.04\nRUN apt-get update");
        let b = cache_key(b"FROM ubuntu:22.04\nRUN apt-get update");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // full SHA-256
    }

    #[test]
    fn test_cache_key_different() {
        let a = cache_key(b"FROM ubuntu:22.04");
        let b = cache_key(b"FROM alpine:3.21");
        assert_ne!(a, b);
    }

    #[test]
    fn test_looks_like_dockerfile() {
        let dir = tempfile::TempDir::new().unwrap();
        let df = dir.path().join("Dockerfile");

        std::fs::write(&df, "FROM ubuntu:22.04\nRUN echo hi").unwrap();
        assert!(looks_like_dockerfile(&df));

        std::fs::write(&df, "# comment\nFROM alpine").unwrap();
        assert!(looks_like_dockerfile(&df));

        std::fs::write(&df, "not a dockerfile").unwrap();
        assert!(!looks_like_dockerfile(&df));

        std::fs::write(&df, "").unwrap();
        assert!(!looks_like_dockerfile(&df));
    }

    #[test]
    fn test_has_ext4_magic_nonexistent() {
        assert!(!has_ext4_magic(Path::new("/nonexistent")));
    }

    #[test]
    fn staging_paths_uses_the_user_cache_dir_verbatim() {
        // A cache dir under /Users is visible to the guest at the same path,
        // so host and guest paths must match exactly.
        let (host, guest) = staging_paths(
            Some(Path::new("/Users/someone/Library/Caches")),
            Path::new("/Users/someone/.arcbox"),
        );
        assert_eq!(
            host,
            PathBuf::from("/Users/someone/Library/Caches/arcbox/sandbox-oci")
        );
        assert_eq!(guest, "/Users/someone/Library/Caches/arcbox/sandbox-oci");
    }

    #[test]
    fn staging_paths_falls_back_to_the_data_dir_off_users() {
        // Off /Users the only guaranteed share is the data dir at /arcbox.
        let (host, guest) = staging_paths(
            Some(Path::new("/home/someone/.cache")),
            Path::new("/srv/arcbox"),
        );
        assert_eq!(host, PathBuf::from("/srv/arcbox/cache/sandbox-oci"));
        assert_eq!(guest, "/arcbox/cache/sandbox-oci");

        let (host, guest) = staging_paths(None, Path::new("/srv/arcbox"));
        assert_eq!(host, PathBuf::from("/srv/arcbox/cache/sandbox-oci"));
        assert_eq!(guest, "/arcbox/cache/sandbox-oci");
    }
}
