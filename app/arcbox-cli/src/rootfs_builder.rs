//! Resolve Docker images to guest-visible overlay2 layer paths.
//!
//! For `--from-dockerfile`, runs `docker build` via the ArcBox Docker context
//! (proxied to guest dockerd), then inspects the image to get the overlay2
//! layer directory. For `--from-image`, inspects an existing image directly.
//!
//! The returned path is a guest-internal filesystem path (under Docker's
//! overlay2 storage) that the guest agent passes to `oci2rootfs` for ext4
//! conversion.

use std::path::Path;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::process::Command;

/// Docker context name used for ArcBox Docker API.
const DOCKER_CONTEXT: &str = "arcbox";

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

/// Build a Docker image from a Dockerfile and return its guest-visible
/// overlay2 layer directory path.
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
    let hash = cache_key(&content);
    let tag = format!("arcbox-sandbox:{hash}");

    let context_dir = dockerfile
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_string_lossy()
        .to_string();

    // docker build
    eprintln!("Building Docker image...");
    let output = Command::new("docker")
        .args([
            "--context",
            DOCKER_CONTEXT,
            "build",
            "-t",
            &tag,
            "-f",
            dockerfile_path,
            &context_dir,
        ])
        .output()
        .await
        .context("failed to spawn docker build")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("docker build failed:\n{stderr}");
    }

    inspect_layer_path(&tag).await
}

/// Get the guest-visible overlay2 layer directory for an existing Docker image.
pub async fn resolve_from_image(image_ref: &str) -> Result<String> {
    inspect_layer_path(image_ref).await
}

/// Query the overlay2 layer directory for an image via `docker inspect`.
///
/// Returns the chain-id directory (parent of UpperDir) so that `oci2rootfs`
/// can resolve the full layer chain.
async fn inspect_layer_path(image_ref: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "--context",
            DOCKER_CONTEXT,
            "inspect",
            "--format",
            "{{.GraphDriver.Data.UpperDir}}",
            image_ref,
        ])
        .output()
        .await
        .context("failed to spawn docker inspect")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("docker inspect failed (is the image present?):\n{stderr}");
    }

    let upper_dir = String::from_utf8(output.stdout)
        .context("docker inspect returned non-UTF-8 output")?
        .trim()
        .to_string();

    if upper_dir.is_empty() {
        bail!("docker inspect returned empty UpperDir for {image_ref}");
    }

    // oci2rootfs expects the chain-id directory (contains diff/, link, lower),
    // not the diff/ subdirectory itself.
    let layer_dir = upper_dir
        .strip_suffix("/diff")
        .unwrap_or(&upper_dir)
        .to_string();

    Ok(layer_dir)
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
}
