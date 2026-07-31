//! Resolve `--from-*` flags to sandbox template references.
//!
//! For `--from-dockerfile` (and the built-in templates) this runs
//! `docker build` via the ArcBox Docker context, which is proxied to the
//! guest's dockerd — so the built image already lives where the sandbox
//! needs it. For `--from-image` an existing image is used as-is.
//!
//! Either way the CLI hands the daemon nothing but `docker:<ref>`: the image
//! export, the OCI layout staging, and the ext4 conversion all happen inside
//! the VM (CORE-54). Nothing here needs a guest-visible host path, which is
//! why the old `~/Library/Caches/arcbox/sandbox-oci` staging is gone.

use std::path::Path;

use anyhow::{Context, Result, bail};
use arcbox_constants::paths::ArcboxProfile;
use sha2::{Digest, Sha256};
use tokio::process::Command;

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

/// Build a Docker image from a Dockerfile and return its template reference.
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

/// Build an in-memory Dockerfile and return its template reference.
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

/// Return the template reference for an existing Docker image.
///
/// The image is resolved inside the VM, so this only has to verify that the
/// reference exists in the guest's image store — catching a typo here rather
/// than as an opaque create failure.
pub async fn resolve_from_image(image_ref: &str) -> Result<String> {
    let output = Command::new("docker")
        .args(["--context", docker_context(), "image", "inspect", image_ref])
        .output()
        .await
        .context("failed to spawn docker image inspect")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("image {image_ref} is not available to ArcBox:\n{stderr}");
    }
    Ok(template_ref(image_ref))
}

/// Docker context for the active runtime profile.
///
/// `main` mirrors `--profile` into `ARCBOX_PROFILE`, so this follows the flag
/// as well as the environment.
fn docker_context() -> &'static str {
    ArcboxProfile::from_env_or_default().docker_context_name()
}

/// Wrap a Docker image reference as a sandbox template reference.
fn template_ref(image_ref: &str) -> String {
    format!("docker:{image_ref}")
}

/// Shared `docker build` step: tag by content hash, then reference the tag.
///
/// The tag is derived from the Dockerfile contents, so an unchanged
/// Dockerfile resolves to the same image — and therefore the same guest-side
/// ext4 — on every run.
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

    Ok(template_ref(&tag))
}

/// Short, filesystem-safe content key.
fn cache_key(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_prefix(&digest, 16)
}

/// Lowercase hex of the first `bytes` of `digest`.
fn hex_prefix(digest: &[u8], bytes: usize) -> String {
    use std::fmt::Write as _;
    digest.iter().take(bytes).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_like_dockerfile() {
        let dir = tempfile::TempDir::new().unwrap();

        let df = dir.path().join("Dockerfile");
        std::fs::write(&df, "FROM alpine\nRUN echo hi\n").unwrap();
        assert!(looks_like_dockerfile(&df));

        let df = dir.path().join("Dockerfile.comment");
        std::fs::write(&df, "# a comment\n\nfrom alpine\n").unwrap();
        assert!(looks_like_dockerfile(&df));

        let df = dir.path().join("not-a-dockerfile");
        std::fs::write(&df, "hello world\n").unwrap();
        assert!(!looks_like_dockerfile(&df));

        let df = dir.path().join("missing");
        assert!(!looks_like_dockerfile(&df));
    }

    #[test]
    fn template_refs_are_prefixed() {
        assert_eq!(template_ref("alpine:3.20"), "docker:alpine:3.20");
        assert_eq!(
            template_ref("ghcr.io/org/img@sha256:ab"),
            "docker:ghcr.io/org/img@sha256:ab"
        );
    }

    #[test]
    fn cache_key_is_stable_and_content_derived() {
        let a = cache_key(b"FROM alpine\n");
        assert_eq!(a, cache_key(b"FROM alpine\n"));
        assert_ne!(a, cache_key(b"FROM debian\n"));
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
