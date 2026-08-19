//! Convert an image source to a cached, bootable ext4 rootfs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use super::{RootfsBuilder, has_ext4_magic, rootfs_err};

/// Marker file that identifies an OCI image layout directory.
const OCI_LAYOUT_MARKER: &str = "oci-layout";

/// True when `dir` is an OCI image layout rather than an overlay2 layer.
///
/// Dispatching on the marker keeps the choice explicit: a `docker save`
/// layout also carries a legacy `manifest.json`, so leaning on the
/// `oci2rootfs` autodetect heuristics would be guesswork.
fn is_oci_layout(dir: &Path) -> bool {
    dir.join(OCI_LAYOUT_MARKER).is_file()
}

impl RootfsBuilder {
    /// Convert an image source directory to a bootable ext4 rootfs.
    ///
    /// `layer_path` is a directory: either an OCI image layout staged by the
    /// host CLI (the `--from-image` / `--from-dockerfile` path) or a Docker
    /// overlay2 chain-id directory (e.g. `/var/lib/docker/overlay2/<chain-id>`).
    ///
    /// `pinned` are images that must survive the superseded-image sweep
    /// because a snapshot still needs them as its dm-snapshot origin
    /// (`SandboxManager::pinned_rootfs_paths`).
    ///
    /// Returns the path to the generated (or cached) ext4 image.
    pub async fn convert_layer_to_rootfs(
        &self,
        layer_path: &str,
        pinned: &BTreeSet<PathBuf>,
    ) -> crate::error::Result<String> {
        self.convert_layer(layer_path, pinned)
            .await
            .map_err(rootfs_err)
    }

    async fn convert_layer(&self, layer_path: &str, pinned: &BTreeSet<PathBuf>) -> Result<String> {
        if !Path::new(layer_path).exists() {
            bail!("layer path not found: {layer_path}");
        }

        // The cached image has two ingredients, so the key names both: the layer
        // (whose directory name carries the image digest for either source kind,
        // making the path a stable identifier) and the `vm-agent` binary injected
        // below. Keying on the layer alone meant a newer agent never reached an
        // already-converted image — the sandbox kept booting the old init with no
        // sign anything was stale.
        let layer_key = path_hash(layer_path);
        let agent_key = self.vm_agent_key().await?;
        let cache_dir = &self.paths().cache_dir;
        let ext4_path = cache_dir
            .join(format!("rootfs-{layer_key}-{agent_key}.ext4"))
            .to_string_lossy()
            .into_owned();

        // Check cache.
        if Path::new(&ext4_path).exists() && has_ext4_magic(Path::new(&ext4_path)) {
            tracing::info!(path = %ext4_path, "using cached rootfs");
            return Ok(ext4_path);
        }

        tokio::fs::create_dir_all(cache_dir)
            .await
            .context("failed to create rootfs cache dir")?;

        let req_id = Uuid::new_v4().to_string();
        let ext4_tmp = cache_dir
            .join(format!(".rootfs-{req_id}.ext4.tmp"))
            .to_string_lossy()
            .into_owned();

        // Convert via the oci2rootfs library (blocking CPU/IO work).
        tracing::info!(layer = %layer_path, ext4 = %ext4_path, "converting image layer to ext4");
        {
            let layer = layer_path.to_owned();
            let out = ext4_tmp.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let converter = oci2rootfs::Converter::new(&out);
                if is_oci_layout(Path::new(&layer)) {
                    let source = oci2rootfs::OciLayoutSource::open(&layer)
                        .context("failed to open OCI image layout")?;
                    converter
                        .convert(source)
                        .context("OCI layout → ext4 conversion failed")?;
                } else {
                    let source = oci2rootfs::Overlay2Source::open(&layer)
                        .context("failed to open overlay2 layer")?;
                    converter
                        .convert(source)
                        .context("overlay2 → ext4 conversion failed")?;
                }
                Ok(())
            })
            .await
            .context("conversion task panicked")??;
        }

        // Inject vm-agent.
        tracing::info!("injecting vm-agent into rootfs");
        if let Err(e) = self.inject_vm_agent(&ext4_tmp, &req_id).await {
            let _ = tokio::fs::remove_file(&ext4_tmp).await;
            return Err(e);
        }

        // Atomic rename into cache.
        tokio::fs::rename(&ext4_tmp, &ext4_path)
            .await
            .context("failed to rename ext4 into cache")?;

        sweep_superseded(cache_dir, &layer_key, &agent_key, pinned).await;

        tracing::info!(path = %ext4_path, "rootfs ready");
        Ok(ext4_path)
    }

    /// Content key for the `vm-agent` binary that gets injected into every
    /// image.
    ///
    /// Content rather than mtime: this binary is copied into place by
    /// installers and by hand during development, so an older build can
    /// easily carry a newer timestamp — which an mtime check would read as
    /// fresh and then bake in.
    async fn vm_agent_key(&self) -> Result<String> {
        use std::hash::Hasher;
        let bytes = tokio::fs::read(&self.paths().vm_agent)
            .await
            .with_context(|| format!("failed to read {}", self.paths().vm_agent.display()))?;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hasher.write(&bytes);
        Ok(format!("{:016x}", hasher.finish()))
    }

    /// Remove leftover `*.ext4.tmp` build artifacts from the rootfs cache dir.
    ///
    /// A rootfs build that crashed or panicked leaves a `.default-<uuid>.ext4.tmp`
    /// or `.rootfs-<id>.ext4.tmp` (each up to the image size) with no owner;
    /// sweep them at startup so repeated failures don't accrue disk usage.
    pub async fn sweep_stale_tmp(&self) {
        let Ok(mut entries) = tokio::fs::read_dir(&self.paths().cache_dir).await else {
            return;
        };
        let mut removed = 0usize;
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_name().to_string_lossy().ends_with(".ext4.tmp")
                && tokio::fs::remove_file(entry.path()).await.is_ok()
            {
                removed += 1;
            }
        }
        if removed > 0 {
            tracing::info!(removed, "swept stale rootfs build artifacts");
        }
    }
}

/// Delete images for `layer_key` built against a different `vm-agent`.
///
/// Bounds the cache at one image per layer instead of accumulating one per
/// agent version.
///
/// Two kinds of reference survive this:
///
/// - a live sandbox's open image, which unlinks fine on Linux and frees its
///   space when the last reference closes;
/// - anything in `pinned`, i.e. an image a snapshot records as its
///   dm-snapshot origin. That reference is durable (it lives in the snapshot
///   catalog's `meta.json`, so it outlasts reboots) and unrepairable:
///   re-converting the layer with a different `vm-agent` yields different bytes
///   than the snapshot's guest memory was captured against, so a regenerated
///   image is worse than none.
async fn sweep_superseded(
    cache_dir: &Path,
    layer_key: &str,
    agent_key: &str,
    pinned: &BTreeSet<PathBuf>,
) {
    let Ok(mut entries) = tokio::fs::read_dir(cache_dir).await else {
        return;
    };
    let mut removed = 0usize;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_superseded_image(&name, layer_key, agent_key) {
            continue;
        }
        let path = entry.path();
        if pinned.contains(&path) {
            tracing::debug!(path = %path.display(), "keeping superseded rootfs: pinned by a snapshot");
            continue;
        }
        if tokio::fs::remove_file(&path).await.is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!(removed, layer = %layer_key, "removed superseded rootfs images");
    }
}

/// True when `name` is a cached image for `layer_key` built against some other
/// `vm-agent` than `agent_key`.
fn is_superseded_image(name: &str, layer_key: &str, agent_key: &str) -> bool {
    let Some(keys) = name
        .strip_prefix("rootfs-")
        .and_then(|rest| rest.strip_suffix(".ext4"))
    else {
        return false;
    };
    let Some((layer, agent)) = keys.split_once('-') else {
        // Pre-`agent_key` naming (`rootfs-<layer>.ext4`): its injected agent is
        // unknown, so treat it as superseded rather than keep it forever.
        return keys == layer_key;
    };
    layer == layer_key && agent != agent_key
}

/// Derive a stable cache key from the layer path.
fn path_hash(path: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_superseded_image_matches_only_the_same_layer_with_another_agent() {
        // Same layer, older agent build: must go, or the sandbox keeps booting
        // the stale init.
        assert!(is_superseded_image("rootfs-aaaa-0000.ext4", "aaaa", "1111"));
        // The image we just published.
        assert!(!is_superseded_image(
            "rootfs-aaaa-1111.ext4",
            "aaaa",
            "1111"
        ));
        // A different layer is a different image, not a superseded one.
        assert!(!is_superseded_image(
            "rootfs-bbbb-0000.ext4",
            "aaaa",
            "1111"
        ));
        // Legacy name from before the agent key existed: same layer, unknown
        // agent, so treat as superseded; other layers stay.
        assert!(is_superseded_image("rootfs-aaaa.ext4", "aaaa", "1111"));
        assert!(!is_superseded_image("rootfs-bbbb.ext4", "aaaa", "1111"));
        // Anything that is not a published image is left alone, including the
        // in-progress temp files sweep_stale_tmp owns.
        assert!(!is_superseded_image(
            ".rootfs-aaaa-1111.ext4.tmp",
            "aaaa",
            "1111"
        ));
        assert!(!is_superseded_image("default.ext4", "aaaa", "1111"));
        assert!(!is_superseded_image(
            "rootfs-aaaa-1111.ext4.bak",
            "aaaa",
            "1111"
        ));
    }

    #[test]
    fn is_oci_layout_detects_the_layout_marker() {
        let dir = tempfile::TempDir::new().unwrap();

        // An overlay2 chain-id directory has no marker.
        std::fs::create_dir(dir.path().join("diff")).unwrap();
        assert!(!is_oci_layout(dir.path()));

        // A `docker save` export does, alongside a legacy manifest.json.
        std::fs::write(dir.path().join("manifest.json"), "[]").unwrap();
        std::fs::write(
            dir.path().join(OCI_LAYOUT_MARKER),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        assert!(is_oci_layout(dir.path()));
    }

    #[tokio::test]
    async fn sweep_superseded_keeps_images_a_snapshot_still_needs() {
        let dir = tempfile::tempdir().unwrap();
        let image = |name: &str| dir.path().join(name);
        for name in [
            "rootfs-aaaa-0000.ext4",
            "rootfs-aaaa.ext4",
            "rootfs-aaaa-1111.ext4",
            "rootfs-bbbb-0000.ext4",
        ] {
            std::fs::write(image(name), b"x").unwrap();
        }
        let pinned = BTreeSet::from([image("rootfs-aaaa.ext4")]);

        sweep_superseded(dir.path(), "aaaa", "1111", &pinned).await;

        // Superseded and unreferenced: gone.
        assert!(!image("rootfs-aaaa-0000.ext4").exists());
        // Superseded but a snapshot records it as its dm-snapshot origin, and a
        // re-conversion would not reproduce those bytes.
        assert!(image("rootfs-aaaa.ext4").exists());
        // Current image and other layers are untouched.
        assert!(image("rootfs-aaaa-1111.ext4").exists());
        assert!(image("rootfs-bbbb-0000.ext4").exists());
    }

    #[test]
    fn test_path_hash_deterministic() {
        let a = path_hash("/var/lib/docker/overlay2/abc123");
        let b = path_hash("/var/lib/docker/overlay2/abc123");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn test_path_hash_different() {
        let a = path_hash("/var/lib/docker/overlay2/abc123");
        let b = path_hash("/var/lib/docker/overlay2/def456");
        assert_ne!(a, b);
    }
}
