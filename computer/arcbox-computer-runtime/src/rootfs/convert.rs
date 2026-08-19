//! Convert an image source to a bootable ext4 rootfs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use super::{
    ROOTFS_CAPACITY_GRANULARITY, RootfsBuilder, RootfsSource, RootfsSpec, has_ext4_magic,
    rootfs_err,
};
use crate::error::VmmError;

/// Marker file that identifies an OCI image layout directory.
const OCI_LAYOUT_MARKER: &str = "oci-layout";

/// Capacity of the sandbox-template images cached under
/// [`RootfsPaths::cache_dir`](super::RootfsPaths::cache_dir).
///
/// Deliberately absent from the cache key below: this path has exactly one
/// value, and that key's stem is what the template catalog derives a
/// template digest from (`arcbox-agent`'s `sandbox::templates`), so keying on
/// the capacity would churn every published digest. A caller that needs
/// another capacity uses [`RootfsBuilder::build_rootfs`] and owns the path.
const TEMPLATE_ROOTFS_SIZE: u64 = 512 * 1024 * 1024;

/// True when `dir` is an OCI image layout rather than an overlay2 layer.
///
/// Dispatching on the marker keeps the choice explicit: a `docker save`
/// layout also carries a legacy `manifest.json`, so leaning on the
/// `oci2rootfs` autodetect heuristics would be guesswork.
fn is_oci_layout(dir: &Path) -> bool {
    dir.join(OCI_LAYOUT_MARKER).is_file()
}

impl RootfsBuilder {
    /// Build one bootable ext4 rootfs at the capacity and path the caller
    /// chose, with `vm-agent` injected.
    ///
    /// This is how a node produces a Computer image: the caller resolves the
    /// image (its own registry pull, so it keeps the `ImageConfig` and
    /// manifest digest), states the capacity, and names the product, while
    /// the rootfs boot convention stays here. Nothing is cached and nothing
    /// is swept — the path is the caller's, and so is its lifetime.
    ///
    /// The image is built as a sibling `.<uuid>.ext4.tmp` and renamed into
    /// place, so `out` is either the previous image or the new one, never a
    /// half-written file. A build killed mid-conversion leaves that temp
    /// behind for its owner to reap.
    ///
    /// `spec.size` must be a positive multiple of
    /// [`ROOTFS_CAPACITY_GRANULARITY`] — checked here, before the conversion,
    /// because the alternative is spending minutes writing an image no kernel
    /// will mount.
    pub async fn build_rootfs(&self, spec: RootfsSpec) -> crate::error::Result<()> {
        let RootfsSpec { source, out, size } = spec;
        if size == 0 || size % ROOTFS_CAPACITY_GRANULARITY != 0 {
            return Err(VmmError::Config(format!(
                "rootfs capacity {size} must be a positive multiple of \
                 {ROOTFS_CAPACITY_GRANULARITY} bytes (one ext4 block group); \
                 anything else declares more blocks than the image holds and \
                 cannot be mounted"
            )));
        }
        tracing::info!(out = %out.display(), size, "building rootfs");
        self.write_and_publish(source, &out, size)
            .await
            .map_err(rootfs_err)?;
        tracing::info!(out = %out.display(), "rootfs ready");
        Ok(())
    }

    /// Convert `source` into a fresh ext4 image, inject `vm-agent`, and
    /// publish it at `out` — the one place all three steps are ordered.
    async fn write_and_publish(&self, source: RootfsSource, out: &Path, size: u64) -> Result<()> {
        let parent = out
            .parent()
            .with_context(|| format!("rootfs path has no parent: {}", out.display()))?;
        tokio::fs::create_dir_all(parent)
            .await
            .context("failed to create the rootfs output directory")?;
        let tmp = parent.join(format!(".{}.ext4.tmp", Uuid::new_v4()));

        let written = {
            let tmp = tmp.clone();
            tokio::task::spawn_blocking(move || {
                write_image(source, &tmp, size).and_then(|()| verify_geometry(&tmp))
            })
            .await
            .context("conversion task panicked")?
        };

        // Nothing partial survives: a failed conversion, an image the kernel
        // would refuse, or a failed injection all take the temp with them.
        let staged = match written {
            Ok(()) => {
                tracing::debug!(image = %tmp.display(), "injecting vm-agent into rootfs");
                self.inject_agent(&tmp).await
            }
            Err(e) => Err(e),
        };
        if let Err(e) = staged {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }

        tokio::fs::rename(&tmp, out)
            .await
            .context("failed to move the rootfs into place")
    }

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
        let cache_dir = self.paths().cache_dir.clone();
        let ext4_path = cache_dir.join(format!("rootfs-{layer_key}-{agent_key}.ext4"));

        // Check cache.
        if has_ext4_magic(&ext4_path) {
            tracing::info!(path = %ext4_path.display(), "using cached rootfs");
            return Ok(path_string(&ext4_path));
        }

        tracing::info!(layer = %layer_path, ext4 = %ext4_path.display(), "converting image layer to ext4");
        self.write_and_publish(
            RootfsSource::Directory(PathBuf::from(layer_path)),
            &ext4_path,
            TEMPLATE_ROOTFS_SIZE,
        )
        .await?;

        sweep_superseded(&cache_dir, &layer_key, &agent_key, pinned).await;

        tracing::info!(path = %ext4_path.display(), "rootfs ready");
        Ok(path_string(&ext4_path))
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

/// Write `source` into a fresh ext4 image of exactly `size` bytes.
///
/// Blocking CPU/IO work — layer decompression and the ext4 write — so this
/// runs on a blocking thread. A resolved [`RootfsSource::Image`] carries its
/// own layers; a directory is opened here, dispatching on the OCI layout
/// marker. `oci2rootfs` removes a partial output itself, so a failure leaves
/// no image behind.
fn write_image(source: RootfsSource, out: &Path, size: u64) -> Result<()> {
    let converter = oci2rootfs::Converter::new(out).size(size);
    match source {
        RootfsSource::Image(image) => converter
            .convert(image)
            .context("image → ext4 conversion failed")?,
        RootfsSource::Directory(dir) if is_oci_layout(&dir) => {
            let source = oci2rootfs::OciLayoutSource::open(&dir)
                .context("failed to open OCI image layout")?;
            converter
                .convert(source)
                .context("OCI layout → ext4 conversion failed")?;
        }
        RootfsSource::Directory(dir) => {
            let source =
                oci2rootfs::Overlay2Source::open(&dir).context("failed to open overlay2 layer")?;
            converter
                .convert(source)
                .context("overlay2 → ext4 conversion failed")?;
        }
    }
    Ok(())
}

/// Refuse an image whose superblock claims more space than the file has.
///
/// The capacity check in [`RootfsBuilder::build_rootfs`] covers the way this
/// normally happens, but the block count is rounded up for want of *inodes*
/// too — a small image holding more files than one block group's worth of
/// them lands past the end of its own device with a legal capacity. Reading
/// the written superblock catches every shape of it, and turns what would
/// otherwise be an `EINVAL` at mount time into something a caller can act on.
fn verify_geometry(image: &Path) -> Result<()> {
    let reader = arcbox_ext4::Reader::new(image)
        .with_context(|| format!("failed to read back {}", image.display()))?;
    let block = reader.superblock();
    let block_size = 1024u64 << block.log_block_size;
    let declared =
        ((u64::from(block.blocks_count_hi) << 32) | u64::from(block.blocks_count_lo)) * block_size;
    let file = std::fs::metadata(image)
        .with_context(|| format!("failed to stat {}", image.display()))?
        .len();
    if declared > file {
        bail!(
            "the ext4 image declares {declared} bytes but holds {file}; a capacity that is a \
             multiple of {} bytes ({} blocks per group) keeps the two equal",
            u64::from(block.blocks_per_group) * block_size,
            block.blocks_per_group
        );
    }
    Ok(())
}

/// The cached-image path as the sandbox spec carries it.
fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
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
    use std::sync::Arc;

    use arcbox_snapshot::snapshot_cow::BusyboxBlockTools;

    use super::*;
    use crate::rootfs::RootfsPaths;

    /// The smallest capacity a kernel will mount: one whole block group.
    const ONE_GROUP: u64 = ROOTFS_CAPACITY_GRANULARITY;

    /// A minimal overlay2 chain-id directory — `diff/` plus the `link` file
    /// `Overlay2Source` insists on — holding one file to prove the contents
    /// reach the image.
    fn overlay2_layer(root: &Path) -> PathBuf {
        let layer = root.join("ABCDEF");
        std::fs::create_dir_all(layer.join("diff/etc")).unwrap();
        std::fs::write(layer.join("diff/etc/hostname"), b"computer\n").unwrap();
        std::fs::write(layer.join("link"), "ABCDEF").unwrap();
        layer
    }

    fn builder_over(dir: &Path, vm_agent: PathBuf) -> RootfsBuilder {
        RootfsBuilder::new(
            RootfsPaths {
                vm_agent,
                cache_dir: dir.join("cache"),
                busybox: dir.join("absent-busybox"),
            },
            Arc::new(BusyboxBlockTools::default()),
        )
    }

    #[test]
    fn the_conversion_honours_the_capacity_and_path_it_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let layer = overlay2_layer(dir.path());
        // A path of the caller's choosing, in a directory of its own — not
        // the builder's cache, and not the builder's naming.
        let out = dir.path().join("images/sha256-deadbeef.ext4");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        let size = 2 * ONE_GROUP;

        write_image(RootfsSource::Directory(layer), &out, size).unwrap();

        assert!(has_ext4_magic(&out));
        assert_eq!(
            std::fs::metadata(&out).unwrap().len(),
            size,
            "the image must have exactly the requested capacity, not oci2rootfs' default"
        );
        verify_geometry(&out).expect("a whole number of block groups must be mountable");
        let reader = arcbox_ext4::Reader::new(&out).unwrap();
        assert!(
            reader.tree().lookup(Path::new("/etc/hostname")).is_some(),
            "the layer's contents must be in the image"
        );
    }

    #[tokio::test]
    async fn a_capacity_that_is_not_whole_block_groups_is_refused_before_any_work() {
        let dir = tempfile::tempdir().unwrap();
        let builder = builder_over(dir.path(), dir.path().join("vm-agent"));
        let out = dir.path().join("images/computer.ext4");

        for size in [0, ONE_GROUP - 1, ONE_GROUP + 4096, 30_000_000_000] {
            let error = builder
                .build_rootfs(RootfsSpec {
                    source: RootfsSource::Directory(overlay2_layer(dir.path())),
                    out: out.clone(),
                    size,
                })
                .await
                .expect_err("a capacity that cannot be mounted must be refused");
            assert!(
                matches!(error, VmmError::Config(_)),
                "a bad capacity is the caller's argument, so a 400 rather than a 500: {error}"
            );
            // Refused before the conversion, which for a real image is minutes
            // of work: not even the output directory exists yet.
            assert!(!out.parent().unwrap().exists(), "size {size} did work");
        }
    }

    #[test]
    fn an_image_that_outgrew_its_device_is_not_published() {
        // What the capacity rule protects against, pinned against the
        // formatter rather than described: at any capacity short of a whole
        // group, `arcbox-ext4` rounds the superblock's block count up past
        // the end of the file, and the kernel answers a mount with
        // `EXT4-fs: bad geometry` / EINVAL.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("short.ext4");
        write_image(
            RootfsSource::Directory(overlay2_layer(dir.path())),
            &out,
            ONE_GROUP / 2,
        )
        .unwrap();

        let error = format!(
            "{:#}",
            verify_geometry(&out).expect_err("an over-declared image must not be published")
        );
        assert!(
            error.contains(&ROOTFS_CAPACITY_GRANULARITY.to_string()),
            "{error}"
        );
    }

    #[test]
    fn the_capacity_this_crate_picks_for_itself_is_mountable() {
        // The sandbox-template path names its own capacity, out of reach of
        // `build_rootfs`'s check; an edit that makes it un-mountable would
        // otherwise only surface as a failed sandbox boot.
        assert_eq!(TEMPLATE_ROOTFS_SIZE % ROOTFS_CAPACITY_GRANULARITY, 0);
    }

    #[test]
    fn the_source_dispatch_follows_the_layout_marker() {
        let dir = tempfile::tempdir().unwrap();
        let layer = overlay2_layer(dir.path());
        // The marker makes the very same directory an OCI layout, whose
        // parse then fails for want of an index — which reader ran is what
        // the error names.
        std::fs::write(
            layer.join(OCI_LAYOUT_MARKER),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();

        let error = write_image(
            RootfsSource::Directory(layer),
            &dir.path().join("out.ext4"),
            ONE_GROUP,
        )
        .unwrap_err();

        let error = format!("{error:#}");
        assert!(error.contains("OCI image layout"), "{error}");
    }

    #[tokio::test]
    async fn a_build_that_cannot_inject_the_agent_publishes_nothing() {
        // An absent vm-agent is refused before anything is attached or
        // mounted, so the cleanup path runs on every platform and without
        // root.
        let dir = tempfile::tempdir().unwrap();
        let builder = builder_over(dir.path(), dir.path().join("absent-vm-agent"));
        let out = dir.path().join("images/computer.ext4");

        let error = builder
            .build_rootfs(RootfsSpec {
                source: RootfsSource::Directory(overlay2_layer(dir.path())),
                out: out.clone(),
                size: ONE_GROUP,
            })
            .await
            .unwrap_err();

        assert!(format!("{error}").contains("vm-agent"), "{error}");
        assert!(!out.exists(), "a failed build must publish nothing");
        assert_eq!(
            std::fs::read_dir(out.parent().unwrap()).unwrap().count(),
            0,
            "the temp build file must not outlive the failure — nothing sweeps a caller's directory"
        );
    }

    #[tokio::test]
    async fn the_template_cache_answers_with_the_stem_a_digest_is_derived_from() {
        // `rootfs-<layer>-<agent>` is not just a file name: the template
        // catalog reads that stem as the image's source identity. A rename
        // here silently changes every published template digest.
        let dir = tempfile::tempdir().unwrap();
        let vm_agent = dir.path().join("vm-agent");
        std::fs::write(&vm_agent, b"#!vm-agent-stub").unwrap();
        let builder = builder_over(dir.path(), vm_agent);
        let layer = overlay2_layer(dir.path());
        let layer_path = layer.to_string_lossy().into_owned();

        let cached = builder.paths().cache_dir.join(format!(
            "rootfs-{}-{}.ext4",
            path_hash(&layer_path),
            builder.vm_agent_key().await.unwrap()
        ));
        std::fs::create_dir_all(&builder.paths().cache_dir).unwrap();
        write_image(RootfsSource::Directory(layer), &cached, ONE_GROUP).unwrap();

        let answered = builder
            .convert_layer_to_rootfs(&layer_path, &BTreeSet::new())
            .await
            .unwrap();

        assert_eq!(answered, path_string(&cached));
        let stem = Path::new(&answered).file_stem().unwrap().to_str().unwrap();
        let keys = stem.strip_prefix("rootfs-").expect("stem prefix");
        let (layer_key, agent_key) = keys.split_once('-').expect("two content keys");
        assert_eq!((layer_key.len(), agent_key.len()), (16, 16));
    }

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
