//! Build bootable ext4 rootfs images for sandboxes.
//!
//! Two builders live here, both backed by the pure-Rust `oci2rootfs` /
//! `arcbox-ext4` stack (no external binary, no mount, no root required for
//! the ext4 write itself):
//!
//! - [`RootfsBuilder::convert_layer_to_rootfs`] — convert a staged OCI image
//!   layout (or a Docker overlay2 layer directory) to ext4, then inject
//!   `/sbin/vm-agent` through a loop mount. Cached ext4 images are reused to
//!   avoid redundant conversions.
//! - [`RootfsBuilder::ensure_default_rootfs`] — build the default busybox +
//!   vm-agent image used when a create supplies no rootfs. Rebuilt when the
//!   source binaries are newer than the cached image.
//!
//! The rootfs convention the boot protocol relies on — the agent binary at
//! `/sbin/vm-agent` (and `/sbin/init` pointing at it), `/etc/resolv.conf`
//! symlinked into the `/run` tmpfs — is enforced only by the guest failing to
//! boot, so it is implemented once, here, with the agent binary source and
//! the output location supplied by the composer through [`RootfsPaths`].

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use arcbox_ext4::constants::file_mode;
use arcbox_ext4::{FormatOptions, Formatter};
use arcbox_snapshot::snapshot_cow::BlockTools;
use tokio::process::Command;
use uuid::Uuid;

use crate::error::ComputerError;

/// Capacity of the default busybox rootfs image. The image file is written
/// sparsely; per-sandbox writes land in the dm-snapshot COW overlay, so this
/// bounds a sandbox's writable space, not host disk use.
const DEFAULT_ROOTFS_SIZE: u64 = 512 * 1024 * 1024;

/// Where the rootfs builder finds its inputs and keeps its outputs.
#[derive(Debug, Clone)]
pub struct RootfsPaths {
    /// The `vm-agent` binary injected into every image at `/sbin/vm-agent`.
    pub vm_agent: PathBuf,
    /// Directory the generated ext4 images (and their `.ext4.tmp` build
    /// files) live in.
    pub cache_dir: PathBuf,
    /// Static busybox that becomes the default rootfs's userland
    /// (`/bin/busybox` plus one applet symlink per `busybox --list` entry).
    pub busybox: PathBuf,
}

/// Builds sandbox rootfs images; see the module docs.
pub struct RootfsBuilder {
    paths: RootfsPaths,
    /// Loop-device attach/detach for the `vm-agent` injection mount.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "the injection loop mount is Linux-only; other platforms never attach"
        )
    )]
    block_tools: Arc<dyn BlockTools>,
}

/// Serializes default-rootfs builds so concurrent creates don't each rebuild
/// the 512 MiB image. Process-wide, not per builder: two builders over the
/// same paths (the service's and a startup sweep's) must not race each other
/// either. The atomic rename already prevents corruption; this only avoids
/// the redundant work.
fn build_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

impl RootfsBuilder {
    /// A builder over `paths`, mounting through `block_tools`.
    pub fn new(paths: RootfsPaths, block_tools: Arc<dyn BlockTools>) -> Self {
        Self { paths, block_tools }
    }

    /// The paths this builder was composed with.
    pub fn paths(&self) -> &RootfsPaths {
        &self.paths
    }
}

fn rootfs_err(error: anyhow::Error) -> ComputerError {
    ComputerError::Rootfs(format!("{error:#}"))
}

/// Check if a file has a valid ext4 superblock magic (0x53EF at offset 0x438).
pub fn has_ext4_magic(path: &Path) -> bool {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 2];
    file.seek(SeekFrom::Start(0x438)).is_ok()
        && file.read_exact(&mut magic).is_ok()
        && magic == [0x53, 0xEF]
}

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
        let cache_dir = &self.paths.cache_dir;
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
        let bytes = tokio::fs::read(&self.paths.vm_agent)
            .await
            .with_context(|| format!("failed to read {}", self.paths.vm_agent.display()))?;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hasher.write(&bytes);
        Ok(format!("{:016x}", hasher.finish()))
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

impl RootfsBuilder {
    /// Remove leftover `*.ext4.tmp` build artifacts from the rootfs cache dir.
    ///
    /// A rootfs build that crashed or panicked leaves a `.default-<uuid>.ext4.tmp`
    /// or `.rootfs-<id>.ext4.tmp` (each up to the image size) with no owner;
    /// sweep them at startup so repeated failures don't accrue disk usage.
    pub async fn sweep_stale_tmp(&self) {
        let Ok(mut entries) = tokio::fs::read_dir(&self.paths.cache_dir).await else {
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

    /// Ensure the default busybox + vm-agent rootfs exists at `path` and is
    /// newer than its source binaries. Returns without touching the image
    /// when it is already up to date.
    pub async fn ensure_default_rootfs(&self, path: &str) -> crate::error::Result<()> {
        self.ensure_default(path).await.map_err(rootfs_err)
    }

    async fn ensure_default(&self, path: &str) -> Result<()> {
        let image = Path::new(path);
        if self.is_default_rootfs_fresh(image) {
            return Ok(());
        }

        // Single-flight: a concurrent create for the same default image waits here,
        // then the re-check lets it reuse the just-built image instead of
        // redundantly rebuilding 512 MiB.
        let _build = build_lock().lock().await;
        if self.is_default_rootfs_fresh(image) {
            return Ok(());
        }

        if !self.paths.vm_agent.exists() {
            bail!(
                "vm-agent not found at {}; it is staged by the host daemon next to arcbox-agent",
                self.paths.vm_agent.display()
            );
        }

        let applets = self.busybox_applets().await?;

        let parent = image
            .parent()
            .with_context(|| format!("default rootfs path has no parent: {path}"))?;
        tokio::fs::create_dir_all(parent)
            .await
            .context("failed to create default rootfs dir")?;

        let tmp = parent.join(format!(".default-{}.ext4.tmp", Uuid::new_v4()));
        let spec = DefaultRootfsSpec {
            busybox: self.paths.busybox.clone(),
            vm_agent: self.paths.vm_agent.clone(),
            applets,
            size: DEFAULT_ROOTFS_SIZE,
        };

        tracing::info!(path, "building default sandbox rootfs");
        {
            let tmp = tmp.clone();
            tokio::task::spawn_blocking(move || build_default_rootfs(&spec, &tmp))
                .await
                .context("default rootfs build task panicked")??;
        }

        tokio::fs::rename(&tmp, image)
            .await
            .context("failed to move default rootfs into place")?;
        tracing::info!(path, "default sandbox rootfs ready");
        Ok(())
    }

    /// True when the default rootfs image can be used as-is (no rebuild
    /// needed).
    ///
    /// A valid ext4 image is fresh unless a build source (busybox or
    /// vm-agent) is **present and newer** than it. A *missing* source is not
    /// staleness: we cannot rebuild from an absent binary, so an existing
    /// valid image — e.g. a caller-supplied default rootfs, or the production
    /// image on a host without the dev build sources — is kept rather than
    /// clobbered.
    fn is_default_rootfs_fresh(&self, image: &Path) -> bool {
        is_fresh_against(image, &[&self.paths.busybox, &self.paths.vm_agent])
    }

    /// List busybox applets via `busybox --list`.
    async fn busybox_applets(&self) -> Result<Vec<String>> {
        let output = Command::new(&self.paths.busybox)
            .arg("--list")
            .output()
            .await
            .with_context(|| format!("failed to run {} --list", self.paths.busybox.display()))?;
        if !output.status.success() {
            bail!("busybox --list failed with {}", output.status);
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect())
    }
}

/// [`RootfsBuilder::is_default_rootfs_fresh`] over explicit sources.
fn is_fresh_against(image: &Path, sources: &[&Path]) -> bool {
    if !has_ext4_magic(image) {
        return false;
    }
    let Ok(image_mtime) = image.metadata().and_then(|m| m.modified()) else {
        return false;
    };
    for source in sources {
        // Only a source that exists AND is newer forces a rebuild.
        if let Ok(mtime) = std::fs::metadata(source).and_then(|m| m.modified())
            && mtime > image_mtime
        {
            return false;
        }
    }
    true
}

/// Inputs for [`build_default_rootfs`].
struct DefaultRootfsSpec {
    /// Static busybox binary copied to `/bin/busybox`.
    busybox: std::path::PathBuf,
    /// vm-agent binary copied to `/sbin/vm-agent` (the sandbox init).
    vm_agent: std::path::PathBuf,
    /// Applet names to symlink into `/bin` (from `busybox --list`).
    applets: Vec<String>,
    /// ext4 image capacity in bytes.
    size: u64,
}

/// Write a minimal bootable rootfs: busybox + applet symlinks + vm-agent as
/// `/sbin/vm-agent` (and `/sbin/init`), plus the standard directory skeleton.
fn build_default_rootfs(spec: &DefaultRootfsSpec, out: &Path) -> Result<()> {
    const DIR: u16 = file_mode::S_IFDIR | 0o755;
    const EXE: u16 = file_mode::S_IFREG | 0o755;
    const LNK: u16 = file_mode::S_IFLNK | 0o777;

    let mut fmt = Formatter::with_options(out, FormatOptions::new(spec.size).label("arcbox-sbx"))
        .context("failed to create ext4 formatter")?;

    for dir in [
        "/bin", "/sbin", "/dev", "/proc", "/sys", "/run", "/etc", "/root", "/var",
    ] {
        fmt.create(dir, DIR, None, None, None, None, None, None)
            .with_context(|| format!("mkdir {dir}"))?;
    }
    // World-writable sticky /tmp.
    fmt.create(
        "/tmp",
        file_mode::S_IFDIR | file_mode::S_ISVTX | 0o777,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .context("mkdir /tmp")?;

    let mut busybox = std::fs::File::open(&spec.busybox)
        .with_context(|| format!("failed to open {}", spec.busybox.display()))?;
    fmt.create(
        "/bin/busybox",
        EXE,
        None,
        None,
        Some(&mut busybox),
        None,
        None,
        None,
    )
    .context("write /bin/busybox")?;

    for applet in &spec.applets {
        if applet == "busybox" || applet.contains('/') {
            continue;
        }
        let path = format!("/bin/{applet}");
        fmt.create(&path, LNK, Some("busybox"), None, None, None, None, None)
            .with_context(|| format!("symlink {path}"))?;
    }

    let mut vm_agent = std::fs::File::open(&spec.vm_agent)
        .with_context(|| format!("failed to open {}", spec.vm_agent.display()))?;
    fmt.create(
        "/sbin/vm-agent",
        EXE,
        None,
        None,
        Some(&mut vm_agent),
        None,
        None,
        None,
    )
    .context("write /sbin/vm-agent")?;
    // Fallback for boot args that omit init=: PID 1 is still vm-agent.
    fmt.create(
        "/sbin/init",
        LNK,
        Some("vm-agent"),
        None,
        None,
        None,
        None,
        None,
    )
    .context("symlink /sbin/init")?;

    let passwd = "root:x:0:0:root:/root:/bin/sh\n";
    fmt.create(
        "/etc/passwd",
        file_mode::S_IFREG | 0o644,
        None,
        None,
        Some(&mut passwd.as_bytes()),
        None,
        None,
        None,
    )
    .context("write /etc/passwd")?;
    let group = "root:x:0:\n";
    fmt.create(
        "/etc/group",
        file_mode::S_IFREG | 0o644,
        None,
        None,
        Some(&mut group.as_bytes()),
        None,
        None,
        None,
    )
    .context("write /etc/group")?;

    // resolv.conf lives on tmpfs (/run, mounted by vm-agent): DNS writes on
    // the post-restore reconfig path must not touch the block device — the
    // clone's first ext4 write pays a synchronous dm-snapshot CoW exception
    // through the nested I/O stack, measured at ~30 ms (CORE-75).
    fmt.create(
        "/etc/resolv.conf",
        LNK,
        Some("../run/resolv.conf"),
        None,
        None,
        None,
        None,
        None,
    )
    .context("symlink /etc/resolv.conf")?;

    fmt.close().context("failed to finalize ext4 image")?;
    Ok(())
}

impl RootfsBuilder {
    /// Inject vm-agent into an ext4 image through a loop mount.
    ///
    /// The image is attached as a loop device through the composer's
    /// [`BlockTools`] and mounted with `mount(2)`; nothing here shells out.
    /// Success means the agent is in the image *and* every resource is
    /// released again: an image whose mount or loop device could not be
    /// torn down is not published, because the caller's rename would cache
    /// a file another mount holds and a leaked `/dev/loopN` per build would
    /// eventually exhaust the pool.
    #[cfg(target_os = "linux")]
    async fn inject_vm_agent(&self, ext4_path: &str, req_id: &str) -> Result<()> {
        if !self.paths.vm_agent.exists() {
            bail!("vm-agent not found at {}", self.paths.vm_agent.display());
        }

        // Attach first: a failed attach (no free loop device, tooling
        // missing) then leaves nothing behind.
        let loop_dev = self
            .attach_loop(ext4_path)
            .await
            .context("failed to attach ext4 image for vm-agent injection")?;
        let mount_dir = std::env::temp_dir().join(format!("arcbox-inject-{req_id}"));
        let staged = match tokio::fs::create_dir_all(&mount_dir).await {
            Ok(()) => mount_ext4(&loop_dev, &mount_dir)
                .await
                .with_context(|| format!("mount {loop_dev} for vm-agent injection")),
            Err(e) => Err(e).context("failed to create injection mount dir"),
        };
        if let Err(error) = staged {
            // Nothing is mounted yet: give the loop device back and report
            // the original failure (plus the detach's, should it also fail).
            let mut failures = Vec::new();
            self.detach_loop(&loop_dev)
                .await
                .push_failure(&mut failures);
            let _ = tokio::fs::remove_dir(&mount_dir).await;
            return Err(match failures.pop() {
                Some(detach) => error.context(format!("and then {detach}")),
                None => error,
            });
        }

        let injected = self.write_agent_into(&mount_dir).await;

        // Release everything, collecting rather than short-circuiting so a
        // failed step never skips the ones after it.
        let mut failures = Vec::new();
        unmount(&mount_dir).await.push_failure(&mut failures);
        self.detach_loop(&loop_dev)
            .await
            .push_failure(&mut failures);
        let _ = tokio::fs::remove_dir(&mount_dir).await;

        if !failures.is_empty() {
            bail!(
                "vm-agent injection left resources behind: {}",
                failures.join("; ")
            );
        }
        injected
    }

    /// Copy the agent to `/sbin/vm-agent` (mode 755) and point
    /// `/etc/resolv.conf` at the `/run` tmpfs inside the mounted image.
    #[cfg(target_os = "linux")]
    async fn write_agent_into(&self, mount_dir: &Path) -> Result<()> {
        let sbin = mount_dir.join("sbin");
        let dest = sbin.join("vm-agent");
        tokio::fs::create_dir_all(&sbin)
            .await
            .context("failed to create /sbin in rootfs")?;
        tokio::fs::copy(&self.paths.vm_agent, &dest)
            .await
            .context("failed to copy vm-agent into rootfs")?;
        tokio::fs::set_permissions(&dest, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .await
            .context("failed to chmod vm-agent in rootfs")?;

        // Point resolv.conf at tmpfs, mirroring the default template: DNS
        // rewrites must stay off the CoW block device (CORE-75). Rewriting
        // is safe for Docker images — Docker itself never ships meaningful
        // resolv.conf content (it bind-mounts one at run time).
        let etc = mount_dir.join("etc");
        if tokio::fs::create_dir_all(&etc).await.is_ok() {
            let resolv = etc.join("resolv.conf");
            let _ = tokio::fs::remove_file(&resolv).await;
            if let Err(e) = tokio::fs::symlink("../run/resolv.conf", &resolv).await {
                tracing::warn!(error = %e, "resolv.conf symlink failed; DNS rewrites will hit the CoW device");
            }
        }
        Ok(())
    }

    /// Loop mounts are a Linux operation; the builder compiles elsewhere but
    /// cannot inject.
    #[cfg(not(target_os = "linux"))]
    async fn inject_vm_agent(&self, _ext4_path: &str, _req_id: &str) -> Result<()> {
        bail!("vm-agent injection needs a Linux loop mount")
    }

    /// [`BlockTools::attach_loop`] on a blocking thread.
    #[cfg(target_os = "linux")]
    async fn attach_loop(&self, image: &str) -> Result<String> {
        let tools = Arc::clone(&self.block_tools);
        let image = PathBuf::from(image);
        tokio::task::spawn_blocking(move || tools.attach_loop(&image, false))
            .await
            .context("loop attach task panicked")?
            .map_err(anyhow::Error::from)
    }

    /// [`BlockTools::detach_loop`] on a blocking thread.
    ///
    /// The kernel accepts `LOOP_CLR_FD` on a device that still has users
    /// (it flags the device autoclear and frees it when the last one goes),
    /// so this succeeds after a lazy unmount as well as a clean one.
    #[cfg(target_os = "linux")]
    async fn detach_loop(&self, loop_dev: &str) -> Result<()> {
        let tools = Arc::clone(&self.block_tools);
        let dev = loop_dev.to_owned();
        tokio::task::spawn_blocking(move || tools.detach_loop(&dev))
            .await
            .context("loop detach task panicked")?
            .with_context(|| format!("detach {loop_dev}"))
    }
}

/// `mount(2)` an ext4 image's loop device at `dir`, off the executor —
/// mounting can replay the journal.
#[cfg(target_os = "linux")]
async fn mount_ext4(loop_dev: &str, dir: &Path) -> Result<()> {
    use nix::mount::{MsFlags, mount};

    let dev = loop_dev.to_owned();
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        mount(
            Some(dev.as_str()),
            &dir,
            Some("ext4"),
            MsFlags::empty(),
            None::<&str>,
        )
    })
    .await
    .context("mount task panicked")?
    .map_err(anyhow::Error::from)
}

/// `umount(2)` `dir`, falling back to a lazy unmount (`MNT_DETACH`) when
/// something still holds the tree, so the following loop detach can at
/// least schedule the device's release instead of stranding it.
#[cfg(target_os = "linux")]
async fn unmount(dir: &Path) -> Result<()> {
    use nix::mount::{MntFlags, umount, umount2};

    let target = dir.to_path_buf();
    tokio::task::spawn_blocking(move || match umount(&target) {
        Ok(()) => Ok(()),
        // Still busy: detach the tree lazily so the loop device can be
        // released once the last user goes, and report the unmount as
        // failed either way — the image is not safe to publish.
        Err(busy) => match umount2(&target, MntFlags::MNT_DETACH) {
            Ok(()) => bail!(
                "umount {}: {busy} (lazily detached instead)",
                target.display()
            ),
            Err(lazy) => bail!("umount {}: {busy}; lazy unmount: {lazy}", target.display()),
        },
    })
    .await
    .context("umount task panicked")?
}

/// Collect a step's failure without stopping the cleanup sequence.
#[cfg(target_os = "linux")]
trait PushFailure {
    fn push_failure(self, failures: &mut Vec<String>);
}

#[cfg(target_os = "linux")]
impl PushFailure for Result<()> {
    fn push_failure(self, failures: &mut Vec<String>) {
        if let Err(e) = self {
            failures.push(format!("{e:#}"));
        }
    }
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
    fn test_has_ext4_magic_nonexistent() {
        assert!(!has_ext4_magic(Path::new("/nonexistent")));
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

    #[test]
    fn default_rootfs_builds_and_contains_init_chain() {
        let dir = tempfile::tempdir().unwrap();
        let busybox = dir.path().join("busybox");
        let vm_agent = dir.path().join("vm-agent");
        std::fs::write(&busybox, b"#!busybox-stub").unwrap();
        std::fs::write(&vm_agent, b"#!vm-agent-stub").unwrap();

        let out = dir.path().join("rootfs.ext4");
        let spec = DefaultRootfsSpec {
            busybox,
            vm_agent,
            applets: vec!["sh".into(), "ls".into(), "busybox".into()],
            size: 8 * 1024 * 1024,
        };
        build_default_rootfs(&spec, &out).unwrap();

        assert!(has_ext4_magic(&out));

        let reader = arcbox_ext4::Reader::new(&out).unwrap();
        for path in [
            "/bin/busybox",
            "/sbin/vm-agent",
            "/sbin/init",
            "/bin/sh",
            "/etc/passwd",
        ] {
            assert!(
                reader.tree().lookup(Path::new(path)).is_some(),
                "missing {path}"
            );
        }
        assert!(
            reader
                .tree()
                .lookup(Path::new("/bin/nonexistent"))
                .is_none()
        );
    }

    #[test]
    fn existing_image_is_fresh_when_build_sources_are_absent() {
        // A valid ext4 default rootfs must be reused as-is when the dev build
        // sources (/bin/busybox, /arcbox/bin/vm-agent) don't exist — the case
        // of a caller-supplied default rootfs on a host without the build
        // toolchain. Regression for the sandbox_service_manager integration
        // test, which passes an empty request rootfs backed by a real image.
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("rootfs.ext4");
        let spec = DefaultRootfsSpec {
            busybox: dir.path().join("busybox"),
            vm_agent: dir.path().join("vm-agent"),
            applets: vec!["sh".into()],
            size: 8 * 1024 * 1024,
        };
        std::fs::write(&spec.busybox, b"stub").unwrap();
        std::fs::write(&spec.vm_agent, b"stub").unwrap();
        build_default_rootfs(&spec, &image).unwrap();
        assert!(has_ext4_magic(&image));

        // Sources that do not exist exercise the missing-source branch
        // directly.
        let absent = dir.path().join("absent");
        assert!(
            is_fresh_against(&image, &[&absent, &absent]),
            "a valid image with absent build sources must be reused, not rebuilt"
        );
        assert!(!is_fresh_against(
            &dir.path().join("missing.ext4"),
            &[&absent]
        ));
        // A source that exists and is newer than the image forces a rebuild.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let newer = dir.path().join("newer-agent");
        std::fs::write(&newer, b"stub").unwrap();
        assert!(!is_fresh_against(&image, &[&newer]));
    }
}
