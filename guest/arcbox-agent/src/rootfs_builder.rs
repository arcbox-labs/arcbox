//! Build bootable ext4 rootfs images for sandboxes.
//!
//! Two builders live here, both backed by the pure-Rust `oci2rootfs` /
//! `arcbox-ext4` stack (no external binary, no mount, no root required for
//! the ext4 write itself):
//!
//! - [`convert_layer_to_rootfs`] — convert a Docker overlay2 layer directory
//!   to ext4, then inject `/sbin/vm-agent` via loop mount. Cached ext4
//!   images are reused to avoid redundant conversions.
//! - [`ensure_default_rootfs`] — build the default busybox + vm-agent image
//!   used when `CreateSandboxRequest` supplies no rootfs. Rebuilt when the
//!   source binaries are newer than the cached image.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use arcbox_ext4::constants::file_mode;
use arcbox_ext4::{FormatOptions, Formatter};
use tokio::process::Command;
use uuid::Uuid;

/// Path to the `vm-agent` binary (host `~/.arcbox/bin` via VirtioFS).
const VM_AGENT_BIN: &str = "/arcbox/bin/vm-agent";

/// Static busybox shipped in the guest EROFS rootfs.
const GUEST_BUSYBOX: &str = "/bin/busybox";

/// Directory for generated rootfs images (btrfs data volume, writable).
const ROOTFS_CACHE_DIR: &str = "/var/lib/arcbox/sandbox";

/// Capacity of the default busybox rootfs image. The image file is written
/// sparsely; per-sandbox writes land in the dm-snapshot COW overlay, so this
/// bounds a sandbox's writable space, not host disk use.
const DEFAULT_ROOTFS_SIZE: u64 = 512 * 1024 * 1024;

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

/// Convert an overlay2 layer directory to a bootable ext4 rootfs.
///
/// `layer_path` is a guest-visible overlay2 chain-id directory
/// (e.g. `/var/lib/docker/overlay2/<chain-id>`).
/// Returns the path to the generated (or cached) ext4 image.
pub async fn convert_layer_to_rootfs(layer_path: &str) -> Result<String> {
    if !Path::new(layer_path).exists() {
        bail!("layer path not found: {layer_path}");
    }

    // Cache key derived from the layer path (overlay2 chain-id directories
    // are content-addressed, so the path is a stable identifier).
    let hash = path_hash(layer_path);
    let ext4_path = format!("{ROOTFS_CACHE_DIR}/rootfs-{hash}.ext4");

    // Check cache.
    if Path::new(&ext4_path).exists() && has_ext4_magic(Path::new(&ext4_path)) {
        tracing::info!(path = %ext4_path, "using cached rootfs");
        return Ok(ext4_path);
    }

    tokio::fs::create_dir_all(ROOTFS_CACHE_DIR)
        .await
        .context("failed to create rootfs cache dir")?;

    let req_id = Uuid::new_v4().to_string();
    let ext4_tmp = format!("{ROOTFS_CACHE_DIR}/.rootfs-{req_id}.ext4.tmp");

    // Convert via the oci2rootfs library (blocking CPU/IO work).
    tracing::info!(layer = %layer_path, ext4 = %ext4_path, "converting overlay2 layer to ext4");
    {
        let layer = layer_path.to_owned();
        let out = ext4_tmp.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let source = oci2rootfs::Overlay2Source::open(&layer)
                .context("failed to open overlay2 layer")?;
            oci2rootfs::Converter::new(&out)
                .convert(source)
                .context("overlay2 → ext4 conversion failed")?;
            Ok(())
        })
        .await
        .context("conversion task panicked")??;
    }

    // Inject vm-agent.
    tracing::info!("injecting vm-agent into rootfs");
    if let Err(e) = inject_vm_agent(&ext4_tmp, &req_id).await {
        let _ = tokio::fs::remove_file(&ext4_tmp).await;
        return Err(e);
    }

    // Atomic rename into cache.
    tokio::fs::rename(&ext4_tmp, &ext4_path)
        .await
        .context("failed to rename ext4 into cache")?;

    tracing::info!(path = %ext4_path, "rootfs ready");
    Ok(ext4_path)
}

/// Ensure the default busybox + vm-agent rootfs exists at `path` and is
/// newer than its source binaries. Returns without touching the image when
/// it is already up to date.
/// Serializes default-rootfs builds so concurrent `create` requests don't each
/// rebuild the 512 MiB image. The atomic rename already prevents corruption;
/// this only avoids the redundant work.
fn build_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Remove leftover `*.ext4.tmp` build artifacts from the rootfs cache dir.
///
/// A rootfs build that crashed or panicked leaves a `.default-<uuid>.ext4.tmp`
/// or `.rootfs-<id>.ext4.tmp` (each up to the image size) with no owner; sweep
/// them at agent startup so repeated failures don't accrue disk usage.
pub async fn sweep_stale_tmp() {
    let Ok(mut entries) = tokio::fs::read_dir(ROOTFS_CACHE_DIR).await else {
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

pub async fn ensure_default_rootfs(path: &str) -> Result<()> {
    let image = Path::new(path);
    if is_default_rootfs_fresh(image) {
        return Ok(());
    }

    // Single-flight: a concurrent create for the same default image waits here,
    // then the re-check lets it reuse the just-built image instead of
    // redundantly rebuilding 512 MiB.
    let _build = build_lock().lock().await;
    if is_default_rootfs_fresh(image) {
        return Ok(());
    }

    if !Path::new(VM_AGENT_BIN).exists() {
        bail!(
            "vm-agent not found at {VM_AGENT_BIN}; it is staged by the host \
             daemon next to arcbox-agent"
        );
    }

    let applets = busybox_applets().await?;

    let parent = image
        .parent()
        .with_context(|| format!("default rootfs path has no parent: {path}"))?;
    tokio::fs::create_dir_all(parent)
        .await
        .context("failed to create default rootfs dir")?;

    let tmp = parent.join(format!(".default-{}.ext4.tmp", Uuid::new_v4()));
    let spec = DefaultRootfsSpec {
        busybox: GUEST_BUSYBOX.into(),
        vm_agent: VM_AGENT_BIN.into(),
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

/// True when the default rootfs image can be used as-is (no rebuild needed).
///
/// A valid ext4 image is fresh unless a build source (busybox or vm-agent)
/// is **present and newer** than it. A *missing* source is not staleness: we
/// cannot rebuild from an absent binary, so an existing valid image — e.g. a
/// caller-supplied default rootfs, or the production image on a host without
/// the dev build sources — is kept rather than clobbered.
fn is_default_rootfs_fresh(image: &Path) -> bool {
    if !has_ext4_magic(image) {
        return false;
    }
    let Ok(image_mtime) = image.metadata().and_then(|m| m.modified()) else {
        return false;
    };
    for source in [GUEST_BUSYBOX, VM_AGENT_BIN] {
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

    fmt.close().context("failed to finalize ext4 image")?;
    Ok(())
}

/// List busybox applets via `busybox --list`.
async fn busybox_applets() -> Result<Vec<String>> {
    let output = Command::new(GUEST_BUSYBOX)
        .arg("--list")
        .output()
        .await
        .with_context(|| format!("failed to run {GUEST_BUSYBOX} --list"))?;
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

/// Inject vm-agent into an ext4 image via loop mount.
async fn inject_vm_agent(ext4_path: &str, req_id: &str) -> Result<()> {
    if !Path::new(VM_AGENT_BIN).exists() {
        bail!("vm-agent not found at {VM_AGENT_BIN}");
    }

    let mount_dir = format!("/tmp/arcbox-inject-{req_id}");
    tokio::fs::create_dir_all(&mount_dir).await?;

    // Mount.
    let status = Command::new(GUEST_BUSYBOX)
        .args(["mount", "-o", "loop", ext4_path, &mount_dir])
        .status()
        .await
        .context("failed to mount ext4 for vm-agent injection")?;
    if !status.success() {
        let _ = tokio::fs::remove_dir(&mount_dir).await;
        bail!("mount -o loop failed");
    }

    // Create /sbin and copy vm-agent.
    let sbin = format!("{mount_dir}/sbin");
    tokio::fs::create_dir_all(&sbin)
        .await
        .context("failed to create /sbin in rootfs")?;
    let dest = format!("{sbin}/vm-agent");
    let copy_result = tokio::fs::copy(VM_AGENT_BIN, &dest).await;

    // chmod 755.
    if copy_result.is_ok() {
        let _ = Command::new(GUEST_BUSYBOX)
            .args(["chmod", "755", &dest])
            .status()
            .await;
    }

    // Always unmount and cleanup, even on failure.
    let _ = Command::new(GUEST_BUSYBOX)
        .args(["umount", &mount_dir])
        .status()
        .await;
    let _ = tokio::fs::remove_dir(&mount_dir).await;

    copy_result.context("failed to copy vm-agent into rootfs")?;
    Ok(())
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

        // GUEST_BUSYBOX / VM_AGENT_BIN are absolute guest paths that do not
        // exist in the host test environment, so this exercises the
        // missing-source branch directly.
        assert!(
            is_default_rootfs_fresh(&image),
            "a valid image with absent build sources must be reused, not rebuilt"
        );
        assert!(!is_default_rootfs_fresh(&dir.path().join("missing.ext4")));
    }
}
