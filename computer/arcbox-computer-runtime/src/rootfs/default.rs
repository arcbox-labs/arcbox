//! The built-in busybox + vm-agent rootfs, used when a create supplies no
//! rootfs of its own.

use std::path::Path;

use anyhow::{Context, Result, bail};
use arcbox_ext4::constants::file_mode;
use arcbox_ext4::{FormatOptions, Formatter};
use tokio::process::Command;
use uuid::Uuid;

use super::{RootfsBuilder, has_ext4_magic, rootfs_err};

/// Capacity of the default busybox rootfs image. The image file is written
/// sparsely; per-sandbox writes land in the dm-snapshot COW overlay, so this
/// bounds a sandbox's writable space, not host disk use.
const DEFAULT_ROOTFS_SIZE: u64 = 512 * 1024 * 1024;

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

        if !self.paths().vm_agent.exists() {
            bail!(
                "vm-agent not found at {}; it is staged by the host daemon next to arcbox-agent",
                self.paths().vm_agent.display()
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
            busybox: self.paths().busybox.clone(),
            vm_agent: self.paths().vm_agent.clone(),
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
        is_fresh_against(image, &[&self.paths().busybox, &self.paths().vm_agent])
    }

    /// List busybox applets via `busybox --list`.
    async fn busybox_applets(&self) -> Result<Vec<String>> {
        let output = Command::new(&self.paths().busybox)
            .arg("--list")
            .output()
            .await
            .with_context(|| format!("failed to run {} --list", self.paths().busybox.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
