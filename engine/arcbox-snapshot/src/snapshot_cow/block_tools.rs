//! Block-device operations the CoW manager needs from its environment.
//!
//! The manager needs three things it cannot do through the filesystem
//! alone: attach a file as a loop device, detach one, and read a block
//! device's size. Which program performs them is an environment fact —
//! busybox applets in the System VM's EROFS userland, `util-linux` on a
//! stock distro, or no program at all through the loop-control ioctls —
//! so [`BlockTools`] names the operations and the composer supplies the
//! implementation. [`BusyboxBlockTools`] is the reference: the System VM's
//! behaviour, unchanged.
//!
//! Device-node helpers that only need syscalls (`stat`, `mknod`) are plain
//! functions here rather than trait methods: there is nothing environment
//! specific about them once they stop shelling out.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Result, SnapshotError};

/// Loop-device and block-size operations, supplied by the composer.
///
/// Every method is synchronous and may block on a subprocess or an ioctl;
/// [`CowManager`](super::CowManager) calls them from `spawn_blocking`.
/// Implementations are shared across sandboxes and tasks, hence
/// `Send + Sync`.
pub trait BlockTools: Send + Sync {
    /// Attach `backing` as a loop device and return the device path
    /// (`/dev/loopN`). Allocation and attach must be one atomic step against
    /// concurrent callers (`losetup -f --show`, or `LOOP_CONFIGURE`).
    fn attach_loop(&self, backing: &Path, read_only: bool) -> Result<String>;

    /// Detach a loop device.
    fn detach_loop(&self, device: &str) -> Result<()>;

    /// Size of a block device in 512-byte sectors.
    fn device_sectors(&self, device: &str) -> Result<u64>;
}

/// [`BlockTools`] over busybox applets — the System VM's userland.
///
/// Every operation runs `<busybox> <applet> …`; the applets are `losetup`
/// (busybox ≥ 1.21 for `-f --show`) and `blockdev`.
#[derive(Debug, Clone)]
pub struct BusyboxBlockTools {
    busybox: PathBuf,
}

impl BusyboxBlockTools {
    /// Where the System VM's EROFS rootfs installs busybox.
    pub const DEFAULT_PATH: &'static str = "/bin/busybox";

    /// Use the busybox binary at `busybox`.
    pub fn new(busybox: impl Into<PathBuf>) -> Self {
        Self {
            busybox: busybox.into(),
        }
    }

    fn run(&self, applet: &str, args: &[&str]) -> Result<std::process::Output> {
        Command::new(&self.busybox)
            .arg(applet)
            .args(args)
            .output()
            .map_err(|e| {
                SnapshotError::DeviceMapper(format!(
                    "spawn {} {applet}: {e}",
                    self.busybox.display()
                ))
            })
    }
}

impl Default for BusyboxBlockTools {
    fn default() -> Self {
        Self::new(Self::DEFAULT_PATH)
    }
}

impl BlockTools for BusyboxBlockTools {
    /// Uses the atomic `losetup -f --show` form so the kernel allocates and
    /// attaches in a single `LOOP_CTL_GET_FREE`+`LOOP_SET_FD` call, avoiding
    /// the TOCTOU window of separate `-f` then `attach` invocations against
    /// other processes that might claim the same slot.
    fn attach_loop(&self, backing: &Path, read_only: bool) -> Result<String> {
        let backing_str = backing
            .to_str()
            .ok_or_else(|| SnapshotError::DeviceMapper("non-UTF-8 path".into()))?;
        let output = if read_only {
            self.run("losetup", &["-r", "-f", "--show", backing_str])?
        } else {
            self.run("losetup", &["-f", "--show", backing_str])?
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SnapshotError::DeviceMapper(format!(
                "losetup attach {}: {stderr}",
                backing.display()
            )));
        }
        let dev = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if dev.is_empty() {
            return Err(SnapshotError::DeviceMapper(
                "losetup --show returned empty device path".into(),
            ));
        }
        Ok(dev)
    }

    fn detach_loop(&self, device: &str) -> Result<()> {
        let output = self.run("losetup", &["-d", device])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SnapshotError::DeviceMapper(format!(
                "losetup -d {device}: {stderr}"
            )));
        }
        Ok(())
    }

    fn device_sectors(&self, device: &str) -> Result<u64> {
        let output = self.run("blockdev", &["--getsz", device])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SnapshotError::DeviceMapper(format!(
                "blockdev --getsz {device}: {stderr}"
            )));
        }
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .map_err(|e| SnapshotError::DeviceMapper(format!("blockdev parse: {e}")))
    }
}

/// The `(major, minor)` device numbers of the block device at `path`.
///
/// Follows symlinks, so `/dev/mapper/<name>` resolves whether device-mapper
/// created a node there itself (no udev, the System VM) or udev left a
/// symlink to `/dev/dm-N` (a stock distro).
#[cfg(target_os = "linux")]
pub fn device_major_minor(path: &str) -> Result<(u32, u32)> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let metadata = std::fs::metadata(path)
        .map_err(|e| SnapshotError::DeviceMapper(format!("stat {path}: {e}")))?;
    if !metadata.file_type().is_block_device() {
        return Err(SnapshotError::DeviceMapper(format!(
            "{path} is not a block device"
        )));
    }
    let dev = metadata.rdev();
    // Linux packs 12-bit majors and 20-bit minors into `dev_t`; nix hands
    // them back as `u64`, and a value outside `u32` is a corrupt node, not
    // something to truncate.
    let narrow = |what: &str, value: u64| {
        u32::try_from(value).map_err(|_| {
            SnapshotError::DeviceMapper(format!("{path}: {what} {value} out of range"))
        })
    };
    Ok((
        narrow("major", nix::sys::stat::major(dev))?,
        narrow("minor", nix::sys::stat::minor(dev))?,
    ))
}

/// Create a block device node at `node_path` for `(major, minor)`, mode 0600.
///
/// The caller owns the node's ownership: a jailer chroot `chown`s it to the
/// jailer uid/gid right after, which is why the mode need not be wider.
#[cfg(target_os = "linux")]
pub fn mknod_blkdev(node_path: &Path, major: u32, minor: u32) -> Result<()> {
    use nix::sys::stat::{Mode, SFlag, makedev, mknod};

    mknod(
        node_path,
        SFlag::S_IFBLK,
        Mode::S_IRUSR | Mode::S_IWUSR,
        makedev(u64::from(major), u64::from(minor)),
    )
    .map_err(|e| SnapshotError::DeviceMapper(format!("mknod {}: {e}", node_path.display())))
}

/// Block device nodes are a Linux concept; off Linux the crate compiles but
/// the operation is unavailable.
#[cfg(not(target_os = "linux"))]
pub fn device_major_minor(path: &str) -> Result<(u32, u32)> {
    Err(SnapshotError::Unavailable(format!(
        "block device numbers for {path}: Linux-only"
    )))
}

/// Block device nodes are a Linux concept; off Linux the crate compiles but
/// the operation is unavailable.
#[cfg(not(target_os = "linux"))]
pub fn mknod_blkdev(node_path: &Path, _major: u32, _minor: u32) -> Result<()> {
    Err(SnapshotError::Unavailable(format!(
        "mknod {}: Linux-only",
        node_path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn device_major_minor_rejects_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain");
        std::fs::write(&file, b"x").unwrap();
        let err = device_major_minor(file.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("not a block device"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn device_major_minor_reports_missing_paths() {
        let err = device_major_minor("/nonexistent/arcbox-blkdev").unwrap_err();
        assert!(err.to_string().contains("stat"), "{err}");
    }

    #[test]
    fn busybox_tools_default_to_the_system_vm_path() {
        assert_eq!(
            BusyboxBlockTools::default().busybox,
            PathBuf::from(BusyboxBlockTools::DEFAULT_PATH)
        );
    }

    #[test]
    fn busybox_tools_report_a_missing_binary() {
        let tools = BusyboxBlockTools::new("/nonexistent/arcbox-busybox");
        let err = tools.detach_loop("/dev/loop0").unwrap_err();
        assert!(err.to_string().contains("spawn"), "{err}");
    }
}
