//! Block-device operations the CoW manager needs from its environment.
//!
//! The manager needs three things it cannot do through the filesystem
//! alone: attach a file as a loop device, detach one, and read a block
//! device's size. Which program performs them is an environment fact —
//! busybox applets in the System VM's EROFS userland, `util-linux` on a
//! stock distro, or no program at all through the loop-control ioctls —
//! so [`BlockTools`] names the operations and the composer supplies the
//! implementation. Two ship here: [`BusyboxBlockTools`], the reference
//! (the System VM's behaviour, unchanged), and [`UtilLinuxBlockTools`]
//! for a stock distro's `/sbin` userland. Each gets its own file — what
//! differs between userlands is the whole tool surface, not a path; see
//! [`UtilLinuxBlockTools`] for what busybox cannot express.
//!
//! Device-node helpers that only need syscalls (`stat`, `mknod`) or a
//! sysfs read are plain functions here rather than trait methods: there is
//! nothing environment specific about them once they stop shelling out.

mod busybox;
mod util_linux;

pub use busybox::BusyboxBlockTools;
pub use util_linux::UtilLinuxBlockTools;

use std::path::Path;

use crate::error::{Result, SnapshotError};

/// Loop-device and block-size operations, supplied by the composer.
///
/// Every method is synchronous and may block on a subprocess or an ioctl;
/// [`CowManager`](super::CowManager) calls them from `spawn_blocking`.
/// Implementations are shared across sandboxes and tasks, hence
/// `Send + Sync`.
pub trait BlockTools: Send + Sync {
    /// Attach `backing` as a loop device and return the device path
    /// (`/dev/loopN`). Must hold up against concurrent callers in other
    /// processes: either allocate and attach in one atomic step
    /// (`LOOP_CONFIGURE`, util-linux `losetup -f --show`) or, when the tool
    /// cannot, query a free device, attach to it, and retry when another
    /// process claimed it in between (what [`BusyboxBlockTools`] does).
    fn attach_loop(&self, backing: &Path, read_only: bool) -> Result<String>;

    /// Detach a loop device.
    fn detach_loop(&self, device: &str) -> Result<()>;

    /// Size of a block device in 512-byte sectors.
    fn device_sectors(&self, device: &str) -> Result<u64>;
}

/// A `/dev/loopN` device name printed by a tool, with the trailing newline
/// stripped and nothing else accepted — the name is reused verbatim as an
/// attach target and as the sysfs node to verify against.
///
/// `what` names the invocation for the error message.
fn parse_loop_device(what: &str, stdout: &[u8]) -> Result<String> {
    let text = String::from_utf8_lossy(stdout);
    let device = text.trim();
    match device.strip_prefix("/dev/loop") {
        Some(index) if !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()) => {
            Ok(device.to_owned())
        }
        _ => Err(SnapshotError::DeviceMapper(format!(
            "{what} printed {device:?}, not a /dev/loopN device"
        ))),
    }
}

/// Confirm the kernel agrees that `device` now backs `backing`.
///
/// `/sys/block/loopN/loop/backing_file` is the kernel's own view of the
/// attachment (the resolved path of the file it holds open); a tool's exit
/// status only says its ioctls returned zero. No sysfs node — no `/sys`
/// mounted, an unusual kernel — leaves nothing to check and is not a
/// failure. A device that answers with a different file is detached again
/// so a failed attach leaks nothing.
fn verify_attached(tools: &dyn BlockTools, device: &str, backing: &Path) -> Result<()> {
    let Some(actual) = loop_backing_file(device)? else {
        return Ok(());
    };
    let matches = actual == backing.to_string_lossy()
        || std::fs::canonicalize(backing).is_ok_and(|path| path.to_string_lossy() == actual);
    if matches {
        return Ok(());
    }
    let detach_note = match tools.detach_loop(device) {
        Ok(()) => String::new(),
        Err(detach) => format!("; and detaching it again failed: {detach}"),
    };
    Err(SnapshotError::DeviceMapper(format!(
        "{device} backs {actual}, not {}{detach_note}",
        backing.display()
    )))
}

/// The file the kernel reports as backing loop device `device`
/// (`/dev/loopN`), read from `/sys/block/loopN/loop/backing_file`: the
/// resolved path of the file the device holds open.
///
/// `None` when the device is unattached or the sysfs node is absent — a
/// host without sysfs, or a name that is not a loop device at all.
pub(super) fn loop_backing_file(device: &str) -> Result<Option<String>> {
    let Some(name) = Path::new(device).file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    match std::fs::read_to_string(format!("/sys/block/{name}/loop/backing_file")) {
        Ok(path) => Ok(Some(path.trim().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
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
    fn a_printed_device_is_a_loop_device_with_the_newline_stripped() {
        assert_eq!(
            parse_loop_device("losetup -f", b"/dev/loop3\n").unwrap(),
            "/dev/loop3"
        );
        assert_eq!(
            parse_loop_device("losetup -f", b"/dev/loop12").unwrap(),
            "/dev/loop12"
        );
        for garbage in [
            &b""[..],
            b"\n",
            b"/dev/loop",
            b"/dev/loopX",
            b"loop3\n",
            b"/dev/sda1\n",
            // util-linux's `losetup -f` marks a device whose backing file
            // was deleted; only the bare name is a usable target.
            b"/dev/loop3 (lost)\n",
        ] {
            let err = parse_loop_device("losetup -f", garbage).unwrap_err();
            assert!(
                err.to_string().contains("not a /dev/loopN"),
                "{garbage:?}: {err}"
            );
        }
    }
}

/// Shared scaffolding for the two implementations' tests: a stand-in for
/// the real binary that records how it was invoked.
#[cfg(test)]
mod test_support {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    /// Write an executable stand-in for `name` into `dir`: a shell script
    /// that logs every invocation's arguments to `<name>.calls` and runs
    /// `body` (a `case "$*"` over them). Returns the script and the call
    /// log.
    ///
    /// Tests hand these scripts `/dev/loop9999`, a device no host has, so
    /// the sysfs verification finds nothing to compare and the script stays
    /// the only authority on what happened.
    pub(super) fn fake_tool(dir: &Path, name: &str, body: &str) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        let calls = dir.join(format!("{name}.calls"));
        let script = dir.join(name);
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\ncase \"$*\" in\n{body}\nesac\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_until_executable(&script);
        // The probe ran the script, so every test starts from an empty record.
        std::fs::remove_file(&calls).ok();
        (script, calls)
    }

    /// Every line the stand-in recorded, in invocation order.
    pub(super) fn calls(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Run the freshly written `script` until the kernel stops refusing it.
    ///
    /// A sibling test thread that forks — `CowManager::new` probes every
    /// `dmsetup` candidate, so most of this crate's tests do — between this
    /// thread's `create` and `close` leaves its child holding a write fd to
    /// the script, and Linux will not exec a file that is open for writing
    /// (`ETXTBSY`). The window closes as soon as that child execs and never
    /// reopens, since nothing writes the script again; exec'ing it until it
    /// runs is what proves the window is shut.
    fn wait_until_executable(script: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match Command::new(script).output() {
                Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "{} stayed busy for 5s",
                        script.display()
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                other => {
                    other.unwrap();
                    return;
                }
            }
        }
    }
}
