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
//! Device-node helpers that only need syscalls (`stat`, `mknod`) or a
//! sysfs read are plain functions here rather than trait methods: there is
//! nothing environment specific about them once they stop shelling out.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tracing::debug;

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

/// How many free-device queries [`BusyboxBlockTools::attach_loop`] makes
/// before giving up on a device that keeps being claimed underneath it.
const ATTACH_ATTEMPTS: u32 = 8;

/// Pause between those attempts — long enough for the competing attach to
/// finish, short enough to be invisible next to the subprocess spawns.
const ATTACH_RETRY_DELAY: Duration = Duration::from_millis(5);

/// [`BlockTools`] over busybox applets — the System VM's userland.
///
/// Every operation runs `<busybox> <applet> …`; the applets are `losetup`
/// and `blockdev`. BusyBox's `losetup` has no long options at all
/// (`util-linux/losetup.c`: `[-rP] [-o OFS] {-f|LOOPDEV} FILE`), so
/// util-linux's atomic allocate-and-report form `-f --show` is an
/// unrecognized-option error there, and `-f FILE` attaches without printing
/// which device it used. Attaching is therefore two applet runs: `losetup
/// -f` prints the first free device, then `losetup [-r] /dev/loopN FILE`
/// attaches to exactly that device. Another process can claim the queried
/// device in between (`mount -o loop`, a concurrent template build), in
/// which case the attach fails and [`attach_loop`](BlockTools::attach_loop)
/// re-queries and retries, up to [`ATTACH_ATTEMPTS`] times.
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

    /// `losetup -f`: the first free loop device, as `/dev/loopN`.
    fn next_free_loop(&self) -> Result<String> {
        let output = self.run("losetup", &["-f"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SnapshotError::DeviceMapper(format!("losetup -f: {stderr}")));
        }
        parse_free_loop(&output.stdout)
    }

    /// Confirm the kernel agrees that `device` now backs `backing`.
    ///
    /// `/sys/block/loopN/loop/backing_file` is the kernel's own view of the
    /// attachment (the resolved path of the file it holds open); busybox's
    /// exit status only says its ioctls returned zero. No sysfs node — no
    /// `/sys` mounted, an unusual kernel — leaves nothing to check and is
    /// not a failure. A device that answers with a different file is
    /// detached again so a failed attach leaks nothing.
    fn verify_attached(&self, device: &str, backing: &Path) -> Result<()> {
        let Some(actual) = loop_backing_file(device)? else {
            return Ok(());
        };
        let matches = actual == backing.to_string_lossy()
            || std::fs::canonicalize(backing).is_ok_and(|path| path.to_string_lossy() == actual);
        if matches {
            return Ok(());
        }
        let detach_note = match self.detach_loop(device) {
            Ok(()) => String::new(),
            Err(detach) => format!("; and detaching it again failed: {detach}"),
        };
        Err(SnapshotError::DeviceMapper(format!(
            "{device} backs {actual}, not {}{detach_note}",
            backing.display()
        )))
    }
}

impl Default for BusyboxBlockTools {
    fn default() -> Self {
        Self::new(Self::DEFAULT_PATH)
    }
}

impl BlockTools for BusyboxBlockTools {
    /// `losetup -f`, then `losetup [-r] /dev/loopN FILE`, retried when the
    /// queried device is claimed by someone else before the attach lands.
    /// A lost race shows up either as the kernel's `EBUSY` from
    /// `LOOP_CONFIGURE`/`LOOP_SET_FD` — busybox prints "Device or resource
    /// busy" — or, when busybox notices the device is taken before it
    /// issues the ioctl, as a failure with whatever stale errno text it had
    /// on hand, so the classifier also asks sysfs whether the device gained
    /// a backing file. Any other failure is reported with busybox's stderr.
    fn attach_loop(&self, backing: &Path, read_only: bool) -> Result<String> {
        let backing_str = backing
            .to_str()
            .ok_or_else(|| SnapshotError::DeviceMapper("non-UTF-8 path".into()))?;
        let mut last_loss = String::new();
        for attempt in 1..=ATTACH_ATTEMPTS {
            let device = self.next_free_loop()?;
            let mut args = Vec::with_capacity(3);
            if read_only {
                args.push("-r");
            }
            args.extend([device.as_str(), backing_str]);
            let output = self.run("losetup", &args)?;
            if output.status.success() {
                self.verify_attached(&device, backing)?;
                return Ok(device);
            }
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if !(is_busy_message(&stderr, backing_str) || loop_backing_file(&device)?.is_some()) {
                return Err(SnapshotError::DeviceMapper(format!(
                    "losetup {device} {}: {stderr}",
                    backing.display()
                )));
            }
            debug!(
                %device,
                attempt,
                %stderr,
                "free loop device was claimed by another process; re-querying"
            );
            last_loss = format!("{device}: {stderr}");
            std::thread::sleep(ATTACH_RETRY_DELAY);
        }
        Err(SnapshotError::DeviceMapper(format!(
            "losetup attach {}: another process claimed the free loop device on all \
             {ATTACH_ATTEMPTS} attempts (last: {last_loss})",
            backing.display()
        )))
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

/// The device `losetup -f` printed: `/dev/loopN` plus a trailing newline,
/// nothing else accepted — the name is reused verbatim as the attach target
/// and as the sysfs node to verify against.
fn parse_free_loop(stdout: &[u8]) -> Result<String> {
    let text = String::from_utf8_lossy(stdout);
    let device = text.trim();
    match device.strip_prefix("/dev/loop") {
        Some(index) if !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()) => {
            Ok(device.to_owned())
        }
        _ => Err(SnapshotError::DeviceMapper(format!(
            "losetup -f printed {device:?}, not a /dev/loopN device"
        ))),
    }
}

/// Whether a failed attach's stderr names the lost-race error: the kernel's
/// `EBUSY` from a device that was free a moment ago — "Device or resource
/// busy" under glibc, "Resource busy" under musl, however the tool spells
/// it. `losetup` echoes the backing path (`losetup: FILE: <reason>`, or
/// just `losetup: FILE` when it died with errno 0), so that path is scrubbed
/// first: a `busybox-…` template must not turn a permanent failure into a
/// phantom race.
fn is_busy_message(stderr: &str, backing: &str) -> bool {
    stderr
        .replace(backing, "")
        .to_ascii_lowercase()
        .contains("busy")
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

    #[test]
    fn free_loop_output_is_a_loop_device_with_the_newline_stripped() {
        assert_eq!(parse_free_loop(b"/dev/loop3\n").unwrap(), "/dev/loop3");
        assert_eq!(parse_free_loop(b"/dev/loop12").unwrap(), "/dev/loop12");
        for garbage in [
            &b""[..],
            b"\n",
            b"/dev/loop",
            b"/dev/loopX",
            b"loop3\n",
            b"/dev/sda1\n",
        ] {
            let err = parse_free_loop(garbage).unwrap_err();
            assert!(
                err.to_string().contains("not a /dev/loopN"),
                "{garbage:?}: {err}"
            );
        }
    }

    #[test]
    fn busy_classifier_reads_the_reason_not_the_echoed_path() {
        let img = "/tmp/x.img";
        assert!(is_busy_message(
            "losetup: /tmp/x.img: Device or resource busy\n",
            img
        ));
        assert!(is_busy_message("losetup: /tmp/x.img: Resource busy", img));
        assert!(is_busy_message("losetup: /dev/loop3: EBUSY", img));
        assert!(is_busy_message(
            "losetup: /tmp/x.img: failed to set up loop device: Device or resource busy",
            img
        ));
        assert!(!is_busy_message(
            "losetup: /tmp/x.img: No such file or directory",
            img
        ));
        assert!(!is_busy_message("", img));

        let template = "/templates/busybox-1.36.ext4";
        assert!(!is_busy_message(
            "losetup: /templates/busybox-1.36.ext4: No such file or directory",
            template
        ));
        assert!(!is_busy_message(
            "losetup: /templates/busybox-1.36.ext4",
            template
        ));
        assert!(is_busy_message(
            "losetup: /templates/busybox-1.36.ext4: Resource busy",
            template
        ));
    }

    /// A busybox stand-in: a shell script that logs every invocation's
    /// arguments to `calls` and runs `body` (a `case "$*"` over them). It
    /// hands out `/dev/loop9999`, a device no host has, so the sysfs
    /// verification finds nothing to compare and the script stays the only
    /// authority on what happened.
    fn fake_busybox(dir: &Path, body: &str) -> (BusyboxBlockTools, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        let calls = dir.join("calls");
        let script = dir.join("busybox");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\ncase \"$*\" in\n{body}\nesac\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        (BusyboxBlockTools::new(script), calls)
    }

    fn attach_calls(calls: &Path) -> Vec<String> {
        std::fs::read_to_string(calls)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with("losetup /dev/loop") || line.starts_with("losetup -r"))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn attach_queries_a_free_device_then_attaches_to_exactly_that_one() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, calls) = fake_busybox(
            dir.path(),
            "\"losetup -f\") echo /dev/loop9999 ;;\n\
             \"losetup -r /dev/loop9999 \"*) exit 0 ;;\n\
             *) echo \"unexpected: $*\" >&2; exit 2 ;;",
        );
        let backing = dir.path().join("template.ext4");
        std::fs::write(&backing, b"").unwrap();

        let device = tools.attach_loop(&backing, true).unwrap();

        assert_eq!(device, "/dev/loop9999");
        assert_eq!(
            attach_calls(&calls),
            [format!("losetup -r /dev/loop9999 {}", backing.display())]
        );
    }

    #[test]
    fn attach_retries_a_claimed_device_a_bounded_number_of_times() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, calls) = fake_busybox(
            dir.path(),
            "\"losetup -f\") echo /dev/loop9999 ;;\n\
             *) echo \"losetup: $3: Device or resource busy\" >&2; exit 1 ;;",
        );

        let err = tools
            .attach_loop(Path::new("/tmp/cow.img"), false)
            .unwrap_err();

        assert!(err.to_string().contains("8 attempts"), "{err}");
        assert_eq!(attach_calls(&calls).len(), 8);
    }

    #[test]
    fn attach_reports_any_other_failure_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, calls) = fake_busybox(
            dir.path(),
            "\"losetup -f\") echo /dev/loop9999 ;;\n\
             *) echo \"losetup: /tmp/cow.img: No such file or directory\" >&2; exit 1 ;;",
        );

        let err = tools
            .attach_loop(Path::new("/tmp/cow.img"), false)
            .unwrap_err();

        assert!(
            err.to_string().contains("No such file or directory"),
            "{err}"
        );
        assert_eq!(attach_calls(&calls).len(), 1);
    }
}
