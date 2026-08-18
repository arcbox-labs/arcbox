//! [`BlockTools`] over busybox applets — the System VM's userland.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tracing::debug;

use crate::error::{Result, SnapshotError};

use super::{BlockTools, loop_backing_file, parse_loop_device, verify_attached};

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
        parse_loop_device("losetup -f", &output.stdout)
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
                verify_attached(self, &device, backing)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{calls, fake_tool};

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

    /// A busybox stand-in whose `case "$*"` body decides what each applet
    /// run does; see `fake_tool`.
    fn fake_busybox(dir: &Path, body: &str) -> (BusyboxBlockTools, PathBuf) {
        let (script, log) = fake_tool(dir, "busybox", body);
        (BusyboxBlockTools::new(script), log)
    }

    fn attach_calls(log: &Path) -> Vec<String> {
        calls(log)
            .into_iter()
            .filter(|line| line.starts_with("losetup /dev/loop") || line.starts_with("losetup -r"))
            .collect()
    }

    #[test]
    fn attach_queries_a_free_device_then_attaches_to_exactly_that_one() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_busybox(
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
            attach_calls(&log),
            [format!("losetup -r /dev/loop9999 {}", backing.display())]
        );
    }

    #[test]
    fn a_free_device_query_that_fails_is_reported_as_itself() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_busybox(
            dir.path(),
            "\"losetup -f\") echo \"losetup: /dev/loop-control: No such device\" >&2; exit 1 ;;\n\
             *) exit 2 ;;",
        );

        let err = tools
            .attach_loop(Path::new("/tmp/cow.img"), false)
            .unwrap_err();

        assert!(err.to_string().contains("losetup -f"), "{err}");
        assert!(err.to_string().contains("No such device"), "{err}");
        // The attach never ran: there was no device to attach to.
        assert_eq!(calls(&log), ["losetup -f"]);
    }

    #[test]
    fn detach_and_size_drive_the_applets_and_parse_the_size() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_busybox(
            dir.path(),
            "\"losetup -d /dev/loop9999\") exit 0 ;;\n\
             \"blockdev --getsz /dev/loop9999\") echo 8192 ;;\n\
             *) exit 2 ;;",
        );

        tools.detach_loop("/dev/loop9999").unwrap();
        assert_eq!(tools.device_sectors("/dev/loop9999").unwrap(), 8192);
        assert_eq!(
            calls(&log),
            ["losetup -d /dev/loop9999", "blockdev --getsz /dev/loop9999"]
        );
    }

    #[test]
    fn a_failed_detach_carries_the_applets_reason() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, _) = fake_busybox(
            dir.path(),
            "*) echo \"losetup: /dev/loop9999: Device or resource busy\" >&2; exit 1 ;;",
        );

        let err = tools.detach_loop("/dev/loop9999").unwrap_err();

        assert!(
            err.to_string().contains("losetup -d /dev/loop9999"),
            "{err}"
        );
        assert!(err.to_string().contains("Device or resource busy"), "{err}");
    }

    #[test]
    fn a_size_that_is_not_a_number_is_a_parse_error_not_a_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, _) = fake_busybox(dir.path(), "*) echo \"lots of them\" ;;");

        let err = tools.device_sectors("/dev/loop9999").unwrap_err();

        assert!(err.to_string().contains("blockdev parse"), "{err}");
    }

    #[test]
    fn a_size_query_that_fails_names_the_applet_call() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, _) = fake_busybox(
            dir.path(),
            "*) echo \"blockdev: /dev/loop9999: No such device\" >&2; exit 1 ;;",
        );

        let err = tools.device_sectors("/dev/loop9999").unwrap_err();

        assert!(
            err.to_string().contains("blockdev --getsz /dev/loop9999"),
            "{err}"
        );
    }

    #[test]
    fn attach_retries_a_claimed_device_a_bounded_number_of_times() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_busybox(
            dir.path(),
            "\"losetup -f\") echo /dev/loop9999 ;;\n\
             *) echo \"losetup: $3: Device or resource busy\" >&2; exit 1 ;;",
        );

        let err = tools
            .attach_loop(Path::new("/tmp/cow.img"), false)
            .unwrap_err();

        assert!(err.to_string().contains("8 attempts"), "{err}");
        assert_eq!(attach_calls(&log).len(), 8);
    }

    #[test]
    fn attach_reports_any_other_failure_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_busybox(
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
        assert_eq!(attach_calls(&log).len(), 1);
    }
}
