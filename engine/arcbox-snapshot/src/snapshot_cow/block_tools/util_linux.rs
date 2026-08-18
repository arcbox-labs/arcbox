//! [`BlockTools`] over util-linux `losetup`/`blockdev` — a stock distro.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Result, SnapshotError};

use super::{BlockTools, parse_loop_device, verify_attached};

/// Reference search list for util-linux's `losetup`. The first entry that
/// exists and answers `--version` as util-linux wins; `/usr/sbin` covers
/// usrmerged distros, `/sbin` stock Debian.
const LOSETUP_CANDIDATES: &[&str] = &["/usr/sbin/losetup", "/sbin/losetup"];

/// Reference search list for util-linux's `blockdev`, same rule.
const BLOCKDEV_CANDIDATES: &[&str] = &["/usr/sbin/blockdev", "/sbin/blockdev"];

/// [`BlockTools`] over util-linux, the block tooling a stock distro ships.
///
/// Where [`BusyboxBlockTools`](super::BusyboxBlockTools) drives one
/// multi-call binary with applet names, this drives two separate programs,
/// and it attaches in a single command rather than two: util-linux's
/// `losetup -f --show FILE` allocates, attaches, and prints the device it
/// used, retrying `EBUSY`/`EAGAIN` itself (64 tries, 200 ms apart, in its
/// own `create_loop`) when another process claims the device it picked. So
/// there is no query-then-attach window here and no host-side retry loop —
/// the difference that makes this a separate implementation rather than
/// [`BusyboxBlockTools`](super::BusyboxBlockTools) pointed at another path.
///
/// `blockdev --getsz` is byte-identical between the two, and `losetup -r` /
/// `losetup -d DEVICE` mean the same thing in both.
#[derive(Debug, Clone)]
pub struct UtilLinuxBlockTools {
    losetup: PathBuf,
    blockdev: PathBuf,
}

impl UtilLinuxBlockTools {
    /// Use the binaries at `losetup` and `blockdev` as given. Nothing is
    /// probed: a composer that knows where its userland lives (a bundled
    /// copy, a non-standard prefix) says so and is believed.
    pub fn new(losetup: impl Into<PathBuf>, blockdev: impl Into<PathBuf>) -> Self {
        Self {
            losetup: losetup.into(),
            blockdev: blockdev.into(),
        }
    }

    /// Find both binaries in the reference search lists, failing when
    /// either is absent or is not util-linux.
    ///
    /// `PATH` is deliberately not searched — the crate never does (see
    /// [`snapshot_cow`](crate::snapshot_cow)), and a node agent's `PATH` is
    /// whatever its unit file happened to inherit.
    pub fn discover() -> Result<Self> {
        Self::discover_in(LOSETUP_CANDIDATES, BLOCKDEV_CANDIDATES)
    }

    fn discover_in(losetup: &[&str], blockdev: &[&str]) -> Result<Self> {
        Ok(Self {
            losetup: first_util_linux("losetup", losetup)?,
            blockdev: first_util_linux("blockdev", blockdev)?,
        })
    }

    fn run(&self, program: &Path, args: &[&str]) -> Result<std::process::Output> {
        Command::new(program)
            .args(args)
            .output()
            .map_err(|e| SnapshotError::DeviceMapper(format!("spawn {}: {e}", program.display())))
    }
}

impl BlockTools for UtilLinuxBlockTools {
    /// `losetup -f --show [-r] -- FILE`, whose stdout is the device that
    /// was attached. The path is passed after `--` so a backing file whose
    /// name starts with `-` cannot be read as an option.
    fn attach_loop(&self, backing: &Path, read_only: bool) -> Result<String> {
        let backing_str = backing
            .to_str()
            .ok_or_else(|| SnapshotError::DeviceMapper("non-UTF-8 path".into()))?;
        let mut args = vec!["-f", "--show"];
        if read_only {
            args.push("-r");
        }
        args.extend(["--", backing_str]);
        let output = self.run(&self.losetup, &args)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SnapshotError::DeviceMapper(format!(
                "losetup -f --show {}: {}",
                backing.display(),
                stderr.trim()
            )));
        }
        let device = parse_loop_device("losetup -f --show", &output.stdout)?;
        verify_attached(self, &device, backing)?;
        Ok(device)
    }

    fn detach_loop(&self, device: &str) -> Result<()> {
        let output = self.run(&self.losetup, &["-d", device])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SnapshotError::DeviceMapper(format!(
                "losetup -d {device}: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }

    fn device_sectors(&self, device: &str) -> Result<u64> {
        let output = self.run(&self.blockdev, &["--getsz", device])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SnapshotError::DeviceMapper(format!(
                "blockdev --getsz {device}: {}",
                stderr.trim()
            )));
        }
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .map_err(|e| SnapshotError::DeviceMapper(format!("blockdev parse: {e}")))
    }
}

/// The first candidate that exists and identifies itself as util-linux.
///
/// Existence is not enough, and the reason is not hypothetical: on
/// busybox-based images `/sbin/losetup` is a symlink to busybox, whose
/// applet rejects `--show` outright. util-linux's `--version` prints
/// `<program> from util-linux <ver>` (`print_version`, `include/c.h`),
/// while the applet has no such option and exits non-zero, so the probe
/// separates them — the same shape as the crate's `dmsetup version` probe.
fn first_util_linux(what: &str, candidates: &[&str]) -> Result<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|bin| is_util_linux(bin))
        .ok_or_else(|| {
            SnapshotError::config(format!(
                "no util-linux {what} among {}",
                candidates.join(", ")
            ))
        })
}

/// Whether `bin` answers `--version` as a util-linux program.
fn is_util_linux(bin: &Path) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .is_ok_and(|out| {
            out.status.success() && String::from_utf8_lossy(&out.stdout).contains("util-linux")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{calls, fake_tool};

    /// util-linux stand-ins for both binaries, each driving its own
    /// `case "$*"` body; see `fake_tool`.
    fn fake_tools(dir: &Path, losetup: &str, blockdev: &str) -> (UtilLinuxBlockTools, PathBuf) {
        let (losetup, log) = fake_tool(dir, "losetup", losetup);
        let (blockdev, _) = fake_tool(dir, "blockdev", blockdev);
        (UtilLinuxBlockTools::new(losetup, blockdev), log)
    }

    const NO_BLOCKDEV: &str = "*) echo \"unexpected: $*\" >&2; exit 2 ;;";

    #[test]
    fn attach_is_one_command_that_reports_the_device_it_used() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_tools(
            dir.path(),
            "\"-f --show -- \"*) echo /dev/loop9999 ;;\n\
             *) echo \"unexpected: $*\" >&2; exit 2 ;;",
            NO_BLOCKDEV,
        );
        let backing = dir.path().join("template.ext4");
        std::fs::write(&backing, b"").unwrap();

        let device = tools.attach_loop(&backing, false).unwrap();

        assert_eq!(device, "/dev/loop9999");
        assert_eq!(
            calls(&log),
            [format!("-f --show -- {}", backing.display())],
            "attach must not query a free device first"
        );
    }

    #[test]
    fn a_read_only_attach_passes_r() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_tools(
            dir.path(),
            "\"-f --show -r -- \"*) echo /dev/loop9999 ;;\n\
             *) echo \"unexpected: $*\" >&2; exit 2 ;;",
            NO_BLOCKDEV,
        );

        let device = tools.attach_loop(Path::new("/tmp/cow.img"), true).unwrap();

        assert_eq!(device, "/dev/loop9999");
        assert_eq!(calls(&log), ["-f --show -r -- /tmp/cow.img"]);
    }

    #[test]
    fn a_failed_attach_reports_losetups_own_reason_without_retrying() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_tools(
            dir.path(),
            "*) echo \"losetup: /tmp/cow.img: failed to set up loop device: \
             Device or resource busy\" >&2; exit 1 ;;",
            NO_BLOCKDEV,
        );

        let err = tools
            .attach_loop(Path::new("/tmp/cow.img"), false)
            .unwrap_err();

        assert!(err.to_string().contains("Device or resource busy"), "{err}");
        assert_eq!(
            calls(&log).len(),
            1,
            "losetup retries EBUSY itself; a second attempt here would double the wait"
        );
    }

    #[test]
    fn attach_rejects_output_that_is_not_a_loop_device() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, _) = fake_tools(
            dir.path(),
            "*) echo \"losetup from util-linux 2.37.2\" ;;",
            NO_BLOCKDEV,
        );

        let err = tools
            .attach_loop(Path::new("/tmp/cow.img"), false)
            .unwrap_err();

        assert!(err.to_string().contains("not a /dev/loopN"), "{err}");
    }

    #[test]
    fn detach_and_size_drive_their_own_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, log) = fake_tools(
            dir.path(),
            "\"-d /dev/loop9999\") exit 0 ;;\n\
             *) exit 2 ;;",
            "\"--getsz /dev/loop9999\") echo 8192 ;;\n\
             *) exit 2 ;;",
        );

        tools.detach_loop("/dev/loop9999").unwrap();
        assert_eq!(tools.device_sectors("/dev/loop9999").unwrap(), 8192);
        assert_eq!(calls(&log), ["-d /dev/loop9999"]);
    }

    #[test]
    fn a_failed_detach_carries_losetups_reason() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, _) = fake_tools(
            dir.path(),
            "*) echo \"losetup: /dev/loop9999: detach failed: Device or resource busy\" >&2; \
             exit 1 ;;",
            NO_BLOCKDEV,
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
        let (tools, _) = fake_tools(dir.path(), NO_BLOCKDEV, "*) echo \"lots of them\" ;;");

        let err = tools.device_sectors("/dev/loop9999").unwrap_err();

        assert!(err.to_string().contains("blockdev parse"), "{err}");
    }

    #[test]
    fn a_size_query_that_fails_names_the_call() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, _) = fake_tools(
            dir.path(),
            NO_BLOCKDEV,
            "*) echo \"blockdev: cannot open /dev/loop9999: No such device\" >&2; exit 1 ;;",
        );

        let err = tools.device_sectors("/dev/loop9999").unwrap_err();

        assert!(
            err.to_string().contains("blockdev --getsz /dev/loop9999"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_binary_is_reported_as_a_failed_spawn() {
        let tools = UtilLinuxBlockTools::new(
            "/nonexistent/arcbox-losetup",
            "/nonexistent/arcbox-blockdev",
        );
        let err = tools.detach_loop("/dev/loop0").unwrap_err();
        assert!(err.to_string().contains("spawn"), "{err}");
    }

    #[test]
    fn discovery_names_the_binary_it_could_not_find() {
        let err = UtilLinuxBlockTools::discover_in(
            &["/nonexistent/arcbox-losetup"],
            &["/nonexistent/arcbox-blockdev"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("no util-linux losetup"), "{err}");
        assert!(
            err.to_string().contains("/nonexistent/arcbox-losetup"),
            "{err}"
        );
    }

    #[test]
    fn discovery_skips_a_busybox_applet_symlinked_into_sbin() {
        let dir = tempfile::tempdir().unwrap();
        // BusyBox's losetup has no --version: it prints usage and fails.
        let (applet, _) = fake_tool(
            dir.path(),
            "losetup",
            "*) echo \"losetup: unrecognized option '--version'\" >&2; exit 1 ;;",
        );
        let (real, _) = fake_tool(
            dir.path(),
            "losetup-real",
            "\"--version\") echo \"losetup from util-linux 2.37.2\" ;;\n*) exit 2 ;;",
        );
        let (blockdev, _) = fake_tool(
            dir.path(),
            "blockdev",
            "\"--version\") echo \"blockdev from util-linux 2.37.2\" ;;\n*) exit 2 ;;",
        );

        let tools = UtilLinuxBlockTools::discover_in(
            &[applet.to_str().unwrap(), real.to_str().unwrap()],
            &[blockdev.to_str().unwrap()],
        )
        .unwrap();

        assert_eq!(tools.losetup, real);
        assert_eq!(tools.blockdev, blockdev);
    }
}
