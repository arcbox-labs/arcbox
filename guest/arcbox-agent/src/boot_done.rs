//! The guest's own declaration that the distro's init has finished booting.
//!
//! A Machine runs an upstream distro image whose init starts *after* the
//! agent — the boot shim runs `machine-init`, backgrounds the agent, then
//! `exec`s `/sbin/init` — and that init typically reconfigures the network
//! from scratch, flushing the interface the shim already configured. The host
//! gates machine readiness on this signal so `Start` does not return into
//! that window (CORE-66).
//!
//! The signal is a sentinel written by a hook ordered at the end of the
//! distro's own boot sequence, not an inspection of the init system's runtime
//! state. That follows what comparable runtimes do:
//!
//! - **Lima** polls `/run/lima-boot-done` for the instance id, written by the
//!   boot scripts it injects (`pkg/hostagent/requirements.go`).
//! - **Multipass** waits on cloud-init's `/var/lib/cloud/instance/boot-finished`
//!   (`base_virtual_machine.cpp`, `wait_for_cloud_init`).
//! - **Incus** has the guest declare itself: `PATCH /1.0 {"state":"Ready"}` on
//!   the devIncus socket, recorded as `volatile.last_state.ready` — documented
//!   as "Instance marked itself as ready".
//!
//! None of them read the init system's internals from outside, and the reason
//! shows up immediately when you try: `/run/openrc/rc.starting` is absent both
//! *before* openrc runs and *after* it finishes, so the obvious check reports
//! "settled" during exactly the window it exists to catch. Unit ordering is a
//! public contract; a runtime directory's layout is not.
//!
//! cloud-init would be the standard vehicle, but the images ArcBox mirrors are
//! the linuxcontainers `default` variant, which does not ship it (verified: an
//! `ubuntu-noble` machine boots with no cloud-init at all). The hook is
//! installed directly instead, which the writable overlay already allows —
//! `machine-init` writes `/etc/resolv.conf` and the DHCP script the same way.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

/// Sentinel carrying the boot it was written for. Lives on `/run` (tmpfs, so
/// it starts each boot empty); the boot id is compared anyway, so a `/run`
/// that persists cannot make a previous boot's sentinel look current.
pub const SENTINEL: &str = "/run/arcbox-boot-done";

const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const SYSTEMD_UNIT: &str = "/etc/systemd/system/arcbox-boot-done.service";
const SYSTEMD_WANTS: &str = "/etc/systemd/system/multi-user.target.wants/arcbox-boot-done.service";
const OPENRC_SERVICE: &str = "/etc/init.d/arcbox-boot-done";
const OPENRC_RUNLEVEL: &str = "/etc/runlevels/default/arcbox-boot-done";

/// The unit that writes the sentinel.
///
/// `WantedBy=multi-user.target` pulls it into the boot; `After=` on the same
/// target orders it after that target is *reached*. Be precise about what
/// that buys: a `.wants` symlink adds no ordering of its own, so the target
/// is reached once the units that declare `Before=multi-user.target` are
/// done — conventional for distro service units, but not something the
/// symlink guarantees. `After=network-online.target` is listed as well and
/// costs nothing: without a matching `Wants=` it constrains ordering only on
/// images where something else already activates that target, and imposes
/// nothing where nothing does. Deliberately no `Wants=network-online.target`
/// — on an image with no wait-online provider the target never activates,
/// and the hook would never run.
fn systemd_unit_body() -> String {
    format!(
        "[Unit]
Description=ArcBox boot-completion sentinel
After=multi-user.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'cat {BOOT_ID} > {SENTINEL}'

[Install]
WantedBy=multi-user.target
"
    )
}

/// `after *` orders this behind every other service in the runlevel, which
/// is openrc's own way to say "last".
fn openrc_service_body() -> String {
    format!(
        "#!/sbin/openrc-run
description=\"ArcBox boot-completion sentinel\"

depend() {{
    after *
}}

start() {{
    cat {BOOT_ID} > {SENTINEL}
}}

stop() {{
    return 0
}}
"
    )
}

/// The filesystem the hook is installed into.
///
/// Rooted rather than hardcoded so the install path — the half with the
/// rollbacks — can be exercised against a temporary directory instead of the
/// running host's own `/etc`. Production is always [`Layout::guest`].
///
/// Paths *written into* the hook bodies stay absolute: they are resolved by
/// the guest's init at boot, not through this root.
struct Layout {
    root: PathBuf,
}

impl Layout {
    /// The guest's own filesystem. Only the in-guest (Linux) build has one;
    /// a host build compiles this module for its tests alone, which root
    /// themselves in a temporary directory.
    #[cfg(target_os = "linux")]
    fn guest() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// Whether a hook is installed, i.e. whether a sentinel is coming at all.
    ///
    /// This is what tells readiness to wait: an image whose init we do not
    /// recognize gets no hook, and readiness must not block on a signal
    /// nothing will ever send. The hook file *is* the marker — there is no
    /// second piece of state to keep in sync with it.
    fn hook_installed(&self) -> bool {
        self.path(SYSTEMD_UNIT).exists() || self.path(OPENRC_SERVICE).exists()
    }

    /// Whether the sentinel was written by the boot that is running now.
    fn boot_complete(&self) -> bool {
        let (Ok(sentinel), Ok(boot_id)) = (
            fs::read_to_string(self.path(SENTINEL)),
            fs::read_to_string(self.path(BOOT_ID)),
        ) else {
            return false;
        };
        sentinel_matches(&sentinel, &boot_id)
    }
}

/// Whether a hook is installed in the guest; see [`Layout::hook_installed`].
#[cfg(target_os = "linux")]
#[must_use]
pub fn hook_installed() -> bool {
    Layout::guest().hook_installed()
}

/// Whether the guest's sentinel names the running boot; see
/// [`Layout::boot_complete`].
#[cfg(target_os = "linux")]
#[must_use]
pub fn boot_complete() -> bool {
    Layout::guest().boot_complete()
}

/// Whether `sentinel` names the boot `boot_id` identifies.
///
/// The boot id is what makes the sentinel self-invalidating: `/run` is tmpfs
/// on every image seen so far, but an image where it is not would otherwise
/// carry a previous boot's sentinel into the window this is meant to catch.
/// An empty boot id (unreadable `/proc`) matches nothing rather than
/// everything.
fn sentinel_matches(sentinel: &str, boot_id: &str) -> bool {
    let boot_id = boot_id.trim();
    !boot_id.is_empty() && sentinel.trim() == boot_id
}

/// Installs the boot-completion hook for the distro's init, if recognized.
///
/// Best-effort by design: a failure here means readiness falls back to not
/// waiting (`hook_installed` stays false), which is the behavior that
/// predates the hook — strictly better than a half-installed hook that never
/// fires and burns the readiness timeout instead.
#[cfg(target_os = "linux")]
pub fn install() -> bool {
    Layout::guest().install()
}

impl Layout {
    /// Installs the hook for whichever init this image ships, if recognized.
    fn install(&self) -> bool {
        if self.path("/usr/lib/systemd/systemd").exists()
            || self.path("/lib/systemd/systemd").exists()
        {
            return self.install_systemd();
        }
        if self.path("/sbin/openrc").exists() || self.path("/usr/libexec/rc").is_dir() {
            return self.install_openrc();
        }
        tracing::info!(
            "no recognized distro init; machine readiness will not wait for boot to settle"
        );
        false
    }

    fn install_systemd(&self) -> bool {
        let unit = self.path(SYSTEMD_UNIT);
        if let Err(e) = write_file(&unit, &systemd_unit_body(), 0o644) {
            tracing::warn!(error = %e, "failed to write the systemd boot-done unit");
            return false;
        }
        // Enabled by symlink rather than `systemctl enable`: systemd is not
        // running yet at this point in the boot shim, so there is nothing to
        // ask. The link target is the in-guest absolute path, which is what
        // systemd itself will resolve.
        if let Err(e) = self.symlink_into_wants() {
            tracing::warn!(error = %e, "failed to enable the systemd boot-done unit");
            let _ = fs::remove_file(&unit);
            return false;
        }
        tracing::info!("installed the systemd boot-completion hook");
        true
    }

    fn symlink_into_wants(&self) -> std::io::Result<()> {
        let wants = self.path(SYSTEMD_WANTS);
        if let Some(parent) = wants.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(&wants);
        std::os::unix::fs::symlink(SYSTEMD_UNIT, &wants)
    }

    fn install_openrc(&self) -> bool {
        let service = self.path(OPENRC_SERVICE);
        if let Err(e) = write_file(&service, &openrc_service_body(), 0o755) {
            tracing::warn!(error = %e, "failed to write the openrc boot-done service");
            return false;
        }
        // `rc-update add` would work, but openrc is not running yet either;
        // the runlevel is just a directory of symlinks.
        let runlevel = self.path(OPENRC_RUNLEVEL);
        if let Some(parent) = runlevel.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            tracing::warn!(error = %e, "failed to create the openrc default runlevel dir");
            let _ = fs::remove_file(&service);
            return false;
        }
        let _ = fs::remove_file(&runlevel);
        if let Err(e) = std::os::unix::fs::symlink(OPENRC_SERVICE, &runlevel) {
            tracing::warn!(error = %e, "failed to add the openrc boot-done service to the runlevel");
            let _ = fs::remove_file(&service);
            return false;
        }
        tracing::info!("installed the openrc boot-completion hook");
        true
    }
}

fn write_file(path: &Path, body: &str, mode: u32) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    file.write_all(body.as_bytes())?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty image rooted in a temp dir: no init, no hook, no sentinel.
    fn image() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = Layout {
            root: dir.path().to_path_buf(),
        };
        (dir, layout)
    }

    fn touch(layout: &Layout, absolute: &str) {
        let path = layout.path(absolute);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, "").expect("write");
    }

    /// An image whose init we do not recognize gets no hook, and readiness
    /// must then not wait — `hook_installed` staying false is what encodes
    /// "no signal is coming".
    #[test]
    fn an_unrecognized_init_installs_nothing_and_promises_nothing() {
        let (_dir, layout) = image();
        assert!(!layout.install());
        assert!(!layout.hook_installed());
    }

    #[test]
    fn a_systemd_image_gets_an_enabled_unit() {
        let (_dir, layout) = image();
        touch(&layout, "/usr/lib/systemd/systemd");

        assert!(layout.install());
        assert!(layout.hook_installed());
        // Enablement is the symlink; without it the unit is inert and
        // readiness would wait out its full timeout.
        let wants = layout.path(SYSTEMD_WANTS);
        assert_eq!(
            fs::read_link(&wants).expect("symlink"),
            Path::new(SYSTEMD_UNIT)
        );
    }

    #[test]
    fn an_openrc_image_gets_a_service_in_the_default_runlevel() {
        let (_dir, layout) = image();
        touch(&layout, "/sbin/openrc");

        assert!(layout.install());
        assert!(layout.hook_installed());
        let runlevel = layout.path(OPENRC_RUNLEVEL);
        assert_eq!(
            fs::read_link(&runlevel).expect("symlink"),
            Path::new(OPENRC_SERVICE)
        );
        let mode = fs::metadata(layout.path(OPENRC_SERVICE))
            .expect("service")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "openrc runs the service as a program");
    }

    /// A half-installed hook is the expensive failure: it never fires and
    /// burns the readiness timeout. A failed enable must therefore roll the
    /// unit back, leaving `hook_installed` false — the pre-hook behaviour.
    #[test]
    fn a_failed_enable_rolls_the_unit_back() {
        let (_dir, layout) = image();
        touch(&layout, "/usr/lib/systemd/systemd");
        // A regular file where the .wants directory must go: create_dir_all
        // fails, so enablement cannot succeed.
        touch(&layout, "/etc/systemd/system/multi-user.target.wants");

        assert!(!layout.install_systemd());
        assert!(!layout.path(SYSTEMD_UNIT).exists());
        assert!(!layout.hook_installed());
    }

    /// The sentinel is only meaningful against the running boot.
    #[test]
    fn boot_complete_reads_the_sentinel_against_this_boot() {
        let (_dir, layout) = image();
        fs::create_dir_all(layout.path(SENTINEL).parent().expect("parent")).expect("mkdir");
        fs::create_dir_all(layout.path(BOOT_ID).parent().expect("parent")).expect("mkdir");
        fs::write(layout.path(BOOT_ID), "boot-2\n").expect("write");

        assert!(!layout.boot_complete(), "no sentinel yet");

        fs::write(layout.path(SENTINEL), "boot-1\n").expect("write");
        assert!(!layout.boot_complete(), "sentinel from the previous boot");

        fs::write(layout.path(SENTINEL), "boot-2\n").expect("write");
        assert!(layout.boot_complete());
    }

    /// Generating the bodies with `format!` means the shell braces in the
    /// openrc service have to be escaped, and getting that wrong yields a
    /// file openrc cannot parse — a hook that installs and never fires,
    /// which is the one failure mode that costs a readiness timeout rather
    /// than degrading safely.
    #[test]
    fn the_openrc_body_survives_format_escaping() {
        let body = openrc_service_body();
        assert!(body.contains("depend() {\n    after *\n}"), "{body}");
        assert!(body.contains("start() {\n"), "{body}");
        assert!(!body.contains("{{") && !body.contains("}}"), "{body}");
    }

    /// A leftover sentinel from a previous boot must not read as complete —
    /// the case a bare "does the file exist" check would get wrong.
    #[test]
    fn a_sentinel_from_another_boot_does_not_count() {
        assert!(!sentinel_matches("stale-boot-id", "current-boot-id"));
    }

    /// The hook writes with `cat`, so the sentinel carries the trailing
    /// newline `/proc/sys/kernel/random/boot_id` has.
    #[test]
    fn the_trailing_newline_the_hook_writes_is_tolerated() {
        assert!(sentinel_matches("boot-id\n", "boot-id\n"));
    }

    /// An unreadable boot id must match nothing rather than everything.
    #[test]
    fn an_empty_boot_id_never_matches() {
        assert!(!sentinel_matches("", ""));
        assert!(!sentinel_matches("anything", ""));
    }
}
