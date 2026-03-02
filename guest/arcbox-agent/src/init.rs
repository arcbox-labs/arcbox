//! System initialization for PID 1 agent.
//!
//! When the agent runs as PID 1 (EROFS boot path), the busybox trampoline has
//! already mounted /proc, /sys, /dev (devtmpfs), and /arcbox (VirtioFS).
//!
//! This module sets up everything else: writable tmpfs layers over the read-only
//! EROFS rootfs, populates /etc, mounts pseudo-filesystems, configures networking,
//! and syncs the system clock.
//!
//! All operations are idempotent and best-effort — failures are logged but do not
//! abort, since PID 1 must not exit.

#[cfg(target_os = "linux")]
mod platform {
    use std::os::unix::fs as unix_fs;
    use std::path::Path;

    use nix::mount::{MsFlags, mount};

    /// Runs one-time system initialization after trampoline hands off to agent.
    ///
    /// Trampoline already mounted: /proc, /sys, /dev, /arcbox (VirtioFS).
    /// EROFS rootfs is purely structural. All writable state goes on tmpfs.
    pub fn init_system() {
        // Writable layers on top of read-only EROFS.
        mount_tmpfs("/tmp");
        mount_tmpfs("/run");
        mount_tmpfs("/var");
        mount_tmpfs("/etc");

        // Populate /etc with files containerd/dockerd expect.
        write_etc_resolv_conf();
        write_etc_hosts();
        write_etc_passwd();
        write_etc_group();

        // TLS CA certificates: EROFS has /cacerts/ca-certificates.crt.
        // Symlink into tmpfs /etc so programs find it at the standard path.
        mkdir_p("/etc/ssl/certs");
        symlink_if_source_exists(
            "/cacerts/ca-certificates.crt",
            "/etc/ssl/certs/ca-certificates.crt",
        );

        // Writable subdirectories under /var.
        mkdir_p("/var/lib/docker");
        mkdir_p("/var/run/docker");
        mkdir_p("/var/log/arcbox");
        mkdir_p("/run/containerd");

        // Pseudo-filesystems.
        mount_cgroup2();
        mount_devpts();
        mount_shm();

        // Network and time.
        setup_networking();
        sync_clock();

        // Optional host /Users share (non-fatal if not configured).
        mount_virtiofs_optional("users", "/Users");

        tracing::info!("PID 1 system initialization complete");
    }

    fn mount_tmpfs(target: &str) {
        // Ensure mount point exists — EROFS may not have /etc or /var.
        mkdir_p(target);
        if let Err(e) = mount(
            Some("tmpfs"),
            target,
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
            None::<&str>,
        ) {
            tracing::warn!(target, error = %e, "failed to mount tmpfs");
        }
    }

    fn mount_cgroup2() {
        if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            return;
        }
        mkdir_p("/sys/fs/cgroup");
        if let Err(e) = mount(
            Some("cgroup2"),
            "/sys/fs/cgroup",
            Some("cgroup2"),
            MsFlags::empty(),
            None::<&str>,
        ) {
            tracing::warn!(error = %e, "failed to mount cgroup2");
        }
    }

    fn mount_devpts() {
        if Path::new("/dev/pts/ptmx").exists() {
            return;
        }
        mkdir_p("/dev/pts");
        if let Err(e) = mount(
            Some("devpts"),
            "/dev/pts",
            Some("devpts"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
            Some("gid=5,mode=0620"),
        ) {
            tracing::warn!(error = %e, "failed to mount devpts");
        }
    }

    fn mount_shm() {
        if Path::new("/dev/shm").exists() {
            return;
        }
        mkdir_p("/dev/shm");
        if let Err(e) = mount(
            Some("shm"),
            "/dev/shm",
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        ) {
            tracing::warn!(error = %e, "failed to mount /dev/shm");
        }
    }

    fn mount_virtiofs_optional(tag: &str, mountpoint: &str) {
        if crate::mount::is_mounted(mountpoint) {
            return;
        }
        mkdir_p(mountpoint);
        if let Err(e) = mount(
            Some(tag),
            mountpoint,
            Some("virtiofs"),
            MsFlags::empty(),
            None::<&str>,
        ) {
            // debug, not warn — this share is optional.
            tracing::debug!(tag, mountpoint, error = %e, "virtiofs share not available");
        }
    }

    fn setup_networking() {
        // Enable IPv4 forwarding for Docker bridge networking.
        if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n") {
            tracing::warn!(error = %e, "failed to enable ip_forward");
        }
        // Bring up loopback interface.
        let status = std::process::Command::new("/bin/busybox")
            .args(["ip", "link", "set", "lo", "up"])
            .status();
        if let Err(e) = status {
            tracing::warn!(error = %e, "failed to bring up loopback");
        }
    }

    fn sync_clock() {
        // One-shot NTP sync. Without a correct clock, TLS cert validation fails
        // with "x509: certificate is not yet valid" because VZ guest RTC starts
        // at epoch.
        let status = std::process::Command::new("/bin/busybox")
            .args(["ntpd", "-q", "-n", "-p", "pool.ntp.org"])
            .status();
        match status {
            Ok(s) if s.success() => tracing::info!("NTP clock synced"),
            Ok(s) => tracing::warn!(
                exit_code = s.code().unwrap_or(-1),
                "NTP sync exited non-zero"
            ),
            Err(e) => tracing::warn!(error = %e, "NTP sync failed"),
        }
    }

    fn write_etc_resolv_conf() {
        let content = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        if let Err(e) = std::fs::write("/etc/resolv.conf", content) {
            tracing::warn!(error = %e, "failed to write /etc/resolv.conf");
        }
    }

    fn write_etc_hosts() {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "arcbox".to_string());
        let content = format!("127.0.0.1\tlocalhost\n::1\t\tlocalhost\n127.0.1.1\t{hostname}\n");
        if let Err(e) = std::fs::write("/etc/hosts", content) {
            tracing::warn!(error = %e, "failed to write /etc/hosts");
        }
    }

    fn write_etc_passwd() {
        let content =
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n";
        if let Err(e) = std::fs::write("/etc/passwd", content) {
            tracing::warn!(error = %e, "failed to write /etc/passwd");
        }
    }

    fn write_etc_group() {
        let content = "root:x:0:\ntty:x:5:\nnobody:x:65534:\n";
        if let Err(e) = std::fs::write("/etc/group", content) {
            tracing::warn!(error = %e, "failed to write /etc/group");
        }
    }

    fn mkdir_p(path: &str) {
        if let Err(e) = std::fs::create_dir_all(path) {
            tracing::warn!(path, error = %e, "failed to create directory");
        }
    }

    fn symlink_if_source_exists(source: &str, link: &str) {
        if !Path::new(source).exists() {
            tracing::debug!(source, "symlink source does not exist, skipping");
            return;
        }
        if let Err(e) = unix_fs::symlink(source, link) {
            tracing::warn!(source, link, error = %e, "failed to create symlink");
        }
    }
}

#[cfg(target_os = "linux")]
pub use platform::init_system;

#[cfg(not(target_os = "linux"))]
pub fn init_system() {
    tracing::warn!("init_system is only functional on Linux");
}
