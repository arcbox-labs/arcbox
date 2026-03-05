//! Machine VM init handler.
//!
//! Runs when kernel cmdline contains `arcbox.mode=machine`.
//! Handles first-boot provisioning of the rootfs from a tarball,
//! then switch_root to the real init.
//!
//! ## First-boot flow
//!
//! 1. Mount /proc, /sys, /dev, /dev/pts
//! 2. Mount VirtioFS "arcbox-setup" at /mnt/setup
//! 3. Mount block device /dev/vda at /mnt/root
//! 4. If /mnt/root is empty (first boot):
//!    a. Extract rootfs.tar.gz from /mnt/setup to /mnt/root
//!    b. Read setup.json for hostname, SSH pubkey, etc.
//!    c. Configure hostname, SSH keys, network
//!    d. Write first-boot completion marker
//! 5. Unmount /mnt/setup
//! 6. switch_root to /mnt/root and exec /sbin/init
//!
//! ## Subsequent boots
//!
//! Steps 1-3 are the same, but step 4 is skipped because the
//! first-boot marker exists. This makes subsequent boots fast.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

/// Setup VirtioFS tag name (must match host-side SharedDirConfig).
const SETUP_TAG: &str = "arcbox-setup";

/// Block device path for the rootfs disk.
const BLOCK_DEVICE: &str = "/dev/vda";

/// Mount points.
const MNT_SETUP: &str = "/mnt/setup";
const MNT_ROOT: &str = "/mnt/root";

/// First-boot completion marker.
const FIRSTBOOT_MARKER: &str = ".arcbox-firstboot-done";

/// Machine VM init entry point.
///
/// This function never returns — it either exec's into the real init
/// or panics on fatal error.
pub fn run() -> ! {
    eprintln!("[arcbox-init] Machine mode detected, starting init...");

    // 1. Mount essential filesystems.
    mount_essential_fs();

    // 2. Mount VirtioFS setup share.
    fs::create_dir_all(MNT_SETUP).expect("failed to create /mnt/setup");
    mount_virtiofs(SETUP_TAG, MNT_SETUP);

    // 3. Mount block device.
    fs::create_dir_all(MNT_ROOT).expect("failed to create /mnt/root");
    mount_ext4(BLOCK_DEVICE, MNT_ROOT);

    // 4. First-boot provisioning.
    let marker = Path::new(MNT_ROOT).join(FIRSTBOOT_MARKER);
    if !marker.exists() {
        eprintln!("[arcbox-init] First boot detected, provisioning rootfs...");
        if first_boot_provision() {
            fs::write(&marker, "done\n").expect("failed to write firstboot marker");
            eprintln!("[arcbox-init] First boot provisioning complete.");
        } else {
            eprintln!(
                "[arcbox-init] First boot provisioning incomplete; marker not written, will retry on next boot."
            );
        }
    } else {
        eprintln!("[arcbox-init] Existing rootfs found, skipping provisioning.");
    }

    // 5. Unmount setup share.
    let _ = umount(MNT_SETUP);

    // 6. switch_root to real rootfs.
    eprintln!("[arcbox-init] Switching root to {}...", MNT_ROOT);
    switch_root(MNT_ROOT);
}

/// Mounts essential pseudo-filesystems.
fn mount_essential_fs() {
    // /proc
    fs::create_dir_all("/proc").ok();
    mount_fs("proc", "/proc", "proc", "");

    // /sys
    fs::create_dir_all("/sys").ok();
    mount_fs("sysfs", "/sys", "sysfs", "");

    // /dev
    fs::create_dir_all("/dev").ok();
    mount_fs("devtmpfs", "/dev", "devtmpfs", "");

    // /dev/pts
    fs::create_dir_all("/dev/pts").ok();
    mount_fs("devpts", "/dev/pts", "devpts", "gid=5,mode=620");
}

/// Mounts a VirtioFS share.
fn mount_virtiofs(tag: &str, target: &str) {
    eprintln!("[arcbox-init] Mounting VirtioFS '{}' at {}", tag, target);
    mount_fs(tag, target, "virtiofs", "");
}

/// Mounts an ext4 block device.
fn mount_ext4(device: &str, target: &str) {
    eprintln!("[arcbox-init] Mounting {} at {}", device, target);
    mount_fs(device, target, "ext4", "");
}

/// Generic mount wrapper.
fn mount_fs(source: &str, target: &str, fstype: &str, options: &str) {
    let mut cmd = Command::new("/bin/busybox");
    cmd.args(["mount", "-t", fstype]);
    if !options.is_empty() {
        cmd.args(["-o", options]);
    }
    cmd.args([source, target]);

    let status = cmd.status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!(
                "[arcbox-init] Warning: mount {} -> {} failed (exit {})",
                source,
                target,
                s.code().unwrap_or(-1)
            );
        }
        Err(e) => {
            // Fall back to mount(2) syscall if busybox is not available.
            eprintln!("[arcbox-init] busybox mount failed ({}), trying syscall", e);
            #[cfg(target_os = "linux")]
            {
                use nix::mount::{MsFlags, mount};
                let flags = MsFlags::empty();
                let opts: Option<&str> = if options.is_empty() {
                    None
                } else {
                    Some(options)
                };
                if let Err(e) = mount(Some(source), target, Some(fstype), flags, opts) {
                    eprintln!(
                        "[arcbox-init] Warning: mount syscall {} -> {} failed: {}",
                        source, target, e
                    );
                }
            }
        }
    }
}

/// Unmounts a filesystem.
fn umount(target: &str) -> std::io::Result<()> {
    let status = Command::new("/bin/busybox")
        .args(["umount", target])
        .status()?;
    if !status.success() {
        eprintln!(
            "[arcbox-init] Warning: umount {} failed (exit {})",
            target,
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Performs first-boot provisioning.
fn first_boot_provision() -> bool {
    // Extract rootfs tarball.
    let tarball_path = Path::new(MNT_SETUP).join("rootfs.tar.gz");
    if tarball_path.exists() {
        eprintln!(
            "[arcbox-init] Extracting rootfs from {}...",
            tarball_path.display()
        );
        extract_tarball(&tarball_path, MNT_ROOT);
    } else {
        eprintln!("[arcbox-init] Warning: rootfs.tar.gz not found in setup share");
    }

    // Read setup.json for configuration.
    let setup_path = Path::new(MNT_SETUP).join("setup.json");
    if setup_path.exists() {
        if let Ok(content) = fs::read_to_string(&setup_path) {
            if let Ok(setup) = serde_json::from_str::<serde_json::Value>(&content) {
                apply_setup(&setup);
            } else {
                eprintln!("[arcbox-init] Warning: failed to parse setup.json");
            }
        }
    } else {
        eprintln!("[arcbox-init] Warning: setup.json not found");
    }

    // Install arcbox-agent into rootfs so it runs after switch_root.
    install_agent()
}

/// Extracts a tar.gz file to a directory.
fn extract_tarball(tarball: &Path, dest: &str) {
    let file = match fs::File::open(tarball) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[arcbox-init] Failed to open tarball: {}", e);
            return;
        }
    };

    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    if let Err(e) = archive.unpack(dest) {
        eprintln!("[arcbox-init] Failed to extract tarball: {}", e);
    } else {
        eprintln!("[arcbox-init] Rootfs extracted successfully.");
    }
}

/// Applies setup.json configuration to the rootfs.
fn apply_setup(setup: &serde_json::Value) {
    let root = Path::new(MNT_ROOT);

    // Set hostname.
    if let Some(hostname) = setup.get("hostname").and_then(|v| v.as_str()) {
        eprintln!("[arcbox-init] Setting hostname: {}", hostname);
        let etc = root.join("etc");
        fs::create_dir_all(&etc).ok();
        let _ = fs::write(etc.join("hostname"), format!("{}\n", hostname));

        // Also update /etc/hosts.
        let hosts_content = format!(
            "127.0.0.1\tlocalhost\n127.0.1.1\t{}\n::1\tlocalhost ip6-localhost\n",
            hostname
        );
        let _ = fs::write(etc.join("hosts"), hosts_content);
    }

    // Set up SSH authorized_keys.
    if let Some(pubkey) = setup.get("ssh_pubkey").and_then(|v| v.as_str()) {
        eprintln!("[arcbox-init] Configuring SSH authorized key.");
        let ssh_dir = root.join("root/.ssh");
        fs::create_dir_all(&ssh_dir).ok();
        let _ = fs::write(ssh_dir.join("authorized_keys"), format!("{}\n", pubkey));
        // Set permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(
                ssh_dir.join("authorized_keys"),
                fs::Permissions::from_mode(0o600),
            );
        }
    }

    // Configure network (DHCP on eth0).
    configure_network(root, setup);

    // Enable SSH server based on distro.
    if let Some(distro) = setup.get("distro").and_then(|v| v.as_str()) {
        enable_sshd(root, distro);
    }
}

/// Configures network for DHCP on eth0.
fn configure_network(root: &Path, _setup: &serde_json::Value) {
    let etc = root.join("etc");

    // Alpine: /etc/network/interfaces
    let interfaces_dir = etc.join("network");
    if interfaces_dir.exists() || etc.join("alpine-release").exists() {
        fs::create_dir_all(&interfaces_dir).ok();
        let config = "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n";
        let _ = fs::write(interfaces_dir.join("interfaces"), config);
        eprintln!("[arcbox-init] Configured Alpine network (DHCP on eth0).");
        return;
    }

    // Ubuntu: /etc/netplan/
    let netplan_dir = etc.join("netplan");
    fs::create_dir_all(&netplan_dir).ok();
    let config = "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n";
    let _ = fs::write(netplan_dir.join("01-arcbox.yaml"), config);
    eprintln!("[arcbox-init] Configured Ubuntu network (netplan DHCP on eth0).");
}

/// Enables the SSH server daemon.
fn enable_sshd(root: &Path, distro: &str) {
    match distro {
        "alpine" => {
            // Alpine: rc-update add sshd default (via openrc).
            // We write a simple enable marker since we can't run rc-update
            // inside the initramfs. The init system will pick it up.
            let runlevel_dir = root.join("etc/runlevels/default");
            fs::create_dir_all(&runlevel_dir).ok();
            // Symlink init script to runlevel.
            let sshd_init = Path::new("/etc/init.d/sshd");
            let sshd_link = runlevel_dir.join("sshd");
            if !sshd_link.exists() {
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(sshd_init, &sshd_link);
                }
            }
            eprintln!("[arcbox-init] Enabled sshd for Alpine (openrc).");
        }
        "ubuntu" => {
            // Ubuntu: systemctl enable ssh.
            // Create symlink in multi-user.target.wants.
            let wants_dir = root.join("etc/systemd/system/multi-user.target.wants");
            fs::create_dir_all(&wants_dir).ok();
            let ssh_service = Path::new("/lib/systemd/system/ssh.service");
            let ssh_link = wants_dir.join("ssh.service");
            if !ssh_link.exists() {
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(ssh_service, &ssh_link);
                }
            }
            eprintln!("[arcbox-init] Enabled ssh for Ubuntu (systemd).");
        }
        _ => {
            eprintln!(
                "[arcbox-init] Unknown distro '{}', skipping sshd setup.",
                distro
            );
        }
    }
}

/// Installs the arcbox-agent binary into the rootfs and sets up a service.
///
/// The agent binary is at /sbin/arcbox-agent in the initramfs. We copy it
/// to the rootfs so it starts after switch_root and the real init runs.
fn install_agent() -> bool {
    let src = Path::new("/sbin/arcbox-agent");
    if !src.exists() {
        eprintln!(
            "[arcbox-init] Warning: /sbin/arcbox-agent not found in initramfs, skipping agent install"
        );
        return false;
    }

    let dest = Path::new(MNT_ROOT).join("usr/local/bin/arcbox-agent");
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).ok();
    }

    if let Err(e) = fs::copy(src, &dest) {
        eprintln!(
            "[arcbox-init] Warning: failed to copy agent to rootfs: {}",
            e
        );
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o755));
    }

    eprintln!("[arcbox-init] Installed arcbox-agent to rootfs.");

    // Detect distro and set up the appropriate service.
    let root = Path::new(MNT_ROOT);
    if root.join("etc/alpine-release").exists() {
        install_agent_openrc(root);
    } else {
        install_agent_systemd(root);
    }

    true
}

/// Sets up arcbox-agent as an OpenRC service (Alpine).
fn install_agent_openrc(root: &Path) {
    let init_script = root.join("etc/init.d/arcbox-agent");
    let content = r#"#!/sbin/openrc-run

name="arcbox-agent"
description="ArcBox guest agent"
command="/usr/local/bin/arcbox-agent"
command_args=""
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/arcbox-agent.log"
error_log="/var/log/arcbox-agent.log"

depend() {
    need net
    after firewall
}
"#;
    let _ = fs::write(&init_script, content);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&init_script, fs::Permissions::from_mode(0o755));
    }

    // Enable at default runlevel.
    enable_openrc_service(root, "arcbox-agent");

    // If runtime services exist in rootfs, enable them too.
    enable_openrc_service(root, "containerd");
    enable_openrc_service(root, "docker");
    eprintln!("[arcbox-init] Installed arcbox-agent OpenRC service.");
}

/// Sets up arcbox-agent as a systemd service (Ubuntu).
fn install_agent_systemd(root: &Path) {
    let unit_dir = root.join("etc/systemd/system");
    fs::create_dir_all(&unit_dir).ok();

    let unit = r#"[Unit]
Description=ArcBox guest agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/arcbox-agent
ExecStart=/usr/local/bin/arcbox-agent
Restart=always
RestartSec=2
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#;
    let _ = fs::write(unit_dir.join("arcbox-agent.service"), unit);

    // Enable the service.
    enable_systemd_service(root, "arcbox-agent.service");

    // If runtime services exist in rootfs, enable them too.
    enable_systemd_service(root, "containerd.service");
    enable_systemd_service(root, "docker.service");
    eprintln!("[arcbox-init] Installed arcbox-agent systemd service.");
}

fn enable_openrc_service(root: &Path, service: &str) {
    let init_script = root.join("etc/init.d").join(service);
    if !init_script.exists() {
        return;
    }

    let runlevel_dir = root.join("etc/runlevels/default");
    fs::create_dir_all(&runlevel_dir).ok();
    let link = runlevel_dir.join(service);
    if link.exists() {
        return;
    }

    #[cfg(unix)]
    {
        let target = format!("/etc/init.d/{}", service);
        if let Err(e) = std::os::unix::fs::symlink(target, &link) {
            eprintln!(
                "[arcbox-init] Warning: failed to enable OpenRC service {}: {}",
                service, e
            );
        } else {
            eprintln!("[arcbox-init] Enabled OpenRC service {}.", service);
        }
    }
}

fn enable_systemd_service(root: &Path, service: &str) {
    let service_in_etc = root.join("etc/systemd/system").join(service);
    let service_in_lib = root.join("lib/systemd/system").join(service);
    let service_in_usr_lib = root.join("usr/lib/systemd/system").join(service);

    let target = if service_in_etc.exists() {
        format!("/etc/systemd/system/{}", service)
    } else if service_in_lib.exists() {
        format!("/lib/systemd/system/{}", service)
    } else if service_in_usr_lib.exists() {
        format!("/usr/lib/systemd/system/{}", service)
    } else {
        return;
    };

    let wants_dir = root.join("etc/systemd/system/multi-user.target.wants");
    fs::create_dir_all(&wants_dir).ok();
    let link = wants_dir.join(service);
    if link.exists() {
        return;
    }

    #[cfg(unix)]
    {
        if let Err(e) = std::os::unix::fs::symlink(target, &link) {
            eprintln!(
                "[arcbox-init] Warning: failed to enable systemd service {}: {}",
                service, e
            );
        } else {
            eprintln!("[arcbox-init] Enabled systemd service {}.", service);
        }
    }
}

/// Performs switch_root to the real rootfs and exec /sbin/init.
fn switch_root(new_root: &str) -> ! {
    // Use busybox switch_root if available.
    let status = Command::new("/bin/busybox")
        .args(["switch_root", new_root, "/sbin/init"])
        .status();

    match status {
        Ok(s) => {
            eprintln!(
                "[arcbox-init] switch_root exited unexpectedly with code {}",
                s.code().unwrap_or(-1)
            );
        }
        Err(e) => {
            eprintln!("[arcbox-init] switch_root failed: {}", e);
            // Fall back to manual approach.
            #[cfg(target_os = "linux")]
            {
                eprintln!("[arcbox-init] Attempting manual pivot_root...");
                manual_switch_root(new_root);
            }
        }
    }

    // If we get here, init failed. Drop into a rescue shell.
    eprintln!("[arcbox-init] Failed to start init! Dropping into rescue shell.");
    let _ = Command::new("/bin/sh").status();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Manual switch_root using pivot_root and chroot.
#[cfg(target_os = "linux")]
fn manual_switch_root(new_root: &str) -> ! {
    use nix::unistd::{chdir, chroot, execv};
    use std::ffi::CString;

    // Move mounts.
    let _ = fs::create_dir_all(format!("{}/oldroot", new_root));

    // pivot_root.
    let put_old = format!("{}/oldroot", new_root);
    if let Err(e) = nix::unistd::pivot_root(new_root, put_old.as_str()) {
        eprintln!("[arcbox-init] pivot_root failed: {}", e);
    }

    // Change directory and chroot.
    let _ = chdir("/");

    // Unmount old root.
    #[cfg(target_os = "linux")]
    {
        use nix::mount::{MntFlags, umount2};
        let _ = umount2("/oldroot", MntFlags::MNT_DETACH);
    }
    let _ = fs::remove_dir("/oldroot");

    // Exec /sbin/init.
    let init = CString::new("/sbin/init").unwrap();
    let args = [init.clone()];
    let _ = execv(&init, &args);

    eprintln!("[arcbox-init] execv /sbin/init failed");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Checks if the kernel command line contains `arcbox.mode=machine`.
pub fn is_machine_mode() -> bool {
    match fs::read_to_string("/proc/cmdline") {
        Ok(cmdline) => cmdline.contains("arcbox.mode=machine"),
        Err(_) => false,
    }
}
