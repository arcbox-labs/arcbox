//! Filesystem mounting in guest.
//!
//! This module is only functional on Linux as it runs inside the guest VM.

use anyhow::Result;

/// Mount a filesystem.
#[cfg(target_os = "linux")]
pub fn mount_fs(source: &str, target: &str, fstype: &str, _options: &[String]) -> Result<()> {
    use nix::mount::{MsFlags, mount};
    use std::path::Path;

    tracing::info!("Mounting {} on {} (type: {})", source, target, fstype);

    // Create mount point if it doesn't exist
    std::fs::create_dir_all(target)?;

    let source: Option<&str> = Some(source);
    let target = Path::new(target);
    let fstype: Option<&str> = Some(fstype);
    let flags = MsFlags::empty();
    let data: Option<&str> = None;

    mount(source, target, fstype, flags, data)?;

    Ok(())
}

/// Mount a filesystem (stub for non-Linux platforms).
#[cfg(not(target_os = "linux"))]
pub fn mount_fs(source: &str, target: &str, fstype: &str, _options: &[String]) -> Result<()> {
    tracing::warn!(
        "mount_fs is only supported on Linux (called with source={}, target={}, fstype={})",
        source,
        target,
        fstype
    );
    anyhow::bail!("mount_fs is only supported on Linux")
}

/// Unmount a filesystem.
#[cfg(target_os = "linux")]
pub fn unmount_fs(target: &str) -> Result<()> {
    tracing::info!("Unmounting {}", target);
    nix::mount::umount(target)?;
    Ok(())
}

/// Unmount a filesystem (stub for non-Linux platforms).
#[cfg(not(target_os = "linux"))]
pub fn unmount_fs(target: &str) -> Result<()> {
    tracing::warn!("unmount_fs is only supported on Linux (target={})", target);
    anyhow::bail!("unmount_fs is only supported on Linux")
}

/// Mount virtiofs share.
pub fn mount_virtiofs(tag: &str, mountpoint: &str) -> Result<()> {
    mount_fs(tag, mountpoint, "virtiofs", &[])
}

/// Checks if a path is already mounted.
#[cfg(target_os = "linux")]
pub fn is_mounted(path: &str) -> bool {
    use std::fs;
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        content.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.get(1).is_some_and(|&p| p == path)
        })
    } else {
        false
    }
}

#[cfg(not(target_os = "linux"))]
pub fn is_mounted(_path: &str) -> bool {
    false
}

/// Mount all standard VirtioFS shares if not already mounted.
///
/// This mounts:
/// - "arcbox" tag -> /arcbox (data directory)
/// - "users" tag -> /Users (macOS /Users, bind-mounted to original path)
pub fn mount_standard_shares() {
    // Mount arcbox data directory
    if !is_mounted("/arcbox") {
        if let Err(e) = mount_virtiofs("arcbox", "/arcbox") {
            tracing::warn!("Failed to mount arcbox share: {}", e);
        } else {
            tracing::info!("Mounted arcbox share at /arcbox");
        }
    }

    // Mount /Users share for transparent macOS path support.
    // This allows `docker run -v /Users/foo/project:/app` to work directly
    // because /Users exists in the guest at the same path as on the host.
    if !is_mounted("/Users") {
        if let Err(e) = mount_virtiofs("users", "/Users") {
            tracing::debug!("Users share not available: {}", e);
        } else {
            tracing::info!("Mounted users share at /Users");
        }
    }
}
