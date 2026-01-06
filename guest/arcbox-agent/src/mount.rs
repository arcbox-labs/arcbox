//! Filesystem mounting in guest.
//!
//! This module is only functional on Linux as it runs inside the guest VM.

use anyhow::Result;

/// Mount a filesystem.
#[cfg(target_os = "linux")]
pub fn mount_fs(
    source: &str,
    target: &str,
    fstype: &str,
    _options: &[String],
) -> Result<()> {
    use nix::mount::{mount, MsFlags};
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
pub fn mount_fs(
    source: &str,
    target: &str,
    fstype: &str,
    _options: &[String],
) -> Result<()> {
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
