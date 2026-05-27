//! Convert a Docker overlay2 layer directory to a bootable ext4 rootfs.
//!
//! Runs `oci2rootfs` on the overlay2 layer path, then injects `/sbin/vm-agent`
//! into the resulting ext4 via loop mount. Cached ext4 images are reused to
//! avoid redundant conversions.

use std::path::Path;

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use uuid::Uuid;

/// Path to the `oci2rootfs` binary (on VirtioFS).
const OCI2ROOTFS_BIN: &str = "/arcbox/bin/oci2rootfs";

/// Path to the `vm-agent` binary (on VirtioFS).
const VM_AGENT_BIN: &str = "/arcbox/bin/vm-agent";

/// Directory for cached rootfs images.
const ROOTFS_CACHE_DIR: &str = "/arcbox/bin";

/// Check if a file has a valid ext4 superblock magic (0x53EF at offset 0x438).
pub fn has_ext4_magic(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 2];
    file.seek(SeekFrom::Start(0x438)).is_ok()
        && file.read_exact(&mut magic).is_ok()
        && magic == [0x53, 0xEF]
}

/// Convert an overlay2 layer directory to a bootable ext4 rootfs.
///
/// `layer_path` is a guest-visible overlay2 chain-id directory
/// (e.g. `/var/lib/docker/overlay2/<chain-id>`).
/// Returns the path to the generated (or cached) ext4 image.
pub async fn convert_layer_to_rootfs(layer_path: &str) -> Result<String> {
    if !Path::new(layer_path).exists() {
        bail!("layer path not found: {layer_path}");
    }

    // Cache key derived from the layer path (overlay2 chain-id directories
    // are content-addressed, so the path is a stable identifier).
    let hash = path_hash(layer_path);
    let ext4_path = format!("{ROOTFS_CACHE_DIR}/rootfs-{hash}.ext4");

    // Check cache.
    if Path::new(&ext4_path).exists() && has_ext4_magic(Path::new(&ext4_path)) {
        tracing::info!(path = %ext4_path, "using cached rootfs");
        return Ok(ext4_path);
    }

    let req_id = Uuid::new_v4().to_string();
    let ext4_tmp = format!("{ROOTFS_CACHE_DIR}/.rootfs-{req_id}.ext4.tmp");

    // Run oci2rootfs.
    tracing::info!(layer = %layer_path, ext4 = %ext4_path, "converting overlay2 layer to ext4");
    run_oci2rootfs(layer_path, &ext4_tmp).await?;

    // Inject vm-agent.
    tracing::info!("injecting vm-agent into rootfs");
    inject_vm_agent(&ext4_tmp, &req_id).await?;

    // Atomic rename into cache.
    tokio::fs::rename(&ext4_tmp, &ext4_path)
        .await
        .context("failed to rename ext4 into cache")?;

    tracing::info!(path = %ext4_path, "rootfs ready");
    Ok(ext4_path)
}

/// Run `oci2rootfs` on an overlay2 layer directory.
async fn run_oci2rootfs(layer_path: &str, output: &str) -> Result<()> {
    if !Path::new(OCI2ROOTFS_BIN).exists() {
        bail!("oci2rootfs not found at {OCI2ROOTFS_BIN}");
    }

    let result = Command::new(OCI2ROOTFS_BIN)
        .args([layer_path, "--output", output])
        .output()
        .await
        .context("failed to spawn oci2rootfs")?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        bail!("oci2rootfs failed: {stderr}");
    }
    Ok(())
}

/// Inject vm-agent into an ext4 image via loop mount.
async fn inject_vm_agent(ext4_path: &str, req_id: &str) -> Result<()> {
    if !Path::new(VM_AGENT_BIN).exists() {
        bail!("vm-agent not found at {VM_AGENT_BIN}");
    }

    let mount_dir = format!("/tmp/arcbox-inject-{req_id}");
    tokio::fs::create_dir_all(&mount_dir).await?;

    // Mount.
    let status = Command::new("/bin/busybox")
        .args(["mount", "-o", "loop", ext4_path, &mount_dir])
        .status()
        .await
        .context("failed to mount ext4 for vm-agent injection")?;
    if !status.success() {
        let _ = tokio::fs::remove_dir(&mount_dir).await;
        bail!("mount -o loop failed");
    }

    // Create /sbin and copy vm-agent.
    let sbin = format!("{mount_dir}/sbin");
    tokio::fs::create_dir_all(&sbin)
        .await
        .context("failed to create /sbin in rootfs")?;
    let dest = format!("{sbin}/vm-agent");
    let copy_result = tokio::fs::copy(VM_AGENT_BIN, &dest).await;

    // chmod 755.
    if copy_result.is_ok() {
        let _ = Command::new("/bin/busybox")
            .args(["chmod", "755", &dest])
            .status()
            .await;
    }

    // Always unmount and cleanup, even on failure.
    let _ = Command::new("/bin/busybox")
        .args(["umount", &mount_dir])
        .status()
        .await;
    let _ = tokio::fs::remove_dir(&mount_dir).await;

    copy_result.context("failed to copy vm-agent into rootfs")?;
    Ok(())
}

/// Derive a stable cache key from the layer path.
fn path_hash(path: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_ext4_magic_nonexistent() {
        assert!(!has_ext4_magic(Path::new("/nonexistent")));
    }

    #[test]
    fn test_path_hash_deterministic() {
        let a = path_hash("/var/lib/docker/overlay2/abc123");
        let b = path_hash("/var/lib/docker/overlay2/abc123");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn test_path_hash_different() {
        let a = path_hash("/var/lib/docker/overlay2/abc123");
        let b = path_hash("/var/lib/docker/overlay2/def456");
        assert_ne!(a, b);
    }
}
