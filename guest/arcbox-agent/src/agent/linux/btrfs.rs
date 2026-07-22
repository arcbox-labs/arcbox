//! Btrfs data volume detection, format, and bind-mount setup.
//!
//! On first boot the data device is formatted as Btrfs with five subvolumes
//! (`@docker`, `@containerd`, `@k3s`, `@kubelet`, `@cni`), each bind-mounted
//! to its canonical path. The fsync-hot boltdb metadata is NOT kept here —
//! it lives on the ext4 metadata volume (`metadata_volume.rs`); btrfs holds
//! the bulk, compression-friendly data.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use arcbox_constants::paths::{
    CNI_DATA_MOUNT_POINT, CONTAINERD_DATA_MOUNT_POINT, DOCKER_DATA_MOUNT_POINT,
    K3S_DATA_MOUNT_POINT, KUBELET_DATA_MOUNT_POINT,
};

use super::cmdline::docker_data_device;

/// Btrfs primary superblock magic `_BHRfS_M` at absolute disk offset
/// `0x10040` (superblock starts at `0x10000`, magic at internal offset `0x40`).
const BTRFS_MAGIC: [u8; 8] = [0x5f, 0x42, 0x48, 0x52, 0x66, 0x53, 0x5f, 0x4d];
const BTRFS_MAGIC_OFFSET: u64 = 0x10040;
/// Offset of the `total_bytes` field in the Btrfs superblock (superblock at
/// 64 KiB + 0x70 within it).
const BTRFS_TOTAL_BYTES_OFFSET: u64 = 0x10070;

/// Temporary mount point for the raw Btrfs device before subvolume bind mounts.
///
/// Must live on a writable filesystem. `/run` is tmpfs (set up in PID1 init),
/// while EROFS root is read-only and cannot host dynamic mountpoints.
const BTRFS_TEMP_MOUNT: &str = "/run/arcbox/data";

fn has_btrfs_superblock(device: &str) -> bool {
    let mut file = match std::fs::File::open(device) {
        Ok(file) => file,
        Err(_) => return false,
    };
    if file.seek(SeekFrom::Start(BTRFS_MAGIC_OFFSET)).is_err() {
        return false;
    }
    let mut magic = [0_u8; 8];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    magic == BTRFS_MAGIC
}

/// Reads the Btrfs superblock's `total_bytes` (the device size the filesystem
/// was last resized to). `None` if the field can't be read.
fn btrfs_total_bytes(device: &str) -> Option<u64> {
    let mut file = std::fs::File::open(device).ok()?;
    file.seek(SeekFrom::Start(BTRFS_TOTAL_BYTES_OFFSET)).ok()?;
    let mut buf = [0_u8; 8];
    file.read_exact(&mut buf).ok()?;
    Some(u64::from_le_bytes(buf))
}

/// Reads a block device's size in bytes by seeking to its end.
fn block_device_size(device: &str) -> Option<u64> {
    let mut file = std::fs::File::open(device).ok()?;
    file.seek(SeekFrom::End(0)).ok()
}

/// Fails loudly when the block device is smaller than the Btrfs filesystem it
/// carries. Btrfs refuses to mount (`open_ctree failed`) in that case, so a
/// bare mount error would otherwise repeat every retry with no explanation.
///
/// The mismatch happens when the VM engine is switched to a backend that
/// exposes a smaller disk than the one the filesystem was grown against (the
/// VZ→HV capacity bug). The data is intact; switching the engine back recovers.
fn check_device_fits_filesystem(device: &str) -> Result<(), String> {
    let (Some(fs_bytes), Some(dev_bytes)) = (btrfs_total_bytes(device), block_device_size(device))
    else {
        return Ok(());
    };
    if dev_bytes < fs_bytes {
        return Err(format!(
            "data disk is {dev_bytes} bytes but its Btrfs filesystem was grown to \
             {fs_bytes} bytes; the block device shrank (VM engine switched to a \
             backend exposing a smaller disk). Switch the engine back to VZ to \
             recover — the data is intact."
        ));
    }
    Ok(())
}

/// Formats the device as Btrfs if it does not already have a Btrfs superblock.
/// Old ext4 disks are unconditionally wiped (alpha breaking change).
fn ensure_btrfs_format(device: &str) -> Result<String, String> {
    if has_btrfs_superblock(device) {
        return Ok("data device already Btrfs".to_string());
    }

    // /sbin/mkfs.btrfs is baked into the EROFS rootfs.
    let binary = "/sbin/mkfs.btrfs";
    if !Path::new(binary).exists() {
        return Err(format!("{} not found in EROFS rootfs", binary));
    }

    match std::process::Command::new(binary)
        .args(["-f", device])
        .status()
    {
        Ok(status) if status.success() => Ok(format!("formatted {} as Btrfs", device)),
        Ok(status) => Err(format!(
            "mkfs.btrfs failed on {} (exit={})",
            device,
            status.code().unwrap_or(-1)
        )),
        Err(e) => Err(format!("failed to execute mkfs.btrfs: {}", e)),
    }
}

/// Mounts the data volume (Btrfs), creates subvolumes, and bind-mounts them.
///
/// Layout after this function returns:
/// - `/run/arcbox/data` — raw Btrfs mount (internal, not used by daemons)
/// - `/var/lib/docker` — bind mount of `@docker` subvolume
/// - `/var/lib/containerd` — bind mount of `@containerd` subvolume
/// - `/var/lib/rancher/k3s` — bind mount of `@k3s` subvolume
/// - `/var/lib/kubelet` — bind mount of `@kubelet` subvolume
/// - `/var/lib/cni` — bind mount of `@cni` subvolume
///
/// Returns `Ok(notes)` on success or `Err(reason)` if the data volume
/// could not be set up. Callers must abort runtime startup on error —
/// running containerd/dockerd without persistent storage is unsafe.
pub(super) fn ensure_data_mount() -> Result<String, String> {
    // Already fully set up?
    if crate::mount::is_mounted(DOCKER_DATA_MOUNT_POINT)
        && crate::mount::is_mounted(CONTAINERD_DATA_MOUNT_POINT)
        && crate::mount::is_mounted(K3S_DATA_MOUNT_POINT)
        && crate::mount::is_mounted(KUBELET_DATA_MOUNT_POINT)
        && crate::mount::is_mounted(CNI_DATA_MOUNT_POINT)
    {
        return Ok("data subvolumes already mounted".to_string());
    }

    let device = docker_data_device();

    // Wait for the VirtIO block device to appear. The kernel may need a
    // moment to probe and register the device after boot. The 5 s budget is
    // a heuristic; if it expires the underlying kernel probe is stuck and
    // raising it would just mask the symptom.
    {
        let mut attempts = 0;
        while !Path::new(&device).exists() {
            attempts += 1;
            if attempts > 50 {
                return Err(format!("data device {} not available after 5 s", device));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if attempts > 0 {
            tracing::info!(device, attempts, "waited for data device");
        }
    }

    // Step 1: Format if not Btrfs.
    match ensure_btrfs_format(&device) {
        Ok(note) => tracing::info!("{}", note),
        Err(e) => return Err(e),
    }

    // Step 1.5: Fail loudly if the device is smaller than its filesystem — Btrfs
    // would otherwise reject the mount below with an opaque error on every retry.
    check_device_fits_filesystem(&device)?;

    // Step 2: Mount raw Btrfs to temporary writable mount point.
    if !crate::mount::is_mounted(BTRFS_TEMP_MOUNT) {
        if let Err(e) = std::fs::create_dir_all(BTRFS_TEMP_MOUNT) {
            return Err(format!("failed to create {}: {}", BTRFS_TEMP_MOUNT, e));
        }
        match std::process::Command::new("/bin/busybox")
            .args([
                "mount",
                "-t",
                "btrfs",
                "-o",
                "compress=zstd:3,discard=async",
                &device,
                BTRFS_TEMP_MOUNT,
            ])
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => {
                return Err(format!(
                    "mount -t btrfs {} {} failed (exit={})",
                    device,
                    BTRFS_TEMP_MOUNT,
                    s.code().unwrap_or(-1)
                ));
            }
            Err(e) => return Err(format!("mount exec failed: {}", e)),
        }
    }

    let mut notes = Vec::new();

    // Step 2.5: Grow the Btrfs filesystem to fill the (possibly resized)
    // block device. The host sparse image may have grown since the last
    // boot (e.g. 64 GiB → 8 TiB upgrade). `BTRFS_IOC_RESIZE` with "max"
    // is a no-op when the FS already fills the device, so this is safe to
    // run unconditionally. Failures are surfaced as a note rather than
    // aborting the mount — running on the old capacity is preferable to
    // refusing to start.
    match btrfs_resize_max(BTRFS_TEMP_MOUNT) {
        Ok(note) => notes.push(note),
        Err(e) => {
            tracing::error!(error = %e, "btrfs resize max failed");
            notes.push(format!("resize failed: {}", e));
        }
    }

    // Step 3: Create subvolumes if missing.
    for subvol in ["@docker", "@containerd", "@k3s", "@kubelet", "@cni"] {
        let subvol_path = format!("{}/{}", BTRFS_TEMP_MOUNT, subvol);
        if Path::new(&subvol_path).exists() {
            continue;
        }
        // EROFS only includes mkfs.btrfs, not full btrfs-progs. Use the
        // BTRFS_IOC_SUBVOL_CREATE ioctl directly to create subvolumes.
        if let Err(e) = btrfs_create_subvolume(&subvol_path) {
            return Err(format!("failed to create subvolume {}: {}", subvol, e));
        }
    }

    // Step 4: Bind mount subvolumes to final paths.
    for (subvol, target) in [
        ("@docker", DOCKER_DATA_MOUNT_POINT),
        ("@containerd", CONTAINERD_DATA_MOUNT_POINT),
        ("@k3s", K3S_DATA_MOUNT_POINT),
        ("@kubelet", KUBELET_DATA_MOUNT_POINT),
        ("@cni", CNI_DATA_MOUNT_POINT),
    ] {
        if crate::mount::is_mounted(target) {
            continue;
        }
        if let Err(e) = std::fs::create_dir_all(target) {
            return Err(format!("failed to create {}: {}", target, e));
        }
        let opts = format!(
            "compress=zstd:1,discard=async,noatime,space_cache=v2,subvol={}",
            subvol
        );
        match std::process::Command::new("/bin/busybox")
            .args(["mount", "-t", "btrfs", "-o", &opts, &device, target])
            .status()
        {
            Ok(s) if s.success() => {
                notes.push(format!("mounted {} -> {}", subvol, target));
            }
            Ok(s) => {
                return Err(format!(
                    "mount subvol={} {} failed (exit={})",
                    subvol,
                    target,
                    s.code().unwrap_or(-1)
                ));
            }
            Err(e) => return Err(format!("mount exec failed: {}", e)),
        }
    }

    if notes.is_empty() {
        Ok("data subvolumes already mounted".to_string())
    } else {
        Ok(notes.join("; "))
    }
}

// BTRFS_IOC_SUBVOL_CREATE = _IOW(0x94, 14, struct btrfs_ioctl_vol_args)
// struct btrfs_ioctl_vol_args { __s64 fd; char name[4088]; }  total = 4096 bytes
//
// nix::ioctl_write_ptr! computes the request number portably (handles
// c_int on musl vs c_ulong on glibc).
nix::ioctl_write_ptr!(btrfs_ioc_subvol_create, 0x94, 14, [u8; 4096]);

// BTRFS_IOC_RESIZE = _IOW(0x94, 3, struct btrfs_ioctl_vol_args)
nix::ioctl_write_ptr!(btrfs_ioc_resize, 0x94, 3, [u8; 4096]);

/// Builds the `BTRFS_IOC_RESIZE` argument buffer.
///
/// Layout: `__s64 devid` (8 bytes) followed by a null-terminated name string
/// (up to 4088 bytes). For `BTRFS_IOC_RESIZE` the default device is `devid=1`
/// and the size token is e.g. `"max"`.
fn build_resize_args(devid: i64, size: &str) -> Result<[u8; 4096], String> {
    let size_bytes = size.as_bytes();
    if size_bytes.len() >= 4088 {
        return Err("resize size token too long".to_string());
    }
    let mut args = [0u8; 4096];
    args[0..8].copy_from_slice(&devid.to_le_bytes());
    args[8..8 + size_bytes.len()].copy_from_slice(size_bytes);
    Ok(args)
}

/// Grows the Btrfs filesystem on `mount_point` to fill the underlying
/// block device. Uses `BTRFS_IOC_RESIZE` with `"max"` — this is a no-op
/// when the FS already occupies the full device.
fn btrfs_resize_max(mount_point: &str) -> Result<String, String> {
    use std::os::unix::io::AsRawFd;

    let dir = std::fs::File::open(mount_point)
        .map_err(|e| format!("open {} for resize: {}", mount_point, e))?;
    let args = build_resize_args(1, "max")?;

    // SAFETY: valid fd from File::open, args buffer matches kernel struct layout.
    unsafe { btrfs_ioc_resize(dir.as_raw_fd(), &args) }
        .map_err(|e| format!("BTRFS_IOC_RESIZE max on {}: {}", mount_point, e))?;

    tracing::info!(mount_point, "btrfs resize max succeeded");
    Ok(format!("resized {} to device max", mount_point))
}

/// Creates a Btrfs subvolume using the `BTRFS_IOC_SUBVOL_CREATE` ioctl.
///
/// This avoids needing the full `btrfs-progs` CLI in the EROFS rootfs.
fn btrfs_create_subvolume(path: &str) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;

    let parent = Path::new(path)
        .parent()
        .ok_or_else(|| "no parent directory".to_string())?;
    let name = Path::new(path)
        .file_name()
        .ok_or_else(|| "no subvolume name".to_string())?
        .to_str()
        .ok_or_else(|| "invalid subvolume name".to_string())?;

    let parent_dir =
        std::fs::File::open(parent).map_err(|e| format!("open {}: {}", parent.display(), e))?;

    let mut args = [0u8; 4096];
    // First 8 bytes: fd field (unused for SUBVOL_CREATE, set to 0).
    // Bytes 8..4096: null-terminated name.
    let name_bytes = name.as_bytes();
    if name_bytes.len() >= 4088 {
        return Err("subvolume name too long".to_string());
    }
    args[8..8 + name_bytes.len()].copy_from_slice(name_bytes);

    // SAFETY: valid fd from File::open, args buffer is 4096 bytes matching
    // the kernel struct btrfs_ioctl_vol_args layout.
    unsafe { btrfs_ioc_subvol_create(parent_dir.as_raw_fd(), &args) }
        .map_err(|e| format!("BTRFS_IOC_SUBVOL_CREATE: {}", e))?;

    tracing::info!("created Btrfs subvolume {}", path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_resize_args;

    #[test]
    fn resize_args_layout_matches_kernel_struct() {
        let args = build_resize_args(1, "max").unwrap();
        // devid=1 as little-endian i64 in the first 8 bytes.
        assert_eq!(&args[0..8], &1i64.to_le_bytes());
        // "max" then a NUL terminator from the zero-initialized buffer.
        assert_eq!(&args[8..11], b"max");
        assert_eq!(args[11], 0);
        // Remainder must stay zero.
        assert!(args[12..].iter().all(|b| *b == 0));
    }

    #[test]
    fn resize_args_rejects_oversized_token() {
        let huge = "x".repeat(4088);
        assert!(build_resize_args(1, &huge).is_err());
    }
}
