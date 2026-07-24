/// Default root block device path in guest.
pub const ROOT_BLOCK_DEVICE: &str = "/dev/vda";

/// Default Docker data block device path in guest.
pub const DOCKER_DATA_BLOCK_DEVICE: &str = "/dev/vdb";

/// Default Docker metadata block device path in guest.
///
/// The ext4 volume carrying the fsync-hot boltdb metadata directories; paired
/// with the btrfs data device (see internal-docs/plans/ext4-metadata-volume.md).
pub const DOCKER_METADATA_BLOCK_DEVICE: &str = "/dev/vdc";

/// Default read-only runtime-image block device path in guest.
///
/// The fourth disk, after the rootfs (vda), data (vdb) and metadata (vdc)
/// images; the host declares the real path on the kernel cmdline.
pub const RUNTIME_IMAGE_BLOCK_DEVICE: &str = "/dev/vdd";
