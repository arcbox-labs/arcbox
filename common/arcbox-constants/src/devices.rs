/// Default root block device path in guest.
pub const ROOT_BLOCK_DEVICE: &str = "/dev/vda";

/// Default Docker data block device path in guest.
pub const DOCKER_DATA_BLOCK_DEVICE: &str = "/dev/vdb";

/// Default Docker metadata block device path in guest.
///
/// The ext4 volume carrying the fsync-hot boltdb metadata directories; paired
/// with the btrfs data device (see ../company/engineering/arcbox/plans/ext4-metadata-volume.md).
pub const DOCKER_METADATA_BLOCK_DEVICE: &str = "/dev/vdc";
