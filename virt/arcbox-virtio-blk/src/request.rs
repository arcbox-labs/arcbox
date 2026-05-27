//! Block device wire types — config, request header, request type, status.

use std::path::PathBuf;

use arcbox_virtio_core::error::VirtioError;
use arcbox_virtio_core::virtio_bindings;

/// Block device configuration.
#[derive(Debug, Clone)]
pub struct BlockConfig {
    /// Disk capacity in 512-byte sectors.
    pub capacity: u64,
    /// Block size (usually 512).
    pub blk_size: u32,
    /// Path to the backing file/device.
    pub path: PathBuf,
    /// Read-only mode.
    pub read_only: bool,
    /// Number of request queues (1 = single queue, >1 = multi-queue with `F_MQ`).
    pub num_queues: u16,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            capacity: 0,
            blk_size: 512,
            path: PathBuf::new(),
            read_only: false,
            num_queues: 1,
        }
    }
}

/// `VirtIO` block request types.
///
/// Values sourced from `virtio_bindings::virtio_blk::VIRTIO_BLK_T_*`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRequestType {
    /// Read request.
    In = virtio_bindings::virtio_blk::VIRTIO_BLK_T_IN,
    /// Write request.
    Out = virtio_bindings::virtio_blk::VIRTIO_BLK_T_OUT,
    /// Flush request.
    Flush = virtio_bindings::virtio_blk::VIRTIO_BLK_T_FLUSH,
    /// Get device ID.
    GetId = virtio_bindings::virtio_blk::VIRTIO_BLK_T_GET_ID,
    /// Discard request.
    Discard = virtio_bindings::virtio_blk::VIRTIO_BLK_T_DISCARD,
    /// Write zeroes request.
    WriteZeroes = virtio_bindings::virtio_blk::VIRTIO_BLK_T_WRITE_ZEROES,
}

impl TryFrom<u32> for BlockRequestType {
    type Error = VirtioError;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        use virtio_bindings::virtio_blk;
        match value {
            virtio_blk::VIRTIO_BLK_T_IN => Ok(Self::In),
            virtio_blk::VIRTIO_BLK_T_OUT => Ok(Self::Out),
            virtio_blk::VIRTIO_BLK_T_FLUSH => Ok(Self::Flush),
            virtio_blk::VIRTIO_BLK_T_GET_ID => Ok(Self::GetId),
            virtio_blk::VIRTIO_BLK_T_DISCARD => Ok(Self::Discard),
            virtio_blk::VIRTIO_BLK_T_WRITE_ZEROES => Ok(Self::WriteZeroes),
            _ => Err(VirtioError::InvalidOperation(format!(
                "Unknown block request type: {value}"
            ))),
        }
    }
}

/// `VirtIO` block request status.
///
/// Values sourced from `virtio_bindings::virtio_blk::VIRTIO_BLK_S_*`.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum BlockStatus {
    /// Success.
    Ok = virtio_bindings::virtio_blk::VIRTIO_BLK_S_OK as u8,
    /// I/O error.
    IoErr = virtio_bindings::virtio_blk::VIRTIO_BLK_S_IOERR as u8,
    /// Unsupported operation.
    Unsupp = virtio_bindings::virtio_blk::VIRTIO_BLK_S_UNSUPP as u8,
}

/// `VirtIO` block request header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockRequestHeader {
    /// Request type.
    pub request_type: u32,
    /// Reserved.
    pub reserved: u32,
    /// Sector offset.
    pub sector: u64,
}

impl BlockRequestHeader {
    /// Size of the header in bytes.
    pub const SIZE: usize = 16;

    /// Parses header from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }

        Some(Self {
            request_type: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            reserved: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            sector: u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_header_parsing() {
        let bytes = [
            0x00, 0x00, 0x00, 0x00, // type: IN
            0x00, 0x00, 0x00, 0x00, // reserved
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sector: 16
        ];

        let header = BlockRequestHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.request_type, 0);
        assert_eq!(header.sector, 16);
    }

    #[test]
    fn test_request_header_too_short() {
        let bytes = [0x00, 0x00, 0x00];
        let header = BlockRequestHeader::from_bytes(&bytes);
        assert!(header.is_none());
    }

    #[test]
    fn test_invalid_request_type() {
        let result = BlockRequestType::try_from(999u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_request_types() {
        assert_eq!(BlockRequestType::try_from(0).unwrap(), BlockRequestType::In);
        assert_eq!(
            BlockRequestType::try_from(1).unwrap(),
            BlockRequestType::Out
        );
        assert_eq!(
            BlockRequestType::try_from(4).unwrap(),
            BlockRequestType::Flush
        );
        assert_eq!(
            BlockRequestType::try_from(8).unwrap(),
            BlockRequestType::GetId
        );
        assert_eq!(
            BlockRequestType::try_from(11).unwrap(),
            BlockRequestType::Discard
        );
        assert_eq!(
            BlockRequestType::try_from(13).unwrap(),
            BlockRequestType::WriteZeroes
        );
    }
}
