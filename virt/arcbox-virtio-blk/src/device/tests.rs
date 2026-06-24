use std::io::Write;
use std::path::PathBuf;

use arcbox_virtio_core::VirtioDevice;
use tempfile::NamedTempFile;

use crate::request::BlockConfig;

use super::VirtioBlock;
use super::range::parse_range_list;

#[test]
fn test_block_device_creation() {
    let config = BlockConfig {
        capacity: 2048,
        blk_size: 512,
        path: PathBuf::from("/tmp/test.img"),
        read_only: false,
        num_queues: 1,
    };

    let device = VirtioBlock::new(config);
    assert_eq!(device.capacity_bytes(), 2048 * 512);
}

#[test]
fn test_block_device_from_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0u8; 4096]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();
    assert_eq!(device.config.capacity, 8); // 4096 / 512
}

#[test]
fn test_block_config_features() {
    let ro_config = BlockConfig {
        capacity: 1024,
        blk_size: 512,
        path: PathBuf::new(),
        read_only: true,
        num_queues: 1,
    };

    let device = VirtioBlock::new(ro_config);
    assert!(device.features() & VirtioBlock::FEATURE_RO != 0);
    // A read-only device must not advertise mutating ops it cannot honor.
    assert_eq!(device.features() & VirtioBlock::FEATURE_DISCARD, 0);
    assert_eq!(device.features() & VirtioBlock::FEATURE_WRITE_ZEROES, 0);
}

#[test]
fn test_read_write() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0u8; 4096]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    let write_data = b"Hello, VirtIO!";
    device.handle_write(0, write_data).unwrap();

    let mut read_data = vec![0u8; write_data.len()];
    device.handle_read(0, &mut read_data).unwrap();

    assert_eq!(&read_data, write_data);
}

#[test]
fn test_block_device_not_activated() {
    let config = BlockConfig {
        capacity: 1024,
        blk_size: 512,
        path: PathBuf::new(),
        read_only: false,
        num_queues: 1,
    };

    let device = VirtioBlock::new(config);

    let mut buf = vec![0u8; 512];
    let result = device.handle_read(0, &mut buf);
    assert!(result.is_err());
}

#[test]
fn test_block_device_read_only_write() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0u8; 4096]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), true).unwrap();

    let result = device.handle_write(0, b"test");
    assert!(result.is_err());
}

#[test]
fn test_block_device_flush() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0u8; 4096]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    assert!(device.handle_flush().is_ok());
}

#[test]
fn test_block_device_get_id() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0u8; 4096]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    let mut buf = vec![0u8; 64];
    let len = device.handle_get_id(&mut buf).unwrap();
    assert!(len > 0);

    let id = String::from_utf8_lossy(&buf[..len]);
    assert!(id.starts_with("arcbox-blk-"));
}

#[test]
fn test_block_device_activate_and_reset() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0u8; 4096]).unwrap();

    let mut device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    device.activate().unwrap();
    assert!(device.queue.is_some());

    device.reset();
    assert!(device.queue.is_none());
    assert_eq!(device.acked_features, 0);
}

#[test]
fn test_block_config_space() {
    let config = BlockConfig {
        capacity: 2048,
        blk_size: 512,
        path: PathBuf::new(),
        read_only: false,
        num_queues: 1,
    };

    let device = VirtioBlock::new(config);

    let mut buf = [0u8; 8];
    device.read_config(0, &mut buf);
    let capacity = u64::from_le_bytes(buf);
    assert_eq!(capacity, 2048);

    let mut buf = [0u8; 4];
    device.read_config(20, &mut buf);
    let blk_size = u32::from_le_bytes(buf);
    assert_eq!(blk_size, 512);
}

#[test]
fn test_block_device_large_io() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let size = 1024 * 1024; // 1MB
    temp_file.write_all(&vec![0u8; size]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    let write_data = vec![0xAB; 65536];
    device.handle_write(0, &write_data).unwrap();

    let mut read_data = vec![0u8; 65536];
    device.handle_read(0, &mut read_data).unwrap();
    assert_eq!(read_data, write_data);
}

#[test]
fn test_block_device_sector_alignment() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0u8; 8192]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    let write_data = b"Sector2Data";
    device.handle_write(2, write_data).unwrap();

    let mut read_data = vec![0u8; write_data.len()];
    device.handle_read(2, &mut read_data).unwrap();
    assert_eq!(&read_data, write_data);

    let mut sector0 = vec![0u8; 512];
    device.handle_read(0, &mut sector0).unwrap();
    assert!(sector0.iter().all(|&b| b == 0));
}

#[test]
fn test_features_advertise_discard_and_write_zeroes() {
    let device = VirtioBlock::new(BlockConfig::default());
    assert!(device.features() & VirtioBlock::FEATURE_DISCARD != 0);
    assert!(device.features() & VirtioBlock::FEATURE_WRITE_ZEROES != 0);
}

#[test]
fn test_config_space_exposes_discard_write_zeroes_limits() {
    let device = VirtioBlock::new(BlockConfig::default());

    let mut buf = [0u8; 4];
    device.read_config(36, &mut buf); // max_discard_sectors
    assert_eq!(u32::from_le_bytes(buf), VirtioBlock::MAX_DISCARD_SECTORS,);

    device.read_config(48, &mut buf); // max_write_zeroes_sectors
    assert_eq!(
        u32::from_le_bytes(buf),
        VirtioBlock::MAX_WRITE_ZEROES_SECTORS,
    );

    let mut unmap = [0u8; 1];
    device.read_config(56, &mut unmap); // write_zeroes_may_unmap
    assert_eq!(unmap[0], 0);
}

#[test]
fn test_parse_range_list_rejects_malformed() {
    assert!(parse_range_list(&[]).is_err());
    assert!(parse_range_list(&[0u8; 15]).is_err());
    assert!(parse_range_list(&[0u8; 17]).is_err());
}

#[test]
fn test_parse_range_list_roundtrip() {
    let mut bytes = Vec::with_capacity(32);
    // range 0: sector=10, num_sectors=8, flags=0
    bytes.extend_from_slice(&10u64.to_le_bytes());
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    // range 1: sector=100, num_sectors=2, flags=1 (UNMAP)
    bytes.extend_from_slice(&100u64.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());

    let ranges = parse_range_list(&bytes).unwrap();
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].sector, 10);
    assert_eq!(ranges[0].num_sectors, 8);
    assert_eq!(ranges[0].flags, 0);
    assert_eq!(ranges[1].sector, 100);
    assert_eq!(ranges[1].flags, 1);
}

#[test]
fn test_handle_discard_accepts_valid_range() {
    use std::os::unix::fs::MetadataExt;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0xAAu8; 1024 * 1024]).unwrap();
    temp_file.as_file().sync_all().unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u64.to_le_bytes()); // sector
    bytes.extend_from_slice(&2048u32.to_le_bytes()); // num_sectors (1 MiB)
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags

    device.handle_discard_list(&bytes).unwrap();
    temp_file.as_file().sync_all().unwrap();

    let after = std::fs::metadata(temp_file.path()).unwrap().blocks() * 512;
    assert!(
        after < 64 * 1024,
        "discard should have punched the backing file, still {after} allocated"
    );
}

#[test]
fn test_handle_discard_rejects_oversize_range() {
    let device = VirtioBlock::new(BlockConfig::default());

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&(VirtioBlock::MAX_DISCARD_SECTORS + 1).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    assert!(device.handle_discard_list(&bytes).is_err());
}

#[test]
fn test_handle_write_zeroes_actually_zeros_sectors() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0xFFu8; 4096]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    // Zero sectors 0..4 (2048 bytes), leave 2048..4096 untouched.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    device.handle_write_zeroes_list(&bytes).unwrap();

    let mut buf = vec![0u8; 2048];
    device.handle_read(0, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));

    let mut tail = vec![0u8; 2048];
    device.handle_read(4, &mut tail).unwrap();
    assert!(tail.iter().all(|&b| b == 0xFF));
}

#[test]
fn test_handle_write_zeroes_rejects_read_only() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0xFFu8; 4096]).unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), true).unwrap();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    assert!(device.handle_write_zeroes_list(&bytes).is_err());
}

#[test]
fn test_handle_write_zeroes_rejects_oversize_range() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file
        .write_all(&vec![
            0u8;
            (VirtioBlock::MAX_WRITE_ZEROES_SECTORS as usize + 1)
                * 512
        ])
        .unwrap();

    let device = VirtioBlock::from_path(temp_file.path(), false).unwrap();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&(VirtioBlock::MAX_WRITE_ZEROES_SECTORS + 1).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    assert!(device.handle_write_zeroes_list(&bytes).is_err());
}
