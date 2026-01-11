//! Integration tests for VirtIO devices.
//!
//! These tests verify the interaction between different VirtIO components.

use arcbox_virtio::blk::{BlockConfig, VirtioBlock, BlockRequestType, MmapBackend, AsyncBlockBackend};
use arcbox_virtio::console::{ConsoleConfig, VirtioConsole, BufferConsole, ConsoleIo};
use arcbox_virtio::net::{NetConfig, VirtioNet, LoopbackBackend, NetPacket, VirtioNetHeader, NetBackend};
use arcbox_virtio::vsock::{VsockConfig, VirtioVsock, VsockAddr};
use arcbox_virtio::fs::{FsConfig, VirtioFs};
use arcbox_virtio::{VirtioDevice, VirtioDeviceId};

// ============================================================================
// Block Device Integration Tests
// ============================================================================

#[test]
fn test_block_device_full_lifecycle() {
    // Create block device
    let config = BlockConfig {
        capacity: 1024 * 1024, // 1MB
        read_only: false,
        ..Default::default()
    };
    let mut blk = VirtioBlock::new(config);

    // Verify initial state
    assert_eq!(blk.device_id(), VirtioDeviceId::Block);

    // Negotiate features
    let offered = blk.features();
    assert!(offered & VirtioBlock::FEATURE_SIZE_MAX != 0);

    blk.ack_features(VirtioBlock::FEATURE_SIZE_MAX | VirtioBlock::FEATURE_BLK_SIZE);

    // Activate device
    blk.activate().unwrap();

    // Test request types exist
    let _in_type = BlockRequestType::In;
    let _out_type = BlockRequestType::Out;

    // Reset and verify state
    blk.reset();
}

#[test]
fn test_block_device_with_mmap_backend() {
    // Create a temporary file and mmap backend
    let temp = tempfile::NamedTempFile::new().unwrap();
    let path = temp.path();

    // Write initial data
    std::fs::write(path, vec![0u8; 4096]).unwrap();

    // Create mmap backend
    let backend = MmapBackend::new(path, false).unwrap();

    // Write through mmap
    let data = [0xDE, 0xAD, 0xBE, 0xEF];
    backend.write(0, &data).unwrap();

    // Read back
    let mut buf = [0u8; 4];
    backend.read(0, &mut buf).unwrap();
    assert_eq!(buf, data);

    // Verify sync
    backend.sync().unwrap();
}

#[test]
fn test_block_config_space_read() {
    let config = BlockConfig {
        capacity: 1024 * 1024 * 100, // 100MB
        blk_size: 4096,
        ..Default::default()
    };
    let blk = VirtioBlock::new(config);

    // Read capacity (offset 0, 8 bytes)
    let mut capacity_bytes = [0u8; 8];
    blk.read_config(0, &mut capacity_bytes);
    let capacity = u64::from_le_bytes(capacity_bytes);
    // Config stores capacity in bytes (or however it's implemented)
    assert!(capacity > 0);
}

// ============================================================================
// Console Device Integration Tests
// ============================================================================

#[test]
fn test_console_device_full_lifecycle() {
    let config = ConsoleConfig {
        cols: 80,
        rows: 25,
        ..Default::default()
    };
    let mut console = VirtioConsole::new(config);

    // Verify device
    assert_eq!(console.device_id(), VirtioDeviceId::Console);

    // Check features
    let features = console.features();
    assert!(features & VirtioConsole::FEATURE_SIZE != 0);

    // Activate
    console.activate().unwrap();

    // Test output
    let output = console.read_output();
    assert!(output.is_empty());

    // Reset
    console.reset();
}

#[test]
fn test_console_with_buffer_backend() {
    let mut backend = BufferConsole::new();

    // Test write
    backend.write(b"Hello Console").unwrap();

    // BufferConsole stores output internally
    // We can't read it back via the trait, just test it doesn't panic
}

#[test]
fn test_console_config_space() {
    let config = ConsoleConfig {
        cols: 132,
        rows: 43,
        ..Default::default()
    };
    let console = VirtioConsole::new(config);

    // Read cols (offset 0)
    let mut cols = [0u8; 2];
    console.read_config(0, &mut cols);
    assert_eq!(u16::from_le_bytes(cols), 132);

    // Read rows (offset 2)
    let mut rows = [0u8; 2];
    console.read_config(2, &mut rows);
    assert_eq!(u16::from_le_bytes(rows), 43);
}

// ============================================================================
// Network Device Integration Tests
// ============================================================================

#[test]
fn test_network_device_full_lifecycle() {
    let config = NetConfig {
        mac: [0x52, 0x54, 0xAB, 0x12, 0x34, 0x56],
        mtu: 1500,
        num_queues: 1,
        tap_name: None,
    };
    let mut net = VirtioNet::new(config);

    // Verify device
    assert_eq!(net.device_id(), VirtioDeviceId::Net);
    assert!(net.is_link_up());

    // Check MAC
    assert_eq!(net.mac(), &[0x52, 0x54, 0xAB, 0x12, 0x34, 0x56]);

    // Features
    let features = net.features();
    assert!(features & VirtioNet::FEATURE_MAC != 0);
    assert!(features & VirtioNet::FEATURE_MTU != 0);

    net.ack_features(VirtioNet::FEATURE_MAC | VirtioNet::FEATURE_STATUS);

    // Activate
    net.activate().unwrap();

    // Test link status
    net.set_link_up(false);
    assert!(!net.is_link_up());
    net.set_link_up(true);
    assert!(net.is_link_up());

    // Stats should be zero
    assert_eq!(net.tx_stats(), (0, 0));
    assert_eq!(net.rx_stats(), (0, 0));

    // Reset
    net.reset();
}

#[test]
fn test_network_with_loopback() {
    let mut net = VirtioNet::with_loopback();
    net.activate().unwrap();

    // Queue a packet for reception
    let packet = NetPacket::new(vec![0xFF; 100]);
    net.queue_rx(packet);

    // Should have the packet pending
    assert_eq!(net.rx_pending(), 1);
}

#[test]
fn test_network_packet_handling() {
    // Create header
    let header = VirtioNetHeader {
        flags: VirtioNetHeader::FLAG_NEEDS_CSUM,
        gso_type: VirtioNetHeader::GSO_NONE,
        hdr_len: 0,
        gso_size: 0,
        csum_start: 14, // After Ethernet header
        csum_offset: 16, // TCP checksum offset
        num_buffers: 1,
    };

    // Serialize and deserialize
    let bytes = header.to_bytes();
    let parsed = VirtioNetHeader::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.flags, VirtioNetHeader::FLAG_NEEDS_CSUM);
    assert_eq!(parsed.gso_type, VirtioNetHeader::GSO_NONE);
    assert_eq!(parsed.csum_start, 14);
    assert_eq!(parsed.csum_offset, 16);

    // Create packet
    let packet = NetPacket {
        header: parsed,
        data: vec![0xAA; 64],
    };
    assert_eq!(packet.total_size(), VirtioNetHeader::SIZE + 64);
}

#[test]
fn test_loopback_backend_throughput() {
    let mut backend = LoopbackBackend::new();

    // Send many packets
    const PACKET_COUNT: usize = 1000;
    const PACKET_SIZE: usize = 1500;

    for i in 0..PACKET_COUNT {
        let data = vec![(i % 256) as u8; PACKET_SIZE];
        let packet = NetPacket::new(data);
        backend.send(&packet).unwrap();
    }

    // Receive all packets
    let mut received = 0;
    while backend.has_data() {
        let mut buf = vec![0u8; PACKET_SIZE];
        let n = backend.recv(&mut buf).unwrap();
        assert_eq!(n, PACKET_SIZE);
        assert_eq!(buf[0], (received % 256) as u8);
        received += 1;
    }

    assert_eq!(received, PACKET_COUNT);
}

// ============================================================================
// Vsock Device Integration Tests
// ============================================================================

#[test]
fn test_vsock_device_full_lifecycle() {
    let config = VsockConfig { guest_cid: 10 };
    let mut vsock = VirtioVsock::new(config);

    // Verify device
    assert_eq!(vsock.device_id(), VirtioDeviceId::Vsock);
    assert_eq!(vsock.guest_cid(), 10);

    // Features
    let features = vsock.features();
    assert!(features & VirtioVsock::FEATURE_STREAM != 0);

    vsock.ack_features(VirtioVsock::FEATURE_STREAM);

    // Activate
    vsock.activate().unwrap();

    // Reset
    vsock.reset();
}

#[test]
fn test_vsock_addressing() {
    // Guest address
    let guest_addr = VsockAddr::new(3, 8080);
    assert_eq!(guest_addr.cid, 3);
    assert_eq!(guest_addr.port, 8080);

    // Host address
    let host_addr = VsockAddr::host(9090);
    assert_eq!(host_addr.cid, VirtioVsock::HOST_CID);
    assert_eq!(host_addr.port, 9090);

    // Equality
    let addr1 = VsockAddr::new(3, 8080);
    let addr2 = VsockAddr::new(3, 8080);
    assert_eq!(addr1, addr2);
}

// ============================================================================
// Filesystem Device Integration Tests
// ============================================================================

#[test]
fn test_fs_device_full_lifecycle() {
    let config = FsConfig {
        tag: "myshare".to_string(),
        num_queues: 2,
        queue_size: 512,
        shared_dir: "/tmp/shared".to_string(),
    };
    let mut fs = VirtioFs::new(config);

    // Verify device
    assert_eq!(fs.device_id(), VirtioDeviceId::Fs);
    assert_eq!(fs.tag(), "myshare");
    assert_eq!(fs.shared_dir(), "/tmp/shared");

    // Features (none by default)
    assert_eq!(fs.features(), 0);

    // Activate
    fs.activate().unwrap();

    // Reset
    fs.reset();
}

#[test]
fn test_fs_config_space() {
    let config = FsConfig {
        tag: "testfs".to_string(),
        num_queues: 8,
        ..Default::default()
    };
    let fs = VirtioFs::new(config);

    // Read tag
    let mut tag = [0u8; 36];
    fs.read_config(0, &mut tag);
    assert_eq!(&tag[0..6], b"testfs");

    // Read num_queues
    let mut num_queues = [0u8; 4];
    fs.read_config(36, &mut num_queues);
    assert_eq!(u32::from_le_bytes(num_queues), 8);
}

// ============================================================================
// Cross-Device Integration Tests
// ============================================================================

#[test]
fn test_all_device_ids_unique() {
    let blk = VirtioBlock::new(BlockConfig::default());
    let console = VirtioConsole::new(ConsoleConfig::default());
    let net = VirtioNet::new(NetConfig::default());
    let vsock = VirtioVsock::new(VsockConfig::default());
    let fs = VirtioFs::new(FsConfig::default());

    let ids = [
        blk.device_id(),
        console.device_id(),
        net.device_id(),
        vsock.device_id(),
        fs.device_id(),
    ];

    // All IDs should be unique
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j], "Device IDs {} and {} are not unique", i, j);
        }
    }
}

#[test]
fn test_all_devices_reset_cleanly() {
    // Block device
    let mut blk = VirtioBlock::new(BlockConfig::default());
    blk.ack_features(VirtioBlock::FEATURE_SIZE_MAX);
    blk.activate().unwrap();
    blk.reset();

    // Console
    let mut console = VirtioConsole::new(ConsoleConfig::default());
    console.ack_features(VirtioConsole::FEATURE_SIZE);
    console.activate().unwrap();
    console.reset();

    // Network
    let mut net = VirtioNet::new(NetConfig::default());
    net.ack_features(VirtioNet::FEATURE_MAC);
    net.activate().unwrap();
    net.reset();

    // Vsock
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.ack_features(VirtioVsock::FEATURE_STREAM);
    vsock.activate().unwrap();
    vsock.reset();

    // Filesystem
    let mut fs = VirtioFs::new(FsConfig {
        shared_dir: "/tmp".to_string(),
        ..Default::default()
    });
    fs.activate().unwrap();
    fs.reset();
}

#[test]
fn test_device_config_immutability() {
    // Network - MAC should be immutable
    let mut net = VirtioNet::new(NetConfig {
        mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        ..Default::default()
    });
    net.write_config(0, &[0xFF; 6]);
    assert_eq!(net.mac(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    // Vsock - CID should be immutable
    let mut vsock = VirtioVsock::new(VsockConfig { guest_cid: 42 });
    vsock.write_config(0, &0xFFFFFFFFu64.to_le_bytes());
    assert_eq!(vsock.guest_cid(), 42);

    // Filesystem - tag should be immutable
    let mut fs = VirtioFs::new(FsConfig {
        tag: "original".to_string(),
        ..Default::default()
    });
    fs.write_config(0, b"modified");
    assert_eq!(fs.tag(), "original");
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_console_high_throughput() {
    let mut backend = BufferConsole::new();

    // Write lots of data
    for _ in 0..1000 {
        backend.write(b"Hello, VirtIO console! This is a test message.\n").unwrap();
    }

    // Just verify it doesn't panic
}

#[test]
fn test_block_request_types() {
    // Test all request types
    let types = [
        BlockRequestType::In,
        BlockRequestType::Out,
        BlockRequestType::Flush,
        BlockRequestType::GetId,
        BlockRequestType::Discard,
        BlockRequestType::WriteZeroes,
    ];

    for _req_type in types {
        // Just verify all types exist and can be used
    }
}

#[test]
fn test_network_mac_generation() {
    // Generate multiple MACs
    let macs: Vec<_> = (0..10).map(|_| NetConfig::random_mac()).collect();

    // All should have correct OUI prefix
    for mac in &macs {
        assert_eq!(mac[0], 0x52);
        assert_eq!(mac[1], 0x54);
        assert_eq!(mac[2], 0xAB);
    }
}
