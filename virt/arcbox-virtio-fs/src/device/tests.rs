
use super::*;
use crate::protocol::{
    FUSE_ASYNC_READ, FUSE_BIG_WRITES, FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION,
};
use arcbox_virtio_core::queue::flags;
use arcbox_virtio_core::{VirtioDevice, VirtioDeviceId, virtio_bindings};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn test_fs_config_default() {
    let config = FsConfig::default();
    assert_eq!(config.tag, "arcbox");
    assert_eq!(config.num_queues, 1);
    assert_eq!(config.queue_size, 1024);
    assert!(config.shared_dir.is_empty());
}

#[test]
fn test_fs_config_custom() {
    let config = FsConfig {
        tag: "myfs".to_string(),
        num_queues: 4,
        queue_size: 256,
        shared_dir: "/home/user/shared".to_string(),
    };
    assert_eq!(config.tag, "myfs");
    assert_eq!(config.num_queues, 4);
    assert_eq!(config.queue_size, 256);
    assert_eq!(config.shared_dir, "/home/user/shared");
}

#[test]
fn test_fs_config_clone() {
    let config = FsConfig {
        tag: "test".to_string(),
        num_queues: 2,
        queue_size: 512,
        shared_dir: "/tmp".to_string(),
    };
    let cloned = config.clone();
    assert_eq!(cloned.tag, "test");
    assert_eq!(cloned.num_queues, 2);
}

#[test]
fn test_fs_new() {
    let fs = VirtioFs::new(FsConfig::default());
    assert_eq!(fs.tag(), "arcbox");
    assert!(fs.shared_dir().is_empty());
}

#[test]
fn test_fs_device_id() {
    let fs = VirtioFs::new(FsConfig::default());
    assert_eq!(fs.device_id(), VirtioDeviceId::Fs);
}

#[test]
fn test_fs_features() {
    let fs = VirtioFs::new(FsConfig::default());
    assert_ne!(
        fs.features() & (1 << virtio_bindings::virtio_config::VIRTIO_F_VERSION_1),
        0
    );
}

#[test]
fn test_fs_ack_features() {
    let mut fs = VirtioFs::new(FsConfig::default());
    fs.ack_features(VirtioFs::FEATURE_NOTIFICATION);
    assert_eq!(fs.acked_features & VirtioFs::FEATURE_NOTIFICATION, 0);
}

#[test]
fn test_fs_read_config_tag() {
    let config = FsConfig {
        tag: "testfs".to_string(),
        ..Default::default()
    };
    let fs = VirtioFs::new(config);

    let mut data = [0u8; 36];
    fs.read_config(0, &mut data);

    assert_eq!(&data[0..6], b"testfs");
    assert!(data[6..].iter().all(|&b| b == 0));
}

#[test]
fn test_fs_read_config_tag_long() {
    let config = FsConfig {
        tag: "a".repeat(50),
        ..Default::default()
    };
    let fs = VirtioFs::new(config);

    let mut data = [0u8; 36];
    fs.read_config(0, &mut data);

    assert!(data.iter().all(|&b| b == b'a'));
}

#[test]
fn test_fs_read_config_num_queues() {
    let config = FsConfig {
        num_queues: 4,
        ..Default::default()
    };
    let fs = VirtioFs::new(config);

    let mut data = [0u8; 4];
    fs.read_config(36, &mut data);

    let num_queues = u32::from_le_bytes(data);
    assert_eq!(num_queues, 4);
}

#[test]
fn test_fs_read_config_partial() {
    let fs = VirtioFs::new(FsConfig::default());

    let mut data = [0u8; 10];
    fs.read_config(35, &mut data);
}

#[test]
fn test_fs_read_config_beyond() {
    let fs = VirtioFs::new(FsConfig::default());

    let mut data = [0xFFu8; 4];
    fs.read_config(100, &mut data);
}

#[test]
fn test_fs_write_config_noop() {
    let config = FsConfig {
        tag: "original".to_string(),
        ..Default::default()
    };
    let mut fs = VirtioFs::new(config);

    fs.write_config(0, b"newvalue");

    assert_eq!(fs.tag(), "original");
}

#[test]
fn test_fs_activate() {
    let config = FsConfig {
        shared_dir: "/tmp".to_string(),
        ..Default::default()
    };
    let mut fs = VirtioFs::new(config);
    assert!(!fs.is_activated());

    assert!(fs.activate().is_ok());
    assert!(fs.is_activated());
    assert_eq!(fs.request_queues.len(), 1);

    // Activating again should be idempotent
    assert!(fs.activate().is_ok());
}

#[test]
fn test_fs_activate_no_shared_dir() {
    let mut fs = VirtioFs::new(FsConfig::default());
    assert!(fs.activate().is_err());
}

#[test]
fn test_fs_reset() {
    let config = FsConfig {
        shared_dir: "/tmp".to_string(),
        ..Default::default()
    };
    let mut fs = VirtioFs::new(config);
    fs.acked_features = 0xFF;
    fs.activate().unwrap();

    fs.reset();

    assert_eq!(fs.acked_features, 0);
    assert!(!fs.is_activated());
    assert!(!fs.session.is_initialized());
    assert!(fs.request_queues.is_empty());
}

#[test]
fn test_fs_tag_accessor() {
    let config = FsConfig {
        tag: "mytag".to_string(),
        ..Default::default()
    };
    let fs = VirtioFs::new(config);
    assert_eq!(fs.tag(), "mytag");
}

#[test]
fn test_fs_shared_dir_accessor() {
    let config = FsConfig {
        shared_dir: "/mnt/share".to_string(),
        ..Default::default()
    };
    let fs = VirtioFs::new(config);
    assert_eq!(fs.shared_dir(), "/mnt/share");
}

#[test]
fn test_fs_feature_constants() {
    assert_eq!(VirtioFs::FEATURE_NOTIFICATION, 1 << 0);
}

#[test]
fn test_fs_activate_creates_multiple_queues() {
    let config = FsConfig {
        shared_dir: "/tmp".to_string(),
        num_queues: 2,
        queue_size: 16,
        ..Default::default()
    };
    let mut fs = VirtioFs::new(config);
    fs.activate().unwrap();
    assert_eq!(fs.request_queues.len(), 2);
}

#[test]
fn test_fs_process_queue_roundtrip() {
    struct TestHandler {
        calls: Arc<AtomicUsize>,
    }

    impl FuseRequestHandler for TestHandler {
        fn handle_request(&self, request: &[u8]) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let unique = u64::from_le_bytes([
                request[8],
                request[9],
                request[10],
                request[11],
                request[12],
                request[13],
                request[14],
                request[15],
            ]);
            Ok(FuseResponse::new(unique, b"ok".to_vec()).into_data())
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(TestHandler {
        calls: Arc::clone(&calls),
    });

    let config = FsConfig {
        shared_dir: "/tmp".to_string(),
        queue_size: 16,
        ..Default::default()
    };
    let mut fs = VirtioFs::with_handler(config, handler);
    fs.activate().unwrap();

    let queue = fs.request_queues.get_mut(0).unwrap();
    let mut memory = vec![0u8; 1024];

    // Build FUSE_INIT request
    let mut init_req = vec![0u8; 56];
    init_req[0..4].copy_from_slice(&56u32.to_le_bytes());
    init_req[4..8].copy_from_slice(&VirtioFs::FUSE_INIT.to_le_bytes());
    init_req[8..16].copy_from_slice(&1u64.to_le_bytes());
    init_req[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
    init_req[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
    init_req[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
    init_req[52..56].copy_from_slice(&(FUSE_ASYNC_READ | FUSE_BIG_WRITES).to_le_bytes());

    let init_req_offset = 0usize;
    let init_resp_offset = 128usize;
    memory[init_req_offset..init_req_offset + init_req.len()].copy_from_slice(&init_req);

    queue
        .set_descriptor(
            0,
            arcbox_virtio_core::queue::Descriptor {
                addr: init_req_offset as u64,
                len: init_req.len() as u32,
                flags: flags::NEXT,
                next: 1,
            },
        )
        .unwrap();
    queue
        .set_descriptor(
            1,
            arcbox_virtio_core::queue::Descriptor {
                addr: init_resp_offset as u64,
                len: 80,
                flags: flags::WRITE,
                next: 0,
            },
        )
        .unwrap();

    // Build a simple FUSE request that goes to the handler
    let mut other_req = vec![0u8; 40];
    other_req[0..4].copy_from_slice(&40u32.to_le_bytes());
    other_req[4..8].copy_from_slice(&1u32.to_le_bytes());
    other_req[8..16].copy_from_slice(&2u64.to_le_bytes());

    let other_req_offset = 256usize;
    let other_resp_offset = 512usize;
    memory[other_req_offset..other_req_offset + other_req.len()].copy_from_slice(&other_req);

    queue
        .set_descriptor(
            2,
            arcbox_virtio_core::queue::Descriptor {
                addr: other_req_offset as u64,
                len: other_req.len() as u32,
                flags: flags::NEXT,
                next: 3,
            },
        )
        .unwrap();
    queue
        .set_descriptor(
            3,
            arcbox_virtio_core::queue::Descriptor {
                addr: other_resp_offset as u64,
                len: 32,
                flags: flags::WRITE,
                next: 0,
            },
        )
        .unwrap();

    queue.add_avail(0).unwrap();
    queue.add_avail(2).unwrap();

    let completions = fs.process_queue(0, &mut memory).unwrap();
    assert_eq!(completions.len(), 2);
    assert!(fs.session.is_initialized());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let response = &memory[other_resp_offset..other_resp_offset + 18];
    assert_eq!(&response[16..18], b"ok");
}

#[test]
fn test_fs_process_request_too_small() {
    let config = FsConfig {
        shared_dir: "/tmp".to_string(),
        ..Default::default()
    };
    let mut fs = VirtioFs::new(config);
    fs.activate().unwrap();

    let result = fs.process_request(&[0u8; 20]);
    assert!(result.is_err());
}

#[test]
fn test_fs_process_request_before_init() {
    let config = FsConfig {
        shared_dir: "/tmp".to_string(),
        ..Default::default()
    };
    let mut fs = VirtioFs::new(config);
    fs.activate().unwrap();

    // Send a non-INIT request before initialization
    let mut request = vec![0u8; 40];
    request[4..8].copy_from_slice(&1u32.to_le_bytes()); // LOOKUP opcode
    request[8..16].copy_from_slice(&1u64.to_le_bytes()); // unique

    let response = fs.process_request(&request).unwrap();

    let error = i32::from_le_bytes([response[4], response[5], response[6], response[7]]);
    assert_eq!(error, -libc::EINVAL);
}

#[test]
fn test_fs_process_request_no_handler() {
    let config = FsConfig {
        shared_dir: "/tmp".to_string(),
        ..Default::default()
    };
    let mut fs = VirtioFs::new(config);
    fs.activate().unwrap();

    // First, send FUSE_INIT
    let mut init_request = vec![0u8; 56];
    init_request[4..8].copy_from_slice(&26u32.to_le_bytes()); // INIT opcode
    init_request[8..16].copy_from_slice(&1u64.to_le_bytes());
    init_request[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
    init_request[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
    init_request[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
    init_request[52..56].copy_from_slice(&0u32.to_le_bytes());

    fs.process_request(&init_request).unwrap();
    assert!(fs.session.is_initialized());

    // Now send another request - should get ENOSYS since no handler
    let mut request = vec![0u8; 40];
    request[4..8].copy_from_slice(&1u32.to_le_bytes()); // LOOKUP opcode
    request[8..16].copy_from_slice(&2u64.to_le_bytes()); // unique

    let response = fs.process_request(&request).unwrap();

    let error = i32::from_le_bytes([response[4], response[5], response[6], response[7]]);
    assert_eq!(error, -libc::ENOSYS);
}

#[test]
fn test_fs_with_handler() {
    use std::sync::atomic::AtomicU32;

    struct TestHandler {
        call_count: AtomicU32,
    }

    impl FuseRequestHandler for TestHandler {
        fn handle_request(&self, _request: &[u8]) -> Result<Vec<u8>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(FuseResponse::new(0, vec![]).into_data())
        }
    }

    let handler = Arc::new(TestHandler {
        call_count: AtomicU32::new(0),
    });

    let config = FsConfig {
        shared_dir: "/tmp".to_string(),
        ..Default::default()
    };
    let mut fs = VirtioFs::with_handler(config, handler.clone());
    fs.activate().unwrap();

    // Send FUSE_INIT
    let mut init_request = vec![0u8; 56];
    init_request[4..8].copy_from_slice(&26u32.to_le_bytes());
    init_request[8..16].copy_from_slice(&1u64.to_le_bytes());
    init_request[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
    init_request[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
    init_request[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
    init_request[52..56].copy_from_slice(&0u32.to_le_bytes());

    fs.process_request(&init_request).unwrap();

    // Send a regular request
    let mut request = vec![0u8; 40];
    request[4..8].copy_from_slice(&1u32.to_le_bytes());
    request[8..16].copy_from_slice(&2u64.to_le_bytes());

    fs.process_request(&request).unwrap();

    assert_eq!(handler.call_count.load(Ordering::SeqCst), 1);
}
