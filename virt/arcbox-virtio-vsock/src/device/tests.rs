use std::sync::{Arc, Mutex};

use arcbox_virtio_core::{QueueConfig, VirtioDevice, VirtioDeviceId};

use crate::addr::{VsockAddr, VsockHostConnections};
use crate::backend::LoopbackBackend;
use crate::protocol::{VsockHeader, VsockOp};

use super::*;

#[test]
fn test_vsock_config_default() {
    let config = VsockConfig::default();
    assert_eq!(config.guest_cid, 3);
}

#[test]
fn test_vsock_config_custom() {
    let config = VsockConfig { guest_cid: 100 };
    assert_eq!(config.guest_cid, 100);
}

#[test]
fn test_vsock_config_clone() {
    let config = VsockConfig { guest_cid: 42 };
    let cloned = config.clone();
    assert_eq!(cloned.guest_cid, 42);
}

#[test]
fn test_vsock_new() {
    let vsock = VirtioVsock::new(VsockConfig::default());
    assert_eq!(vsock.guest_cid(), 3);
}

#[test]
fn test_vsock_device_id() {
    let vsock = VirtioVsock::new(VsockConfig::default());
    assert_eq!(vsock.device_id(), VirtioDeviceId::Vsock);
}

#[test]
fn test_vsock_features() {
    let vsock = VirtioVsock::new(VsockConfig::default());
    let features = vsock.features();
    assert!(features & VirtioVsock::FEATURE_STREAM != 0);
}

#[test]
fn test_vsock_ack_features() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());

    vsock.ack_features(VirtioVsock::FEATURE_STREAM);
    assert_eq!(vsock.acked_features, VirtioVsock::FEATURE_STREAM);
}

#[test]
fn test_vsock_ack_unsupported_feature() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());

    // SEQPACKET is not supported by default
    vsock.ack_features(VirtioVsock::FEATURE_SEQPACKET);
    assert_eq!(vsock.acked_features, 0);
}

#[test]
fn test_vsock_read_config() {
    let config = VsockConfig {
        guest_cid: 0x12345678,
    };
    let vsock = VirtioVsock::new(config);

    let mut data = [0u8; 8];
    vsock.read_config(0, &mut data);

    let cid = u64::from_le_bytes(data);
    assert_eq!(cid, 0x12345678);
}

#[test]
fn test_vsock_read_config_partial() {
    let config = VsockConfig {
        guest_cid: 0xDEADBEEF,
    };
    let vsock = VirtioVsock::new(config);

    let mut data = [0u8; 4];
    vsock.read_config(0, &mut data);

    let low_bytes = u32::from_le_bytes(data);
    assert_eq!(low_bytes, 0xDEADBEEF);
}

#[test]
fn test_vsock_read_config_offset() {
    let config = VsockConfig {
        guest_cid: 0xAABBCCDD_11223344,
    };
    let vsock = VirtioVsock::new(config);

    let mut data = [0u8; 4];
    vsock.read_config(4, &mut data);

    let high_bytes = u32::from_le_bytes(data);
    assert_eq!(high_bytes, 0xAABBCCDD);
}

#[test]
fn test_vsock_read_config_beyond() {
    let vsock = VirtioVsock::new(VsockConfig::default());

    let mut data = [0xFFu8; 4];
    vsock.read_config(100, &mut data);
}

#[test]
fn test_vsock_write_config_noop() {
    let mut vsock = VirtioVsock::new(VsockConfig { guest_cid: 42 });

    vsock.write_config(0, &[0xFF; 8]);

    assert_eq!(vsock.guest_cid(), 42);
}

#[test]
fn test_vsock_activate() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    assert!(vsock.activate().is_ok());
}

#[test]
fn test_vsock_reset() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.ack_features(VirtioVsock::FEATURE_STREAM);
    assert_ne!(vsock.acked_features, 0);

    vsock.reset();
    assert_eq!(vsock.acked_features, 0);
}

#[test]
fn test_vsock_constants() {
    assert_eq!(VirtioVsock::HOST_CID, 2);
    assert_eq!(VirtioVsock::RESERVED_CID, 1);
    assert_eq!(VirtioVsock::FEATURE_STREAM, 1 << 0);
    assert_eq!(VirtioVsock::FEATURE_SEQPACKET, 1 << 1);
}

#[test]
fn test_vsock_with_loopback_backend() {
    let vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
    assert_eq!(vsock.guest_cid(), 3);
    assert_eq!(vsock.connection_count(), 0);
}

#[test]
fn test_vsock_connect_send_recv() {
    let vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());

    vsock.handle_connect(1000, 80).unwrap();
    assert_eq!(vsock.connection_count(), 1);

    let data = b"GET / HTTP/1.1";
    let sent = vsock.handle_send(1000, 80, data).unwrap();
    assert_eq!(sent, data.len());

    let mut buf = [0u8; 64];
    let received = vsock.handle_recv(1000, 80, &mut buf).unwrap();
    assert_eq!(received, data.len());
    assert_eq!(&buf[..received], data);

    vsock.handle_close(1000, 80).unwrap();
    assert_eq!(vsock.connection_count(), 0);
}

#[test]
fn test_vsock_activate_creates_queues() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    assert!(vsock.rx_queue.is_none());
    assert!(vsock.tx_queue.is_none());
    assert!(vsock.event_queue.is_none());

    vsock.activate().unwrap();

    assert!(vsock.rx_queue.is_some());
    assert!(vsock.tx_queue.is_some());
    assert!(vsock.event_queue.is_some());
}

#[test]
fn test_vsock_reset_clears_queues() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.activate().unwrap();
    assert!(vsock.rx_queue.is_some());

    vsock.reset();
    assert!(vsock.rx_queue.is_none());
    assert!(vsock.tx_queue.is_none());
    assert!(vsock.event_queue.is_none());
}

/// Helper: Build a simulated guest memory region with a vsock packet
/// placed at a given address, and configure the TX queue with matching
/// descriptors.
fn setup_tx_packet(
    vsock: &mut VirtioVsock,
    guest_addr: usize,
    header: &VsockHeader,
    payload: &[u8],
    memory: &mut Vec<u8>,
) {
    let header_bytes = header.to_bytes();
    let total = header_bytes.len() + payload.len();

    if memory.len() < guest_addr + total {
        memory.resize(guest_addr + total, 0);
    }

    memory[guest_addr..guest_addr + header_bytes.len()].copy_from_slice(&header_bytes);
    if !payload.is_empty() {
        memory[guest_addr + header_bytes.len()..guest_addr + total].copy_from_slice(payload);
    }

    let queue = vsock.tx_queue.as_mut().unwrap();
    let desc = arcbox_virtio_core::queue::Descriptor {
        addr: guest_addr as u64,
        len: total as u32,
        flags: 0, // Read-only for device
        next: 0,
    };
    queue.set_descriptor(0, desc).unwrap();
    queue.add_avail(0).unwrap();
}

#[test]
fn test_process_tx_queue_not_ready() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    let mut memory = vec![0u8; 1024];
    let result = vsock.process_tx_queue(&mut memory);
    assert!(result.is_err());
}

#[test]
fn test_process_tx_queue_empty() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.activate().unwrap();

    let mut memory = vec![0u8; 4096];
    let completions = vsock.process_tx_queue(&mut memory).unwrap();
    assert!(completions.is_empty());
}

#[test]
fn test_process_tx_queue_connect_request() {
    let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
    vsock.activate().unwrap();

    let mut memory = vec![0u8; 4096];

    // Guest sends OP_REQUEST from port 1000 to host port 80.
    let header = VsockHeader::new(
        VsockAddr::new(3, 1000),
        VsockAddr::new(VirtioVsock::HOST_CID, 80),
        VsockOp::Request,
    );
    setup_tx_packet(&mut vsock, 0x100, &header, &[], &mut memory);

    // Also prepare RX queue with a write-only descriptor for the response.
    {
        let rx_queue = vsock.rx_queue.as_mut().unwrap();
        let rx_desc = arcbox_virtio_core::queue::Descriptor {
            addr: 0x800,
            len: 256,
            flags: arcbox_virtio_core::queue::flags::WRITE,
            next: 0,
        };
        rx_queue.set_descriptor(0, rx_desc).unwrap();
        rx_queue.add_avail(0).unwrap();
    }

    let completions = vsock.process_tx_queue(&mut memory).unwrap();
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].0, 0); // descriptor head index

    assert_eq!(vsock.connection_count(), 1);

    let resp_header = VsockHeader::from_bytes(&memory[0x800..0x800 + VsockHeader::SIZE]);
    assert!(resp_header.is_some());
    let resp = resp_header.unwrap();
    assert_eq!(resp.operation(), Some(VsockOp::Response));
    let resp_src_cid = resp.src_cid;
    let resp_dst_cid = resp.dst_cid;
    assert_eq!(resp_src_cid, VirtioVsock::HOST_CID);
    assert_eq!(resp_dst_cid, 3);
}

#[test]
fn test_process_tx_queue_data_rw() {
    let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
    vsock.activate().unwrap();

    vsock.handle_connect(1000, 80).unwrap();

    let mut memory = vec![0u8; 4096];

    let payload = b"hello world";
    let mut header = VsockHeader::new(
        VsockAddr::new(3, 1000),
        VsockAddr::new(VirtioVsock::HOST_CID, 80),
        VsockOp::Rw,
    );
    header.len = payload.len() as u32;
    setup_tx_packet(&mut vsock, 0x100, &header, payload, &mut memory);

    let completions = vsock.process_tx_queue(&mut memory).unwrap();
    assert_eq!(completions.len(), 1);

    let backend = vsock.backend.as_ref().unwrap();
    let mut backend = backend.lock().unwrap();
    let addr = VsockAddr::new(3, 1000);
    assert!(backend.has_pending_data(addr));

    let mut buf = [0u8; 64];
    let n = backend.on_recv(addr, &mut buf).unwrap();
    assert_eq!(&buf[..n], payload);
}

#[test]
fn test_process_tx_queue_shutdown() {
    let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
    vsock.activate().unwrap();

    vsock.handle_connect(2000, 443).unwrap();
    assert_eq!(vsock.connection_count(), 1);

    let mut memory = vec![0u8; 4096];

    let header = VsockHeader::new(
        VsockAddr::new(3, 2000),
        VsockAddr::new(VirtioVsock::HOST_CID, 443),
        VsockOp::Shutdown,
    );
    setup_tx_packet(&mut vsock, 0x100, &header, &[], &mut memory);

    // Provide an RX descriptor for the RST response.
    {
        let rx_queue = vsock.rx_queue.as_mut().unwrap();
        let rx_desc = arcbox_virtio_core::queue::Descriptor {
            addr: 0x800,
            len: 256,
            flags: arcbox_virtio_core::queue::flags::WRITE,
            next: 0,
        };
        rx_queue.set_descriptor(0, rx_desc).unwrap();
        rx_queue.add_avail(0).unwrap();
    }

    let completions = vsock.process_tx_queue(&mut memory).unwrap();
    assert_eq!(completions.len(), 1);

    assert_eq!(vsock.connection_count(), 0);

    let rst_header = VsockHeader::from_bytes(&memory[0x800..0x800 + VsockHeader::SIZE]);
    assert!(rst_header.is_some());
    assert_eq!(rst_header.unwrap().operation(), Some(VsockOp::Rst));
}

#[test]
fn test_process_tx_queue_credit_update() {
    let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
    vsock.activate().unwrap();

    vsock.handle_connect(3000, 22).unwrap();

    let mut memory = vec![0u8; 4096];

    let mut header = VsockHeader::new(
        VsockAddr::new(3, 3000),
        VsockAddr::new(VirtioVsock::HOST_CID, 22),
        VsockOp::CreditUpdate,
    );
    header.buf_alloc = 131_072;
    header.fwd_cnt = 500;
    setup_tx_packet(&mut vsock, 0x100, &header, &[], &mut memory);

    let completions = vsock.process_tx_queue(&mut memory).unwrap();
    assert_eq!(completions.len(), 1);

    let conns = vsock.connections.read().unwrap();
    let conn = conns.get(&(3000, 22)).unwrap();
    assert_eq!(conn.peer_buf_alloc, 131_072);
    assert_eq!(conn.peer_fwd_cnt, 500);
}

#[test]
fn test_process_queue_dispatches_tx() {
    let mut vsock = VirtioVsock::with_backend(VsockConfig::default(), LoopbackBackend::new());
    vsock.activate().unwrap();

    let mut memory = vec![0u8; 4096];

    let completions = vsock.process_queue(1, &mut memory).unwrap();
    assert!(completions.is_empty());
}

#[test]
fn test_process_queue_unknown_index() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.activate().unwrap();

    let mut memory = vec![0u8; 1024];
    let completions = vsock.process_queue(0, &mut memory).unwrap();
    assert!(completions.is_empty());
    let completions = vsock.process_queue(2, &mut memory).unwrap();
    assert!(completions.is_empty());
    let completions = vsock.process_queue(99, &mut memory).unwrap();
    assert!(completions.is_empty());
}

#[test]
fn test_inject_rx_packet_not_ready() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    let header = VsockHeader::new(
        VsockAddr::host(80),
        VsockAddr::new(3, 1000),
        VsockOp::Response,
    );
    let mut memory = vec![0u8; 1024];
    let result = vsock.inject_rx_packet(&header, &[], &mut memory);
    assert!(result.is_err());
}

#[test]
fn test_inject_rx_packet_no_descriptors() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.activate().unwrap();

    let header = VsockHeader::new(
        VsockAddr::host(80),
        VsockAddr::new(3, 1000),
        VsockOp::Response,
    );
    let mut memory = vec![0u8; 1024];
    let result = vsock.inject_rx_packet(&header, &[], &mut memory);
    assert!(result.is_err());
}

#[test]
fn test_inject_rx_packet_with_data() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.activate().unwrap();

    let mut memory = vec![0u8; 4096];

    {
        let rx_queue = vsock.rx_queue.as_mut().unwrap();
        let desc = arcbox_virtio_core::queue::Descriptor {
            addr: 0x200,
            len: 512,
            flags: arcbox_virtio_core::queue::flags::WRITE,
            next: 0,
        };
        rx_queue.set_descriptor(0, desc).unwrap();
        rx_queue.add_avail(0).unwrap();
    }

    let payload = b"response data";
    let mut header = VsockHeader::new(VsockAddr::host(80), VsockAddr::new(3, 1000), VsockOp::Rw);
    header.len = payload.len() as u32;

    vsock
        .inject_rx_packet(&header, payload, &mut memory)
        .unwrap();

    let written_hdr = VsockHeader::from_bytes(&memory[0x200..0x200 + VsockHeader::SIZE]).unwrap();
    assert_eq!(written_hdr.operation(), Some(VsockOp::Rw));
    let wh_src_cid = written_hdr.src_cid;
    assert_eq!(wh_src_cid, VirtioVsock::HOST_CID);

    let payload_start = 0x200 + VsockHeader::SIZE;
    assert_eq!(
        &memory[payload_start..payload_start + payload.len()],
        payload
    );
}

/// Builds a simulated split virtqueue layout in a flat memory buffer.
/// Returns (`desc_addr`, `avail_addr`, `used_addr`).
fn setup_virtqueue_layout(
    memory: &mut Vec<u8>,
    base: usize,
    q_size: usize,
) -> (usize, usize, usize) {
    let desc_addr = base;
    let avail_addr = desc_addr + q_size * 16;
    let avail_addr = (avail_addr + 15) & !15;
    let avail_size = 4 + 2 * q_size + 2;
    let used_addr = avail_addr + avail_size;
    let used_addr = (used_addr + 15) & !15;
    let used_size = 4 + 8 * q_size + 2;
    let total = used_addr + used_size;
    if memory.len() < total {
        memory.resize(total, 0);
    }
    (desc_addr, avail_addr, used_addr)
}

fn write_descriptor(
    memory: &mut [u8],
    desc_addr: usize,
    idx: usize,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) {
    let off = desc_addr + idx * 16;
    memory[off..off + 8].copy_from_slice(&addr.to_le_bytes());
    memory[off + 8..off + 12].copy_from_slice(&len.to_le_bytes());
    memory[off + 12..off + 14].copy_from_slice(&flags.to_le_bytes());
    memory[off + 14..off + 16].copy_from_slice(&next.to_le_bytes());
}

fn avail_ring_push(memory: &mut [u8], avail_addr: usize, q_size: usize, head_idx: u16) {
    let avail_idx = u16::from_le_bytes([memory[avail_addr + 2], memory[avail_addr + 3]]) as usize;
    let ring_off = avail_addr + 4 + 2 * (avail_idx % q_size);
    memory[ring_off..ring_off + 2].copy_from_slice(&head_idx.to_le_bytes());
    let new_idx = (avail_idx + 1) as u16;
    memory[avail_addr + 2..avail_addr + 4].copy_from_slice(&new_idx.to_le_bytes());
}

/// Verifies that the guest-memory-based `process_queue` correctly parses
/// a 44-byte OP_RESPONSE packet from the TX virtqueue.
#[test]
fn test_process_queue_guest_memory_op_response() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.activate().unwrap();

    let q_size = 16usize;
    let mut memory = vec![0u8; 0x10000];

    let (desc_addr, avail_addr, used_addr) = setup_virtqueue_layout(&mut memory, 0x4000, q_size);

    let pkt_addr = 0x8000usize;
    let hdr = VsockHeader::new(
        VsockAddr::new(3, 1024),
        VsockAddr::host(50000),
        VsockOp::Response,
    );
    let hdr_bytes = hdr.to_bytes();
    assert_eq!(
        hdr_bytes.len(),
        44,
        "VsockHeader must serialize to 44 bytes"
    );
    memory[pkt_addr..pkt_addr + 44].copy_from_slice(&hdr_bytes[..44]);

    write_descriptor(&mut memory, desc_addr, 0, pkt_addr as u64, 44, 0, 0);
    avail_ring_push(&mut memory, avail_addr, q_size, 0);

    struct MockConns {
        connected: Vec<(u32, u32)>,
        credit_updates: Vec<(u32, u32, u32, u32)>,
    }
    impl VsockHostConnections for MockConns {
        fn fd_for(&self, _gp: u32, _hp: u32) -> Option<std::os::unix::io::RawFd> {
            None
        }
        fn mark_connected(&mut self, gp: u32, hp: u32) {
            self.connected.push((gp, hp));
        }
        fn remove_connection(&mut self, _gp: u32, _hp: u32) {}
        fn update_peer_credit(&mut self, gp: u32, hp: u32, ba: u32, fc: u32) {
            self.credit_updates.push((gp, hp, ba, fc));
        }
    }

    let mock = Arc::new(Mutex::new(MockConns {
        connected: Vec::new(),
        credit_updates: Vec::new(),
    }));

    let qcfg = QueueConfig {
        desc_addr: desc_addr as u64,
        avail_addr: avail_addr as u64,
        used_addr: used_addr as u64,
        size: q_size as u16,
        ready: true,
        gpa_base: 0,
    };
    vsock.bind_connections(mock.clone());

    let completions =
        <VirtioVsock as VirtioDevice>::process_queue(&mut vsock, 1, &mut memory, &qcfg).unwrap();

    assert_eq!(
        completions.len(),
        1,
        "Expected 1 completion for OP_RESPONSE"
    );
    assert_eq!(completions[0].0, 0, "head_idx should be 0");
    assert_eq!(completions[0].1, 44, "written bytes should be 44");

    let mock_guard = mock.lock().unwrap();
    assert_eq!(
        mock_guard.connected.len(),
        1,
        "mark_connected should be called once for OP_RESPONSE"
    );
    assert_eq!(mock_guard.connected[0], (1024, 50000));

    assert_eq!(mock_guard.credit_updates.len(), 1);
    assert_eq!(
        mock_guard.credit_updates[0],
        (1024, 50000, 64 * 1024, 0),
        "peer credit should be synced from OP_RESPONSE header"
    );
}

/// Verifies that a 44-byte OP_RST from guest is correctly parsed via
/// the guest-memory `process_queue` path.
#[test]
fn test_process_queue_guest_memory_op_rst() {
    let mut vsock = VirtioVsock::new(VsockConfig::default());
    vsock.activate().unwrap();

    let q_size = 16usize;
    let mut memory = vec![0u8; 0x10000];

    let (desc_addr, avail_addr, used_addr) = setup_virtqueue_layout(&mut memory, 0x4000, q_size);

    let pkt_addr = 0x8000usize;
    let hdr = VsockHeader::new(
        VsockAddr::new(3, 1024),
        VsockAddr::host(50000),
        VsockOp::Rst,
    );
    memory[pkt_addr..pkt_addr + 44].copy_from_slice(&hdr.to_bytes()[..44]);

    write_descriptor(&mut memory, desc_addr, 0, pkt_addr as u64, 44, 0, 0);
    avail_ring_push(&mut memory, avail_addr, q_size, 0);

    struct MockConns {
        removed: Vec<(u32, u32)>,
    }
    impl VsockHostConnections for MockConns {
        fn fd_for(&self, _: u32, _: u32) -> Option<std::os::unix::io::RawFd> {
            None
        }
        fn mark_connected(&mut self, _: u32, _: u32) {}
        fn remove_connection(&mut self, gp: u32, hp: u32) {
            self.removed.push((gp, hp));
        }
    }
    let mock = Arc::new(Mutex::new(MockConns {
        removed: Vec::new(),
    }));

    let qcfg = QueueConfig {
        desc_addr: desc_addr as u64,
        avail_addr: avail_addr as u64,
        used_addr: used_addr as u64,
        size: q_size as u16,
        ready: true,
        gpa_base: 0,
    };
    vsock.bind_connections(mock.clone());

    let completions =
        <VirtioVsock as VirtioDevice>::process_queue(&mut vsock, 1, &mut memory, &qcfg).unwrap();
    assert_eq!(completions.len(), 1);

    let mock_guard = mock.lock().unwrap();
    assert_eq!(mock_guard.removed.len(), 1);
    assert_eq!(mock_guard.removed[0], (1024, 50000));
}
