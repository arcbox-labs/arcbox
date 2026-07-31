#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arcbox_virtio_core::{VirtioDevice, VirtioDeviceId};

use crate::backend::{LoopbackBackend, NetBackend};
use crate::config::{NetConfig, NetStatus};
use crate::header::{NetPacket, VirtioNetHeader};

use super::VirtioNet;
#[test]
fn test_net_device_creation() {
    let net = VirtioNet::new(NetConfig::default());
    assert_eq!(net.device_id(), VirtioDeviceId::Net);
    assert!(net.features() & VirtioNet::FEATURE_MAC != 0);
}

#[test]
fn test_net_device_features() {
    let net = VirtioNet::new(NetConfig::default());
    let features = net.features();

    assert!(features & VirtioNet::FEATURE_MAC != 0);
    assert!(features & VirtioNet::FEATURE_MTU != 0);
    assert!(features & VirtioNet::FEATURE_STATUS != 0);
    assert!(features & VirtioNet::FEATURE_CSUM != 0);
    assert!(features & VirtioNet::FEATURE_GUEST_CSUM != 0);
    assert!(features & VirtioNet::FEATURE_VERSION_1 != 0);
}

#[test]
fn test_net_device_ack_features() {
    let mut net = VirtioNet::new(NetConfig::default());

    let requested = VirtioNet::FEATURE_MAC | VirtioNet::FEATURE_MTU;
    net.ack_features(requested);

    assert_eq!(net.acked_features, requested & net.features());
}

#[test]
fn test_net_device_ack_features_unsupported() {
    let mut net = VirtioNet::new(NetConfig::default());

    let unsupported = 1 << 63;
    net.ack_features(unsupported);

    assert_eq!(net.acked_features, 0);
}

#[test]
fn test_mac_address() {
    let config = NetConfig {
        mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        ..Default::default()
    };
    let net = VirtioNet::new(config);

    let mut data = [0u8; 6];
    net.read_config(0, &mut data);
    assert_eq!(data, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
}

#[test]
fn test_read_config_status() {
    let net = VirtioNet::new(NetConfig::default());

    let mut data = [0u8; 2];
    net.read_config(6, &mut data);

    let status = u16::from_le_bytes(data);
    assert_eq!(status, NetStatus::LinkUp as u16);
}

#[test]
fn test_read_config_mtu() {
    let config = NetConfig {
        mtu: 9000,
        ..Default::default()
    };
    let net = VirtioNet::new(config);

    let mut data = [0u8; 2];
    net.read_config(10, &mut data);

    let mtu = u16::from_le_bytes(data);
    assert_eq!(mtu, 9000);
}

#[test]
fn test_read_config_num_queues() {
    let config = NetConfig {
        num_queues: 4,
        ..Default::default()
    };
    let net = VirtioNet::new(config);

    let mut data = [0u8; 2];
    net.read_config(8, &mut data);

    let num_queues = u16::from_le_bytes(data);
    assert_eq!(num_queues, 4);
}

#[test]
fn test_read_config_beyond_end() {
    let net = VirtioNet::new(NetConfig::default());

    let mut data = [0xFFu8; 4];
    net.read_config(100, &mut data);

    // Should not crash.
}

#[test]
fn test_read_config_partial() {
    let net = VirtioNet::new(NetConfig::default());

    let mut data = [0u8; 20];
    net.read_config(0, &mut data);

    assert_eq!(&data[0..6], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
}

#[test]
fn test_write_config_noop() {
    let mut net = VirtioNet::new(NetConfig::default());

    net.write_config(0, &[0xFF; 6]);

    assert_eq!(net.mac(), &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
}

#[test]
fn test_net_with_loopback() {
    let mut net = VirtioNet::with_loopback();
    net.activate().unwrap();

    assert!(net.is_link_up());
    assert!(net.backend.is_some());

    assert_eq!(net.tx_stats(), (0, 0));
    assert_eq!(net.rx_stats(), (0, 0));
}

#[test]
fn test_link_status() {
    let mut net = VirtioNet::new(NetConfig::default());

    assert!(net.is_link_up());

    net.set_link_up(false);
    assert!(!net.is_link_up());

    net.set_link_up(true);
    assert!(net.is_link_up());
}

#[test]
fn test_link_status_toggle_multiple() {
    let mut net = VirtioNet::new(NetConfig::default());

    for _ in 0..10 {
        net.set_link_up(false);
        assert!(!net.is_link_up());
        net.set_link_up(true);
        assert!(net.is_link_up());
    }
}

#[test]
fn test_net_activate() {
    let mut net = VirtioNet::new(NetConfig::default());

    assert!(net.rx_queue.is_none());
    assert!(net.tx_queue.is_none());

    net.activate().unwrap();

    assert!(net.rx_queue.is_some());
    assert!(net.tx_queue.is_some());
}

#[test]
fn test_net_reset() {
    let mut net = VirtioNet::with_loopback();
    net.activate().unwrap();

    net.queue_rx(NetPacket::new(vec![1, 2, 3]));
    assert_eq!(net.rx_pending(), 1);

    net.ack_features(VirtioNet::FEATURE_MAC);

    net.reset();

    assert_eq!(net.acked_features, 0);
    assert!(net.rx_queue.is_none());
    assert!(net.tx_queue.is_none());
    assert_eq!(net.rx_pending(), 0);
    assert_eq!(net.tx_stats(), (0, 0));
    assert_eq!(net.rx_stats(), (0, 0));
}

#[test]
fn test_queue_rx() {
    let mut net = VirtioNet::new(NetConfig::default());

    assert_eq!(net.rx_pending(), 0);

    net.queue_rx(NetPacket::new(vec![1, 2, 3]));
    assert_eq!(net.rx_pending(), 1);

    net.queue_rx(NetPacket::new(vec![4, 5, 6]));
    assert_eq!(net.rx_pending(), 2);
}

#[test]
fn test_set_backend() {
    let mut net = VirtioNet::new(NetConfig::default());

    assert!(net.backend.is_none());

    let backend = Arc::new(Mutex::new(LoopbackBackend::new()));
    net.set_backend(backend);

    assert!(net.backend.is_some());
}

#[test]
fn test_poll_backend_no_data() {
    let mut net = VirtioNet::with_loopback();

    net.poll_backend().unwrap();
    assert_eq!(net.rx_pending(), 0);
}

#[test]
fn test_poll_backend_with_data() {
    let mut net = VirtioNet::with_loopback();

    if let Some(backend) = &net.backend {
        let mut backend = backend.lock().unwrap();
        backend.send(&NetPacket::new(vec![1, 2, 3, 4, 5])).unwrap();
    }

    net.poll_backend().unwrap();
    assert_eq!(net.rx_pending(), 1);
    assert_eq!(net.rx_stats(), (1, 5));
}

#[test]
fn test_poll_backend_multiple() {
    let mut net = VirtioNet::with_loopback();

    if let Some(backend) = &net.backend {
        let mut backend = backend.lock().unwrap();
        for i in 0..5 {
            backend.send(&NetPacket::new(vec![i; 100])).unwrap();
        }
    }

    net.poll_backend().unwrap();
    assert_eq!(net.rx_pending(), 5);
    assert_eq!(net.rx_stats(), (5, 500));
}

#[test]
fn test_handle_tx_too_small() {
    let mut net = VirtioNet::with_loopback();

    let data = [0u8; 5];
    let result = net.handle_tx(&data);
    assert!(result.is_err());
}

#[test]
fn test_net_no_backend() {
    let mut net = VirtioNet::new(NetConfig::default());

    net.poll_backend().unwrap();
    assert_eq!(net.rx_pending(), 0);
}

#[test]
fn test_process_tx_queue_not_ready() {
    let mut net = VirtioNet::new(NetConfig::default());

    let memory = vec![0u8; 1024];
    let result = net.process_tx_queue(&memory);

    assert!(result.is_err());
}

#[test]
fn drain_tx_queue_refreshes_avail_event_on_empty_drain() {
    // ABX-386 regression: with VIRTIO_F_EVENT_IDX the guest consults
    // avail_event (vring_need_event) before every TX kick. An empty TX
    // kick MUST still republish avail_event = consumed cursor, otherwise a
    // stale value makes the guest suppress future kicks and wedges
    // guest→host TX — the flaky cold-boot "stuck at Starting Docker engine"
    // where the guest's DHCP DISCOVER never reaches the host.
    use std::sync::atomic::AtomicU16;

    use arcbox_virtio_core::{DeviceCtx, QueueConfig};

    use crate::config::NetPort;

    // Minimal split-virtqueue layout in a scratch "guest RAM" buffer,
    // GPA base 0, q_size = 4: desc @ 0x100, avail @ 0x200, used @ 0x300.
    let q_size: u16 = 4;
    let (desc_addr, avail_addr, used_addr) = (0x100usize, 0x200usize, 0x300usize);
    let avail_event_off = used_addr + 4 + q_size as usize * 8;
    let mut mem = vec![0u8; 0x1000];

    // The device has already drained everything the guest produced
    // (last_avail_tx == avail_idx == 3) → this kick drains nothing.
    let drained: u16 = 3;
    mem[avail_addr + 2..avail_addr + 4].copy_from_slice(&drained.to_le_bytes());
    // Stale avail_event (what the pre-fix empty-drain path leaves behind).
    mem[avail_event_off..avail_event_off + 2].copy_from_slice(&0u16.to_le_bytes());

    let mut net = VirtioNet::new(NetConfig::default());
    net.ack_features(arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX);

    // SAFETY: `mem` outlives `net` (declared first, dropped last) and is
    // not moved while the raw pointer is held by the bound context.
    let ctx = DeviceCtx {
        mem: std::sync::Arc::new(unsafe {
            arcbox_virtio_core::GuestMemWriter::new(mem.as_mut_ptr(), mem.len(), 0)
        }),
        raise_irq: std::sync::Arc::new(|_| {}),
    };
    net.bind_ctx(ctx);
    net.bind_port(NetPort {
        host_fd: -1, // unused: the empty drain writes no frame
        last_avail_tx: AtomicU16::new(drained),
    })
    .expect("bind port");

    let qcfg = QueueConfig {
        desc_addr: desc_addr as u64,
        avail_addr: avail_addr as u64,
        used_addr: used_addr as u64,
        size: q_size,
        ready: true,
        gpa_base: 0,
    };

    let notify = net.drain_tx_queue(&qcfg, |_| {});
    assert!(!notify, "nothing to drain → no completion → no IRQ");

    let published = u16::from_le_bytes([mem[avail_event_off], mem[avail_event_off + 1]]);
    assert_eq!(
        published, drained,
        "avail_event must be refreshed to the consumed cursor on an empty drain"
    );
}

#[test]
fn test_inject_rx_batch_mrg_rxbuf_spans_chains() {
    use arcbox_virtio_core::queue::{Descriptor, flags};
    // With MRG_RXBUF on, a frame larger than a single chain's write-only
    // capacity should consume multiple chains and stamp num_buffers with
    // the chain count in the first chain's virtio_net_hdr.
    let mut net = VirtioNet::with_loopback();
    net.enable_tso_features(); // adds MRG_RXBUF to the advertised set
    net.ack_features(VirtioNet::FEATURE_MRG_RXBUF);
    net.activate().unwrap();

    // Lay out a scratch "guest memory" big enough for header + payload
    // split across two small buffers (32 bytes each of write space).
    let mut memory = vec![0u8; 512];
    let buf0_addr = 128u64;
    let buf1_addr = 256u64;
    let buf_size: u32 = 32;

    {
        let q = net.rx_queue.as_mut().expect("rx queue");
        // Chain 0 at descriptor 0 — single write-only descriptor.
        q.set_descriptor(
            0,
            Descriptor {
                addr: buf0_addr,
                len: buf_size,
                flags: flags::WRITE,
                next: 0,
            },
        )
        .unwrap();
        // Chain 1 at descriptor 1 — single write-only descriptor.
        q.set_descriptor(
            1,
            Descriptor {
                addr: buf1_addr,
                len: buf_size,
                flags: flags::WRITE,
                next: 0,
            },
        )
        .unwrap();
        q.add_avail(0).unwrap();
        q.add_avail(1).unwrap();
        q.set_ready(true);
    }

    // Packet payload of 40 bytes; total frame = 12 (header) + 40 = 52
    // which exceeds a single 32-byte buffer → MRG_RXBUF must span.
    let payload = vec![0xABu8; 40];
    net.queue_rx(NetPacket::new(payload));

    let completions = net.inject_rx_batch(&mut memory).unwrap();
    assert_eq!(completions.len(), 2, "frame should span two chains");

    // num_buffers stamped at offset 10..12 in the first chain's header.
    let num_buffers = u16::from_le_bytes([
        memory[buf0_addr as usize + 10],
        memory[buf0_addr as usize + 11],
    ]);
    assert_eq!(num_buffers, 2);
}

#[test]
fn test_inject_rx_batch_no_mrg_rxbuf_stamps_one() {
    use arcbox_virtio_core::queue::{Descriptor, flags};
    // Without MRG_RXBUF, num_buffers should still be set to 1 for spec
    // compliance on VERSION_1 headers, and we should never consume more
    // than one chain even if the frame overflows.
    let mut net = VirtioNet::with_loopback();
    net.activate().unwrap(); // no MRG_RXBUF ack

    let mut memory = vec![0u8; 512];
    let buf_addr = 64u64;

    {
        let q = net.rx_queue.as_mut().expect("rx queue");
        q.set_descriptor(
            0,
            Descriptor {
                addr: buf_addr,
                len: 128,
                flags: flags::WRITE,
                next: 0,
            },
        )
        .unwrap();
        q.set_descriptor(
            1,
            Descriptor {
                addr: 300,
                len: 128,
                flags: flags::WRITE,
                next: 0,
            },
        )
        .unwrap();
        q.add_avail(0).unwrap();
        q.add_avail(1).unwrap();
        q.set_ready(true);
    }

    net.queue_rx(NetPacket::new(vec![0xCDu8; 40]));
    let completions = net.inject_rx_batch(&mut memory).unwrap();
    assert_eq!(completions.len(), 1, "must not span without MRG_RXBUF");

    let num_buffers = u16::from_le_bytes([
        memory[buf_addr as usize + 10],
        memory[buf_addr as usize + 11],
    ]);
    assert_eq!(num_buffers, 1);
}

#[test]
fn test_feature_constants() {
    assert_eq!(VirtioNet::FEATURE_CSUM, 1 << 0);
    assert_eq!(VirtioNet::FEATURE_GUEST_CSUM, 1 << 1);
    assert_eq!(VirtioNet::FEATURE_MTU, 1 << 3);
    assert_eq!(VirtioNet::FEATURE_MAC, 1 << 5);
    assert_eq!(VirtioNet::FEATURE_GSO, 1 << 6);
    assert_eq!(VirtioNet::FEATURE_GUEST_TSO4, 1 << 7);
    assert_eq!(VirtioNet::FEATURE_GUEST_TSO6, 1 << 8);
    assert_eq!(VirtioNet::FEATURE_GUEST_ECN, 1 << 9);
    assert_eq!(VirtioNet::FEATURE_GUEST_UFO, 1 << 10);
    assert_eq!(VirtioNet::FEATURE_HOST_TSO4, 1 << 11);
    assert_eq!(VirtioNet::FEATURE_HOST_TSO6, 1 << 12);
    assert_eq!(VirtioNet::FEATURE_HOST_ECN, 1 << 13);
    assert_eq!(VirtioNet::FEATURE_HOST_UFO, 1 << 14);
    assert_eq!(VirtioNet::FEATURE_MRG_RXBUF, 1 << 15);
    assert_eq!(VirtioNet::FEATURE_STATUS, 1 << 16);
    assert_eq!(VirtioNet::FEATURE_CTRL_VQ, 1 << 17);
    assert_eq!(VirtioNet::FEATURE_MQ, 1 << 22);
    assert_eq!(VirtioNet::FEATURE_VERSION_1, 1 << 32);
}

#[test]
fn test_enable_tso_features() {
    let mut net = VirtioNet::new(NetConfig::default());
    let base = net.features();

    assert_eq!(base & VirtioNet::FEATURE_GUEST_TSO4, 0);
    assert_eq!(base & VirtioNet::FEATURE_HOST_TSO4, 0);

    net.enable_tso_features();
    let tso = net.features();
    assert_ne!(tso & VirtioNet::FEATURE_GUEST_TSO4, 0);
    assert_ne!(tso & VirtioNet::FEATURE_GUEST_TSO6, 0);
    assert_ne!(tso & VirtioNet::FEATURE_HOST_TSO4, 0);
    assert_ne!(tso & VirtioNet::FEATURE_HOST_TSO6, 0);
    assert_ne!(tso & VirtioNet::FEATURE_GUEST_ECN, 0);
    assert_ne!(tso & VirtioNet::FEATURE_HOST_ECN, 0);
}

#[test]
fn test_tso_negotiated() {
    let mut net = VirtioNet::new(NetConfig::default());
    net.enable_tso_features();
    assert!(!net.tso_negotiated());

    net.ack_features(
        VirtioNet::FEATURE_MAC
            | VirtioNet::FEATURE_GUEST_TSO4
            | VirtioNet::FEATURE_VERSION_1
            | arcbox_virtio_core::queue::VIRTIO_F_EVENT_IDX,
    );
    assert!(net.tso_negotiated());
}

#[test]
fn test_handle_tx_routes_tso_to_send_tso() {
    // Backend that tracks whether send_tso was called.
    struct TsoTracker {
        tso_called: Arc<AtomicBool>,
    }
    impl NetBackend for TsoTracker {
        fn send(&mut self, _packet: &NetPacket) -> std::io::Result<usize> {
            Ok(0)
        }
        fn send_tso(&mut self, _packet: &NetPacket) -> std::io::Result<usize> {
            self.tso_called.store(true, Ordering::Relaxed);
            Ok(0)
        }
        fn recv(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
        fn has_data(&self) -> bool {
            false
        }
        fn supports_tso(&self) -> bool {
            true
        }
    }

    let flag = Arc::new(AtomicBool::new(false));
    let tracker = TsoTracker {
        tso_called: flag.clone(),
    };

    let mut net = VirtioNet::new(NetConfig::default());
    net.enable_tso_features();
    net.set_backend(Arc::new(Mutex::new(tracker)));

    // Build a TSO TX packet: 12-byte header + payload.
    let mut data = vec![0u8; VirtioNetHeader::SIZE + 4000];
    data[1] = VirtioNetHeader::GSO_TCPV4; // gso_type
    data[4..6].copy_from_slice(&1460u16.to_le_bytes()); // gso_size

    net.handle_tx(&data).unwrap();
    assert!(
        flag.load(Ordering::Relaxed),
        "send_tso should be called for TSO packets"
    );
}

#[test]
fn test_handle_tx_normal_packet_uses_send() {
    struct SendTracker {
        send_called: Arc<AtomicBool>,
    }
    impl NetBackend for SendTracker {
        fn send(&mut self, _packet: &NetPacket) -> std::io::Result<usize> {
            self.send_called.store(true, Ordering::Relaxed);
            Ok(0)
        }
        fn recv(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
        fn has_data(&self) -> bool {
            false
        }
    }

    let flag = Arc::new(AtomicBool::new(false));
    let tracker = SendTracker {
        send_called: flag.clone(),
    };

    let mut net = VirtioNet::new(NetConfig::default());
    net.set_backend(Arc::new(Mutex::new(tracker)));

    let data = vec![0u8; VirtioNetHeader::SIZE + 100];
    net.handle_tx(&data).unwrap();
    assert!(
        flag.load(Ordering::Relaxed),
        "send should be called for normal packets"
    );
}

/// Harness for `poll_rx`: scratch guest RAM with one RX chain of write-only
/// descriptors (`descs` = (addr, len) each, linked with NEXT), a datagram
/// socketpair as the host fd, and one queued `frame`. Returns (guest memory,
/// poll result), with the used ring at 0x300.
fn poll_rx_one_frame(descs: &[(u64, u32)], frame: &[u8]) -> (Vec<u8>, bool) {
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::AtomicU16;

    use arcbox_virtio_core::queue::flags;
    use arcbox_virtio_core::{DeviceCtx, QueueConfig};

    use crate::config::NetPort;

    let q_size: u16 = 4;
    let (desc_addr, avail_addr, used_addr) = (0x100usize, 0x200, 0x300);
    let mut mem = vec![0u8; 0x1000];

    // One chain of write-only descriptors, head 0, linked with NEXT.
    for (i, &(addr, len)) in descs.iter().enumerate() {
        let d = desc_addr + i * 16;
        let last = i == descs.len() - 1;
        let f = if last {
            flags::WRITE
        } else {
            flags::WRITE | flags::NEXT
        };
        mem[d..d + 8].copy_from_slice(&addr.to_le_bytes());
        mem[d + 8..d + 12].copy_from_slice(&len.to_le_bytes());
        mem[d + 12..d + 14].copy_from_slice(&f.to_le_bytes());
        mem[d + 14..d + 16].copy_from_slice(&((i as u16) + 1).to_le_bytes());
    }
    // Avail ring: one posted chain (head 0).
    mem[avail_addr + 2..avail_addr + 4].copy_from_slice(&1u16.to_le_bytes());
    mem[avail_addr + 4..avail_addr + 6].copy_from_slice(&0u16.to_le_bytes());

    // Host fd: a datagram pair with the frame already queued.
    let (tx, rx) = std::os::unix::net::UnixDatagram::pair().unwrap();
    tx.send(frame).unwrap();

    let mut net = VirtioNet::new(NetConfig::default());
    // SAFETY: `mem` outlives `net` (returned to the caller after `net` is
    // dropped at the end of this function) and is not moved while the raw
    // pointer is held by the bound context.
    let ctx = DeviceCtx {
        mem: Arc::new(unsafe {
            arcbox_virtio_core::GuestMemWriter::new(mem.as_mut_ptr(), mem.len(), 0)
        }),
        raise_irq: Arc::new(|_| {}),
    };
    net.bind_ctx(ctx);
    net.bind_port(NetPort {
        host_fd: rx.as_raw_fd(),
        last_avail_tx: AtomicU16::new(0),
    })
    .expect("bind port");

    let qcfg = QueueConfig {
        desc_addr: desc_addr as u64,
        avail_addr: avail_addr as u64,
        used_addr: used_addr as u64,
        size: q_size,
        ready: true,
        gpa_base: 0,
    };
    let published = net.poll_rx(&qcfg);
    drop(net);
    (mem, published)
}

#[test]
fn poll_rx_delivers_whole_frame_and_stamps_num_buffers() {
    let frame = [0xABu8; 100];
    let (mem, published) = poll_rx_one_frame(&[(0x400, 256)], &frame);
    assert!(published);

    let used_addr = 0x300usize;
    let used_idx = u16::from_le_bytes([mem[used_addr + 2], mem[used_addr + 3]]);
    assert_eq!(used_idx, 1, "one completion");
    let used_len = u32::from_le_bytes([
        mem[used_addr + 8],
        mem[used_addr + 9],
        mem[used_addr + 10],
        mem[used_addr + 11],
    ]);
    assert_eq!(used_len, 12 + 100, "header + payload delivered whole");

    // num_buffers (header offset 10..12) = 1 for spec compliance on
    // VERSION_1 headers without MRG_RXBUF.
    let num_buffers = u16::from_le_bytes([mem[0x400 + 10], mem[0x400 + 11]]);
    assert_eq!(num_buffers, 1);
    assert_eq!(&mem[0x400 + 12..0x400 + 112], &frame[..], "payload intact");
}

#[test]
fn poll_rx_drops_frame_exceeding_chain_capacity() {
    // 100-byte frame + 12-byte header = 112 > the chain's 64 bytes. The
    // device never offers MRG_RXBUF on this path, so spanning is not an
    // option: the frame must be dropped whole (zero-length completion the
    // guest reclaims), never delivered truncated — the guest would parse a
    // truncated buffer as a complete frame.
    let frame = [0xCDu8; 100];
    let (mem, published) = poll_rx_one_frame(&[(0x400, 64)], &frame);
    assert!(published, "the consumed chain still needs its interrupt");

    let used_addr = 0x300usize;
    let used_idx = u16::from_le_bytes([mem[used_addr + 2], mem[used_addr + 3]]);
    assert_eq!(used_idx, 1, "chain returned to the used ring");
    let used_len = u32::from_le_bytes([
        mem[used_addr + 8],
        mem[used_addr + 9],
        mem[used_addr + 10],
        mem[used_addr + 11],
    ]);
    assert_eq!(used_len, 0, "no truncated delivery — dropped whole");
}

#[test]
fn poll_rx_oob_descriptor_poisons_chain() {
    // Chain: valid 64B → OOB 64B (outside the 0x1000 scratch RAM) → valid
    // 64B. Numeric capacity (192) covers the 112-byte frame, and skipping
    // the OOB descriptor while filling the tail would still reach `total` —
    // delivering a full-length frame with a hole in the middle. The chain
    // must be poisoned instead: zero-length completion, nothing delivered.
    let frame = [0xEFu8; 100];
    let (mem, published) = poll_rx_one_frame(&[(0x400, 64), (0x10_0000, 64), (0x500, 64)], &frame);
    assert!(published, "the consumed chain still needs its interrupt");

    let used_addr = 0x300usize;
    let used_idx = u16::from_le_bytes([mem[used_addr + 2], mem[used_addr + 3]]);
    assert_eq!(used_idx, 1, "chain returned to the used ring");
    let used_len = u32::from_le_bytes([
        mem[used_addr + 8],
        mem[used_addr + 9],
        mem[used_addr + 10],
        mem[used_addr + 11],
    ]);
    assert_eq!(used_len, 0, "a holed chain must complete at zero length");
    assert!(
        mem[0x500..0x540].iter().all(|&b| b == 0),
        "nothing may be scattered past the refused descriptor"
    );
}
