use super::*;
use std::net::Ipv4Addr;

use arcbox_net::ethernet::{TcpFrameParams, build_tcp_ack_frame, build_udp_ip_ethernet};
use arcbox_net::nat_engine::checksum::{tcp_checksum, udp_checksum};
use arcbox_virtio::net::VirtioNetHeader;

#[test]
fn test_device_registration() {
    let mut manager = DeviceManager::new();
    let id = manager.register(DeviceType::Serial, "serial0").unwrap();

    let info = manager.get(id);
    assert!(info.is_some());
    assert_eq!(info.unwrap().name, "serial0");
}

#[test]
fn test_virtio_mmio_state() {
    let state = VirtioMmioState::new(2, 0x1234_5678);

    assert_eq!(
        state.read(virtio_mmio::regs::MAGIC),
        virtio_mmio::MAGIC_VALUE
    );
    assert_eq!(state.read(virtio_mmio::regs::VERSION), virtio_mmio::VERSION);
    assert_eq!(state.read(virtio_mmio::regs::DEVICE_ID), 2);
}

#[test]
fn test_virtio_mmio_features() {
    let mut state = VirtioMmioState::new(2, 0xDEAD_BEEF_CAFE_BABE);

    // Read low 32 bits
    assert_eq!(state.read(virtio_mmio::regs::DEVICE_FEATURES), 0xCAFE_BABE);

    // Select high 32 bits
    state.write(virtio_mmio::regs::DEVICE_FEATURES_SEL, 1);
    assert_eq!(state.read(virtio_mmio::regs::DEVICE_FEATURES), 0xDEAD_BEEF);
}

#[test]
fn test_finalize_virtio_net_checksum_repairs_ipv4_tcp_frame() {
    let params = TcpFrameParams {
        src_ip: Ipv4Addr::new(10, 0, 2, 2),
        dst_ip: Ipv4Addr::new(198, 18, 30, 95),
        src_port: 36402,
        dst_port: 443,
        seq: 1234,
        ack: 0,
        window: 64240,
        src_mac: [0x52, 0x54, 0xAB, 0xFA, 0x2A, 0x70],
        dst_mac: [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01],
    };
    let mut frame = build_tcp_ack_frame(&params);
    let tcp_start = 14 + 20;
    frame[tcp_start + 13] = 0x02;
    frame[tcp_start + 16..tcp_start + 18].fill(0);

    let header = VirtioNetHeader {
        flags: VirtioNetHeader::FLAG_NEEDS_CSUM,
        gso_type: VirtioNetHeader::GSO_NONE,
        hdr_len: 0,
        gso_size: 0,
        csum_start: tcp_start as u16,
        csum_offset: 16,
        num_buffers: 1,
    };
    let mut packet_data = header.to_bytes().to_vec();
    packet_data.extend_from_slice(&frame);

    finalize_virtio_net_checksum(&mut packet_data);

    let frame = &packet_data[VirtioNetHeader::SIZE..];
    let stored = u16::from_be_bytes([frame[tcp_start + 16], frame[tcp_start + 17]]);
    let mut tcp_segment = frame[tcp_start..].to_vec();
    tcp_segment[16..18].fill(0);

    assert_ne!(stored, 0);
    assert_eq!(
        stored,
        tcp_checksum(params.src_ip.octets(), params.dst_ip.octets(), &tcp_segment)
    );
}

#[test]
fn test_finalize_virtio_net_checksum_repairs_ipv4_udp_frame() {
    let src_ip = Ipv4Addr::new(10, 0, 2, 2);
    let dst_ip = Ipv4Addr::new(10, 0, 2, 1);
    let payload = b"hello dns";
    let src_mac = [0x52, 0x54, 0xAB, 0xFA, 0x2A, 0x70];
    let dst_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
    let frames = build_udp_ip_ethernet(src_ip, dst_ip, 49152, 53, payload, src_mac, dst_mac, 1500);
    let mut frame = frames
        .into_iter()
        .next()
        .expect("small payload yields one frame");
    let udp_start = 14 + 20;
    frame[udp_start + 6..udp_start + 8].fill(0);

    let header = VirtioNetHeader {
        flags: VirtioNetHeader::FLAG_NEEDS_CSUM,
        gso_type: VirtioNetHeader::GSO_NONE,
        hdr_len: 0,
        gso_size: 0,
        csum_start: udp_start as u16,
        csum_offset: 6,
        num_buffers: 1,
    };
    let mut packet_data = header.to_bytes().to_vec();
    packet_data.extend_from_slice(&frame);

    finalize_virtio_net_checksum(&mut packet_data);

    let frame = &packet_data[VirtioNetHeader::SIZE..];
    let stored = u16::from_be_bytes([frame[udp_start + 6], frame[udp_start + 7]]);
    let mut udp_datagram = frame[udp_start..].to_vec();
    udp_datagram[6..8].fill(0);

    assert_ne!(stored, 0);
    assert_eq!(
        stored,
        udp_checksum(src_ip.octets(), dst_ip.octets(), &udp_datagram)
    );
}

#[test]
fn queue_notify_write_counts_kicks() {
    let mut state = VirtioMmioState::new(1, 0);
    state.write(virtio_mmio::regs::QUEUE_NOTIFY, 0);
    state.write(virtio_mmio::regs::QUEUE_NOTIFY, 0);
    state.write(virtio_mmio::regs::QUEUE_NOTIFY, 2);
    // Out-of-range queue index is ignored, not a panic.
    state.write(virtio_mmio::regs::QUEUE_NOTIFY, 9);
    assert_eq!(state.kicks[0], 2);
    assert_eq!(state.kicks[2], 1);
    assert_eq!(state.kicks[1], 0);
}

#[test]
fn kick_counters_survive_device_reset() {
    let mut state = VirtioMmioState::new(1, 0);
    state.write(virtio_mmio::regs::QUEUE_NOTIFY, 0);
    state.trigger_interrupt(virtio_mmio::INT_VRING);
    state.write(virtio_mmio::regs::STATUS, 0); // device reset
    assert_eq!(state.kicks[0], 1);
    assert_eq!(state.interrupts, 1);
    assert_eq!(state.interrupt_status, 0); // reset still clears live state
}

#[test]
fn trigger_interrupt_counts() {
    let mut state = VirtioMmioState::new(1, 0);
    state.trigger_interrupt(virtio_mmio::INT_VRING);
    state.trigger_interrupt(virtio_mmio::INT_VRING);
    assert_eq!(state.interrupts, 2);
    assert_eq!(state.interrupt_status, virtio_mmio::INT_VRING);
}

#[test]
fn virtio_debug_snapshot_reads_ring_indices() {
    const GPA_BASE: u64 = 0x1000;
    const QUEUE_SIZE: u16 = 4;
    let mut ram = vec![0u8; 0x1000];
    let avail = GPA_BASE + 0x100;
    let used = GPA_BASE + 0x200;

    // Split-ring words the snapshot should pick up.
    let w = |ram: &mut [u8], gpa: u64, value: u16| {
        let off = (gpa - GPA_BASE) as usize;
        ram[off..off + 2].copy_from_slice(&value.to_le_bytes());
    };
    w(&mut ram, avail, 1); // avail.flags = NO_INTERRUPT
    w(&mut ram, avail + 2, 7); // avail.idx
    w(&mut ram, avail + 4 + 2 * u64::from(QUEUE_SIZE), 5); // used_event
    w(&mut ram, used + 2, 3); // used.idx
    w(&mut ram, used + 4 + 8 * u64::from(QUEUE_SIZE), 6); // avail_event

    let mut manager = DeviceManager::new();
    // SAFETY: `ram` outlives the manager use below and covers the range.
    unsafe { manager.set_guest_memory(ram.as_mut_ptr(), ram.len(), GPA_BASE) };
    let id = manager.register(DeviceType::VirtioNet, "net0").unwrap();

    let mut state = VirtioMmioState::new(1, 0);
    state.driver_features = arcbox_virtio::queue::VIRTIO_F_EVENT_IDX;
    state.queue_num[0] = QUEUE_SIZE;
    state.queue_ready[0] = true;
    state.queue_driver[0] = avail;
    state.queue_device[0] = used;
    // Queue 1 configured but with unset ring addresses: fields become None.
    state.queue_num[1] = QUEUE_SIZE;
    state.write(virtio_mmio::regs::QUEUE_NOTIFY, 0);
    state.trigger_interrupt(virtio_mmio::INT_VRING);
    manager.devices.get_mut(&id).unwrap().mmio_state = Some(Arc::new(RwLock::new(state)));

    let snapshot = manager.virtio_debug();
    assert_eq!(snapshot.len(), 1);
    let device = &snapshot[0];
    assert_eq!(device.device_type, "VirtioNet");
    assert!(device.event_idx);
    assert_eq!(device.interrupts, 1);
    assert_eq!(device.queues.len(), 2);

    let q0 = &device.queues[0];
    assert!(q0.ready);
    assert_eq!(q0.kicks, 1);
    assert_eq!(q0.avail_flags, Some(1));
    assert_eq!(q0.avail_idx, Some(7));
    assert_eq!(q0.used_idx, Some(3));
    assert_eq!(q0.used_event, Some(5));
    assert_eq!(q0.avail_event, Some(6));

    let q1 = &device.queues[1];
    assert_eq!(q1.avail_idx, None);
    assert_eq!(q1.used_idx, None);
}

/// Regression for ABX-386: virtio-blk uses one queue per vCPU, so VMs
/// with more than 8 vCPUs configure queue selectors >= 8. The old 8-slot
/// register file silently dropped those writes — the guest's blk-mq
/// queues 8..N existed guest-side only and any request submitted on them
/// was never seen by the host (the cold-boot demand-paging stall).
#[test]
fn queue_config_beyond_eight_round_trips() {
    let mut state = VirtioMmioState::new(2, 0);

    state.write(virtio_mmio::regs::QUEUE_SEL, 12);
    state.write(virtio_mmio::regs::QUEUE_NUM, 256);
    state.write(virtio_mmio::regs::QUEUE_DESC_LOW, 0x8000_1000);
    state.write(virtio_mmio::regs::QUEUE_DESC_HIGH, 0x1);
    state.write(virtio_mmio::regs::QUEUE_DRIVER_LOW, 0x8000_2000);
    state.write(virtio_mmio::regs::QUEUE_DEVICE_LOW, 0x8000_3000);
    state.write(virtio_mmio::regs::QUEUE_READY, 1);
    state.write(virtio_mmio::regs::QUEUE_NOTIFY, 12);

    assert_eq!(state.queue_num[12], 256);
    assert_eq!(state.queue_desc[12], 0x1_8000_1000);
    assert_eq!(state.queue_driver[12], 0x8000_2000);
    assert_eq!(state.queue_device[12], 0x8000_3000);
    assert!(state.queue_ready[12]);
    assert_eq!(state.read(virtio_mmio::regs::QUEUE_READY), 1);
    assert_eq!(state.kicks[12], 1);

    // Selectors beyond the register file must advertise "queue not
    // available" (QueueNumMax = 0) instead of silently dropping config.
    state.write(virtio_mmio::regs::QUEUE_SEL, MAX_VIRTQUEUES as u32);
    assert_eq!(state.read(virtio_mmio::regs::QUEUE_NUM_MAX), 0);
    state.write(virtio_mmio::regs::QUEUE_SEL, 12);
    assert_eq!(state.read(virtio_mmio::regs::QUEUE_NUM_MAX), 1024);
}

/// A guest can program arbitrary garbage as a ring address; the debug
/// snapshot must survive it (no overflow panic, no out-of-bounds read)
/// and report the fields as unreadable.
#[test]
fn virtio_debug_survives_garbage_ring_addresses() {
    const GPA_BASE: u64 = 0x1000;
    let mut ram = vec![0u8; 0x1000];
    let mut manager = DeviceManager::new();
    // SAFETY: `ram` outlives the manager use below and covers the range.
    unsafe { manager.set_guest_memory(ram.as_mut_ptr(), ram.len(), GPA_BASE) };
    let id = manager.register(DeviceType::VirtioBlock, "blk0").unwrap();

    let mut state = VirtioMmioState::new(2, 0);
    state.driver_features = arcbox_virtio::queue::VIRTIO_F_EVENT_IDX;
    state.queue_num[0] = u16::MAX;
    state.queue_ready[0] = true;
    // Near-u64::MAX addresses: adding field offsets overflows if unchecked.
    state.queue_driver[0] = u64::MAX - 1;
    state.queue_device[0] = u64::MAX - 3;
    manager.devices.get_mut(&id).unwrap().mmio_state = Some(Arc::new(RwLock::new(state)));

    let snapshot = manager.virtio_debug();
    let q0 = &snapshot[0].queues[0];
    assert_eq!(q0.avail_idx, None);
    assert_eq!(q0.used_idx, None);
    assert_eq!(q0.used_event, None);
    assert_eq!(q0.avail_event, None);
}
