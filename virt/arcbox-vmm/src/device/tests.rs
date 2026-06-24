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
    let mut frame = build_udp_ip_ethernet(src_ip, dst_ip, 49152, 53, payload, src_mac, dst_mac);
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
