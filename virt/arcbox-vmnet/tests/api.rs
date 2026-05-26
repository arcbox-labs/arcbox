//! Integration tests for the `arcbox-vmnet` public API.
//!
//! These exercise the surface that consumer crates (`arcbox-net`,
//! `arcbox-vmm`) actually depend on. Tests that need a live vmnet
//! interface — and therefore the `com.apple.vm.networking` entitlement
//! or root — are marked `#[ignore]` and only run via:
//!
//! ```sh
//! sudo cargo test -p arcbox-vmnet --test api -- --ignored
//! ```

#![cfg(target_os = "macos")]

use std::net::Ipv4Addr;

use arcbox_vmnet::{Vmnet, VmnetConfig, VmnetError, VmnetInterfaceInfo, VmnetMode};

// ---------------------------------------------------------------------------
// Pure-Rust API tests — no vmnet syscalls, safe to run anywhere on macOS.
// ---------------------------------------------------------------------------

#[test]
fn config_default_is_shared_nat() {
    let config = VmnetConfig::default();
    assert_eq!(config.mode, VmnetMode::Shared);
    assert_eq!(config.mtu, 1500);
    assert!(config.mac.is_none());
    assert!(config.bridge_interface.is_none());
    assert!(config.dhcp_start.is_none());
    assert!(!config.isolated);
}

#[test]
fn shared_builder_chain_sets_all_fields() {
    let mac = [0x02, 0x00, 0x00, 0x12, 0x34, 0x56];
    let config = VmnetConfig::shared()
        .with_mac(mac)
        .with_mtu(9000)
        .with_dhcp_range(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 254))
        .with_subnet_mask(Ipv4Addr::new(255, 255, 255, 0));

    assert_eq!(config.mode, VmnetMode::Shared);
    assert_eq!(config.mac, Some(mac));
    assert_eq!(config.mtu, 9000);
    assert_eq!(config.dhcp_start, Some(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(config.dhcp_end, Some(Ipv4Addr::new(10, 0, 0, 254)));
    assert_eq!(config.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
}

#[test]
fn host_only_with_isolation() {
    let config = VmnetConfig::host_only().with_isolation(true);
    assert_eq!(config.mode, VmnetMode::HostOnly);
    assert!(config.isolated);
}

#[test]
fn bridged_carries_interface_name() {
    let config = VmnetConfig::bridged("en0");
    assert_eq!(config.mode, VmnetMode::Bridged);
    assert_eq!(config.bridge_interface.as_deref(), Some("en0"));
}

#[test]
fn vmnet_mode_default_is_shared() {
    assert_eq!(VmnetMode::default(), VmnetMode::Shared);
}

#[test]
fn vmnet_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Vmnet>();
    assert_send_sync::<VmnetConfig>();
    assert_send_sync::<VmnetInterfaceInfo>();
}

#[test]
fn config_error_carries_message() {
    let err = VmnetError::config("bad input");
    let s = err.to_string();
    assert!(s.contains("bad input"), "display missing message: {s}");
    assert!(s.contains("vmnet"), "display missing crate prefix: {s}");
    assert!(matches!(err, VmnetError::Config(_)));
}

#[test]
fn io_error_converts_into_vmnet_error() {
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let err: VmnetError = io.into();
    assert!(matches!(err, VmnetError::Io(_)));
}

#[test]
fn interface_info_fields_round_trip() {
    let info = VmnetInterfaceInfo {
        mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        mtu: 1500,
        max_packet_size: 1518,
    };
    let cloned = info.clone();
    assert_eq!(cloned.mac, info.mac);
    assert_eq!(cloned.mtu, info.mtu);
    assert_eq!(cloned.max_packet_size, info.max_packet_size);
}

/// Bridged mode without a bridge interface is rejected before vmnet is
/// touched, so this path runs without root or entitlement.
#[test]
fn bridged_without_interface_fails_with_config_error() {
    let config = VmnetConfig {
        mode: VmnetMode::Bridged,
        bridge_interface: None,
        ..Default::default()
    };

    match Vmnet::new(config) {
        Err(VmnetError::Config(msg)) => {
            assert!(msg.contains("bridge mode"), "unexpected message: {msg}");
        }
        Ok(_) => panic!("bridged mode without interface should fail"),
        Err(other) => panic!("expected config error, got {other:?}"),
    }
}

/// An interface name containing an interior NUL byte must not panic — vmnet
/// should reject it cleanly with a `Config` error.
#[test]
fn bridged_with_nul_in_interface_name_fails_cleanly() {
    let config = VmnetConfig::bridged("en0\0evil");
    match Vmnet::new(config) {
        Err(VmnetError::Config(msg)) => {
            assert!(msg.contains("NUL"), "unexpected message: {msg}");
        }
        Ok(_) => panic!("interface name with NUL should fail"),
        Err(other) => panic!("expected config error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Live tests — require entitlement / root.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires com.apple.vm.networking entitlement or root"]
fn shared_interface_starts_and_stops() {
    let vmnet = Vmnet::new_shared().expect("vmnet start");
    assert!(vmnet.is_running());
    assert!(vmnet.max_packet_size() >= 1500);
    vmnet.stop();
    assert!(!vmnet.is_running());
}

#[test]
#[ignore = "requires com.apple.vm.networking entitlement or root"]
fn host_only_isolated_interface_starts() {
    let config = VmnetConfig::host_only().with_isolation(true);
    let vmnet = Vmnet::new(config).expect("vmnet start");
    assert!(vmnet.is_running());
}

#[test]
#[ignore = "requires com.apple.vm.networking entitlement or root"]
fn read_with_no_traffic_returns_zero() {
    let vmnet = Vmnet::new_shared().expect("vmnet start");
    let mut buf = [0u8; 1500];
    let n = vmnet.read_packet(&mut buf).expect("read");
    assert_eq!(n, 0);
}
