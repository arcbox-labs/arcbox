//! Network device configuration, link status, and host-side `NetPort`.

use std::os::unix::io::RawFd;
use std::sync::atomic::AtomicU16;

/// Network device configuration.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// MAC address.
    pub mac: [u8; 6],
    /// MTU size.
    pub mtu: u16,
    /// TAP device name (if applicable).
    pub tap_name: Option<String>,
    /// Number of queue pairs.
    pub num_queues: u16,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // Default QEMU MAC prefix
            mtu: 1500,
            tap_name: None,
            num_queues: 1,
        }
    }
}

impl NetConfig {
    /// Generates a random MAC address.
    ///
    /// The first three bytes are the locally-administered ArcBox OUI
    /// (`52:54:AB`). The remaining three bytes come from `getrandom`, giving
    /// 24 bits of true entropy — 1-in-16M collision odds. Time-derived
    /// fallbacks were rejected because concurrent VM creation within the
    /// same nanosecond tick would otherwise produce identical MACs and
    /// poison the host ARP cache.
    #[must_use]
    pub fn random_mac() -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac[0] = 0x52;
        mac[1] = 0x54;
        mac[2] = 0xAB;
        let mut suffix = [0u8; 3];
        if getrandom::getrandom(&mut suffix).is_err() {
            // Extremely unlikely on supported platforms; fall back to the
            // process-id XOR monotonic counter so we still avoid the
            // all-zeroes collision pattern.
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let pid = std::process::id();
            let mixed = pid ^ n ^ 0x9E37_79B9;
            suffix[0] = (mixed >> 16) as u8;
            suffix[1] = (mixed >> 8) as u8;
            suffix[2] = mixed as u8;
        }
        mac[3..6].copy_from_slice(&suffix);
        mac
    }
}

/// Network device status.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetStatus {
    /// Link is up.
    LinkUp = 1,
    /// Announce required.
    Announce = 2,
}

/// Host-side plumbing for a `VirtioNet` instance running under the custom VMM.
///
/// Holds the raw socket fd used to exchange L2 frames with the datapath
/// (primary NIC) or the vmnet relay (bridge NIC), plus the TX cursor.
///
/// A `NetPort` is bound once via `VirtioNet::bind_port` after the host
/// fd is known (which is *after* device registration, when the socketpair
/// has been created). It is kept in an `OnceLock` on the device so hot-path
/// methods can read both fields without mutex overhead.
#[derive(Debug)]
pub struct NetPort {
    /// Raw fd of the host-side socketpair peer. Reads pull inbound frames
    /// from the datapath; writes push guest TX frames to the datapath.
    pub host_fd: RawFd,
    /// Cursor into the TX avail ring — the last avail index the device
    /// has already drained. Wrapping u16 matches the VirtIO spec.
    pub last_avail_tx: AtomicU16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_net_config_default() {
        let config = NetConfig::default();
        assert_eq!(config.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(config.mtu, 1500);
        assert!(config.tap_name.is_none());
        assert_eq!(config.num_queues, 1);
    }

    #[test]
    fn test_net_config_custom() {
        let config = NetConfig {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            mtu: 9000, // Jumbo frames
            tap_name: Some("tap0".to_string()),
            num_queues: 4,
        };
        assert_eq!(config.mac[0], 0x00);
        assert_eq!(config.mtu, 9000);
        assert_eq!(config.tap_name.as_deref(), Some("tap0"));
        assert_eq!(config.num_queues, 4);
    }

    #[test]
    fn test_random_mac() {
        let mac1 = NetConfig::random_mac();
        let mac2 = NetConfig::random_mac();

        assert_eq!(mac1[0], 0x52);
        assert_eq!(mac1[1], 0x54);
        assert_eq!(mac1[2], 0xAB);

        assert_eq!(mac2[0], 0x52);
        assert_eq!(mac2[1], 0x54);
        assert_eq!(mac2[2], 0xAB);
    }

    #[test]
    fn test_net_status_values() {
        assert_eq!(NetStatus::LinkUp as u16, 1);
        assert_eq!(NetStatus::Announce as u16, 2);
    }

    #[test]
    fn test_config_clone() {
        let config = NetConfig {
            mac: [1, 2, 3, 4, 5, 6],
            mtu: 1234,
            tap_name: Some("test".to_string()),
            num_queues: 2,
        };

        let cloned = config.clone();
        assert_eq!(cloned.mac, config.mac);
        assert_eq!(cloned.mtu, config.mtu);
        assert_eq!(cloned.tap_name, config.tap_name);
        assert_eq!(cloned.num_queues, config.num_queues);
    }
}
